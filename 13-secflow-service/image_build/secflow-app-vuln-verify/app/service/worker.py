"""Background worker that runs vuln-verify CLI tasks."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from datetime import timedelta
from pathlib import Path

from app.config import get_config
from app.model import VulnVerifyTask, get_db_session
from app.service.task_service import create_event, summarize_results
from app.time_utils import now_local

logger = logging.getLogger(__name__)
TERMINAL = {"success", "failed", "cancelled"}


class VulnVerifyWorker:
    def __init__(self) -> None:
        self.owner_id = os.environ.get("POD_NAME") or f"vuln-verify-worker-{os.getpid()}"
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._running: set[str] = set()

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        if not get_config().worker.enabled:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="vuln-verify-worker")

    async def stop(self) -> None:
        self._stopping.set()
        if not self._task:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task

    async def _run(self) -> None:
        cfg = get_config().worker
        while not self._stopping.is_set():
            try:
                self._reap_cancelling_processes()
                while len(self._running) < max(1, cfg.max_local_running_tasks):
                    task_id = self._claim_one()
                    if not task_id:
                        break
                    self._running.add(task_id)
                    asyncio.create_task(self._run_one_guarded(task_id), name=f"vuln-verify-task-{task_id}")
            except Exception as exc:
                logger.warning("worker tick failed: %s", exc, exc_info=True)
            await asyncio.sleep(max(1, cfg.poll_interval_seconds))

    def _claim_one(self) -> str | None:
        cfg = get_config().worker
        db = get_db_session()
        try:
            now = now_local()
            task = (
                db.query(VulnVerifyTask)
                .filter(VulnVerifyTask.status == "pending")
                .order_by(VulnVerifyTask.created_at.asc())
                .first()
            )
            if not task:
                return None
            task.status = "running"
            task.worker_id = self.owner_id
            task.lease_until = now + timedelta(seconds=max(30, cfg.lease_seconds))
            task.heartbeat_at = now
            task.started_at = task.started_at or now
            task.finished_at = None
            task.error_reason = None
            task.progress = {"message": "任务已被Worker领取", "percent": 5}
            create_event(db, task, "task_started", f"任务由 {self.owner_id} 开始执行", payload={"worker_id": self.owner_id})
            db.commit()
            return task.id
        finally:
            db.close()

    async def _run_one_guarded(self, task_id: str) -> None:
        try:
            await self._run_one(task_id)
        except Exception as exc:
            logger.exception("task failed unexpectedly: %s", task_id)
            db = get_db_session()
            try:
                task = db.query(VulnVerifyTask).filter(VulnVerifyTask.id == task_id).first()
                if task:
                    task.status = "failed"
                    task.error_reason = str(exc)
                    task.finished_at = now_local()
                    task.pid = None
                    task.progress = {"message": str(exc), "percent": 100}
                    create_event(db, task, "task_failed", f"任务异常失败: {exc}", level="error")
                    db.commit()
            finally:
                db.close()
        finally:
            self._running.discard(task_id)

    async def _run_one(self, task_id: str) -> None:
        db = get_db_session()
        try:
            task = db.query(VulnVerifyTask).filter(VulnVerifyTask.id == task_id).first()
            if not task:
                return
            output_dir = Path(task.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            stdout_path = output_dir / "service.stdout"
            stderr_path = output_dir / "service.stderr"
            cmd = [
                sys.executable,
                "-m",
                "vuln_verify.cli",
                "--reports",
                task.reports_dir,
                "--source-root",
                task.source_root,
                "--binary-root",
                task.binary_root,
                "--threat",
                task.threat_path,
                "--output",
                task.output_dir,
                "-j",
                str(int(task.concurrency or 1)),
                "-v",
            ]
            if task.model:
                cmd.extend(["--model", task.model])
            if task.resume:
                cmd.append("--resume")
            task.progress = {"message": "正在启动 vuln-verify", "percent": 10, "cmd": _redact_cmd(cmd)}
            create_event(db, task, "process_starting", "正在启动 vuln-verify CLI", payload={"cmd": _redact_cmd(cmd)})
            db.commit()
        finally:
            db.close()

        with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
            process = subprocess.Popen(cmd, cwd=str(output_dir), stdout=stdout, stderr=stderr, start_new_session=True)

        db = get_db_session()
        try:
            task = db.query(VulnVerifyTask).filter(VulnVerifyTask.id == task_id).first()
            if not task:
                _kill_process_group(process.pid)
                return
            task.pid = process.pid
            task.progress = {"message": "vuln-verify 执行中", "percent": 30, "pid": process.pid}
            create_event(db, task, "process_started", f"vuln-verify 进程已启动 pid={process.pid}", payload={"pid": process.pid})
            db.commit()
        finally:
            db.close()

        started = time.monotonic()
        timeout = int(get_config().worker.task_timeout_seconds or 0)
        return_code: int | None = None
        while return_code is None:
            return_code = process.poll()
            db = get_db_session()
            try:
                task = db.query(VulnVerifyTask).filter(VulnVerifyTask.id == task_id).first()
                if not task:
                    _kill_process_group(process.pid)
                    return
                if task.status == "cancelling":
                    _kill_process_group(process.pid)
                    task.progress = {"message": "正在取消进程组", "percent": 90, "pid": process.pid}
                    db.commit()
                elif timeout > 0 and time.monotonic() - started > timeout:
                    _kill_process_group(process.pid)
                    task.status = "cancelling"
                    task.error_reason = f"任务超过超时时间 {timeout}s，已终止"
                    task.progress = {"message": task.error_reason, "percent": 90, "pid": process.pid}
                    create_event(db, task, "task_timeout", task.error_reason, level="warning")
                    db.commit()
                else:
                    task.heartbeat_at = now_local()
                    task.lease_until = now_local() + timedelta(seconds=max(30, get_config().worker.lease_seconds))
                    db.commit()
            finally:
                db.close()
            if return_code is None:
                await asyncio.sleep(max(2, get_config().worker.heartbeat_interval_seconds))
        if return_code is None:
            return_code = await asyncio.to_thread(process.wait)

        db = get_db_session()
        try:
            task = db.query(VulnVerifyTask).filter(VulnVerifyTask.id == task_id).first()
            if not task:
                return
            task.return_code = int(return_code)
            task.pid = None
            task.finished_at = now_local()
            task.lease_until = None
            summary = summarize_results(task)
            task.result_summary = summary
            if task.status == "cancelling":
                task.status = "cancelled"
                task.progress = {"message": "任务已取消", "percent": 100}
                create_event(db, task, "task_cancelled", "任务已取消", level="warning", payload={"return_code": return_code, "summary": summary})
            elif return_code == 0:
                task.status = "success"
                task.error_reason = None
                task.progress = {"message": "任务执行成功", "percent": 100}
                create_event(db, task, "task_completed", "任务执行成功", payload={"return_code": return_code, "summary": summary})
            else:
                task.status = "failed"
                task.error_reason = f"vuln-verify exited with code {return_code}"
                task.progress = {"message": task.error_reason, "percent": 100}
                create_event(db, task, "task_failed", task.error_reason, level="error", payload={"return_code": return_code, "summary": summary})
            db.commit()
        finally:
            db.close()

    def _reap_cancelling_processes(self) -> None:
        db = get_db_session()
        try:
            tasks = db.query(VulnVerifyTask).filter(VulnVerifyTask.status == "cancelling", VulnVerifyTask.pid.isnot(None)).all()
            for task in tasks:
                _kill_process_group(int(task.pid))
        finally:
            db.close()


def _redact_cmd(cmd: list[str]) -> list[str]:
    return [str(part) for part in cmd]


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(int(pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception:
            return


_worker: VulnVerifyWorker | None = None


def get_worker() -> VulnVerifyWorker:
    global _worker
    if _worker is None:
        _worker = VulnVerifyWorker()
    return _worker
