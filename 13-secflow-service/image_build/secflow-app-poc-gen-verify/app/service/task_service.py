"""Task service for poc-gen-verify: DB-backed task lifecycle + Celery worker execution.

API pod calls `create_task` / `list_tasks` / `get_task` / `cancel_task` /
`restart_task` / `get_task_logs` / `get_task_timeline` / `list_artifacts` /
`get_artifact_content` (read path; create only INSERTs a pending row — the scheduler
dispatcher pump publishes to Celery).

Worker pod (Celery prefork child) calls `_execute_task(task_id, epoch, cv)`: it
CAS-claims running, starts a lease heartbeat, runs the `poc` CLI as a subprocess
(in its own session so revoke can killpg the whole poc+claude+gdb tree), and
CAS-commits the terminal state. Ownership drift → lease heartbeat killpgs + aborts.
"""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_config
from app.db.models import AppPocTask, AppPocTaskEvent
from app.runner import build_poc_cmd, default_output_dir, run_poc_cli
from app.runtime_context import HEARTBEAT_INTERVAL_SECONDS, WORKER_ID
from app.service.execution_coordinator import (
    begin_execution_if_owner,
    commit_terminal_state_if_owner,
    renew_lease,
    still_owner,
)
from app.time_utils import isoformat_local, now_local

logger = logging.getLogger("poc.task_service")

# task_id → {"pgid": int|None, "stop": threading.Event} for the running task on
# this worker. The lease-heartbeat thread and the streaming abort-check share it.
_RUNNING: dict[str, dict] = {}


def _task_id_stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _record_task_event(
    db: Session,
    row: AppPocTask,
    event_type: str,
    message: str,
    *,
    level: str = "info",
    status: Optional[str] = None,
    payload: Optional[dict] = None,
    epoch: Optional[int] = None,
    control_version: Optional[int] = None,
) -> None:
    """INSERT a timeline event (best-effort; dedupe_key is unique per insert)."""
    try:
        ev = AppPocTaskEvent(
            id=uuid.uuid4().hex[:32],
            task_id=row.task_id,
            project_id=row.project_id,
            level=level,
            event_type=event_type,
            status=status if status is not None else row.status,
            worker_id=WORKER_ID,
            execution_epoch=epoch if epoch is not None else int(row.execution_epoch or 0),
            control_version=control_version if control_version is not None else int(row.control_version or 0),
            message=message,
            dedupe_key=f"{row.task_id}:{epoch if epoch is not None else int(row.execution_epoch or 0)}:{event_type}:{uuid.uuid4().hex[:8]}",
        )
        ev.payload = payload or {}
        db.add(ev)
        db.commit()
    except Exception:
        logger.debug("failed to record task event %s", event_type, exc_info=True)
        db.rollback()


class TaskService:
    # ── create ────────────────────────────────────────────────────────────────
    def create_task(
        self,
        db: Session,
        *,
        project_id: str,
        task_name: str,
        entry_function: str,
        vuln_report_path: str,
        binary_dir: str,
        output_dir: Optional[str] = None,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        session_name: Optional[str] = None,
        session_id: Optional[str] = None,
        session_dir: Optional[str] = None,
        timeout: Optional[int] = None,
        task_description: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> dict:
        cfg = get_config()
        task_id = f"poc-{_task_id_stamp()}-{uuid.uuid4().hex[:8]}"
        work_dir = cfg.state_root / "tasks" / task_id
        work_dir.mkdir(parents=True, exist_ok=True)
        out_dir = output_dir or default_output_dir(entry_function, binary_dir, work_dir)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        row = AppPocTask(
            task_id=task_id,
            project_id=project_id,
            task_name=task_name or f"PoC: {entry_function}",
            task_description=task_description,
            entry_function=entry_function,
            vuln_report_path=vuln_report_path,
            binary_dir=binary_dir,
            output_dir=out_dir,
            model=model,
            effort=effort,
            session_name=session_name,
            session_id=session_id,
            session_dir=session_dir,
            timeout=timeout if timeout is not None else cfg.default_timeout,
            status="pending",
            execution_epoch=0,
            control_version=0,
            dispatch_status="pending",
            celery_task_id=None,
            created_by=created_by,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        _record_task_event(
            db, row, "task_created",
            f"任务已创建: poc -e {entry_function} -r {vuln_report_path} -b {binary_dir}",
            payload={"entry_function": entry_function, "binary_dir": binary_dir,
                     "vuln_report_path": vuln_report_path, "output_dir": out_dir},
        )
        return self._row_to_dict(row)

    # ── read ──────────────────────────────────────────────────────────────────
    def _get_or_404(self, db: Session, task_id: str) -> AppPocTask:
        row = (
            db.query(AppPocTask)
            .filter(AppPocTask.task_id == task_id, AppPocTask.is_deleted.is_(False))
            .first()
        )
        if row is None:
            raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
        return row

    def list_tasks(
        self, db: Session, *, project_id: Optional[str], page: int = 1,
        per_page: int = 100, status: Optional[str] = None,
    ) -> dict:
        q = db.query(AppPocTask).filter(AppPocTask.is_deleted.is_(False))
        if project_id:
            q = q.filter(AppPocTask.project_id == project_id)
        if status:
            q = q.filter(AppPocTask.status == status)
        total = q.count()
        rows = (
            q.order_by(AppPocTask.created_at.desc(), AppPocTask.id.desc())
            .offset((page - 1) * per_page).limit(per_page).all()
        )
        return {
            "items": [self._row_to_dict(r, include_heavy=False) for r in rows],
            "total": total, "page": page, "per_page": per_page,
        }

    def get_task_stats(self, db: Session, *, project_id: Optional[str] = None) -> dict:
        q = db.query(AppPocTask.status, func.count(AppPocTask.id)).filter(AppPocTask.is_deleted.is_(False))
        if project_id:
            q = q.filter(AppPocTask.project_id == project_id)
        rows = q.group_by(AppPocTask.status).all()
        counts = {str(s or ""): int(c or 0) for s, c in rows}
        return {
            "total": sum(counts.values()),
            "pending": counts.get("pending", 0),
            "running": counts.get("running", 0),
            "succeeded": counts.get("succeeded", 0),
            "failed": counts.get("failed", 0),
            "timeout": counts.get("timeout", 0),
            "cancelled": counts.get("cancelled", 0),
        }

    def get_task(self, db: Session, task_id: str) -> dict:
        return self._row_to_dict(self._get_or_404(db, task_id))

    def get_task_logs(self, db: Session, task_id: str, *, tail_lines: int = 500) -> dict:
        row = self._get_or_404(db, task_id)
        log_path = self._log_path(row.task_id)
        content = ""
        if log_path.is_file():
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
                content = "".join(lines[-tail_lines:])
            except Exception as exc:
                content = f"[failed to read log: {exc}]"
        return {
            "task_id": row.task_id,
            "status": row.status,
            "returncode": row.returncode,
            "log_path": str(log_path),
            "log_tail": content,
        }

    def get_task_timeline(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        # Full event history (across epochs) — the epoch is included per-event so
        # the frontend can distinguish runs after a restart.
        events = (
            db.query(AppPocTaskEvent)
            .filter(AppPocTaskEvent.task_id == row.task_id)
            .order_by(AppPocTaskEvent.created_at.desc())
            .all()
        )
        return {
            "task_id": row.task_id,
            "events": [
                {
                    "id": e.id, "event_type": e.event_type, "level": e.level,
                    "status": e.status, "worker_id": e.worker_id,
                    "execution_epoch": e.execution_epoch,
                    "control_version": e.control_version,
                    "message": e.message, "payload": e.payload,
                    "created_at": isoformat_local(e.created_at),
                }
                for e in events
            ],
        }

    def list_artifacts(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        art_dir = Path(row.output_dir) / "output" if row.output_dir else None
        disk = sorted(p.name for p in art_dir.iterdir()) if art_dir and art_dir.is_dir() else []
        return {
            "task_id": row.task_id,
            "output_dir": row.output_dir,
            "artifacts": row.artifacts_json or disk,
            "on_disk": disk,
        }

    def get_artifact_content(self, db: Session, task_id: str, name: str) -> dict:
        row = self._get_or_404(db, task_id)
        if not row.output_dir:
            raise HTTPException(status_code=404, detail="任务无输出目录")
        # guard path traversal: name must be a bare basename
        safe = Path(name).name
        if safe != name or "/" in name or ".." in name:
            raise HTTPException(status_code=400, detail="非法的产物文件名")
        target = Path(row.output_dir) / "output" / safe
        if not target.is_file():
            raise HTTPException(status_code=404, detail=f"产物不存在: {safe}")
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"读取产物失败: {exc}")
        return {"task_id": row.task_id, "name": safe, "content": content, "size": len(content)}

    # ── cancel / restart ──────────────────────────────────────────────────────
    def _revoke_celery_task(self, row: AppPocTask) -> None:
        cid = getattr(row, "celery_task_id", None)
        if not cid:
            return
        try:
            from app.celery_app import app as celery_app
            celery_app.control.revoke(cid, terminate=True, signal="SIGKILL")
            logger.info("celery revoke sent task=%s celery_id=%s", row.task_id, cid)
        except Exception as exc:
            logger.warning("celery revoke failed task=%s: %s (stale scan will recover)", row.task_id, exc)

    def cancel_task(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        self._revoke_celery_task(row)
        # also kill the local poc group if running on this worker
        h = _RUNNING.get(task_id)
        if h and h.get("pgid"):
            try:
                os.killpg(h["pgid"], signal.SIGKILL)
            except OSError:
                pass
            h["stop"].set()
        if row.status in ("succeeded", "failed", "timeout", "cancelled"):
            return self._row_to_dict(row)
        row.status = "cancelled"
        row.finished_at = now_local()
        row.execution_owner_id = None
        row.execution_lease_until = None
        row.execution_heartbeat_at = None
        row.execution_epoch = int(row.execution_epoch or 0) + 1
        row.control_version = int(row.control_version or 0) + 1
        row.dispatch_status = None
        row.celery_task_id = None
        db.commit()
        db.refresh(row)
        _record_task_event(db, row, "task_cancelled", "任务已被取消", level="warning",
                           status="cancelled", payload={"reason": "cancel_requested"})
        return self._row_to_dict(row)

    def restart_task(self, db: Session, task_id: str) -> dict:
        row = self._get_or_404(db, task_id)
        self._revoke_celery_task(row)
        # clean previous artifacts (output dir) so it runs from scratch
        if row.output_dir:
            art_dir = Path(row.output_dir) / "output"
            if art_dir.is_dir():
                try:
                    import shutil
                    shutil.rmtree(art_dir)
                except Exception as exc:
                    logger.warning("restart clean output failed: %s", exc)
        row.status = "pending"
        row.started_at = None
        row.finished_at = None
        row.stages_json = None
        row.result_json = None
        row.returncode = None
        row.artifacts_json = None
        row.error = None
        row.execution_owner_id = None
        row.execution_lease_until = None
        row.execution_heartbeat_at = None
        row.execution_epoch = int(row.execution_epoch or 0) + 1
        row.control_version = int(row.control_version or 0) + 1
        row.dispatch_status = "pending"
        row.celery_task_id = None  # dispatcher pump will re-publish
        db.commit()
        db.refresh(row)
        _record_task_event(db, row, "task_retried", "任务已重置并重新执行", status="pending",
                           payload={"reason": "restart_requested"})
        return self._row_to_dict(row)

    # ── worker execution ──────────────────────────────────────────────────────
    def _execute_task(self, task_id: str, epoch: int, control_version: int) -> None:
        """Run the `poc` CLI in a Celery worker prefork child + commit terminal state."""
        from app.db import get_db

        cfg = get_config()
        db_gen = get_db()
        db: Session = next(db_gen)
        handle: dict = {"pgid": None, "stop": threading.Event()}
        _RUNNING[task_id] = handle
        lease_thread = None
        try:
            row = db.query(AppPocTask).filter_by(task_id=task_id).first()
            if not row or row.status == "cancelled":
                return
            if not still_owner(db, task_id, WORKER_ID, epoch, control_version):
                logger.info("task lost ownership before execution task=%s", task_id)
                return

            started_at = now_local()
            if not begin_execution_if_owner(db, task_id, WORKER_ID, epoch, control_version, started_at=started_at):
                return
            db.refresh(row)
            _record_task_event(
                db, row, "task_started", f"任务开始执行: poc -e {row.entry_function}",
                status="running", epoch=epoch, control_version=control_version,
                payload={"entry_function": row.entry_function, "binary_dir": row.binary_dir,
                         "vuln_report_path": row.vuln_report_path},
            )

            timeout = int(row.timeout or cfg.default_timeout)
            model = row.model or cfg.default_model
            work_dir = cfg.state_root / "tasks" / task_id
            work_dir.mkdir(parents=True, exist_ok=True)
            if not row.output_dir:
                row.output_dir = default_output_dir(row.entry_function, row.binary_dir, work_dir)
                db.commit()
                db.refresh(row)
            log_path = str(work_dir / "poc_cli.log")
            cmd = build_poc_cmd(
                poc_bin=cfg.poc_bin, entry_function=row.entry_function,
                vuln_report_path=row.vuln_report_path, binary_dir=row.binary_dir,
                output_dir=row.output_dir, timeout=timeout, model=model,
                effort=row.effort, session_name=row.session_name,
                session_id=row.session_id, session_dir=row.session_dir,
            )

            lease_thread = self._start_lease_heartbeat(task_id, epoch, control_version, handle)

            def _on_popen(proc):
                try:
                    pgid = os.getpgid(proc.pid)
                except OSError:
                    pgid = proc.pid
                handle["pgid"] = pgid
                # let task_revoked (celery control) reach this poc group too
                try:
                    from celery import current_task
                    cid = current_task.request.id
                    if cid:
                        from app.celery_tasks import _PGID, _PGID_LOCK
                        with _PGID_LOCK:
                            _PGID[cid] = pgid
                except Exception:
                    pass

            def _should_abort() -> bool:
                return handle["stop"].is_set()

            result = run_poc_cli(
                cmd=cmd, work_dir=work_dir, log_path=log_path,
                output_dir=row.output_dir, timeout=timeout,
                on_popen=_on_popen, should_abort=_should_abort,
            )

            finished_at = now_local()
            stages = {
                "status": result["status"], "returncode": result["returncode"],
                "artifacts": result["artifacts"], "timed_out": result["timed_out"],
            }
            result_json = {
                "artifacts": result["artifacts"],
                "returncode": result["returncode"],
                "timed_out": result["timed_out"],
            }
            ok = commit_terminal_state_if_owner(
                db, task_id, WORKER_ID, epoch, control_version,
                status=result["status"], finished_at=finished_at,
                returncode=result["returncode"], artifacts_json=result["artifacts"],
                stages_json=stages, result_json=result_json, error=result["error"],
            )
            if ok:
                _record_task_event(
                    db, row, "task_finished", f"任务结束: {result['status']}",
                    status=result["status"], epoch=epoch, control_version=control_version,
                    payload={"returncode": result["returncode"], "error": result["error"],
                             "artifacts": result["artifacts"]},
                )
            else:
                logger.warning("terminal commit rejected (ownership lost) task=%s", task_id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("task execution crashed task=%s", task_id)
            try:
                commit_terminal_state_if_owner(
                    db, task_id, WORKER_ID, epoch, control_version,
                    status="failed", finished_at=now_local(), returncode=None,
                    artifacts_json=None, stages_json={"error": str(exc)},
                    result_json=None, error=f"{type(exc).__name__}: {exc}",
                )
            except Exception:
                logger.exception("failed to commit crashed-task terminal state task=%s", task_id)
        finally:
            handle["stop"].set()
            _RUNNING.pop(task_id, None)
            try:
                next(db_gen)
            except StopIteration:
                pass

    def _start_lease_heartbeat(self, task_id: str, epoch: int, control_version: int, handle: dict) -> threading.Thread:
        from app.db import get_db

        def _worker() -> None:
            while True:
                h = _RUNNING.get(task_id)
                if h is None or h["stop"].is_set():
                    return
                # wait for one interval (or stop signal)
                if h["stop"].wait(HEARTBEAT_INTERVAL_SECONDS):
                    return
                h = _RUNNING.get(task_id)
                if h is None or h["stop"].is_set():
                    return
                db_gen = get_db()
                db: Session = next(db_gen)
                try:
                    ok = renew_lease(db, task_id, WORKER_ID, epoch)
                    if not ok or not still_owner(db, task_id, WORKER_ID, epoch, control_version):
                        logger.warning("lease lost during heartbeat task=%s", task_id)
                        pgid = h.get("pgid")
                        if pgid:
                            try:
                                os.killpg(pgid, signal.SIGKILL)
                            except OSError:
                                pass
                        h["stop"].set()
                        return
                except Exception:
                    logger.debug("lease heartbeat error task=%s", task_id, exc_info=True)
                finally:
                    try:
                        next(db_gen)
                    except StopIteration:
                        pass

        t = threading.Thread(target=_worker, name=f"poc_lease_{task_id}", daemon=True)
        t.start()
        return t

    # ── serialization ─────────────────────────────────────────────────────────
    def _log_path(self, task_id: str) -> Path:
        return get_config().state_root / "tasks" / task_id / "poc_cli.log"

    def _row_to_dict(self, row: AppPocTask, *, include_heavy: bool = True) -> dict:
        return {
            "task_id": row.task_id,
            "project_id": row.project_id,
            "task_name": row.task_name,
            "task_description": row.task_description,
            "entry_function": row.entry_function,
            "vuln_report_path": row.vuln_report_path,
            "binary_dir": row.binary_dir,
            "output_dir": row.output_dir,
            "model": row.model,
            "effort": row.effort,
            "session_name": row.session_name,
            "session_id": row.session_id,
            "session_dir": row.session_dir,
            "timeout": row.timeout,
            "status": row.status,
            "error": row.error,
            "returncode": row.returncode,
            "artifacts": row.artifacts_json or [],
            "result_json": row.result_json if include_heavy else None,
            "stages_json": row.stages_json if include_heavy else None,
            "created_by": row.created_by,
            "created_at": isoformat_local(row.created_at),
            "updated_at": isoformat_local(row.updated_at),
            "started_at": isoformat_local(row.started_at),
            "finished_at": isoformat_local(row.finished_at),
            "execution_owner_id": row.execution_owner_id,
            "execution_lease_until": isoformat_local(row.execution_lease_until),
            "execution_heartbeat_at": isoformat_local(row.execution_heartbeat_at),
            "execution_epoch": int(row.execution_epoch or 0),
            "control_version": int(row.control_version or 0),
            "dispatch_status": row.dispatch_status,
            "celery_task_id": row.celery_task_id,
            "log_path": str(self._log_path(row.task_id)),
            "is_deleted": row.is_deleted,
        }


_task_service: Optional[TaskService] = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service
