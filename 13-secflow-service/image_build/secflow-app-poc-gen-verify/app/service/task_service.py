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
import re
import shlex
import signal
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.exc import OperationalError, PendingRollbackError
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


# ── session-file helpers (for the detail view's "会话记录" tab) ───────────────
# Mirror the containment pattern from secflow-app-entry-analyse `_resolve_session_path`
# and secflow-app-dataflow-vuln-scan `_safe_session_file`: resolve under output_dir,
# reject traversal, whitelist suffixes. The per-stage .log header is parsed for the
# `claude -p …` cmd; .jsonl/transcripts are served as raw seek-from-end tails (never
# full-parsed — a multi-hour claude stream-json can be hundreds of MB).
_SESSION_SUFFIXES = {".log", ".jsonl", ".txt"}
_LOG_HEADER_RE = re.compile(r"^#\s*(\w+)=(.*)$")


def _stage_of(name: str) -> str:
    """stage1 / stage2 / single, from a poc_cli_<ts>_stageN.* / poc_prompt_stageN.* name."""
    m = re.search(r"_stage(\d+)", name)
    return f"stage{m.group(1)}" if m else "single"


def _safe_session_path(output_dir: Path, rel: str) -> Path:
    """Resolve `rel` under `output_dir`; reject absolute/`..` and non-whitelisted suffixes."""
    p = Path(rel or "")
    if p.is_absolute() or ".." in p.parts:
        raise HTTPException(status_code=400, detail="非法会话路径")
    root = output_dir.resolve()
    target = (root / p).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=400, detail="非法会话路径")
    if target.suffix.lower() not in _SESSION_SUFFIXES:
        raise HTTPException(status_code=400, detail="仅支持 .log/.jsonl/.txt 会话文件")
    return target


def _parse_stage_log_header(path: Path) -> dict:
    """Read only the leading `# key=value` header lines of a per-stage .log (cmd/session_id/...)."""
    meta: dict = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for _ in range(25):
                line = fh.readline()
                if not line:
                    break
                m = _LOG_HEADER_RE.match(line.rstrip("\n"))
                if m:
                    meta[m.group(1)] = m.group(2).strip()
                # header is a contiguous block of `# …` lines; stop at the first non-# line once we have meta
                if meta and not line.startswith("#"):
                    break
    except OSError:
        pass
    return meta


def _read_tail(path: Path, *, max_lines: int, max_bytes: int) -> str:
    """Seek-from-end bounded tail — does NOT load the whole file into memory."""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    if size == 0:
        return ""
    start = max(0, size - max_bytes)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(start)
            data = fh.read(max_bytes)
    except OSError as exc:
        return f"[failed to read: {exc}]"
    lines = data.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(lines)


class TaskService:
    # ── create ────────────────────────────────────────────────────────────────
    def create_task(
        self,
        db: Session,
        *,
        project_id: str,
        task_name: str,
        entry_function: Optional[str] = None,
        vuln_report_path: str,
        binary_dir: str,
        output_dir: Optional[str] = None,
        model: Optional[str] = None,
        effort: Optional[str] = None,
        session_name: Optional[str] = None,
        session_id: Optional[str] = None,
        session_dir: Optional[str] = None,
        task_description: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> dict:
        cfg = get_config()
        task_id = f"poc-{_task_id_stamp()}-{uuid.uuid4().hex[:8]}"
        # default work dir on the fileserver (mounted at /data, shared by api+worker) so
        # logs / session records / artifacts live with the task and are readable from the
        # detail view. Naming: <report-basename>_<bindir-basename>_<ts>.
        workspaces_base = cfg.fileserver_root / project_id / "app" / "secflow-app-poc-gen-verify" / "workspaces"
        out_dir = output_dir or default_output_dir(vuln_report_path, binary_dir, workspaces_base)
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        # task name = <report-basename>_<bindir-basename>_<ts>
        _rpt_stem = Path(vuln_report_path).stem if vuln_report_path else "poc"
        _bin_name = Path(binary_dir).name if binary_dir else "bindir"
        _ts = _task_id_stamp()
        row = AppPocTask(
            task_id=task_id,
            project_id=project_id,
            task_name=task_name or f"{_rpt_stem}_{_bin_name}_{_ts}",
            task_description=task_description,
            entry_function=(entry_function or ""),
            vuln_report_path=vuln_report_path,
            binary_dir=binary_dir,
            output_dir=out_dir,
            model=model,
            effort=effort,
            session_name=session_name,
            session_id=session_id,
            session_dir=session_dir,
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
            "cancelled": counts.get("cancelled", 0),
        }

    def get_task(self, db: Session, task_id: str) -> dict:
        return self._row_to_dict(self._get_or_404(db, task_id))

    def get_task_logs(self, db: Session, task_id: str, *, tail_lines: int = 500) -> dict:
        row = self._get_or_404(db, task_id)
        log_path = self._log_path(row.output_dir)
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

    def delete_task(self, db: Session, task_id: str, *, delete_files: bool = True) -> dict:
        """Soft-delete a task (is_deleted=True). Optionally clean output_dir + revoke celery."""
        row = self._get_or_404(db, task_id)
        # revoke any running celery task
        self._revoke_celery_task(row)
        # kill local poc group if running
        h = _RUNNING.get(task_id)
        if h and h.get("pgid"):
            try:
                os.killpg(h["pgid"], signal.SIGKILL)
            except OSError:
                pass
            h["stop"].set()
        # clean output files
        if delete_files and row.output_dir:
            try:
                import shutil as _shutil
                _shutil.rmtree(row.output_dir, ignore_errors=True)
            except Exception as exc:
                logger.warning("delete output failed: %s", exc)
        row.is_deleted = True
        row.status = "cancelled"
        row.finished_at = now_local()
        row.execution_owner_id = None
        row.execution_lease_until = None
        row.execution_heartbeat_at = None
        row.dispatch_status = None
        row.celery_task_id = None
        db.commit()
        db.refresh(row)
        _record_task_event(db, row, "task_deleted", "任务已删除", level="warning",
                           status="cancelled", payload={"delete_files": delete_files})
        return {"task_id": row.task_id, "status": "deleted"}

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

    def get_artifact_path(self, db: Session, task_id: str, name: str) -> Path:
        """Return the safe filesystem path of an artifact (for FileResponse download)."""
        row = self._get_or_404(db, task_id)
        if not row.output_dir:
            raise HTTPException(status_code=404, detail="任务无输出目录")
        safe = Path(name).name
        if safe != name or "/" in name or ".." in name:
            raise HTTPException(status_code=400, detail="非法的产物文件名")
        target = Path(row.output_dir) / "output" / safe
        if not target.is_file():
            raise HTTPException(status_code=404, detail=f"产物不存在: {safe}")
        return target

    def get_artifact_paths(self, db: Session, task_id: str, names: Optional[list[str]] = None) -> list[Path]:
        """Return safe paths for a batch (names list, or all on_disk files)."""
        row = self._get_or_404(db, task_id)
        if not row.output_dir:
            raise HTTPException(status_code=404, detail="任务无输出目录")
        art_dir = Path(row.output_dir) / "output"
        if not art_dir.is_dir():
            return []
        if names:
            paths: list[Path] = []
            for n in names:
                safe = Path(n).name
                if safe != n or "/" in n or ".." in n:
                    continue
                p = art_dir / safe
                if p.is_file():
                    paths.append(p)
            return paths
        return sorted(p for p in art_dir.iterdir() if p.is_file())

    # ── session files (per-stage claude logs / stream-json / prompts / transcripts) ─
    def list_sessions(self, db: Session, task_id: str) -> dict:
        """List the `poc` CLI's per-stage session files under output_dir.

        Top-level: poc_cli_<ts>_stageN.{log,jsonl} + poc_prompt_stageN.txt.
        Transcripts: output_dir/.claude/projects/**/*.jsonl (claude's own session records).
        The `output/` artifacts subdir is skipped (served by /artifacts). Each .log carries
        its claude cmd + session_id in the header. Files survive across restart epochs (only
        `output/` is cleaned) — distinguish by mtime; `is_active` flags recency.
        """
        row = self._get_or_404(db, task_id)
        if not row.output_dir:
            raise HTTPException(status_code=404, detail="任务无输出目录")
        root = Path(row.output_dir)
        if not root.is_dir():
            return {"task_id": row.task_id, "output_dir": row.output_dir, "sessions": []}
        now = time.time()
        items: list[dict] = []
        for p in sorted(list(root.glob("poc_cli_*")) + list(root.glob("poc_prompt_*"))):
            if not p.is_file():
                continue
            meta = _parse_stage_log_header(p) if p.suffix == ".log" else {}
            items.append(self._session_item(p, root, _stage_of(p.name), meta, now))
        claude_dir = root / ".claude"
        if claude_dir.is_dir():
            for p in sorted(claude_dir.rglob("*.jsonl")):
                if p.is_file():
                    items.append(self._session_item(p, root, "transcript", {}, now))
        # honor a user-overridden session_dir (transcripts may live outside output_dir)
        sid = row.session_dir
        if sid and Path(sid).is_dir():
            sid_root = Path(sid).resolve()
            try:
                claude_root = claude_dir.resolve()
            except OSError:
                claude_root = claude_dir
            if sid_root != claude_root:
                for p in sorted(Path(sid).rglob("*.jsonl")):
                    if p.is_file():
                        items.append(self._session_item(p, Path(sid), "transcript", {}, now))
        items.sort(key=lambda x: (x.get("stage", ""), -x.get("mtime", 0)))
        return {"task_id": row.task_id, "output_dir": row.output_dir, "sessions": items}

    def _session_item(self, p: Path, root: Path, stage: str, meta: dict, now: float) -> dict:
        try:
            st = p.stat()
            mtime = st.st_mtime
            size = st.st_size
        except OSError:
            mtime, size = 0.0, 0
        try:
            rel = str(p.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = p.name
        return {
            "name": p.name,
            "rel_path": rel,
            "size": size,
            "mtime": mtime,
            "kind": p.suffix.lstrip(".") if p.suffix else "file",
            "stage": stage,
            "claude_cmd": meta.get("cmd", ""),
            "session_id": meta.get("session_id", ""),
            "jsonl": meta.get("jsonl", ""),
            "prompt_file": meta.get("prompt_file", ""),
            "is_active": (now - mtime) <= 120,
        }

    def get_session_content(self, db: Session, task_id: str, rel_path: str, *, tail_lines: int = 1000) -> dict:
        """Return a bounded tail of a session file (seek-from-end; never full-parses .jsonl)."""
        row = self._get_or_404(db, task_id)
        if not row.output_dir:
            raise HTTPException(status_code=404, detail="任务无输出目录")
        target = _safe_session_path(Path(row.output_dir), rel_path)
        if not target.is_file():
            raise HTTPException(status_code=404, detail=f"会话文件不存在: {rel_path}")
        content = _read_tail(target, max_lines=tail_lines, max_bytes=2097152)
        try:
            size = target.stat().st_size
        except OSError:
            size = 0
        return {
            "task_id": row.task_id,
            "rel_path": rel_path,
            "name": target.name,
            "content": content,
            "size": size,
            "tail_lines": tail_lines,
        }

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
        row.cli_command = None
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
    def _commit_terminal_retry(
        self, task_id: str, epoch: int, control_version: int, *, max_attempts: int = 5, **commit_kw,
    ) -> bool:
        """Commit terminal state using FRESH db sessions with retry.

        WHY: the main `_execute_task` session is opened before `run_poc_cli` and
        held idle for the whole poc run — Stage1 routinely takes 1.5–2.6h, which
        exceeds MySQL `wait_timeout` (3600s). The held connection is NEVER
        returned to the pool, so `pool_pre_ping` never re-validates it; by the
        time we commit, MySQL has closed the socket → `Lost connection during
        query` → the session's transaction is poisoned → `PendingRollbackError`.
        The result: the task actually SUCCEEDED (returncode 0) but the terminal
        UPDATE never lands, so the row stays `running` forever, the scheduler
        eventually restarts it (epoch+1), wipes the artifacts, and re-runs — an
        infinite success→discard→rerun loop.

        FIX: do NOT reuse the long-idle session. Each attempt here opens a
        brand-new session (pool_pre_ping validates the fresh connection) and we
        retry on the stale-connection errors. Closing each attempt's session
        returns the (dead) connection to the pool where pre_ping will reject it
        on the next checkout.
        """
        from app.db import get_db

        last_exc: Optional[Exception] = None
        for attempt in range(1, max_attempts + 1):
            gen = get_db()
            db: Session = next(gen)
            try:
                ok = commit_terminal_state_if_owner(
                    db, task_id, WORKER_ID, epoch, control_version, **commit_kw,
                )
                if ok:
                    return True
                # ownership lost (row no longer running / not ours) — don't retry
                logger.warning("terminal commit rejected (ownership lost) task=%s", task_id)
                return False
            except (OperationalError, PendingRollbackError) as exc:
                last_exc = exc
                try:
                    db.rollback()
                except Exception:  # noqa: BLE001
                    pass
                logger.warning(
                    "terminal commit attempt %d/%d failed (stale mysql conn) task=%s: %s",
                    attempt, max_attempts, task_id, type(exc).__name__,
                )
                time.sleep(min(2.0 * attempt, 10.0))
            finally:
                try:
                    next(gen)  # closes the session
                except StopIteration:
                    pass
        logger.error(
            "terminal commit FAILED after %d attempts task=%s (row stuck in running → "
            "scheduler will restart): %s", max_attempts, task_id, last_exc,
        )
        return False

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

            model = row.model or cfg.default_model
            # work dir = the task's output_dir on the fileserver (shared by api+worker);
            # the runner log + the poc CLI's per-stage logs/sessions/artifacts all live here.
            if not row.output_dir:
                workspaces_base = cfg.fileserver_root / row.project_id / "app" / "secflow-app-poc-gen-verify" / "workspaces"
                row.output_dir = default_output_dir(row.vuln_report_path, row.binary_dir, workspaces_base)
                db.commit()
                db.refresh(row)
            work_dir = Path(row.output_dir)
            work_dir.mkdir(parents=True, exist_ok=True)
            log_path = str(work_dir / "poc_cli.log")
            cmd = build_poc_cmd(
                poc_bin=cfg.poc_bin, entry_function=row.entry_function,
                vuln_report_path=row.vuln_report_path, binary_dir=row.binary_dir,
                output_dir=row.output_dir, model=model,
                effort=row.effort, session_name=row.session_name,
                session_id=row.session_id, session_dir=row.session_dir,
            )

            # Persist the actual `poc` CLI command so the detail view can show the
            # real cmd (all flags) while the task is running — before stages_json /
            # result_json are written at terminal state.
            row.cli_command = shlex.join(cmd)
            db.commit()
            db.refresh(row)

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
                output_dir=row.output_dir,
                on_popen=_on_popen, should_abort=_should_abort,
            )

            # Derive (if absent) the entry function from Stage0's stage0_report.md
            # (the CLI derived it during the run). This is a FILESYSTEM read — we do
            # NOT write it onto the long-idle main session (whose connection is dead
            # by now); instead we fold it into the terminal CAS commit below.
            derived_entry: Optional[str] = None
            if not row.entry_function and row.output_dir:
                s0_report = Path(row.output_dir) / "output" / "stage0_report.md"
                if s0_report.is_file():
                    txt = s0_report.read_text(encoding="utf-8", errors="replace")
                    m = re.search(r"入口函数\s*[:：]\s*([A-Za-z0-9_]+)", txt)
                    if m:
                        derived_entry = m.group(1).strip()

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
            # Commit via FRESH sessions + retry. The main `db` session has been
            # idle for the whole poc run (Stage1 routinely 1.5–2.6h > MySQL
            # wait_timeout=3600s), so its connection is dead — reusing it here
            # reproduces the success→discard→rerun loop (task succeeds but the
            # terminal UPDATE never lands → row stuck `running` → scheduler
            # restarts → wipes artifacts → re-runs forever).
            ok = self._commit_terminal_retry(
                task_id, epoch, control_version,
                status=result["status"], finished_at=finished_at,
                returncode=result["returncode"], artifacts_json=result["artifacts"],
                stages_json=stages, result_json=result_json, error=result["error"],
                entry_function=derived_entry,
            )
            if ok:
                _record_task_event(
                    db, row, "task_finished", f"任务结束: {result['status']}",
                    status=result["status"], epoch=epoch, control_version=control_version,
                    payload={"returncode": result["returncode"], "error": result["error"],
                             "artifacts": result["artifacts"]},
                )
            # (else: ownership lost or commit failed — _commit_terminal_retry logged it)
        except Exception as exc:  # noqa: BLE001
            logger.exception("task execution crashed task=%s", task_id)
            # Same fresh-session+retry rationale as the success path: the main
            # `db` session is likely stale by now, so don't commit a crashed-task
            # terminal state through it.
            self._commit_terminal_retry(
                task_id, epoch, control_version,
                status="failed", finished_at=now_local(), returncode=None,
                artifacts_json=None, stages_json={"error": str(exc)},
                result_json=None, error=f"{type(exc).__name__}: {exc}",
            )
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
    def _log_path(self, output_dir: Optional[str]) -> Path:
        """Runner log lives in the task's work dir (output_dir/poc_cli.log)."""
        return Path(output_dir) / "poc_cli.log" if output_dir else Path("")

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
            "cli_command": row.cli_command,
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
            "log_path": str(self._log_path(row.output_dir)),
            "is_deleted": row.is_deleted,
        }


_task_service: Optional[TaskService] = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service
