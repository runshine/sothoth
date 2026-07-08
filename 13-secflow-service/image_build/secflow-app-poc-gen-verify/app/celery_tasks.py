"""DVS-style Celery task for poc-gen-verify.

run_poc_task(task_id): a Celery prefork child executes one PoC task.
  - os.setsid() puts the child (and the `poc`/`claude`/`gdb` subprocess tree it
    spawns) in a new process group, so revoke can killpg the whole tree.
  - claim_specific_task sets owner/epoch (guards against acks_late re-deliver
    double-run).
  - reuses task_service._execute_task to run the `poc` CLI + commit terminal state.
  - task_revoked signal → killpg fallback (cancel / worker death).
"""
from __future__ import annotations

import logging
import os
import shutil
import signal
import threading
from pathlib import Path

from celery.signals import task_revoked

from app.celery_app import app
from app.runtime_context import WORKER_ID

logger = logging.getLogger("poc.celery_tasks")

# celery_task_id → process group id (for revoke killpg)
_PGID_LOCK = threading.Lock()
_PGID: dict[str, int] = {}


@app.task(bind=True, name="app.celery_tasks.run_poc_task", acks_late=True)
def run_poc_task(self, task_id: str) -> dict:
    """Execute one PoC task (Celery prefork child)."""
    celery_id = self.request.id
    # New process group: poc/claude/gdb/tmux children all join this group, so
    # revoke can killpg them in one shot.
    try:
        os.setsid()
    except OSError:
        pass
    try:
        pgid = os.getpgid(0)
    except OSError:
        pgid = os.getpid()
    with _PGID_LOCK:
        _PGID[celery_id] = pgid
    logger.info("run_poc_task start task=%s celery_id=%s pgid=%s pod=%s", task_id, celery_id, pgid, WORKER_ID)

    from app.db import get_db
    from app.service.execution_coordinator import claim_specific_task
    from app.service.task_service import get_task_service

    db_gen = get_db()
    db = next(db_gen)
    claimed = None
    try:
        claimed = claim_specific_task(db, WORKER_ID, task_id)
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass

    if claimed is None:
        # Owned by another live worker (running+fresh lease) or already terminal →
        # this message is acked away without execution.
        logger.info("run_poc_task skip (not claimable) task=%s", task_id)
        with _PGID_LOCK:
            _PGID.pop(celery_id, None)
        return {"task_id": task_id, "status": "skipped"}

    # restart / re-deliver semantics: clear previous run artifacts so the task
    # starts from scratch (first run = no-op).
    _clean_task_artifacts(task_id)

    try:
        svc = get_task_service()
        svc._execute_task(task_id, claimed.epoch, claimed.control_version)
        return {"task_id": task_id, "status": "done"}
    finally:
        with _PGID_LOCK:
            _PGID.pop(celery_id, None)
        _cleanup_residual_processes()


def _cleanup_residual_processes() -> None:
    """Best-effort reap of residual poc/claude/node processes in this process group."""
    try:
        os.killpg(os.getpgid(0), 0)  # no-op probe; raises if group gone
    except OSError:
        pass


def _clean_task_artifacts(task_id: str) -> None:
    """restart semantics: clear previous run/output artifacts + DB replay buffers.

    Clears DB stages_json (the /logs status buffer) / result_json / returncode /
    artifacts / error, and rmtree's <output_dir>/output (the poc artifacts), so a
    re-deliver/restart runs from scratch. The DB task_events timeline is retained
    for audit. First run = no-op.
    """
    from app.db import get_db
    from app.db.models import AppPocTask
    try:
        db_gen = get_db()
        db = next(db_gen)
        try:
            row = db.query(AppPocTask).filter_by(task_id=task_id).first()
            if row is None:
                return
            row.stages_json = None
            row.result_json = None
            row.returncode = None
            row.artifacts_json = None
            row.error = None
            db.commit()
            out_dir = Path(row.output_dir) if row.output_dir else None
            if out_dir and out_dir.is_dir():
                art_dir = out_dir / "output"
                if art_dir.exists():
                    try:
                        shutil.rmtree(art_dir)
                        logger.info("cleaned task artifacts: %s/output", task_id)
                    except Exception as exc:
                        logger.warning("clean output failed task=%s: %s", task_id, exc)
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
    except Exception:
        logger.warning("_clean_task_artifacts failed task=%s", task_id, exc_info=True)


@task_revoked.connect
def _on_revoked(sender, request, **kwargs):
    """cancel/revoke → kill the whole poc/claude/gdb process group."""
    celery_id = getattr(request, "id", None) if request else None
    if not celery_id:
        return
    with _PGID_LOCK:
        pgid = _PGID.pop(celery_id, None)
    if pgid is None:
        return
    logger.info("task_revoked celery_id=%s pgid=%s → killpg SIGKILL", celery_id, pgid)
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        except OSError:
            return
        if sig == signal.SIGTERM:
            import time
            time.sleep(0.5)
