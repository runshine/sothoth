"""Celery task for poc-gen-verify: run ONCE, no re-delivery.

run_poc_task(task_id): a Celery prefork child executes one PoC task.
  - os.setsid() puts the child (and the `poc`/`claude`/`gdb` subprocess tree it
    spawns) in a new process group, so revoke can killpg the whole tree.
  - claim_specific_task sets owner/epoch (guards against double-run if a
    duplicate message somehow arrives).
  - reuses task_service._execute_task to run the `poc` CLI + commit terminal state.
  - task_revoked signal → killpg fallback (cancel only — not worker death).
"""
from __future__ import annotations

import logging
import os
import signal
import threading

from celery.signals import task_revoked

from app.celery_app import app
from app.runtime_context import WORKER_ID

logger = logging.getLogger("poc.celery_tasks")

# celery_task_id → process group id (for cancel revoke killpg)
_PGID_LOCK = threading.Lock()
_PGID: dict[str, int] = {}


@app.task(bind=True, name="app.celery_tasks.run_poc_task")
def run_poc_task(self, task_id: str) -> dict:
    """Execute one PoC task (Celery prefork child). Runs ONCE — no re-delivery."""
    celery_id = self.request.id
    # New process group: poc/claude/gdb/tmux children all join this group, so
    # cancel revoke can killpg them in one shot.
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
        # Already running or already terminal → skip (no double-run).
        logger.info("run_poc_task skip (not claimable) task=%s", task_id)
        with _PGID_LOCK:
            _PGID.pop(celery_id, None)
        return {"task_id": task_id, "status": "skipped"}

    try:
        svc = get_task_service()
        svc._execute_task(task_id, claimed.epoch, claimed.control_version)
        return {"task_id": task_id, "status": "done"}
    finally:
        with _PGID_LOCK:
            _PGID.pop(celery_id, None)


@task_revoked.connect
def _on_revoked(sender, request, **kwargs):
    """cancel/revoke → kill the whole poc/claude/gdb process group.

    This is ONLY for user-initiated cancel (POST /tasks/{id}/cancel).
    Worker death does NOT trigger this (acks_late=False, no re-delivery).
    """
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
