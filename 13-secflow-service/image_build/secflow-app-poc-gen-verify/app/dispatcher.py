"""poc-gen-verify scheduler sidecar: DB→Celery pump + startup reset + stale scan.

Runs on the scheduler pod (alongside Redis). Pure threading, no asyncio (CLAUDE.md
compliant). DB is the source of truth; Redis is a transient queue. Redis loss /
restart → `_startup_reset` re-queues all running→pending + clears stale
celery_task_id, then the pump re-publishes. Worker death → `_stale_loop` uses
`inspect.active()` to find DB-running tasks with no live worker → reset pending.

Entry: `python -m app.dispatcher`
"""
from __future__ import annotations

import logging
import os
import signal
import threading
import time

logger = logging.getLogger("poc.dispatcher")

from app.runtime_context import (
    DISPATCH_POLL_INTERVAL_SECONDS as PUMP_INTERVAL,
    STALE_SCAN_INTERVAL_SECONDS as STALE_INTERVAL,
    STALE_HEARTBEAT_SECONDS,
    PUMP_BATCH,
    INSPECT_TIMEOUT,
)


class Dispatcher:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._stop.clear()
        self._startup_reset()
        t = threading.Thread(target=self._pump_loop, name="poc_disp_pump", daemon=True)
        t.start()
        self._threads.append(t)
        t = threading.Thread(target=self._stale_loop, name="poc_disp_stale", daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("Dispatcher started: pump=%ss stale=%ss", PUMP_INTERVAL, STALE_INTERVAL)

    def stop(self) -> None:
        self._stop.set()

    # ── startup reset: Redis queue lost → running back to pending + clear stale celery_id ──
    def _startup_reset(self) -> None:
        from app.db import get_db
        from app.db.models import AppPocTask
        db_gen = get_db()
        db = next(db_gen)
        try:
            n_running = (
                db.query(AppPocTask)
                .filter(AppPocTask.status == "running", AppPocTask.is_deleted.is_(False))
                .update(
                    {
                        AppPocTask.status: "pending",
                        AppPocTask.celery_task_id: None,
                        AppPocTask.execution_owner_id: None,
                        AppPocTask.execution_lease_until: None,
                        AppPocTask.dispatch_status: None,
                    },
                    synchronize_session=False,
                )
            )
            n_pending = (
                db.query(AppPocTask)
                .filter(
                    AppPocTask.status == "pending",
                    AppPocTask.is_deleted.is_(False),
                    AppPocTask.celery_task_id.is_not(None),
                )
                .update(
                    {
                        AppPocTask.celery_task_id: None,
                        AppPocTask.execution_owner_id: None,
                        AppPocTask.execution_lease_until: None,
                        AppPocTask.dispatch_status: None,
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
            if n_running or n_pending:
                logger.warning(
                    "startup_reset: %d running→pending, %d pending stale celery_id cleared (redis queue rebuilt)",
                    n_running, n_pending,
                )
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass

    # ── pump: pending (celery_task_id IS NULL) → publish to Celery ──
    def _pump_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._pump_once()
            except Exception as exc:
                logger.warning("pump loop error: %s", exc, exc_info=True)
            self._stop.wait(PUMP_INTERVAL)

    def _pump_once(self) -> int:
        from app.db import get_db
        from app.db.models import AppPocTask
        from app.celery_tasks import run_poc_task
        db_gen = get_db()
        db = next(db_gen)
        published = 0
        try:
            rows = (
                db.query(AppPocTask)
                .filter(
                    AppPocTask.status == "pending",
                    AppPocTask.is_deleted.is_(False),
                    AppPocTask.celery_task_id.is_(None),
                )
                .order_by(AppPocTask.created_at.asc())
                .limit(PUMP_BATCH)
                .all()
            )
            for row in rows:
                try:
                    ar = run_poc_task.delay(row.task_id)
                    row.celery_task_id = ar.id
                    db.commit()
                    published += 1
                    logger.info("published task=%s celery_id=%s", row.task_id, ar.id)
                except Exception as exc:
                    logger.warning("publish failed task=%s: %s (retry next loop)", row.task_id, exc)
                    db.rollback()
                    break  # Redis unreachable → retry next loop
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
        return published

    # ── stale scan: DB running but no live worker running it → reset pending ──
    def _stale_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._stale_once()
            except Exception as exc:
                logger.warning("stale loop error: %s", exc, exc_info=True)
            self._stop.wait(STALE_INTERVAL)

    def _stale_once(self) -> int:
        from app.db import get_db
        from app.db.models import AppPocTask
        from app.time_utils import now_local
        from app.celery_app import app as celery_app

        # 1. Collect celery_ids of all tasks actively running on live workers.
        active_ids: set[str] = set()
        try:
            inspect = celery_app.control.inspect(timeout=INSPECT_TIMEOUT)
            active = inspect.active() or {}
            for _pod, tasks in active.items():
                for t in (tasks or []):
                    cid = t.get("id") if isinstance(t, dict) else None
                    if cid:
                        active_ids.add(cid)
        except Exception as exc:
            logger.warning("inspect.active failed: %s (skip this round)", exc)
            return 0

        # 2. DB running tasks: celery_id not in active AND heartbeat stale → orphan/stuck.
        db_gen = get_db()
        db = next(db_gen)
        reset = 0
        try:
            now = now_local()
            rows = (
                db.query(AppPocTask)
                .filter(AppPocTask.status == "running", AppPocTask.is_deleted.is_(False))
                .all()
            )
            for row in rows:
                cid = row.celery_task_id
                in_active = cid is not None and cid in active_ids
                heartbeat_stale = (
                    row.execution_heartbeat_at is None
                    or (now - row.execution_heartbeat_at).total_seconds() > STALE_HEARTBEAT_SECONDS
                )
                if in_active and not heartbeat_stale:
                    continue  # genuinely running
                # orphan (not in active) or stuck (in active but no heartbeat) → reset
                if cid:
                    try:
                        celery_app.control.revoke(cid, terminate=True, signal="SIGKILL")
                    except Exception:
                        pass
                row.status = "pending"
                row.celery_task_id = None
                row.execution_owner_id = None
                row.execution_lease_until = None
                row.dispatch_status = None
                reset += 1
                logger.warning(
                    "stale reset task=%s celery_id=%s in_active=%s hb_stale=%s",
                    row.task_id, cid, in_active, heartbeat_stale,
                )
            if reset:
                db.commit()
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
        return reset


_dispatcher: Dispatcher | None = None


def get_dispatcher() -> Dispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = Dispatcher()
    return _dispatcher


def main() -> None:
    import logging as _logging
    _logging.basicConfig(
        level=_logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from app.celery_app import _ensure_db
    _ensure_db()
    disp = get_dispatcher()
    disp.start()

    def _handle(signum, frame):
        disp.stop()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    while not disp._stop.is_set():
        time.sleep(5)


if __name__ == "__main__":
    main()
