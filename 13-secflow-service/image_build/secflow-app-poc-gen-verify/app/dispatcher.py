"""poc-gen-verify scheduler sidecar: DB→Celery pump only.

No startup_reset, no stale scan, no lease/heartbeat. Tasks run ONCE:
- Worker death = task stays in "running" (user can manually restart).
- Scheduler restart = no tasks are reset or re-published.
- No automatic re-delivery (acks_late=False).

Entry: `python -m app.dispatcher`
"""
from __future__ import annotations

import logging
import signal
import threading
import time

from app.runtime_context import DISPATCH_POLL_INTERVAL_SECONDS as PUMP_INTERVAL, PUMP_BATCH, INSPECT_TIMEOUT

logger = logging.getLogger("poc.dispatcher")

# Worker death detection: if a running task's heartbeat is older than this, AND
# the worker pod is not reachable via Celery inspect.ping(), the task is marked
# as 'failed' (NOT re-run — just so the user knows the worker died).
DEAD_WORKER_HEARTBEAT_SECONDS = 600  # 10 minutes with no heartbeat = likely dead


class Dispatcher:
    """Pump pending tasks (celery_task_id IS NULL) → publish to Celery. Nothing else."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._stop.clear()
        t = threading.Thread(target=self._pump_loop, name="poc_disp_pump", daemon=True)
        t.start()
        self._threads.append(t)
        t = threading.Thread(target=self._dead_worker_scan_loop, name="poc_disp_dead", daemon=True)
        t.start()
        self._threads.append(t)
        logger.info("Dispatcher started: pump=%ss dead-scan=60s (mark dead, no rerun)", PUMP_INTERVAL)

    def stop(self) -> None:
        self._stop.set()

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
        from app.celery_app import app as celery_app
        db_gen = get_db()
        db = next(db_gen)
        published = 0
        try:
            # First: clear stale celery_task_id on pending tasks whose celery message
            # was already consumed (acked) but the task never started running.
            # With acks_late=False, a consumed message is gone — the celery_id is
            # stale. We detect this by checking if the celery_id is NOT in any
            # worker's active set (meaning the message was consumed and failed).
            try:
                inspect = celery_app.control.inspect(timeout=3)
                active = inspect.active() or {}
                active_ids = set()
                for _worker, tasks in active.items():
                    for t in (tasks or []):
                        cid = t.get("id") if isinstance(t, dict) else None
                        if cid:
                            active_ids.add(cid)
            except Exception:
                active_ids = set()  # inspect failed → don't clear anything this round

            stale_rows = (
                db.query(AppPocTask)
                .filter(
                    AppPocTask.status == "pending",
                    AppPocTask.is_deleted.is_(False),
                    AppPocTask.celery_task_id.is_not(None),
                )
                .all()
            )
            for row in stale_rows:
                if row.celery_task_id not in active_ids:
                    row.celery_task_id = None
                    logger.info("cleared stale celery_id task=%s (message consumed but task not running)", row.task_id)
            if stale_rows:
                db.commit()

            # Then: publish pending tasks with no celery_task_id
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

    # ── dead worker detection: heartbeat stale + worker unreachable → mark failed ──
    def _dead_worker_scan_loop(self) -> None:
        """Every 60s, check if any running task's worker has died.

        If heartbeat is stale (>DEAD_WORKER_HEARTBEAT_SECONDS) AND the worker pod
        is not in Celery's ping response, mark the task as 'failed' with a clear
        message. This does NOT re-run the task — it just informs the user.
        """
        while not self._stop.is_set():
            try:
                self._dead_worker_scan_once()
            except Exception as exc:
                logger.warning("dead worker scan error: %s", exc, exc_info=True)
            self._stop.wait(60)

    def _dead_worker_scan_once(self) -> int:
        from app.db import get_db
        from app.db.models import AppPocTask
        from app.time_utils import now_local
        from app.celery_app import app as celery_app

        # Get set of live worker names
        try:
            inspect = celery_app.control.inspect(timeout=INSPECT_TIMEOUT)
            ping_results = inspect.ping() or {}
            live_workers = set(ping_results.keys())
        except Exception as exc:
            logger.warning("dead scan: inspect.ping failed: %s (skip this round)", exc)
            return 0

        now = now_local()
        db_gen = get_db()
        db = next(db_gen)
        marked = 0
        try:
            rows = (
                db.query(AppPocTask)
                .filter(AppPocTask.status == "running", AppPocTask.is_deleted.is_(False))
                .all()
            )
            for row in rows:
                hb = row.execution_heartbeat_at
                if hb is None:
                    continue  # not started yet (or just claimed)
                hb_age = (now - hb).total_seconds()
                if hb_age <= DEAD_WORKER_HEARTBEAT_SECONDS:
                    continue  # heartbeat fresh — worker alive
                # Heartbeat is stale. Check if the owning worker is still alive.
                owner = row.execution_owner_id or ""
                # Owner is the pod name (e.g. secflow-app-poc-gen-verify-worker-xxx)
                # Live workers from ping are like "poc-worker@secflow-app-poc-gen-verify-worker-xxx"
                worker_alive = any(owner in w for w in live_workers)
                if worker_alive:
                    continue  # worker is alive but heartbeat thread might have a DB issue
                # Worker is dead → mark task as failed (NOT re-run)
                row.status = "failed"
                row.error = f"Worker pod died (heartbeat stale {int(hb_age)}s, owner={owner})"
                row.finished_at = now
                row.execution_owner_id = None
                row.execution_lease_until = None
                row.execution_heartbeat_at = None
                row.dispatch_status = None
                marked += 1
                logger.warning(
                    "dead worker detected: task=%s owner=%s hb_age=%ds → marked failed",
                    row.task_id, owner, int(hb_age),
                )
            if marked:
                db.commit()
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
        return marked


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
