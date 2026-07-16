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

from app.runtime_context import DISPATCH_POLL_INTERVAL_SECONDS as PUMP_INTERVAL, PUMP_BATCH

logger = logging.getLogger("poc.dispatcher")


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
        logger.info("Dispatcher started: pump=%ss (no stale scan, no startup reset)", PUMP_INTERVAL)

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
