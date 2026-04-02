"""Manager scheduler loop."""

import logging
import threading
import time
from datetime import datetime

from app.celery_tasks import process_single_elf
from app.model import BinaryToSourceTask, ItemTaskStatus, get_db_session
from app.services.leader import LeaderElector
from app.services.task_service import auto_retry_transient_items, get_pending_items_for_dispatch, recover_timed_out_items, refresh_parent_status
from app.services.worker_registry import list_available_workers


logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self):
        from app.config import get_config

        self.cfg = get_config()
        self.leader = LeaderElector()
        self.running = False
        self.dispatch_thread: threading.Thread | None = None
        self.recovery_thread: threading.Thread | None = None

    def start(self):
        self.running = True
        self.dispatch_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self.recovery_thread = threading.Thread(target=self._recovery_loop, daemon=True)
        self.dispatch_thread.start()
        self.recovery_thread.start()
        logger.info("Scheduler service started")

    def stop(self):
        self.running = False
        logger.info("Scheduler service stopped")

    def _dispatch_loop(self):
        interval = self.cfg.scheduler.dispatch_interval_seconds
        while self.running:
            try:
                if self.leader.acquire():
                    self._dispatch_once()
            except Exception as exc:
                logger.exception("dispatch loop failed: %s", exc)
            time.sleep(interval)

    def _recovery_loop(self):
        interval = self.cfg.scheduler.recovery_interval_seconds
        while self.running:
            try:
                if self.leader.acquire():
                    db = get_db_session()
                    try:
                        recovered = recover_timed_out_items(db)
                        retried = auto_retry_transient_items(db)
                        if recovered or retried:
                            logger.info("recovery result: recovered=%s retried=%s", recovered, retried)
                    finally:
                        db.close()
            except Exception as exc:
                logger.exception("recovery loop failed: %s", exc)
            time.sleep(interval)

    def _dispatch_once(self):
        available_workers = list_available_workers(limit=200)
        if not available_workers:
            return

        db = get_db_session()
        try:
            pending_items = get_pending_items_for_dispatch(db, limit=len(available_workers))
            if not pending_items:
                return

            for item, worker in zip(pending_items, available_workers):
                parent = db.query(BinaryToSourceTask).filter(BinaryToSourceTask.id == item.parent_task_id).first()
                if not parent:
                    continue
                if parent.status == "cancelling":
                    item.status = ItemTaskStatus.CANCELLED
                    item.error_reason = "parent cancelling"
                    item.finished_at = datetime.utcnow()
                    refresh_parent_status(parent)
                    continue

                item.status = ItemTaskStatus.QUEUED
                item.queued_at = datetime.utcnow()
                item.worker_id = worker.worker_id
                item.worker_queue = worker.queue

                async_result = process_single_elf.apply_async(args=[item.id], queue=worker.queue)
                item.celery_task_id = async_result.id
                refresh_parent_status(parent)

            db.commit()
        finally:
            db.close()


_scheduler: SchedulerService | None = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler
    if _scheduler is None:
        _scheduler = SchedulerService()
    return _scheduler
