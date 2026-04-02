"""Celery task definitions."""

import logging
from datetime import datetime

from app.celery_app import celery_app
from app.model import (
    BinaryToSourceTask,
    BinaryToSourceTaskItem,
    FailureType,
    ItemTaskStatus,
    ParentTaskStatus,
    get_db_session,
)
from app.services.decompiler_adapter import get_decompiler_adapter
from app.services.task_service import refresh_parent_status
from app.services.worker_registry import get_worker_id_and_queue, worker_finish_task, worker_start_task


logger = logging.getLogger(__name__)


@celery_app.task(name="binary_to_source.process_single_elf", bind=True)
def process_single_elf(self, task_item_id: str):
    db = get_db_session()
    worker_id, _ = get_worker_id_and_queue()
    try:
        item = db.query(BinaryToSourceTaskItem).filter(BinaryToSourceTaskItem.id == task_item_id).first()
        if not item:
            return {"ok": False, "reason": "item_not_found"}

        parent = db.query(BinaryToSourceTask).filter(BinaryToSourceTask.id == item.parent_task_id).first()
        if not parent:
            return {"ok": False, "reason": "parent_not_found"}

        if parent.status == ParentTaskStatus.CANCELLING or item.cancel_requested:
            item.status = ItemTaskStatus.CANCELLED
            item.failure_type = FailureType.CANCELLED_BY_USER
            item.error_reason = "cancelled before execution"
            item.finished_at = datetime.utcnow()
            refresh_parent_status(parent)
            db.commit()
            return {"ok": True, "status": item.status}

        worker_start_task(current_task_item_id=item.id)
        item.status = ItemTaskStatus.RUNNING
        item.started_at = datetime.utcnow()
        item.attempt_count = (item.attempt_count or 0) + 1
        item.worker_id = worker_id
        db.commit()

        adapter = get_decompiler_adapter()
        result = adapter.decompile_elf(item.elf_path, item.output_dir)

        if parent.status == ParentTaskStatus.CANCELLING or item.cancel_requested:
            item.status = ItemTaskStatus.CANCELLED
            item.failure_type = FailureType.CANCELLED_BY_USER
            item.error_reason = "cancelled during execution"
            item.result_message = result.message
        elif result.status == "success":
            item.status = ItemTaskStatus.SUCCESS
            item.failure_type = None
            item.error_reason = None
            item.result_message = result.message
        elif result.status == "partial_success":
            item.status = ItemTaskStatus.PARTIAL_SUCCESS
            item.failure_type = None
            item.error_reason = result.error_reason
            item.result_message = result.message
        else:
            item.status = ItemTaskStatus.FAILED
            item.failure_type = FailureType.WORKER_BUSINESS_ERROR
            item.error_reason = result.error_reason or "worker business failed"
            item.result_message = result.message
            item.can_auto_retry = False

        item.generated_files = result.generated_files
        item.raw_payload = result.raw_payload
        item.finished_at = datetime.utcnow()
        refresh_parent_status(parent)
        db.commit()

        return {"ok": True, "status": item.status, "failure_type": item.failure_type}
    except Exception as exc:
        logger.exception("worker task execution error: %s", exc)
        item = db.query(BinaryToSourceTaskItem).filter(BinaryToSourceTaskItem.id == task_item_id).first()
        if item:
            item.status = ItemTaskStatus.FAILED
            item.failure_type = FailureType.TRANSIENT_SYSTEM_ERROR
            item.error_reason = str(exc)
            item.result_message = "internal worker error"
            item.finished_at = datetime.utcnow()
            item.can_auto_retry = True
            parent = db.query(BinaryToSourceTask).filter(BinaryToSourceTask.id == item.parent_task_id).first()
            if parent:
                refresh_parent_status(parent)
            db.commit()
        return {"ok": False, "reason": "internal_error"}
    finally:
        worker_finish_task()
        db.close()
