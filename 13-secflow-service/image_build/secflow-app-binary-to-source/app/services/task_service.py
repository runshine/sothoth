"""Task domain service."""

import os
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, ValidationError
from app.model import (
    BinaryToSourceTask,
    BinaryToSourceTaskItem,
    FailureType,
    ItemTaskStatus,
    ParentTaskStatus,
    generate_id,
)
from app.services.worker_registry import list_alive_worker_ids


_TERMINAL_ITEM_STATUSES = {
    ItemTaskStatus.SUCCESS,
    ItemTaskStatus.PARTIAL_SUCCESS,
    ItemTaskStatus.FAILED,
    ItemTaskStatus.CANCELLED,
}


def _ensure_status_counts(task: BinaryToSourceTask, items: Iterable[BinaryToSourceTaskItem]) -> None:
    counts = {
        ItemTaskStatus.PENDING: 0,
        ItemTaskStatus.QUEUED: 0,
        ItemTaskStatus.RUNNING: 0,
        ItemTaskStatus.SUCCESS: 0,
        ItemTaskStatus.PARTIAL_SUCCESS: 0,
        ItemTaskStatus.FAILED: 0,
        ItemTaskStatus.CANCELLED: 0,
    }
    item_list = list(items)
    for item in item_list:
        counts[item.status] = counts.get(item.status, 0) + 1

    task.total_items = len(item_list)
    task.pending_items = counts.get(ItemTaskStatus.PENDING, 0)
    task.queued_items = counts.get(ItemTaskStatus.QUEUED, 0)
    task.running_items = counts.get(ItemTaskStatus.RUNNING, 0)
    task.success_items = counts.get(ItemTaskStatus.SUCCESS, 0)
    task.partial_items = counts.get(ItemTaskStatus.PARTIAL_SUCCESS, 0)
    task.failed_items = counts.get(ItemTaskStatus.FAILED, 0)
    task.cancelled_items = counts.get(ItemTaskStatus.CANCELLED, 0)


def refresh_parent_status(task: BinaryToSourceTask) -> None:
    items = list(task.items or [])
    _ensure_status_counts(task, items)

    all_terminal = all(item.status in _TERMINAL_ITEM_STATUSES for item in items)
    any_running = task.running_items > 0 or task.queued_items > 0
    any_success = task.success_items > 0
    any_partial = task.partial_items > 0
    any_failed = task.failed_items > 0
    any_cancelled = task.cancelled_items > 0

    if not task.started_at and any_running:
        task.started_at = datetime.utcnow()

    if task.status == ParentTaskStatus.CANCELLING:
        if all_terminal:
            task.status = ParentTaskStatus.CANCELLED if not (any_success or any_partial or any_failed) else ParentTaskStatus.PARTIAL_SUCCESS
            task.finished_at = datetime.utcnow()
        return

    if any_running:
        task.status = ParentTaskStatus.RUNNING
        return

    if not all_terminal:
        task.status = ParentTaskStatus.PENDING
        return

    task.finished_at = datetime.utcnow()

    if any_failed and not (any_success or any_partial):
        task.status = ParentTaskStatus.FAILED
    elif any_failed or any_partial or (any_success and any_cancelled):
        task.status = ParentTaskStatus.PARTIAL_SUCCESS
    elif any_cancelled and not any_success:
        task.status = ParentTaskStatus.CANCELLED
    else:
        task.status = ParentTaskStatus.COMPLETED


def _build_output_dir(project_id: str, parent_task_id: str, sequence_no: int, output_subdir: Optional[str]) -> str:
    root = get_config().storage.shared_root
    base = os.path.join(root, project_id, parent_task_id, f"item-{sequence_no:04d}")
    if output_subdir:
        return os.path.join(base, output_subdir)
    return base


def create_task(db: Session, *, project_id: str, name: str, description: Optional[str], priority: int, tags: list[str], created_by: str, elf_tasks: list[dict]) -> BinaryToSourceTask:
    if not elf_tasks:
        raise ValidationError("elf_tasks 不能为空")

    parent = BinaryToSourceTask(
        id=generate_id(),
        project_id=project_id,
        name=name,
        description=description,
        priority=priority,
        tags=tags,
        status=ParentTaskStatus.PENDING,
        created_by=created_by,
        result_summary={},
    )
    db.add(parent)

    items: list[BinaryToSourceTaskItem] = []
    for idx, payload in enumerate(elf_tasks, start=1):
        output_dir = _build_output_dir(project_id, parent.id, idx, payload.get("output_subdir"))
        item = BinaryToSourceTaskItem(
            id=generate_id(),
            parent_task_id=parent.id,
            project_id=project_id,
            sequence_no=idx,
            elf_path=payload["elf_path"],
            file_list=payload.get("file_list") or [],
            output_dir=output_dir,
            status=ItemTaskStatus.PENDING,
            raw_payload={"metadata": payload.get("metadata") or {}},
            can_auto_retry=True,
        )
        db.add(item)
        items.append(item)

    db.flush()
    parent.items = items
    refresh_parent_status(parent)
    db.commit()
    db.refresh(parent)
    return parent


def list_tasks(db: Session, project_id: str, status: Optional[str], offset: int, limit: int) -> tuple[int, list[BinaryToSourceTask]]:
    query = db.query(BinaryToSourceTask).filter(BinaryToSourceTask.project_id == project_id)
    if status:
        query = query.filter(BinaryToSourceTask.status == status)
    total = query.count()
    items = query.order_by(BinaryToSourceTask.created_at.desc()).offset(offset).limit(limit).all()
    return total, items


def get_task(db: Session, project_id: str, task_id: str) -> BinaryToSourceTask:
    task = db.query(BinaryToSourceTask).filter(
        BinaryToSourceTask.project_id == project_id,
        BinaryToSourceTask.id == task_id,
    ).first()
    if not task:
        raise NotFoundError("任务", task_id)
    refresh_parent_status(task)
    db.commit()
    db.refresh(task)
    return task


def patch_task(db: Session, project_id: str, task_id: str, payload: dict) -> BinaryToSourceTask:
    task = get_task(db, project_id, task_id)
    if "name" in payload and payload["name"] is not None:
        task.name = payload["name"]
    if "description" in payload:
        task.description = payload["description"]
    if "priority" in payload and payload["priority"] is not None:
        task.priority = int(payload["priority"])
    if "tags" in payload and payload["tags"] is not None:
        task.tags = payload["tags"]
    refresh_parent_status(task)
    db.commit()
    db.refresh(task)
    return task


def delete_task(db: Session, project_id: str, task_id: str) -> None:
    task = get_task(db, project_id, task_id)
    if task.status not in {
        ParentTaskStatus.COMPLETED,
        ParentTaskStatus.FAILED,
        ParentTaskStatus.CANCELLED,
        ParentTaskStatus.PARTIAL_SUCCESS,
    }:
        raise ConflictError("仅终态任务允许删除")
    if task.running_items > 0 or task.queued_items > 0:
        raise ConflictError("任务仍在执行，无法删除")
    db.delete(task)
    db.commit()


def mark_task_cancelling(db: Session, project_id: str, task_id: str) -> BinaryToSourceTask:
    task = get_task(db, project_id, task_id)
    if task.status in {ParentTaskStatus.COMPLETED, ParentTaskStatus.FAILED, ParentTaskStatus.CANCELLED, ParentTaskStatus.PARTIAL_SUCCESS}:
        return task

    task.status = ParentTaskStatus.CANCELLING
    task.cancel_requested_at = datetime.utcnow()

    for item in task.items:
        if item.status == ItemTaskStatus.PENDING:
            item.status = ItemTaskStatus.CANCELLED
            item.failure_type = FailureType.CANCELLED_BY_USER
            item.error_reason = "cancelled before dispatch"
            item.finished_at = datetime.utcnow()
        elif item.status in {ItemTaskStatus.QUEUED, ItemTaskStatus.RUNNING}:
            item.cancel_requested = True

    refresh_parent_status(task)
    db.commit()
    db.refresh(task)
    return task


def manual_retry(db: Session, project_id: str, task_id: str, item_ids: Optional[list[str]]) -> tuple[BinaryToSourceTask, list[BinaryToSourceTaskItem]]:
    task = get_task(db, project_id, task_id)
    id_set = set(item_ids or [])
    selected: list[BinaryToSourceTaskItem] = []

    for item in task.items:
        if item_ids and item.id not in id_set:
            continue
        if item.status not in {ItemTaskStatus.FAILED, ItemTaskStatus.CANCELLED}:
            continue
        item.status = ItemTaskStatus.PENDING
        item.failure_type = None
        item.error_reason = None
        item.result_message = None
        item.generated_files = []
        item.raw_payload = item.raw_payload or {}
        item.worker_id = None
        item.worker_queue = None
        item.celery_task_id = None
        item.queued_at = None
        item.started_at = None
        item.finished_at = None
        item.cancel_requested = False
        item.manual_retry_count = (item.manual_retry_count or 0) + 1
        item.can_auto_retry = True
        selected.append(item)

    if not selected:
        raise ValidationError("没有可重试的子任务")

    task.status = ParentTaskStatus.PENDING
    task.finished_at = None
    task.error_summary = None
    refresh_parent_status(task)
    db.commit()
    db.refresh(task)
    return task, selected


def get_pending_items_for_dispatch(db: Session, limit: int) -> list[BinaryToSourceTaskItem]:
    return (
        db.query(BinaryToSourceTaskItem)
        .filter(BinaryToSourceTaskItem.status == ItemTaskStatus.PENDING)
        .order_by(BinaryToSourceTaskItem.created_at.asc(), BinaryToSourceTaskItem.sequence_no.asc())
        .limit(limit)
        .all()
    )


def recover_timed_out_items(db: Session) -> int:
    cfg = get_config().scheduler
    now = datetime.utcnow()
    changed = 0
    alive_worker_ids = list_alive_worker_ids()

    queued_deadline = now - timedelta(seconds=cfg.queued_timeout_seconds)
    queued = db.query(BinaryToSourceTaskItem).filter(
        BinaryToSourceTaskItem.status == ItemTaskStatus.QUEUED,
        BinaryToSourceTaskItem.queued_at.isnot(None),
        BinaryToSourceTaskItem.queued_at < queued_deadline,
    ).all()
    for item in queued:
        item.status = ItemTaskStatus.PENDING
        item.worker_id = None
        item.worker_queue = None
        item.celery_task_id = None
        item.queued_at = None
        item.cancel_requested = False
        changed += 1

    # Fast recovery for orphaned queued items whose target worker is no longer alive.
    orphaned_queued = db.query(BinaryToSourceTaskItem).filter(
        BinaryToSourceTaskItem.status == ItemTaskStatus.QUEUED,
        BinaryToSourceTaskItem.worker_id.isnot(None),
    ).all()
    for item in orphaned_queued:
        if item.worker_id in alive_worker_ids:
            continue
        item.status = ItemTaskStatus.PENDING
        item.worker_id = None
        item.worker_queue = None
        item.celery_task_id = None
        item.queued_at = None
        item.cancel_requested = False
        changed += 1

    running_deadline = now - timedelta(seconds=cfg.stale_running_timeout_seconds)
    running = db.query(BinaryToSourceTaskItem).filter(
        BinaryToSourceTaskItem.status == ItemTaskStatus.RUNNING,
        BinaryToSourceTaskItem.started_at.isnot(None),
        BinaryToSourceTaskItem.started_at < running_deadline,
    ).all()
    for item in running:
        item.status = ItemTaskStatus.FAILED
        item.failure_type = FailureType.TRANSIENT_SYSTEM_ERROR
        item.error_reason = "running timeout"
        item.result_message = "worker execution timeout"
        item.finished_at = now
        item.can_auto_retry = True
        changed += 1

    if changed:
        _refresh_parent_for_items(db, queued + orphaned_queued + running)
        db.commit()

    return changed


def auto_retry_transient_items(db: Session) -> int:
    cfg = get_config()
    if not cfg.task_policy.auto_retry_enabled:
        return 0

    items = db.query(BinaryToSourceTaskItem).filter(
        BinaryToSourceTaskItem.status == ItemTaskStatus.FAILED,
        BinaryToSourceTaskItem.failure_type == FailureType.TRANSIENT_SYSTEM_ERROR,
        BinaryToSourceTaskItem.can_auto_retry.is_(True),
    ).all()

    changed = 0
    for item in items:
        if (item.auto_retry_count or 0) >= cfg.task_policy.max_auto_retries:
            continue
        item.status = ItemTaskStatus.PENDING
        item.auto_retry_count = (item.auto_retry_count or 0) + 1
        item.error_reason = None
        item.result_message = None
        item.failure_type = None
        item.generated_files = []
        item.worker_id = None
        item.worker_queue = None
        item.celery_task_id = None
        item.queued_at = None
        item.started_at = None
        item.finished_at = None
        item.cancel_requested = False
        changed += 1

    if changed:
        _refresh_parent_for_items(db, items)
        db.commit()

    return changed


def _refresh_parent_for_items(db: Session, items: list[BinaryToSourceTaskItem]):
    touched = set()
    for item in items:
        if item.parent_task_id in touched:
            continue
        parent = db.query(BinaryToSourceTask).filter(BinaryToSourceTask.id == item.parent_task_id).first()
        if not parent:
            continue
        refresh_parent_status(parent)
        touched.add(item.parent_task_id)
