"""Shared-DB task scheduling for firmware unpacker service."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Optional

from app.config import get_config


logger = logging.getLogger(__name__)

_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()
_dispatcher_thread: Optional[threading.Thread] = None
_dispatcher_stop = threading.Event()
_futures: Dict[str, Future] = {}
_futures_lock = threading.Lock()


def _executor_capacity() -> int:
    return max(1, int(get_config().service.max_background_workers))


def _runtime_max_concurrent() -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        value = get_config_value(db, "max_concurrent", default=_executor_capacity())
        return max(1, min(_executor_capacity(), int(value)))
    finally:
        db.close()


def _dispatch_interval_seconds() -> int:
    return max(1, int(get_config().worker.claim_interval_seconds))


def _claim_batch_size() -> int:
    return max(1, int(get_config().worker.claim_batch_size))


def get_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:
                _executor = ThreadPoolExecutor(
                    max_workers=_executor_capacity(),
                    thread_name_prefix="fw-unpacker",
                )
    return _executor


def _cleanup_completed_futures() -> None:
    with _futures_lock:
        done_ids = [task_id for task_id, future in _futures.items() if future.done()]
        for task_id in done_ids:
            _futures.pop(task_id, None)


def _active_future_count() -> int:
    _cleanup_completed_futures()
    with _futures_lock:
        return sum(1 for future in _futures.values() if not future.done())


def submit_unpack_task(
    firmware_path: str,
    output_path: str,
    project_id: Optional[str] = None,
) -> str:
    """Insert a pending task into the shared database."""
    from app.model import TaskStatus, UnpackTask, generate_id, get_db_session

    task_id = generate_id()
    db = get_db_session()
    try:
        db.add(
            UnpackTask(
                id=task_id,
                project_id=project_id,
                firmware_path=firmware_path,
                output_path=output_path,
                status=TaskStatus.PENDING.value,
            )
        )
        db.commit()
    finally:
        db.close()

    logger.info("task queued: %s", task_id)
    return task_id


def cancel_task(task_id: str) -> tuple[bool, str]:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return False, "任务不存在"
        if task.status == TaskStatus.PENDING.value:
            task.status = TaskStatus.CANCELLED.value
            task.completed_at = datetime.utcnow()
        elif task.status in (TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value):
            task.status = TaskStatus.CANCELLING.value
        elif task.status == TaskStatus.CANCELLED.value:
            return True, "任务已取消"
        else:
            return False, "仅支持取消排队中或运行中的任务"
        db.commit()
        return True, "取消请求已提交"
    finally:
        db.close()


def retry_task(task_id: str) -> tuple[bool, Optional[str], str]:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return False, None, "任务不存在"
        if task.status not in (
            TaskStatus.FAILED.value,
            TaskStatus.CANCELLED.value,
        ):
            return False, None, "仅支持重试失败或已取消的任务"
        new_task_id = submit_unpack_task(
            firmware_path=task.firmware_path,
            output_path=task.output_path,
            project_id=task.project_id,
        )
        return True, new_task_id, "重试任务已创建"
    finally:
        db.close()


def delete_tasks(task_ids: list[str]) -> tuple[int, list[str]]:
    from app.model import TaskStatus, UnpackTask, get_db_session

    deleted_count = 0
    skipped_ids: list[str] = []
    db = get_db_session()
    try:
        for task_id in task_ids:
            task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
            if task is None:
                skipped_ids.append(task_id)
                continue
            deleted = (
                db.query(UnpackTask)
                .filter(
                    UnpackTask.id == task_id,
                    UnpackTask.status.notin_(
                        [
                            TaskStatus.RUNNING.value,
                            TaskStatus.CANCELLING.value,
                        ]
                    ),
                )
                .delete(synchronize_session=False)
            )
            if not deleted:
                skipped_ids.append(task_id)
                continue
            deleted_count += 1
        db.commit()
        return deleted_count, skipped_ids
    finally:
        db.close()


def _should_cancel(task_id: str) -> bool:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return True
        return task.status in (
            TaskStatus.CANCELLING.value,
            TaskStatus.CANCELLED.value,
        )
    finally:
        db.close()


def _claim_task(task_id: str) -> bool:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id

    db = get_db_session()
    try:
        updated = (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.status == TaskStatus.PENDING.value,
            )
            .update(
                {
                    UnpackTask.status: TaskStatus.RUNNING.value,
                    UnpackTask.worker_id: get_worker_id(),
                    UnpackTask.started_at: datetime.utcnow(),
                    UnpackTask.completed_at: None,
                    UnpackTask.error_message: None,
                },
                synchronize_session=False,
            )
        )
        if updated:
            db.commit()
            return True
        db.rollback()
        return False
    finally:
        db.close()


def _reset_claim(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id == task_id,
                UnpackTask.status == TaskStatus.RUNNING.value,
            )
            .update(
                {
                    UnpackTask.status: TaskStatus.PENDING.value,
                    UnpackTask.worker_id: None,
                    UnpackTask.started_at: None,
                },
                synchronize_session=False,
            )
        )
        db.commit()
    finally:
        db.close()


def _schedule_pending_tasks() -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    available_slots = _runtime_max_concurrent() - _active_future_count()
    if available_slots <= 0:
        return

    fetch_limit = max(available_slots, _claim_batch_size())
    db = get_db_session()
    try:
        candidate_ids = [
            row.id
            for row in (
                db.query(UnpackTask.id)
                .filter(UnpackTask.status == TaskStatus.PENDING.value)
                .order_by(UnpackTask.created_at.asc())
                .limit(fetch_limit)
                .all()
            )
        ]
    finally:
        db.close()

    for task_id in candidate_ids:
        if _runtime_max_concurrent() - _active_future_count() <= 0:
            break
        if not _claim_task(task_id):
            continue
        try:
            future = get_executor().submit(_run_claimed_task, task_id)
        except Exception:
            _reset_claim(task_id)
            raise
        with _futures_lock:
            _futures[task_id] = future


def _run_claimed_task(task_id: str) -> None:
    import os

    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_worker_id, update_worker_active_tasks
    from app.unpacker_engine import run_unpack

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return
        if task.worker_id != get_worker_id():
            return
        firmware_path = task.firmware_path
        output_path = task.output_path
    finally:
        db.close()

    update_worker_active_tasks(+1)
    try:
        if _should_cancel(task_id):
            _mark_task_cancelled(task_id)
            return

        os.makedirs(output_path, exist_ok=True)
        result = run_unpack(
            firmware_path,
            output_path,
            cancel_check=lambda: _should_cancel(task_id),
        )
        _update_task_result(task_id, result)
    except Exception as exc:
        logger.exception("task %s failed with exception: %s", task_id, exc)
        _update_task_error(task_id, str(exc))
    finally:
        update_worker_active_tasks(-1)
        with _futures_lock:
            _futures.pop(task_id, None)


def _mark_task_cancelled(task_id: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return
        task.status = TaskStatus.CANCELLED.value
        task.result_status = "cancelled"
        task.result_message = "Task was cancelled"
        task.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


def _update_task_result(task_id: str, result: dict) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return

        result_status = str(result.get("status") or "").lower()
        if task.status == TaskStatus.CANCELLING.value or result_status == "cancelled":
            task.status = TaskStatus.CANCELLED.value
        elif result_status == "success":
            task.status = TaskStatus.SUCCESS.value
        else:
            task.status = TaskStatus.FAILED.value

        task.result_status = result.get("status")
        task.result_message = result.get("message")
        task.rounds = result.get("rounds")
        task.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


def _update_task_error(task_id: str, error: str) -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session

    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if task is None:
            return
        task.status = TaskStatus.CANCELLED.value if task.status == TaskStatus.CANCELLING.value else TaskStatus.FAILED.value
        task.error_message = error
        task.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


def _dispatch_loop() -> None:
    while not _dispatcher_stop.wait(timeout=_dispatch_interval_seconds()):
        try:
            _schedule_pending_tasks()
        except Exception as exc:
            logger.warning("task dispatch warning: %s", exc)


def start() -> None:
    global _dispatcher_thread

    if _dispatcher_thread and _dispatcher_thread.is_alive():
        return

    get_executor()
    _dispatcher_stop.clear()
    _dispatcher_thread = threading.Thread(
        target=_dispatch_loop,
        name="fw-task-dispatcher",
        daemon=True,
    )
    _dispatcher_thread.start()
    logger.info("task dispatcher started")


def stop() -> None:
    global _dispatcher_thread

    _dispatcher_stop.set()
    if _dispatcher_thread and _dispatcher_thread.is_alive():
        _dispatcher_thread.join(timeout=5)
    _dispatcher_thread = None
    shutdown()
    logger.info("task dispatcher stopped")


def shutdown() -> None:
    global _executor

    _cleanup_completed_futures()
    if _executor is not None:
        _executor.shutdown(wait=False, cancel_futures=False)
        _executor = None
