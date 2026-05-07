"""Worker registration, heartbeat, and cluster coordination."""

from __future__ import annotations

import logging
import os
import socket
import threading
from datetime import datetime, timedelta
from typing import Optional

from app.config import get_config


logger = logging.getLogger(__name__)

_heartbeat_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
_active_lock = threading.Lock()


def get_worker_id() -> str:
    from app.model import get_worker_id as _get_worker_id

    return _get_worker_id()


def _runtime_dead_threshold_seconds() -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        default = int(get_config().worker.dead_threshold_seconds)
        value = get_config_value(db, "dead_threshold", default=default)
        return max(15, int(value))
    finally:
        db.close()


def _runtime_cleanup_days() -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        default = int(get_config().service.task_retention_days)
        value = get_config_value(db, "auto_cleanup_days", default=default)
        return max(0, int(value))
    finally:
        db.close()


def register_worker() -> None:
    from app.model import WorkerInstance, get_db_session

    worker_id = get_worker_id()
    db = get_db_session()
    try:
        row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == worker_id).first()
        if row is None:
            row = WorkerInstance(
                worker_id=worker_id,
                hostname=socket.gethostname(),
                pod_ip=os.environ.get("POD_IP", ""),
                started_at=datetime.utcnow(),
                last_heartbeat=datetime.utcnow(),
                is_alive=True,
                active_tasks=0,
            )
            db.add(row)
        else:
            row.hostname = socket.gethostname()
            row.pod_ip = os.environ.get("POD_IP", "")
            row.is_alive = True
            row.last_heartbeat = datetime.utcnow()
            row.active_tasks = 0
        db.commit()
        logger.info("worker registered: %s", worker_id)
    finally:
        db.close()


def heartbeat() -> None:
    from app.model import WorkerInstance, get_db_session

    worker_id = get_worker_id()
    db = get_db_session()
    try:
        row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == worker_id).first()
        if row is not None:
            row.last_heartbeat = datetime.utcnow()
            row.is_alive = True
            db.commit()
    finally:
        db.close()


def update_worker_active_tasks(delta: int) -> None:
    from app.model import WorkerInstance, get_db_session

    worker_id = get_worker_id()
    with _active_lock:
        db = get_db_session()
        try:
            row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == worker_id).first()
            if row is not None:
                row.active_tasks = max(0, int(row.active_tasks or 0) + delta)
                row.last_heartbeat = datetime.utcnow()
                db.commit()
        finally:
            db.close()


def deregister_worker() -> None:
    from app.model import WorkerInstance, get_db_session

    worker_id = get_worker_id()
    db = get_db_session()
    try:
        row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == worker_id).first()
        if row is not None:
            row.is_alive = False
            row.active_tasks = 0
            row.last_heartbeat = datetime.utcnow()
            db.commit()
        logger.info("worker deregistered: %s", worker_id)
    finally:
        db.close()


def reclaim_orphaned_tasks() -> None:
    from app.model import TaskStatus, UnpackTask, WorkerInstance, get_db_session

    cutoff = datetime.utcnow() - timedelta(seconds=_runtime_dead_threshold_seconds())
    db = get_db_session()
    try:
        stale_workers = (
            db.query(WorkerInstance)
            .filter(WorkerInstance.last_heartbeat < cutoff)
            .all()
        )
        for worker in stale_workers:
            worker.is_alive = False
            worker.active_tasks = 0
            tasks = (
                db.query(UnpackTask)
                .filter(
                    UnpackTask.worker_id == worker.worker_id,
                    UnpackTask.status.in_(
                        [
                            TaskStatus.RUNNING.value,
                            TaskStatus.CANCELLING.value,
                        ]
                    ),
                )
                .all()
            )
            for task in tasks:
                task.status = TaskStatus.PENDING.value
                task.worker_id = None
                task.started_at = None
        db.commit()
    finally:
        db.close()


def cleanup_finished_tasks() -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.task_manager import remove_task_workspace

    retention_days = _runtime_cleanup_days()
    if retention_days <= 0:
        return

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    expired_tasks: list[tuple[str, Optional[str]]] = []
    db = get_db_session()
    try:
        expired_tasks = [
            (task.id, task.project_id)
            for task in db.query(UnpackTask)
            .filter(
                UnpackTask.status.in_(
                    [
                        TaskStatus.SUCCESS.value,
                        TaskStatus.FAILED.value,
                        TaskStatus.CANCELLED.value,
                    ]
                ),
                UnpackTask.completed_at.isnot(None),
                UnpackTask.completed_at < cutoff,
            )
            .all()
        ]
        if not expired_tasks:
            return

        task_ids = [task_id for task_id, _ in expired_tasks]
        (
            db.query(UnpackTask)
            .filter(
                UnpackTask.id.in_(task_ids),
            )
            .delete(synchronize_session=False)
        )
        db.commit()
    finally:
        db.close()

    for task_id, project_id in expired_tasks:
        try:
            remove_task_workspace(task_id, project_id)
        except Exception as exc:
            logger.warning(
                "failed to remove workspace for cleaned task %s: %s",
                task_id,
                exc,
            )


def get_cluster_snapshot() -> dict:
    from app.model import TaskStatus, UnpackTask, WorkerInstance, get_db_session

    reclaim_orphaned_tasks()

    db = get_db_session()
    try:
        workers = db.query(WorkerInstance).order_by(WorkerInstance.started_at.asc()).all()
        all_tasks = db.query(UnpackTask).all()
        task_counts = {
            TaskStatus.PENDING.value: 0,
            TaskStatus.RUNNING.value: 0,
            TaskStatus.CANCELLING.value: 0,
            TaskStatus.CANCELLED.value: 0,
            TaskStatus.SUCCESS.value: 0,
            TaskStatus.FAILED.value: 0,
        }
        for task in all_tasks:
            task_counts[task.status] = int(task_counts.get(task.status, 0)) + 1

        return {
            "this_worker": get_worker_id(),
            "total_workers": len(workers),
            "alive_workers": sum(1 for worker in workers if worker.is_alive),
            "workers": [worker.to_dict() for worker in workers],
            "task_counts": task_counts,
            "total_tasks": len(all_tasks),
        }
    finally:
        db.close()


def _heartbeat_loop(interval: int) -> None:
    while not _stop_event.wait(timeout=interval):
        try:
            heartbeat()
            reclaim_orphaned_tasks()
            cleanup_finished_tasks()
        except Exception as exc:
            logger.warning("worker heartbeat loop warning: %s", exc)


def start_heartbeat(interval: Optional[int] = None) -> None:
    global _heartbeat_thread

    if _heartbeat_thread and _heartbeat_thread.is_alive():
        return

    _stop_event.clear()
    loop_interval = interval or int(get_config().worker.heartbeat_interval_seconds)
    _heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(max(5, loop_interval),),
        name="fw-worker-heartbeat",
        daemon=True,
    )
    _heartbeat_thread.start()
    logger.info("worker heartbeat started")


def stop_heartbeat() -> None:
    _stop_event.set()
    if _heartbeat_thread and _heartbeat_thread.is_alive():
        _heartbeat_thread.join(timeout=5)
    logger.info("worker heartbeat stopped")
