"""Worker registration, heartbeat, and cluster coordination."""

from __future__ import annotations

import logging
import os
import socket
import threading
from datetime import timedelta
from typing import Optional

from app.config import get_config
from app.time_utils import now_local


logger = logging.getLogger(__name__)

_heartbeat_thread: Optional[threading.Thread] = None
_maintenance_thread: Optional[threading.Thread] = None
_cleanup_thread: Optional[threading.Thread] = None
_evolution_thread: Optional[threading.Thread] = None
_heartbeat_stop_event = threading.Event()
_maintenance_stop_event = threading.Event()
_cleanup_stop_event = threading.Event()
_evolution_stop_event = threading.Event()
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

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == owner_id).first()
        if row is None:
            row = WorkerInstance(
                worker_id=owner_id,
                hostname=socket.gethostname(),
                pod_ip=os.environ.get("POD_IP", ""),
                started_at=now_local(),
                last_heartbeat=now_local(),
                is_alive=True,
                active_tasks=0,
            )
            db.add(row)
        else:
            row.hostname = socket.gethostname()
            row.pod_ip = os.environ.get("POD_IP", "")
            row.is_alive = True
            row.last_heartbeat = now_local()
            row.active_tasks = 0
        db.commit()
        logger.info("worker registered: %s", owner_id)
    finally:
        db.close()


def heartbeat() -> None:
    from app.model import WorkerInstance, get_db_session

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == owner_id).first()
        if row is not None:
            row.last_heartbeat = now_local()
            row.is_alive = True
            db.commit()
    finally:
        db.close()


def refresh_worker_active_tasks() -> None:
    from app.model import WorkerInstance, get_db_session
    from app.services.task_manager import get_local_active_task_count

    owner_id = get_worker_id()
    current_active = get_local_active_task_count()
    with _active_lock:
        db = get_db_session()
        try:
            row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == owner_id).first()
            if row is not None:
                row.active_tasks = max(0, int(current_active))
                row.last_heartbeat = now_local()
                row.is_alive = True
                db.commit()
        finally:
            db.close()


def deregister_worker() -> None:
    from app.model import WorkerInstance, get_db_session

    owner_id = get_worker_id()
    db = get_db_session()
    try:
        row = db.query(WorkerInstance).filter(WorkerInstance.worker_id == owner_id).first()
        if row is not None:
            row.is_alive = False
            row.active_tasks = 0
            row.last_heartbeat = now_local()
            db.commit()
        logger.info("worker deregistered: %s", owner_id)
    finally:
        db.close()


def reclaim_orphaned_tasks() -> None:
    from app.model import WorkerInstance, get_db_session
    from app.services.task_manager import recover_orphaned_tasks

    cutoff = now_local() - timedelta(seconds=_runtime_dead_threshold_seconds())
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
        db.commit()
    finally:
        db.close()

    recover_orphaned_tasks()


def cleanup_finished_tasks() -> None:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.task_manager import enqueue_workspace_cleanup

    retention_days = _runtime_cleanup_days()
    if retention_days <= 0:
        return

    cutoff = now_local() - timedelta(days=retention_days)
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
        enqueue_workspace_cleanup(
            task_id,
            project_id,
            reason="retention_cleanup",
            created_by="worker",
        )


def get_cluster_snapshot() -> dict:
    from app.model import TaskStatus, UnpackTask, WorkerInstance, get_db_session
    from app.services.task_manager import get_concurrency_snapshot

    reclaim_orphaned_tasks()

    db = get_db_session()
    try:
        workers = db.query(WorkerInstance).order_by(WorkerInstance.started_at.asc()).all()
        all_tasks = db.query(UnpackTask).all()
        task_counts = {
            TaskStatus.PENDING.value: 0,
            TaskStatus.CLAIMED.value: 0,
            TaskStatus.RETRY_PREPARING.value: 0,
            TaskStatus.ARCHIVE_PENDING.value: 0,
            TaskStatus.ARCHIVING.value: 0,
            TaskStatus.RUNNING.value: 0,
            TaskStatus.CANCELLING.value: 0,
            TaskStatus.CANCELLED.value: 0,
            TaskStatus.SUCCESS.value: 0,
            TaskStatus.FAILED.value: 0,
        }
        for task in all_tasks:
            task_counts[task.status] = int(task_counts.get(task.status, 0)) + 1

        return {
            "this_owner": get_worker_id(),
            "total_workers": len(workers),
            "alive_workers": sum(1 for worker in workers if worker.is_alive),
            "workers": [worker.to_dict() for worker in workers],
            "task_counts": task_counts,
            "total_tasks": len(all_tasks),
            "concurrency": get_concurrency_snapshot(),
        }
    finally:
        db.close()


def _heartbeat_loop(interval: int) -> None:
    while not _heartbeat_stop_event.wait(timeout=interval):
        try:
            heartbeat()
            refresh_worker_active_tasks()
        except Exception as exc:
            logger.warning("worker heartbeat loop warning: %s", exc)


def _maintenance_loop(interval: int) -> None:
    while not _maintenance_stop_event.wait(timeout=interval):
        try:
            reclaim_orphaned_tasks()
            cleanup_finished_tasks()
        except Exception as exc:
            logger.warning("worker maintenance loop warning: %s", exc)


def _cleanup_loop(interval: int) -> None:
    from app.services.task_manager import process_workspace_cleanup_jobs

    while not _cleanup_stop_event.wait(timeout=interval):
        try:
            process_workspace_cleanup_jobs()
        except Exception as exc:
            logger.warning("workspace cleanup loop warning: %s", exc)


def _evolution_loop(interval: int) -> None:
    from app.services.task_manager import process_evolution_jobs

    while not _evolution_stop_event.wait(timeout=interval):
        try:
            process_evolution_jobs()
        except Exception as exc:
            logger.warning("evolution loop warning: %s", exc)


def start_worker_heartbeat(interval: Optional[int] = None) -> None:
    global _heartbeat_thread

    if _heartbeat_thread and _heartbeat_thread.is_alive():
        return

    _heartbeat_stop_event.clear()
    loop_interval = interval or int(get_config().worker.heartbeat_interval_seconds)
    _heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(max(5, loop_interval),),
        name="fw-worker-heartbeat",
        daemon=True,
    )
    _heartbeat_thread.start()
    logger.info("worker heartbeat started")


def stop_worker_heartbeat() -> None:
    global _heartbeat_thread

    _heartbeat_stop_event.set()
    if _heartbeat_thread and _heartbeat_thread.is_alive():
        _heartbeat_thread.join(timeout=5)
    _heartbeat_thread = None
    logger.info("worker heartbeat stopped")


def start_cluster_maintenance(interval: Optional[int] = None) -> None:
    global _maintenance_thread

    if _maintenance_thread and _maintenance_thread.is_alive():
        return

    _maintenance_stop_event.clear()
    loop_interval = interval or int(get_config().worker.heartbeat_interval_seconds)
    _maintenance_thread = threading.Thread(
        target=_maintenance_loop,
        args=(max(5, loop_interval),),
        name="fw-worker-maintenance",
        daemon=True,
    )
    _maintenance_thread.start()
    logger.info("worker maintenance loop started")


def stop_cluster_maintenance() -> None:
    global _maintenance_thread

    _maintenance_stop_event.set()
    if _maintenance_thread and _maintenance_thread.is_alive():
        _maintenance_thread.join(timeout=5)
    _maintenance_thread = None
    logger.info("worker maintenance loop stopped")


def start_cleanup_loop(interval: Optional[int] = None) -> None:
    global _cleanup_thread

    if _cleanup_thread and _cleanup_thread.is_alive():
        return

    _cleanup_stop_event.clear()
    loop_interval = interval or int(get_config().worker.heartbeat_interval_seconds)
    _cleanup_thread = threading.Thread(
        target=_cleanup_loop,
        args=(max(5, loop_interval),),
        name="fw-workspace-cleanup",
        daemon=True,
    )
    _cleanup_thread.start()
    logger.info("workspace cleanup loop started")


def stop_cleanup_loop() -> None:
    global _cleanup_thread

    _cleanup_stop_event.set()
    if _cleanup_thread and _cleanup_thread.is_alive():
        _cleanup_thread.join(timeout=5)
    _cleanup_thread = None
    logger.info("workspace cleanup loop stopped")


def start_evolution_loop(interval: Optional[int] = None) -> None:
    global _evolution_thread

    if _evolution_thread and _evolution_thread.is_alive():
        return

    _evolution_stop_event.clear()
    loop_interval = interval or int(get_config().worker.heartbeat_interval_seconds)
    _evolution_thread = threading.Thread(
        target=_evolution_loop,
        args=(max(5, loop_interval),),
        name="fw-evolution",
        daemon=True,
    )
    _evolution_thread.start()
    logger.info("evolution loop started")


def stop_evolution_loop() -> None:
    global _evolution_thread

    _evolution_stop_event.set()
    if _evolution_thread and _evolution_thread.is_alive():
        _evolution_thread.join(timeout=5)
    _evolution_thread = None
    logger.info("evolution loop stopped")


def start_heartbeat(interval: Optional[int] = None) -> None:
    start_worker_heartbeat(interval)
    start_cluster_maintenance(interval)
    start_cleanup_loop(interval)
    start_evolution_loop(interval)


def stop_heartbeat() -> None:
    stop_evolution_loop()
    stop_cleanup_loop()
    stop_cluster_maintenance()
    stop_worker_heartbeat()


def stop_background_loops() -> None:
    stop_heartbeat()


def stop_selected_loops(*, heartbeat: bool = False, maintenance: bool = False, cleanup: bool = False, evolution: bool = False) -> None:
    if evolution:
        stop_evolution_loop()
    if cleanup:
        stop_cleanup_loop()
    if maintenance:
        stop_cluster_maintenance()
    if heartbeat:
        stop_worker_heartbeat()


def stop_all_loops() -> None:
    if _heartbeat_thread and _heartbeat_thread.is_alive():
        stop_worker_heartbeat()
    if _maintenance_thread and _maintenance_thread.is_alive():
        stop_cluster_maintenance()
    if _cleanup_thread and _cleanup_thread.is_alive():
        stop_cleanup_loop()
    if _evolution_thread and _evolution_thread.is_alive():
        stop_evolution_loop()
