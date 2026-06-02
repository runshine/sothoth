"""Worker registration, heartbeat, and cluster coordination."""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from datetime import timedelta
from typing import Optional

from sqlalchemy import func, or_

from app.config import get_config
from app.services.observability import record_maintenance_operation, refresh_cluster_state_metrics
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
_background_loop_interval: Optional[int] = None
_cleanup_loop_heartbeat_at: float = 0.0
_evolution_loop_heartbeat_at: float = 0.0


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


def _runtime_worker_history_retention_days() -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        default = int(get_config().service.worker_history_retention_days)
        value = get_config_value(db, "worker_history_retention_days", default=default)
        return max(0, int(value))
    finally:
        db.close()


def _runtime_cleanup_job_retention_days() -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        default = int(get_config().service.cleanup_job_retention_days)
        value = get_config_value(db, "cleanup_job_retention_days", default=default)
        return max(0, int(value))
    finally:
        db.close()


def _runtime_task_event_retention_days() -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        default = int(get_config().service.task_event_retention_days)
        value = get_config_value(db, "task_event_retention_days", default=default)
        return max(0, int(value))
    finally:
        db.close()


def _runtime_task_event_max_per_task() -> int:
    from app.model import get_config_value, get_db_session

    db = get_db_session()
    try:
        default = int(get_config().service.task_event_max_per_task)
        value = get_config_value(db, "task_event_max_per_task", default=default)
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
    stale_count = 0
    try:
        stale_workers = (
            db.query(WorkerInstance)
            .filter(
                WorkerInstance.last_heartbeat < cutoff,
                (WorkerInstance.is_alive.is_(True) | (WorkerInstance.active_tasks > 0)),
            )
            .all()
        )
        for worker in stale_workers:
            worker.is_alive = False
            worker.active_tasks = 0
        stale_count = len(stale_workers)
        db.commit()
    finally:
        db.close()

    if stale_count:
        logger.info("marked stale workers inactive: count=%s cutoff=%s", stale_count, cutoff.isoformat())
    recover_orphaned_tasks()


def prune_worker_history() -> int:
    from app.model import WorkerInstance, get_db_session

    retention_days = _runtime_worker_history_retention_days()
    if retention_days <= 0:
        return 0

    cutoff = now_local() - timedelta(days=retention_days)
    db = get_db_session()
    deleted = 0
    try:
        deleted = (
            db.query(WorkerInstance)
            .filter(
                WorkerInstance.is_alive.is_(False),
                WorkerInstance.active_tasks <= 0,
                WorkerInstance.last_heartbeat.isnot(None),
                WorkerInstance.last_heartbeat < cutoff,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
    finally:
        db.close()
    if deleted:
        logger.info(
            "pruned worker history: deleted=%s retention_days=%s cutoff=%s",
            deleted,
            retention_days,
            cutoff.isoformat(),
        )
    return int(deleted or 0)


def prune_finished_cleanup_jobs() -> int:
    from app.model import WorkspaceCleanupJob, get_db_session

    retention_days = _runtime_cleanup_job_retention_days()
    if retention_days <= 0:
        return 0

    cutoff = now_local() - timedelta(days=retention_days)
    db = get_db_session()
    deleted = 0
    try:
        deleted = (
            db.query(WorkspaceCleanupJob)
            .filter(
                WorkspaceCleanupJob.status.in_(["success", "failed"]),
                WorkspaceCleanupJob.completed_at.isnot(None),
                WorkspaceCleanupJob.completed_at < cutoff,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
    finally:
        db.close()
    if deleted:
        logger.info(
            "pruned cleanup job history: deleted=%s retention_days=%s cutoff=%s",
            deleted,
            retention_days,
            cutoff.isoformat(),
        )
    return int(deleted or 0)


def prune_task_event_history() -> int:
    from app.model import TERMINAL_STATUSES, TaskStatus, UnpackTask, UnpackTaskEvent, get_db_session

    retention_days = _runtime_task_event_retention_days()
    if retention_days <= 0:
        return 0

    cutoff = now_local() - timedelta(days=retention_days)
    terminal_values = [item.value if isinstance(item, TaskStatus) else str(item) for item in TERMINAL_STATUSES]
    db = get_db_session()
    deleted = 0
    try:
        deleted = (
            db.query(UnpackTaskEvent)
            .filter(
                UnpackTaskEvent.created_at.isnot(None),
                UnpackTaskEvent.created_at < cutoff,
                or_(
                    ~UnpackTaskEvent.task_id.in_(db.query(UnpackTask.id)),
                    UnpackTaskEvent.task_id.in_(
                        db.query(UnpackTask.id).filter(UnpackTask.status.in_(terminal_values))
                    ),
                ),
            )
            .delete(synchronize_session=False)
        )
        db.commit()
    finally:
        db.close()
    if deleted:
        logger.info(
            "pruned task event history: deleted=%s retention_days=%s cutoff=%s",
            deleted,
            retention_days,
            cutoff.isoformat(),
        )
    return int(deleted or 0)


def prune_task_event_backlog() -> int:
    from app.model import UnpackTaskEvent, get_db_session

    max_per_task = _runtime_task_event_max_per_task()
    if max_per_task <= 0:
        return 0

    db = get_db_session()
    deleted = 0
    try:
        oversized_tasks = (
            db.query(UnpackTaskEvent.task_id, func.count(UnpackTaskEvent.id).label("event_count"))
            .group_by(UnpackTaskEvent.task_id)
            .having(func.count(UnpackTaskEvent.id) > max_per_task)
            .all()
        )
        for task_id, event_count in oversized_tasks:
            trim_count = max(0, int(event_count) - max_per_task)
            if trim_count <= 0:
                continue
            old_event_ids = [
                row.id
                for row in (
                    db.query(UnpackTaskEvent.id)
                    .filter(UnpackTaskEvent.task_id == task_id)
                    .order_by(UnpackTaskEvent.created_at.asc(), UnpackTaskEvent.id.asc())
                    .limit(trim_count)
                    .all()
                )
            ]
            if not old_event_ids:
                continue
            deleted += int(
                db.query(UnpackTaskEvent)
                .filter(UnpackTaskEvent.id.in_(old_event_ids))
                .delete(synchronize_session=False)
            )
        db.commit()
    finally:
        db.close()
    if deleted:
        logger.info(
            "pruned task event backlog: deleted=%s max_per_task=%s",
            deleted,
            max_per_task,
        )
    return int(deleted or 0)


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
            stale_after = max(60, int((_background_loop_interval or interval) * 4))
            now_monotonic = time.monotonic()
            if _cleanup_thread is not None and not _cleanup_thread.is_alive() and not _cleanup_stop_event.is_set():
                logger.warning("workspace cleanup loop died unexpectedly; restarting")
                start_cleanup_loop(_background_loop_interval or interval)
            elif (
                _cleanup_thread is not None
                and _cleanup_thread.is_alive()
                and _cleanup_loop_heartbeat_at > 0
                and (now_monotonic - _cleanup_loop_heartbeat_at) > stale_after
            ):
                logger.warning(
                    "workspace cleanup loop heartbeat stale for %.1fs; starting replacement loop",
                    now_monotonic - _cleanup_loop_heartbeat_at,
                )
                start_cleanup_loop(_background_loop_interval or interval, force=True)
            if _evolution_thread is not None and not _evolution_thread.is_alive() and not _evolution_stop_event.is_set():
                logger.warning("evolution loop died unexpectedly; restarting")
                start_evolution_loop(_background_loop_interval or interval)
            elif (
                _evolution_thread is not None
                and _evolution_thread.is_alive()
                and _evolution_loop_heartbeat_at > 0
                and (now_monotonic - _evolution_loop_heartbeat_at) > stale_after
            ):
                logger.warning(
                    "evolution loop heartbeat stale for %.1fs; starting replacement loop",
                    now_monotonic - _evolution_loop_heartbeat_at,
                )
                start_evolution_loop(_background_loop_interval or interval, force=True)

            started_at = time.monotonic()
            reclaim_orphaned_tasks()
            record_maintenance_operation(
                operation="reclaim_orphaned_tasks",
                result="success",
                duration_seconds=max(0.0, time.monotonic() - started_at),
            )

            started_at = time.monotonic()
            cleanup_finished_tasks()
            record_maintenance_operation(
                operation="cleanup_finished_tasks",
                result="success",
                duration_seconds=max(0.0, time.monotonic() - started_at),
            )

            started_at = time.monotonic()
            prune_worker_history()
            record_maintenance_operation(
                operation="prune_worker_history",
                result="success",
                duration_seconds=max(0.0, time.monotonic() - started_at),
            )

            started_at = time.monotonic()
            prune_finished_cleanup_jobs()
            record_maintenance_operation(
                operation="prune_finished_cleanup_jobs",
                result="success",
                duration_seconds=max(0.0, time.monotonic() - started_at),
            )

            started_at = time.monotonic()
            prune_task_event_history()
            record_maintenance_operation(
                operation="prune_task_event_history",
                result="success",
                duration_seconds=max(0.0, time.monotonic() - started_at),
            )

            started_at = time.monotonic()
            prune_task_event_backlog()
            record_maintenance_operation(
                operation="prune_task_event_backlog",
                result="success",
                duration_seconds=max(0.0, time.monotonic() - started_at),
            )

            started_at = time.monotonic()
            refresh_cluster_state_metrics()
            record_maintenance_operation(
                operation="refresh_cluster_state_metrics",
                result="success",
                duration_seconds=max(0.0, time.monotonic() - started_at),
            )
        except Exception as exc:
            record_maintenance_operation(
                operation="maintenance_loop",
                result="failed",
                duration_seconds=0.0,
            )
            logger.warning("worker maintenance loop warning: %s", exc)


def _cleanup_loop(interval: int) -> None:
    from app.services.task_manager import process_workspace_cleanup_jobs
    global _cleanup_loop_heartbeat_at

    while not _cleanup_stop_event.is_set():
        _cleanup_loop_heartbeat_at = time.monotonic()
        try:
            processed = process_workspace_cleanup_jobs()
            if processed:
                logger.info("workspace cleanup loop processed jobs: count=%s", processed)
        except Exception as exc:
            logger.warning("workspace cleanup loop warning: %s", exc)
        _cleanup_loop_heartbeat_at = time.monotonic()
        if _cleanup_stop_event.wait(timeout=interval):
            break


def _evolution_loop(interval: int) -> None:
    from app.services.task_manager import process_evolution_jobs
    global _evolution_loop_heartbeat_at

    while not _evolution_stop_event.is_set():
        _evolution_loop_heartbeat_at = time.monotonic()
        try:
            processed = process_evolution_jobs()
            if processed:
                logger.info("evolution loop processed jobs: count=%s", processed)
        except Exception as exc:
            logger.warning("evolution loop warning: %s", exc)
        _evolution_loop_heartbeat_at = time.monotonic()
        if _evolution_stop_event.wait(timeout=interval):
            break


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


def start_cleanup_loop(interval: Optional[int] = None, *, force: bool = False) -> None:
    global _cleanup_thread, _background_loop_interval

    if not force and _cleanup_thread and _cleanup_thread.is_alive():
        return

    _cleanup_stop_event.clear()
    loop_interval = interval or int(get_config().worker.heartbeat_interval_seconds)
    _background_loop_interval = max(5, loop_interval)
    _cleanup_thread = threading.Thread(
        target=_cleanup_loop,
        args=(_background_loop_interval,),
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


def start_evolution_loop(interval: Optional[int] = None, *, force: bool = False) -> None:
    global _evolution_thread, _background_loop_interval

    if not force and _evolution_thread and _evolution_thread.is_alive():
        return

    _evolution_stop_event.clear()
    loop_interval = interval or int(get_config().worker.heartbeat_interval_seconds)
    _background_loop_interval = max(5, loop_interval)
    _evolution_thread = threading.Thread(
        target=_evolution_loop,
        args=(_background_loop_interval,),
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
