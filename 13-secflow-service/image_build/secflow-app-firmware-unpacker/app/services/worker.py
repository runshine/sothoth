"""Worker registration, heartbeat, and cluster coordination."""

from __future__ import annotations

import logging
import os
import socket
import threading
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
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


def _agentflow_runs_dir_usage_mb(runs_dir: Path) -> float:
    if not runs_dir.exists():
        return 0.0
    total = 0
    for path in runs_dir.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return round(total / (1024 * 1024), 3)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
    except Exception:
        return None


def cleanup_agentflow_runs() -> None:
    config = get_config()
    retention_days = int(getattr(config.agentflow, "cleanup_runs_retention_days", 0) or 0)
    if retention_days <= 0:
        return
    runs_dir = Path(config.agentflow.runs_dir)
    if not runs_dir.exists():
        return

    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    for run_dir in runs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        run_json = run_dir / "run.json"
        if not run_json.is_file():
            logger.warning("agentflow run cleanup skipped malformed directory: %s", run_dir)
            continue
        try:
            payload = json.loads(run_json.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("agentflow run cleanup skipped unreadable run: %s: %s", run_dir, exc)
            continue
        status = str(payload.get("status") or "")
        if status not in {"completed", "failed", "cancelled"}:
            continue
        finished_at = _parse_iso(payload.get("finished_at") or payload.get("completed_at"))
        if finished_at is None:
            logger.warning("agentflow run cleanup skipped run without finish time: %s", run_dir)
            continue
        if finished_at >= cutoff:
            continue
        try:
            shutil.rmtree(run_dir)
            logger.info(
                "agentflow run cleaned",
                extra={
                    "agentflow_run_id": run_dir.name,
                    "agentflow_run_dir": str(run_dir),
                    "finished_at": finished_at.isoformat(),
                    "retention_days": retention_days,
                },
            )
        except Exception as exc:
            logger.warning("agentflow run cleanup failed for %s: %s", run_dir, exc)


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
    from app.services.task_manager import get_concurrency_snapshot

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

        config = get_config()
        runs_dir = Path(config.agentflow.runs_dir)
        active_agentflow_runs = sum(
            1
            for task in all_tasks
            if task.status in {TaskStatus.RUNNING.value, TaskStatus.CANCELLING.value}
            and bool(task.agentflow_run_id)
        )
        return {
            "this_worker": get_worker_id(),
            "total_workers": len(workers),
            "alive_workers": sum(1 for worker in workers if worker.is_alive),
            "workers": [worker.to_dict() for worker in workers],
            "task_counts": task_counts,
            "total_tasks": len(all_tasks),
            "concurrency": get_concurrency_snapshot(),
            "agentflow_active_runs": active_agentflow_runs,
            "agentflow_max_concurrent": int(config.agentflow.max_concurrent_runs),
            "agentflow_runs_dir_usage_mb": _agentflow_runs_dir_usage_mb(runs_dir),
        }
    finally:
        db.close()


def _heartbeat_loop(interval: int) -> None:
    while not _stop_event.wait(timeout=interval):
        try:
            heartbeat()
            reclaim_orphaned_tasks()
            cleanup_finished_tasks()
            cleanup_agentflow_runs()
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
