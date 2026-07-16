"""Worker cluster capacity snapshot (Celery-driven, replaces v1 worker_slot table).

Uses Celery inspect (ping/active/stats) to get live workers + running tasks,
plus DB query for pending queue. Mirrors DVS worker_snapshot pattern.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, List

from app.time_utils import isoformat_local

logger = logging.getLogger("poc.worker_snapshot")


@dataclass(frozen=True)
class PocWorkerJobSnapshot:
    task_id: str
    task_name: str
    status: str
    started_at: Any
    updated_at: Any
    dispatch_status: str | None
    execution_owner_id: str | None
    execution_lease_until: Any
    execution_heartbeat_at: Any
    mapped: bool = True
    mapping_reason: str = "celery_active"


@dataclass(frozen=True)
class PocWorkerSnapshot:
    worker_id: str
    host_name: str = ""
    pod_name: str = ""
    healthy: bool = True
    max_concurrent_jobs: int = 1
    running_jobs: int = 0
    available_slots: int = 0
    source: str = "celery"
    last_heartbeat_at: Any = None
    running_job_snapshots: list = field(default_factory=list)


def build_worker_cluster_snapshot() -> dict:
    """Build a live cluster capacity snapshot from Celery inspect + DB.

    Returns dict with: total_workers, healthy_workers, total_capacity,
    total_running, total_available, workers[].
    """
    from app.celery_app import app as celery_app
    from app.db import get_db
    from app.db.models import AppPocTask
    from app.runtime_context import INSPECT_TIMEOUT

    workers: List[dict] = []
    total_capacity = 0
    total_running = 0
    healthy_count = 0

    try:
        inspect = celery_app.control.inspect(timeout=INSPECT_TIMEOUT)
        ping_results = inspect.ping() or {}
    except Exception as exc:
        logger.warning("celery inspect.ping failed: %s", exc)
        return {
            "total_workers": 0, "healthy_workers": 0,
            "total_capacity": 0, "total_running": 0, "total_available": 0,
            "workers": [], "error": str(exc),
        }

    # Query DB for running tasks (reliable — DB is source of truth, unlike
    # inspect.active() which is unreliable from the API pod due to short
    # timeout and broker connectivity issues).
    db_gen = get_db()
    db = next(db_gen)
    try:
        running_rows = (
            db.query(AppPocTask)
            .filter(AppPocTask.status == "running", AppPocTask.is_deleted.is_(False))
            .all()
        )
        pending_count = db.query(AppPocTask).filter(
            AppPocTask.status == "pending", AppPocTask.is_deleted.is_(False)
        ).count()
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass

    for worker_name in sorted(ping_results.keys()):
        # Each worker has concurrency=1 (celery -c 1)
        max_jobs = 1
        # Use DB running count instead of inspect.active() (unreliable from API pod).
        # Map running tasks to workers by execution_owner_id.
        worker_running = [r for r in running_rows if (r.execution_owner_id or "") and (r.execution_owner_id in worker_name or worker_name in (r.execution_owner_id or ""))]
        running_count = len(worker_running)
        available = max(0, max_jobs - running_count)
        total_capacity += max_jobs
        total_running += running_count
        if running_count <= max_jobs:
            healthy_count += 1

        job_snapshots: list = []
        for row in worker_running:
            job_snapshots.append({
                "task_id": row.task_id,
                "task_name": row.task_name,
                "status": row.status,
                "started_at": isoformat_local(row.started_at),
                "updated_at": isoformat_local(row.updated_at),
                "dispatch_status": row.dispatch_status,
                "execution_owner_id": row.execution_owner_id,
                "execution_lease_until": isoformat_local(row.execution_lease_until),
                "execution_heartbeat_at": isoformat_local(row.execution_heartbeat_at),
                "mapped": True,
                "mapping_reason": "db_running",
            })

        workers.append({
            "worker_id": worker_name,
            "host_name": worker_name,
            "pod_name": worker_name,
            "healthy": True,
            "max_concurrent_jobs": max_jobs,
            "running_jobs": running_count,
            "available_slots": available,
            "source": "celery",
            "last_heartbeat_at": None,
            "running_job_snapshots": job_snapshots,
        })

    return {
        "total_workers": len(workers),
        "healthy_workers": healthy_count,
        "total_capacity": total_capacity,
        "total_running": len(running_rows),  # DB is source of truth
        "total_available": max(0, total_capacity - len(running_rows)),
        "pending_count": pending_count,
        "workers": workers,
    }
