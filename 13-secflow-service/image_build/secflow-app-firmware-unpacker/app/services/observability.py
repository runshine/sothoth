"""Prometheus metrics for firmware unpacker runtime."""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Iterator

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest


logger = logging.getLogger(__name__)

CLAIM_OPERATIONS_TOTAL = Counter(
    "firmware_unpacker_claim_operations_total",
    "Total task claim operations.",
    ("result",),
)
CLAIMED_TASKS_TOTAL = Counter(
    "firmware_unpacker_claimed_tasks_total",
    "Total tasks claimed by dispatchers.",
)
CLAIM_DURATION_SECONDS = Histogram(
    "firmware_unpacker_claim_duration_seconds",
    "Duration of task claim operations.",
)
DB_RETRY_TOTAL = Counter(
    "firmware_unpacker_db_retry_total",
    "Total transient database retries.",
    ("operation",),
)
DB_OPERATION_RESULTS_TOTAL = Counter(
    "firmware_unpacker_db_operation_results_total",
    "Final result of retried database operations.",
    ("operation", "result"),
)
ORPHAN_RECOVERY_ACTIONS_TOTAL = Counter(
    "firmware_unpacker_orphan_recovery_actions_total",
    "Actions taken during orphaned task recovery.",
    ("action",),
)
ORPHAN_RECOVERY_DURATION_SECONDS = Histogram(
    "firmware_unpacker_orphan_recovery_duration_seconds",
    "Duration of orphaned task recovery runs.",
)
CLEANUP_JOB_TOTAL = Counter(
    "firmware_unpacker_cleanup_job_total",
    "Workspace cleanup jobs processed.",
    ("reason", "result"),
)
CLEANUP_JOB_DURATION_SECONDS = Histogram(
    "firmware_unpacker_cleanup_job_duration_seconds",
    "Duration of workspace cleanup job processing.",
    ("reason",),
)
MAINTENANCE_OPERATIONS_TOTAL = Counter(
    "firmware_unpacker_maintenance_operations_total",
    "Maintenance operations executed by background workers.",
    ("operation", "result"),
)
MAINTENANCE_DURATION_SECONDS = Histogram(
    "firmware_unpacker_maintenance_duration_seconds",
    "Duration of maintenance operations.",
    ("operation",),
)
DISPATCH_BACKPRESSURE_TOTAL = Counter(
    "firmware_unpacker_dispatch_backpressure_total",
    "Times the dispatcher found no free local execution slots.",
)
TASKS_BY_STATUS = Gauge(
    "firmware_unpacker_tasks_by_status",
    "Current task count by status.",
    ("status",),
)
CLEANUP_JOBS_BY_STATUS = Gauge(
    "firmware_unpacker_cleanup_jobs_by_status",
    "Current workspace cleanup job count by status.",
    ("status",),
)
WORKERS_BY_STATE = Gauge(
    "firmware_unpacker_workers_by_state",
    "Current worker count by state.",
    ("state",),
)
CONCURRENCY_GAUGE = Gauge(
    "firmware_unpacker_effective_max_concurrent",
    "Effective runtime concurrency limit for the current process.",
)


@contextmanager
def observe_duration(histogram: Histogram, *labels: str) -> Iterator[None]:
    started_at = time.monotonic()
    try:
        yield
    finally:
        elapsed = max(0.0, time.monotonic() - started_at)
        if labels:
            histogram.labels(*labels).observe(elapsed)
        else:
            histogram.observe(elapsed)


def generate_metrics_payload() -> bytes:
    return generate_latest()


def metrics_content_type() -> str:
    return CONTENT_TYPE_LATEST


def record_db_retry(operation: str) -> None:
    DB_RETRY_TOTAL.labels(operation=operation).inc()


def record_db_operation_result(operation: str, result: str) -> None:
    DB_OPERATION_RESULTS_TOTAL.labels(operation=operation, result=result).inc()


def record_claim_result(*, claimed_count: int, duration_seconds: float, result: str) -> None:
    CLAIM_OPERATIONS_TOTAL.labels(result=result).inc()
    CLAIM_DURATION_SECONDS.observe(max(0.0, duration_seconds))
    if claimed_count > 0:
        CLAIMED_TASKS_TOTAL.inc(claimed_count)


def record_orphan_recovery(*, scanned_tasks: int, action_counts: dict[str, int], duration_seconds: float) -> None:
    ORPHAN_RECOVERY_DURATION_SECONDS.observe(max(0.0, duration_seconds))
    if not action_counts and scanned_tasks <= 0:
        ORPHAN_RECOVERY_ACTIONS_TOTAL.labels(action="noop").inc()
        return
    ORPHAN_RECOVERY_ACTIONS_TOTAL.labels(action="scanned_tasks").inc(max(0, int(scanned_tasks)))
    for action, count in action_counts.items():
        if count > 0:
            ORPHAN_RECOVERY_ACTIONS_TOTAL.labels(action=action).inc(int(count))


def record_cleanup_job(*, reason: str, result: str, duration_seconds: float) -> None:
    normalized_reason = str(reason or "unknown").strip() or "unknown"
    CLEANUP_JOB_TOTAL.labels(reason=normalized_reason, result=result).inc()
    CLEANUP_JOB_DURATION_SECONDS.labels(normalized_reason).observe(max(0.0, duration_seconds))


def record_maintenance_operation(*, operation: str, result: str, duration_seconds: float) -> None:
    MAINTENANCE_OPERATIONS_TOTAL.labels(operation=operation, result=result).inc()
    MAINTENANCE_DURATION_SECONDS.labels(operation).observe(max(0.0, duration_seconds))


def record_dispatch_backpressure() -> None:
    DISPATCH_BACKPRESSURE_TOTAL.inc()


def refresh_cluster_state_metrics() -> None:
    from app.model import TaskStatus, WorkerInstance, WorkspaceCleanupJob, UnpackTask, get_db_session
    from app.services.task_manager import get_concurrency_snapshot

    task_statuses = [
        TaskStatus.PENDING.value,
        TaskStatus.CLAIMED.value,
        TaskStatus.RETRY_PREPARING.value,
        TaskStatus.ARCHIVE_PENDING.value,
        TaskStatus.ARCHIVING.value,
        TaskStatus.RUNNING.value,
        TaskStatus.CANCELLING.value,
        TaskStatus.CANCELLED.value,
        TaskStatus.SUCCESS.value,
        TaskStatus.FAILED.value,
    ]
    cleanup_statuses = ["pending", "running", "success", "failed"]
    task_counts = {status: 0 for status in task_statuses}
    cleanup_counts = {status: 0 for status in cleanup_statuses}

    db = get_db_session()
    try:
        for status, count in db.query(UnpackTask.status, UnpackTask.id).all():
            task_counts[str(status)] = int(task_counts.get(str(status), 0)) + 1
        for status, count in db.query(WorkspaceCleanupJob.status, WorkspaceCleanupJob.id).all():
            cleanup_counts[str(status)] = int(cleanup_counts.get(str(status), 0)) + 1
        total_workers = int(db.query(WorkerInstance).count())
        alive_workers = int(
            db.query(WorkerInstance).filter(WorkerInstance.is_alive.is_(True)).count()
        )
    finally:
        db.close()

    for status, count in task_counts.items():
        TASKS_BY_STATUS.labels(status=status).set(int(count))
    for status, count in cleanup_counts.items():
        CLEANUP_JOBS_BY_STATUS.labels(status=status).set(int(count))
    WORKERS_BY_STATE.labels(state="total").set(total_workers)
    WORKERS_BY_STATE.labels(state="alive").set(alive_workers)
    WORKERS_BY_STATE.labels(state="dead").set(max(0, total_workers - alive_workers))
    try:
        CONCURRENCY_GAUGE.set(int(get_concurrency_snapshot()["effective_max_concurrent"]))
    except Exception as exc:
        logger.debug("failed to refresh concurrency gauge: %s", exc)
