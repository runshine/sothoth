"""Prometheus metrics for firmware unpacker runtime."""

from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from pathlib import Path
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
API_REQUESTS_TOTAL = Counter(
    "firmware_unpacker_api_requests_total",
    "Total HTTP requests handled by the firmware unpacker service.",
    ("method", "path", "status"),
)
API_REQUEST_DURATION_SECONDS = Histogram(
    "firmware_unpacker_api_request_duration_seconds",
    "HTTP request duration in seconds.",
    ("method", "path"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
TASK_LIFECYCLE_TOTAL = Counter(
    "firmware_unpacker_task_lifecycle_total",
    "Total task lifecycle transitions.",
    ("event", "status", "task_origin"),
)
TASK_DURATION_SECONDS = Histogram(
    "firmware_unpacker_task_duration_seconds",
    "Task queue wait, execution, and total durations in seconds.",
    ("phase", "status", "task_origin"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 1800, 3600, 7200),
)
TASK_STAGE_TRANSITIONS_TOTAL = Counter(
    "firmware_unpacker_task_stage_transitions_total",
    "Total task stage transitions.",
    ("stage", "task_origin"),
)
TASK_ERRORS_TOTAL = Counter(
    "firmware_unpacker_task_errors_total",
    "Total classified task errors.",
    ("category", "status", "task_origin"),
)
QUEUE_STATE_GAUGE = Gauge(
    "firmware_unpacker_queue_state",
    "Current queue and lease state counts.",
    ("state",),
)
SLOT_USAGE_GAUGE = Gauge(
    "firmware_unpacker_slot_usage",
    "Runtime slot usage and capacity gauges.",
    ("kind",),
)
TOKEN_USAGE_GAUGE = Gauge(
    "firmware_unpacker_token_usage",
    "Aggregated token usage across task artifacts.",
    ("kind",),
)
COST_USAGE_GAUGE = Gauge(
    "firmware_unpacker_cost_usage",
    "Aggregated LLM cost across task artifacts.",
    ("kind",),
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
    try:
        refresh_cluster_state_metrics()
    except Exception as exc:
        logger.debug("failed to refresh cluster state metrics before scrape: %s", exc)
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


def record_api_request(*, method: str, path: str, status_code: int, duration_seconds: float) -> None:
    status = str(int(status_code))
    normalized_method = str(method or "GET").upper()
    normalized_path = str(path or "/")
    API_REQUESTS_TOTAL.labels(normalized_method, normalized_path, status).inc()
    API_REQUEST_DURATION_SECONDS.labels(normalized_method, normalized_path).observe(max(0.0, duration_seconds))


def record_task_lifecycle(*, event: str, status: str, task_origin: str) -> None:
    TASK_LIFECYCLE_TOTAL.labels(
        str(event or "unknown"),
        str(status or "unknown"),
        str(task_origin or "unknown"),
    ).inc()


def record_task_duration(*, phase: str, duration_seconds: float | None, status: str, task_origin: str) -> None:
    if duration_seconds is None:
        return
    TASK_DURATION_SECONDS.labels(
        str(phase or "unknown"),
        str(status or "unknown"),
        str(task_origin or "unknown"),
    ).observe(max(0.0, float(duration_seconds)))


def record_task_stage_transition(*, stage: str, task_origin: str) -> None:
    TASK_STAGE_TRANSITIONS_TOTAL.labels(
        str(stage or "unknown"),
        str(task_origin or "unknown"),
    ).inc()


def record_task_error(*, category: str, status: str, task_origin: str) -> None:
    TASK_ERRORS_TOTAL.labels(
        str(category or "unknown"),
        str(status or "unknown"),
        str(task_origin or "unknown"),
    ).inc()


def _safe_int(value: object) -> int:
    try:
        if value in (None, ""):
            return 0
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _safe_float(value: object) -> float:
    try:
        if value in (None, ""):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _aggregate_token_cost_metrics(tasks: list[object]) -> dict[str, float]:
    totals = {
        "input": 0.0,
        "output": 0.0,
        "cache_read": 0.0,
        "cache_write": 0.0,
        "total_tokens": 0.0,
        "total_cost": 0.0,
    }
    for task in tasks:
        raw_run_root = str(getattr(task, "runtime_root", "") or "").strip()
        if not raw_run_root:
            continue
        run_root = Path(raw_run_root)
        tokens_summary_path = run_root / "round_000" / "tokens_summary.json"
        if not tokens_summary_path.exists():
            continue
        try:
            payload = json.loads(tokens_summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        total = payload.get("total") if isinstance(payload, dict) else {}
        if not isinstance(total, dict):
            continue
        totals["input"] += _safe_float(total.get("input"))
        totals["output"] += _safe_float(total.get("output"))
        totals["cache_read"] += _safe_float(total.get("cache_read", total.get("cacheRead")))
        totals["cache_write"] += _safe_float(total.get("cache_write", total.get("cacheWrite")))
        current_total = _safe_float(total.get("total"))
        if current_total <= 0:
            current_total = (
                _safe_float(total.get("input"))
                + _safe_float(total.get("output"))
                + _safe_float(total.get("cache_read", total.get("cacheRead")))
                + _safe_float(total.get("cache_write", total.get("cacheWrite")))
            )
        totals["total_tokens"] += current_total
        totals["total_cost"] += _safe_float(total.get("cost"))
    return totals


def refresh_cluster_state_metrics() -> None:
    from app.model import TaskStatus, WorkerInstance, WorkspaceCleanupJob, UnpackTask, get_db_session
    from app.services.task_manager import get_concurrency_snapshot, get_executor, get_local_active_task_count

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
        leased_tasks = int(
            db.query(UnpackTask)
            .filter(
                (UnpackTask.dispatch_lease_expires_at.isnot(None))
                | (UnpackTask.lease_expires_at.isnot(None))
            )
            .count()
        )
        terminal_tasks = db.query(UnpackTask).all()
    finally:
        db.close()

    for status, count in task_counts.items():
        TASKS_BY_STATUS.labels(status=status).set(int(count))
    for status, count in cleanup_counts.items():
        CLEANUP_JOBS_BY_STATUS.labels(status=status).set(int(count))
    WORKERS_BY_STATE.labels(state="total").set(total_workers)
    WORKERS_BY_STATE.labels(state="alive").set(alive_workers)
    WORKERS_BY_STATE.labels(state="dead").set(max(0, total_workers - alive_workers))
    QUEUE_STATE_GAUGE.labels(state="pending").set(int(task_counts.get(TaskStatus.PENDING.value, 0)))
    QUEUE_STATE_GAUGE.labels(state="queued").set(int(task_counts.get(TaskStatus.CLAIMED.value, 0)))
    QUEUE_STATE_GAUGE.labels(state="running").set(int(task_counts.get(TaskStatus.RUNNING.value, 0)))
    QUEUE_STATE_GAUGE.labels(state="leased").set(leased_tasks)
    QUEUE_STATE_GAUGE.labels(state="cleanup_pending").set(int(cleanup_counts.get("pending", 0)))
    try:
        snapshot = get_concurrency_snapshot()
        effective_max = int(snapshot["effective_max_concurrent"])
        CONCURRENCY_GAUGE.set(effective_max)
        SLOT_USAGE_GAUGE.labels(kind="worker_active").set(int(get_local_active_task_count()))
        SLOT_USAGE_GAUGE.labels(kind="slot_usage").set(int(get_local_active_task_count()))
        SLOT_USAGE_GAUGE.labels(kind="slot_capacity").set(effective_max)
        executor = get_executor()
        SLOT_USAGE_GAUGE.labels(kind="executor_capacity").set(int(getattr(executor, "_max_workers", effective_max)))
    except Exception as exc:
        logger.debug("failed to refresh concurrency gauge: %s", exc)
    try:
        aggregated = _aggregate_token_cost_metrics(terminal_tasks)
        TOKEN_USAGE_GAUGE.labels(kind="input").set(aggregated["input"])
        TOKEN_USAGE_GAUGE.labels(kind="output").set(aggregated["output"])
        TOKEN_USAGE_GAUGE.labels(kind="cache_read").set(aggregated["cache_read"])
        TOKEN_USAGE_GAUGE.labels(kind="cache_write").set(aggregated["cache_write"])
        TOKEN_USAGE_GAUGE.labels(kind="total").set(aggregated["total_tokens"])
        COST_USAGE_GAUGE.labels(kind="total").set(aggregated["total_cost"])
    except Exception as exc:
        logger.debug("failed to refresh token/cost gauges: %s", exc)
