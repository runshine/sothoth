"""Prometheus-style observability helpers for the Binary Security service."""

from __future__ import annotations

import threading
import time
import re
from contextlib import contextmanager
from typing import Iterator

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
except ImportError:  # pragma: no cover - exercised indirectly in current dev env
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    class _BaseMetric:
        def __init__(self, name: str, documentation: str, labelnames=(), buckets=None):
            self.name = name
            self.documentation = documentation
            self.labelnames = tuple(labelnames or ())
            self.buckets = tuple(buckets or ())
            self._lock = threading.Lock()
            self._samples: dict[tuple[str, ...], float] = {}

        def labels(self, **labels):
            key = tuple(str(labels.get(label, "")) for label in self.labelnames)
            return _BoundMetric(self, key)

        def _inc(self, key: tuple[str, ...], value: float) -> None:
            with self._lock:
                self._samples[key] = float(self._samples.get(key, 0.0)) + float(value)

        def _set(self, key: tuple[str, ...], value: float) -> None:
            with self._lock:
                self._samples[key] = float(value)

        def _observe(self, key: tuple[str, ...], value: float) -> None:
            self._inc(key, value)

        def _render(self, metric_type: str) -> list[str]:
            lines = [
                f"# HELP {self.name} {self.documentation}",
                f"# TYPE {self.name} {metric_type}",
            ]
            with self._lock:
                for key, value in sorted(self._samples.items()):
                    if self.labelnames:
                        labels = ",".join(
                            f'{label}="{val}"' for label, val in zip(self.labelnames, key)
                        )
                        lines.append(f"{self.name}{{{labels}}} {value}")
                    else:
                        lines.append(f"{self.name} {value}")
            return lines

    class _BoundMetric:
        def __init__(self, metric: _BaseMetric, key: tuple[str, ...]):
            self.metric = metric
            self.key = key

        def inc(self, value: float = 1.0) -> None:
            self.metric._inc(self.key, value)

        def dec(self, value: float = 1.0) -> None:
            self.metric._inc(self.key, -float(value))

        def set(self, value: float) -> None:
            self.metric._set(self.key, value)

        def observe(self, value: float) -> None:
            self.metric._observe(self.key, value)

    _FALLBACK_METRICS: list[tuple[_BaseMetric, str]] = []

    class Counter(_BaseMetric):
        def __init__(self, name: str, documentation: str, labelnames=()):
            super().__init__(name, documentation, labelnames=labelnames)
            _FALLBACK_METRICS.append((self, "counter"))

    class Gauge(_BaseMetric):
        def __init__(self, name: str, documentation: str, labelnames=()):
            super().__init__(name, documentation, labelnames=labelnames)
            _FALLBACK_METRICS.append((self, "gauge"))

    class Histogram(_BaseMetric):
        def __init__(self, name: str, documentation: str, labelnames=(), buckets=None):
            super().__init__(name, documentation, labelnames=labelnames, buckets=buckets)
            _FALLBACK_METRICS.append((self, "histogram"))

    def generate_latest() -> bytes:
        payload: list[str] = []
        for metric, metric_type in _FALLBACK_METRICS:
            payload.extend(metric._render(metric_type))
        return ("\n".join(payload) + "\n").encode("utf-8")


HTTP_REQUESTS_TOTAL = Counter(
    "secflow_binary_security_http_requests_total",
    "Total normalized HTTP requests handled by the Binary Security service.",
    labelnames=("method", "route", "status_class", "status_code"),
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "secflow_binary_security_http_request_duration_seconds",
    "Normalized HTTP request duration in seconds.",
    labelnames=("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
HTTP_REQUEST_INFLIGHT = Gauge(
    "secflow_binary_security_http_request_inflight",
    "Current inflight HTTP requests.",
    labelnames=("method", "route"),
)

SCHEDULER_LOOP_ITERATIONS_TOTAL = Counter(
    "secflow_binary_security_scheduler_loop_iterations_total",
    "Total scheduler loop iterations.",
    labelnames=("loop",),
)

SCHEDULER_LOOP_ERRORS_TOTAL = Counter(
    "secflow_binary_security_scheduler_loop_errors_total",
    "Total scheduler loop errors.",
    labelnames=("loop",),
)

SCHEDULER_LOOP_DURATION_SECONDS = Histogram(
    "secflow_binary_security_scheduler_loop_duration_seconds",
    "Duration of scheduler loop body execution in seconds.",
    labelnames=("loop",),
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
)
TASK_READLESS_RECONCILE_TASKS_TOTAL = Counter(
    "secflow_binary_security_task_readless_reconcile_tasks_total",
    "Total tasks processed by the background readless reconcile loop.",
    labelnames=("result",),
)
TASK_READLESS_RECONCILE_CANDIDATES = Gauge(
    "secflow_binary_security_task_readless_reconcile_candidates",
    "Current number of tasks eligible for background readless reconciliation.",
)
TASK_READLESS_RECONCILE_LAST_ATTEMPTED = Gauge(
    "secflow_binary_security_task_readless_reconcile_last_attempted",
    "Number of tasks attempted in the last readless reconcile loop iteration.",
)
TASK_READLESS_RECONCILE_LAST_CHANGED = Gauge(
    "secflow_binary_security_task_readless_reconcile_last_changed",
    "Number of tasks changed in the last readless reconcile loop iteration.",
)
TASK_READLESS_RECONCILE_LAST_FAILED = Gauge(
    "secflow_binary_security_task_readless_reconcile_last_failed",
    "Number of tasks failed in the last readless reconcile loop iteration.",
)
TASK_READLESS_RECONCILE_LAST_RUN_TIMESTAMP = Gauge(
    "secflow_binary_security_task_readless_reconcile_last_run_timestamp",
    "Unix timestamp of the last readless reconcile loop run.",
)

TASK_OPERATIONS_TOTAL = Counter(
    "secflow_binary_security_task_operations_total",
    "Total task-level operation requests.",
    labelnames=("action", "result"),
)
CONTROL_OPERATIONS_TOTAL = Counter(
    "secflow_binary_security_operations_total",
    "Total control-plane task operations by type and status.",
    labelnames=("operation_type", "status"),
)
CONTROL_OPERATION_RUNNING_SECONDS = Histogram(
    "secflow_binary_security_operation_running_seconds",
    "Observed wall-clock duration of control-plane task operations.",
    labelnames=("operation_type", "status"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 1800, 3600),
)
CONTROL_OPERATION_LEASE_LOST_TOTAL = Counter(
    "secflow_binary_security_operation_lease_lost_total",
    "Total control-plane task operations that lost ownership or heartbeat.",
    labelnames=("operation_type",),
)
CONTROL_OPERATION_STEP_RETRIES_TOTAL = Counter(
    "secflow_binary_security_operation_step_retries_total",
    "Total operation step retries by operation type and step.",
    labelnames=("operation_type", "step"),
)
CONTROL_OPERATION_SUPERSEDED_TOTAL = Counter(
    "secflow_binary_security_operation_superseded_total",
    "Total control-plane task operations superseded by another operation.",
    labelnames=("operation_type",),
)

ARCHIVE_ACTIONS_TOTAL = Counter(
    "secflow_binary_security_archive_actions_total",
    "Total archive pipeline actions.",
    labelnames=("action", "result"),
)
ARCHIVE_RECLAIM_TOTAL = Counter(
    "secflow_binary_security_archive_reclaim_total",
    "Total archive reclaim observations and resolutions.",
    labelnames=("result",),
)

HEARTBEAT_UPDATES_TOTAL = Counter(
    "secflow_binary_security_heartbeat_updates_total",
    "Total task heartbeat update attempts.",
    labelnames=("result",),
)
DISPATCH_RECLAIM_TOTAL = Counter(
    "secflow_binary_security_dispatch_reclaim_total",
    "Total parent task dispatch reclaim outcomes by reason.",
    labelnames=("reason",),
)
RUNNING_REQUEUE_TOTAL = Counter(
    "secflow_binary_security_running_requeue_total",
    "Total running-task requeue outcomes by reason.",
    labelnames=("reason",),
)
RUNTIME_LEASE_OWNER_MISMATCH_TOTAL = Counter(
    "secflow_binary_security_runtime_lease_owner_mismatch_total",
    "Total runtime lease owner mismatch or stale-owner recoveries.",
    labelnames=("reason",),
)
STREAMING_PARENT_RECOVERED_TOTAL = Counter(
    "secflow_binary_security_streaming_parent_recovered_total",
    "Total streaming-tail parent state recoveries.",
    labelnames=("stage", "from_status"),
)
TASK_HEARTBEAT_CANDIDATES = Gauge(
    "secflow_binary_security_task_heartbeat_candidates",
    "Current number of task heartbeat candidates owned by this pod.",
)
TASK_HEARTBEAT_LOOP_DURATION_SECONDS = Histogram(
    "secflow_binary_security_task_heartbeat_loop_duration_seconds",
    "Duration of a task heartbeat controller loop iteration in seconds.",
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
)

ACTIVE_WORKERS = Gauge(
    "secflow_binary_security_active_workers",
    "Current number of in-memory active workers by kind.",
    labelnames=("kind",),
)

QUEUE_DEPTH = Gauge(
    "secflow_binary_security_queue_depth",
    "Current queue depth / backlog by queue type.",
    labelnames=("queue",),
)

QUEUE_AGE_SECONDS = Gauge(
    "secflow_binary_security_queue_oldest_age_seconds",
    "Age in seconds of the oldest queued item by queue type.",
    labelnames=("queue",),
)

SLOT_USAGE = Gauge(
    "secflow_binary_security_slot_usage",
    "Current worker slot usage and configured capacity.",
    labelnames=("kind",),
)

TASK_LIFECYCLE_TOTAL = Counter(
    "secflow_binary_security_task_lifecycle_total",
    "Total task lifecycle transitions.",
    labelnames=("event", "status", "task_type"),
)

TASK_DURATION_SECONDS = Histogram(
    "secflow_binary_security_task_duration_seconds",
    "Observed task lifecycle durations in seconds.",
    labelnames=("phase", "status", "task_type"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 1800, 3600, 7200),
)

TASK_LIST_QUERIES_TOTAL = Counter(
    "secflow_binary_security_task_list_queries_total",
    "Total task list query executions.",
    labelnames=("result", "task_type"),
)

TASK_LIST_QUERY_DURATION_SECONDS = Histogram(
    "secflow_binary_security_task_list_query_duration_seconds",
    "Task list query duration in seconds.",
    labelnames=("result", "task_type"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)

TASK_LIST_QUERY_STAGE_DURATION_SECONDS = Histogram(
    "secflow_binary_security_task_list_query_stage_duration_seconds",
    "Task list query stage duration in seconds.",
    labelnames=("stage", "task_type"),
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)

TASK_ERRORS_TOTAL = Counter(
    "secflow_binary_security_task_errors_total",
    "Total classified task and downstream errors.",
    labelnames=("category", "stage", "result"),
)

DOWNSTREAM_REQUESTS_TOTAL = Counter(
    "secflow_binary_security_downstream_requests_total",
    "Total downstream HTTP requests.",
    labelnames=("service", "method", "operation", "status"),
)

DOWNSTREAM_REQUEST_DURATION_SECONDS = Histogram(
    "secflow_binary_security_downstream_request_duration_seconds",
    "Downstream HTTP request duration in seconds.",
    labelnames=("service", "method", "operation"),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120),
)

AUTH_TOKEN_VALIDATIONS_TOTAL = Counter(
    "secflow_binary_security_auth_token_validations_total",
    "Total token validation attempts against the auth service.",
    labelnames=("result", "source"),
)

AUTH_TOKEN_CACHE_EVENTS_TOTAL = Counter(
    "secflow_binary_security_auth_token_cache_events_total",
    "Total auth token cache events.",
    labelnames=("result",),
)

AUTH_TOKEN_CACHE_ENTRIES = Gauge(
    "secflow_binary_security_auth_token_cache_entries",
    "Current number of cached auth tokens.",
)

STAGE_DURATION_SECONDS = Histogram(
    "secflow_binary_security_stage_duration_seconds",
    "Stage execution duration in seconds.",
    labelnames=("stage", "result"),
    buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 1800, 3600),
)
AI_ROLE_COUNT = Gauge(
    "secflow_binary_security_ai_role_count",
    "Aggregated AI-oriented orchestration role counts.",
    labelnames=("role",),
)
AI_ROUND_TOTAL = Counter(
    "secflow_binary_security_ai_round_total",
    "Aggregated AI-oriented orchestration rounds.",
    labelnames=("kind",),
)
AI_RETRY_TOTAL = Counter(
    "secflow_binary_security_ai_retry_total",
    "Aggregated AI-oriented orchestration retries.",
    labelnames=("reason",),
)
AI_FAILURE_TOTAL = Counter(
    "secflow_binary_security_ai_failure_total",
    "Aggregated AI-oriented orchestration failures.",
    labelnames=("category",),
)

ARCHIVE_DURATION_SECONDS = Histogram(
    "secflow_binary_security_archive_duration_seconds",
    "Archive operation duration in seconds.",
    labelnames=("action", "result"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900),
)

STATE_EVENTS_TOTAL = Counter(
    "secflow_binary_security_state_events_total",
    "Total state reducer events by event type and enqueue result.",
    labelnames=("event_type", "result"),
)

STATE_EVENT_QUEUE_DEPTH = Gauge(
    "secflow_binary_security_state_event_queue_depth",
    "Current state event queue depth by status.",
    labelnames=("status",),
)

STATE_EVENT_OLDEST_AGE_SECONDS = Gauge(
    "secflow_binary_security_state_event_oldest_age_seconds",
    "Age in seconds of the oldest state event by status.",
    labelnames=("status",),
)

STATE_EVENT_LAG_SECONDS = Histogram(
    "secflow_binary_security_state_event_lag_seconds",
    "State event lag from creation to reducer processing.",
    labelnames=("event_type",),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 1800),
)

STATE_REDUCER_RUNS_TOTAL = Counter(
    "secflow_binary_security_state_reducer_runs_total",
    "Total state reducer runs by result and pod.",
    labelnames=("result", "pod"),
)

STATE_REDUCER_EVENTS_TOTAL = Counter(
    "secflow_binary_security_state_reducer_events_total",
    "Total state reducer event applications.",
    labelnames=("event_type", "result"),
)

STATE_REDUCER_DURATION_SECONDS = Histogram(
    "secflow_binary_security_state_reducer_duration_seconds",
    "State reducer run duration in seconds.",
    labelnames=("result",),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)

STATE_REDUCER_HEALTH = Gauge(
    "secflow_binary_security_state_reducer_health",
    "Reducer heartbeat, crash and event-processing health signals by pod.",
    labelnames=("pod", "signal"),
)

TASK_STATE_LOCK_WAIT_SECONDS = Histogram(
    "secflow_binary_security_task_state_lock_wait_seconds",
    "Task state reducer lock wait duration in seconds.",
    labelnames=("operation",),
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

TASK_STATE_LOCK_HELD_SECONDS = Histogram(
    "secflow_binary_security_task_state_lock_held_seconds",
    "Task state reducer lock held duration in seconds.",
    labelnames=("operation",),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)

TASK_STATE_LOCK_ACTIVE = Gauge(
    "secflow_binary_security_task_state_lock_active",
    "Current active task state reducer locks.",
    labelnames=("operation",),
)

STATE_DEAD_LETTERS_TOTAL = Counter(
    "secflow_binary_security_state_dead_letters_total",
    "Total state events moved to dead letter.",
    labelnames=("event_type", "reason"),
)

STATE_FILE_WRITES_TOTAL = Counter(
    "secflow_binary_security_state_file_writes_total",
    "Total reducer-owned file writes.",
    labelnames=("target", "result"),
)

STATE_FILE_WRITE_DURATION_SECONDS = Histogram(
    "secflow_binary_security_state_file_write_duration_seconds",
    "Reducer-owned file write duration in seconds.",
    labelnames=("target", "result"),
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)

ARCHIVE_JOBS_BY_STATUS = Gauge(
    "secflow_binary_security_archive_jobs_by_status",
    "Current archive jobs by stage and status.",
    labelnames=("stage", "status"),
)

DOWNSTREAM_RECONCILE_OBSERVATIONS_TOTAL = Counter(
    "secflow_binary_security_downstream_reconcile_observations_total",
    "Total downstream reconcile observations.",
    labelnames=("stage", "service", "result"),
)

_PATH_ID_SEGMENT_RE = re.compile(r"/(?:\d+|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)", re.IGNORECASE)


def normalize_http_route(path: str | None) -> str:
    raw = str(path or "/").strip() or "/"
    return _PATH_ID_SEGMENT_RE.sub("/{id}", raw)


def http_status_class(status_code: int | str | None) -> str:
    try:
        code = int(status_code or 500)
    except (TypeError, ValueError):
        code = 500
    if code < 0:
        return "cancelled"
    return f"{code // 100}xx"


def observe_http_request_inflight(method: str, route: str, delta: int) -> None:
    HTTP_REQUEST_INFLIGHT.labels(method=str(method or "GET").upper(), route=normalize_http_route(route)).inc(delta)


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


def observe_http_request(method: str, path: str, status_code: int, duration_seconds: float) -> None:
    status = str(int(status_code))
    normalized_method = str(method or "GET").upper()
    normalized_route = normalize_http_route(path)
    HTTP_REQUESTS_TOTAL.labels(
        method=normalized_method,
        route=normalized_route,
        status_class=http_status_class(status_code),
        status_code=status,
    ).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=normalized_method, route=normalized_route).observe(max(0.0, duration_seconds))


@contextmanager
def observe_scheduler_loop(loop_name: str) -> Iterator[None]:
    started = time.perf_counter()
    try:
        yield
    except Exception:
        SCHEDULER_LOOP_ERRORS_TOTAL.labels(loop=loop_name).inc()
        raise
    finally:
        SCHEDULER_LOOP_ITERATIONS_TOTAL.labels(loop=loop_name).inc()
        SCHEDULER_LOOP_DURATION_SECONDS.labels(loop=loop_name).observe(max(0.0, time.perf_counter() - started))


def observe_task_readless_reconcile(*, attempted: int, changed: int, failed: int, candidates: int) -> None:
    TASK_READLESS_RECONCILE_TASKS_TOTAL.labels(result="attempted").inc(max(0, int(attempted)))
    TASK_READLESS_RECONCILE_TASKS_TOTAL.labels(result="changed").inc(max(0, int(changed)))
    TASK_READLESS_RECONCILE_TASKS_TOTAL.labels(result="failed").inc(max(0, int(failed)))
    TASK_READLESS_RECONCILE_CANDIDATES.set(max(0, int(candidates)))
    TASK_READLESS_RECONCILE_LAST_ATTEMPTED.set(max(0, int(attempted)))
    TASK_READLESS_RECONCILE_LAST_CHANGED.set(max(0, int(changed)))
    TASK_READLESS_RECONCILE_LAST_FAILED.set(max(0, int(failed)))
    TASK_READLESS_RECONCILE_LAST_RUN_TIMESTAMP.set(time.time())


def observe_task_operation(action: str, result: str) -> None:
    TASK_OPERATIONS_TOTAL.labels(action=action, result=result).inc()
    action_key = str(action or "unknown")
    result_key = str(result or "unknown")
    if result_key == "accepted" and action_key in {"continue", "retry"}:
        AI_RETRY_TOTAL.labels(reason=action_key).inc()
    if action_key in {"module_selection", "confirm_module_selection"} and result_key == "accepted":
        AI_ROUND_TOTAL.labels(kind="selection").inc()


def observe_control_operation(operation_type: str, status: str) -> None:
    CONTROL_OPERATIONS_TOTAL.labels(
        operation_type=str(operation_type or "unknown"),
        status=str(status or "unknown"),
    ).inc()


def observe_control_operation_duration(*, operation_type: str, status: str, duration_seconds: float | None) -> None:
    if duration_seconds is None:
        return
    CONTROL_OPERATION_RUNNING_SECONDS.labels(
        operation_type=str(operation_type or "unknown"),
        status=str(status or "unknown"),
    ).observe(max(0.0, float(duration_seconds)))


def observe_control_operation_lease_lost(operation_type: str) -> None:
    CONTROL_OPERATION_LEASE_LOST_TOTAL.labels(operation_type=str(operation_type or "unknown")).inc()


def observe_control_operation_step_retry(*, operation_type: str, step: str) -> None:
    CONTROL_OPERATION_STEP_RETRIES_TOTAL.labels(
        operation_type=str(operation_type or "unknown"),
        step=str(step or "unknown"),
    ).inc()


def observe_control_operation_superseded(operation_type: str) -> None:
    CONTROL_OPERATION_SUPERSEDED_TOTAL.labels(operation_type=str(operation_type or "unknown")).inc()


def observe_task_lifecycle(event: str, *, status: str, task_type: str) -> None:
    TASK_LIFECYCLE_TOTAL.labels(
        event=str(event or "unknown"),
        status=str(status or "unknown"),
        task_type=str(task_type or "unknown"),
    ).inc()


def observe_task_duration(*, phase: str, duration_seconds: float | None, status: str, task_type: str) -> None:
    if duration_seconds is None:
        return
    TASK_DURATION_SECONDS.labels(
        phase=str(phase or "unknown"),
        status=str(status or "unknown"),
        task_type=str(task_type or "unknown"),
    ).observe(max(0.0, float(duration_seconds)))


def observe_task_list_query(*, result: str, task_type: str, duration_seconds: float | None) -> None:
    result_value = str(result or "unknown")
    task_type_value = str(task_type or "all")
    TASK_LIST_QUERIES_TOTAL.labels(result=result_value, task_type=task_type_value).inc()
    if duration_seconds is not None:
        TASK_LIST_QUERY_DURATION_SECONDS.labels(result=result_value, task_type=task_type_value).observe(max(0.0, float(duration_seconds)))


def observe_task_list_query_stage(*, stage: str, task_type: str, duration_seconds: float | None) -> None:
    stage_value = str(stage or "unknown")
    task_type_value = str(task_type or "all")
    if duration_seconds is not None:
        TASK_LIST_QUERY_STAGE_DURATION_SECONDS.labels(
            stage=stage_value,
            task_type=task_type_value,
        ).observe(max(0.0, float(duration_seconds)))


def observe_task_error(category: str, *, stage: str | None = None, result: str | None = None) -> None:
    category_value = str(category or "unknown")
    TASK_ERRORS_TOTAL.labels(
        category=category_value,
        stage=str(stage or "none"),
        result=str(result or "unknown"),
    ).inc()
    AI_FAILURE_TOTAL.labels(category=_ai_failure_category(category_value, result)).inc()


def observe_archive_action(action: str, result: str) -> None:
    ARCHIVE_ACTIONS_TOTAL.labels(action=action, result=result).inc()


def observe_archive_duration(*, action: str, result: str, duration_seconds: float | None) -> None:
    if duration_seconds is None:
        return
    ARCHIVE_DURATION_SECONDS.labels(
        action=str(action or "unknown"),
        result=str(result or "unknown"),
    ).observe(max(0.0, float(duration_seconds)))


def observe_archive_reclaim(result: str) -> None:
    ARCHIVE_RECLAIM_TOTAL.labels(result=str(result or "unknown")).inc()


def observe_heartbeat_update(result: str) -> None:
    HEARTBEAT_UPDATES_TOTAL.labels(result=result).inc()


def observe_dispatch_reclaim(reason: str) -> None:
    DISPATCH_RECLAIM_TOTAL.labels(reason=str(reason or "unknown")).inc()


def observe_running_requeue(reason: str) -> None:
    RUNNING_REQUEUE_TOTAL.labels(reason=str(reason or "unknown")).inc()


def observe_runtime_lease_owner_mismatch(reason: str) -> None:
    RUNTIME_LEASE_OWNER_MISMATCH_TOTAL.labels(reason=str(reason or "unknown")).inc()


def observe_streaming_parent_recovered(*, stage: str, from_status: str) -> None:
    STREAMING_PARENT_RECOVERED_TOTAL.labels(
        stage=str(stage or "unknown"),
        from_status=str(from_status or "unknown"),
    ).inc()


def observe_task_heartbeat_candidates(count: int) -> None:
    TASK_HEARTBEAT_CANDIDATES.set(max(0, int(count)))


def observe_task_heartbeat_loop_duration(duration_seconds: float | None) -> None:
    if duration_seconds is None:
        return
    TASK_HEARTBEAT_LOOP_DURATION_SECONDS.observe(max(0.0, float(duration_seconds)))


def observe_downstream_request(
    *,
    service: str,
    method: str,
    operation: str,
    status: str,
    duration_seconds: float | None,
) -> None:
    DOWNSTREAM_REQUESTS_TOTAL.labels(
        service=str(service or "unknown"),
        method=str(method or "UNKNOWN").upper(),
        operation=str(operation or "unknown"),
        status=str(status or "unknown"),
    ).inc()
    if duration_seconds is not None:
        DOWNSTREAM_REQUEST_DURATION_SECONDS.labels(
            service=str(service or "unknown"),
            method=str(method or "UNKNOWN").upper(),
            operation=str(operation or "unknown"),
        ).observe(max(0.0, float(duration_seconds)))


def observe_auth_token_validation(*, result: str, source: str = "auth_service") -> None:
    AUTH_TOKEN_VALIDATIONS_TOTAL.labels(
        result=str(result or "unknown"),
        source=str(source or "auth_service"),
    ).inc()


def observe_auth_token_cache(*, result: str, entries: int | None = None) -> None:
    AUTH_TOKEN_CACHE_EVENTS_TOTAL.labels(result=str(result or "unknown")).inc()
    if entries is not None:
        AUTH_TOKEN_CACHE_ENTRIES.set(max(0, int(entries)))


def observe_worker_counts(*, task_workers: int, operation_workers: int, archive_workers: int) -> None:
    ACTIVE_WORKERS.labels(kind="task").set(max(0, int(task_workers)))
    ACTIVE_WORKERS.labels(kind="operation").set(max(0, int(operation_workers)))
    ACTIVE_WORKERS.labels(kind="archive").set(max(0, int(archive_workers)))


def observe_queue_depths(
    *,
    pending_tasks: int,
    running_tasks: int,
    archive_pending_jobs: int,
    archive_running_jobs: int,
    archive_applying_jobs: int,
    reconcile_candidates: int,
    redis_task_queue: int = 0,
    redis_operation_queue: int = 0,
    leased_tasks: int = 0,
    task_queue_oldest_age_seconds: float | None = None,
    operation_queue_oldest_age_seconds: float | None = None,
) -> None:
    QUEUE_DEPTH.labels(queue="task_pending").set(max(0, int(pending_tasks)))
    QUEUE_DEPTH.labels(queue="task_running").set(max(0, int(running_tasks)))
    QUEUE_DEPTH.labels(queue="task_queued").set(max(0, int(redis_task_queue)))
    QUEUE_DEPTH.labels(queue="operation_queued").set(max(0, int(redis_operation_queue)))
    QUEUE_DEPTH.labels(queue="task_leased").set(max(0, int(leased_tasks)))
    QUEUE_DEPTH.labels(queue="archive_pending").set(max(0, int(archive_pending_jobs)))
    QUEUE_DEPTH.labels(queue="archive_running").set(max(0, int(archive_running_jobs)))
    QUEUE_DEPTH.labels(queue="archive_applying").set(max(0, int(archive_applying_jobs)))
    QUEUE_DEPTH.labels(queue="downstream_reconcile_candidates").set(max(0, int(reconcile_candidates)))
    QUEUE_AGE_SECONDS.labels(queue="task_queued").set(max(0.0, float(task_queue_oldest_age_seconds or 0.0)))
    QUEUE_AGE_SECONDS.labels(queue="operation_queued").set(max(0.0, float(operation_queue_oldest_age_seconds or 0.0)))
    AI_ROLE_COUNT.labels(role="agent").set(max(0, int(running_tasks)))
    AI_ROLE_COUNT.labels(role="worker").set(max(0, int(redis_operation_queue)))
    AI_ROLE_COUNT.labels(role="advisor").set(max(0, int(reconcile_candidates)))


def observe_slot_usage(*, task_active: int, task_capacity: int, action_active: int, action_capacity: int) -> None:
    SLOT_USAGE.labels(kind="task_active").set(max(0, int(task_active)))
    SLOT_USAGE.labels(kind="task_capacity").set(max(0, int(task_capacity)))
    SLOT_USAGE.labels(kind="action_active").set(max(0, int(action_active)))
    SLOT_USAGE.labels(kind="action_capacity").set(max(0, int(action_capacity)))


def observe_stage_duration(*, stage: str, result: str, duration_seconds: float | None) -> None:
    if duration_seconds is None:
        return
    STAGE_DURATION_SECONDS.labels(
        stage=str(stage or "unknown"),
        result=str(result or "unknown"),
    ).observe(max(0.0, float(duration_seconds)))
    if str(result or "unknown") in {"success", "partial_success", "completed"}:
        AI_ROUND_TOTAL.labels(kind="selection" if str(stage or "") == "system_analysis" else "round").inc()


def observe_state_event(event_type: str, result: str) -> None:
    STATE_EVENTS_TOTAL.labels(event_type=str(event_type or "unknown"), result=str(result or "unknown")).inc()


def observe_state_event_queues(*, status_counts: dict[str, int], oldest_ages: dict[str, float]) -> None:
    statuses = set(status_counts) | set(oldest_ages) | {"pending", "processing", "retryable", "processed", "dead_letter"}
    for status in statuses:
        STATE_EVENT_QUEUE_DEPTH.labels(status=str(status)).set(max(0, int(status_counts.get(status, 0))))
        STATE_EVENT_OLDEST_AGE_SECONDS.labels(status=str(status)).set(max(0.0, float(oldest_ages.get(status, 0.0))))


def observe_state_event_lag(event_type: str, duration_seconds: float | None) -> None:
    if duration_seconds is None:
        return
    STATE_EVENT_LAG_SECONDS.labels(event_type=str(event_type or "unknown")).observe(max(0.0, float(duration_seconds)))


def observe_state_reducer_run(*, result: str, pod: str, duration_seconds: float | None) -> None:
    STATE_REDUCER_RUNS_TOTAL.labels(result=str(result or "unknown"), pod=str(pod or "unknown")).inc()
    if duration_seconds is not None:
        STATE_REDUCER_DURATION_SECONDS.labels(result=str(result or "unknown")).observe(max(0.0, float(duration_seconds)))


def observe_state_reducer_event(event_type: str, result: str) -> None:
    STATE_REDUCER_EVENTS_TOTAL.labels(event_type=str(event_type or "unknown"), result=str(result or "unknown")).inc()


def observe_state_reducer_health(
    *,
    pod: str,
    loop_ok_at: float | None = None,
    event_processed_at: float | None = None,
    crash_at: float | None = None,
    consecutive_crash_count: int | None = None,
) -> None:
    pod_value = str(pod or "unknown")
    if loop_ok_at is not None:
        STATE_REDUCER_HEALTH.labels(pod=pod_value, signal="loop_ok_at").set(max(0.0, float(loop_ok_at)))
    if event_processed_at is not None:
        STATE_REDUCER_HEALTH.labels(pod=pod_value, signal="event_processed_at").set(max(0.0, float(event_processed_at)))
    if crash_at is not None:
        STATE_REDUCER_HEALTH.labels(pod=pod_value, signal="crash_at").set(max(0.0, float(crash_at)))
    if consecutive_crash_count is not None:
        STATE_REDUCER_HEALTH.labels(pod=pod_value, signal="consecutive_crash_count").set(max(0, int(consecutive_crash_count)))


def observe_task_state_lock(*, operation: str, wait_seconds: float | None = None, held_seconds: float | None = None, active: int | None = None) -> None:
    operation_value = str(operation or "unknown")
    if wait_seconds is not None:
        TASK_STATE_LOCK_WAIT_SECONDS.labels(operation=operation_value).observe(max(0.0, float(wait_seconds)))
    if held_seconds is not None:
        TASK_STATE_LOCK_HELD_SECONDS.labels(operation=operation_value).observe(max(0.0, float(held_seconds)))
    if active is not None:
        TASK_STATE_LOCK_ACTIVE.labels(operation=operation_value).set(max(0, int(active)))


def observe_state_dead_letter(event_type: str, reason: str) -> None:
    STATE_DEAD_LETTERS_TOTAL.labels(event_type=str(event_type or "unknown"), reason=str(reason or "unknown")).inc()


def observe_state_file_write(*, target: str, result: str, duration_seconds: float | None = None) -> None:
    target_value = str(target or "unknown")
    result_value = str(result or "unknown")
    STATE_FILE_WRITES_TOTAL.labels(target=target_value, result=result_value).inc()
    if duration_seconds is not None:
        STATE_FILE_WRITE_DURATION_SECONDS.labels(target=target_value, result=result_value).observe(max(0.0, float(duration_seconds)))


def observe_archive_job_statuses(status_counts: dict[tuple[str, str], int]) -> None:
    for (stage, status), count in status_counts.items():
        ARCHIVE_JOBS_BY_STATUS.labels(stage=str(stage or "unknown"), status=str(status or "unknown")).set(max(0, int(count)))


def observe_downstream_reconcile_observation(*, stage: str | None, service: str | None, result: str) -> None:
    DOWNSTREAM_RECONCILE_OBSERVATIONS_TOTAL.labels(
        stage=str(stage or "none"),
        service=str(service or "none"),
        result=str(result or "unknown"),
    ).inc()


def _ai_failure_category(category: str, result: str | None) -> str:
    text = f"{category} {result or ''}".lower()
    if "timeout" in text:
        return "timeout"
    if "cancel" in text:
        return "cancel"
    if "quota" in text:
        return "quota"
    if "validation" in text or "quality" in text:
        return "quality"
    if "model" in text:
        return "model"
    if "business" in text or "module" in text:
        return "business"
    if "runtime" in text or "error" in text or "failed" in text or "retry" in text:
        return "runtime"
    return "unknown"
