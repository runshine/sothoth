"""Prometheus-style observability helpers for the Binary Security service."""

from __future__ import annotations

import threading
import time
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


API_REQUESTS_TOTAL = Counter(
    "secflow_binary_security_api_requests_total",
    "Total HTTP requests handled by the Binary Security service.",
    labelnames=("method", "path", "status"),
)

API_REQUEST_DURATION_SECONDS = Histogram(
    "secflow_binary_security_api_request_duration_seconds",
    "HTTP request duration in seconds.",
    labelnames=("method", "path"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
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

TASK_OPERATIONS_TOTAL = Counter(
    "secflow_binary_security_task_operations_total",
    "Total task-level operation requests.",
    labelnames=("action", "result"),
)

ARCHIVE_ACTIONS_TOTAL = Counter(
    "secflow_binary_security_archive_actions_total",
    "Total archive pipeline actions.",
    labelnames=("action", "result"),
)

HEARTBEAT_UPDATES_TOTAL = Counter(
    "secflow_binary_security_heartbeat_updates_total",
    "Total task heartbeat update attempts.",
    labelnames=("result",),
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

ARCHIVE_DURATION_SECONDS = Histogram(
    "secflow_binary_security_archive_duration_seconds",
    "Archive operation duration in seconds.",
    labelnames=("action", "result"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900),
)


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


def observe_api_request(method: str, path: str, status_code: int, duration_seconds: float) -> None:
    status = str(int(status_code))
    API_REQUESTS_TOTAL.labels(method=method, path=path, status=status).inc()
    API_REQUEST_DURATION_SECONDS.labels(method=method, path=path).observe(max(0.0, duration_seconds))


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


def observe_task_operation(action: str, result: str) -> None:
    TASK_OPERATIONS_TOTAL.labels(action=action, result=result).inc()


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


def observe_task_error(category: str, *, stage: str | None = None, result: str | None = None) -> None:
    TASK_ERRORS_TOTAL.labels(
        category=str(category or "unknown"),
        stage=str(stage or "none"),
        result=str(result or "unknown"),
    ).inc()


def observe_archive_action(action: str, result: str) -> None:
    ARCHIVE_ACTIONS_TOTAL.labels(action=action, result=result).inc()


def observe_archive_duration(*, action: str, result: str, duration_seconds: float | None) -> None:
    if duration_seconds is None:
        return
    ARCHIVE_DURATION_SECONDS.labels(
        action=str(action or "unknown"),
        result=str(result or "unknown"),
    ).observe(max(0.0, float(duration_seconds)))


def observe_heartbeat_update(result: str) -> None:
    HEARTBEAT_UPDATES_TOTAL.labels(result=result).inc()


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


def observe_worker_counts(*, task_workers: int, action_workers: int, archive_workers: int) -> None:
    ACTIVE_WORKERS.labels(kind="task").set(max(0, int(task_workers)))
    ACTIVE_WORKERS.labels(kind="action").set(max(0, int(action_workers)))
    ACTIVE_WORKERS.labels(kind="archive").set(max(0, int(archive_workers)))


def observe_queue_depths(
    *,
    pending_tasks: int,
    running_tasks: int,
    preparing_tasks: int,
    archive_pending_jobs: int,
    archive_running_jobs: int,
    archive_applying_jobs: int,
    reconcile_candidates: int,
    redis_task_queue: int = 0,
    redis_action_queue: int = 0,
    leased_tasks: int = 0,
    task_queue_oldest_age_seconds: float | None = None,
    action_queue_oldest_age_seconds: float | None = None,
) -> None:
    QUEUE_DEPTH.labels(queue="task_pending").set(max(0, int(pending_tasks)))
    QUEUE_DEPTH.labels(queue="task_running").set(max(0, int(running_tasks)))
    QUEUE_DEPTH.labels(queue="task_preparing").set(max(0, int(preparing_tasks)))
    QUEUE_DEPTH.labels(queue="task_queued").set(max(0, int(redis_task_queue)))
    QUEUE_DEPTH.labels(queue="action_queued").set(max(0, int(redis_action_queue)))
    QUEUE_DEPTH.labels(queue="task_leased").set(max(0, int(leased_tasks)))
    QUEUE_DEPTH.labels(queue="archive_pending").set(max(0, int(archive_pending_jobs)))
    QUEUE_DEPTH.labels(queue="archive_running").set(max(0, int(archive_running_jobs)))
    QUEUE_DEPTH.labels(queue="archive_applying").set(max(0, int(archive_applying_jobs)))
    QUEUE_DEPTH.labels(queue="downstream_reconcile_candidates").set(max(0, int(reconcile_candidates)))
    QUEUE_AGE_SECONDS.labels(queue="task_queued").set(max(0.0, float(task_queue_oldest_age_seconds or 0.0)))
    QUEUE_AGE_SECONDS.labels(queue="action_queued").set(max(0.0, float(action_queue_oldest_age_seconds or 0.0)))


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
