from __future__ import annotations

import math
import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fastapi import Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.database import (
    RunIndex,
    RunIndexCycle,
    RunIndexSession,
    SchedulerWorker,
    TriggerTask,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.observability.service_ops import emit_service_operation_metrics
from app.services.execution_service import _ACTIVE_RUN_INDEX_STATUSES
from app.services.run_index_service import _load_externalized_json_payload, _load_externalized_mapping_payload
from app.services.scheduler import ACTIVE_JOB_STATUSES, get_scheduler_service

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
HTTP_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, math.inf)
NORMALIZED_HTTP_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, math.inf)
_PATH_ID_SEGMENT_RE = re.compile(r"/(?:\d+|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f-]{27,})(?=/|$)", re.IGNORECASE)


def _sanitize_label_value(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"")


def _format_value(value: float | int) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return f"{float(value):.12g}"


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


class MetricsBuilder:
    def __init__(self) -> None:
        self._entries: dict[str, dict[str, Any]] = {}
        self._families: dict[str, dict[str, Any]] = {}

    def metric(self, name: str, metric_type: str, help_text: str) -> None:
        self._entries.setdefault(name, {"type": metric_type, "help": help_text, "samples": []})

    def family(self, name: str, metric_type: str, help_text: str) -> None:
        self._families.setdefault(name, {"type": metric_type, "help": help_text, "samples": []})

    def sample(self, name: str, value: float | int, labels: dict[str, Any] | None = None) -> None:
        entry = self._entries.setdefault(name, {"type": "gauge", "help": name, "samples": []})
        entry["samples"].append((dict(labels or {}), value))

    def family_sample(
        self,
        family_name: str,
        sample_name: str,
        value: float | int,
        labels: dict[str, Any] | None = None,
    ) -> None:
        entry = self._families.setdefault(family_name, {"type": "gauge", "help": family_name, "samples": []})
        entry["samples"].append((sample_name, dict(labels or {}), value))

    def render(self) -> str:
        lines: list[str] = []
        for family_name in sorted(self._families):
            entry = self._families[family_name]
            lines.append(f"# HELP {family_name} {entry['help']}")
            lines.append(f"# TYPE {family_name} {entry['type']}")
            for sample_name, labels, value in entry["samples"]:
                if labels:
                    encoded = ",".join(
                        f'{key}="{_sanitize_label_value(labels[key])}"'
                        for key in sorted(labels)
                    )
                    lines.append(f"{sample_name}{{{encoded}}} {_format_value(value)}")
                else:
                    lines.append(f"{sample_name} {_format_value(value)}")
        for name in sorted(self._entries):
            entry = self._entries[name]
            lines.append(f"# HELP {name} {entry['help']}")
            lines.append(f"# TYPE {name} {entry['type']}")
            for labels, value in entry["samples"]:
                if labels:
                    encoded = ",".join(
                        f'{key}="{_sanitize_label_value(labels[key])}"'
                        for key in sorted(labels)
                    )
                    lines.append(f"{name}{{{encoded}}} {_format_value(value)}")
                else:
                    lines.append(f"{name} {_format_value(value)}")
        return "\n".join(lines) + "\n"


class HttpMetrics:
    def __init__(self, buckets: tuple[float, ...]) -> None:
        self._buckets = buckets
        self._lock = threading.Lock()
        self._request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        self._normalized_request_counts: dict[tuple[str, str, str, str], int] = defaultdict(int)
        self._duration_counts: dict[tuple[str, str], int] = defaultdict(int)
        self._duration_sums: dict[tuple[str, str], float] = defaultdict(float)
        self._duration_buckets: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0] * len(self._buckets))
        self._normalized_duration_counts: dict[tuple[str, str], int] = defaultdict(int)
        self._normalized_duration_sums: dict[tuple[str, str], float] = defaultdict(float)
        self._normalized_duration_buckets: dict[tuple[str, str], list[int]] = defaultdict(
            lambda: [0] * len(NORMALIZED_HTTP_DURATION_BUCKETS)
        )
        self._inflight: dict[tuple[str, str], int] = defaultdict(int)

    def observe(self, method: str, path: str, status: int, duration_seconds: float) -> None:
        request_key = (str(method or "UNKNOWN").upper(), str(path or "/"), str(status))
        duration_key = (request_key[0], request_key[1])
        normalized_route = normalize_http_route(path)
        normalized_request_key = (request_key[0], normalized_route, http_status_class(status), str(status))
        normalized_duration_key = (request_key[0], normalized_route)
        with self._lock:
            self._request_counts[request_key] += 1
            self._duration_counts[duration_key] += 1
            self._duration_sums[duration_key] += max(float(duration_seconds), 0.0)
            buckets = self._duration_buckets[duration_key]
            for index, upper_bound in enumerate(self._buckets):
                if duration_seconds <= upper_bound:
                    buckets[index] += 1
            self._normalized_request_counts[normalized_request_key] += 1
            self._normalized_duration_counts[normalized_duration_key] += 1
            self._normalized_duration_sums[normalized_duration_key] += max(float(duration_seconds), 0.0)
            normalized_buckets = self._normalized_duration_buckets[normalized_duration_key]
            for index, upper_bound in enumerate(NORMALIZED_HTTP_DURATION_BUCKETS):
                if duration_seconds <= upper_bound:
                    normalized_buckets[index] += 1

    def observe_inflight(self, method: str, path: str, delta: int) -> None:
        key = (str(method or "UNKNOWN").upper(), normalize_http_route(path))
        with self._lock:
            self._inflight[key] += int(delta)
            if self._inflight[key] < 0:
                self._inflight[key] = 0

    def emit(self, builder: MetricsBuilder) -> None:
        builder.metric(
            "secflow_dataflow_http_requests_total",
            "counter",
            "Total HTTP requests served by this process.",
        )
        for (method, path, status), count in sorted(self._request_counts.items()):
            builder.sample(
                "secflow_dataflow_http_requests_total",
                count,
                {"method": method, "path": path, "status": status},
            )

        builder.family(
            "secflow_dataflow_http_request_duration_seconds",
            "histogram",
            "HTTP request latency in seconds for this process.",
        )
        for key in sorted(self._duration_counts):
            method, path = key
            cumulative = 0
            buckets = self._duration_buckets[key]
            for index, upper_bound in enumerate(self._buckets):
                cumulative += buckets[index]
                builder.family_sample(
                    "secflow_dataflow_http_request_duration_seconds",
                    "secflow_dataflow_http_request_duration_seconds_bucket",
                    cumulative,
                    {"method": method, "path": path, "le": _format_value(upper_bound)},
                )
            builder.family_sample(
                "secflow_dataflow_http_request_duration_seconds",
                "secflow_dataflow_http_request_duration_seconds_sum",
                self._duration_sums[key],
                {"method": method, "path": path},
            )
            builder.family_sample(
                "secflow_dataflow_http_request_duration_seconds",
                "secflow_dataflow_http_request_duration_seconds_count",
                self._duration_counts[key],
                {"method": method, "path": path},
            )
        builder.metric(
            "secflow_dataflow_vuln_http_requests_total",
            "counter",
            "Total normalized HTTP requests served by this process.",
        )
        for (method, route, status_class, status_code), count in sorted(self._normalized_request_counts.items()):
            builder.sample(
                "secflow_dataflow_vuln_http_requests_total",
                count,
                {"method": method, "route": route, "status_class": status_class, "status_code": status_code},
            )
        builder.family(
            "secflow_dataflow_vuln_http_request_duration_seconds",
            "histogram",
            "Normalized HTTP request latency in seconds for this process.",
        )
        for key in sorted(self._normalized_duration_counts):
            method, route = key
            cumulative = 0
            buckets = self._normalized_duration_buckets[key]
            for index, upper_bound in enumerate(NORMALIZED_HTTP_DURATION_BUCKETS):
                cumulative += buckets[index]
                builder.family_sample(
                    "secflow_dataflow_vuln_http_request_duration_seconds",
                    "secflow_dataflow_vuln_http_request_duration_seconds_bucket",
                    cumulative,
                    {"method": method, "route": route, "le": _format_value(upper_bound)},
                )
            builder.family_sample(
                "secflow_dataflow_vuln_http_request_duration_seconds",
                "secflow_dataflow_vuln_http_request_duration_seconds_sum",
                self._normalized_duration_sums[key],
                {"method": method, "route": route},
            )
            builder.family_sample(
                "secflow_dataflow_vuln_http_request_duration_seconds",
                "secflow_dataflow_vuln_http_request_duration_seconds_count",
                self._normalized_duration_counts[key],
                {"method": method, "route": route},
            )
        builder.metric(
            "secflow_dataflow_vuln_http_request_inflight",
            "gauge",
            "Current inflight normalized HTTP requests.",
        )
        for (method, route), value in sorted(self._inflight.items()):
            builder.sample(
                "secflow_dataflow_vuln_http_request_inflight",
                value,
                {"method": method, "route": route},
            )


_http_metrics = HttpMetrics(HTTP_DURATION_BUCKETS)


def observe_http_request(method: str, path: str, status_code: int, duration_seconds: float) -> None:
    _http_metrics.observe(method, path, status_code, duration_seconds)


def observe_http_request_inflight(method: str, path: str, delta: int) -> None:
    _http_metrics.observe_inflight(method, path, delta)


def build_metrics_response() -> Response:
    builder = MetricsBuilder()
    builder.metric(
        "secflow_dataflow_metrics_scrape_success",
        "gauge",
        "Whether the last metrics scrape finished successfully.",
    )
    try:
        _http_metrics.emit(builder)
        emit_service_operation_metrics(
            builder,
            "secflow_dataflow_service_operation_duration_seconds",
            "secflow_dataflow_service_operation_total",
        )
        _collect_runtime_metrics(builder)
        builder.sample("secflow_dataflow_metrics_scrape_success", 1)
    except Exception as exc:
        builder.sample("secflow_dataflow_metrics_scrape_success", 0)
        builder.metric(
            "secflow_dataflow_metrics_scrape_errors_total",
            "counter",
            "Metrics scrape failures observed by this process.",
        )
        builder.sample(
            "secflow_dataflow_metrics_scrape_errors_total",
            1,
            {"error_type": exc.__class__.__name__},
        )
    return Response(content=builder.render(), media_type=PROMETHEUS_CONTENT_TYPE)


def _duration_seconds(started_at: datetime | None, finished_at: datetime | None) -> float:
    if started_at is None or finished_at is None:
        return 0.0
    return max((finished_at - started_at).total_seconds(), 0.0)


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _bool_gauge(value: Any) -> int:
    return 1 if bool(value) else 0


def _collect_runtime_metrics(builder: MetricsBuilder) -> None:
    db = get_db_session()
    try:
        _collect_task_and_execution_metrics(db, builder)
        _collect_scheduler_metrics(db, builder)
        _collect_scheduler_snapshot_metrics(builder)
        _collect_run_summary_metrics(db, builder)
        _collect_cycle_metrics(db, builder)
        _collect_plugin_metrics(db, builder)
        _collect_runtime_trace_metrics(db, builder)
        _collect_ai_metrics(db, builder)
    finally:
        db.close()


def _collect_task_and_execution_metrics(db: Session, builder: MetricsBuilder) -> None:
    builder.metric("secflow_dataflow_task_status", "gauge", "Current trigger task counts by status.")
    builder.metric("secflow_dataflow_execution_status", "gauge", "Current execution counts by status.")
    builder.metric("secflow_dataflow_task_events_total", "counter", "Aggregated trigger task lifecycle counters.")
    builder.metric("secflow_dataflow_execution_events_total", "counter", "Aggregated execution lifecycle and event counters.")
    builder.metric("secflow_dataflow_queue_depth", "gauge", "Current queue depth across scheduler-managed entities.")
    builder.family("secflow_dataflow_execution_dispatch_duration_seconds", "summary", "Execution dispatch delay from creation to process start.")
    builder.family("secflow_dataflow_execution_process_duration_seconds", "summary", "Execution process duration from process start to finish.")

    task_total = db.query(func.count(TriggerTask.id)).scalar() or 0
    task_started_total = db.query(func.count(TriggerTask.id)).filter(TriggerTask.started_at.is_not(None)).scalar() or 0
    task_finished_total = db.query(func.count(TriggerTask.id)).filter(TriggerTask.finished_at.is_not(None)).scalar() or 0
    task_retry_total = db.query(func.coalesce(func.sum(TriggerTask.retry_count), 0)).scalar() or 0
    for status_value, count in db.query(TriggerTask.status, func.count(TriggerTask.id)).group_by(TriggerTask.status).all():
        builder.sample("secflow_dataflow_task_status", count, {"status": status_value or "unknown"})
    builder.sample("secflow_dataflow_task_events_total", task_total, {"event": "created"})
    builder.sample("secflow_dataflow_task_events_total", task_started_total, {"event": "started"})
    builder.sample("secflow_dataflow_task_events_total", task_finished_total, {"event": "finished"})
    builder.sample("secflow_dataflow_task_events_total", task_retry_total, {"event": "retry"})

    execution_total = db.query(func.count(WorkflowExecution.id)).scalar() or 0
    execution_started_total = db.query(func.count(WorkflowExecution.id)).filter(WorkflowExecution.started_at.is_not(None)).scalar() or 0
    execution_finished_total = db.query(func.count(WorkflowExecution.id)).filter(WorkflowExecution.finished_at.is_not(None)).scalar() or 0
    for status_value, count in db.query(WorkflowExecution.status, func.count(WorkflowExecution.id)).group_by(WorkflowExecution.status).all():
        builder.sample("secflow_dataflow_execution_status", count, {"status": status_value or "unknown"})
    builder.sample("secflow_dataflow_execution_events_total", execution_total, {"event": "created"})
    builder.sample("secflow_dataflow_execution_events_total", execution_started_total, {"event": "started"})
    builder.sample("secflow_dataflow_execution_events_total", execution_finished_total, {"event": "finished"})

    event_type_counts = dict(
        db.query(WorkflowExecutionEvent.event_type, func.count(WorkflowExecutionEvent.id))
        .group_by(WorkflowExecutionEvent.event_type)
        .all()
    )
    for event_type, count in sorted(event_type_counts.items()):
        builder.sample("secflow_dataflow_execution_events_total", count, {"event": event_type or "unknown"})

    cancel_total = sum(
        int(event_type_counts.get(name, 0))
        for name in ("execution_cancelled", "execution_cancel_checkpoint")
    )
    retry_total = sum(
        int(event_type_counts.get(name, 0))
        for name in ("task_retry_queued", "run_resume_queued")
    )
    error_total = sum(
        int(event_type_counts.get(name, 0))
        for name in ("execution_failed", "workflow_abnormal_exit", "abnormal_exit")
    )
    builder.sample("secflow_dataflow_execution_events_total", cancel_total, {"event": "cancel"})
    builder.sample("secflow_dataflow_execution_events_total", retry_total, {"event": "retry"})
    builder.sample("secflow_dataflow_execution_events_total", error_total, {"event": "error"})

    task_queue_depth = (
        db.query(func.count(TriggerTask.id))
        .filter(TriggerTask.status == "pending")
        .scalar()
        or 0
    )
    execution_queue_depth = (
        db.query(func.count(WorkflowExecution.id))
        .filter(WorkflowExecution.status == "pending")
        .scalar()
        or 0
    )
    run_queue_depth = (
        db.query(func.count(RunIndex.id))
        .filter(RunIndex.status.in_(tuple(_ACTIVE_RUN_INDEX_STATUSES & {"pending", "queued"})))
        .scalar()
        or 0
    )
    builder.sample("secflow_dataflow_queue_depth", task_queue_depth, {"kind": "task"})
    builder.sample("secflow_dataflow_queue_depth", execution_queue_depth, {"kind": "execution"})
    builder.sample("secflow_dataflow_queue_depth", run_queue_depth, {"kind": "run"})

    dispatch_sum = 0.0
    dispatch_count = 0
    process_sum = 0.0
    process_count = 0
    running_process_count = 0
    for execution in db.query(
        WorkflowExecution.created_at,
        WorkflowExecution.process_started_at,
        WorkflowExecution.process_finished_at,
        WorkflowExecution.process_status,
    ).all():
        created_at, process_started_at, process_finished_at, process_status = execution
        if created_at is not None and process_started_at is not None:
            dispatch_sum += max((process_started_at - created_at).total_seconds(), 0.0)
            dispatch_count += 1
        if process_started_at is not None and process_finished_at is not None:
            process_sum += _duration_seconds(process_started_at, process_finished_at)
            process_count += 1
        elif process_started_at is not None and str(process_status or "").strip().lower() in {"running", "stop_requested", "delete_requested"}:
            running_process_count += 1
    builder.family_sample("secflow_dataflow_execution_dispatch_duration_seconds", "secflow_dataflow_execution_dispatch_duration_seconds_sum", dispatch_sum)
    builder.family_sample("secflow_dataflow_execution_dispatch_duration_seconds", "secflow_dataflow_execution_dispatch_duration_seconds_count", dispatch_count)
    builder.family_sample("secflow_dataflow_execution_process_duration_seconds", "secflow_dataflow_execution_process_duration_seconds_sum", process_sum)
    builder.family_sample("secflow_dataflow_execution_process_duration_seconds", "secflow_dataflow_execution_process_duration_seconds_count", process_count)
    builder.sample("secflow_dataflow_execution_process_duration_seconds_active", running_process_count)


def _collect_scheduler_metrics(db: Session, builder: MetricsBuilder) -> None:
    builder.metric("secflow_dataflow_scheduler_worker_capacity", "gauge", "Scheduler worker capacity.")
    builder.metric("secflow_dataflow_scheduler_running_count", "gauge", "Scheduler running worker count.")
    builder.metric("secflow_dataflow_scheduler_workers", "gauge", "Scheduler worker rows by status.")

    workers = db.query(SchedulerWorker).all()
    db_capacity = sum(int(worker.capacity or 0) for worker in workers)
    db_running = sum(int(worker.running_count or 0) for worker in workers)
    builder.sample("secflow_dataflow_scheduler_worker_capacity", db_capacity, {"scope": "db"})
    builder.sample("secflow_dataflow_scheduler_running_count", db_running, {"scope": "db"})
    worker_status_counts: dict[str, int] = defaultdict(int)
    for worker in workers:
        worker_status_counts[str(worker.status or "unknown")] += 1
    for status_value, count in sorted(worker_status_counts.items()):
        builder.sample("secflow_dataflow_scheduler_workers", count, {"status": status_value})

    scheduler = get_scheduler_service()
    builder.sample(
        "secflow_dataflow_scheduler_worker_capacity",
        scheduler.capacity,
        {"scope": "local", "role": scheduler.role, "pod_id": scheduler.pod_id},
    )
    builder.sample(
        "secflow_dataflow_scheduler_running_count",
        scheduler.local_running_count(),
        {"scope": "local", "role": scheduler.role, "pod_id": scheduler.pod_id},
    )
    builder.sample(
        "secflow_dataflow_queue_depth",
        (
            db.query(func.count(WorkflowExecution.id))
            .filter(WorkflowExecution.status == "pending")
            .scalar()
            or 0
        ),
        {"kind": "scheduler_active_queue"},
    )


def _collect_scheduler_snapshot_metrics(builder: MetricsBuilder) -> None:
    builder.metric(
        "secflow_dataflow_cluster_capacity_summary_snapshot_total",
        "counter",
        "Cluster capacity summary snapshot events observed by this process.",
    )
    builder.metric(
        "secflow_dataflow_cluster_capacity_summary_snapshot_state",
        "gauge",
        "Current cluster capacity summary snapshot state for this process.",
    )
    scheduler = get_scheduler_service()
    snapshot_metrics = scheduler.cluster_capacity_summary_snapshot_metrics()
    builder.sample(
        "secflow_dataflow_cluster_capacity_summary_snapshot_total",
        snapshot_metrics.get("hits_total", 0),
        {"result": "hit"},
    )
    builder.sample(
        "secflow_dataflow_cluster_capacity_summary_snapshot_total",
        snapshot_metrics.get("misses_total", 0),
        {"result": "miss"},
    )
    builder.sample(
        "secflow_dataflow_cluster_capacity_summary_snapshot_total",
        snapshot_metrics.get("refresh_failures_total", 0),
        {"result": "refresh_failure"},
    )
    for field in ("last_refresh_duration_seconds", "age_seconds", "available", "stale", "refreshing"):
        builder.sample(
            "secflow_dataflow_cluster_capacity_summary_snapshot_state",
            snapshot_metrics.get(field, 0),
            {"field": field},
        )


def _collect_run_summary_metrics(db: Session, builder: MetricsBuilder) -> None:
    builder.metric("secflow_dataflow_run_status", "gauge", "Current run-index counts by status.")
    builder.metric("secflow_dataflow_run_summary_total", "gauge", "Aggregated run summary values across all indexed runs.")

    for status_value, count in db.query(RunIndex.status, func.count(RunIndex.id)).group_by(RunIndex.status).all():
        builder.sample("secflow_dataflow_run_status", count, {"status": status_value or "unknown"})

    aggregates = db.query(
        func.coalesce(func.sum(RunIndex.result_count), 0),
        func.coalesce(func.sum(RunIndex.passed_count), 0),
        func.coalesce(func.sum(RunIndex.failed_count), 0),
        func.coalesce(func.sum(RunIndex.cycles_used), 0),
        func.coalesce(func.sum(RunIndex.duration_seconds), 0),
    ).one()
    builder.sample("secflow_dataflow_run_summary_total", aggregates[0], {"field": "result_count"})
    builder.sample("secflow_dataflow_run_summary_total", aggregates[1], {"field": "passed_count"})
    builder.sample("secflow_dataflow_run_summary_total", aggregates[2], {"field": "failed_count"})
    builder.sample("secflow_dataflow_run_summary_total", aggregates[3], {"field": "cycles_used"})
    builder.sample("secflow_dataflow_run_summary_total", aggregates[4], {"field": "duration_seconds"})


def _latest_cycle_rows(db: Session) -> list[tuple[RunIndexCycle, str]]:
    subquery = (
        db.query(
            RunIndexCycle.run_index_id.label("run_index_id"),
            func.max(RunIndexCycle.cycle).label("max_cycle"),
        )
        .group_by(RunIndexCycle.run_index_id)
        .subquery()
    )
    return (
        db.query(RunIndexCycle, RunIndex.run_root_path)
        .join(
            subquery,
            (RunIndexCycle.run_index_id == subquery.c.run_index_id)
            & (RunIndexCycle.cycle == subquery.c.max_cycle),
        )
        .join(RunIndex, RunIndex.id == RunIndexCycle.run_index_id)
        .all()
    )


def _collect_cycle_metrics(db: Session, builder: MetricsBuilder) -> None:
    builder.metric("secflow_dataflow_cycle_metrics", "gauge", "Aggregated latest-cycle run metrics.")
    builder.metric("secflow_dataflow_cycle_plateau_flags", "gauge", "Aggregated latest-cycle plateau flags across runs.")

    totals: dict[str, float] = defaultdict(float)
    plateau_totals: dict[str, int] = defaultdict(int)
    for cycle_row, run_root in _latest_cycle_rows(db):
        metrics = _load_externalized_mapping_payload(run_root, cycle_row.metrics_json)
        plateau_status = _load_externalized_mapping_payload(run_root, cycle_row.plateau_status_json)
        totals["issue_count"] += _to_float(metrics.get("issue_count"))
        totals["current_failed"] += _to_float(
            metrics.get("current_failed_result_count", metrics.get("failed_result_count"))
        )
        totals["historical_removed"] += _to_float(metrics.get("historical_removed_result_count"))
        totals["unreviewed_new"] += _to_float(metrics.get("unreviewed_new_result_count"))
        totals["summary_size"] += _to_float(metrics.get("summary_size"))
        totals["supporting_docs_count"] += _to_float(metrics.get("supporting_docs_count"))

        for flag_name in (
            "stagnant",
            "switched_to_closure",
            "abort",
            "progress_gate_active",
            "no_effective_progress_failure",
            "summary_artifact_unchanged",
            "supporting_docs_unchanged",
            "summary_repair_deferred_abort",
        ):
            plateau_totals[flag_name] += _bool_gauge(plateau_status.get(flag_name))

    for field, value in sorted(totals.items()):
        builder.sample("secflow_dataflow_cycle_metrics", value, {"field": field})
    for flag_name, value in sorted(plateau_totals.items()):
        builder.sample("secflow_dataflow_cycle_plateau_flags", value, {"flag": flag_name})


@dataclass
class PluginAggregate:
    count: int = 0
    duration_sum_seconds: float = 0.0


def _collect_plugin_metrics(db: Session, builder: MetricsBuilder) -> None:
    builder.metric("secflow_dataflow_plugin_results_total", "counter", "Plugin execution result counts aggregated from execution events.")
    builder.family("secflow_dataflow_plugin_duration_seconds", "summary", "Plugin execution duration aggregated from execution events.")

    aggregates: dict[tuple[str, str, str], PluginAggregate] = {}
    rows = (
        db.query(WorkflowExecutionEvent.payload_json)
        .filter(WorkflowExecutionEvent.event_type == "plugin_completed")
        .all()
    )
    for (payload,) in rows:
        data = dict(payload or {})
        key = (
            str(data.get("plugin_id") or "unknown"),
            str(data.get("phase") or "unknown"),
            str(data.get("result_code") or "unknown"),
        )
        aggregate = aggregates.setdefault(key, PluginAggregate())
        aggregate.count += 1
        aggregate.duration_sum_seconds += _to_float(data.get("duration_ms")) / 1000.0

    for (plugin_id, phase, result_code), aggregate in sorted(aggregates.items()):
        labels = {"plugin_id": plugin_id, "phase": phase, "result_code": result_code}
        builder.sample("secflow_dataflow_plugin_results_total", aggregate.count, labels)
        builder.family_sample("secflow_dataflow_plugin_duration_seconds", "secflow_dataflow_plugin_duration_seconds_sum", aggregate.duration_sum_seconds, labels)
        builder.family_sample("secflow_dataflow_plugin_duration_seconds", "secflow_dataflow_plugin_duration_seconds_count", aggregate.count, labels)


def _collect_runtime_trace_metrics(db: Session, builder: MetricsBuilder) -> None:
    builder.metric("secflow_dataflow_runtime_trace_total", "counter", "Aggregated runtime trace counters from indexed session call records.")
    builder.metric("secflow_dataflow_token_usage_total", "counter", "Aggregated token usage from runtime response traces.")

    runtime_totals: dict[tuple[str, str], float] = defaultdict(float)
    token_totals: dict[str, float] = defaultdict(float)
    session_rows = db.query(RunIndexSession, RunIndex.run_root_path).join(RunIndex, RunIndex.id == RunIndexSession.run_index_id).all()
    for session_row, run_root in session_rows:
        calls = _load_externalized_json_payload(run_root, session_row.calls_json)
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, dict):
                continue
            mode = str(call.get("mode") or "unknown")
            status = str(call.get("status") or "unknown")
            labels = (mode, status)
            runtime_totals[(labels[0], "calls")] += 1
            runtime_totals[(labels[0], "attempts")] += len(call.get("attempts") or [])
            runtime_totals[(labels[0], "api_failures")] += _to_float(call.get("api_failures"))
            runtime_totals[(labels[0], "pi_failures")] += _to_float(call.get("pi_failures"))
            runtime_totals[(labels[0], "timeout_failures")] += _to_float(call.get("timeout_failures"))
            runtime_totals[(labels[0], "output_bytes")] += _to_float(call.get("output_total_bytes"))
            runtime_totals[(labels[0], "stderr_bytes")] += _to_float(call.get("stderr_total_bytes"))
            runtime_totals[(labels[0], "duration_seconds")] += _to_float(call.get("duration_ms")) / 1000.0
            runtime_totals[(labels[0], "stdout_truncated")] += _bool_gauge(call.get("stdout_truncated"))
            runtime_totals[(labels[0], "stderr_truncated")] += _bool_gauge(call.get("stderr_truncated"))
            runtime_totals[(labels[0], "stdout_soft_limit_exceeded")] += _bool_gauge(call.get("stdout_soft_limit_exceeded"))
            token_usage = call.get("token_usage")
            if isinstance(token_usage, dict):
                for token_type, value in token_usage.items():
                    token_totals[str(token_type or "unknown")] += _to_float(value)

    for (mode, field), value in sorted(runtime_totals.items()):
        builder.sample("secflow_dataflow_runtime_trace_total", value, {"mode": mode, "field": field})
    for token_type, value in sorted(token_totals.items()):
        builder.sample("secflow_dataflow_token_usage_total", value, {"token_type": token_type})


def _collect_ai_metrics(db: Session, builder: MetricsBuilder) -> None:
    builder.metric("secflow_dataflow_ai_role_count", "gauge", "Aggregated AI role counts for dataflow vuln scanner.")
    builder.metric("secflow_dataflow_ai_session_total", "counter", "Aggregated AI session count by role.")
    builder.metric("secflow_dataflow_ai_round_total", "counter", "Aggregated AI round counts by kind.")
    builder.metric("secflow_dataflow_ai_retry_total", "counter", "Aggregated AI retry counts by reason.")
    builder.metric("secflow_dataflow_ai_timeout_total", "counter", "Aggregated AI timeout counts by scope.")
    builder.metric("secflow_dataflow_ai_failure_total", "counter", "Aggregated AI failure counts by category.")
    builder.metric("secflow_dataflow_ai_token_usage_total", "counter", "Aggregated AI token usage by type.")
    builder.metric("secflow_dataflow_ai_token_cost_total", "counter", "Aggregated AI token cost.")
    builder.metric("secflow_dataflow_ai_review_total", "counter", "Aggregated AI review outcomes.")

    cycle_total = db.query(func.count(RunIndexCycle.id)).scalar() or 0
    session_total = db.query(func.count(RunIndexSession.id)).scalar() or 0
    plugin_total = (
        db.query(func.count(WorkflowExecutionEvent.id))
        .filter(WorkflowExecutionEvent.event_type == "plugin_completed")
        .scalar()
        or 0
    )
    event_counts = dict(
        db.query(WorkflowExecutionEvent.event_type, func.count(WorkflowExecutionEvent.id))
        .group_by(WorkflowExecutionEvent.event_type)
        .all()
    )
    timeout_total = sum(
        int(event_counts.get(name, 0))
        for name in event_counts
        if "timeout" in str(name or "").lower()
    )
    retry_total = sum(
        int(event_counts.get(name, 0))
        for name in event_counts
        if "retry" in str(name or "").lower() or "resume" in str(name or "").lower()
    )
    failure_total = sum(
        int(event_counts.get(name, 0))
        for name in event_counts
        if "fail" in str(name or "").lower() or "error" in str(name or "").lower() or "abnormal" in str(name or "").lower()
    )
    token_totals: dict[str, float] = defaultdict(float)
    session_rows = db.query(RunIndexSession, RunIndex.run_root_path).join(RunIndex, RunIndex.id == RunIndexSession.run_index_id).all()
    for session_row, run_root in session_rows:
        calls = _load_externalized_json_payload(run_root, session_row.calls_json)
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, dict):
                continue
            token_usage = call.get("token_usage")
            if isinstance(token_usage, dict):
                token_totals["input"] += _to_float(token_usage.get("input", token_usage.get("prompt_tokens")))
                token_totals["output"] += _to_float(token_usage.get("output", token_usage.get("completion_tokens")))
                token_totals["cache_read"] += _to_float(token_usage.get("cache_read", token_usage.get("cacheRead")))
                token_totals["cache_write"] += _to_float(token_usage.get("cache_write", token_usage.get("cacheWrite")))
                token_totals["total"] += _to_float(token_usage.get("total")) or (
                    _to_float(token_usage.get("input", token_usage.get("prompt_tokens")))
                    + _to_float(token_usage.get("output", token_usage.get("completion_tokens")))
                    + _to_float(token_usage.get("cache_read", token_usage.get("cacheRead")))
                    + _to_float(token_usage.get("cache_write", token_usage.get("cacheWrite")))
                )
                token_totals["cost"] += _to_float(token_usage.get("cost"))

    builder.sample("secflow_dataflow_ai_role_count", plugin_total, {"role": "plugin"})
    builder.sample("secflow_dataflow_ai_role_count", max(session_total, 1), {"role": "agent"})
    builder.sample("secflow_dataflow_ai_session_total", session_total, {"role": "agent"})
    builder.sample("secflow_dataflow_ai_round_total", cycle_total, {"kind": "cycle"})
    builder.sample("secflow_dataflow_ai_round_total", plugin_total, {"kind": "review"})
    builder.sample("secflow_dataflow_ai_retry_total", retry_total, {"reason": "retry"})
    builder.sample("secflow_dataflow_ai_timeout_total", timeout_total, {"scope": "plugin"})
    builder.sample("secflow_dataflow_ai_failure_total", failure_total, {"category": "runtime"})
    for token_type in ("input", "output", "cache_read", "cache_write", "total"):
        builder.sample("secflow_dataflow_ai_token_usage_total", token_totals.get(token_type, 0.0), {"type": token_type})
    builder.sample("secflow_dataflow_ai_token_cost_total", token_totals.get("cost", 0.0))
    builder.sample("secflow_dataflow_ai_review_total", plugin_total, {"result": "partial"})
