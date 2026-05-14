from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Callable, Iterable

from fastapi import Request, Response
from sqlalchemy.orm import Session

from app.model import EvolutionTask, EvolutionTaskRound, SchedulerWorker, get_db_session


def _labels_key(labels: dict[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(key), str(value)) for key, value in labels.items()))


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    escaped = ",".join(f'{key}="{value}"' for key, value in labels)
    return f"{{{escaped}}}"


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


class PromMetrics:
    def __init__(self, namespace: str) -> None:
        self.namespace = namespace
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(lambda: defaultdict(float))
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(dict)
        self._histograms: dict[str, dict[tuple[tuple[str, str], ...], list[float]]] = defaultdict(lambda: defaultdict(lambda: [0.0, 0.0]))

    def inc(self, name: str, amount: float = 1.0, **labels: Any) -> None:
        with self._lock:
            self._counters[name][_labels_key(labels)] += amount

    def set_gauge(self, name: str, value: float, **labels: Any) -> None:
        with self._lock:
            self._gauges[name][_labels_key(labels)] = value

    def observe(self, name: str, value: float, **labels: Any) -> None:
        with self._lock:
            slot = self._histograms[name][_labels_key(labels)]
            slot[0] += _safe_float(value)
            slot[1] += 1.0

    def render(self, snapshot_lines: Iterable[str] = ()) -> str:
        lines = list(snapshot_lines)
        with self._lock:
            for name, samples in sorted(self._counters.items()):
                metric = f"{self.namespace}_{name}_total"
                for labels, value in sorted(samples.items()):
                    lines.append(f"{metric}{_format_labels(labels)} {value}")
            for name, samples in sorted(self._gauges.items()):
                metric = f"{self.namespace}_{name}"
                for labels, value in sorted(samples.items()):
                    lines.append(f"{metric}{_format_labels(labels)} {value}")
            for name, samples in sorted(self._histograms.items()):
                metric = f"{self.namespace}_{name}_seconds"
                for labels, (total, count) in sorted(samples.items()):
                    lines.append(f"{metric}_sum{_format_labels(labels)} {total}")
                    lines.append(f"{metric}_count{_format_labels(labels)} {count}")
        return "\n".join(lines) + "\n"


class EvolutionObservability:
    def __init__(self) -> None:
        self.prom = PromMetrics("secflow_binary_evolution")

    async def http_middleware(self, request: Request, call_next: Callable):
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration = max(0.0, time.perf_counter() - started)
            route = request.url.path
            self.prom.inc("http_requests", method=request.method, path=route, status=str(status_code))
            self.prom.observe("http_request_duration", duration, method=request.method, path=route)

    def record_task_created(self, task: EvolutionTask, source_count: int) -> None:
        self.prom.inc("tasks_created", status=task.status)
        self.prom.set_gauge("last_task_source_count", source_count)

    def record_task_started(self, task: EvolutionTask) -> None:
        self.prom.inc("tasks_started")
        if task.created_at and task.started_at:
            self.prom.observe("queue_wait_duration", max(0.0, (task.started_at - task.created_at).total_seconds()))

    def record_task_finished(self, task: EvolutionTask, outcome: str) -> None:
        self.prom.inc("tasks_finished", status=outcome)
        if task.started_at and task.finished_at:
            self.prom.observe("execution_duration", max(0.0, (task.finished_at - task.started_at).total_seconds()), status=outcome)
        if task.created_at and task.finished_at:
            self.prom.observe("total_duration", max(0.0, (task.finished_at - task.created_at).total_seconds()), status=outcome)

    def record_round_metrics(self, round_no: int, metrics: dict[str, Any], score: int, derived_tasks: list[dict[str, Any]]) -> None:
        self.prom.set_gauge("round_number", round_no)
        self.prom.set_gauge("round_score", score, round=str(round_no))
        self.prom.set_gauge("false_positive_count", _safe_float(metrics.get("false_positive_count")), round=str(round_no))
        self.prom.set_gauge("false_negative_count", _safe_float(metrics.get("false_negative_count")), round=str(round_no))
        self.prom.set_gauge("severity_shift_count", _safe_float(metrics.get("severity_shift_count")), round=str(round_no))
        self.prom.set_gauge("avg_discovery_round", _safe_float(metrics.get("avg_discovery_round")), round=str(round_no))
        self.prom.set_gauge("derived_task_count", len(derived_tasks), round=str(round_no))

    def record_timeout(self, scope: str) -> None:
        self.prom.inc("timeouts", scope=scope)

    def record_error(self, scope: str, error_type: str = "runtime") -> None:
        self.prom.inc("errors", scope=scope, error_type=error_type)

    def metrics_response(self) -> Response:
        return Response(content=self.prom.render(_build_snapshot_lines()), media_type="text/plain; version=0.0.4; charset=utf-8")


def _build_snapshot_lines() -> list[str]:
    db = get_db_session()
    try:
        return _snapshot_lines(db)
    finally:
        db.close()


def _snapshot_lines(db: Session) -> list[str]:
    lines: list[str] = []
    tasks = db.query(EvolutionTask).filter(EvolutionTask.deleted.is_(False)).all()
    rounds = db.query(EvolutionTaskRound).all()
    workers = db.query(SchedulerWorker).all()

    status_counts: dict[str, int] = defaultdict(int)
    for task in tasks:
        status_counts[str(task.status or "unknown")] += 1
    for status_name, count in sorted(status_counts.items()):
        lines.append(f'secflow_binary_evolution_task_status{{status="{status_name}"}} {count}')

    pending_backlog = status_counts.get("pending", 0)
    running_tasks = status_counts.get("running", 0)
    lines.append(f"secflow_binary_evolution_queue_backlog {pending_backlog}")
    lines.append(f"secflow_binary_evolution_queue_running {running_tasks}")

    capacity_total = sum(int(worker.capacity or 0) for worker in workers if worker.status != "offline")
    running_total = sum(int(worker.running_count or 0) for worker in workers if worker.status != "offline")
    lines.append(f"secflow_binary_evolution_scheduler_worker_capacity {capacity_total}")
    lines.append(f"secflow_binary_evolution_scheduler_worker_running_count {running_total}")
    lines.append(f"secflow_binary_evolution_scheduler_worker_count {len(workers)}")
    for worker in workers:
        lines.append(
            f'secflow_binary_evolution_scheduler_worker_status{{pod_id="{worker.pod_id}",status="{worker.status}"}} 1'
        )

    if rounds:
        latest_round = max(int(round_.round_no or 0) for round_ in rounds)
        lines.append(f"secflow_binary_evolution_latest_round {latest_round}")
    latest_score = None
    for task in tasks:
        if task.overall_score is not None:
            latest_score = max(latest_score, int(task.overall_score)) if latest_score is not None else int(task.overall_score)
    if latest_score is not None:
        lines.append(f"secflow_binary_evolution_best_score {latest_score}")

    round_fp = round_fn = round_derived = 0.0
    for round_ in rounds:
        metrics = dict(round_.metrics_json or {}) if isinstance(round_.metrics_json, dict) else {}
        round_fp += _safe_float(metrics.get("false_positive_count"))
        round_fn += _safe_float(metrics.get("false_negative_count"))
        round_derived += len(round_.derived_tasks_json or []) if isinstance(round_.derived_tasks_json, list) else 0
    lines.append(f"secflow_binary_evolution_round_false_positive_total {round_fp}")
    lines.append(f"secflow_binary_evolution_round_false_negative_total {round_fn}")
    lines.append(f"secflow_binary_evolution_round_derived_task_total {round_derived}")
    return lines


_observability: EvolutionObservability | None = None


def get_observability() -> EvolutionObservability:
    global _observability
    if _observability is None:
        _observability = EvolutionObservability()
    return _observability
