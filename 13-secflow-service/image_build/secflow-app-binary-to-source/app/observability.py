from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

from fastapi import Request, Response
from sqlalchemy.orm import Session

from app.model import B2STask, B2STaskItem, get_db_session


def _labels_key(labels: dict[str, Any] | None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(key), str(value)) for key, value in labels.items()))


def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{key}="{value}"' for key, value in labels) + "}"


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


class B2SObservability:
    def __init__(self) -> None:
        self.prom = PromMetrics("secflow_binary_to_source")

    async def http_middleware(self, request: Request, call_next: Callable):
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration = max(0.0, time.perf_counter() - started)
            self.prom.inc("http_requests", method=request.method, path=request.url.path, status=str(status_code))
            self.prom.observe("http_request_duration", duration, method=request.method, path=request.url.path)

    def record_task_created(self, item_count: int) -> None:
        self.prom.inc("tasks_created")
        self.prom.set_gauge("last_task_item_count", item_count)

    def record_item_submit(self, item: B2STaskItem, selected_worker: str) -> None:
        if item.status == "running":
            self.prom.inc("tasks_started", entity="item")
        if item.created_at and item.started_at:
            self.prom.observe("queue_wait_duration", max(0.0, (item.started_at - item.created_at).total_seconds()))
        self.prom.inc("worker_selection", worker=selected_worker)

    def record_item_finished(self, item: B2STaskItem) -> None:
        self.prom.inc("tasks_finished", status=item.status or "unknown")
        if item.started_at and item.finished_at:
            self.prom.observe("execution_duration", max(0.0, (item.finished_at - item.started_at).total_seconds()), status=item.status or "unknown")
        if item.created_at and item.finished_at:
            self.prom.observe("total_duration", max(0.0, (item.finished_at - item.created_at).total_seconds()), status=item.status or "unknown")
        if item.failure_type:
            self.prom.inc("errors", error_type=item.failure_type)
        if "timeout" in str(item.error_reason or "").lower():
            self.prom.inc("timeouts", error_type=item.failure_type or "timeout")

    def record_retry(self, mode: str, count: int) -> None:
        self.prom.inc("retries", amount=float(count), mode=mode)

    def metrics_response(self) -> Response:
        return Response(content=self.prom.render(_build_snapshot_lines()), media_type="text/plain; version=0.0.4; charset=utf-8")


def _build_snapshot_lines() -> list[str]:
    db = get_db_session()
    try:
        return _snapshot_lines(db)
    finally:
        db.close()


def _snapshot_lines(db: Session) -> list[str]:
    from app.service.task_service import (
        build_overall_progress,
        build_task_item_review_analytics,
        configured_pi_workers,
        item_pi_worker_url,
        map_pi_phase,
    )

    lines: list[str] = []
    tasks = db.query(B2STask).all()
    items = db.query(B2STaskItem).all()

    task_status_counts: dict[str, int] = defaultdict(int)
    item_status_counts: dict[str, int] = defaultdict(int)
    phase_counts: dict[str, int] = defaultdict(int)
    upstream_status_counts: dict[str, int] = defaultdict(int)
    failure_type_counts: dict[str, int] = defaultdict(int)
    worker_loads: dict[str, int] = {worker: 0 for worker in configured_pi_workers()}

    for task in tasks:
        task_status_counts[str(task.status or "unknown")] += 1
    for item in items:
        item_status = str(item.status or "unknown")
        phase = str(item.phase or map_pi_phase((item.progress or {}).get("raw_phase"), item.status) or "unknown")
        item_status_counts[item_status] += 1
        phase_counts[phase] += 1
        upstream_status_counts[str(item_status)] += 1
        if item.failure_type:
            failure_type_counts[str(item.failure_type)] += 1
        worker_url = item_pi_worker_url(item)
        if worker_url:
            worker_loads.setdefault(worker_url, 0)
            if item.status in {"queued", "running"}:
                worker_loads[worker_url] += 1

    for status_name, count in sorted(task_status_counts.items()):
        lines.append(f'secflow_binary_to_source_task_status{{status="{status_name}"}} {count}')
    for status_name, count in sorted(item_status_counts.items()):
        lines.append(f'secflow_binary_to_source_item_status{{status="{status_name}"}} {count}')
    for phase_name, count in sorted(phase_counts.items()):
        lines.append(f'secflow_binary_to_source_phase_summary{{phase="{phase_name}"}} {count}')
    for status_name, count in sorted(upstream_status_counts.items()):
        lines.append(f'secflow_binary_to_source_upstream_job_status{{status="{status_name}"}} {count}')
    for error_type, count in sorted(failure_type_counts.items()):
        lines.append(f'secflow_binary_to_source_error_type{{error_type="{error_type}"}} {count}')
    for worker_url, count in sorted(worker_loads.items()):
        lines.append(f'secflow_binary_to_source_worker_load{{worker="{worker_url}"}} {count}')

    overall = build_overall_progress(items)
    lines.append(f"secflow_binary_to_source_overall_progress_percent {_safe_float(overall.percent)}")
    lines.append(f"secflow_binary_to_source_overall_completed_items {_safe_float(overall.completed_items)}")
    lines.append(f"secflow_binary_to_source_overall_total_items {_safe_float(overall.total_items)}")
    if overall.total_functions is not None:
        lines.append(f"secflow_binary_to_source_overall_completed_functions {_safe_float(overall.completed_functions)}")
        lines.append(f"secflow_binary_to_source_overall_total_functions {_safe_float(overall.total_functions)}")
    if overall.total_batches is not None:
        lines.append(f"secflow_binary_to_source_overall_completed_batches {_safe_float(overall.completed_batches)}")
        lines.append(f"secflow_binary_to_source_overall_total_batches {_safe_float(overall.total_batches)}")
    if overall.total_bytes is not None:
        lines.append(f"secflow_binary_to_source_overall_completed_bytes {_safe_float(overall.completed_bytes)}")
        lines.append(f"secflow_binary_to_source_overall_total_bytes {_safe_float(overall.total_bytes)}")

    review_attempts = 0.0
    review_issues = 0.0
    review_resolved = 0.0
    review_remaining = 0.0
    review_passed = 0.0
    for item in items:
        try:
            analytics = build_task_item_review_analytics(item)
        except Exception:
            continue
        review_attempts += int(analytics.summary.attempt_count or 0)
        review_issues += int(analytics.summary.issue_total or 0)
        review_resolved += int(analytics.summary.issue_resolved or 0)
        review_remaining += int(analytics.summary.issue_remaining or 0)
        if str(analytics.summary.final_verdict or "").upper() == "PASS":
            review_passed += 1
    lines.append(f"secflow_binary_to_source_review_attempt_total {review_attempts}")
    lines.append(f"secflow_binary_to_source_review_issue_total {review_issues}")
    lines.append(f"secflow_binary_to_source_review_issue_resolved_total {review_resolved}")
    lines.append(f"secflow_binary_to_source_review_issue_remaining_total {review_remaining}")
    lines.append(f"secflow_binary_to_source_review_passed_items {review_passed}")
    _append_ai_snapshot_lines(
        lines,
        items=items,
        worker_loads=worker_loads,
        failure_type_counts=failure_type_counts,
        review_attempts=review_attempts,
        review_passed=review_passed,
    )
    return lines


def _append_ai_snapshot_lines(
    lines: list[str],
    *,
    items: list[B2STaskItem],
    worker_loads: dict[str, int],
    failure_type_counts: dict[str, int],
    review_attempts: float,
    review_passed: float,
) -> None:
    token_totals = defaultdict(float)
    session_total = 0
    timeout_total = 0
    retry_total = 0
    review_fail_total = 0
    for item in items:
        metadata = item.extra_metadata if isinstance(item.extra_metadata, dict) else {}
        review_fail_total += 1 if str(item.status or "").lower() not in {"passed", "success", "completed"} else 0
        if "timeout" in str(item.error_reason or "").lower():
            timeout_total += 1
        if metadata:
            retry_total += max(0.0, _safe_float(metadata.get("retry_count", metadata.get("attempt_count", 0))) - 1)
        output_dir = Path(str(item.output_dir or "")).expanduser()
        summary = _load_token_summary(output_dir)
        for key, value in summary.items():
            token_totals[key] += value
        session_total += _count_session_files(output_dir / "agent_sessions")

    total_tokens = (
        token_totals["input"]
        + token_totals["output"]
        + token_totals["cache_read"]
        + token_totals["cache_write"]
    )
    lines.extend([
        '# HELP secflow_binary_to_source_ai_role_count Aggregated AI role counts for this service.',
        '# TYPE secflow_binary_to_source_ai_role_count gauge',
        '# HELP secflow_binary_to_source_ai_session_total Aggregated AI session count by role.',
        '# TYPE secflow_binary_to_source_ai_session_total counter',
        '# HELP secflow_binary_to_source_ai_round_total Aggregated AI round counts by kind.',
        '# TYPE secflow_binary_to_source_ai_round_total counter',
        '# HELP secflow_binary_to_source_ai_retry_total Aggregated AI retry counts by reason.',
        '# TYPE secflow_binary_to_source_ai_retry_total counter',
        '# HELP secflow_binary_to_source_ai_timeout_total Aggregated AI timeout counts by scope.',
        '# TYPE secflow_binary_to_source_ai_timeout_total counter',
        '# HELP secflow_binary_to_source_ai_failure_total Aggregated AI failures by category.',
        '# TYPE secflow_binary_to_source_ai_failure_total counter',
        '# HELP secflow_binary_to_source_ai_token_usage_total Aggregated AI token usage by type.',
        '# TYPE secflow_binary_to_source_ai_token_usage_total counter',
        '# HELP secflow_binary_to_source_ai_token_cost_total Aggregated AI token cost.',
        '# TYPE secflow_binary_to_source_ai_token_cost_total counter',
        '# HELP secflow_binary_to_source_ai_review_total Aggregated AI review outcomes.',
        '# TYPE secflow_binary_to_source_ai_review_total counter',
    ])
    lines.append(f'secflow_binary_to_source_ai_role_count{{role="worker"}} {sum(worker_loads.values())}')
    lines.append(f'secflow_binary_to_source_ai_role_count{{role="judge"}} {int(review_attempts)}')
    lines.append(f'secflow_binary_to_source_ai_role_count{{role="validator"}} {int(review_attempts)}')
    lines.append(f'secflow_binary_to_source_ai_session_total{{role="agent"}} {session_total}')
    lines.append(f'secflow_binary_to_source_ai_round_total{{kind="review"}} {int(review_attempts)}')
    lines.append(f'secflow_binary_to_source_ai_retry_total{{reason="retry"}} {max(0, int(retry_total))}')
    lines.append(f'secflow_binary_to_source_ai_timeout_total{{scope="worker"}} {timeout_total}')
    for category, count in sorted(failure_type_counts.items()):
        lines.append(f'secflow_binary_to_source_ai_failure_total{{category="{category}"}} {count}')
    lines.append(f'secflow_binary_to_source_ai_failure_total{{category="timeout"}} {timeout_total}')
    lines.append(f'secflow_binary_to_source_ai_token_usage_total{{type="input"}} {int(token_totals["input"])}')
    lines.append(f'secflow_binary_to_source_ai_token_usage_total{{type="output"}} {int(token_totals["output"])}')
    lines.append(f'secflow_binary_to_source_ai_token_usage_total{{type="cache_read"}} {int(token_totals["cache_read"])}')
    lines.append(f'secflow_binary_to_source_ai_token_usage_total{{type="cache_write"}} {int(token_totals["cache_write"])}')
    lines.append(f'secflow_binary_to_source_ai_token_usage_total{{type="total"}} {int(total_tokens)}')
    lines.append(f'secflow_binary_to_source_ai_token_cost_total {token_totals["cost"]}')
    lines.append(f'secflow_binary_to_source_ai_review_total{{result="pass"}} {int(review_passed)}')
    lines.append(f'secflow_binary_to_source_ai_review_total{{result="fail"}} {max(0, int(review_fail_total))}')


def _load_token_summary(output_dir: Path) -> dict[str, float]:
    totals = defaultdict(float)
    if not output_dir.exists():
        return totals
    for path in output_dir.rglob("tokens_summary.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        total = payload.get("total") if isinstance(payload, dict) else {}
        if not isinstance(total, dict):
            continue
        totals["input"] += _safe_float(total.get("input", total.get("prompt_tokens")))
        totals["output"] += _safe_float(total.get("output", total.get("completion_tokens")))
        totals["cache_read"] += _safe_float(total.get("cache_read", total.get("cacheRead")))
        totals["cache_write"] += _safe_float(total.get("cache_write", total.get("cacheWrite")))
        totals["cost"] += _safe_float(total.get("cost"))
    return totals


def _count_session_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob("*") if item.is_file())


_observability: B2SObservability | None = None


def get_observability() -> B2SObservability:
    global _observability
    if _observability is None:
        _observability = B2SObservability()
    return _observability
