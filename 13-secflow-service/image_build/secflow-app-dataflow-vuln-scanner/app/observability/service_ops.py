from __future__ import annotations

import math
import threading
from collections import defaultdict
from typing import Mapping

try:
    from prometheus_client import Counter
except Exception:  # pragma: no cover - optional dependency fallback
    Counter = None


if Counter is not None:
    _TOKEN_CACHE_HITS = Counter(
        "secflow_dfvs_token_cache_hits_total",
        "Total token validation cache hits in dataflow vuln scanner service",
        labelnames=("outcome",),
    )
else:
    _TOKEN_CACHE_HITS = None


def observe_token_cache_hit(outcome: str) -> None:
    if _TOKEN_CACHE_HITS is None:
        return
    _TOKEN_CACHE_HITS.labels(outcome=_normalize_label(outcome)).inc()


def _normalize_label(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    normalized = []
    for ch in text:
        if ch.isalnum():
            normalized.append(ch)
        else:
            normalized.append("_")
    label = "".join(normalized).strip("_")
    return label or "unknown"


def build_token_cache_stats_payload(stats: Mapping[str, object] | None) -> dict[str, object]:
    payload = dict(stats or {})
    payload["enabled"] = bool(payload.get("enabled", False))
    payload["ttl_seconds"] = int(payload.get("ttl_seconds") or 0)
    payload["size"] = int(payload.get("size") or 0)
    payload["hits"] = int(payload.get("hits") or 0)
    payload["misses"] = int(payload.get("misses") or 0)
    payload["evictions"] = int(payload.get("evictions") or 0)
    payload["expired"] = int(payload.get("expired") or 0)
    return payload


def _format_value(value: float | int) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return f"{float(value):.12g}"


class ServiceLatencyMetrics:
    def __init__(self, buckets: tuple[float, ...]) -> None:
        self._buckets = buckets
        self._lock = threading.Lock()
        self._counts: dict[str, int] = defaultdict(int)
        self._sums: dict[str, float] = defaultdict(float)
        self._bucket_counts: dict[str, list[int]] = defaultdict(lambda: [0] * len(self._buckets))

    def observe(self, operation: str, duration_seconds: float) -> None:
        key = str(operation or "unknown")
        with self._lock:
            self._counts[key] += 1
            self._sums[key] += max(float(duration_seconds), 0.0)
            buckets = self._bucket_counts[key]
            for index, upper_bound in enumerate(self._buckets):
                if duration_seconds <= upper_bound:
                    buckets[index] += 1

    def emit(self, builder: object, family_name: str, total_name: str) -> None:
        builder.metric(
            total_name,
            "counter",
            "Total service-level operations observed in this process.",
        )
        builder.family(
            family_name,
            "histogram",
            "Latency of service-level operations in seconds.",
        )
        for operation, count in sorted(self._counts.items()):
            builder.sample(total_name, count, {"operation": operation})
            cumulative = 0
            buckets = self._bucket_counts[operation]
            for index, upper_bound in enumerate(self._buckets):
                cumulative += buckets[index]
                builder.family_sample(
                    family_name,
                    f"{family_name}_bucket",
                    cumulative,
                    {"operation": operation, "le": _format_value(upper_bound)},
                )
            builder.family_sample(
                family_name,
                f"{family_name}_sum",
                self._sums[operation],
                {"operation": operation},
            )
            builder.family_sample(
                family_name,
                f"{family_name}_count",
                count,
                {"operation": operation},
            )


HTTP_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, math.inf)
_service_latency_metrics = ServiceLatencyMetrics(HTTP_DURATION_BUCKETS)


def observe_service_operation(operation: str, duration_seconds: float) -> None:
    _service_latency_metrics.observe(operation, duration_seconds)


def emit_service_operation_metrics(builder: object, family_name: str, total_name: str) -> None:
    _service_latency_metrics.emit(builder, family_name, total_name)
