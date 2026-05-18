"""Cluster-aggregated Prometheus metrics for Binary Security."""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass, field
from typing import Iterable

import httpx

from app.observability import CONTENT_TYPE_LATEST
from app.service.http_client import get_shared_async_client


_ROLE_LABELS = {"api", "worker", "reducer"}
_AGGREGATED_ROLE_LABELS = ("api", "reducer")
_ROLE_SERVICE_NAMES = {
    "api": "secflow-app-binary-security",
    "reducer": "secflow-app-binary-security-reducer",
}
_POD_DISCOVERY_CACHE_TTL_SECONDS = 30.0
_AGGREGATED_METRICS_CACHE_TTL_SECONDS = 5.0
_SCRAPE_TIMEOUT_SECONDS = 1.5
_DISCOVERY_TIMEOUT_SECONDS = 2.0
_METRIC_NAME_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+([^\s]+)(?:\s+\d+)?$")
_HELP_RE = re.compile(r"^# HELP ([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(.+)$")
_TYPE_RE = re.compile(r"^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(counter|gauge|histogram|summary|untyped)$")
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')

_AUTHORITATIVE_REDUCER_MAX_METRICS = {
    "secflow_binary_security_queue_depth",
    "secflow_binary_security_queue_oldest_age_seconds",
    "secflow_binary_security_state_event_queue_depth",
    "secflow_binary_security_state_event_oldest_age_seconds",
    "secflow_binary_security_archive_jobs_by_status",
    "secflow_binary_security_task_state_lock_active",
}

_MAX_METRICS = {
    "secflow_binary_security_metrics_aggregate_last_success_timestamp_seconds",
}

_SUM_GAUGES = {
    "secflow_binary_security_active_workers",
    "secflow_binary_security_slot_usage",
    "secflow_binary_security_ai_role_count",
    "secflow_binary_security_auth_token_cache_entries",
}


@dataclass(frozen=True)
class PodTarget:
    pod_name: str
    role: str
    ip: str
    port: int = 8080

    @property
    def url(self) -> str:
        return f"http://{self.ip}:{self.port}/api/app/binary-security/metrics"


@dataclass
class MetricSample:
    name: str
    family_name: str
    labels: dict[str, str]
    value: float
    metric_type: str
    help_text: str | None


@dataclass
class AggregatedMetricSeries:
    metric_type: str
    help_text: str | None
    samples: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)


@dataclass
class ScrapeResult:
    target: PodTarget
    raw_text: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.raw_text) and not self.error


@dataclass
class AggregateMetadata:
    attempted_by_role: dict[str, int]
    successful_by_role: dict[str, int]
    partial: bool
    generated_at: float


@dataclass
class AggregatedMetricsPayload:
    payload: bytes
    content_type: str
    metadata: AggregateMetadata


def _sample_family_name(name: str) -> str:
    return re.sub(r"_(bucket|sum|count|total|created)$", "", name)


def _parse_labels(source: str | None) -> dict[str, str]:
    if not source:
        return {}
    labels: dict[str, str] = {}
    for match in _LABEL_RE.finditer(source):
        labels[match.group(1)] = (
            match.group(2)
            .replace(r"\n", "\n")
            .replace(r"\"", '"')
            .replace(r"\\", "\\")
        )
    return labels


def _escape_label_value(value: str) -> str:
    return value.replace("\\", r"\\").replace("\n", r"\n").replace('"', r"\"")


def _format_labels(labels: Iterable[tuple[str, str]]) -> str:
    rendered = ",".join(f'{key}="{_escape_label_value(value)}"' for key, value in labels)
    return f"{{{rendered}}}" if rendered else ""


def parse_prometheus_text(raw_text: str) -> list[MetricSample]:
    help_map: dict[str, str] = {}
    type_map: dict[str, str] = {}
    rows: list[MetricSample] = []
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("# HELP "):
            match = _HELP_RE.match(line)
            if match:
                help_map[match.group(1)] = match.group(2)
            continue
        if line.startswith("# TYPE "):
            match = _TYPE_RE.match(line)
            if match:
                type_map[match.group(1)] = match.group(2)
            continue
        if line.startswith("#"):
            continue
        match = _METRIC_NAME_RE.match(line)
        if not match:
            continue
        value = float(match.group(3))
        if not value == value or value in (float("inf"), float("-inf")):
            continue
        name = match.group(1)
        family_name = _sample_family_name(name)
        rows.append(
            MetricSample(
                name=name,
                family_name=family_name,
                labels=_parse_labels(match.group(2)),
                value=value,
                metric_type=type_map.get(family_name) or type_map.get(name) or "untyped",
                help_text=help_map.get(family_name) or help_map.get(name),
            )
        )
    return rows


def _source_priority_for_metric(metric_name: str) -> tuple[str, ...] | None:
    if metric_name in _AUTHORITATIVE_REDUCER_MAX_METRICS:
        return ("reducer", "worker", "api")
    return None


def _aggregate_values(metric_name: str, metric_type: str, values: list[float]) -> float:
    if metric_type in {"counter", "histogram", "summary"}:
        return sum(values)
    if metric_name in _AUTHORITATIVE_REDUCER_MAX_METRICS or metric_name in _MAX_METRICS:
        return max(values)
    if metric_name in _SUM_GAUGES:
        return sum(values)
    if metric_name.endswith("_oldest_age_seconds"):
        return max(values)
    return sum(values)


def aggregate_prometheus_samples(results: list[ScrapeResult]) -> dict[str, AggregatedMetricSeries]:
    bucket: dict[tuple[str, tuple[tuple[str, str], ...]], list[tuple[str, float, str, str | None]]] = {}
    for result in results:
        if not result.ok or not result.raw_text:
            continue
        for sample in parse_prometheus_text(result.raw_text):
            if sample.name.endswith("_created"):
                continue
            label_key = tuple(sorted(sample.labels.items()))
            bucket.setdefault((sample.name, label_key), []).append(
                (result.target.role, sample.value, sample.metric_type, sample.help_text)
            )

    aggregated: dict[str, AggregatedMetricSeries] = {}
    for (metric_name, label_key), observations in bucket.items():
        metric_type = next((item[2] for item in observations if item[2]), "untyped")
        help_text = next((item[3] for item in observations if item[3]), None)
        prioritized_roles = _source_priority_for_metric(metric_name)
        values: list[float]
        if prioritized_roles:
            selected_values: list[float] = []
            for role in prioritized_roles:
                selected_values = [value for source_role, value, _, _ in observations if source_role == role]
                if selected_values:
                    break
            values = selected_values or [value for _, value, _, _ in observations]
        else:
            values = [value for _, value, _, _ in observations]
        series = aggregated.setdefault(
            metric_name,
            AggregatedMetricSeries(metric_type=metric_type, help_text=help_text),
        )
        series.samples[label_key] = _aggregate_values(metric_name, metric_type, values)
    return aggregated


def render_aggregated_metrics(
    aggregated: dict[str, AggregatedMetricSeries],
    *,
    metadata: AggregateMetadata,
) -> bytes:
    lines: list[str] = []
    for metric_name in sorted(aggregated):
        series = aggregated[metric_name]
        if series.help_text:
            lines.append(f"# HELP {metric_name} {series.help_text}")
        lines.append(f"# TYPE {metric_name} {series.metric_type}")
        for label_key, value in sorted(series.samples.items()):
            lines.append(f"{metric_name}{_format_labels(label_key)} {value}")

    meta_metrics = {
        "secflow_binary_security_metrics_aggregate_scrape_targets": (
            "gauge",
            "Attempted scrape targets by role for the aggregate metrics endpoint.",
            metadata.attempted_by_role,
        ),
        "secflow_binary_security_metrics_aggregate_scrape_success_targets": (
            "gauge",
            "Successful scrape targets by role for the aggregate metrics endpoint.",
            metadata.successful_by_role,
        ),
    }
    for metric_name, (metric_type, help_text, values) in meta_metrics.items():
        lines.append(f"# HELP {metric_name} {help_text}")
        lines.append(f"# TYPE {metric_name} {metric_type}")
        for role in sorted(_ROLE_LABELS):
            lines.append(f'{metric_name}{{role="{role}"}} {float(values.get(role, 0))}')

    lines.append(
        "# HELP secflow_binary_security_metrics_aggregate_partial Whether the aggregate scrape was partial."
    )
    lines.append("# TYPE secflow_binary_security_metrics_aggregate_partial gauge")
    lines.append(
        f"secflow_binary_security_metrics_aggregate_partial {1.0 if metadata.partial else 0.0}"
    )

    lines.append(
        "# HELP secflow_binary_security_metrics_aggregate_last_success_timestamp_seconds Last aggregate generation time."
    )
    lines.append("# TYPE secflow_binary_security_metrics_aggregate_last_success_timestamp_seconds gauge")
    lines.append(
        f"secflow_binary_security_metrics_aggregate_last_success_timestamp_seconds {metadata.generated_at}"
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


async def _fetch_k8s_resource(path: str) -> dict:
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    if not os.path.exists(token_path):
        return {}
    try:
        with open(token_path, "r", encoding="utf-8") as token_file:
            token = token_file.read().strip()
    except OSError:
        return {}
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        return {}
    url = f"https://{host}:{port}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    verify = ca_path if os.path.exists(ca_path) else True
    try:
        async with httpx.AsyncClient(timeout=_DISCOVERY_TIMEOUT_SECONDS, verify=verify) as client:
            response = await client.get(url, headers=headers)
    except Exception:
        return {}
    if response.status_code >= 400:
        return {}
    return response.json()


async def _discover_binary_security_pods() -> list[PodTarget]:
    namespace = (
        str(os.environ.get("POD_NAMESPACE") or "").strip()
        or str(os.environ.get("NAMESPACE") or "").strip()
        or "secflow-ns"
    )
    pods: list[PodTarget] = []
    seen: set[tuple[str, str]] = set()
    for role in _AGGREGATED_ROLE_LABELS:
        service_name = _ROLE_SERVICE_NAMES[role]
        payload = await _fetch_k8s_resource(f"/api/v1/namespaces/{namespace}/endpoints/{service_name}")
        for subset in payload.get("subsets") or []:
            ports = subset.get("ports") or []
            port_value = next((int(port.get("port")) for port in ports if port.get("port")), 8080)
            for address in subset.get("addresses") or []:
                ip = str(address.get("ip") or "").strip()
                target_ref = address.get("targetRef") or {}
                pod_name = str(target_ref.get("name") or address.get("hostname") or ip).strip()
                if not ip or not pod_name:
                    continue
                dedupe_key = (role, ip)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                pods.append(PodTarget(pod_name=pod_name, role=role, ip=ip, port=port_value))
    return sorted(pods, key=lambda item: (item.role, item.pod_name))


def _discover_local_pod_ip() -> list[PodTarget]:
    role = str(os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or "").strip().lower()
    pod_ip = str(os.environ.get("POD_IP") or "").strip()
    if role not in _AGGREGATED_ROLE_LABELS or not pod_ip:
        return []
    return [PodTarget(pod_name=str(os.environ.get("HOSTNAME") or pod_ip), role=role, ip=pod_ip)]


async def _scrape_pod_metrics(target: PodTarget) -> ScrapeResult:
    client = await get_shared_async_client("binary-security-metrics-aggregate", timeout=_SCRAPE_TIMEOUT_SECONDS)
    try:
        response = await client.get(target.url, headers={"Accept": "text/plain"})
    except Exception as exc:
        return ScrapeResult(target=target, error=str(exc))
    if response.status_code >= 400:
        return ScrapeResult(target=target, error=f"upstream status {response.status_code}")
    return ScrapeResult(target=target, raw_text=response.text)


class BinarySecurityMetricsAggregator:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._cached_pods: list[PodTarget] = []
        self._cached_pods_at = 0.0
        self._cached_payload: AggregatedMetricsPayload | None = None
        self._cached_payload_at = 0.0

    async def aggregate(self) -> AggregatedMetricsPayload:
        now = time.time()
        async with self._lock:
            if self._cached_payload and now - self._cached_payload_at <= _AGGREGATED_METRICS_CACHE_TTL_SECONDS:
                return self._cached_payload
        pods = await self._discover_pods_cached()
        if not pods:
            pods = _discover_local_pod_ip()
        results = await asyncio.gather(*(_scrape_pod_metrics(pod) for pod in pods), return_exceptions=False)
        successful = [result for result in results if result.ok]
        if not successful:
            raise RuntimeError("No binary-security pod metrics could be scraped")
        attempted_by_role = {role: 0 for role in _ROLE_LABELS}
        successful_by_role = {role: 0 for role in _ROLE_LABELS}
        for result in results:
            attempted_by_role[result.target.role] = attempted_by_role.get(result.target.role, 0) + 1
            if result.ok:
                successful_by_role[result.target.role] = successful_by_role.get(result.target.role, 0) + 1
        metadata = AggregateMetadata(
            attempted_by_role=attempted_by_role,
            successful_by_role=successful_by_role,
            partial=len(successful) != len(results),
            generated_at=time.time(),
        )
        payload = AggregatedMetricsPayload(
            payload=render_aggregated_metrics(aggregate_prometheus_samples(results), metadata=metadata),
            content_type=CONTENT_TYPE_LATEST,
            metadata=metadata,
        )
        async with self._lock:
            self._cached_payload = payload
            self._cached_payload_at = time.time()
        return payload

    async def _discover_pods_cached(self) -> list[PodTarget]:
        now = time.time()
        async with self._lock:
            if self._cached_pods and now - self._cached_pods_at <= _POD_DISCOVERY_CACHE_TTL_SECONDS:
                return list(self._cached_pods)
        pods = await _discover_binary_security_pods()
        async with self._lock:
            self._cached_pods = list(pods)
            self._cached_pods_at = time.time()
        return pods


_aggregator = BinarySecurityMetricsAggregator()


def get_metrics_aggregator() -> BinarySecurityMetricsAggregator:
    return _aggregator
