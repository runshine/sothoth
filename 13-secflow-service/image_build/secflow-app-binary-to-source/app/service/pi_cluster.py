"""Dynamic pi-re-agent worker discovery and capacity tracking."""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import get_config
from app.observability import get_observability
from app.service.pod_metrics import fetch_pod_resource_map
from app.service.pi_re_agent import get_pi_client
from app.time_utils import ensure_local, isoformat_local, now_local


_CACHE_REFRESH_INTERVAL_SECONDS = 60.0
_CACHE_TTL_SECONDS = 60.0


def _infer_pod_name_from_url(url: str) -> str | None:
    try:
        host = (urlparse(url).hostname or "").strip()
    except Exception:
        host = ""
    if not host:
        return None
    if host.startswith("secflow-pi-re-agent-"):
        return host.split(".", 1)[0]
    return None


@dataclass
class PiWorkerSnapshot:
    worker_id: str
    url: str
    healthy: bool
    max_concurrent_jobs: int
    pod_name: str | None = None
    pod_ip: str | None = None
    running_jobs: int = 0
    queued_jobs: int = 0
    pod_created_at: str | None = None
    pod_started_at: str | None = None
    pod_metrics_at: str | None = None
    pod_cpu_usage_millicores: int | None = None
    pod_memory_usage_bytes: int | None = None
    pod_cpu_request_millicores: int | None = None
    pod_memory_request_bytes: int | None = None
    pod_cpu_limit_millicores: int | None = None
    pod_memory_limit_bytes: int | None = None
    source: str = "fallback"
    error: str | None = None
    active_jobs: list["PiWorkerActiveJobSnapshot"] = field(default_factory=list)


@dataclass
class PiWorkerActiveJobSnapshot:
    pi_job_id: str
    status: str
    phase: str | None = None
    worker_id: str | None = None
    elf_path: str | None = None
    elf_name: str | None = None
    current_batch: int | None = None
    current_attempt: int | None = None
    current_function: str | None = None
    started_at: str | None = None
    updated_at: str | None = None


@dataclass
class PiClusterSnapshot:
    workers: list[PiWorkerSnapshot] = field(default_factory=list)
    updated_at: str | None = None

    @property
    def worker_count(self) -> int:
        return len([worker for worker in self.workers if worker.healthy])

    @property
    def total_capacity(self) -> int:
        return sum(worker.max_concurrent_jobs for worker in self.workers if worker.healthy)

    @property
    def running_jobs(self) -> int:
        return sum(worker.running_jobs for worker in self.workers if worker.healthy)

    @property
    def queued_jobs(self) -> int:
        return max((worker.queued_jobs for worker in self.workers if worker.healthy), default=0)

    @property
    def available_slots(self) -> int:
        return max(0, self.total_capacity - self.running_jobs)


@dataclass
class PiClusterCacheState:
    snapshot: PiClusterSnapshot = field(default_factory=PiClusterSnapshot)
    refreshed_at: str | None = None
    expires_at: str | None = None
    last_success_at: str | None = None
    last_error: str | None = None
    refresh_in_progress: bool = False

    @property
    def stale(self) -> bool:
        if not self.expires_at:
            return True
        try:
            expires_at = ensure_local(datetime.fromisoformat(self.expires_at))
            return expires_at is None or now_local() > expires_at
        except Exception:
            return True


class PiClusterMonitor:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._refresh_task: asyncio.Task | None = None
        self._cache = PiClusterCacheState(
            snapshot=PiClusterSnapshot(updated_at=None),
            refreshed_at=None,
            expires_at=None,
            last_success_at=None,
            last_error=None,
            refresh_in_progress=False,
        )

    async def _collect_snapshot(self) -> PiClusterSnapshot:
        urls = await discover_worker_urls()
        workers = await asyncio.gather(*(probe_worker(url) for url in urls), return_exceptions=True)
        snapshots: list[PiWorkerSnapshot] = []
        for url, result in zip(urls, workers):
            if isinstance(result, PiWorkerSnapshot):
                snapshots.append(result)
            else:
                snapshots.append(PiWorkerSnapshot(
                    worker_id=url.rsplit("/", 1)[-1] or url,
                    url=url,
                    pod_name=None,
                    pod_ip=None,
                    healthy=False,
                    max_concurrent_jobs=0,
                    error=str(result),
                ))
        active_jobs_by_worker, worker_job_errors = await _load_worker_active_jobs(snapshots)
        pod_resource_map = fetch_pod_resource_map(
            pod_names=[str(worker.pod_name or "").strip() for worker in snapshots if str(worker.pod_name or "").strip()],
        )
        snapshot = PiClusterSnapshot(
            workers=[
                PiWorkerSnapshot(
                    worker_id=worker.worker_id,
                    url=worker.url,
                    pod_name=worker.pod_name,
                    pod_ip=worker.pod_ip,
                    healthy=worker.healthy,
                    max_concurrent_jobs=worker.max_concurrent_jobs,
                    running_jobs=worker.running_jobs,
                    queued_jobs=worker.queued_jobs,
                    pod_created_at=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_created_at"),
                    pod_started_at=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_started_at"),
                    pod_metrics_at=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_metrics_at"),
                    pod_cpu_usage_millicores=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_cpu_usage_millicores"),
                    pod_memory_usage_bytes=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_memory_usage_bytes"),
                    pod_cpu_request_millicores=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_cpu_request_millicores"),
                    pod_memory_request_bytes=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_memory_request_bytes"),
                    pod_cpu_limit_millicores=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_cpu_limit_millicores"),
                    pod_memory_limit_bytes=(pod_resource_map.get(str(worker.pod_name or "").strip(), {}) or {}).get("pod_memory_limit_bytes"),
                    source=worker.source,
                    error=_merge_worker_error(worker.error, worker_job_errors.get(worker.worker_id)),
                    active_jobs=active_jobs_by_worker.get(worker.worker_id, []),
                )
                for worker in snapshots
            ],
            updated_at=isoformat_local(now_local()),
        )
        return snapshot

    async def refresh_once(self) -> PiClusterSnapshot:
        started_at = time.perf_counter()
        async with self._lock:
            if self._cache.refresh_in_progress:
                return self._cache.snapshot
            self._cache.refresh_in_progress = True
        try:
            snapshot = await self._collect_snapshot()
            now = now_local()
            refreshed_at = isoformat_local(now)
            expires_at = isoformat_local(now + timedelta(seconds=_CACHE_TTL_SECONDS))
            age_seconds = 0.0
            async with self._lock:
                self._cache.snapshot = snapshot
                self._cache.refreshed_at = refreshed_at
                self._cache.expires_at = expires_at
                self._cache.last_success_at = refreshed_at
                self._cache.last_error = None
            duration = max(0.0, time.perf_counter() - started_at)
            obs = get_observability().prom
            obs.inc("pi_cluster_cache_refresh")
            obs.observe("pi_cluster_cache_refresh_duration", duration)
            obs.set_gauge("pi_cluster_cache_age_seconds", age_seconds)
            return snapshot
        except Exception as exc:
            duration = max(0.0, time.perf_counter() - started_at)
            async with self._lock:
                self._cache.last_error = str(exc)
            obs = get_observability().prom
            obs.inc("pi_cluster_cache_refresh_failed")
            obs.observe("pi_cluster_cache_refresh_duration", duration)
            raise
        finally:
            async with self._lock:
                self._cache.refresh_in_progress = False

    async def get_cached_state(self) -> PiClusterCacheState:
        async with self._lock:
            cache = self._cache
            return PiClusterCacheState(
                snapshot=cache.snapshot,
                refreshed_at=cache.refreshed_at,
                expires_at=cache.expires_at,
                last_success_at=cache.last_success_at,
                last_error=cache.last_error,
                refresh_in_progress=cache.refresh_in_progress,
            )

    async def snapshot(self) -> PiClusterSnapshot:
        return (await self.get_cached_state()).snapshot

    async def start(self) -> None:
        if self._refresh_task and not self._refresh_task.done():
            return
        try:
            await self.refresh_once()
        except Exception:
            pass
        self._refresh_task = asyncio.create_task(self._refresh_loop(), name="b2s-pi-cluster-refresh")

    async def stop(self) -> None:
        if not self._refresh_task:
            return
        self._refresh_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._refresh_task
        self._refresh_task = None

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(_CACHE_REFRESH_INTERVAL_SECONDS)
            try:
                await self.refresh_once()
            except Exception:
                pass


async def discover_worker_urls() -> list[str]:
    cfg = get_config().pi_re_agent
    if cfg.discovery_mode == "k8s_headless":
        urls = await _discover_from_k8s_endpoints()
        if urls:
            return urls
    if cfg.worker_urls:
        return sorted({url.rstrip("/") for url in cfg.worker_urls})
    return [cfg.base_url.rstrip("/")]


async def _discover_from_k8s_endpoints() -> list[str]:
    cfg = get_config().pi_re_agent
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    if not os.path.exists(token_path):
        return _discover_from_dns()
    try:
        with open(token_path, "r", encoding="utf-8") as token_file:
            token = token_file.read().strip()
    except OSError:
        return _discover_from_dns()
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        return _discover_from_dns()
    url = (
        f"https://{host}:{port}/api/v1/namespaces/"
        f"{cfg.discovery_namespace}/endpoints/{cfg.discovery_service_name}"
    )
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=cfg.worker_probe_timeout_seconds, verify=ca_path if os.path.exists(ca_path) else True) as client:
            resp = await client.get(url, headers=headers)
    except Exception:
        return _discover_from_dns()
    if resp.status_code != 200:
        return _discover_from_dns()
    payload = resp.json()
    urls: set[str] = set()
    for subset in payload.get("subsets") or []:
        ports = subset.get("ports") or []
        port_value = next((int(port.get("port")) for port in ports if port.get("port")), cfg.discovery_port)
        for address in subset.get("addresses") or []:
            hostname = str(address.get("hostname") or "").strip()
            ip = str(address.get("ip") or "").strip()
            host_value = (
                f"{hostname}.{cfg.discovery_service_name}.{cfg.discovery_namespace}.svc.cluster.local"
                if hostname else ip
            )
            if host_value:
                urls.add(f"http://{host_value}:{port_value}")
    return sorted(urls)


def _discover_from_dns() -> list[str]:
    cfg = get_config().pi_re_agent
    host = f"{cfg.discovery_service_name}.{cfg.discovery_namespace}.svc.cluster.local"
    try:
        infos = socket.getaddrinfo(host, cfg.discovery_port, type=socket.SOCK_STREAM)
    except OSError:
        return []
    urls = {f"http://{info[4][0]}:{cfg.discovery_port}" for info in infos if info and info[4]}
    return sorted(urls)


async def probe_worker(url: str) -> PiWorkerSnapshot:
    cfg = get_config().pi_re_agent
    client = get_pi_client(url)
    worker_id = url.rsplit("//", 1)[-1].split(":", 1)[0]
    try:
        payload = await client.capacity()
        return _snapshot_from_capacity(url, payload)
    except Exception as exc:
        await client.list_jobs()
        return PiWorkerSnapshot(
            worker_id=worker_id,
            url=url.rstrip("/"),
            pod_name=None,
            pod_ip=None,
            healthy=True,
            max_concurrent_jobs=cfg.default_worker_max_concurrent_jobs,
            running_jobs=0,
            queued_jobs=0,
            source="jobs_fallback",
            error=str(exc),
        )


def _snapshot_from_capacity(url: str, payload: dict[str, Any]) -> PiWorkerSnapshot:
    cfg = get_config().pi_re_agent
    worker_id = str(payload.get("worker_id") or url.rsplit("//", 1)[-1].split(":", 1)[0])
    inferred_pod_name = _infer_pod_name_from_url(url)
    return PiWorkerSnapshot(
        worker_id=worker_id,
        url=url.rstrip("/"),
        pod_name=str(payload.get("pod_name") or "").strip() or inferred_pod_name,
        pod_ip=str(payload.get("pod_ip") or "").strip() or None,
        healthy=bool(payload.get("healthy", True)),
        max_concurrent_jobs=int(payload.get("max_concurrent_jobs") or cfg.default_worker_max_concurrent_jobs),
        running_jobs=int(payload.get("running_jobs") or payload.get("running") or 0),
        queued_jobs=int(payload.get("queued_jobs") or payload.get("queued") or 0),
        source="capacity",
    )


def _merge_worker_error(worker_error: str | None, detail_error: str | None) -> str | None:
    left = str(worker_error or "").strip()
    right = str(detail_error or "").strip()
    if left and right:
        return f"{left}; active_jobs={right}"
    return left or right or None


async def fetch_worker_active_jobs(worker: PiWorkerSnapshot) -> list[PiWorkerActiveJobSnapshot]:
    client = get_pi_client(worker.url)
    jobs = await client.list_jobs(active=True, worker_id=worker.worker_id)
    running_jobs = [
        job for job in jobs
        if str(job.get("status") or "").strip().lower() == "running"
    ]
    if not running_jobs:
        return []

    details = await asyncio.gather(
        *(client.get_job(str(job.get("id") or "").strip()) for job in running_jobs),
        return_exceptions=True,
    )
    snapshots: list[PiWorkerActiveJobSnapshot] = []
    for summary, detail in zip(running_jobs, details):
        if isinstance(detail, Exception):
            detail = None
        payload = detail if isinstance(detail, dict) else summary
        progress = payload.get("progress") if isinstance(payload.get("progress"), dict) else {}
        elf_path = str(payload.get("target") or summary.get("target") or "").strip() or None
        snapshots.append(PiWorkerActiveJobSnapshot(
            pi_job_id=str(payload.get("id") or summary.get("id") or "").strip(),
            status=str(payload.get("status") or summary.get("status") or "").strip() or "running",
            phase=str(payload.get("phase") or summary.get("phase") or "").strip() or None,
            worker_id=str(payload.get("worker_id") or summary.get("worker_id") or worker.worker_id).strip() or worker.worker_id,
            elf_path=elf_path,
            elf_name=Path(elf_path).name if elf_path else None,
            current_batch=_int_or_none(progress.get("current_batch")),
            current_attempt=_int_or_none(progress.get("current_attempt")),
            current_function=str(progress.get("current_function") or "").strip() or None,
            started_at=str(payload.get("created_at") or summary.get("created_at") or "").strip() or None,
            updated_at=str(payload.get("updated_at") or summary.get("updated_at") or "").strip() or None,
        ))
    return snapshots


def _int_or_none(value: object) -> int | None:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except Exception:
        return None
    return parsed


async def _load_worker_active_jobs(workers: list[PiWorkerSnapshot]) -> tuple[dict[str, list[PiWorkerActiveJobSnapshot]], dict[str, str]]:
    healthy_workers = [worker for worker in workers if worker.healthy]
    results = await asyncio.gather(*(fetch_worker_active_jobs(worker) for worker in healthy_workers), return_exceptions=True)
    active_jobs_by_worker: dict[str, list[PiWorkerActiveJobSnapshot]] = {worker.worker_id: [] for worker in workers}
    worker_errors: dict[str, str] = {}
    for worker, result in zip(healthy_workers, results):
        if isinstance(result, Exception):
            worker_errors[worker.worker_id] = str(result)
            active_jobs_by_worker[worker.worker_id] = []
        else:
            active_jobs_by_worker[worker.worker_id] = result
    return active_jobs_by_worker, worker_errors


_monitor = PiClusterMonitor()


def get_pi_cluster_monitor() -> PiClusterMonitor:
    return _monitor
