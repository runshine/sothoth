"""Dynamic pi-re-agent worker discovery and capacity tracking."""

from __future__ import annotations

import asyncio
import os
import socket
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import get_config
from app.service.pi_re_agent import get_pi_client
from app.time_utils import isoformat_local, now_local


@dataclass
class PiWorkerSnapshot:
    worker_id: str
    url: str
    healthy: bool
    max_concurrent_jobs: int
    running_jobs: int = 0
    queued_jobs: int = 0
    source: str = "fallback"
    error: str | None = None


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


class PiClusterMonitor:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._snapshot = PiClusterSnapshot(updated_at=isoformat_local(now_local()))

    async def refresh(self) -> PiClusterSnapshot:
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
                    healthy=False,
                    max_concurrent_jobs=0,
                    error=str(result),
                ))
        snapshot = PiClusterSnapshot(workers=snapshots, updated_at=isoformat_local(now_local()))
        async with self._lock:
            self._snapshot = snapshot
        return snapshot

    async def snapshot(self) -> PiClusterSnapshot:
        async with self._lock:
            return self._snapshot


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
    return PiWorkerSnapshot(
        worker_id=worker_id,
        url=url.rstrip("/"),
        healthy=bool(payload.get("healthy", True)),
        max_concurrent_jobs=int(payload.get("max_concurrent_jobs") or cfg.default_worker_max_concurrent_jobs),
        running_jobs=int(payload.get("running_jobs") or payload.get("running") or 0),
        queued_jobs=int(payload.get("queued_jobs") or payload.get("queued") or 0),
        source="capacity",
    )


_monitor = PiClusterMonitor()


def get_pi_cluster_monitor() -> PiClusterMonitor:
    return _monitor
