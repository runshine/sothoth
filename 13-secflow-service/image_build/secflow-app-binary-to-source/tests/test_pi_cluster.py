from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

from app.service import pi_cluster


class _FakePiClient:
    def __init__(self, *, capacity_payload=None, capacity_error=None, jobs=None):
        self.capacity_payload = capacity_payload
        self.capacity_error = capacity_error
        self.jobs = list(jobs or [])

    async def capacity(self):
        if self.capacity_error:
            raise self.capacity_error
        return self.capacity_payload

    async def list_jobs(self):
        return self.jobs


def _config(**overrides):
    values = {
        "discovery_mode": "k8s_headless",
        "worker_urls": [],
        "base_url": "http://secflow-pi-re-agent:8000",
        "discovery_service_name": "secflow-pi-re-agent-headless",
        "discovery_namespace": "secflow-ns",
        "discovery_port": 8000,
        "worker_probe_timeout_seconds": 5,
        "default_worker_max_concurrent_jobs": 3,
    }
    values.update(overrides)
    return SimpleNamespace(pi_re_agent=SimpleNamespace(**values))


class PiClusterTests(unittest.TestCase):
    def test_discover_worker_urls_prefers_k8s_headless_results(self):
        async def _run():
            with (
                mock.patch.object(pi_cluster, "get_config", return_value=_config()),
                mock.patch.object(pi_cluster, "_discover_from_k8s_endpoints", return_value=["http://worker-1:8000"]),
            ):
                return await pi_cluster.discover_worker_urls()

        self.assertEqual(["http://worker-1:8000"], asyncio.run(_run()))

    def test_discover_worker_urls_falls_back_to_static_workers(self):
        async def _run():
            with (
                mock.patch.object(pi_cluster, "get_config", return_value=_config(worker_urls=["http://worker-2:8000/"])),
                mock.patch.object(pi_cluster, "_discover_from_k8s_endpoints", return_value=[]),
            ):
                return await pi_cluster.discover_worker_urls()

        self.assertEqual(["http://worker-2:8000"], asyncio.run(_run()))

    def test_probe_worker_uses_capacity_endpoint_when_available(self):
        fake_client = _FakePiClient(capacity_payload={
            "worker_id": "pi-1",
            "healthy": True,
            "max_concurrent_jobs": 5,
            "running_jobs": 4,
            "queued_jobs": 1,
        })

        async def _run():
            with (
                mock.patch.object(pi_cluster, "get_config", return_value=_config(default_worker_max_concurrent_jobs=3)),
                mock.patch.object(pi_cluster, "get_pi_client", return_value=fake_client),
            ):
                return await pi_cluster.probe_worker("http://pi-1:8000")

        snapshot = asyncio.run(_run())

        self.assertEqual("pi-1", snapshot.worker_id)
        self.assertEqual(5, snapshot.max_concurrent_jobs)
        self.assertEqual(4, snapshot.running_jobs)
        self.assertEqual(1, snapshot.queued_jobs)
        self.assertEqual("capacity", snapshot.source)

    def test_probe_worker_falls_back_to_default_capacity_when_capacity_endpoint_missing(self):
        fake_client = _FakePiClient(capacity_error=RuntimeError("404"), jobs=[{"status": "running"}])

        async def _run():
            with (
                mock.patch.object(pi_cluster, "get_config", return_value=_config(default_worker_max_concurrent_jobs=3)),
                mock.patch.object(pi_cluster, "get_pi_client", return_value=fake_client),
            ):
                return await pi_cluster.probe_worker("http://pi-2:8000")

        snapshot = asyncio.run(_run())

        self.assertTrue(snapshot.healthy)
        self.assertEqual(3, snapshot.max_concurrent_jobs)
        self.assertEqual("jobs_fallback", snapshot.source)


if __name__ == "__main__":
    unittest.main()
