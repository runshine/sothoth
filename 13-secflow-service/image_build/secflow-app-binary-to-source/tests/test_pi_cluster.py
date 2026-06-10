from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import tasks as tasks_api
from app.service import pi_cluster


class _FakePiClient:
    def __init__(self, *, capacity_payload=None, capacity_error=None, jobs=None, job_details=None):
        self.capacity_payload = capacity_payload
        self.capacity_error = capacity_error
        self.jobs = list(jobs or [])
        self.job_details = dict(job_details or {})

    async def capacity(self):
        if self.capacity_error:
            raise self.capacity_error
        return self.capacity_payload

    async def list_jobs(self, **_params):
        return self.jobs

    async def get_job(self, job_id):
        return self.job_details.get(job_id)


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
    def test_cluster_snapshot_uses_global_queue_count_without_double_counting(self):
        snapshot = pi_cluster.PiClusterSnapshot(workers=[
            pi_cluster.PiWorkerSnapshot(
                worker_id="pi-1",
                url="http://pi-1:8000",
                healthy=True,
                max_concurrent_jobs=3,
                running_jobs=1,
                queued_jobs=4,
            ),
            pi_cluster.PiWorkerSnapshot(
                worker_id="pi-2",
                url="http://pi-2:8000",
                healthy=True,
                max_concurrent_jobs=3,
                running_jobs=2,
                queued_jobs=4,
            ),
        ])

        self.assertEqual(4, snapshot.queued_jobs)

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

    def test_fetch_worker_active_jobs_only_keeps_running_jobs_and_uses_detail_progress(self):
        fake_client = _FakePiClient(
            jobs=[
                {
                    "id": "job-running",
                    "status": "running",
                    "phase": "body_generation",
                    "target": "/tmp/demo-running.elf",
                    "created_at": "2026-05-20T10:00:00",
                    "updated_at": "2026-05-20T10:01:00",
                    "worker_id": "pi-1",
                },
                {
                    "id": "job-queued",
                    "status": "queued",
                    "phase": "queued",
                    "target": "/tmp/demo-queued.elf",
                    "created_at": "2026-05-20T10:02:00",
                    "updated_at": "2026-05-20T10:03:00",
                    "worker_id": "pi-1",
                },
            ],
            job_details={
                "job-running": {
                    "id": "job-running",
                    "status": "running",
                    "phase": "body_generation",
                    "target": "/tmp/demo-running.elf",
                    "created_at": "2026-05-20T10:00:00",
                    "updated_at": "2026-05-20T10:05:00",
                    "worker_id": "pi-1",
                    "progress": {
                        "current_batch": 4,
                        "current_attempt": 2,
                        "current_function": "demo_func",
                    },
                },
            },
        )

        async def _run():
            with mock.patch.object(pi_cluster, "get_pi_client", return_value=fake_client):
                return await pi_cluster.fetch_worker_active_jobs(
                    pi_cluster.PiWorkerSnapshot(
                        worker_id="pi-1",
                        url="http://pi-1:8000",
                        healthy=True,
                        max_concurrent_jobs=3,
                    )
                )

        jobs = asyncio.run(_run())

        self.assertEqual(1, len(jobs))
        self.assertEqual("job-running", jobs[0].pi_job_id)
        self.assertEqual("demo-running.elf", jobs[0].elf_name)
        self.assertEqual(4, jobs[0].current_batch)
        self.assertEqual(2, jobs[0].current_attempt)
        self.assertEqual("demo_func", jobs[0].current_function)

    def test_pi_cluster_api_uses_cached_snapshot_without_refresh(self):
        app = FastAPI()
        app.include_router(tasks_api.router)

        cache_state = pi_cluster.PiClusterCacheState(
            snapshot=pi_cluster.PiClusterSnapshot(workers=[
                pi_cluster.PiWorkerSnapshot(
                    worker_id="pi-1",
                    url="http://pi-1:8000",
                    healthy=True,
                    max_concurrent_jobs=4,
                    running_jobs=2,
                    queued_jobs=1,
                    pod_name="worker-1",
                    source="capacity",
                    active_jobs=[
                        pi_cluster.PiWorkerActiveJobSnapshot(
                            pi_job_id="job-1",
                            status="running",
                            worker_id="pi-1",
                            started_at="2026-05-20T10:00:00",
                            updated_at="2026-05-20T10:05:00",
                        )
                    ],
                )
            ], updated_at="2026-05-20T10:05:00"),
            refreshed_at="2026-05-20T10:05:00",
            expires_at="2026-05-20T10:06:00",
            last_success_at="2026-05-20T10:05:00",
            last_error=None,
            refresh_in_progress=False,
        )

        class _FakeMonitor:
            async def get_cached_state(self):
                return cache_state

        async def fake_context():
            return tasks_api.TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")

        class _FakeQuery:
            def filter(self, *_args, **_kwargs):
                return self

            def all(self):
                return []

        class _FakeDB:
            def query(self, *_args, **_kwargs):
                return _FakeQuery()

        def fake_db():
            yield _FakeDB()

        app.dependency_overrides[tasks_api.get_current_user_context] = fake_context
        app.dependency_overrides[tasks_api.get_db] = fake_db

        with mock.patch.object(tasks_api, "get_pi_cluster_monitor", return_value=_FakeMonitor()):
            client = TestClient(app)
            resp = client.get("/api/app/binary-to-source/pi-cluster", headers={"Authorization": "Bearer test-token"})

        self.assertEqual(200, resp.status_code)
        payload = resp.json()
        self.assertEqual("2026-05-20T10:05:00", payload["snapshot_refreshed_at"])
        self.assertIsInstance(payload["snapshot_stale"], bool)
        self.assertEqual("2026-05-20T10:06:00", payload["snapshot_expires_at"])
        self.assertEqual(1, payload["worker_count"])


if __name__ == "__main__":
    unittest.main()
