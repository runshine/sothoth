import asyncio
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app import main
from app.observability import observe_api_request


class MainRoleTests(unittest.TestCase):
    def test_service_role_defaults_to_all(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual("all", main._service_role())

    def test_service_role_normalizes_known_values(self):
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "WORKER"}, clear=True):
            self.assertEqual("worker", main._service_role())

    def test_scheduler_env_override_wins(self):
        with patch.dict(
            os.environ,
            {
                "SECFLOW_BINARY_SECURITY_ROLE": "api",
                "SECFLOW_BINARY_SECURITY_ENABLE_SCHEDULER": "true",
            },
            clear=True,
        ):
            self.assertTrue(main._scheduler_enabled())

    def test_scheduler_defaults_follow_role(self):
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "api"}, clear=True):
            self.assertFalse(main._scheduler_enabled())
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "worker"}, clear=True):
            self.assertTrue(main._scheduler_enabled())

    def test_scheduler_falls_back_to_config_for_all_role(self):
        fake_config = SimpleNamespace(scheduler=SimpleNamespace(enabled=False))
        with patch.dict(os.environ, {}, clear=True), patch("app.main.get_config", return_value=fake_config):
            self.assertFalse(main._scheduler_enabled())

    def test_registry_disabled_for_worker_role(self):
        fake_config = SimpleNamespace(registry=SimpleNamespace(enabled=True))
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "worker"}, clear=True), patch(
            "app.main.get_config", return_value=fake_config
        ):
            self.assertFalse(main._registry_enabled())

    def test_metrics_endpoint_exposes_prometheus_payload(self):
        observe_api_request("GET", "/health", 200, 0.01)
        response = asyncio.run(main.metrics_endpoint())
        self.assertEqual(200, response.status_code)
        self.assertIn("text/plain", response.media_type or "")
        body = response.body.decode("utf-8", errors="ignore")
        self.assertIn("secflow_binary_security_api_requests_total", body)

    def test_reducer_metrics_endpoint_reads_snapshot_when_running_as_api(self):
        fake_store = SimpleNamespace(
            render_metrics=AsyncMock(
                return_value=(b"# HELP demo metric\n# TYPE demo gauge\ndemo 1\n", "text/plain; version=0.0.4; charset=utf-8")
            )
        )
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "api"}, clear=True), patch(
            "app.main.get_reducer_metrics_snapshot_store",
            return_value=fake_store,
        ):
            response = asyncio.run(main.reducer_metrics_endpoint())
        self.assertEqual(200, response.status_code)
        self.assertIn("text/plain", response.media_type or "")
        body = response.body.decode("utf-8", errors="ignore")
        self.assertIn("# HELP demo metric", body)
        fake_store.render_metrics.assert_awaited_once_with(fallback_payload=None)

    def test_reducer_metrics_endpoint_passes_local_fallback_when_running_as_reducer(self):
        fake_store = SimpleNamespace(
            render_metrics=AsyncMock(return_value=(b"demo 1\n", "text/plain; version=0.0.4; charset=utf-8"))
        )
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "reducer"}, clear=True), patch(
            "app.main.get_reducer_metrics_snapshot_store",
            return_value=fake_store,
        ):
            response = asyncio.run(main.reducer_metrics_endpoint())
        self.assertEqual(200, response.status_code)
        self.assertIn("text/plain", response.media_type or "")
        fallback_payload = fake_store.render_metrics.await_args.kwargs.get("fallback_payload")
        self.assertIsInstance(fallback_payload, str)
        self.assertIn("secflow_binary_security_api_requests_total", fallback_payload)

    def test_ready_route_returns_503_when_checks_fail(self):
        async def fake_collect():
            return {
                "status": "not_ready",
                "role": "worker",
                "checks": {
                    "process": {"ok": True, "detail": "alive"},
                    "scheduler": {"ok": False, "detail": {"missing_loops": ["task_dispatch"]}},
                },
            }

        from app.api import tasks as task_routes

        with patch("app.api.tasks.collect_readiness", side_effect=fake_collect):
            response = asyncio.run(task_routes.ready_check())
        self.assertEqual(503, response.status_code)
        self.assertIn("not_ready", response.body.decode("utf-8", errors="ignore"))

    def test_ready_route_returns_200_when_checks_pass(self):
        async def fake_collect():
            return {
                "status": "ready",
                "role": "worker",
                "checks": {
                    "process": {"ok": True, "detail": "alive"},
                    "scheduler": {"ok": True, "detail": {"missing_loops": []}},
                },
            }

        from app.api import tasks as task_routes

        with patch("app.api.tasks.collect_readiness", side_effect=fake_collect):
            response = asyncio.run(task_routes.ready_check())
        self.assertEqual(200, response.status_code)
        self.assertIn("ready", response.body.decode("utf-8", errors="ignore"))

    def test_health_route_returns_lightweight_payload(self):
        from app.api import tasks as task_routes

        with patch("app.api.tasks.collect_liveness", return_value={"status": "ok", "role": "worker", "checks": {"process": {"ok": True}}}):
            payload = asyncio.run(task_routes.health_check())
        self.assertEqual("ok", payload["status"])
        self.assertEqual("worker", payload["role"])
        self.assertEqual("secflow-app-binary-security", payload["service"])


if __name__ == "__main__":
    unittest.main()
