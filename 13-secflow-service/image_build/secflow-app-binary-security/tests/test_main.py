import asyncio
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
