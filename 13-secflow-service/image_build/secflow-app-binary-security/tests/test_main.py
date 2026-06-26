import asyncio
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app import main
from app.observability import observe_http_request


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
        observe_http_request("GET", "/health", 200, 0.01)
        response = asyncio.run(main.metrics_endpoint())
        self.assertEqual(200, response.status_code)
        self.assertIn("text/plain", response.media_type or "")
        body = response.body.decode("utf-8", errors="ignore")
        self.assertIn("secflow_binary_security_http_requests_total", body)

    def test_state_event_metrics_endpoint_reads_snapshot_when_running_as_api(self):
        fake_store = SimpleNamespace(
            render_metrics=AsyncMock(
                return_value=(b"# HELP demo metric\n# TYPE demo gauge\ndemo 1\n", "text/plain; version=0.0.4; charset=utf-8")
            )
        )
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "api"}, clear=True), patch(
            "app.main.get_state_event_inbox_metrics_snapshot_store",
            return_value=fake_store,
        ):
            response = asyncio.run(main.state_event_metrics_endpoint())
        self.assertEqual(200, response.status_code)
        self.assertIn("text/plain", response.media_type or "")
        body = response.body.decode("utf-8", errors="ignore")
        self.assertIn("# HELP demo metric", body)
        fake_store.render_metrics.assert_awaited_once_with(fallback_payload=None)

    def test_state_event_metrics_endpoint_does_not_pass_local_fallback_when_running_as_worker(self):
        fake_store = SimpleNamespace(
            render_metrics=AsyncMock(return_value=(b"demo 1\n", "text/plain; version=0.0.4; charset=utf-8"))
        )
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "worker"}, clear=True), patch(
            "app.main.get_state_event_inbox_metrics_snapshot_store",
            return_value=fake_store,
        ):
            response = asyncio.run(main.state_event_metrics_endpoint())
        self.assertEqual(200, response.status_code)
        self.assertIn("text/plain", response.media_type or "")
        fallback_payload = fake_store.render_metrics.await_args.kwargs.get("fallback_payload")
        self.assertIsNone(fallback_payload)

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

    def test_lifespan_logs_startup_steps_on_success(self):
        fake_cfg = SimpleNamespace(
            app=SimpleNamespace(host="0.0.0.0", port=8080, debug=False, timeout_keep_alive_seconds=5),
            database=SimpleNamespace(host="mysql.example", port=3306, name="binary_security"),
            queue=SimpleNamespace(redis_url="redis://redis.example:6379/0", task_queue_key="secflow:binary-security:tasks"),
            auth_service=SimpleNamespace(host="auth.example", port=9000, timeout=10),
            registry=SimpleNamespace(menu_service_url="http://menu.example", service_id="secflow-app-binary-security"),
        )
        fake_conn = MagicMock()
        fake_engine = MagicMock()
        fake_engine.connect.return_value.__enter__.return_value = fake_conn
        fake_engine.connect.return_value.__exit__.return_value = None
        with tempfile.TemporaryDirectory() as temp_dir:
            started_at_file = os.path.join(temp_dir, "started_at")

            async def _run():
                async with main.lifespan(main.app):
                    return None

            with patch.dict(
                os.environ,
                {
                    "SECFLOW_BINARY_SECURITY_ROLE": "worker",
                    "SECFLOW_MAIN_STARTED_AT_FILE": started_at_file,
                },
                clear=True,
            ), \
                patch("app.main.load_config"), \
                patch("app.main.get_config", return_value=fake_cfg), \
                patch("app.main._external_probe_process_enabled", return_value=True), \
                patch("app.main.init_database"), \
                patch("app.main.get_engine", return_value=fake_engine), \
                patch("app.main.verify_auth_service_or_exit"), \
                patch("app.main._registry_enabled", return_value=False), \
                patch("app.main._scheduler_enabled", return_value=False), \
                patch("builtins.print") as mock_print, \
                patch.object(main.logger, "info") as logger_info:
                asyncio.run(_run())

            self.assertTrue(os.path.exists(started_at_file))
            self.assertTrue(float(open(started_at_file, "r", encoding="utf-8").read().strip()) > 0)
            self.assertTrue(mock_print.called)
            printed_banner = mock_print.call_args.args[0]
            self.assertIn("SecFlow Binary Security Boot Banner", printed_banner)
            self.assertIn("redis_url=redis://redis.example:6379/0", printed_banner)

        info_calls = [call.args for call in logger_info.call_args_list if call.args]

        def _has_step(step_name: str) -> bool:
            return any(
                len(args) >= 3
                and args[0] == "Binary Security startup step=%s%s"
                and args[1] == step_name
                for args in info_calls
            )

        def _has_step_done(step_name: str) -> bool:
            return any(
                len(args) >= 3
                and args[0] == "Binary Security startup step=%s status=ok%s"
                and args[1] == step_name
                for args in info_calls
            )

        self.assertTrue(_has_step("load_config"))
        self.assertTrue(_has_step_done("load_config"))
        self.assertTrue(_has_step("init_database"))
        self.assertTrue(_has_step_done("init_database"))
        self.assertTrue(_has_step("database_ping"))
        self.assertTrue(_has_step_done("database_ping"))
        self.assertTrue(_has_step("verify_auth"))
        self.assertTrue(_has_step_done("verify_auth"))
        self.assertTrue(any(args[0] == "Binary Security startup banner\n%s" for args in info_calls))
        self.assertTrue(any(args[0] == "SecFlow Binary Security 服务启动成功" for args in info_calls))

    def test_lifespan_logs_failed_startup_step_context(self):
        fake_cfg = SimpleNamespace(
            app=SimpleNamespace(host="0.0.0.0", port=8080, debug=False, timeout_keep_alive_seconds=5),
            database=SimpleNamespace(host="mysql.example", port=3306, name="binary_security"),
            queue=SimpleNamespace(redis_url="redis://redis.example:6379/0", task_queue_key="secflow:binary-security:tasks"),
            auth_service=SimpleNamespace(host="auth.example", port=9000, timeout=10),
            registry=SimpleNamespace(menu_service_url="http://menu.example", service_id="secflow-app-binary-security"),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            started_at_file = os.path.join(temp_dir, "started_at")

            async def _run():
                async with main.lifespan(main.app):
                    return None

            with patch.dict(
                os.environ,
                {
                    "SECFLOW_BINARY_SECURITY_ROLE": "worker",
                    "SECFLOW_MAIN_STARTED_AT_FILE": started_at_file,
                },
                clear=True,
            ), \
                patch("app.main.load_config"), \
                patch("app.main.get_config", return_value=fake_cfg), \
                patch("app.main._external_probe_process_enabled", return_value=True), \
                patch("app.main.init_database", side_effect=TimeoutError("Timeout connecting to server")), \
                patch("app.main._registry_enabled", return_value=False), \
                patch("app.main._scheduler_enabled", return_value=True), \
                patch.object(main.logger, "exception") as logger_exception, \
                patch("app.main.sys.exit", side_effect=SystemExit(1)):
                with self.assertRaises(SystemExit):
                    asyncio.run(_run())

            self.assertFalse(os.path.exists(started_at_file))

        self.assertTrue(logger_exception.called)
        args = logger_exception.call_args.args
        self.assertIn("Binary Security 服务启动失败: step=%s role=%s scheduler_enabled=%s registry_enabled=%s error=%s", args[0])
        self.assertEqual("init_database", args[1])
        self.assertEqual("worker", args[2])
        self.assertTrue(args[3])
        self.assertFalse(args[4])
        self.assertIn("Timeout connecting to server", str(args[5]))


if __name__ == "__main__":
    unittest.main()
