import asyncio
import unittest
from unittest.mock import AsyncMock, patch


from app import runtime


class RuntimeBootstrapTests(unittest.TestCase):
    def setUp(self):
        runtime._runtime_started = False
        runtime._runtime_state.update(
            {
                "worker_registered": False,
                "worker_heartbeat": False,
                "cluster_maintenance": False,
                "cleanup_loop": False,
                "evolution_loop": False,
                "dispatcher": False,
                "registry": False,
            }
        )

    def tearDown(self):
        runtime._runtime_started = False

    def test_start_runtime_is_idempotent(self):
        with (
            patch("app.runtime._verify_auth_service_or_exit") as verify_auth,
            patch("app.runtime.init_database") as init_db,
            patch("app.runtime.get_runtime_roles", return_value={"api", "dispatcher", "worker", "cleanup-worker"}),
            patch("app.runtime.runtime_has_role", side_effect=lambda role: role in {"api", "dispatcher", "worker", "cleanup-worker"}),
            patch("app.runtime.register_worker") as register_worker,
            patch("app.runtime.start_worker_heartbeat") as start_heartbeat,
            patch("app.runtime.start_cluster_maintenance") as start_maintenance,
            patch("app.runtime.start_task_dispatcher") as start_dispatcher,
            patch("app.runtime.start_cleanup_loop") as start_cleanup,
            patch("app.runtime.start_evolution_loop") as start_evolution,
            patch("app.runtime.get_registry_service") as get_registry_service,
        ):
            registry = type("Registry", (), {"start": AsyncMock()})()
            get_registry_service.return_value = registry

            asyncio.run(runtime.start_runtime())
            asyncio.run(runtime.start_runtime())

        verify_auth.assert_called_once()
        init_db.assert_called_once()
        register_worker.assert_called_once()
        start_heartbeat.assert_called_once()
        start_maintenance.assert_called_once()
        start_dispatcher.assert_called_once()
        start_cleanup.assert_called_once()
        start_evolution.assert_called_once()
        registry.start.assert_awaited_once()

    def test_stop_runtime_is_idempotent(self):
        runtime._runtime_started = True
        runtime._runtime_state.update(
            {
                "worker_registered": True,
                "worker_heartbeat": True,
                "cluster_maintenance": True,
                "cleanup_loop": True,
                "evolution_loop": True,
                "dispatcher": True,
                "registry": True,
            }
        )
        with (
            patch("app.runtime.stop_task_dispatcher") as stop_dispatcher,
            patch("app.runtime.stop_all_loops") as stop_all_loops,
            patch("app.runtime.deregister_worker") as deregister_worker,
            patch("app.runtime.get_registry_service") as get_registry_service,
        ):
            registry = type("Registry", (), {"stop": AsyncMock()})()
            get_registry_service.return_value = registry

            asyncio.run(runtime.stop_runtime())
            asyncio.run(runtime.stop_runtime())

        stop_dispatcher.assert_called_once()
        stop_all_loops.assert_called_once()
        deregister_worker.assert_called_once()
        registry.stop.assert_awaited_once()

    def test_start_runtime_rolls_back_on_registry_start_failure(self):
        with (
            patch("app.runtime._verify_auth_service_or_exit"),
            patch("app.runtime.init_database"),
            patch("app.runtime.get_runtime_roles", return_value={"api", "dispatcher", "worker"}),
            patch("app.runtime.runtime_has_role", side_effect=lambda role: role in {"api", "dispatcher", "worker"}),
            patch("app.runtime.register_worker") as register_worker,
            patch("app.runtime.start_worker_heartbeat") as start_heartbeat,
            patch("app.runtime.start_cluster_maintenance") as start_maintenance,
            patch("app.runtime.start_task_dispatcher") as start_dispatcher,
            patch("app.runtime.stop_task_dispatcher") as stop_dispatcher,
            patch("app.runtime.stop_all_loops") as stop_all_loops,
            patch("app.runtime.deregister_worker") as deregister_worker,
            patch("app.runtime.get_registry_service") as get_registry_service,
        ):
            registry = type("Registry", (), {"start": AsyncMock(side_effect=RuntimeError("boom")), "stop": AsyncMock()})()
            get_registry_service.return_value = registry

            with self.assertRaises(RuntimeError):
                asyncio.run(runtime.start_runtime())

        register_worker.assert_called_once()
        start_heartbeat.assert_called_once()
        start_maintenance.assert_called_once()
        start_dispatcher.assert_called_once()
        stop_dispatcher.assert_called_once()
        stop_all_loops.assert_called_once()
        deregister_worker.assert_called_once()
        self.assertFalse(runtime._runtime_started)
