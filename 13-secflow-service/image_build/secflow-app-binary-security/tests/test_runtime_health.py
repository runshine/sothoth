import unittest
from unittest.mock import patch

from app import runtime_health


class RuntimeHealthTests(unittest.TestCase):
    def test_owner_readiness_ignores_inbox_loops_as_hard_requirement(self):
        fake_runtime = {
            "running": True,
            "loops": {
            },
            "loop_details": {
                "legacy_state_event_inbox": {"alive": True, "stale": False},
                "legacy_state_event_inbox_metrics": {"alive": False, "stale": False},
            },
            "lease_auditor_active": True,
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._owner_readiness()
        self.assertTrue(ok)
        self.assertEqual([], detail["missing_loops"])

    def test_owner_readiness_passes_when_inbox_loops_alive(self):
        fake_runtime = {
            "running": True,
            "loops": {
            },
            "loop_details": {
                "legacy_state_event_inbox": {"alive": True, "stale": False},
                "legacy_state_event_inbox_metrics": {"alive": True, "stale": False},
            },
            "lease_auditor_active": True,
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._owner_readiness()
        self.assertTrue(ok)
        self.assertEqual([], detail["missing_loops"])

    def test_owner_readiness_does_not_require_inbox_loops_when_runtime_lease_capable(self):
        fake_runtime = {
            "running": True,
            "loops": {},
            "loop_details": {},
            "lease_auditor_active": True,
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._owner_readiness()
        self.assertTrue(ok)
        self.assertTrue(detail["lease_auditor_active"])

    def test_owner_readiness_requires_lease_capability_even_when_idle(self):
        fake_runtime = {
            "running": True,
            "loops": {
            },
            "loop_details": {
                "legacy_state_event_inbox": {"alive": True, "stale": False},
                "legacy_state_event_inbox_metrics": {"alive": True, "stale": False},
            },
            "lease_auditor_active": False,
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._owner_readiness()
        self.assertFalse(ok)
        self.assertFalse(detail["lease_auditor_active"])

    def test_scheduler_readiness_rejects_stale_loop(self):
        fake_runtime = {
            "running": True,
            "loops": {
                "task_dispatch": True,
                "archive_dispatch": True,
                "stage_item_dispatch": True,
            },
            "loop_details": {
                "task_dispatch": {"alive": True, "stale": False},
                "archive_dispatch": {"alive": True, "stale": True},
                "stage_item_dispatch": {"alive": True, "stale": False},
            },
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._scheduler_readiness()
        self.assertFalse(ok)
        self.assertEqual(["archive_dispatch"], detail["missing_loops"])

    def test_collect_probe_snapshot_contains_startup_phase_and_last_error(self):
        fake_runtime = {"running": False, "loops": {}, "loop_details": {}}
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager, patch(
            "app.runtime_health.snapshot_startup_state"
        ) as mock_snapshot:
            mock_get_config.return_value.scheduler.enabled = False
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            mock_snapshot.return_value = {
                "started_at": 123.0,
                "startup_ready": False,
                "startup_error": "boom",
                "auth_ready": False,
                "registry_ready": False,
                "database_ready": False,
                "shutting_down": False,
            }
            payload = runtime_health.collect_probe_snapshot()
        self.assertEqual("booting", payload["startup_phase"])
        self.assertEqual("boom", payload["last_error"])


if __name__ == "__main__":
    unittest.main()
