import unittest
from unittest.mock import patch

from app import runtime_health


class RuntimeHealthTests(unittest.TestCase):
    def test_reducer_readiness_requires_snapshot_loop(self):
        fake_runtime = {
            "running": True,
            "loops": {
                "state_reducer": True,
                "reducer_metrics_snapshot": False,
            },
            "loop_details": {
                "state_reducer": {"alive": True, "stale": False},
                "reducer_metrics_snapshot": {"alive": False, "stale": False},
            },
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._reducer_readiness()
        self.assertFalse(ok)
        self.assertEqual(["reducer_metrics_snapshot"], detail["missing_loops"])

    def test_reducer_readiness_passes_when_both_loops_alive(self):
        fake_runtime = {
            "running": True,
            "loops": {
                "state_reducer": True,
                "reducer_metrics_snapshot": True,
            },
            "loop_details": {
                "state_reducer": {"alive": True, "stale": False},
                "reducer_metrics_snapshot": {"alive": True, "stale": False},
            },
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._reducer_readiness()
        self.assertTrue(ok)
        self.assertEqual([], detail["missing_loops"])

    def test_scheduler_readiness_rejects_stale_loop(self):
        fake_runtime = {
            "running": True,
            "loops": {
                "task_dispatch": True,
                "operation_dispatch": True,
                "archive_dispatch": True,
                "downstream_reconcile": True,
                "readless_reconcile": True,
            },
            "loop_details": {
                "task_dispatch": {"alive": True, "stale": False},
                "operation_dispatch": {"alive": True, "stale": True},
                "archive_dispatch": {"alive": True, "stale": False},
                "downstream_reconcile": {"alive": True, "stale": False},
                "readless_reconcile": {"alive": True, "stale": False},
            },
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._scheduler_readiness()
        self.assertFalse(ok)
        self.assertEqual(["operation_dispatch"], detail["missing_loops"])


if __name__ == "__main__":
    unittest.main()
