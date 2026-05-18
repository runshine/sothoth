import unittest

from app.service.task_manager import TaskManager


class TaskManagerRuntimeStatusTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_runtime_status_reports_reducer_snapshot_loop(self):
        self.manager._running = True

        class _Task:
            def __init__(self, done):
                self._done = done

            def done(self):
                return self._done

        self.manager._loop_task = _Task(False)
        self.manager._action_loop_task = _Task(False)
        self.manager._archive_loop_task = _Task(True)
        self.manager._downstream_reconcile_task = _Task(False)
        self.manager._state_reducer_loop_task = _Task(False)
        self.manager._reducer_metrics_snapshot_loop_task = _Task(False)

        status = self.manager.runtime_status()

        self.assertTrue(status["running"])
        self.assertEqual(
            {
                "task_dispatch": True,
                "action_dispatch": True,
                "archive_dispatch": False,
                "downstream_reconcile": True,
                "state_reducer": True,
                "reducer_metrics_snapshot": True,
            },
            status["loops"],
        )


if __name__ == "__main__":
    unittest.main()
