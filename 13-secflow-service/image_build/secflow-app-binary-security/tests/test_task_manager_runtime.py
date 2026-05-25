import unittest
from unittest.mock import patch

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
        self.manager._stage_item_loop_task = _Task(False)
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
                "stage_item_dispatch": True,
                "downstream_reconcile": True,
                "state_reducer": True,
                "reducer_metrics_snapshot": True,
            },
            status["loops"],
        )
        self.assertEqual(0, status["workers"]["stage_item_workers"])


class TaskManagerDispatchLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_dispatch_loop_reconciles_queues_even_when_task_queue_is_busy(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.queue.enabled = True
        manager.cfg.queue.block_timeout_seconds = 1
        popped = False
        reconcile_calls = []

        class _Queue:
            async def pop_task(self, _timeout_seconds):
                nonlocal popped
                if not popped:
                    popped = True
                    return "task-1"
                manager._running = False
                return None

        def _dispatch_task_by_id(_db, task_id):
            return task_id

        async def _run_task(_task_id):
            return None

        async def _reconcile(_db):
            reconcile_calls.append("called")

        async def _observe(_db):
            return None

        manager._dispatch_task_by_id = _dispatch_task_by_id
        manager._run_task = _run_task
        manager._reconcile_work_queues = _reconcile
        manager._observe_runtime_metrics = _observe

        with patch("app.service.task_manager.get_task_queue", return_value=_Queue()):
            await manager._dispatch_loop()

        self.assertEqual(["called", "called"], reconcile_calls)

    async def test_state_reducer_loop_recovers_from_observe_failure(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.scheduler.poll_interval_seconds = 1
        observe_calls = []
        sleep_calls = []

        def _observe_state_runtime_metrics(_db):
            observe_calls.append("called")
            raise RuntimeError("boom")

        async def _sleep(_seconds):
            sleep_calls.append(_seconds)
            manager._running = False

        manager._observe_state_runtime_metrics = _observe_state_runtime_metrics

        with (
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
            patch("app.service.task_manager.logger.exception") as logger_exception,
            patch("app.service.task_manager.observe_state_reducer_health") as observe_health,
        ):
            await manager._state_reducer_loop()

        self.assertEqual(["called"], observe_calls)
        self.assertGreaterEqual(len(sleep_calls), 1)
        self.assertTrue(all(seconds == 1 for seconds in sleep_calls))
        logger_exception.assert_called_once()
        observe_health.assert_called_once()
        self.assertEqual(1, manager._state_reducer_consecutive_crash_count)

    async def test_state_reducer_loop_records_healthy_heartbeat_after_iteration(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.scheduler.poll_interval_seconds = 1
        sleep_calls = []

        async def _sleep(_seconds):
            sleep_calls.append(_seconds)
            manager._running = False

        manager._observe_state_runtime_metrics = lambda _db: None
        manager._claim_state_event = lambda _db: None
        async def _observe_runtime_metrics(_db):
            return None
        manager._observe_runtime_metrics = _observe_runtime_metrics
        manager._state_reducer_consecutive_crash_count = 3

        with (
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
            patch("app.service.task_manager.observe_state_reducer_health") as observe_health,
        ):
            await manager._state_reducer_loop()

        self.assertGreaterEqual(len(sleep_calls), 1)
        self.assertEqual(0, manager._state_reducer_consecutive_crash_count)
        observe_health.assert_called_once()
        self.assertEqual(0, observe_health.call_args.kwargs["consecutive_crash_count"])


if __name__ == "__main__":
    unittest.main()
