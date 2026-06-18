import unittest
from unittest.mock import AsyncMock, patch

from app.model import BinarySecurityStateEvent, BinarySecurityTask
from app.service.task.reducer import TaskReducerServiceMixin
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskReducerServiceStructureTests(unittest.TestCase):
    def test_task_manager_reducer_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._apply_stage_worker_start_requested_locked, TaskReducerServiceMixin._apply_stage_worker_start_requested_locked)
        self.assertIs(TaskManager._state_reducer_loop, TaskReducerServiceMixin._state_reducer_loop)
        self.assertIs(TaskManager._reducer_metrics_snapshot_loop, TaskReducerServiceMixin._reducer_metrics_snapshot_loop)
        self.assertIs(TaskManager._publish_reducer_metrics_snapshot, TaskReducerServiceMixin._publish_reducer_metrics_snapshot)
        self.assertIs(TaskManager._observe_state_runtime_metrics, TaskReducerServiceMixin._observe_state_runtime_metrics)
        self.assertIs(TaskManager._claim_state_event, TaskReducerServiceMixin._claim_state_event)
        self.assertIs(TaskManager._acquire_task_state_lease, TaskReducerServiceMixin._acquire_task_state_lease)
        self.assertIs(TaskManager._release_task_state_lease, TaskReducerServiceMixin._release_task_state_lease)
        self.assertIs(TaskManager._reduce_state_event, TaskReducerServiceMixin._reduce_state_event)
        self.assertIs(TaskManager._repair_retryable_state_events, TaskReducerServiceMixin._repair_retryable_state_events)


class TaskReducerServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_apply_stage_worker_start_requested_locked_marks_task_and_stage_running(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="pending",
            current_stage="binary_to_source",
            task_type="binary",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
        )
        event = BinarySecurityStateEvent(
            id="evt-1",
            task_id=task.id,
            project_id=task.project_id,
            event_type="stage_worker_start_requested",
            stage_name="entry_analysis",
            payload={"stage_name": "entry_analysis"},
        )
        db = _ModelAwareDb(tasks=[task], state_events=[event], stage_runs=[], events=[])

        self.manager._apply_stage_worker_start_requested_locked(db, event)

        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(1, len(db.stage_runs))
        self.assertEqual("running", db.stage_runs[0].status)
        self.assertIn("stage_started", [row.event_type for row in db.events])

    def test_publish_reducer_metrics_snapshot_lightweight_skips_full_render(self):
        store = AsyncMock()
        with (
            patch("app.service.task_manager.render_metrics", side_effect=AssertionError("full render should be skipped")),
            patch("app.service.task_manager.get_reducer_metrics_snapshot_store", return_value=store),
        ):
            import asyncio

            asyncio.run(self.manager._publish_reducer_metrics_snapshot(lightweight=True))

        store.write_snapshot.assert_awaited_once()
        payload = store.write_snapshot.await_args.kwargs["metrics_payload"]
        self.assertIn("secflow_binary_security_reducer_bootstrap_snapshot", payload)


if __name__ == "__main__":
    unittest.main()
