import unittest

from app.service.task.reducer import TaskReducerServiceMixin
from app.service.task_manager import TaskManager


class TaskReducerServiceStructureTests(unittest.TestCase):
    def test_task_manager_reducer_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._state_reducer_loop, TaskReducerServiceMixin._state_reducer_loop)
        self.assertIs(TaskManager._reducer_metrics_snapshot_loop, TaskReducerServiceMixin._reducer_metrics_snapshot_loop)
        self.assertIs(TaskManager._publish_reducer_metrics_snapshot, TaskReducerServiceMixin._publish_reducer_metrics_snapshot)
        self.assertIs(TaskManager._observe_state_runtime_metrics, TaskReducerServiceMixin._observe_state_runtime_metrics)
        self.assertIs(TaskManager._claim_state_event, TaskReducerServiceMixin._claim_state_event)
        self.assertIs(TaskManager._acquire_task_state_lease, TaskReducerServiceMixin._acquire_task_state_lease)
        self.assertIs(TaskManager._release_task_state_lease, TaskReducerServiceMixin._release_task_state_lease)
        self.assertIs(TaskManager._reduce_state_event, TaskReducerServiceMixin._reduce_state_event)
        self.assertIs(TaskManager._repair_retryable_state_events, TaskReducerServiceMixin._repair_retryable_state_events)


if __name__ == "__main__":
    unittest.main()
