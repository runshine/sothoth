import unittest

from app.service.task_manager import TaskManager
from app.service.task_operation_service import TaskOperationServiceMixin


class TaskOperationServiceWiringTests(unittest.TestCase):
    def test_task_manager_operation_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._run_sync, TaskOperationServiceMixin._run_sync)
        self.assertFalse(hasattr(TaskManager, "_run_task_operation"))
        self.assertIs(TaskManager._run_current_task_operation, TaskOperationServiceMixin._run_current_task_operation)
        self.assertIs(TaskManager._run_task_operation_steps, TaskOperationServiceMixin._run_task_operation_steps)
        self.assertIs(TaskManager._run_cancel_operation_steps, TaskOperationServiceMixin._run_cancel_operation_steps)
        self.assertIs(TaskManager._run_retry_failed_items_operation_steps, TaskOperationServiceMixin._run_retry_failed_items_operation_steps)
        self.assertIs(TaskManager._run_retry_stage_full_operation_steps, TaskOperationServiceMixin._run_retry_stage_full_operation_steps)


if __name__ == "__main__":
    unittest.main()
