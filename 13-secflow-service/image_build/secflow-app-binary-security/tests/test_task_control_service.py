import unittest

from app.service.task_control_service import TaskControlServiceMixin
from app.service.task_manager import TaskManager


class TaskControlServiceWiringTests(unittest.TestCase):
    def test_task_manager_control_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager.create_task, TaskControlServiceMixin.create_task)
        self.assertIs(TaskManager.cancel_task, TaskControlServiceMixin.cancel_task)
        self.assertIs(TaskManager.finish_task_as_success, TaskControlServiceMixin.finish_task_as_success)
        self.assertIs(TaskManager.continue_task, TaskControlServiceMixin.continue_task)
        self.assertIs(TaskManager.retry_task, TaskControlServiceMixin.retry_task)
        self.assertIs(TaskManager.retry_failed_items, TaskControlServiceMixin.retry_failed_items)
        self.assertIs(TaskManager.retry_stage_full, TaskControlServiceMixin.retry_stage_full)


if __name__ == "__main__":
    unittest.main()
