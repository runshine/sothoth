import unittest

from app.service.task_archive_service import TaskArchiveServiceMixin
from app.service.task_manager import TaskManager


class TaskArchiveServiceWiringTests(unittest.TestCase):
    def test_task_manager_archive_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._persist_downstream_sync_failure, TaskArchiveServiceMixin._persist_downstream_sync_failure)
        self.assertIs(TaskManager._run_archive_copy_job, TaskArchiveServiceMixin._run_archive_copy_job)
        self.assertIs(TaskManager._apply_archive_job_status, TaskArchiveServiceMixin._apply_archive_job_status)
        self.assertIs(TaskManager._apply_archive_job_status_locked, TaskArchiveServiceMixin._apply_archive_job_status_locked)
        self.assertIs(
            TaskManager._repair_descendants_after_archive_apply_if_needed,
            TaskArchiveServiceMixin._repair_descendants_after_archive_apply_if_needed,
        )


if __name__ == "__main__":
    unittest.main()
