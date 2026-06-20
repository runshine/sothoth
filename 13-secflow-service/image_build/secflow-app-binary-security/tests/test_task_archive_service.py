import unittest

from app.model import BinarySecurityTask, TASK_RUNTIME_PHASE_OWNED_EXECUTION
from app.service.task_archive_service import TaskArchiveServiceMixin
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


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


class TaskArchiveServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_mark_task_waiting_for_archive_retry_requeues_pending_owned_execution(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="failed",
            task_type="binary",
            current_stage="binary_to_source",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
            dispatcher_instance_id="worker-a",
        )
        db = _ModelAwareDb(tasks=[task], events=[])
        enqueued: list[str] = []

        self.manager._enqueue_task = lambda task_id: enqueued.append(task_id)
        self.manager._write_task_metadata = lambda *args, **kwargs: None

        self.manager._mark_task_waiting_for_archive_retry(db, task, "binary_to_source")

        self.assertEqual("pending", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, self.manager._task_runtime_phase(task))
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)
        self.assertIsNone(task.lease_expires_at)
        self.assertEqual(["task-1"], enqueued)
        self.assertIn("task_archive_retry_requeued", [row.event_type for row in db.events])


if __name__ == "__main__":
    unittest.main()
