import unittest
from unittest.mock import patch

from app.model import BinarySecurityTask, BinarySecurityTaskOperation, TASK_TYPE_BINARY
from app.service.task.operation_events import TaskOperationEventServiceMixin
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskOperationEventServiceStructureTests(unittest.TestCase):
    def test_task_manager_operation_event_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._record_operation_event, TaskOperationEventServiceMixin._record_operation_event)
        self.assertIs(TaskManager._set_operation_step_state, TaskOperationEventServiceMixin._set_operation_step_state)
        self.assertIs(TaskManager._record_operation_step_started, TaskOperationEventServiceMixin._record_operation_step_started)
        self.assertIs(TaskManager._record_operation_step_finished, TaskOperationEventServiceMixin._record_operation_step_finished)
        self.assertIs(TaskManager._record_operation_step_failed, TaskOperationEventServiceMixin._record_operation_step_failed)


class TaskOperationEventServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        self.operation = BinarySecurityTaskOperation(
            id="op-1",
            task_id=self.task.id,
            project_id=self.task.project_id,
            operation_type="continue",
            target_stage="system_analysis",
            status="running",
        )
        self.db = _ModelAwareDb(tasks=[self.task], operations=[self.operation])

    def test_record_operation_event_merges_operation_metadata(self):
        with patch.object(self.manager, "_record_event") as record_event:
            self.manager._record_operation_event(
                self.db,
                self.task,
                self.operation,
                "operation_started",
                "started",
                payload={"custom": "value"},
            )

        args, kwargs = record_event.call_args
        self.assertEqual("operation_started", args[2])
        self.assertEqual("continue", kwargs["payload"]["operation_type"])
        self.assertEqual("value", kwargs["payload"]["custom"])
        self.assertEqual("op-1", kwargs["operation_id"])

    def test_record_operation_step_started_updates_state(self):
        with patch.object(self.manager, "_record_operation_event"):
            self.manager._record_operation_step_started(
                self.db,
                self.task,
                self.operation,
                step_name="collect_cleanup_plan",
                message="started",
                payload={"k": "v"},
            )

        self.assertEqual("collect_cleanup_plan", self.operation.current_step)
        self.assertEqual(1, self.operation.step_attempts["collect_cleanup_plan"])
        self.assertEqual("running", self.operation.step_payload["collect_cleanup_plan"]["status"])

    def test_record_operation_step_failed_sets_resume_cursor_and_error_payload(self):
        with patch.object(self.manager, "_record_operation_event"):
            self.manager._record_operation_step_failed(
                self.db,
                self.task,
                self.operation,
                step_name="collect_cleanup_plan",
                error="boom",
            )

        self.assertEqual("collect_cleanup_plan", self.operation.resume_cursor["current_step"])
        self.assertEqual("failed", self.operation.step_payload["collect_cleanup_plan"]["status"])
        self.assertIn("payload_path", self.operation.step_payload["collect_cleanup_plan"])

    def test_operation_response_marks_owner_only_inbox_model(self):
        response = self.manager._operation_response(self.operation)

        self.assertEqual("task_owner_inbox", response.execution_model)
        self.assertEqual("task_lease_owner", response.owner_model)
        self.assertFalse(hasattr(response, "owner_instance_id"))
        self.assertFalse(hasattr(response, "claim_lease_expires_at"))
        self.assertFalse(hasattr(response, "heartbeat_at"))
