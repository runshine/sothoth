import asyncio
import unittest

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager
from test_task_manager import _AppendingModelAwareDb


class RetryBindingGuardTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_operation_verify_retry_bindings_skips_duplicate_control_for_adopt_active_pending_verification(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op1",
        )
        task.summary = {
            "retry_plan": {
                "target_stage": "system_analysis",
                "mode": "retry",
                "item_actions": [
                    {
                        "stage_name": "system_analysis",
                        "item_id": "si-system",
                        "item_key": "source_project",
                        "parent_key": "source_project",
                        "downstream_service": "system_analyse",
                        "old_downstream_task_id": "sat-old",
                        "current_downstream_task_id": "sat-old",
                        "new_downstream_task_id": "sat-old",
                        "strategy": "adopt_active",
                        "observed_status": "running",
                        "cleanup_performed": False,
                        "binding_cleared": False,
                        "verification_status": "pending",
                        "error": None,
                    }
                ],
                "affected_stages": ["system_analysis"],
            }
        }
        stage_run = BinarySecurityStageRun(
            id="sr-system",
            task_id="task1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="pending",
        )
        item = BinarySecurityStageItem(
            id="si-system",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr-system",
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source-project",
            parent_key="source_project",
            item_identity_key="source_project::source_project",
            downstream_service="system_analyse",
            downstream_task_id="sat-old",
            status="pending",
        )
        self.manager._mark_replacement_in_progress(
            item,
            old_downstream_task_id="sat-old",
            binding_cleared=False,
            verification_status="pending",
        )
        operation = BinarySecurityTaskOperation(
            id="op1",
            task_id="task1",
            project_id="p1",
            operation_type="retry",
            target_stage="system_analysis",
            status="running",
            current_step="verify_retry_bindings",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], operations=[operation], events=[])

        original_control = self.manager._downstream_control_existing_task
        try:
            async def should_not_run(*args, **kwargs):
                raise AssertionError("duplicate downstream control should be skipped while adopt_active verification is pending")

            self.manager._downstream_control_existing_task = should_not_run
            result = asyncio.run(self.manager._operation_verify_retry_bindings(db, task, operation))
        finally:
            self.manager._downstream_control_existing_task = original_control

        self.assertTrue(result["validation"]["validated"])
        action_rows = list((operation.result_payload or {}).get("item_actions") or [])
        self.assertEqual("pending", action_rows[0].get("verification_status"))
