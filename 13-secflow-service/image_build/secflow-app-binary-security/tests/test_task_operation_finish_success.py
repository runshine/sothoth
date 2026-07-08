import asyncio
import unittest
from datetime import timedelta
from types import SimpleNamespace

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, ValidationError, _now
from test_task_manager import _ModelAwareDb


class TaskOperationFinishSuccessTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_finish_task_as_success_accepts_and_supersedes_existing_operation(self):
        task = BinarySecurityTask(
            id="task-force-success",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-retry",
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="running",
            target_stage="entry_analysis",
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[])
        cancellations = []
        original_cancel = self.manager._request_local_worker_cancel

        async def _fake_cancel(task_id: str, *, wait_for_runner: bool):
            cancellations.append((task_id, wait_for_runner))
            return None

        try:
            self.manager._request_local_worker_cancel = _fake_cancel
            response = asyncio.run(
                self.manager.finish_task_as_success(
                    db,
                    project_id="p1",
                    task_id=task.id,
                    requested_by="tester",
                )
            )
        finally:
            self.manager._request_local_worker_cancel = original_cancel

        self.assertTrue(response.accepted)
        self.assertEqual(task_manager_module.TASK_ACTION_FINISH_SUCCESS, response.action)
        self.assertEqual("running", response.task_status_after_accept)
        self.assertEqual([(task.id, False)], cancellations)
        self.assertEqual("superseded", operation.status)
        self.assertEqual(response.operation_id, task.current_operation_id)
        self.assertTrue(any(event.event_type == "task_force_success_accepted" for event in db.events))
        self.assertTrue(any(event.event_type == "operation_force_success_superseded" for event in db.events))

    def test_apply_finish_task_as_success_now_terminalizes_task_and_clears_runtime(self):
        task = BinarySecurityTask(
            id="task-force-success-run",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-finish-success",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            last_error="still running",
            execution_mode="continue",
            tail_reconcile_state="handoff_waiting",
        )
        task.summary = {
            "failure_code": "owner_lost",
            "failure_message": "stale owner",
            "runtime_workset": {"pending_downstream_sync": {"reason": "sync_needed"}},
        }
        finish_operation = BinarySecurityTaskOperation(
            id="op-finish-success",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_FINISH_SUCCESS,
            status="running",
            target_stage="dataflow_vuln_scan",
        )
        superseded_operation = BinarySecurityTaskOperation(
            id="op-retry-active",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="running",
            target_stage="entry_analysis",
        )
        item = BinarySecurityStageItem(
            id="item-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-a",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-1",
        )
        stage_run = BinarySecurityStageRun(
            id="sr-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            status="running",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            owner_pod_uid="pod-1",
            owner_boot_id="boot-1",
            lease_expires_at=_now() + timedelta(seconds=120),
            generation=1,
            execution_epoch=1,
        )
        db = _ModelAwareDb(
            tasks=[task],
            operations=[finish_operation, superseded_operation],
            stage_items=[item],
            stage_runs=[stage_run],
            runtime_leases=[lease],
            events=[],
        )
        cancelled_refs = []
        original_cancel_refs = self.manager._cancel_downstream_refs
        original_clear_runtime_lease = self.manager._clear_runtime_lease
        original_can_clear_parent_runtime_ownership = self.manager._can_clear_parent_runtime_ownership
        original_record_parent_runtime_lease_decision = self.manager._record_parent_runtime_lease_decision
        original_task_main_state_write_allowed = self.manager._task_main_state_write_allowed

        async def _fake_cancel_refs(db_arg, task_arg, refs_arg, token_arg):
            cancelled_refs.append((db_arg, task_arg.id, list(refs_arg), token_arg))
            return len(refs_arg)

        try:
            self.manager._cancel_downstream_refs = _fake_cancel_refs
            self.manager._clear_runtime_lease = lambda _db, _task_id, **_kwargs: db.runtime_leases.clear()
            self.manager._can_clear_parent_runtime_ownership = lambda *_args, **_kwargs: SimpleNamespace(allowed=True)
            self.manager._record_parent_runtime_lease_decision = lambda *_args, **_kwargs: None
            self.manager._task_main_state_write_allowed = lambda *_args, **_kwargs: True
            result = asyncio.run(
                self.manager._apply_finish_task_as_success_now(
                    db,
                    task,
                    requested_by="tester",
                    operation=finish_operation,
                )
            )
        finally:
            self.manager._cancel_downstream_refs = original_cancel_refs
            self.manager._clear_runtime_lease = original_clear_runtime_lease
            self.manager._can_clear_parent_runtime_ownership = original_can_clear_parent_runtime_ownership
            self.manager._record_parent_runtime_lease_decision = original_record_parent_runtime_lease_decision
            self.manager._task_main_state_write_allowed = original_task_main_state_write_allowed

        self.assertTrue(result["operation_finalized"])
        self.assertEqual("success", task.status)
        self.assertEqual(task_manager_module.TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertIsNone(task.last_error)
        self.assertEqual("idle", task.tail_reconcile_state)
        self.assertIsNone(task.execution_mode)
        self.assertEqual("cancelled", item.status)
        self.assertEqual("cancelled", stage_run.status)
        self.assertEqual("succeeded", finish_operation.status)
        self.assertEqual("superseded", superseded_operation.status)
        self.assertEqual(1, len(cancelled_refs))
        self.assertEqual("dfa-1", cancelled_refs[0][2][0]["task_id"])
        self.assertEqual("tester", dict(task.summary or {}).get("manual_success_override", {}).get("requested_by"))
        self.assertNotIn("failure_code", dict(task.summary or {}))
        self.assertTrue(any(event.event_type == "task_force_success_completed" for event in db.events))

    def test_finish_task_as_success_rejects_terminal_task(self):
        task = BinarySecurityTask(
            id="task-force-success-terminal",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            status="success",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task], events=[])

        with self.assertRaises(ValidationError):
            asyncio.run(
                self.manager.finish_task_as_success(
                    db,
                    project_id="p1",
                    task_id=task.id,
                    requested_by="tester",
                )
            )


if __name__ == "__main__":
    unittest.main()
