import asyncio
import json
import unittest
from datetime import timedelta

from app.model import (
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TASK_ACTION_CONTINUE, TASK_OPERATION_STEP_REQUEUE_TASK, TaskManager, ValidationError, _now
from test_task_manager import _ModelAwareDb


class TaskOperationForceResetTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_force_reset_task_to_pending_clears_stuck_operation_and_runtime_state(self):
        task = BinarySecurityTask(
            id="task-force-reset",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-force-reset",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            last_error="stale owner",
            tail_reconcile_state="handoff_waiting",
            execution_mode=TASK_ACTION_CONTINUE,
        )
        task.summary = {
            "failure_code": "owner_lost",
            "failure_message": "retry_in_process",
            "runtime_workset": {
                "pending_operation_repair": {"reason": "stale_owner"},
                "pending_downstream_sync": {"reason": "sync_needed"},
            },
        }
        operation = BinarySecurityTaskOperation(
            id="op-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="running",
            current_step=TASK_OPERATION_STEP_REQUEUE_TASK,
            target_stage="system_analysis",
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
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[lease], events=[])
        queued = []
        cancellations = []
        original_enqueue = self.manager._enqueue_task
        original_cancel = self.manager._request_local_worker_cancel
        original_clear_runtime_lease = self.manager._clear_runtime_lease

        async def _fake_cancel(task_id: str, *, wait_for_runner: bool):
            cancellations.append((task_id, wait_for_runner))
            return None

        try:
            self.manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            self.manager._request_local_worker_cancel = _fake_cancel
            self.manager._clear_runtime_lease = lambda _db, _task_id, **_kwargs: db.runtime_leases.clear()
            response = asyncio.run(
                self.manager.force_reset_task_to_pending(
                    db,
                    project_id="p1",
                    task_id=task.id,
                    requested_by="tester",
                )
            )
        finally:
            self.manager._enqueue_task = original_enqueue
            self.manager._request_local_worker_cancel = original_cancel
            self.manager._clear_runtime_lease = original_clear_runtime_lease

        self.assertTrue(response.accepted)
        self.assertEqual("force_reset_to_pending", response.action)
        self.assertEqual("running", response.task_status_after_accept)
        self.assertEqual([(task.id, False)], cancellations)
        self.assertEqual([task.id], queued)
        self.assertEqual("running", task.status)
        self.assertEqual(response.operation_id, task.current_operation_id)
        self.assertEqual("worker-a", db.runtime_leases[0].owner_instance_id)
        self.assertIsNotNone(db.runtime_leases[0].lease_expires_at)
        self.assertEqual(TASK_ACTION_CONTINUE, task.execution_mode)
        self.assertEqual("stale owner", task.last_error)
        self.assertEqual("handoff_waiting", task.tail_reconcile_state)
        self.assertIn("runtime_workset", dict(task.summary or {}))
        self.assertIn("failure_code", dict(task.summary or {}))
        self.assertEqual("superseded", operation.status)
        self.assertIsNotNone(operation.finished_at)
        self.assertEqual(1, len(db.runtime_leases))
        self.assertTrue(any(event.event_type == "task_force_reset_to_pending_accepted" for event in db.events))
        self.assertTrue(any(event.event_type == "operation_force_reset_superseded" for event in db.events))

    def test_force_reset_task_to_pending_externalizes_large_operation_result_payload(self):
        task = BinarySecurityTask(
            id="task-force-reset-large-payload",
            project_id="p1",
            name="source",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-force-reset-large",
        )
        operation = BinarySecurityTaskOperation(
            id="op-force-reset-large",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="running",
            target_stage="system_analysis",
        )
        oversized_payload = {"huge": "x" * 100000}
        self.manager._persist_operation_result_payload(
            operation,
            oversized_payload,
            workspace_root=task.workspace_root,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[])
        original_cancel = self.manager._request_local_worker_cancel
        original_clear_runtime_lease = self.manager._clear_runtime_lease
        original_enqueue = self.manager._enqueue_task

        async def _fake_cancel(task_id: str, *, wait_for_runner: bool):
            return None

        try:
            self.manager._request_local_worker_cancel = _fake_cancel
            self.manager._clear_runtime_lease = lambda *_args, **_kwargs: None
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            response = asyncio.run(
                self.manager.force_reset_task_to_pending(
                    db,
                    project_id="p1",
                    task_id=task.id,
                    requested_by="tester",
                )
            )
        finally:
            self.manager._request_local_worker_cancel = original_cancel
            self.manager._clear_runtime_lease = original_clear_runtime_lease
            self.manager._enqueue_task = original_enqueue

        self.assertTrue(response.accepted)
        result_payload = dict(operation.result_payload or {})
        self.assertEqual("tester", dict(result_payload.get("force_reset") or {}).get("requested_by"))
        persisted_payload = json.loads(operation.result_payload_json or "{}")
        self.assertIn("result_payload_path", persisted_payload)
        self.assertNotIn("huge", persisted_payload)
        self.assertLess(len(operation.result_payload_json or ""), 4096)

    def test_force_reset_task_to_pending_rejects_terminal_success(self):
        task = BinarySecurityTask(
            id="task-force-reset-terminal",
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
                self.manager.force_reset_task_to_pending(
                    db,
                    project_id="p1",
                    task_id=task.id,
                    requested_by="tester",
                )
            )
