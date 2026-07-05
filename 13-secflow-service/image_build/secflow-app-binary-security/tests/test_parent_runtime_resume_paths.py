import asyncio
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import (
    TASK_ACTION_CANCEL,
    TASK_ACTION_CONTINUE,
    TASK_OPERATION_STEP_REQUEUE_TASK,
    TaskManager,
    _now,
)
from test_task_manager import _AppendingModelAwareDb, _TaskManagerQueuePatchedMixin


class ParentRuntimeResumePathTests(_TaskManagerQueuePatchedMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = TaskManager()

    def test_finalize_task_requeues_owned_execution_without_active_holder(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        current_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
        )
        next_run = BinarySecurityStageRun(
            id="sr2",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=3,
            status="running",
        )
        next_item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr2",
            stage_name="binary_to_source",
            item_key="fw1",
            parent_key="fw1",
            status="running",
            downstream_service="binary_to_source",
            downstream_task_id="b2s1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[current_run, next_run], stage_items=[next_item], events=[])

        original_enqueue = self.manager._enqueue_task
        queued = []
        self.manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
        try:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                gate = self.manager._evaluate_task_finalization_gate(db, task, stage_runs=db.stage_runs)
                self.manager._handle_finalize_gate_blocked_active_path(db, task, stage_runs=db.stage_runs, finalize_gate=gate)
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertIn(task.status, {"pending", "running"})
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertEqual([], queued)

    def test_apply_archive_job_status_requeues_owned_execution_without_active_holder(self):
        task = BinarySecurityTask(
            id="t-archive-requeue",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            summary={},
        )
        previous_run = BinarySecurityStageRun(
            id="sr-archive-0",
            task_id=task.id,
            project_id="p1",
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
        )
        current_run = BinarySecurityStageRun(
            id="sr-archive-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
        )
        next_run = BinarySecurityStageRun(
            id="sr-archive-2",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si-archive-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=current_run.id,
            stage_name="system_analysis",
            item_key="fw1",
            parent_key="fw1",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat1",
        )
        job = BinarySecurityArchiveJob(
            id="job-archive-1",
            task_id=task.id,
            project_id="p1",
            stage_name="system_analysis",
            item_id=item.id,
            item_key=item.item_key,
            downstream_service="system_analyse",
            downstream_task_id="sat1",
            archive_status="archived",
        )
        job.payload = {
            "mapped_status": "success",
            "downstream_payload": {"task_id": "sat1", "status": "passed"},
        }
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[previous_run, current_run, next_run], stage_items=[item], archive_jobs=[job], events=[])

        original_write = self.manager._write_task_metadata_async
        original_refresh_terminal = self.manager._refresh_terminal_item_result_from_downstream
        original_enqueue_owner_signal = self.manager._enqueue_owner_signal
        owner_signals = []

        async def _noop_write(*_args, **_kwargs):
            return None

        async def _noop_refresh(*_args, **_kwargs):
            return None

        self.manager._write_task_metadata_async = _noop_write
        self.manager._refresh_terminal_item_result_from_downstream = _noop_refresh
        self.manager._enqueue_owner_signal = lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
        try:
            asyncio.run(self.manager._apply_archive_job_status_locked(db, job.id, "/tmp/archive"))
        finally:
            self.manager._write_task_metadata_async = original_write
            self.manager._refresh_terminal_item_result_from_downstream = original_refresh_terminal
            self.manager._enqueue_owner_signal = original_enqueue_owner_signal

        self.assertIn(task.status, {"pending", "running"})
        self.assertEqual("system_analysis", task.current_stage)
        self.assertEqual([], owner_signals)
        pending_reconcile = dict(self.manager._task_runtime_workset(task).get("pending_task_layer_reconcile") or {})
        self.assertEqual("archive_apply", pending_reconcile.get("reconcile_reason"))
        self.assertEqual("observe_only", pending_reconcile.get("reconcile_mode"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_layer_reconcile_shared_dispatch_requested", event_types)
        self.assertNotIn("owner_reconcile_signal_enqueued", event_types)
        self.assertIn("shared_dispatch_signal_enqueued", event_types)

    def test_requeue_task_after_retry_operation_uses_resume_decision(self):
        now_value = _now()
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-1",
            lease_expires_at=now_value + timedelta(seconds=60),
        )
        operation = BinarySecurityTaskOperation(
            id="op1",
            task_id="task1",
            project_id="p1",
            operation_type="retry_failed_items",
            target_stage="entry_analysis",
            status="running",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-1",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(seconds=60),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        original_apply = self.manager._apply_task_resume_decision
        original_enqueue = self.manager._enqueue_task
        original_should_auto = self.manager._should_auto_advance_to_stage
        applied = []
        queued = []

        def _capture_apply(_db, _task, decision, *, operation=None):
            applied.append({"next_stage": decision.next_stage, "source": decision.source, "operation_id": getattr(operation, "id", None)})
            return original_apply(_db, _task, decision, operation=operation)

        self.manager.instance_id = "worker-1"
        self.manager._apply_task_resume_decision = _capture_apply
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        self.manager._should_auto_advance_to_stage = lambda *_args, **_kwargs: True
        try:
            self.manager._requeue_task_after_retry_operation(db, task, target_stage="entry_analysis", operation=operation)
        finally:
            self.manager._apply_task_resume_decision = original_apply
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        self.assertEqual([], queued)
        self.assertEqual([], applied)
        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("worker-1", task.dispatcher_instance_id)
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("in_place_runtime_resume")))
        self.assertFalse(bool((operation.result_payload or {}).get("requeue", {}).get("owner_release_and_requeue")))

    def test_requeue_task_after_retry_operation_preserves_local_runtime_owner_for_retry(self):
        now_value = _now()
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id="worker-1",
            dispatch_started_at=now_value - timedelta(seconds=10),
            lease_expires_at=now_value + timedelta(seconds=60),
        )
        operation = BinarySecurityTaskOperation(
            id="op1",
            task_id="task1",
            project_id="p1",
            operation_type="retry",
            target_stage="entry_analysis",
            status="running",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-1",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(seconds=60),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        original_instance_id = self.manager.instance_id
        original_enqueue = self.manager._enqueue_task
        original_should_auto = self.manager._should_auto_advance_to_stage
        queued = []
        self.manager.instance_id = "worker-1"
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        self.manager._should_auto_advance_to_stage = lambda *_args, **_kwargs: True
        self.manager._register_task_execution_owner(task.id, "primary_task_worker")
        try:
            self.manager._requeue_task_after_retry_operation(db, task, target_stage="entry_analysis", operation=operation)
        finally:
            self.manager._release_task_execution_owner(task.id, "primary_task_worker")
            self.manager.instance_id = original_instance_id
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        self.assertEqual("running", task.status)
        self.assertEqual("worker-1", task.dispatcher_instance_id)
        self.assertEqual([], queued)
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("requested")))
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("in_place_runtime_resume")))
        self.assertFalse(bool((operation.result_payload or {}).get("requeue", {}).get("owner_release_and_requeue")))

    def test_run_task_operation_steps_requeue_uses_resume_decision(self):
        now_value = _now()
        task = BinarySecurityTask(
            id="task-op-requeue",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="test-worker",
            lease_expires_at=now_value + timedelta(minutes=5),
        )
        operation = BinarySecurityTaskOperation(
            id="op-requeue",
            task_id="task-op-requeue",
            project_id="p1",
            operation_type=TASK_ACTION_CONTINUE,
            target_stage="entry_analysis",
            status="running",
            current_step=TASK_OPERATION_STEP_REQUEUE_TASK,
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="test-worker",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        original_apply = self.manager._apply_task_resume_decision
        original_enqueue = self.manager._enqueue_task
        original_should_auto = self.manager._should_auto_advance_to_stage
        applied = []
        queued = []

        def _capture_apply(_db, _task, decision, *, operation=None):
            applied.append(
                {
                    "next_stage": decision.next_stage,
                    "source": decision.source,
                    "event_type": decision.event_type,
                    "operation_id": getattr(operation, "id", None),
                }
            )
            return original_apply(_db, _task, decision, operation=operation)

        self.manager.instance_id = "test-worker"
        self.manager._apply_task_resume_decision = _capture_apply
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        self.manager._should_auto_advance_to_stage = lambda *_args, **_kwargs: True
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager._apply_task_resume_decision = original_apply
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        self.assertEqual([], queued)
        self.assertEqual([], applied)
        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        event_types = [event.event_type for event in db.events]
        self.assertIn("retry_in_place_resume_applied", event_types)

    def test_run_task_operation_steps_requeue_does_not_skip_hard_restart_pending_state_without_requeue_marker(self):
        now_value = _now()
        task = BinarySecurityTask(
            id="task-op-hard-retry",
            project_id="p1",
            name="n",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="test-worker",
            lease_expires_at=now_value + timedelta(minutes=5),
        )
        operation = BinarySecurityTaskOperation(
            id="op-hard-retry",
            task_id="task-op-hard-retry",
            project_id="p1",
            operation_type=task_manager_module.TASK_ACTION_RETRY,
            target_stage="system_analysis",
            status="running",
            current_step=TASK_OPERATION_STEP_REQUEUE_TASK,
            result_payload={},
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="test-worker",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        original_apply = self.manager._apply_task_resume_decision
        original_enqueue = self.manager._enqueue_task
        original_should_auto = self.manager._should_auto_advance_to_stage
        applied = []
        queued = []

        def _capture_apply(_db, _task, decision, *, operation=None):
            applied.append(
                {
                    "next_stage": decision.next_stage,
                    "source": decision.source,
                    "event_type": decision.event_type,
                    "operation_id": getattr(operation, "id", None),
                }
            )
            return original_apply(_db, _task, decision, operation=operation)

        self.manager.instance_id = "test-worker"
        self.manager._apply_task_resume_decision = _capture_apply
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        self.manager._should_auto_advance_to_stage = lambda *_args, **_kwargs: True
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager._apply_task_resume_decision = original_apply
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        self.assertEqual([], queued)
        self.assertEqual([], applied)
        self.assertEqual("running", task.status)
        self.assertEqual("system_analysis", task.current_stage)
        self.assertEqual("running", operation.status)
        self.assertEqual(TASK_OPERATION_STEP_REQUEUE_TASK, operation.current_step)
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("in_place_runtime_resume")))
        self.assertFalse(bool((operation.result_payload or {}).get("requeue", {}).get("owner_release_and_requeue")))
        event_types = [event.event_type for event in db.events]
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertIn("operation_step_succeeded", event_types)

    def test_run_task_operation_steps_requeue_fails_without_owner_release_permission(self):
        task = BinarySecurityTask(
            id="task-op-requeue-blocked",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="other-worker",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        operation = BinarySecurityTaskOperation(
            id="op-requeue-blocked",
            task_id=task.id,
            project_id="p1",
            operation_type=task_manager_module.TASK_ACTION_RETRY,
            target_stage="system_analysis",
            status="running",
            current_step=TASK_OPERATION_STEP_REQUEUE_TASK,
            result_payload={},
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="other-worker",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        original_enqueue = self.manager._enqueue_task
        original_should_auto = self.manager._should_auto_advance_to_stage
        queued = []

        self.manager.instance_id = "test-worker"
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        self.manager._should_auto_advance_to_stage = lambda *_args, **_kwargs: True
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        self.assertEqual([], queued)
        self.assertEqual("running", operation.status)
        self.assertEqual(TASK_OPERATION_STEP_REQUEUE_TASK, operation.current_step)
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("in_place_runtime_resume")))
        self.assertFalse(bool((operation.result_payload or {}).get("requeue", {}).get("owner_release_and_requeue")))
        self.assertEqual("failed", task.status)
        self.assertEqual("other-worker", task.dispatcher_instance_id)
        self.assertTrue(any(lease.task_id == task.id for lease in db.runtime_leases))
        event_types = [event.event_type for event in db.events]
        self.assertIn("main_state_write_blocked", event_types)
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertIn("operation_step_succeeded", event_types)

    def test_apply_task_action_after_stage_terminal_requeue_uses_resume_decision(self):
        task = BinarySecurityTask(
            id="task-terminal",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _AppendingModelAwareDb(tasks=[task], events=[])

        original_decide = self.manager._decide_task_action_after_stage_terminal
        original_apply = self.manager._apply_task_resume_decision
        original_metadata = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task
        applied = []
        queued = []

        def _fake_decide(*_args, **_kwargs):
            return task_manager_module._StageTerminalTaskDecision(
                action="requeue_next_stage",
                next_stage="entry_analysis",
                event_type="task_requeued_after_stage_completion",
                message="阶段完成后任务继续进入下一阶段: entry_analysis",
                payload={"state_event_id": "sev1", "completed_stage": "system_analysis"},
            )

        def _capture_apply(_db, _task, decision, *, operation=None, enqueue_task=True):
            del operation
            applied.append(
                {
                    "next_stage": decision.next_stage,
                    "source": decision.source,
                    "event_type": decision.event_type,
                }
            )
            return original_apply(_db, _task, decision, enqueue_task=enqueue_task)

        async def _noop_metadata(*_args, **_kwargs):
            return None

        self.manager._decide_task_action_after_stage_terminal = _fake_decide
        self.manager._apply_task_resume_decision = _capture_apply
        self.manager._write_task_metadata_async = _noop_metadata
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        try:
            applied_result = asyncio.run(
                self.manager._apply_task_action_after_stage_terminal(
                    db,
                    task,
                    stage_name="system_analysis",
                    status="success",
                    summary={},
                    payload={},
                    state_event_id="sev1",
                )
            )
        finally:
            self.manager._decide_task_action_after_stage_terminal = original_decide
            self.manager._apply_task_resume_decision = original_apply
            self.manager._write_task_metadata_async = original_metadata
            self.manager._enqueue_task = original_enqueue

        self.assertTrue(applied_result)
        self.assertEqual(["task-terminal"], queued)
        self.assertEqual("entry_analysis", applied[0]["next_stage"])
        self.assertEqual("stage_terminal", applied[0]["source"])
        self.assertEqual("task_requeued_after_stage_completion", applied[0]["event_type"])

    def test_refresh_task_status_after_sync_pending_next_stage_uses_resume_decision(self):
        task = BinarySecurityTask(
            id="task-sync-resume",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        current_run = BinarySecurityStageRun(
            id="sr-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        next_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[current_run, next_run], stage_items=[], events=[])

        original_next = self.manager._next_stage_candidate
        original_items = self.manager._stage_items
        original_runnable = self.manager._stage_has_real_runnable_work
        original_nonterminal = self.manager._stage_has_nonterminal_items
        original_apply = self.manager._apply_task_resume_decision
        original_enqueue = self.manager._enqueue_task
        applied = []
        queued = []

        self.manager._next_stage_candidate = lambda *_args, **_kwargs: "entry_analysis"
        self.manager._stage_items = lambda *_args, **_kwargs: []
        self.manager._stage_has_real_runnable_work = lambda *_args, **_kwargs: True
        self.manager._stage_has_nonterminal_items = lambda *_args, **_kwargs: False
        original_apply = self.manager._apply_task_resume_decision

        def _capture_apply(_db, _task, decision, *, operation=None):
            del operation
            applied.append(
                {
                    "next_stage": decision.next_stage,
                    "source": decision.source,
                    "event_type": decision.event_type,
                }
            )
            return original_apply(_db, _task, decision)

        self.manager._apply_task_resume_decision = _capture_apply
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        try:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._next_stage_candidate = original_next
            self.manager._stage_items = original_items
            self.manager._stage_has_real_runnable_work = original_runnable
            self.manager._stage_has_nonterminal_items = original_nonterminal
            self.manager._apply_task_resume_decision = original_apply
            self.manager._enqueue_task = original_enqueue

        self.assertGreaterEqual(len(queued), 1)
        self.assertTrue(all(task_id == "task-sync-resume" for task_id in queued))
        self.assertEqual("entry_analysis", applied[0]["next_stage"])
        self.assertEqual("downstream_sync", applied[0]["source"])
        self.assertEqual("task_requeued_after_downstream_sync", applied[0]["event_type"])

    def test_handoff_active_serial_control_operation_from_runtime_uses_owner_inbox(self):
        manager = TaskManager()
        manager.instance_id = "worker-owner"
        fake_handle = SimpleNamespace(
            done=lambda: False,
            lease_established=True,
            owner_active=True,
            cancel_requested=False,
            active_commit_succeeded=True,
            release_requested=False,
            takeover_observed=False,
        )
        task = BinarySecurityTask(
            id="task-control-owner",
            project_id="p1",
            name="control",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id="worker-owner",
            current_operation_id="op-1",
        )
        operation = BinarySecurityTaskOperation(
            id="op-1",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=TASK_ACTION_CANCEL,
            status="running",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-owner",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=1),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[lease], events=[])

        original_factory = task_manager_module.get_session_factory
        original_runtime_handle = manager._runtime_handle
        original_cancel = manager._request_local_worker_cancel
        original_enqueue_task = manager._enqueue_task
        original_enqueue_owner_signal = manager._enqueue_owner_signal
        queued = []
        owner_signals = []

        async def _fake_cancel(*_args, **_kwargs):
            return True

        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._runtime_handle = lambda task_id: fake_handle if task_id == task.id else None
            manager._request_local_worker_cancel = _fake_cancel
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            manager._enqueue_owner_signal = lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
            result = asyncio.run(manager._handoff_active_serial_control_operation_from_runtime(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._runtime_handle = original_runtime_handle
            manager._request_local_worker_cancel = original_cancel
            manager._enqueue_task = original_enqueue_task
            manager._enqueue_owner_signal = original_enqueue_owner_signal

        self.assertTrue(result)
        self.assertEqual([task.id], queued)
        self.assertEqual([], owner_signals)
        self.assertTrue(any(event.event_type == "runtime_yielded_for_serial_control_operation" for event in db.events))


if __name__ == "__main__":
    unittest.main()
