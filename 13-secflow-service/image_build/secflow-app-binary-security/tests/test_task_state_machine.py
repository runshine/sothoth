import unittest
from types import SimpleNamespace
from unittest.mock import patch
import asyncio

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
    TASK_RUNTIME_PHASE_TERMINAL,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskStateMachineTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_next_incomplete_stage_returns_first_pending_enabled_stage(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        stage_run = BinarySecurityStageRun(
            id="sr-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[])

        with (
            patch.object(self.manager, "_stage_sequence_for_task", return_value=["system_analysis", "binary_to_source", "entry_analysis"]),
            patch.object(self.manager, "_stage_enabled", return_value=True),
            patch.object(self.manager, "_upstream_stage_retried", return_value=(False, None)),
            patch.object(self.manager, "_should_finalize_without_entries", return_value=False),
            patch.object(self.manager, "_should_skip_stage_without_runnable_work", return_value=False),
        ):
            next_stage = self.manager._next_incomplete_stage(db, task)

        self.assertEqual("binary_to_source", next_stage)

    def test_should_auto_advance_to_stage_uses_active_stage_run_as_authoritative_progress(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=1,
            status="queued",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[])

        with patch.object(self.manager, "_stage_items", return_value=[]):
            should_advance = self.manager._should_auto_advance_to_stage(db, task, "entry_analysis")

        self.assertTrue(should_advance)

    def test_decide_task_resume_after_stage_reset_reports_blocked_reason(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task])

        with (
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=False),
            patch.object(self.manager, "_continue_stage_input_error", return_value="missing inputs"),
        ):
            decision = self.manager._decide_task_resume_after_stage_reset(
                db,
                task,
                next_stage="entry_analysis",
                resume_reason="unit_test",
                source="unit",
                message="resume",
            )

        self.assertFalse(decision.should_resume)
        self.assertEqual("task_resume_blocked", decision.event_type)
        self.assertEqual("missing inputs", decision.payload["blocked_reason"])

    def test_apply_task_resume_decision_requeues_and_records_event(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out", status="failed")
        db = _ModelAwareDb(tasks=[task])
        decision = self.manager._decide_task_resume_after_stage_reset(
            db,
            task,
            next_stage="entry_analysis",
            resume_reason="unit_test",
            source="unit",
            message="resume",
        )

        with (
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=True),
            patch.object(self.manager, "_has_authoritative_active_stage", return_value=False),
        ):
            decision = self.manager._decide_task_resume_after_stage_reset(
                db,
                task,
                next_stage="entry_analysis",
                resume_reason="unit_test",
                source="unit",
                message="resume",
            )

        with (
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_enqueue_task") as enqueue_task,
        ):
            changed = self.manager._apply_task_resume_decision(db, task, decision)

        self.assertTrue(changed)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual(2, record_event.call_count)
        enqueue_task.assert_called_once_with(task.id)

    def test_decide_owned_execution_requeue_uses_authoritative_active_stage(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        active_run = BinarySecurityStageRun(
            id="sr-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=1,
            status="running",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[active_run], stage_items=[BinarySecurityStageItem(task_id=task.id, stage_name="dataflow_vuln_scan")])

        with (
            patch.object(self.manager, "_has_active_owned_execution_holder", return_value=False),
            patch.object(self.manager, "_should_requeue_for_owned_execution", return_value=True),
        ):
            decision = self.manager._decide_owned_execution_requeue(
                db,
                task,
                reason="unit_test",
                message="take over",
            )

        self.assertTrue(decision.owned_execution_requeue_required)
        self.assertEqual("dataflow_vuln_scan", decision.owned_execution_requeue_stage_name)

    def test_reconcile_task_summary_delegates_to_refresh_task_status_after_sync(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="running", current_stage="system_analysis", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task])

        with (
            patch.object(self.manager, "_refresh_task_status_after_sync") as refresh_status,
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: db),
        ):
            snapshot = self.manager._reconcile_task_summary(task.id)

        refresh_status.assert_called_once_with(db, task)
        self.assertEqual(task.status, snapshot.status)
        self.assertEqual(task.current_stage, snapshot.current_stage)

    def test_readless_reconcile_task_layer_delegates_to_task_summary(self):
        expected = SimpleNamespace(status="pending")
        with patch.object(self.manager, "_reconcile_task_summary", return_value=expected) as reconcile_summary:
            result = self.manager._readless_reconcile_task_layer("task-1")

        reconcile_summary.assert_called_once_with("task-1")
        self.assertIs(expected, result)

    def test_decide_task_action_after_stage_terminal_blocks_when_next_stage_cannot_advance(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="running", current_stage="system_analysis", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task])

        with (
            patch.object(self.manager, "_next_incomplete_stage", return_value="entry_analysis"),
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=False),
            patch.object(self.manager, "_continue_stage_input_error", return_value="missing inputs"),
        ):
            decision = self.manager._decide_task_action_after_stage_terminal(
                db,
                task,
                stage_name="system_analysis",
                status="success",
                summary={},
                payload={},
                state_event_id="evt-1",
            )

        self.assertEqual("advance_blocked", decision.action)
        self.assertEqual("missing inputs", decision.payload["blocked_reason"])

    def test_apply_task_action_after_stage_terminal_activates_streaming_tail(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="running", current_stage="system_analysis", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task])

        async def _noop_write(*_args, **_kwargs):
            return None

        with (
            patch.object(
                self.manager,
                "_decide_task_action_after_stage_terminal",
                return_value=task_manager_module._StageTerminalTaskDecision(
                    action="activate_streaming_tail",
                    next_stage="entry_analysis",
                    event_type="streaming_tail_activated",
                    payload={"state_event_id": "evt-1"},
                ),
            ),
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_write_task_metadata_async", new=_noop_write),
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            patch.object(
                self.manager,
                "_activate_tail_reconciliation",
                return_value=BinarySecurityTaskRuntimeLease(
                    task_id=task.id,
                    execution_epoch=1,
                    owner_instance_id="worker-1",
                    heartbeat_at=task_manager_module._now(),
                    lease_expires_at=task_manager_module._now() + task_manager_module.timedelta(seconds=30),
                ),
            ),
        ):
            applied = asyncio.run(
                self.manager._apply_task_action_after_stage_terminal(
                    db,
                    task,
                    stage_name="system_analysis",
                    status="success",
                    summary={},
                    payload={},
                    state_event_id="evt-1",
                )
            )

        self.assertTrue(applied)
        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_TAIL_RECONCILIATION, task.runtime_phase)
        self.assertEqual(1, record_event.call_count)

    def test_apply_task_action_after_stage_terminal_blocks_streaming_tail_without_owner(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="running", current_stage="system_analysis", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task])

        async def _noop_write(*_args, **_kwargs):
            return None

        with (
            patch.object(
                self.manager,
                "_decide_task_action_after_stage_terminal",
                return_value=task_manager_module._StageTerminalTaskDecision(
                    action="activate_streaming_tail",
                    next_stage="entry_analysis",
                    event_type="streaming_tail_activated",
                    payload={"state_event_id": "evt-1"},
                ),
            ),
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_write_task_metadata_async", new=_noop_write),
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=False),
            patch.object(self.manager, "_activate_tail_reconciliation", return_value=None) as activate_tail,
        ):
            applied = asyncio.run(
                self.manager._apply_task_action_after_stage_terminal(
                    db,
                    task,
                    stage_name="system_analysis",
                    status="success",
                    summary={},
                    payload={},
                    state_event_id="evt-1",
                )
            )

        self.assertTrue(applied)
        self.assertEqual("running", task.status)
        self.assertEqual("system_analysis", task.current_stage)
        self.assertNotEqual(TASK_RUNTIME_PHASE_TAIL_RECONCILIATION, task.runtime_phase)
        self.assertFalse(activate_tail.called)
        event_types = [call.args[2] for call in record_event.call_args_list]
        self.assertIn("main_state_write_blocked", event_types)

    def test_finalize_task_defers_for_active_stage(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="running", current_stage="entry_analysis", workspace_root="/tmp/ws", output_root="/tmp/out")
        stage_run = BinarySecurityStageRun(id="sr-1", task_id=task.id, project_id=task.project_id, stage_name="entry_analysis", sequence_no=1, status="running")
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run])

        with (
            patch.object(self.manager, "_ensure_task_remains_cancelling", return_value=None),
            patch.object(self.manager, "_streaming_has_active_upstream_stage", return_value=(False, None, None)),
            patch.object(self.manager, "_has_any_active_incomplete_stage", return_value=(True, "entry_analysis", "running")),
            patch.object(self.manager, "_is_streaming_tail_stage", return_value=False),
            patch.object(self.manager, "_should_requeue_for_owned_execution", return_value=False),
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_sync_task_abnormal_reason_snapshot"),
        ):
            self.manager._finalize_task(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        record_event.assert_called_once()

    def test_finalize_task_marks_terminal_success(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="running", current_stage="dataflow_vuln_scan", workspace_root="/tmp/ws", output_root="/tmp/out")
        stage_run = BinarySecurityStageRun(id="sr-1", task_id=task.id, project_id=task.project_id, stage_name="dataflow_vuln_scan", sequence_no=1, status="success")
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[])

        with (
            patch.object(self.manager, "_ensure_task_remains_cancelling", return_value=None),
            patch.object(self.manager, "_streaming_has_active_upstream_stage", return_value=(False, None, None)),
            patch.object(self.manager, "_has_any_active_incomplete_stage", return_value=(False, None, None)),
            patch.object(self.manager, "_next_incomplete_stage", return_value=None),
            patch.object(self.manager, "_stage_sequence_for_task", return_value=["dataflow_vuln_scan"]),
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            patch.object(self.manager, "_sync_task_abnormal_reason_snapshot"),
            patch.object(self.manager, "_record_event") as record_event,
        ):
            self.manager._finalize_task(db, task)

        self.assertEqual("success", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertEqual(2, record_event.call_count)

    def test_refresh_task_status_after_sync_active_operation_returns_early(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="failed", workspace_root="/tmp/ws", output_root="/tmp/out")
        operation = SimpleNamespace(id="op-1", status="running")
        db = _ModelAwareDb(tasks=[task], operations=[operation])

        with (
            patch.object(self.manager, "_active_cancel_operation", return_value=None),
            patch.object(self.manager, "_ensure_task_remains_cancelling", return_value=None),
            patch.object(self.manager, "_recover_failed_cancelled_task_state", return_value=False),
            patch.object(self.manager, "_active_operation", return_value=operation),
        ):
            self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("op-1", task.current_operation_id)
        self.assertIsNone(task.finished_at)

    def test_refresh_task_status_after_sync_finalizes_failed_task_without_active_reconcile_items(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", status="failed", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task], stage_runs=[])

        with (
            patch.object(self.manager, "_refresh_task_status_after_sync_early_return", return_value=False),
            patch.object(self.manager, "_refresh_task_status_after_sync_refresh_authoritative_stages", return_value=[]),
            patch.object(self.manager, "_recover_streaming_parent_running_state_locked", return_value=False),
            patch.object(self.manager, "_refresh_task_status_after_sync_handle_active_running_stages", return_value=False),
            patch.object(self.manager, "_refresh_task_status_after_sync_handle_retry_and_reopen", return_value=False),
            patch.object(self.manager, "_task_has_active_reconcile_items", return_value=False),
            patch.object(self.manager, "_finalize_task") as finalize_task,
        ):
            self.manager._refresh_task_status_after_sync(db, task)

        finalize_task.assert_called_once_with(db, task)

    def test_ensure_task_remains_cancelling_updates_main_state_for_owner(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="pending",
            current_stage="entry_analysis",
            current_operation_id="op-old",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        operation = SimpleNamespace(id="op-cancel", operation_type="cancel", status="running")
        db = _ModelAwareDb(tasks=[task], operations=[operation])

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            active = self.manager._ensure_task_remains_cancelling(db, task, active_cancel_operation=operation)

        self.assertIs(active, operation)
        self.assertEqual("cancelling", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.finished_at)
        self.assertIsNone(task.last_error)
        self.assertEqual("op-cancel", task.current_operation_id)

    def test_ensure_task_remains_cancelling_blocks_non_owner(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="pending",
            current_stage="entry_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        operation = SimpleNamespace(id="op-cancel", operation_type="cancel", status="running")
        db = _ModelAwareDb(tasks=[task], operations=[operation])

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=False):
            active = self.manager._ensure_task_remains_cancelling(db, task, active_cancel_operation=operation)

        self.assertIs(active, operation)
        self.assertEqual("pending", task.status)
        self.assertNotEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        event_types = [event.event_type for event in db.events]
        self.assertIn("main_state_write_blocked", event_types)

    def test_recover_failed_cancelled_task_state_updates_terminal_for_owner(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="cancelling",
            current_stage="entry_analysis",
            current_operation_id="op-old",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            dispatcher_instance_id="worker-a",
        )
        operation = SimpleNamespace(
            id="op-cancel",
            operation_type="cancel",
            status="failed",
            error_message="cancel failed",
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation])

        with (
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            patch.object(self.manager, "_latest_cancel_operation", return_value=operation),
        ):
            recovered = self.manager._recover_failed_cancelled_task_state(db, task)

        self.assertTrue(recovered)
        self.assertEqual("cancel_failed", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertEqual("cancel failed", task.last_error)
        self.assertEqual("op-cancel", task.current_operation_id)
        self.assertIsNotNone(task.finished_at)
        self.assertIsNone(task.dispatcher_instance_id)

    def test_recover_failed_cancelled_task_state_blocks_non_owner(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="cancelling",
            current_stage="entry_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        operation = SimpleNamespace(
            id="op-cancel",
            operation_type="cancel",
            status="failed",
            error_message="cancel failed",
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation])

        with (
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=False),
            patch.object(self.manager, "_latest_cancel_operation", return_value=operation),
        ):
            recovered = self.manager._recover_failed_cancelled_task_state(db, task)

        self.assertTrue(recovered)
        self.assertEqual("cancelling", task.status)
        event_types = [event.event_type for event in db.events]
        self.assertIn("main_state_write_blocked", event_types)

    def test_finalize_task_after_authoritative_failure_updates_terminal_for_owner(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="dispatching",
            current_stage="system_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            dispatcher_instance_id="worker-a",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], events=[])

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._finalize_task_after_authoritative_failure(
                db,
                task,
                failure_ctx={"stage_name": "system_analysis", "failure_message": "boom", "failure_category": "infrastructure"},
            )

        self.assertEqual("failed", task.status)
        self.assertEqual("system_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertEqual("boom", task.last_error)
        self.assertIsNotNone(task.finished_at)
        self.assertIsNone(task.dispatcher_instance_id)

    def test_finalize_task_after_authoritative_failure_blocks_non_owner(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="dispatching",
            current_stage="system_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            dispatcher_instance_id="worker-a",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], events=[])

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=False):
            self.manager._finalize_task_after_authoritative_failure(
                db,
                task,
                failure_ctx={"stage_name": "system_analysis", "failure_message": "boom", "failure_category": "infrastructure"},
            )

        self.assertEqual("dispatching", task.status)
        self.assertNotEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        event_types = [event.event_type for event in db.events]
        self.assertIn("main_state_write_blocked", event_types)

    def test_refresh_task_status_after_sync_early_return_terminalizes_cancelled_task_for_owner(self):
        task = BinarySecurityTask(
            id="task-cancelled",
            project_id="project-1",
            name="task",
            status="cancelled",
            current_stage="entry_analysis",
            dispatcher_instance_id="worker-a",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[])

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            changed = self.manager._refresh_task_status_after_sync_early_return(db, task)

        self.assertTrue(changed)
        self.assertEqual("cancelled", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertIsNotNone(task.finished_at)
        self.assertIsNone(task.dispatcher_instance_id)

    def test_refresh_task_status_after_sync_early_return_terminalizes_cancel_failed_task_for_owner(self):
        task = BinarySecurityTask(
            id="task-cancel-failed",
            project_id="project-1",
            name="task",
            status=task_manager_module.TASK_STATUS_CANCEL_FAILED,
            current_stage="entry_analysis",
            last_error="cancel failed",
            dispatcher_instance_id="worker-a",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[])

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            changed = self.manager._refresh_task_status_after_sync_early_return(db, task)

        self.assertTrue(changed)
        self.assertEqual(task_manager_module.TASK_STATUS_CANCEL_FAILED, task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertEqual("cancel failed", task.last_error)
        self.assertIsNotNone(task.finished_at)
        self.assertIsNone(task.dispatcher_instance_id)

    def test_refresh_task_status_after_sync_early_return_terminalizes_factless_failed_task_for_owner(self):
        task = BinarySecurityTask(
            id="task-failed",
            project_id="project-1",
            name="task",
            status="failed",
            current_stage="entry_analysis",
            last_error="boom",
            dispatcher_instance_id="worker-a",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[])

        with (
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            patch.object(self.manager, "_active_operation", return_value=None),
        ):
            changed = self.manager._refresh_task_status_after_sync_early_return(db, task)

        self.assertTrue(changed)
        self.assertEqual("failed", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertEqual("boom", task.last_error)
        self.assertIsNotNone(task.finished_at)
        self.assertIsNone(task.dispatcher_instance_id)


if __name__ == "__main__":
    unittest.main()
