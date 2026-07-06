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

    def test_should_auto_advance_to_stage_blocks_entry_analysis_pending_shell_when_rebuild_required(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=1,
            status="pending",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[])

        with (
            patch.object(self.manager, "_stage_items", return_value=[]),
            patch.object(
                self.manager,
                "_entry_analysis_authoritative_rebuild_required",
                return_value={
                    "required": True,
                    "reason": "historical_children_exist_but_authoritative_items_missing",
                    "input_count": 1,
                    "historical_child_count": 1,
                    "current_stage_item_count": 0,
                },
            ),
            patch.object(self.manager, "_mark_entry_analysis_authoritative_rebuild_summary"),
        ):
            should_advance = self.manager._should_auto_advance_to_stage(db, task, "entry_analysis")

        self.assertFalse(should_advance)

    def test_should_auto_advance_to_stage_blocks_entry_analysis_when_only_historical_children_remain(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=1,
            status="pending",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[])

        with (
            patch.object(self.manager, "_stage_items", return_value=[]),
            patch.object(
                self.manager,
                "_entry_analysis_authoritative_rebuild_required",
                return_value={
                    "required": False,
                    "reason": "no_historical_entry_analysis_children",
                    "input_count": 0,
                    "historical_child_count": 1,
                    "current_stage_item_count": 0,
                },
            ),
            patch.object(self.manager, "_mark_entry_analysis_authoritative_rebuild_summary"),
        ):
            should_advance = self.manager._should_auto_advance_to_stage(db, task, "entry_analysis")

        self.assertFalse(should_advance)

    def test_streaming_stage_start_ready_reuses_auto_advance_gate_for_entry_analysis(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[])

        with (
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=True),
            patch.object(self.manager, "_stage_has_materialized_inputs", return_value=True),
        ):
            self.assertTrue(self.manager._streaming_stage_start_ready(db, task, "entry_analysis"))

        with (
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=False),
            patch.object(self.manager, "_stage_has_materialized_inputs", return_value=True),
        ):
            self.assertFalse(self.manager._streaming_stage_start_ready(db, task, "entry_analysis"))

    def test_streaming_stage_start_ready_requires_authoritative_materialization_for_non_entry_stage(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[])

        with (
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=True),
            patch.object(self.manager, "_stage_has_authoritative_materialization", return_value=True),
        ):
            self.assertTrue(self.manager._streaming_stage_start_ready(db, task, "dataflow_vuln_scan"))

        with (
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=True),
            patch.object(self.manager, "_stage_has_authoritative_materialization", return_value=False),
        ):
            self.assertFalse(self.manager._streaming_stage_start_ready(db, task, "dataflow_vuln_scan"))

    def test_evaluate_stage_start_gate_reports_blocked_reason(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task], stage_runs=[], stage_items=[])

        with (
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=False),
            patch.object(self.manager, "_continue_stage_input_error", return_value="missing archive success"),
            patch.object(self.manager, "_stage_items", return_value=[]),
            patch.object(self.manager, "_build_workflow_stage_snapshots", return_value=[]),
        ):
            gate = self.manager._evaluate_stage_start_gate(db, task, "entry_analysis")

        self.assertFalse(gate["allowed"])
        self.assertEqual("entry_analysis", gate["stage_name"])
        self.assertEqual("missing archive success", gate["blocked_reason"])

    def test_decide_task_resume_after_stage_reset_reports_blocked_reason(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task])

        with (
            patch.object(
                self.manager,
                "_evaluate_stage_start_gate",
                return_value={
                    "stage_name": "entry_analysis",
                    "allowed": False,
                    "blocked_reason": "missing inputs",
                },
            ),
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
        self.assertFalse(decision.payload["stage_start_allowed"])

    def test_decide_task_action_after_stage_terminal_keeps_system_analysis_final_when_no_next_stage(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="system_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        db = _ModelAwareDb(tasks=[task])

        with (
            patch.object(self.manager, "_next_stage_candidate", return_value=None),
            patch.object(self.manager, "_should_auto_advance_to_stage", return_value=True),
        ):
            decision = self.manager._decide_task_action_after_stage_terminal(
                db,
                task,
                stage_name="system_analysis",
                status="success",
                summary={"candidate_modules": [], "selected_modules": []},
                payload={},
                state_event_id="evt-1",
            )

        self.assertEqual("finalize_failed", decision.action)
        self.assertIsNone(decision.next_stage)

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
        self.assertEqual(3, record_event.call_count)
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
        task.summary = {"candidate_modules": [{"module_key": "mod-a"}], "selected_modules": [{"module_key": "mod-a"}]}

        with (
            patch.object(self.manager, "_next_stage_candidate", return_value="entry_analysis"),
            patch.object(self.manager, "_evaluate_stage_start_gate", return_value={"allowed": False, "blocked_reason": "missing inputs"}),
            patch.object(self.manager, "_entry_analysis_inputs", return_value=[{"module_key": "mod-a"}]),
            patch.object(self.manager, "_system_analysis_authoritative_complete", return_value=True),
            patch.object(self.manager, "_source_entry_analysis_barrier_enabled", return_value=True),
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
        self.assertIsNone(decision.next_stage)

    def test_decide_task_action_after_system_analysis_terminal_waits_for_archive(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="system_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        stage_item = BinarySecurityStageItem(
            id="si-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-system",
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source-project",
            status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[stage_item])

        decision = self.manager._decide_task_action_after_stage_terminal(
            db,
            task,
            stage_name="system_analysis",
            status="success",
            summary={},
            payload={},
            state_event_id="evt-1",
        )

        self.assertEqual("wait_for_archive", decision.action)
        self.assertEqual("stage_terminal_waiting_for_archive", decision.event_type)

    def test_apply_task_action_after_system_analysis_terminal_waits_for_archive(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="system_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        db = _ModelAwareDb(tasks=[task])

        async def _noop_write(*_args, **_kwargs):
            return None

        with (
            patch.object(
                self.manager,
                "_decide_task_action_after_stage_terminal",
                return_value=task_manager_module._StageTerminalTaskDecision(
                    action="wait_for_archive",
                    event_type="stage_terminal_waiting_for_archive",
                    level="info",
                    payload={"state_event_id": "evt-1"},
                ),
            ),
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_write_task_metadata_async", new=_noop_write),
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
        event_types = [call.args[2] for call in record_event.call_args_list]
        self.assertIn("stage_terminal_waiting_for_archive", event_types)

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
                "_maybe_upsert_runtime_lease",
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
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertGreaterEqual(record_event.call_count, 1)

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
            patch.object(self.manager, "_maybe_upsert_runtime_lease", return_value=None) as acquire_lease,
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
        self.assertNotEqual("tail_reconciliation", task.runtime_phase)
        self.assertFalse(acquire_lease.called)
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
        self.assertEqual(2, record_event.call_count)

    def test_finalize_task_handle_resume_or_missing_stage_does_not_jump_current_stage_when_candidate_not_start_ready(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="system_analysis",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        system_run = BinarySecurityStageRun(
            id="sr-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[system_run], stage_items=[])

        with (
            patch.object(self.manager, "_build_workflow_stage_snapshots", return_value=[]),
            patch.object(self.manager, "_workflow_blocked_on_stage", return_value=None),
            patch.object(self.manager, "_workflow_ready_for_finalization", return_value=False),
            patch.object(self.manager, "_next_stage_candidate", return_value="entry_analysis"),
            patch.object(
                self.manager,
                "_evaluate_stage_start_gate",
                return_value={
                    "stage_name": "entry_analysis",
                    "allowed": False,
                    "blocked_reason": "missing archive success",
                    "stage_run": None,
                    "stage_items": [],
                    "snapshot": None,
                    "stage_status": "pending",
                    "has_active_ownerless_progress": False,
                },
            ),
            patch.object(self.manager, "_entry_analysis_pending_requires_materialization", return_value=False),
            patch.object(self.manager, "_should_requeue_for_owned_execution", return_value=False),
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_sync_task_abnormal_reason_snapshot"),
            patch.object(self.manager, "_enqueue_task") as enqueue_task,
        ):
            handled = self.manager._finalize_task_handle_resume_or_missing_stage(
                db,
                task,
                stage_runs=[system_run],
            )

        self.assertTrue(handled)
        self.assertEqual("system_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        enqueue_task.assert_called_once_with(task.id)
        payload = record_event.call_args.kwargs["payload"]
        self.assertEqual("entry_analysis", payload["candidate_next_stage"])
        self.assertFalse(payload["stage_start_allowed"])
        self.assertEqual("missing archive success", payload["blocked_reason"])

    def test_evaluate_task_finalization_gate_does_not_treat_blocked_candidate_as_resumable_next_stage(self):
        task = BinarySecurityTask(
            id="task-finalize-gate-blocked-candidate",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="system_analysis",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        system_run = BinarySecurityStageRun(
            id="sr-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[system_run], stage_items=[])

        with (
            patch.object(self.manager, "_build_workflow_stage_snapshots", return_value=[]),
            patch.object(self.manager, "_workflow_blocked_on_stage", return_value=None),
            patch.object(self.manager, "_next_stage_candidate", return_value="entry_analysis"),
            patch.object(
                self.manager,
                "_evaluate_stage_start_gate",
                return_value={
                    "stage_name": "entry_analysis",
                    "allowed": False,
                    "blocked_reason": "missing authoritative postprocess",
                    "stage_run": None,
                    "stage_items": [],
                    "snapshot": None,
                    "stage_status": "pending",
                    "has_active_ownerless_progress": False,
                },
            ),
            patch.object(self.manager, "_task_has_any_active_children", return_value=False),
            patch.object(self.manager, "_task_has_pending_stage_materialization", return_value=False),
            patch.object(self.manager, "_task_requires_runtime_takeover_or_requeue", return_value=False),
            patch.object(self.manager, "_task_has_resumable_execution_path", return_value=False),
            patch.object(self.manager, "_current_stage_authoritative_failure_context", return_value=None),
            patch.object(self.manager, "_earlier_stage_authoritative_failure_context", return_value=None),
            patch.object(self.manager, "_later_stage_authoritative_failure_context", return_value=None),
        ):
            decision = self.manager._evaluate_task_finalization_gate(
                db,
                task,
                stage_runs=[system_run],
                stage_items=[],
            )

        self.assertFalse(decision.allowed)
        self.assertEqual("workflow_not_ready_for_finalization", decision.reason_code)
        self.assertEqual("entry_analysis", decision.next_stage)
        self.assertIn(decision.blocked_by_stage, {None, "system_analysis"})

    def test_finalize_task_handle_resume_or_missing_stage_keeps_binary_module_current_stage_when_entry_analysis_not_start_ready(self):
        task = BinarySecurityTask(
            id="task-bmod-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="binary_to_source",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type="binary_module",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[b2s_run], stage_items=[])

        with (
            patch.object(self.manager, "_build_workflow_stage_snapshots", return_value=[]),
            patch.object(self.manager, "_workflow_blocked_on_stage", return_value=None),
            patch.object(self.manager, "_workflow_ready_for_finalization", return_value=False),
            patch.object(self.manager, "_next_stage_candidate", return_value="entry_analysis"),
            patch.object(
                self.manager,
                "_evaluate_stage_start_gate",
                return_value={
                    "stage_name": "entry_analysis",
                    "allowed": False,
                    "blocked_reason": "missing b2s archive success",
                    "stage_run": None,
                    "stage_items": [],
                    "snapshot": None,
                    "stage_status": "pending",
                    "has_active_ownerless_progress": False,
                },
            ),
            patch.object(self.manager, "_entry_analysis_pending_requires_materialization", return_value=False),
            patch.object(self.manager, "_should_requeue_for_owned_execution", return_value=False),
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_sync_task_abnormal_reason_snapshot"),
            patch.object(self.manager, "_enqueue_task") as enqueue_task,
        ):
            handled = self.manager._finalize_task_handle_resume_or_missing_stage(
                db,
                task,
                stage_runs=[b2s_run],
            )

        self.assertTrue(handled)
        self.assertEqual("binary_to_source", task.current_stage)
        enqueue_task.assert_called_once_with(task.id)
        payload = record_event.call_args.kwargs["payload"]
        self.assertEqual("entry_analysis", payload["candidate_next_stage"])
        self.assertFalse(payload["stage_start_allowed"])
        self.assertEqual("missing b2s archive success", payload["blocked_reason"])

    def test_finalize_task_handle_resume_or_missing_stage_keeps_kg_current_stage_when_dataflow_not_start_ready(self):
        task = BinarySecurityTask(
            id="task-kg-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="knowledge_graph_entry_fetch",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type="source",
            policy_json='{"pipeline_profile":"kg_source_vuln_scan"}',
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        kg_run = BinarySecurityStageRun(
            id="sr-kg",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[kg_run], stage_items=[])

        with (
            patch.object(self.manager, "_build_workflow_stage_snapshots", return_value=[]),
            patch.object(self.manager, "_workflow_blocked_on_stage", return_value=None),
            patch.object(self.manager, "_workflow_ready_for_finalization", return_value=False),
            patch.object(self.manager, "_next_stage_candidate", return_value="dataflow_vuln_scan"),
            patch.object(
                self.manager,
                "_evaluate_stage_start_gate",
                return_value={
                    "stage_name": "dataflow_vuln_scan",
                    "allowed": False,
                    "blocked_reason": "missing knowledge graph entry results",
                    "stage_run": None,
                    "stage_items": [],
                    "snapshot": None,
                    "stage_status": "pending",
                    "has_active_ownerless_progress": False,
                },
            ),
            patch.object(self.manager, "_should_requeue_for_owned_execution", return_value=False),
            patch.object(self.manager, "_record_event") as record_event,
            patch.object(self.manager, "_sync_task_abnormal_reason_snapshot"),
            patch.object(self.manager, "_enqueue_task") as enqueue_task,
        ):
            handled = self.manager._finalize_task_handle_resume_or_missing_stage(
                db,
                task,
                stage_runs=[kg_run],
            )

        self.assertTrue(handled)
        self.assertEqual("knowledge_graph_entry_fetch", task.current_stage)
        enqueue_task.assert_called_once_with(task.id)
        payload = record_event.call_args.kwargs["payload"]
        self.assertEqual("dataflow_vuln_scan", payload["candidate_next_stage"])
        self.assertFalse(payload["stage_start_allowed"])
        self.assertEqual("missing knowledge graph entry results", payload["blocked_reason"])

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

        self.assertIn(task.status, {"success", "partial_success"})
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertEqual(3, record_event.call_count)

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
            patch.object(self.manager, "_enqueue_task", side_effect=lambda *_args, **_kwargs: None),
            patch.object(self.manager, "_finalize_task") as finalize_task,
        ):
            self.manager._refresh_task_status_after_sync(db, task)

        finalize_task.assert_not_called()

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

    def test_finalize_task_after_authoritative_failure_blocks_non_owner(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="dispatching",
            current_stage="system_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
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

    def test_refresh_task_status_after_sync_early_return_terminalizes_cancel_failed_task_for_owner(self):
        task = BinarySecurityTask(
            id="task-cancel-failed",
            project_id="project-1",
            name="task",
            status=task_manager_module.TASK_STATUS_CANCEL_FAILED,
            current_stage="entry_analysis",
            last_error="cancel failed",
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

    def test_refresh_task_status_after_sync_early_return_terminalizes_factless_failed_task_for_owner(self):
        task = BinarySecurityTask(
            id="task-failed",
            project_id="project-1",
            name="task",
            status="failed",
            current_stage="entry_analysis",
            last_error="boom",
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


if __name__ == "__main__":
    unittest.main()
