import asyncio
import unittest
from datetime import timedelta

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


class TaskLayerReconcileDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.manager.instance_id = "worker-local"

    def _task(self, **overrides):
        data = {
            "id": "task-1",
            "project_id": "project-1",
            "name": "binary",
            "status": "running",
            "task_type": TASK_TYPE_BINARY,
            "current_stage": "entry_analysis",
            "firmware_source": "project_filesystem",
            "firmware_path": "/fw.bin",
            "output_root": "/o",
            "workspace_root": "/tmp",
            "runtime_phase": TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            "dispatcher_instance_id": "worker-stale",
        }
        data.update(overrides)
        return BinarySecurityTask(**data)

    def test_observe_only_reconcile_without_owner_uses_shared_dispatch_only(self):
        task = self._task()
        db = _ModelAwareDb(tasks=[task], events=[], runtime_leases=[])
        queued = []
        owner_signals = []

        original_enqueue_task = self.manager._enqueue_task_with_context
        original_enqueue_owner_signal = self.manager._enqueue_owner_signal
        self.manager._enqueue_task_with_context = lambda task_id, **_kwargs: queued.append(task_id)
        self.manager._enqueue_owner_signal = lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
        try:
            self.manager._request_task_layer_reconcile(
                db,
                task,
                stage_name="entry_analysis",
                source_event_type="archive_job_copied",
                state_event_id=None,
                reconcile_reason="archive_apply",
                message="archive apply without live owner",
            )
        finally:
            self.manager._enqueue_task_with_context = original_enqueue_task
            self.manager._enqueue_owner_signal = original_enqueue_owner_signal

        self.assertEqual(["task-1"], queued)
        self.assertEqual([], owner_signals)
        event_types = [row.event_type for row in db.events]
        self.assertNotIn("owner_reconcile_signal_enqueued", event_types)
        signal_event = next(row for row in db.events if row.event_type == "shared_dispatch_signal_enqueued")
        payload = dict(signal_event.payload or {})
        self.assertEqual("shared_dispatch", payload.get("signal_channel"))
        self.assertEqual("observe_only", payload.get("reconcile_mode"))
        self.assertEqual("runtime_lease_owner_missing_requires_shared_dispatch", payload.get("decision_reason"))

    def test_observe_only_reconcile_with_active_runtime_owner_uses_owner_inbox(self):
        task = self._task(dispatcher_instance_id="worker-live")
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], events=[], runtime_leases=[lease])
        queued = []
        owner_signals = []

        original_enqueue_task = self.manager._enqueue_task_with_context
        original_enqueue_owner_signal = self.manager._enqueue_owner_signal
        self.manager._enqueue_task_with_context = lambda task_id, **_kwargs: queued.append(task_id)
        self.manager._enqueue_owner_signal = lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
        try:
            self.manager._request_task_layer_reconcile(
                db,
                task,
                stage_name="entry_analysis",
                source_event_type="archive_job_copied",
                state_event_id=None,
                reconcile_reason="archive_apply",
                message="archive apply with live owner",
            )
        finally:
            self.manager._enqueue_task_with_context = original_enqueue_task
            self.manager._enqueue_owner_signal = original_enqueue_owner_signal

        self.assertEqual([], queued)
        self.assertEqual([("worker-live", "task-1")], owner_signals)
        event_types = [row.event_type for row in db.events]
        self.assertIn("owner_reconcile_signal_enqueued", event_types)

    def test_drop_unclaimed_dispatch_task_after_pop_records_complete_signal_metadata(self):
        task = self._task(
            current_stage="dataflow_vuln_scan",
            dispatcher_instance_id="worker-owner",
        )
        task.summary = {
            "pending_shared_dispatch_signal": {
                "signal_type": "task_layer_reconcile",
                "enqueue_context": "shared_dispatch_task_layer_reconcile_enqueue",
                "source_event_type": "stage_worker_terminal_observed",
                "requested_by_instance_id": "worker-origin",
            }
        }
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-owner",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], events=[], runtime_leases=[lease])

        asyncio.run(
            self.manager._drop_unclaimed_dispatch_task_after_pop(
                db,
                task.id,
                reason="non_pending_task_already_owned_by_supported_runtime",
            )
        )

        event = next(row for row in db.events if row.event_type == "dispatch_claim_dropped_after_pop")
        payload = dict(event.payload or {})
        self.assertEqual("task_layer_reconcile", payload.get("signal_type"))
        self.assertEqual("shared_dispatch_task_layer_reconcile_enqueue", payload.get("enqueue_context"))
        self.assertEqual("stage_worker_terminal_observed", payload.get("source_event_type"))
        self.assertEqual("worker-owner", payload.get("runtime_lease_owner"))
        self.assertEqual("worker-owner", payload.get("row_mirror_owner"))
        self.assertTrue(payload.get("runtime_lease_active"))

    def test_task_layer_reconcile_delivery_decision_ignores_stale_dispatcher_without_runtime_lease(self):
        task = self._task(dispatcher_instance_id="worker-stale")
        db = _ModelAwareDb(tasks=[task], events=[], runtime_leases=[])

        decision = self.manager._task_layer_reconcile_delivery_decision(
            db,
            task,
            source_event_type="stage_worker_terminal_observed",
            reconcile_reason="stage_worker_terminal_observed",
        )

        self.assertEqual("shared_dispatch", decision.delivery_channel)
        self.assertIsNone(decision.target_owner_instance_id)
        self.assertEqual("runtime_lease_owner_missing_requires_shared_dispatch", decision.decision_reason)

    def test_missing_stage_terminal_recovery_prefers_owner_inbox_with_allow_execution(self):
        task = self._task(
            id="task-missing-stage-terminal",
            current_stage="firmware_unpack",
            firmware_path="/fw.bin",
            dispatcher_instance_id="worker-a",
        )
        task.dispatch_started_at = _now()
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], runtime_leases=[runtime_lease], events=[])

        decision = self.manager._task_layer_reconcile_delivery_decision(
            db,
            task,
            source_event_type="stage_worker_terminal_observed",
            reconcile_reason="missing_stage_terminal_recovery",
        )

        self.assertEqual("owner_inbox", decision.delivery_channel)
        self.assertFalse(decision.observe_only)

    def test_missing_stage_terminal_recovery_request_uses_allow_execution_signal(self):
        task = self._task(
            id="task-missing-stage-terminal-request",
            current_stage="firmware_unpack",
            firmware_path="/fw.bin",
            dispatcher_instance_id="worker-a",
        )
        task.dispatch_started_at = _now()
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], runtime_leases=[runtime_lease], events=[])

        original_enqueue_owner_signal = self.manager._enqueue_owner_signal
        enqueued = []

        def _capture_enqueue(owner_instance_id: str, task_id: str, *, context: str = "owner_signal_enqueue"):
            enqueued.append((owner_instance_id, task_id, context))

        self.manager._enqueue_owner_signal = _capture_enqueue
        try:
            self.manager._request_task_layer_reconcile(
                db,
                task,
                stage_name="firmware_unpack",
                source_event_type="stage_worker_terminal_observed",
                state_event_id="sev-terminal-missing",
                reconcile_reason="missing_stage_terminal_recovery",
                message="missing terminal recovery",
            )
        finally:
            self.manager._enqueue_owner_signal = original_enqueue_owner_signal

        pending_reconcile = dict(self.manager._task_runtime_workset(task).get("pending_task_layer_reconcile") or {})
        self.assertEqual("allow_execution", pending_reconcile.get("reconcile_mode"))
        self.assertEqual("missing_stage_terminal_recovery", pending_reconcile.get("reconcile_reason"))
        self.assertEqual("stage_worker_terminal_observed", pending_reconcile.get("source_event_type"))
        self.assertEqual([("worker-a", task.id, "owner_reconcile_signal_enqueue")], enqueued)

    def test_archive_apply_remains_owner_inbox_observe_only(self):
        task = self._task(
            id="task-archive-observe-only",
            current_stage="firmware_unpack",
            firmware_path="/fw.bin",
            dispatcher_instance_id="worker-a",
        )
        task.dispatch_started_at = _now()
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], runtime_leases=[runtime_lease], events=[])

        decision = self.manager._task_layer_reconcile_delivery_decision(
            db,
            task,
            source_event_type="archive_job_copied",
            reconcile_reason="archive_apply",
        )

        self.assertEqual("owner_inbox", decision.delivery_channel)
        self.assertTrue(decision.observe_only)

    def test_observe_only_reconcile_skips_tail_sync_for_non_tail_stage(self):
        task = self._task(
            id="task-non-tail-observe-only",
            current_stage="firmware_unpack",
            firmware_path="/fw.bin",
        )
        task.summary = {
            "runtime_workset": {
                "pending_task_layer_reconcile": {
                    "source_event_type": "archive_job_copied",
                    "state_event_id": "sev-non-tail-observe-only",
                    "reconcile_reason": "archive_apply",
                    "stage_name": "firmware_unpack",
                    "reconcile_mode": "observe_only",
                    "fact_applied": True,
                }
            }
        }
        stage_run = BinarySecurityStageRun(
            id="sr-non-tail-observe-only",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], events=[])

        from app.service import task_manager as task_manager_module

        original_factory = task_manager_module.get_session_factory
        original_sync_tail = self.manager._sync_streaming_task_tail_state
        sync_tail_calls = []

        async def _capture_sync_tail(task_id: str):
            sync_tail_calls.append(task_id)

        task_manager_module.get_session_factory = lambda: (lambda: db)
        self.manager._sync_streaming_task_tail_state = _capture_sync_tail
        try:
            changed = asyncio.run(self.manager._run_task_runtime_signals(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            self.manager._sync_streaming_task_tail_state = original_sync_tail

        self.assertFalse(changed)
        self.assertEqual([], sync_tail_calls)

    def test_finalize_deferred_keeps_running_during_owned_stage_handoff(self):
        task = self._task(
            id="task-stage-handoff",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_path="/src",
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-handoff",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            output_summary={"success_count": 1},
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-handoff",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-handoff",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            item_key="source_project-http_parse",
            status="pending",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[system_run, entry_run], stage_items=[entry_item], events=[])
        original_next_incomplete_stage = self.manager._next_stage_candidate
        original_workflow_blocked_on_stage = self.manager._workflow_blocked_on_stage
        original_enqueue_task = self.manager._enqueue_task
        enqueued = []

        self.manager._next_stage_candidate = lambda _db, _task: "entry_analysis"
        self.manager._workflow_blocked_on_stage = lambda _task, _snapshots: None
        self.manager._enqueue_task = lambda task_id: enqueued.append(task_id)
        try:
            changed = self.manager._finalize_task_handle_resume_or_missing_stage(
                db,
                task,
                stage_runs=[system_run, entry_run],
            )
        finally:
            self.manager._next_stage_candidate = original_next_incomplete_stage
            self.manager._workflow_blocked_on_stage = original_workflow_blocked_on_stage
            self.manager._enqueue_task = original_enqueue_task

        self.assertTrue(changed)
        self.assertEqual("running", task.status)
        self.assertEqual([task.id], enqueued)
        self.assertFalse(
            any(
                row.__class__.__name__ == "BinarySecurityEvent"
                and row.event_type == "task_status_changed"
                and '"to_status": "pending"' in str(getattr(row, "payload_json", "") or "")
                for row in db.added
            )
        )
