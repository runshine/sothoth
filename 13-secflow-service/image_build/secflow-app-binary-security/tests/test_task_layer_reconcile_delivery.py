import asyncio
import unittest
from datetime import timedelta

from app.model import BinarySecurityTask, BinarySecurityTaskRuntimeLease, TASK_RUNTIME_PHASE_OWNED_EXECUTION, TASK_TYPE_BINARY
from app.service.task_manager import TaskManager, _now
from test_task_manager import _ModelAwareDb


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
