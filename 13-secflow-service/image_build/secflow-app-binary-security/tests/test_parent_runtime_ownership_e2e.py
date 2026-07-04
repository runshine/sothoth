import asyncio
import os
import unittest
from datetime import datetime, timedelta

from unittest.mock import patch

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


class ParentRuntimeOwnershipE2ETests(unittest.TestCase):
    def _task(self, **overrides):
        data = {
            "id": "task-e2e",
            "project_id": "project-1",
            "name": "source-task",
            "status": "running",
            "task_type": TASK_TYPE_SOURCE,
            "current_stage": "entry_analysis",
            "firmware_source": "project_filesystem",
            "firmware_path": "/src",
            "output_root": "/o",
            "workspace_root": "/w",
            "runtime_phase": TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            "dispatcher_instance_id": "worker-a",
            "dispatch_started_at": _now() - timedelta(minutes=3),
            "lease_expires_at": _now() - timedelta(seconds=10),
        }
        data.update(overrides)
        return BinarySecurityTask(**data)

    def test_live_runtime_lease_row_mirror_drift_e2e(self):
        manager = TaskManager()
        manager.instance_id = "worker-b"
        task = self._task(dispatcher_instance_id="worker-stale")
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        released = manager._release_unsupported_task_row_owner(
            db,
            task,
            reason="row_mirror_drift_e2e",
        )
        repaired = manager._repair_running_lease_invariant(
            db,
            task,
            reason="row_mirror_drift_e2e",
        )

        self.assertFalse(released)
        self.assertFalse(repaired)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-stale", task.dispatcher_instance_id)
        event = next(row for row in db.events if row.event_type == "parent_runtime_reopen_suppressed_active_lease")
        self.assertTrue(dict(event.payload or {}).get("row_mirror_drift"))

    def test_observe_only_reconcile_without_owner_e2e(self):
        manager = TaskManager()
        manager.instance_id = "worker-b"
        task = self._task(dispatcher_instance_id="worker-stale")
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])
        queued = []
        original_enqueue = manager._enqueue_task_with_context
        manager._enqueue_task_with_context = lambda task_id, **_kwargs: queued.append(task_id)
        try:
            manager._request_task_layer_reconcile(
                db,
                task,
                stage_name="entry_analysis",
                source_event_type="archive_job_copied",
                state_event_id="evt-1",
                reconcile_reason="archive_apply",
                message="observe-only reconcile without live owner",
            )
        finally:
            manager._enqueue_task_with_context = original_enqueue

        self.assertEqual([task.id], queued)
        event = next(row for row in db.events if row.event_type == "shared_dispatch_signal_enqueued")
        payload = dict(event.payload or {})
        self.assertEqual("observe_only", payload.get("reconcile_mode"))
        self.assertEqual("runtime_lease_owner_missing_requires_shared_dispatch", payload.get("decision_reason"))

    def test_stale_shared_dispatch_signal_drop_e2e(self):
        manager = TaskManager()
        manager.instance_id = "worker-b"
        task = self._task(
            dispatcher_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        task.summary = {
            "pending_shared_dispatch_signal": {
                "signal_type": "task_layer_reconcile",
                "enqueue_context": "shared_dispatch_task_layer_reconcile_enqueue",
                "source_event_type": "archive_job_copied",
                "requested_by_instance_id": "worker-a",
            }
        }
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        asyncio.run(
            manager._drop_unclaimed_dispatch_task_after_pop(
                db,
                task.id,
                reason="non_pending_task_already_owned_by_supported_runtime",
            )
        )

        self.assertEqual("running", task.status)
        drop_event = next(row for row in db.events if row.event_type == "dispatch_claim_dropped_after_pop")
        payload = dict(drop_event.payload or {})
        self.assertEqual("task_layer_reconcile", payload.get("signal_type"))
        self.assertEqual("archive_job_copied", payload.get("source_event_type"))
        self.assertEqual("worker-live", payload.get("runtime_lease_owner"))

    def test_delete_queue_consumption_deferred_then_recovered_e2e(self):
        manager = TaskManager()
        manager.instance_id = "worker-b"
        task = BinarySecurityTask(
            id="task-delete-blocked-recover",
            project_id="p1",
            name="source-task",
            status="running",
            current_stage="knowledge_graph_entry_fetch",
            current_operation_id="op-delete-blocked",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/output",
            workspace_root="/workspace",
            dispatcher_instance_id="worker-a",
            dispatch_started_at=_now() - timedelta(minutes=1),
            lease_expires_at=_now() + timedelta(minutes=3),
            cleanup_snapshot={},
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-blocked",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            target_stage=task.current_stage,
            request_payload={},
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=3),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])
        requeued = []
        manager._force_requeue_delete_task = lambda task_id: requeued.append(task_id)

        asyncio.run(manager._consume_delete_queue_task(db, task.id))

        self.assertEqual([task.id], requeued)
        self.assertEqual("worker-a", task.dispatcher_instance_id)
        deferred = next(row for row in db.events if row.event_type == "task_delete_queue_consumption_deferred_for_active_blocker")
        self.assertEqual("active_runtime_lease_blocks_delete_consume", (deferred.payload or {}).get("reason_code"))

        db.runtime_leases.clear()
        task.status = "failed"
        task.runtime_phase = TASK_RUNTIME_PHASE_TERMINAL
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        started = []

        async def _fake_prepare_delete(_db_session, current_task):
            started.append(current_task.id)

        original_prepare_delete = manager._prepare_delete_task
        try:
            manager._prepare_delete_task = _fake_prepare_delete
            asyncio.run(manager._consume_delete_queue_task(db, task.id))
        finally:
            manager._prepare_delete_task = original_prepare_delete

        self.assertEqual([task.id], started)
        self.assertEqual("worker-b", task.dispatcher_instance_id)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertTrue(any(row.event_type == "task_delete_queue_consumption_started" for row in db.events))

    def test_refresh_task_status_after_sync_recovers_dispatching_streaming_parent(self):
        manager = TaskManager()
        task = self._task(
            id="task-streaming-recover",
            status="dispatching",
            current_stage="entry_analysis",
            dispatcher_instance_id="worker-z",
            dispatch_started_at=_now() - timedelta(minutes=3),
            lease_expires_at=_now() - timedelta(seconds=10),
            policy_json='{"pipeline_mode": "mixed_streaming"}',
        )
        system_run = BinarySecurityStageRun(
            id="sr-sys",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        item = BinarySecurityStageItem(
            id="si-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-a",
            item_name="module-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[system_run, entry_run], stage_items=[item], events=[])

        with (
            patch.object(manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            patch.object(manager, "_enqueue_task", lambda *_args, **_kwargs: None),
        ):
            manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("worker-z", task.dispatcher_instance_id)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual("idle", task.tail_reconcile_state)
        self.assertTrue(any(event.event_type == "streaming_parent_state_recovered" for event in db.events))

    def test_owner_sync_downstream_status_resumes_owned_execution_from_running_tail_reconciliation_task_e2e(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="tail-reconcile-running-1",
            project_id="p1",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
            policy_json='{"pipeline_mode": "mixed_streaming"}',
            runtime_phase="tail_reconciliation",
        )
        stage_run = BinarySecurityStageRun(
            id="sr-tail-reconcile-running-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=1,
            status="running",
        )
        pending_item = BinarySecurityStageItem(
            id="si-tail-reconcile-running-pending-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-1",
            status="pending",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dvs-1",
        )
        active_item = BinarySecurityStageItem(
            id="si-tail-reconcile-running-active-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-2",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dvs-2",
            result={
                "sync_status": "skipped",
                "sync_observation": {
                    "last_attempt_at": (_now() - timedelta(minutes=10)).isoformat(),
                    "last_synced_at": (_now() - timedelta(minutes=10)).isoformat(),
                },
            },
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[pending_item, active_item], events=[])

        async def _fetch(_task, item, _token):
            return {
                "task_id": item.downstream_task_id,
                "status": "running" if item.id == active_item.id else "pending",
                "parent_stage_item_id": item.id,
            }

        original_fetch = manager._fetch_downstream_task_payload
        original_enqueue = manager._enqueue_task
        queued = []
        try:
            manager._fetch_downstream_task_payload = _fetch
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "worker"}, clear=False):
                asyncio.run(
                    manager.sync_downstream_status(
                        db,
                        project_id=task.project_id,
                        task_id=task.id,
                        force=False,
                        record_request_event=False,
                        apply_state=True,
                    )
                )
        finally:
            manager._fetch_downstream_task_payload = original_fetch
            manager._enqueue_task = original_enqueue

        self.assertEqual("running", task.status)
        self.assertEqual("tail_reconciliation", task.runtime_phase)
        self.assertEqual([], queued)
        self.assertEqual([], db.runtime_leases)
        requested_events = [event for event in db.events if event.event_type == "tail_execution_takeover_requested"]
        self.assertEqual([], requested_events)


    def test_refresh_task_status_after_sync_converts_failed_streaming_parent_to_failed(self):
        manager = TaskManager()
        task = self._task(
            id="task-firmware-failed",
            status="dispatching",
            current_stage="firmware_unpack",
            dispatcher_instance_id="worker-z",
            dispatch_started_at=_now() - timedelta(minutes=3),
            lease_expires_at=_now() - timedelta(seconds=10),
            policy_json='{"pipeline_mode": "mixed_streaming"}',
        )
        firmware_run = BinarySecurityStageRun(
            id="sr-fw",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="failed",
            last_error="Task owner pod lost",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[firmware_run], stage_items=[], events=[])

        with patch.object(manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("failed", task.status)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)
        self.assertIsNone(task.lease_expires_at)
        self.assertEqual("firmware_unpack", task.current_stage)
        self.assertIn("task_finalized_after_stage_failure", [event.event_type for event in db.events])

    def test_refresh_task_status_after_sync_keeps_owner_lost_child_recoverable(self):
        manager = TaskManager()
        task = self._task(
            id="task-firmware-owner-lost",
            status="dispatching",
            current_stage="firmware_unpack",
            dispatcher_instance_id="worker-z",
            dispatch_started_at=_now() - timedelta(minutes=3),
            lease_expires_at=_now() - timedelta(seconds=10),
            policy_json='{"pipeline_mode": "mixed_streaming"}',
        )
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-owner-lost",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="failed",
            last_error="Task owner pod lost",
        )
        item = BinarySecurityStageItem(
            id="si-fw-owner-lost",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=firmware_run.id,
            stage_name="firmware_unpack",
            item_key="fw.bin",
            item_name="fw.bin",
            status="failed",
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-owner-lost",
            error_message="Task owner pod lost",
            result={
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_type": "StaleTaskExecution",
                    "error_message": "任务 task-firmware-owner-lost 当前执行 token 已失效",
                    "last_result": "error",
                }
            },
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[firmware_run], stage_items=[item], events=[])

        with patch.object(manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual("firmware_unpack", task.current_stage)
        self.assertIsNone(task.finished_at)
        self.assertEqual("worker-z", task.dispatcher_instance_id)
        self.assertIsNotNone(task.dispatch_started_at)
        self.assertIsNotNone(task.lease_expires_at)
