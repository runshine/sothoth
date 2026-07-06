import asyncio
import unittest
from datetime import timedelta

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStateEvent,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import StaleTaskExecution, TaskManager, _now
from test_task_manager import _ModelAwareDb


class ParentRuntimeControlPathTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.manager.instance_id = "worker-local"

    def _task(self, **overrides):
        data = {
            "id": "task-1",
            "project_id": "project-1",
            "name": "task",
            "status": "running",
            "current_stage": "entry_analysis",
            "task_type": "binary",
            "workspace_root": "/tmp/ws",
            "output_root": "/tmp/out",
            "firmware_path": "/tmp/fw.bin",
            "runtime_phase": TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        }
        data.update(overrides)
        return BinarySecurityTask(**data)

    def test_operation_requeue_applied_requires_active_runtime_lease(self):
        task = self._task(current_operation_id="op-1")
        operation = BinarySecurityTaskOperation(
            id="op-1",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="running",
            result_payload={
                "requeue": {
                    "requested": True,
                    "applied": True,
                    "current_stage_after": "entry_analysis",
                }
            },
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            owner_started_at=_now(),
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[lease], events=[])

        self.assertTrue(self.manager._operation_requeue_applied(task, operation, db=db))

    def test_operation_requeue_inline_finalize_requires_runtime_lease_owner(self):
        self.manager.instance_id = "worker-live"
        task = self._task(current_operation_id="op-1")
        operation = BinarySecurityTaskOperation(
            id="op-1",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="running",
            result_payload={
                "requeue": {
                    "requested": True,
                    "applied": True,
                    "current_stage_after": "entry_analysis",
                }
            },
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            owner_started_at=_now(),
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[lease], events=[])

        self.assertTrue(self.manager._can_finalize_requeue_applied_operation_inline(db, task, operation))

    def test_reduce_state_event_does_not_treat_runtime_lease_only_owner_as_foreign_owner(self):
        task = self._task()
        event = BinarySecurityStateEvent(
            id="evt-1",
            task_id=task.id,
            project_id=task.project_id,
            event_type="downstream_status_observed",
            stage_name="entry_analysis",
            status="processing",
            leased_by=self.manager.instance_id,
            available_at=_now(),
            payload={"mapped_status": "running"},
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], state_events=[event], events=[])

        import app.service.task_manager as task_manager_module

        original_factory = task_manager_module.get_session_factory
        original_enqueue_owner = self.manager._enqueue_owner_signal
        original_enqueue_task = self.manager._enqueue_task_with_context
        owner_signals = []
        queued_tasks = []
        task_manager_module.get_session_factory = lambda: (lambda: db)
        self.manager._enqueue_owner_signal = lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
        self.manager._enqueue_task_with_context = lambda task_id, **_kwargs: queued_tasks.append(task_id)
        try:
            asyncio.run(self.manager._reduce_state_event(event.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            self.manager._enqueue_owner_signal = original_enqueue_owner
            self.manager._enqueue_task_with_context = original_enqueue_task

        self.assertEqual([], owner_signals)
        self.assertEqual([task.id], queued_tasks)
        takeover_event = next(row for row in db.events if row.event_type == "task_layer_reconcile_shared_dispatch_requested")
        payload = dict(takeover_event.payload or {})
        self.assertEqual("owner_not_active_on_replay_path", payload.get("forward_reason"))
        self.assertFalse(bool(payload.get("runtime_lease_active")))
        self.assertIsNone(payload.get("runtime_lease_owner"))

    def test_task_needs_downstream_reconcile_allows_runtime_lease_only_running_task(self):
        task = self._task(updated_at=_now() - timedelta(minutes=5))
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], stage_items=[])

        self.assertTrue(self.manager._task_needs_downstream_reconcile(db, task))

    def test_reclaim_stale_running_archive_job_uses_runtime_lease_authoritatively(self):
        task = self._task(current_stage="dataflow_vuln_scan")
        job = BinarySecurityArchiveJob(
            id="aj-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            item_id="item-1",
            item_key="entry-1",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-1",
            archive_status="running",
            created_at=_now() - timedelta(minutes=20),
            started_at=_now() - timedelta(minutes=20),
            updated_at=_now() - timedelta(minutes=20),
        )
        db = _ModelAwareDb(tasks=[task], archive_jobs=[job], runtime_leases=[], events=[])

        import app.service.task_manager as task_manager_module

        original_factory = task_manager_module.get_session_factory
        task_manager_module.get_session_factory = lambda: (lambda: db)
        try:
            reclaimed = self.manager._reclaim_stale_archive_jobs()
        finally:
            task_manager_module.get_session_factory = original_factory

        self.assertEqual(1, reclaimed)
        self.assertEqual("pending", job.archive_status)

    def test_has_task_write_ownership_prefers_runtime_lease_owner_over_runtime_lease_mirror(self):
        self.manager.instance_id = "worker-live"
        task = self._task()
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            owner_started_at=_now(),
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        self.assertTrue(self.manager._has_task_write_ownership(task, db=db))

    def test_ensure_owned_execution_current_prefers_runtime_lease_owner_over_runtime_lease_mirror(self):
        self.manager.instance_id = "worker-live"
        task = self._task()
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            owner_started_at=_now(),
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        row = self._task()
        db = _ModelAwareDb(tasks=[row], runtime_leases=[lease], events=[])
        self.manager._bind_execution_token(db, task)

        import app.service.task_manager as task_manager_module

        original_factory = task_manager_module.get_session_factory
        task_manager_module.get_session_factory = lambda: (lambda: db)
        try:
            self.manager._ensure_owned_execution_current(task)
        finally:
            task_manager_module.get_session_factory = original_factory

    def test_ensure_owned_execution_current_rejects_runtime_lease_owner_mismatch_even_if_row_matches(self):
        self.manager.instance_id = "worker-live"
        task = self._task()
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            owner_started_at=_now(),
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        row = self._task()
        db = _ModelAwareDb(tasks=[row], runtime_leases=[lease], events=[])
        self.manager._bind_execution_token(db, task)
        db.runtime_leases[0].owner_instance_id = "worker-other"

        import app.service.task_manager as task_manager_module

        original_factory = task_manager_module.get_session_factory
        task_manager_module.get_session_factory = lambda: (lambda: db)
        try:
            with self.assertRaises(StaleTaskExecution):
                self.manager._ensure_owned_execution_current(task)
        finally:
            task_manager_module.get_session_factory = original_factory

    def test_dispatch_task_by_id_suppresses_foreign_owner_delete_operation_with_active_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-foreign-owner-delete",
            project_id="p1",
            name="source",
            status="running",
            task_type="source",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-foreign-delete",
        )
        operation = BinarySecurityTaskOperation(
            id="op-foreign-delete",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            current_step=None,
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="old-worker",
            owner_started_at=_now(),
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[lease])
        manager._enqueue_task = lambda task_id: None

        claimed = manager._dispatch_task_by_id(db, task.id)

        self.assertIsNone(claimed)
        self.assertEqual("running", task.status)
        self.assertEqual(operation.id, task.current_operation_id)
        event_types = [event.event_type for event in db.events]
        self.assertIn("local_owner_runtime_restart_started", event_types)

    def test_dispatch_task_by_id_clears_stale_delete_queue_hidden_state_for_pending_task(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        manager._enqueue_task = lambda *_args, **_kwargs: None
        manager._enqueue_task_with_context = lambda *_args, **_kwargs: None
        task = BinarySecurityTask(
            id="task-stale-delete-hidden",
            project_id="p1",
            name="source",
            status="pending",
            task_type="source",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-retry",
        )
        task.cleanup_snapshot = {
            "delete_queued": True,
            "delete_in_progress": True,
            "delete_operation_id": "op-delete-stale",
            "delete_mode": "delete",
        }
        operation = BinarySecurityTaskOperation(
            id="op-retry",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="queued",
            current_step=None,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[])

        claimed = manager._dispatch_task_by_id(db, task.id)

        self.assertEqual(task.id, claimed)
        self.assertFalse(task.cleanup_snapshot.get("delete_queued"))
        self.assertFalse(task.cleanup_snapshot.get("delete_in_progress"))
        self.assertEqual("local-worker", db.runtime_leases[0].owner_instance_id)
        self.assertTrue(any(event.event_type == "stale_delete_queue_hidden_state_cleared" for event in db.events))

    def test_dispatch_task_by_id_keeps_hidden_when_active_delete_queue_operation_exists(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        manager._enqueue_task = lambda *_args, **_kwargs: None
        manager._enqueue_task_with_context = lambda *_args, **_kwargs: None
        task = BinarySecurityTask(
            id="task-active-delete-hidden",
            project_id="p1",
            name="source",
            status="pending",
            task_type="source",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-delete-active",
        )
        task.cleanup_snapshot = {
            "delete_queued": True,
            "delete_in_progress": False,
            "delete_operation_id": "op-delete-active",
            "delete_mode": "delete",
        }
        operation = BinarySecurityTaskOperation(
            id="op-delete-active",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            current_step=None,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[])

        claimed = manager._dispatch_task_by_id(db, task.id)

        self.assertIsNone(claimed)
        self.assertTrue(task.cleanup_snapshot.get("delete_queued"))
        self.assertEqual("op-delete-active", task.current_operation_id)
        self.assertFalse(any(event.event_type == "stale_delete_queue_hidden_state_cleared" for event in db.events))

    def test_task_supported_runtime_owner_keeps_remote_owner_when_active_runtime_lease_matches(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        now_value = _now()
        task = BinarySecurityTask(
            id="task-foreign-owner-healthy",
            project_id="p1",
            name="source",
            status="dispatching",
            task_type="source",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-remote-queued",
        )
        operation = BinarySecurityTaskOperation(
            id="op-remote-queued",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="queued",
            current_step=None,
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=1,
            owner_instance_id="remote-worker",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(seconds=120),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[lease])

        supported = manager._task_has_supported_runtime_owner(db, task, active_operation=operation)

        self.assertTrue(supported)
        self.assertEqual("dispatching", task.status)

    def test_task_supported_runtime_owner_rejects_recent_remote_dispatch_without_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-foreign-owner-starting",
            project_id="p1",
            name="source",
            status="dispatching",
            task_type="source",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[])

        supported = manager._task_has_supported_runtime_owner(db, task)

        self.assertFalse(supported)

    def test_task_supported_runtime_owner_rejects_stale_remote_dispatch_without_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-foreign-owner-stale",
            project_id="p1",
            name="source",
            status="dispatching",
            task_type="source",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[])

        supported = manager._task_has_supported_runtime_owner(db, task)

        self.assertFalse(supported)

    def test_task_supported_runtime_owner_does_not_require_runtime_handle_for_queued_cancel(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-cancel-no-runtime-handle",
            project_id="p1",
            name="source",
            status=task_manager_module.TASK_STATUS_CANCELLING,
            task_type="source",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            current_operation_id="op-cancel-queued",
        )
        operation = BinarySecurityTaskOperation(
            id="op-cancel-queued",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            status="queued",
            current_step=None,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[])

        supported = manager._task_has_supported_runtime_owner(db, task, active_operation=operation)

        self.assertFalse(supported)


if __name__ == "__main__":
    unittest.main()
