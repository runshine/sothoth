import unittest
from datetime import timedelta

from app.model import (
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager, _now
from test_task_manager import _ModelAwareDb, _TaskManagerQueuePatchedMixin


class ParentRuntimeOwnershipGuardTests(_TaskManagerQueuePatchedMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = TaskManager()
        self.manager.instance_id = "worker-local"

    def _task(self, **overrides):
        data = {
            "id": "task-1",
            "project_id": "project-1",
            "name": "task",
            "status": "running",
            "task_type": TASK_TYPE_SOURCE,
            "current_stage": "system_analysis",
            "firmware_source": "project_filesystem",
            "firmware_path": "/tmp/fw.bin",
            "output_root": "/tmp/out",
            "workspace_root": "/tmp/ws",
            "runtime_phase": TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        }
        data.update(overrides)
        return BinarySecurityTask(**data)

    def test_parent_runtime_ownership_snapshot_prefers_runtime_lease(self):
        task = self._task()
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        snapshot = self.manager._parent_runtime_ownership_snapshot(db, task)

        self.assertTrue(snapshot.runtime_lease_active)
        self.assertEqual("worker-live", snapshot.runtime_lease_owner)

    def test_release_task_without_supported_runtime_owner_keeps_running_task_when_runtime_lease_active(self):
        task = self._task()
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        changed = self.manager._release_task_without_supported_runtime_owner(
            db,
            task,
            reason="unit_test_runtime_lease_active",
        )

        self.assertFalse(changed)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-live", db.runtime_leases[0].owner_instance_id)

    def test_repair_running_lease_invariant_requeues_when_runtime_lease_missing_even_if_local_handle_alive(self):
        task = self._task()
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])
        self.manager._has_local_task_execution_owner = lambda _task_id: True

        repaired = self.manager._repair_running_lease_invariant(
            db,
            task,
            reason="unit_test_local_handle_alive",
        )

        self.assertTrue(repaired)
        self.assertEqual("pending", task.status)
        self.assertTrue(any(row.event_type == "running_without_active_lease_requeued" for row in db.events))

    def test_task_queue_state_prefers_runtime_lease_for_pending_task(self):
        task = self._task(status="pending")
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        queue_state, recoverable_reason = self.manager._task_queue_state(
            task,
            {"pending_positions": {}},
            db=db,
        )

        self.assertEqual("dispatching", queue_state)
        self.assertEqual("pending_task_owned_by_active_runtime", recoverable_reason)

    def test_task_queue_state_marks_running_task_without_runtime_lease_as_leased(self):
        task = self._task(status="running")
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])

        queue_state, recoverable_reason = self.manager._task_queue_state(
            task,
            {"pending_positions": {}},
            db=db,
        )

        self.assertEqual("leased", queue_state)
        self.assertEqual("execution_owner_missing", recoverable_reason)

    def test_task_owner_runtime_supported_locally_requires_active_runtime_lease(self):
        self.manager.instance_id = "worker-local"
        task = self._task(
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])

        import app.service.task_manager as task_manager_module

        original_factory = task_manager_module.get_session_factory
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            supported = self.manager._task_owner_runtime_supported_locally(task)
        finally:
            task_manager_module.get_session_factory = original_factory

        self.assertFalse(supported)

    def test_should_skip_readless_reconcile_for_active_task_keeps_runtime_lease_without_row_owner(self):
        task = self._task(
            status="cancelling",
        )
        self.manager._lease_is_active = lambda _task, db=None: True

        supported = self.manager._should_skip_readless_reconcile_for_active_task(task)

        self.assertTrue(supported)

    def test_should_preserve_task_dispatch_ownership_keeps_runtime_lease_without_row_owner(self):
        task = self._task(
            status="cancelling",
        )
        self.manager._lease_is_active = lambda _task, db=None: True

        supported = self.manager._should_preserve_task_dispatch_ownership(
            task,
            previous_status="cancelling",
            db=None,
        )

        self.assertTrue(supported)

    def test_dispatch_task_by_id_claims_fake_local_owner_without_runtime_lease(self):
        self.manager.instance_id = "local-worker"
        task = self._task(
            id="task-fake-owner-dispatch",
            status="dispatching",
            current_stage="system_analysis",
            current_operation_id="op-queued",
        )
        operation = BinarySecurityTaskOperation(
            id="op-queued",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            status="queued",
            current_step=None,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[])
        self.manager._enqueue_task = lambda _task_id: None

        claimed = self.manager._dispatch_task_by_id(db, task.id)

        self.assertEqual(task.id, claimed)
        self.assertEqual("dispatching", task.status)
        self.assertEqual("local-worker", db.runtime_leases[0].owner_instance_id)

    def test_release_task_without_supported_runtime_owner_suppresses_release_without_expired_runtime_lease(self):
        self.manager.instance_id = "local-worker"
        task = self._task(
            id="task-release-owner-repair-op",
            status="running",
            current_stage="system_analysis",
            current_operation_id="op-old",
        )
        older = BinarySecurityTaskOperation(
            id="op-old",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="continue",
            target_stage="system_analysis",
            status="accepted",
            created_at=_now() - timedelta(minutes=2),
            updated_at=_now() - timedelta(minutes=2),
        )
        newer = BinarySecurityTaskOperation(
            id="op-new",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="system_analysis",
            status="queued",
            created_at=_now() - timedelta(minutes=1),
            updated_at=_now() - timedelta(minutes=1),
        )
        db = _ModelAwareDb(tasks=[task], operations=[older, newer], runtime_leases=[], events=[])

        released = self.manager._release_task_without_supported_runtime_owner(
            db,
            task,
            active_operation=older,
            reason="unit_test_owner_drift",
        )

        self.assertTrue(released)
        self.assertEqual("pending", task.status)
        self.assertEqual("op-new", task.current_operation_id)
        self.assertEqual("superseded", older.status)
        self.assertTrue(any(event.event_type == "parent_takeover_recovery_committed" for event in db.events))
        self.assertEqual(
            [{"task_id": task.id, "context": "owned_execution_release_for_takeover"}],
            self.fake_task_queue.requeued_tasks,
        )

    def test_release_task_without_supported_runtime_owner_defers_when_takeover_lock_not_acquired(self):
        self.manager.instance_id = "local-worker"
        task = self._task(
            id="task-release-owner-lock-deferred",
            status="running",
            current_stage="system_analysis",
        )
        db = _ModelAwareDb(tasks=[task], operations=[], runtime_leases=[], events=[])
        self.fake_task_queue.parent_takeover_locks[task.id] = "other-worker:token"

        released = self.manager._release_task_without_supported_runtime_owner(
            db,
            task,
            reason="unit_test_takeover_lock_deferred",
        )

        self.assertFalse(released)
        self.assertEqual("running", task.status)
        self.assertTrue(any(event.event_type == "parent_takeover_lock_deferred" for event in db.events))
        self.assertEqual([], self.fake_task_queue.requeued_tasks)

    def test_release_task_without_supported_runtime_owner_suppresses_release_with_active_runtime_lease_mismatch(self):
        self.manager.instance_id = "local-worker"
        task = self._task(
            id="task-release-owner-active-runtime",
            status="running",
            current_stage="system_analysis",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=2),
            heartbeat_at=_now(),
        )
        db = _ModelAwareDb(tasks=[task], operations=[], runtime_leases=[runtime_lease], events=[])

        released = self.manager._release_task_without_supported_runtime_owner(
            db,
            task,
            reason="unit_test_active_runtime_lease_mismatch",
        )

        self.assertFalse(released)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-live", db.runtime_leases[0].owner_instance_id)

    def test_dispatch_task_by_id_skips_non_pending_task_when_active_runtime_lease_matches_owner(self):
        self.manager.instance_id = "local-worker"
        now_value = _now()
        task = self._task(
            id="task-active-lease-owned",
            status="running",
            current_stage="system_analysis",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=1,
            owner_instance_id="remote-worker",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(seconds=120),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        claimed = self.manager._dispatch_task_by_id(db, task.id)

        self.assertIsNone(claimed)
        self.assertEqual("running", task.status)
        self.assertEqual("remote-worker", db.runtime_leases[0].owner_instance_id)

    def test_repair_running_lease_invariant_requeues_after_runtime_lease_expired(self):
        self.manager.instance_id = "worker-new"
        task = self._task(
            id="task-running-lease-expired",
            status="running",
            current_stage="dataflow_vuln_scan",
        )
        expired_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-dead",
            lease_expires_at=_now() - timedelta(minutes=1),
            heartbeat_at=_now() - timedelta(minutes=1),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[expired_lease], events=[])

        repaired = self.manager._repair_running_lease_invariant(
            db,
            task,
            reason="unit_test_running_with_expired_lease",
            stage_name="dataflow_vuln_scan",
        )

        self.assertTrue(repaired)
        self.assertEqual("pending", task.status)
        self.assertTrue(any(event.event_type == "parent_runtime_reopen_allowed_after_lease_expiry" for event in db.events))

    def test_release_task_without_supported_runtime_owner_ignores_expired_runtime_lease(self):
        self.manager.instance_id = "worker-new"
        task = self._task(
            id="task-running-release-expired",
            status="running",
            current_stage="entry_analysis",
        )
        expired_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-dead",
            lease_expires_at=_now() - timedelta(minutes=1),
            heartbeat_at=_now() - timedelta(minutes=1),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[expired_lease], events=[])

        released = self.manager._release_task_without_supported_runtime_owner(
            db,
            task,
            reason="unit_test_release_running_to_pending_after_lease_expiry",
        )

        self.assertTrue(released)
        self.assertEqual("pending", task.status)
        self.assertTrue(any(event.event_type == "parent_takeover_recovery_committed" for event in db.events))
        self.assertEqual(
            [{"task_id": task.id, "context": "owned_execution_release_for_takeover"}],
            self.fake_task_queue.requeued_tasks,
        )

    def test_release_task_without_supported_runtime_owner_ignores_missing_runtime_lease(self):
        self.manager.instance_id = "worker-new"
        task = self._task(
            id="task-running-release-missing",
            status="running",
            current_stage="entry_analysis",
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])

        released = self.manager._release_task_without_supported_runtime_owner(
            db,
            task,
            reason="unit_test_release_running_to_pending_after_lease_missing",
        )

        self.assertTrue(released)
        self.assertEqual("pending", task.status)
        self.assertTrue(any(event.event_type == "parent_takeover_recovery_committed" for event in db.events))
        self.assertEqual(
            [{"task_id": task.id, "context": "owned_execution_release_for_takeover"}],
            self.fake_task_queue.requeued_tasks,
        )

    def test_release_task_without_supported_runtime_owner_ignores_stale_pending_claim_after_ten_minutes(self):
        self.manager.instance_id = "worker-new"
        task = self._task(
            id="task-running-release-stale-pending-claim",
            status="dispatching",
            current_stage="dataflow_vuln_scan",
            summary={
                "parent_takeover_pending_claim": {
                    "active": True,
                    "released_at": (_now() - timedelta(minutes=11)).isoformat(),
                    "enqueue_context": "owned_execution_release_for_takeover",
                }
            },
        )
        expired_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-dead",
            lease_expires_at=_now() - timedelta(minutes=1),
            heartbeat_at=_now() - timedelta(minutes=1),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[expired_lease], events=[])

        released = self.manager._release_task_without_supported_runtime_owner(
            db,
            task,
            reason="unit_test_release_dispatching_to_pending_after_pending_claim_expired",
        )

        self.assertTrue(released)
        self.assertEqual("pending", task.status)
        self.assertTrue(any(event.event_type == "parent_takeover_recovery_committed" for event in db.events))
        self.assertEqual(
            [{"task_id": task.id, "context": "owned_execution_release_for_takeover"}],
            self.fake_task_queue.requeued_tasks,
        )

    def test_release_task_without_supported_runtime_owner_requeues_only_after_db_commit(self):
        self.manager.instance_id = "worker-new"
        task = self._task(
            id="task-running-release-ordering",
            status="dispatching",
            current_stage="dataflow_vuln_scan",
            workspace_root="/tmp/ws-release-ordering",
        )
        expired_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-dead",
            lease_expires_at=_now() - timedelta(minutes=1),
            heartbeat_at=_now() - timedelta(minutes=1),
        )
        ordering: list[tuple[str, str]] = []
        original_enqueue = self.manager._enqueue_task_and_wait

        async def _recording_enqueue(task_id, *, context, timeout_seconds=None, force_requeue=False):
            ordering.append(("enqueue", str(task.status or "")))
            return await original_enqueue(
                task_id,
                context=context,
                timeout_seconds=timeout_seconds,
                force_requeue=force_requeue,
            )

        class _CommitTrackingDb(_ModelAwareDb):
            def commit(self_inner):
                ordering.append(("commit", str(task.status or "")))
                return super().commit()

        db = _CommitTrackingDb(tasks=[task], runtime_leases=[expired_lease], events=[])
        self.manager._enqueue_task_and_wait = _recording_enqueue
        try:
            released = self.manager._release_task_without_supported_runtime_owner(
                db,
                task,
                reason="unit_test_release_requeue_only_after_db_commit",
            )
        finally:
            self.manager._enqueue_task_and_wait = original_enqueue

        self.assertTrue(released)
        self.assertEqual("pending", task.status)
        self.assertEqual(
            [("commit", "pending"), ("enqueue", "pending"), ("commit", "pending")],
            ordering,
        )
