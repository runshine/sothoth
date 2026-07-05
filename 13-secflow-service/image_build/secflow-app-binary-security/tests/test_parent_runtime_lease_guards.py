import os
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.model import (
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


class ParentRuntimeLeaseGuardTests(unittest.TestCase):
    def test_write_task_heartbeat_refreshes_runtime_lease_and_task_row_mirror(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        now_value = _now()
        task = BinarySecurityTask(
            id="task-heartbeat-mirror",
            project_id="p1",
            name="demo",
            status="running",
            current_stage="entry_analysis",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id=None,
            dispatch_started_at=None,
            lease_expires_at=now_value - timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])

        wrote = manager._write_task_heartbeat(db, task.id, now_value=now_value, source="unit_test")

        self.assertTrue(wrote)
        self.assertEqual("worker-a", task.dispatcher_instance_id)
        self.assertEqual(now_value, task.dispatch_started_at)
        self.assertIsNotNone(task.lease_expires_at)
        self.assertGreater(task.lease_expires_at, now_value)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        lease = db.runtime_leases[0]
        self.assertEqual("worker-a", lease.owner_instance_id)
        self.assertEqual(lease.lease_expires_at, task.lease_expires_at)

    def test_queue_reconcile_skips_pending_not_enqueued_when_runtime_lease_is_active(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-pending-active-lease",
            project_id="p1",
            name="demo",
            status="pending",
            current_stage="entry_analysis",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-a",
        )
        now_value = _now()
        db = _AppendingModelAwareDb(
            tasks=[task],
            runtime_leases=[
                BinarySecurityTaskRuntimeLease(
                    task_id=task.id,
                    owner_instance_id="worker-a",
                    lease_expires_at=now_value + timedelta(minutes=5),
                    heartbeat_at=now_value,
                )
            ],
            events=[],
        )

        class _Queue:
            async def queue_positions(self, *_args, **_kwargs):
                return {}

            async def cleanup_dedupe_orphans(self, *_args, **_kwargs):
                return {}

        original_get_queue = task_manager_module.get_task_queue
        try:
            task_manager_module.get_task_queue = lambda: _Queue()
            import asyncio

            asyncio.run(manager._reconcile_work_queues_once(db, now_value=now_value))
        finally:
            task_manager_module.get_task_queue = original_get_queue

        event_types = [event.event_type for event in db.events]
        self.assertNotIn("pending_task_not_enqueued_detected", event_types)

    def test_task_heartbeat_controller_refreshes_running_task_without_dispatcher_ownership(self):
        manager = TaskManager()
        now_value = _now()
        task = BinarySecurityTask(
            id="task-3",
            project_id="p1",
            status="running",
            dispatcher_instance_id="other-worker",
            dispatch_started_at=now_value,
            lease_expires_at=now_value + timedelta(seconds=5),
        )
        db = _AppendingModelAwareDb(tasks=[task])
        original_factory = task_manager_module.get_session_factory
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._register_task_execution_owner(task.id, "primary_task_worker")
            manager._workers[task.id] = task_manager_module.TaskRuntimeHandle(
                task_id=task.id,
                runner_task=AsyncMock(),
                heartbeat_task=None,
                claimed_at=now_value,
                execution_token=None,
                lease_owner_instance_id=manager.instance_id,
            )
            original_lease = task.lease_expires_at
            manager._refresh_task_heartbeats_once()
            self.assertEqual(0, len(db.runtime_leases))
            self.assertEqual(original_lease, task.lease_expires_at)
        finally:
            task_manager_module.get_session_factory = original_factory

    def test_touch_task_heartbeat_does_not_refresh_without_active_runtime_lease_even_if_local_handle_alive(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        now_value = _now()
        task = BinarySecurityTask(
            id="task-no-active-lease-local-handle",
            project_id="p1",
            status="running",
            current_stage="system_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id="worker-a",
            dispatch_started_at=now_value - timedelta(minutes=1),
            lease_expires_at=now_value - timedelta(seconds=1),
            updated_at=now_value - timedelta(minutes=1),
        )
        expired_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            heartbeat_at=now_value - timedelta(minutes=1),
            lease_expires_at=now_value - timedelta(seconds=1),
        )
        db = _AppendingModelAwareDb(tasks=[task], runtime_leases=[expired_lease], events=[])
        manager._workers[task.id] = task_manager_module.TaskRuntimeHandle(
            task_id=task.id,
            runner_task=AsyncMock(),
            heartbeat_task=None,
            claimed_at=now_value - timedelta(minutes=1),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            owner_active=True,
        )
        manager._register_task_execution_owner(task.id, "primary_task_worker")

        original_factory = task_manager_module.get_session_factory
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            original_expiry = task.lease_expires_at
            manager._touch_task_heartbeat(task.id)
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._release_task_execution_owner(task.id, "primary_task_worker")
            manager._workers.pop(task.id, None)

        self.assertEqual(original_expiry, task.lease_expires_at)
        self.assertEqual(1, len(db.runtime_leases))

    def test_worker_does_not_take_tail_runtime_lease_on_refresh(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="tail-refresh-1",
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
            id="sr-tail-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=1,
            status="running",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="reducer-a",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], runtime_leases=[lease])
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "worker"}, clear=False):
            manager._refresh_task_status_after_sync(db, task)
        self.assertEqual("reducer-a", db.runtime_leases[0].owner_instance_id)
        self.assertEqual("running", task.status)

    def test_reclaim_stale_dispatching_skips_stale_row_when_runtime_lease_active(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-dispatching-stale-row-active-runtime",
            project_id="p1",
            name="source",
            status="dispatching",
            task_type=TASK_TYPE_SOURCE,
            current_stage="firmware_unpack",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-stale",
            dispatch_started_at=_now() - timedelta(minutes=10),
            lease_expires_at=_now() - timedelta(minutes=5),
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=2),
            heartbeat_at=_now(),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], events=[], runtime_leases=[runtime_lease])

        with patch.object(manager, "_streaming_tail_active_context", return_value=(None, 0, False)):
            reclaimed = manager._reclaim_stale_dispatching_locked(db)

        self.assertFalse(reclaimed)
        self.assertEqual("dispatching", task.status)
        self.assertEqual("worker-stale", task.dispatcher_instance_id)
        self.assertFalse(
            any(
                event.event_type in {
                    "dispatch_reclaimed",
                    "dispatch_reclaim_blocked",
                    "dispatching_execution_released_for_takeover",
                }
                for event in db.events
            )
        )

    def test_reclaim_stale_running_skips_stale_row_when_runtime_lease_active(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-running-stale-row-active-runtime",
            project_id="p1",
            name="source",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-stale",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            policy_json='{"pipeline_mode": "mixed_streaming"}',
        )
        task.dispatch_started_at = _now() - timedelta(minutes=10)
        task.updated_at = _now() - timedelta(minutes=10)
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-live",
            lease_expires_at=_now() + timedelta(minutes=2),
            heartbeat_at=_now(),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], events=[], runtime_leases=[runtime_lease])

        original_loader = manager._load_service_config
        manager._load_service_config = lambda db: SimpleNamespace(dispatch_timeout_seconds=60)
        try:
            reclaimed = manager._reclaim_stale_running_locked(db)
        finally:
            manager._load_service_config = original_loader

        self.assertFalse(reclaimed)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-stale", task.dispatcher_instance_id)
        self.assertFalse(
            any(
                event.event_type in {
                    "running_without_active_lease_requeued",
                    "task_finalized_after_child_failure",
                    "main_state_write_blocked",
                }
                for event in db.events
            )
        )


if __name__ == "__main__":
    unittest.main()
