import asyncio
import json
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _FakeDb, _FakeQuery


class ParentRuntimeRecoveryPathTests(unittest.TestCase):
    def test_task_heartbeat_controller_refreshes_tail_reconcile_owner_task(self):
        manager = TaskManager()
        now_value = _now()
        task = BinarySecurityTask(
            id="task-tail-heartbeat",
            project_id="p1",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id=manager.instance_id,
            lease_expires_at=now_value + timedelta(seconds=30),
            updated_at=now_value - timedelta(minutes=5),
        )
        item = BinarySecurityStageItem(
            id="si-tail-heartbeat",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            item_key="module-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id=manager.instance_id,
            heartbeat_at=now_value - timedelta(minutes=1),
            lease_expires_at=now_value + timedelta(seconds=30),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], runtime_leases=[lease])
        manager._register_task_execution_owner(task.id, "primary_task_worker")
        manager._workers[task.id] = task_manager_module.TaskRuntimeHandle(
            task_id=task.id,
            runner_task=AsyncMock(),
            heartbeat_task=None,
            claimed_at=now_value,
            execution_token=None,
            lease_owner_instance_id=manager.instance_id,
        )
        previous_heartbeat_at = lease.heartbeat_at

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            manager._touch_task_heartbeat(task.id)

        self.assertEqual(manager.instance_id, db.runtime_leases[0].owner_instance_id)
        self.assertGreater(task.updated_at, previous_heartbeat_at)

    def test_touch_task_heartbeat_keeps_lease_alive_for_tail_reconcile_owner(self):
        manager = TaskManager()
        now_value = _now()
        started_at = _now() - timedelta(seconds=20)
        original_expiry = now_value + timedelta(seconds=5)
        task = BinarySecurityTask(
            id="task-tail-touch-heartbeat",
            project_id="p1",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id=manager.instance_id,
            lease_expires_at=original_expiry,
            updated_at=started_at,
        )
        item = BinarySecurityStageItem(
            id="si-tail-touch-heartbeat",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            item_key="module-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id=manager.instance_id,
            heartbeat_at=_now() - timedelta(seconds=20),
            lease_expires_at=original_expiry,
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], runtime_leases=[lease])
        original_factory = task_manager_module.get_session_factory
        original_interval = manager.cfg.scheduler.heartbeat_update_interval_seconds
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager.cfg.scheduler.heartbeat_update_interval_seconds = 0
            manager._register_task_execution_owner(task.id, "primary_task_worker")
            manager._workers[task.id] = task_manager_module.TaskRuntimeHandle(
                task_id=task.id,
                runner_task=AsyncMock(),
                heartbeat_task=None,
                claimed_at=now_value,
                execution_token=None,
                lease_owner_instance_id=manager.instance_id,
            )
            manager._touch_task_heartbeat(task.id)
        finally:
            task_manager_module.get_session_factory = original_factory
            manager.cfg.scheduler.heartbeat_update_interval_seconds = original_interval

        self.assertEqual(original_expiry, task.lease_expires_at)
        self.assertGreater(db.runtime_leases[0].lease_expires_at, original_expiry)
        self.assertGreater(task.updated_at, started_at)

    def test_task_heartbeat_controller_keeps_lease_after_runner_exit_when_owner_still_active(self):
        manager = TaskManager()
        now_value = _now()
        task = BinarySecurityTask(
            id="task-runner-exited-heartbeat",
            project_id="p1",
            status="running",
            current_stage="system_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id=manager.instance_id,
            dispatch_started_at=now_value - timedelta(minutes=1),
            lease_expires_at=now_value + timedelta(seconds=5),
            updated_at=now_value - timedelta(minutes=1),
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id=manager.instance_id,
            heartbeat_at=now_value - timedelta(minutes=1),
            lease_expires_at=now_value + timedelta(seconds=5),
        )
        db = _AppendingModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        done_runner = AsyncMock()
        done_runner.done.return_value = True
        manager._workers[task.id] = task_manager_module.TaskRuntimeHandle(
            task_id=task.id,
            runner_task=done_runner,
            heartbeat_task=None,
            claimed_at=now_value - timedelta(minutes=1),
            execution_token="exec-1",
            lease_owner_instance_id=manager.instance_id,
            owner_active=True,
            last_runner_exit_at=now_value - timedelta(seconds=10),
        )

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            previous_expiry = db.runtime_leases[0].lease_expires_at
            manager._touch_task_heartbeat(task.id)

        self.assertEqual(now_value + timedelta(seconds=5), task.lease_expires_at)
        self.assertGreater(db.runtime_leases[0].lease_expires_at, previous_expiry)
        self.assertEqual(manager.instance_id, db.runtime_leases[0].owner_instance_id)

    def test_run_task_finally_requeues_tail_runtime_without_active_owner(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-preserve-tail",
            project_id="p1",
            name="source",
            status="dispatching",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-a",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.dispatch_started_at = _now()
        task.lease_expires_at = _now() + timedelta(seconds=120)
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        item = BinarySecurityStageItem(
            id="si-preserve-tail",
            task_id=task.id,
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-a",
            item_name="module-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )

        class _RunTaskCleanupDb(_AppendingModelAwareDb):
            def query(self, model, *args, **kwargs):
                if getattr(model, "__name__", "") == "BinarySecurityTaskRuntimeLease":
                    parent = self

                    class _RuntimeLeaseQuery(_FakeQuery):
                        def filter(self, *args, **kwargs):
                            return self

                        def delete(self, synchronize_session=False):
                            del synchronize_session
                            deleted = len(parent.runtime_leases)
                            parent.runtime_leases.clear()
                            return deleted

                    return _RuntimeLeaseQuery(self.runtime_leases)
                return super().query(model, *args, **kwargs)

        db = _RunTaskCleanupDb(tasks=[task], stage_items=[item], events=[], runtime_leases=[lease])

        async def _tail_execute(_task_id):
            task.status = "running"
            task.tail_reconcile_state = "idle"
            manager._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_OWNED_EXECUTION)

        original_factory = task_manager_module.get_session_factory
        original_execute = manager._execute_task
        original_active_context = manager._task_has_authoritative_active_stage_context
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._execute_task = _tail_execute
            manager._task_has_authoritative_active_stage_context = lambda *_args, **_kwargs: False
            asyncio.run(manager._run_task(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._execute_task = original_execute
            manager._task_has_authoritative_active_stage_context = original_active_context

        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-a", task.dispatcher_instance_id)
        self.assertIsNotNone(task.dispatch_started_at)
        self.assertIsNotNone(task.lease_expires_at)
        self.assertEqual(1, len(db.runtime_leases))
        self.assertFalse(any(event.event_type == "owned_execution_takeover_requeued" for event in db.events))
        self.assertTrue(any(event.event_type == "parent_runtime_reopen_suppressed_active_lease" for event in db.events))

    def test_run_task_finally_requeues_nonstreaming_runtime_without_active_owner(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-run-exit-requeue",
            project_id="p1",
            name="binary",
            status="dispatching",
            current_stage="system_analysis",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-a",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        task.dispatch_started_at = _now()
        task.lease_expires_at = _now() + timedelta(seconds=120)
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        stage_run = BinarySecurityStageRun(
            id="sr-run-exit-requeue",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
        )

        class _RunTaskCleanupDb(_AppendingModelAwareDb):
            def query(self, model, *args, **kwargs):
                if getattr(model, "__name__", "") == "BinarySecurityTaskRuntimeLease":
                    parent = self

                    class _RuntimeLeaseQuery(_FakeQuery):
                        def filter(self, *args, **kwargs):
                            return self

                        def delete(self, synchronize_session=False):
                            del synchronize_session
                            deleted = len(parent.runtime_leases)
                            parent.runtime_leases.clear()
                            return deleted

                    return _RuntimeLeaseQuery(self.runtime_leases)
                return super().query(model, *args, **kwargs)

        db = _RunTaskCleanupDb(tasks=[task], stage_runs=[stage_run], runtime_leases=[lease], events=[])

        async def _noop_execute(_task_id):
            task.status = "running"
            return None

        original_factory = task_manager_module.get_session_factory
        original_execute = manager._execute_task
        original_active_context = manager._task_has_authoritative_active_stage_context
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._execute_task = _noop_execute
            manager._task_has_authoritative_active_stage_context = lambda *_args, **_kwargs: False
            asyncio.run(manager._run_task(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._execute_task = original_execute
            manager._task_has_authoritative_active_stage_context = original_active_context

        self.assertEqual("running", task.status)
        self.assertEqual("system_analysis", task.current_stage)
        self.assertEqual("worker-a", task.dispatcher_instance_id)
        self.assertIsNotNone(task.dispatch_started_at)
        self.assertIsNotNone(task.lease_expires_at)
        self.assertEqual(1, len(db.runtime_leases))
        self.assertFalse(any(event.event_type == "owned_execution_takeover_requeued" for event in db.events))
        self.assertTrue(any(event.event_type == "parent_runtime_reopen_suppressed_active_lease" for event in db.events))

    def test_reclaim_stale_running_streaming_tail_requeues_for_takeover(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-stale-tail",
            project_id="p1",
            name="source",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="dead-worker",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.dispatch_started_at = _now() - timedelta(seconds=600)
        task.updated_at = _now() - timedelta(seconds=600)
        item = BinarySecurityStageItem(
            id="si-stale-tail",
            task_id=task.id,
            project_id="p1",
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-a",
            item_name="module-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )

        class _ReclaimDb(_FakeDb):
            def query(self, model, *args, **kwargs):
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if model_name == "BinarySecurityStageRun":
                    return _FakeQuery([])
                if model_name == "BinarySecurityStageItem":
                    return _FakeQuery([item])
                if model_name == "BinarySecurityTaskRuntimeLease":
                    return _FakeQuery([])
                return _FakeQuery([])

            def flush(self):
                pass

        db = _ReclaimDb()
        db.events = []
        original_loader = manager._load_service_config
        manager._load_service_config = lambda db: SimpleNamespace(dispatch_timeout_seconds=60)
        try:
            reclaimed = manager._reclaim_stale_running_locked(db)
        finally:
            manager._load_service_config = original_loader

        self.assertTrue(reclaimed)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)
        self.assertIsNone(task.lease_expires_at)
        self.assertFalse(any(event.event_type == "main_state_write_blocked" for event in db.events))


if __name__ == "__main__":
    unittest.main()
