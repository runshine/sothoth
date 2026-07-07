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
from test_task_manager import _AppendingModelAwareDb, _FakeDb, _FakeQuery, _FakeTaskSyncQueue


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
            manager._write_task_heartbeat(db, task.id, now_value=_now(), source="watchdog")

        self.assertEqual(manager.instance_id, db.runtime_leases[0].owner_instance_id)
        self.assertGreater(task.updated_at, previous_heartbeat_at)

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
            manager._write_task_heartbeat(db, task.id, now_value=_now(), source="watchdog")

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
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
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
        signal_calls = {"count": 0}

        async def _tail_execute(_task_id):
            task.status = "running"
            task.tail_reconcile_state = "idle"
            manager._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_OWNED_EXECUTION)

        async def _run_task_runtime_signals(_task_id):
            signal_calls["count"] += 1
            if signal_calls["count"] >= 3:
                task.status = "success"
            return False

        async def _fast_sleep(_seconds, result=None):
            return result

        original_factory = task_manager_module.get_session_factory
        original_execute = manager._execute_task
        original_active_context = manager._task_has_authoritative_active_stage_context
        original_run_task_runtime_signals = manager._run_task_runtime_signals
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._execute_task = _tail_execute
            manager._run_task_runtime_signals = _run_task_runtime_signals
            manager._task_has_authoritative_active_stage_context = lambda *_args, **_kwargs: False
            manager.cfg.scheduler.stage_poll_interval_seconds = 0
            # _run_task() can release/requeue parent ownership through takeover locks.
            # Use the fake queue here so the test never depends on the real Redis
            # lock client and cannot hang in rebuild-forever retry loops.
            with (
                patch("app.service.task.runtime.asyncio.sleep", new=_fast_sleep),
                patch.object(task_manager_module, "get_task_queue", return_value=_FakeTaskSyncQueue()),
            ):
                asyncio.run(manager._run_task(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._execute_task = original_execute
            manager._task_has_authoritative_active_stage_context = original_active_context
            manager._run_task_runtime_signals = original_run_task_runtime_signals

        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual("success", task.status)
        self.assertEqual(0, len(db.runtime_leases))
        self.assertFalse(any(event.event_type == "owned_execution_takeover_requeued" for event in db.events))
        self.assertGreaterEqual(signal_calls["count"], 3)

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
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
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
        signal_calls = {"count": 0}

        async def _noop_execute(_task_id):
            task.status = "running"
            return None

        async def _run_task_runtime_signals(_task_id):
            signal_calls["count"] += 1
            if signal_calls["count"] >= 3:
                task.status = "success"
            return False

        async def _fast_sleep(_seconds, result=None):
            return result

        original_factory = task_manager_module.get_session_factory
        original_execute = manager._execute_task
        original_active_context = manager._task_has_authoritative_active_stage_context
        original_run_task_runtime_signals = manager._run_task_runtime_signals
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._execute_task = _noop_execute
            manager._run_task_runtime_signals = _run_task_runtime_signals
            manager._task_has_authoritative_active_stage_context = lambda *_args, **_kwargs: False
            manager.cfg.scheduler.stage_poll_interval_seconds = 0
            with (
                patch("app.service.task.runtime.asyncio.sleep", new=_fast_sleep),
                patch.object(task_manager_module, "get_task_queue", return_value=_FakeTaskSyncQueue()),
            ):
                asyncio.run(manager._run_task(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._execute_task = original_execute
            manager._task_has_authoritative_active_stage_context = original_active_context
            manager._run_task_runtime_signals = original_run_task_runtime_signals

        self.assertEqual("success", task.status)
        self.assertEqual("system_analysis", task.current_stage)
        self.assertEqual(0, len(db.runtime_leases))
        self.assertFalse(any(event.event_type == "owned_execution_takeover_requeued" for event in db.events))
        self.assertGreaterEqual(signal_calls["count"], 3)

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
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
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
            with patch.object(task_manager_module, "get_task_queue", return_value=_FakeTaskSyncQueue()):
                reclaimed = manager._reclaim_stale_running_locked(db)
        finally:
            manager._load_service_config = original_loader

        self.assertTrue(reclaimed)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertFalse(any(event.event_type == "main_state_write_blocked" for event in db.events))

    def test_reclaim_stale_running_requeues_running_task_even_with_pending_claim_marker(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-stale-tail-pending-claim",
            project_id="p1",
            name="source",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
            summary={
                "parent_takeover_pending_claim": {
                    "active": True,
                    "released_at": _now().isoformat(),
                    "enqueue_context": "owned_execution_release_for_takeover",
                }
            },
        )

        class _ReclaimDb(_FakeDb):
            def query(self, model, *args, **kwargs):
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if model_name == "BinarySecurityStageRun":
                    return _FakeQuery([])
                if model_name == "BinarySecurityStageItem":
                    return _FakeQuery([])
                if model_name == "BinarySecurityTaskRuntimeLease":
                    return _FakeQuery([])
                return _FakeQuery([])

            def flush(self):
                pass

        db = _ReclaimDb()
        db.events = []
        enqueued = []
        original_loader = manager._load_service_config
        original_enqueue = manager._enqueue_task
        manager._load_service_config = lambda db: SimpleNamespace(dispatch_timeout_seconds=60)
        manager._enqueue_task = lambda task_id: enqueued.append(task_id)
        try:
            with patch.object(task_manager_module, "get_task_queue", return_value=_FakeTaskSyncQueue()):
                reclaimed = manager._reclaim_stale_running_locked(db)
        finally:
            manager._load_service_config = original_loader
            manager._enqueue_task = original_enqueue

        self.assertTrue(reclaimed)
        self.assertEqual("pending", task.status)
        self.assertEqual([], enqueued)
        self.assertTrue(dict(task.summary or {}).get("parent_takeover_pending_claim", {}).get("active"))


if __name__ == "__main__":
    unittest.main()
