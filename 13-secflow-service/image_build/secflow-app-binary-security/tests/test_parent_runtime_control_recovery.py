import asyncio
import unittest
from datetime import datetime, timedelta

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


class ParentRuntimeControlRecoveryTests(unittest.TestCase):
    def test_requeue_orphaned_owned_execution_locked_recovers_orphan(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary-module",
            status="running",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="binary_to_source",
            item_key="module1",
            parent_key="module1",
            status="failed",
            downstream_service="binary_to_source",
            downstream_task_id=None,
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], events=[])

        original_enqueue = manager._enqueue_task_with_context
        queued = []
        manager._enqueue_task_with_context = lambda task_id, **_kwargs: queued.append(task_id)
        try:
            with (
                unittest.mock.patch.object(manager, "_task_runtime_transition_guard_active", return_value=False),
                unittest.mock.patch.object(manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            ):
                reclaimed = manager._requeue_orphaned_owned_execution_locked(db)
        finally:
            manager._enqueue_task_with_context = original_enqueue

        self.assertTrue(reclaimed)
        self.assertEqual("running", task.status)
        self.assertEqual([], queued)
        requeue_events = [event for event in db.events if event.event_type == "owned_execution_takeover_requeued"]
        self.assertFalse(requeue_events)
        suppress_events = [event for event in db.events if event.event_type == "parent_runtime_reopen_suppressed_active_lease"]
        self.assertTrue(suppress_events)

    def test_owner_drift_requeue_can_be_claimed_and_runtime_restarted(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-owner-drift-restart",
            project_id="p1",
            name="binary-module",
            status="running",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id="stale-worker",
            current_operation_id="op-old",
            lease_expires_at=_now() - timedelta(seconds=1),
        )
        stage_run = BinarySecurityStageRun(
            id="sr-owner-drift-restart",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si-owner-drift-restart",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="binary_to_source",
            item_key="module1",
            parent_key="module1",
            status="running",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-owner-drift",
        )
        older = BinarySecurityTaskOperation(
            id="op-old",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="continue",
            target_stage="binary_to_source",
            status="accepted",
            created_at=_now() - timedelta(minutes=2),
            updated_at=_now() - timedelta(minutes=2),
        )
        newer = BinarySecurityTaskOperation(
            id="op-new",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="binary_to_source",
            status="queued",
            created_at=_now() - timedelta(minutes=1),
            updated_at=_now() - timedelta(minutes=1),
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[stage_run],
            stage_items=[item],
            operations=[older, newer],
            runtime_leases=[],
            events=[],
        )

        released = manager._release_unsupported_task_row_owner(
            db,
            task,
            active_operation=older,
            reason="unit_test_owner_drift_runtime_restart",
        )

        self.assertTrue(released)
        self.assertEqual("pending", task.status)
        self.assertEqual("op-new", task.current_operation_id)
        self.assertEqual("superseded", older.status)

        manager._enqueue_task = lambda *_args, **_kwargs: None
        claimed = manager._dispatch_task_by_id(db, task.id)

        self.assertEqual(task.id, claimed)
        self.assertEqual("dispatching", task.status)
        self.assertEqual("local-worker", task.dispatcher_instance_id)
        self.assertIsNotNone(task.dispatch_started_at)
        self.assertIsNotNone(task.lease_expires_at)

    def test_requeue_orphaned_owned_execution_ignores_legacy_row_lease_without_runtime_lease(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary-module",
            status="running",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            dispatcher_instance_id="stale-worker-pod",
            dispatch_started_at=datetime.fromisoformat("2026-06-11T20:26:44"),
            lease_expires_at=datetime.fromisoformat("2026-06-11T20:29:43"),
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="binary_to_source",
            item_key="module1",
            parent_key="module1",
            status="running",
            downstream_service="binary_to_source",
            downstream_task_id="b2s1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], events=[])

        original_enqueue = manager._enqueue_task_with_context
        queued = []
        manager._enqueue_task_with_context = lambda task_id, **_kwargs: queued.append(task_id)
        try:
            with (
                unittest.mock.patch.object(manager, "_task_runtime_transition_guard_active", return_value=False),
                unittest.mock.patch.object(manager, "_task_runtime_owner_matches_current_instance", return_value=True),
            ):
                reclaimed = manager._requeue_orphaned_owned_execution_locked(db)
        finally:
            manager._enqueue_task_with_context = original_enqueue

        self.assertTrue(reclaimed)
        self.assertEqual("pending", task.status)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)
        self.assertIsNone(task.lease_expires_at)
        self.assertEqual(["t1"], queued)
        requeue_events = [event for event in db.events if event.event_type == "owned_execution_takeover_requeued"]
        self.assertTrue(requeue_events)

    def test_requeue_orphaned_owned_execution_locked_skips_active_transition_guard(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary-module",
            status="running",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            summary={
                "runtime_transition_guard": {
                    "guard_id": "guard-1",
                    "owner_instance_id": "worker-1",
                    "from_stage": "binary_to_source",
                    "to_stage": "binary_to_source",
                    "reason": "dispatch_startup_window",
                    "created_at": "2026-06-22T19:13:00+00:00",
                    "expires_at": "2099-06-22T19:13:30+00:00",
                }
            },
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="binary_to_source",
            item_key="module1",
            parent_key="module1",
            status="running",
            downstream_service="binary_to_source",
            downstream_task_id="b2s1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item], events=[])

        original_enqueue = manager._enqueue_task
        queued = []
        manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
        try:
            with unittest.mock.patch.object(manager, "_task_runtime_transition_guard_active", return_value=True):
                reclaimed = manager._requeue_orphaned_owned_execution_locked(db)
        finally:
            manager._enqueue_task = original_enqueue

        self.assertFalse(reclaimed)
        self.assertIn(task.status, {"pending", "running"})
        self.assertEqual([], queued)
        requeue_events = [event for event in db.events if event.event_type == "owned_execution_takeover_requeued"]
        self.assertEqual([], requeue_events)

    def test_can_consume_delete_queue_task_blocks_on_active_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "worker-b"
        task = BinarySecurityTask(
            id="task-delete-blocked",
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
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-blocked",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            target_stage=task.current_stage,
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=3),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        decision = manager._can_consume_delete_queue_task(db, task, active_operation=operation)

        self.assertFalse(decision.allowed)
        self.assertEqual("active_runtime_lease", decision.blocker_kind)
        self.assertEqual("active_runtime_lease_blocks_delete_consume", decision.reason_code)

    def test_can_consume_delete_queue_task_allows_stale_dispatcher_without_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "worker-b"
        task = BinarySecurityTask(
            id="task-delete-stale-dispatcher",
            project_id="p1",
            name="source-task",
            status="failed",
            current_stage="knowledge_graph_entry_fetch",
            current_operation_id="op-delete-stale-dispatcher",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/output",
            workspace_root="/workspace",
            dispatcher_instance_id="worker-a",
            dispatch_started_at=_now() - timedelta(minutes=5),
            lease_expires_at=_now() - timedelta(minutes=1),
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-stale-dispatcher",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            target_stage=task.current_stage,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[], events=[])

        normalized = manager._normalize_delete_queue_task_state(db, task, active_operation=operation)
        decision = manager._can_consume_delete_queue_task(db, task, active_operation=operation)

        self.assertTrue(bool(normalized.get("stale_owner_cleared")))
        self.assertTrue(bool(normalized.get("runtime_phase_repaired")))
        self.assertTrue(decision.allowed)
        self.assertEqual("terminal_delete_takeover_without_runtime_lease", decision.reason_code)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)

    def test_consume_delete_queue_task_starts_orphan_delete_without_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-delete-orphan-consume",
            project_id="p1",
            name="source-task",
            status="pending",
            current_stage="system_analysis",
            current_operation_id="op-delete-consume",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/output",
            workspace_root="/workspace",
            dispatcher_instance_id=None,
            dispatch_started_at=None,
            lease_expires_at=None,
            cleanup_snapshot={},
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-consume",
            task_id="task-delete-orphan-consume",
            project_id="p1",
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            target_stage="system_analysis",
            request_payload={},
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[], events=[])

        original_prepare_delete = manager._prepare_delete_task
        calls = []

        async def _fake_prepare_delete(db_session, current_task):
            del db_session
            calls.append(current_task.id)

        manager._prepare_delete_task = _fake_prepare_delete
        try:
            asyncio.run(manager._consume_delete_queue_task(db, task.id))
        finally:
            manager._prepare_delete_task = original_prepare_delete

        self.assertEqual(["task-delete-orphan-consume"], calls)
        self.assertEqual("worker-a", task.dispatcher_instance_id)
        self.assertIsNotNone(task.dispatch_started_at)
        self.assertIsNotNone(task.lease_expires_at)
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_delete_queue_consumption_started", event_types)
        self.assertNotIn("task_delete_queue_consumption_deferred_for_active_blocker", event_types)

    def test_consume_delete_queue_task_starts_terminal_delete_without_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-delete-terminal-consume",
            project_id="p1",
            name="source-task",
            status="failed",
            current_stage="knowledge_graph_entry_fetch",
            current_operation_id="op-delete-terminal-consume",
            runtime_phase=TASK_RUNTIME_PHASE_TERMINAL,
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/output",
            workspace_root="/workspace",
            dispatcher_instance_id=None,
            dispatch_started_at=None,
            lease_expires_at=None,
            cleanup_snapshot={},
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-terminal-consume",
            task_id="task-delete-terminal-consume",
            project_id="p1",
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            target_stage="knowledge_graph_entry_fetch",
            request_payload={},
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[], events=[])

        original_prepare_delete = manager._prepare_delete_task
        calls = []

        async def _fake_prepare_delete(db_session, current_task):
            del db_session
            calls.append(current_task.id)

        manager._prepare_delete_task = _fake_prepare_delete
        try:
            asyncio.run(manager._consume_delete_queue_task(db, task.id))
        finally:
            manager._prepare_delete_task = original_prepare_delete

        self.assertEqual(["task-delete-terminal-consume"], calls)
        self.assertEqual("worker-a", task.dispatcher_instance_id)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_delete_queue_consumption_started", event_types)
        self.assertNotIn("task_delete_queue_consumption_deferred_for_active_blocker", event_types)

    def test_consume_delete_queue_task_clears_stale_dispatcher_before_processing(self):
        manager = TaskManager()
        manager.instance_id = "worker-b"
        task = BinarySecurityTask(
            id="task-delete-terminal-stale-owner-consume",
            project_id="p1",
            name="source-task",
            status="failed",
            current_stage="knowledge_graph_entry_fetch",
            current_operation_id="op-delete-terminal-stale-owner-consume",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/output",
            workspace_root="/workspace",
            dispatcher_instance_id="worker-a",
            dispatch_started_at=_now() - timedelta(minutes=8),
            lease_expires_at=_now() - timedelta(minutes=3),
            cleanup_snapshot={},
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-terminal-stale-owner-consume",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            target_stage="knowledge_graph_entry_fetch",
            request_payload={},
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[], events=[])
        calls = []

        async def _fake_prepare_delete(db_session, current_task):
            del db_session
            calls.append(current_task.id)

        original_prepare_delete = manager._prepare_delete_task
        manager._prepare_delete_task = _fake_prepare_delete
        try:
            asyncio.run(manager._consume_delete_queue_task(db, task.id))
        finally:
            manager._prepare_delete_task = original_prepare_delete

        self.assertEqual(["task-delete-terminal-stale-owner-consume"], calls)
        self.assertEqual("worker-b", task.dispatcher_instance_id)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        normalized_event = next(row for row in db.events if row.event_type == "delete_queue_task_state_normalized")
        self.assertTrue(bool(dict(normalized_event.payload or {}).get("stale_owner_cleared")))
        started_event = next(row for row in db.events if row.event_type == "task_delete_queue_consumption_started")
        self.assertTrue(bool(dict(started_event.payload or {}).get("owner_released_before_delete_consume")))


if __name__ == "__main__":
    unittest.main()
