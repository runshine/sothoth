import asyncio
import unittest
from datetime import timedelta

from app.model import (
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import (
    TASK_ACTION_CONTINUE,
    TASK_ACTION_RETRY,
    TASK_OPERATION_STEP_REQUEUE_TASK,
    TaskManager,
    ValidationError,
    _now,
)
from test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


class TaskOperationFinalizePathTests(unittest.TestCase):
    def test_run_current_task_operation_stops_on_stale_task_ownership(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-stale-operation-owner",
            project_id="p1",
            name="source",
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task], operations=[])
        manager.instance_id = "local-worker"

        def _boom(*args, **kwargs):
            raise task_manager_module.StaleTaskExecution("owner lost")

        original_factory = task_manager_module.get_session_factory
        original_ensure = manager._ensure_task_write_ownership
        task_manager_module.get_session_factory = lambda: (lambda: db)
        manager._ensure_task_write_ownership = _boom
        try:
            result = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._ensure_task_write_ownership = original_ensure

        self.assertFalse(result)

    def test_run_current_task_operation_skips_duplicate_local_operation_worker(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-duplicate-op-worker",
            project_id="p1",
            name="source",
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_vuln_scan",
            current_operation_id="op-duplicate",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        operation = BinarySecurityTaskOperation(
            id="op-duplicate",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="delete",
            status="accepted",
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[])

        original_factory = task_manager_module.get_session_factory
        original_ensure = manager._ensure_task_write_ownership
        original_run_steps = manager._run_task_operation_steps

        async def _should_not_run(_db, _task, _operation):
            raise AssertionError("duplicate local operation worker should skip execution")

        class _ActiveWorker:
            @staticmethod
            def done():
                return False

        duplicate_worker = _ActiveWorker()
        manager._operation_workers[operation.id] = duplicate_worker
        task_manager_module.get_session_factory = lambda: (lambda: db)
        manager._ensure_task_write_ownership = lambda *args, **kwargs: None
        manager._run_task_operation_steps = _should_not_run
        try:
            result = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            manager._operation_workers.clear()
            task_manager_module.get_session_factory = original_factory
            manager._ensure_task_write_ownership = original_ensure
            manager._run_task_operation_steps = original_run_steps

        self.assertFalse(result)
        self.assertEqual("accepted", operation.status)

    def test_run_current_task_operation_treats_delete_as_succeeded_when_task_row_removed(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-delete-row-removed",
            project_id="p1",
            name="source",
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_vuln_scan",
            current_operation_id="op-delete-row-removed",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-row-removed",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="delete",
            status="accepted",
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[])

        original_factory = task_manager_module.get_session_factory
        original_ensure = manager._ensure_task_write_ownership
        original_run_steps = manager._run_task_operation_steps

        async def _delete_task_row(_db, _task, _operation):
            db.delete(task)

        task_manager_module.get_session_factory = lambda: (lambda: db)
        manager._ensure_task_write_ownership = lambda *args, **kwargs: None
        manager._run_task_operation_steps = _delete_task_row
        try:
            result = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._ensure_task_write_ownership = original_ensure
            manager._run_task_operation_steps = original_run_steps

        self.assertTrue(result)
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
        self.assertIsNotNone(operation.finished_at)

    def test_run_current_task_operation_finalizes_orphan_delete_operation_when_task_row_missing_at_start(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        operation = BinarySecurityTaskOperation(
            id="op-delete-orphan-start",
            task_id="task-delete-orphan-start",
            project_id="p1",
            operation_type="delete",
            status="running",
            current_step="operation_succeeded",
        )
        db = _ModelAwareDb(tasks=[], operations=[operation], events=[])

        original_factory = task_manager_module.get_session_factory
        task_manager_module.get_session_factory = lambda: (lambda: db)
        try:
            result = asyncio.run(manager._run_current_task_operation(operation.task_id))
        finally:
            task_manager_module.get_session_factory = original_factory

        self.assertFalse(result)
        self.assertEqual("running", operation.status)
        self.assertEqual("operation_succeeded", operation.current_step)
        self.assertIsNone(operation.finished_at)

    def test_run_current_task_operation_finalizes_after_requeue_owner_handoff(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-stale-operation-finalize",
            project_id="p1",
            name="source",
            status="pending",
            runtime_phase=TASK_RUNTIME_PHASE_TERMINAL,
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            current_operation_id="op-requeue",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        operation = BinarySecurityTaskOperation(
            id="op-requeue",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            target_stage="system_analysis",
            status="running",
            current_step=TASK_OPERATION_STEP_REQUEUE_TASK,
            result_payload={
                "requeue": {
                    "requested": True,
                    "applied": True,
                    "current_stage_after": "system_analysis",
                    "task_status_after": "pending",
                    "runtime_phase_after": TASK_RUNTIME_PHASE_TERMINAL,
                    "in_place_runtime_resume": False,
                }
            },
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[])

        original_factory = task_manager_module.get_session_factory
        original_ensure = manager._ensure_task_write_ownership
        original_run_steps = manager._run_task_operation_steps
        call_count = {"value": 0}

        def _ensure(*args, **kwargs):
            del args, kwargs
            call_count["value"] += 1
            if call_count["value"] >= 2:
                raise task_manager_module.StaleTaskExecution("owner handed off after requeue")
            return None

        async def _no_op_run_steps(_db, _task, _operation):
            return None

        task_manager_module.get_session_factory = lambda: (lambda: db)
        manager._ensure_task_write_ownership = _ensure
        manager._run_task_operation_steps = _no_op_run_steps
        try:
            result = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._ensure_task_write_ownership = original_ensure
            manager._run_task_operation_steps = original_run_steps

        self.assertTrue(result)
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
        self.assertIsNone(task.current_operation_id)
        event_types = [event.event_type for event in db.events]
        self.assertIn("operation_finalize_after_owner_handoff", event_types)
        self.assertIn("operation_succeeded", event_types)

    def test_run_current_task_operation_finalizes_after_requeue_owner_handoff_for_retry_family(self):
        operation_types = [
            TASK_ACTION_CONTINUE,
            TASK_ACTION_RETRY,
            "retry_failed_items",
            "retry_stage_full",
            "retry_stage_failed_items",
            "retry_archive_failed_items",
            "retry_archive_full",
        ]
        for operation_type in operation_types:
            with self.subTest(operation_type=operation_type):
                manager = TaskManager()
                manager.instance_id = "local-worker"
                task = BinarySecurityTask(
                    id=f"task-handoff-{operation_type}",
                    project_id="p1",
                    name="source",
                    status="pending",
                    runtime_phase=TASK_RUNTIME_PHASE_TERMINAL,
                    task_type=TASK_TYPE_SOURCE,
                    current_stage="system_analysis",
                    current_operation_id=f"op-{operation_type}",
                    firmware_source="project_filesystem",
                    firmware_path="/src",
                    output_root="/o",
                    workspace_root="/w",
                )
                operation = BinarySecurityTaskOperation(
                    id=f"op-{operation_type}",
                    task_id=task.id,
                    project_id=task.project_id,
                    operation_type=operation_type,
                    target_stage="system_analysis",
                    status="running",
                    current_step=TASK_OPERATION_STEP_REQUEUE_TASK,
                    result_payload={
                        "requeue": {
                            "requested": True,
                            "applied": True,
                            "current_stage_after": "system_analysis",
                            "task_status_after": "pending",
                            "runtime_phase_after": TASK_RUNTIME_PHASE_TERMINAL,
                            "in_place_runtime_resume": False,
                        }
                    },
                )
                db = _ModelAwareDb(tasks=[task], operations=[operation], events=[])

                original_factory = task_manager_module.get_session_factory
                original_ensure = manager._ensure_task_write_ownership
                original_run_steps = manager._run_task_operation_steps
                call_count = {"value": 0}

                def _ensure(*args, **kwargs):
                    del args, kwargs
                    call_count["value"] += 1
                    if call_count["value"] >= 2:
                        raise task_manager_module.StaleTaskExecution("owner handed off after requeue")
                    return None

                async def _no_op_run_steps(_db, _task, _operation):
                    return None

                task_manager_module.get_session_factory = lambda: (lambda: db)
                manager._ensure_task_write_ownership = _ensure
                manager._run_task_operation_steps = _no_op_run_steps
                try:
                    result = asyncio.run(manager._run_current_task_operation(task.id))
                finally:
                    task_manager_module.get_session_factory = original_factory
                    manager._ensure_task_write_ownership = original_ensure
                    manager._run_task_operation_steps = original_run_steps

                self.assertTrue(result)
                self.assertEqual("succeeded", operation.status)
                self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
                self.assertIsNone(task.current_operation_id)

    def test_run_current_task_operation_cancel_success_repairs_reopened_running_task(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-cancel-repair",
            project_id="p1",
            name="source",
            status="running",
            current_stage="dataflow_vuln_scan",
            current_operation_id="op-cancel-repair",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        operation = BinarySecurityTaskOperation(
            id="op-cancel-repair",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage="dataflow_vuln_scan",
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_FINALIZE_TASK_CANCELLED,
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])
        original_factory = task_manager_module.get_session_factory
        original_runner = manager._run_task_operation_steps
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _fake_run_task_operation_steps(_db, current_task, current_operation):
                current_task.status = "running"
                current_task.current_operation_id = current_operation.id
                current_task.finished_at = _now()
                return None

            manager._run_task_operation_steps = _fake_run_task_operation_steps
            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._run_task_operation_steps = original_runner

        self.assertTrue(changed)
        self.assertEqual("cancelled", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)

    def test_run_current_task_operation_cancel_terminal_finalize_is_atomic(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-cancel-atomic",
            project_id="p1",
            name="source",
            status="cancelling",
            current_stage="dataflow_vuln_scan",
            current_operation_id="op-cancel-atomic",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        operation = BinarySecurityTaskOperation(
            id="op-cancel-atomic",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage="dataflow_vuln_scan",
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[], events=[])
        original_factory = task_manager_module.get_session_factory
        original_prepare_cancel = manager._prepare_cancel_task
        original_write_metadata = manager._write_task_metadata_async
        original_ensure = manager._ensure_task_write_ownership
        original_owner_match = manager._task_runtime_owner_matches_current_instance
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _fake_prepare_cancel_task(_db, _task):
                return []

            async def _noop_write(*_args, **_kwargs):
                return None

            manager._prepare_cancel_task = _fake_prepare_cancel_task
            manager._write_task_metadata_async = _noop_write
            manager._ensure_task_write_ownership = lambda *args, **kwargs: None
            manager._task_runtime_owner_matches_current_instance = lambda *_args, **_kwargs: True
            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._prepare_cancel_task = original_prepare_cancel
            manager._write_task_metadata_async = original_write_metadata
            manager._ensure_task_write_ownership = original_ensure
            manager._task_runtime_owner_matches_current_instance = original_owner_match

        self.assertTrue(changed)
        self.assertEqual("cancelled", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
        event_types = [event.event_type for event in db.events]
        self.assertIn("control_operation_terminal_finalize_started", event_types)
        self.assertIn("control_operation_terminal_finalize_committed", event_types)

    def test_run_current_task_operation_returns_after_atomic_terminal_finalize_without_post_tail_ownership_check(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-cancel-atomic-tail",
            project_id="p1",
            name="source",
            status="cancelling",
            current_stage="dataflow_vuln_scan",
            current_operation_id="op-cancel-atomic-tail",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        operation = BinarySecurityTaskOperation(
            id="op-cancel-atomic-tail",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage="dataflow_vuln_scan",
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_FINALIZE_TASK_CANCELLED,
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[], events=[])
        original_factory = task_manager_module.get_session_factory
        original_runner = manager._run_task_operation_steps
        original_ensure = manager._ensure_task_write_ownership
        ensure_calls: list[str] = []
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _fake_run_task_operation_steps(_db, current_task, current_operation):
                current_task.status = "cancelled"
                current_task.runtime_phase = TASK_RUNTIME_PHASE_TERMINAL
                current_task.current_operation_id = None
                current_operation.status = "succeeded"
                current_operation.current_step = task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
                current_operation.finished_at = _now()
                return {"operation_finalized": True, "task_status": "cancelled"}

            def _fake_ensure_task_write_ownership(*args, **kwargs):
                del args, kwargs
                ensure_calls.append("called")
                if len(ensure_calls) > 1:
                    raise AssertionError("post-finalize ownership check should not run")

            manager._run_task_operation_steps = _fake_run_task_operation_steps
            manager._ensure_task_write_ownership = _fake_ensure_task_write_ownership
            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._run_task_operation_steps = original_runner
            manager._ensure_task_write_ownership = original_ensure

        self.assertTrue(changed)
        self.assertEqual(["called"], ensure_calls)
        self.assertEqual("cancelled", task.status)
        self.assertIsNone(task.current_operation_id)

    def test_run_current_task_operation_preserves_cancel_binding_when_terminal_finalize_stales_before_commit(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-cancel-stale-before-commit",
            project_id="p1",
            name="source",
            status="cancelling",
            current_stage="dataflow_vuln_scan",
            current_operation_id="op-cancel-stale-before-commit",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        operation = BinarySecurityTaskOperation(
            id="op-cancel-stale-before-commit",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage="dataflow_vuln_scan",
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_FINALIZE_TASK_CANCELLED,
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[], events=[])
        original_factory = task_manager_module.get_session_factory
        original_runner = manager._run_task_operation_steps
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _fake_run_task_operation_steps(_db, current_task, current_operation):
                current_task.status = "cancelling"
                current_task.current_operation_id = current_operation.id
                raise task_manager_module.StaleTaskExecution("ownership changed before terminal commit")

            manager._run_task_operation_steps = _fake_run_task_operation_steps
            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._run_task_operation_steps = original_runner

        self.assertFalse(changed)
        self.assertEqual("cancelling", task.status)
        self.assertEqual(operation.id, task.current_operation_id)
        self.assertEqual("running", operation.status)

    def test_run_current_task_operation_preserves_cancel_operation_when_quiesce_retry_pending(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-cancel-retry-pending",
            project_id="p1",
            name="source",
            status="cancelling",
            current_stage="entry_analysis",
            current_operation_id="op-cancel-retry",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        operation = BinarySecurityTaskOperation(
            id="op-cancel-retry",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage="entry_analysis",
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])
        original_factory = task_manager_module.get_session_factory
        original_runner = manager._run_task_operation_steps
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _fake_run_task_operation_steps(_db, current_task, current_operation):
                current_task.status = "cancelling"
                current_task.current_operation_id = current_operation.id
                return {"operation_incomplete": True, "result": "retry"}

            manager._run_task_operation_steps = _fake_run_task_operation_steps
            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._run_task_operation_steps = original_runner

        self.assertFalse(changed)
        self.assertEqual("cancelling", task.status)
        self.assertEqual(operation.id, task.current_operation_id)
        self.assertEqual("running", operation.status)
        self.assertIsNone(operation.finished_at)

    def test_run_current_task_operation_finalizes_requeue_applied_operation_inline(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-inline-requeue-finalize",
            project_id="p1",
            name="source",
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            current_operation_id="op-inline-requeue",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        operation = BinarySecurityTaskOperation(
            id="op-inline-requeue",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="system_analysis",
            status="running",
            current_step=TASK_OPERATION_STEP_REQUEUE_TASK,
            result_payload={
                "requeue": {
                    "requested": True,
                    "applied": True,
                    "current_stage_after": "system_analysis",
                    "task_status_after": "pending",
                    "runtime_phase_after": TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    "in_place_runtime_resume": False,
                }
            },
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="local-worker",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        original_factory = task_manager_module.get_session_factory
        original_run_steps = manager._run_task_operation_steps

        async def _no_op_run_steps(_db, _task, _operation):
            _task.status = "pending"
            return None

        task_manager_module.get_session_factory = lambda: (lambda: db)
        manager._run_task_operation_steps = _no_op_run_steps
        try:
            result = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._run_task_operation_steps = original_run_steps

        self.assertTrue(result)
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
        self.assertIsNone(task.current_operation_id)
        event_types = [event.event_type for event in db.events]
        self.assertIn("operation_finalize_after_requeue", event_types)
        self.assertIn("operation_succeeded", event_types)

    def test_run_current_task_operation_restores_preaccept_snapshot_on_retry_failure(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-retry-failure-restore",
            project_id="p1",
            name="source",
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            current_operation_id="op-retry-failure",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-failure",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry",
            target_stage="firmware_unpack",
            status="accepted",
            request_payload={
                "target_stage": "firmware_unpack",
                "task_state_snapshot": {
                    "status": "failed",
                    "current_stage": "entry_analysis",
                    "runtime_phase": TASK_RUNTIME_PHASE_TERMINAL,
                    "last_error": "old failure",
                    "execution_mode": None,
                    "target_stage_name": None,
                },
            },
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="local-worker",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[runtime_lease], events=[])

        original_factory = task_manager_module.get_session_factory
        original_run_steps = manager._run_task_operation_steps

        async def _boom(_db, _task, _operation):
            raise ValidationError("cleanup verify failed")

        task_manager_module.get_session_factory = lambda: (lambda: db)
        manager._run_task_operation_steps = _boom
        try:
            result = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._run_task_operation_steps = original_run_steps

        self.assertTrue(result)
        self.assertEqual("failed", operation.status)
        self.assertIsNone(task.current_operation_id)
        self.assertEqual("failed", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        event_types = [event.event_type for event in db.events]
        self.assertIn("operation_failed", event_types)
