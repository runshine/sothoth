import asyncio
import unittest

from app.model import (
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _ModelAwareDb


def _source_task(*, task_id: str, operation_id: str, status: str) -> BinarySecurityTask:
    task = BinarySecurityTask(
        id=task_id,
        project_id="project-1",
        name=f"task-{task_id}",
        status=status,
        task_type=TASK_TYPE_SOURCE,
        current_stage="dataflow_vuln_scan",
        current_operation_id=operation_id,
        firmware_source="project_filesystem",
        firmware_path="/tmp/source-project",
        output_root="/tmp/out",
        workspace_root="/tmp/ws",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        dispatcher_instance_id="worker-a",
    )
    task.dispatch_started_at = _now()
    task.lease_expires_at = _now()
    return task


def _binary_module_task(*, task_id: str, operation_id: str, status: str) -> BinarySecurityTask:
    task = BinarySecurityTask(
        id=task_id,
        project_id="project-1",
        name=f"task-{task_id}",
        status=status,
        task_type=TASK_TYPE_BINARY_MODULE,
        current_stage="entry_analysis",
        current_operation_id=operation_id,
        firmware_source="project_filesystem",
        firmware_path="/tmp/module-input/IPSEC.bin",
        output_root="/tmp/out",
        workspace_root="/tmp/ws",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        dispatcher_instance_id="worker-a",
    )
    task.dispatch_started_at = _now()
    task.lease_expires_at = _now()
    task.summary = {
        "b2s_results": [
            {
                "module_key": "IPSEC",
                "module_name": "IPSEC",
                "firmware_key": "module-input",
                "source_dir": "/mock/b2s/IPSEC",
                "source_root": "/mock/b2s/IPSEC",
                "source_root_path": "/mock/b2s/IPSEC",
                "module_dir": "/mock/b2s/IPSEC",
                "entry_files_list": "/mock/b2s/IPSEC/files.list",
                "task_type": TASK_TYPE_BINARY_MODULE,
            }
        ]
    }
    return task


class ControlOperationTerminalE2ETests(unittest.TestCase):
    def test_cancel_owner_handoff_e2e(self):
        task = _source_task(task_id="task-cancel-handoff", operation_id="op-cancel-handoff", status="cancelling")
        operation = BinarySecurityTaskOperation(
            id="op-cancel-handoff",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage=task.current_stage,
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[], runtime_leases=[])

        manager_a = TaskManager()
        manager_a.instance_id = "worker-a"
        manager_b = TaskManager()
        manager_b.instance_id = "worker-b"

        original_factory = task_manager_module.get_session_factory
        original_runner_a = manager_a._run_task_operation_steps
        original_runner_b = manager_b._run_task_operation_steps
        original_prepare_cancel_b = manager_b._prepare_cancel_task
        original_write_metadata_b = manager_b._write_task_metadata_async
        original_ensure_a = manager_a._ensure_task_write_ownership
        original_ensure_b = manager_b._ensure_task_write_ownership
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _stale_before_finalize(_db, current_task, current_operation):
                current_task.status = "cancelling"
                current_task.current_operation_id = current_operation.id
                raise task_manager_module.StaleTaskExecution("owner handoff before finalize")

            async def _noop_prepare_cancel(_db, _task):
                return []

            async def _noop_write(*_args, **_kwargs):
                return None

            async def _atomic_finalize_on_takeover(_db, current_task, current_operation):
                current_task.status = "cancelled"
                current_task.runtime_phase = TASK_RUNTIME_PHASE_TERMINAL
                current_task.current_operation_id = None
                current_task.dispatcher_instance_id = None
                current_operation.status = "succeeded"
                current_operation.current_step = task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
                return {"operation_finalized": True, "task_status": "cancelled"}

            manager_a._ensure_task_write_ownership = lambda *args, **kwargs: None
            manager_b._ensure_task_write_ownership = lambda *args, **kwargs: None
            manager_a._run_task_operation_steps = _stale_before_finalize
            first_changed = asyncio.run(manager_a._run_current_task_operation(task.id))
            self.assertFalse(first_changed)
            self.assertEqual("cancelling", task.status)
            self.assertEqual(operation.id, task.current_operation_id)

            task.dispatcher_instance_id = "worker-b"
            task.lease_expires_at = _now()
            manager_b._prepare_cancel_task = _noop_prepare_cancel
            manager_b._write_task_metadata_async = _noop_write
            manager_b._run_task_operation_steps = _atomic_finalize_on_takeover
            second_changed = asyncio.run(manager_b._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager_a._run_task_operation_steps = original_runner_a
            manager_b._run_task_operation_steps = original_runner_b
            manager_b._prepare_cancel_task = original_prepare_cancel_b
            manager_b._write_task_metadata_async = original_write_metadata_b
            manager_a._ensure_task_write_ownership = original_ensure_a
            manager_b._ensure_task_write_ownership = original_ensure_b

        self.assertTrue(second_changed)
        self.assertEqual("cancelled", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertEqual("succeeded", operation.status)
        self.assertFalse(any(str(getattr(row, "current_operation_id", "") or "").strip() for row in db.tasks if row.id == task.id))

    def test_binary_module_cancel_owner_handoff_e2e(self):
        task = _binary_module_task(
            task_id="task-binary-module-cancel-handoff",
            operation_id="op-binary-module-cancel-handoff",
            status="cancelling",
        )
        operation = BinarySecurityTaskOperation(
            id="op-binary-module-cancel-handoff",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage=task.current_stage,
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[], runtime_leases=[])

        manager_a = TaskManager()
        manager_a.instance_id = "worker-a"
        manager_b = TaskManager()
        manager_b.instance_id = "worker-b"

        original_factory = task_manager_module.get_session_factory
        original_runner_a = manager_a._run_task_operation_steps
        original_runner_b = manager_b._run_task_operation_steps
        original_prepare_cancel_b = manager_b._prepare_cancel_task
        original_write_metadata_b = manager_b._write_task_metadata_async
        original_ensure_a = manager_a._ensure_task_write_ownership
        original_ensure_b = manager_b._ensure_task_write_ownership
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _stale_before_finalize(_db, current_task, current_operation):
                current_task.status = "cancelling"
                current_task.current_operation_id = current_operation.id
                raise task_manager_module.StaleTaskExecution("binary-module owner handoff before finalize")

            async def _noop_prepare_cancel(_db, _task):
                return []

            async def _noop_write(*_args, **_kwargs):
                return None

            async def _atomic_finalize_on_takeover(_db, current_task, current_operation):
                current_task.status = "cancelled"
                current_task.runtime_phase = TASK_RUNTIME_PHASE_TERMINAL
                current_task.current_operation_id = None
                current_task.dispatcher_instance_id = None
                current_operation.status = "succeeded"
                current_operation.current_step = task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
                return {"operation_finalized": True, "task_status": "cancelled"}

            manager_a._ensure_task_write_ownership = lambda *args, **kwargs: None
            manager_b._ensure_task_write_ownership = lambda *args, **kwargs: None
            manager_a._run_task_operation_steps = _stale_before_finalize
            first_changed = asyncio.run(manager_a._run_current_task_operation(task.id))
            self.assertFalse(first_changed)
            self.assertEqual("cancelling", task.status)
            self.assertEqual(operation.id, task.current_operation_id)

            task.dispatcher_instance_id = "worker-b"
            task.lease_expires_at = _now()
            manager_b._prepare_cancel_task = _noop_prepare_cancel
            manager_b._write_task_metadata_async = _noop_write
            manager_b._run_task_operation_steps = _atomic_finalize_on_takeover
            second_changed = asyncio.run(manager_b._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager_a._run_task_operation_steps = original_runner_a
            manager_b._run_task_operation_steps = original_runner_b
            manager_b._prepare_cancel_task = original_prepare_cancel_b
            manager_b._write_task_metadata_async = original_write_metadata_b
            manager_a._ensure_task_write_ownership = original_ensure_a
            manager_b._ensure_task_write_ownership = original_ensure_b

        self.assertTrue(second_changed)
        self.assertEqual("cancelled", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertEqual("succeeded", operation.status)
        self.assertTrue((task.summary or {}).get("b2s_results"))
        self.assertFalse(any(str(getattr(row, "current_operation_id", "") or "").strip() for row in db.tasks if row.id == task.id))

    def test_delete_force_delete_fallback_e2e(self):
        task = _source_task(task_id="task-delete-fallback", operation_id="op-delete-fallback", status="running")
        operation = BinarySecurityTaskOperation(
            id="op-delete-fallback",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            target_stage=task.current_stage,
            status="queued",
            request_payload={"force": False, "force_delete": False},
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[], runtime_leases=[])
        manager = TaskManager()
        manager.instance_id = "worker-a"

        original_factory = task_manager_module.get_session_factory
        original_wait = manager._wait_for_task_workspace_quiesce
        original_cleanup = manager._cleanup_task_workspace
        original_archive_cleanup = manager._delete_archive_children_for_stages
        original_stage_item_cleanup = manager._delete_stage_items_for_stages
        original_stage_run_cleanup = manager._delete_stage_run_rows
        original_state_event_cleanup = manager._delete_task_state_event_rows
        original_release_runtime = manager._release_task_delete_runtime_state
        original_cancel_local = manager._request_local_worker_cancel
        original_ensure = manager._ensure_task_write_ownership
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _wait_true(_db, _task):
                return True

            async def _cleanup_force_fallback(_task, *, token=None):
                del token
                return "recreated_during_delete"

            async def _cancel_local(*_args, **_kwargs):
                return None

            manager._wait_for_task_workspace_quiesce = _wait_true
            manager._cleanup_task_workspace = _cleanup_force_fallback
            manager._delete_archive_children_for_stages = lambda *_args, **_kwargs: 0
            manager._delete_stage_items_for_stages = lambda *_args, **_kwargs: 0
            manager._delete_stage_run_rows = lambda *_args, **_kwargs: 0
            manager._delete_task_state_event_rows = lambda *_args, **_kwargs: 0
            manager._release_task_delete_runtime_state = lambda *_args, **_kwargs: None
            manager._request_local_worker_cancel = _cancel_local
            manager._ensure_task_write_ownership = lambda *args, **kwargs: None

            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._wait_for_task_workspace_quiesce = original_wait
            manager._cleanup_task_workspace = original_cleanup
            manager._delete_archive_children_for_stages = original_archive_cleanup
            manager._delete_stage_items_for_stages = original_stage_item_cleanup
            manager._delete_stage_run_rows = original_stage_run_cleanup
            manager._delete_task_state_event_rows = original_state_event_cleanup
            manager._release_task_delete_runtime_state = original_release_runtime
            manager._request_local_worker_cancel = original_cancel_local
            manager._ensure_task_write_ownership = original_ensure

        self.assertTrue(changed)
        self.assertFalse(any(row.id == task.id for row in db.tasks))
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
        self.assertTrue(bool(dict(operation.request_payload or {}).get("force_delete")))
        self.assertTrue(bool(dict(operation.request_payload or {}).get("auto_force_delete_fallback")))
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_delete_auto_force_delete_fallback", event_types)
        self.assertIn("control_operation_terminal_finalize_committed", event_types)

    def test_binary_module_delete_force_delete_fallback_e2e(self):
        task = _binary_module_task(
            task_id="task-binary-module-delete-fallback",
            operation_id="op-binary-module-delete-fallback",
            status="running",
        )
        operation = BinarySecurityTaskOperation(
            id="op-binary-module-delete-fallback",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            target_stage=task.current_stage,
            status="queued",
            request_payload={"force": False, "force_delete": False},
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[], runtime_leases=[])
        manager = TaskManager()
        manager.instance_id = "worker-a"

        original_factory = task_manager_module.get_session_factory
        original_wait = manager._wait_for_task_workspace_quiesce
        original_cleanup = manager._cleanup_task_workspace
        original_archive_cleanup = manager._delete_archive_children_for_stages
        original_stage_item_cleanup = manager._delete_stage_items_for_stages
        original_stage_run_cleanup = manager._delete_stage_run_rows
        original_state_event_cleanup = manager._delete_task_state_event_rows
        original_release_runtime = manager._release_task_delete_runtime_state
        original_cancel_local = manager._request_local_worker_cancel
        original_ensure = manager._ensure_task_write_ownership
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _wait_true(_db, _task):
                return True

            async def _cleanup_force_fallback(_task, *, token=None):
                del token
                return "recreated_during_delete"

            async def _cancel_local(*_args, **_kwargs):
                return None

            manager._wait_for_task_workspace_quiesce = _wait_true
            manager._cleanup_task_workspace = _cleanup_force_fallback
            manager._delete_archive_children_for_stages = lambda *_args, **_kwargs: 0
            manager._delete_stage_items_for_stages = lambda *_args, **_kwargs: 0
            manager._delete_stage_run_rows = lambda *_args, **_kwargs: 0
            manager._delete_task_state_event_rows = lambda *_args, **_kwargs: 0
            manager._release_task_delete_runtime_state = lambda *_args, **_kwargs: None
            manager._request_local_worker_cancel = _cancel_local
            manager._ensure_task_write_ownership = lambda *args, **kwargs: None

            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._wait_for_task_workspace_quiesce = original_wait
            manager._cleanup_task_workspace = original_cleanup
            manager._delete_archive_children_for_stages = original_archive_cleanup
            manager._delete_stage_items_for_stages = original_stage_item_cleanup
            manager._delete_stage_run_rows = original_stage_run_cleanup
            manager._delete_task_state_event_rows = original_state_event_cleanup
            manager._release_task_delete_runtime_state = original_release_runtime
            manager._request_local_worker_cancel = original_cancel_local
            manager._ensure_task_write_ownership = original_ensure

        self.assertTrue(changed)
        self.assertFalse(any(row.id == task.id for row in db.tasks))
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
        self.assertTrue(bool(dict(operation.request_payload or {}).get("force_delete")))
        self.assertTrue(bool(dict(operation.request_payload or {}).get("auto_force_delete_fallback")))
        self.assertTrue((task.summary or {}).get("b2s_results"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_delete_auto_force_delete_fallback", event_types)
        self.assertIn("control_operation_terminal_finalize_committed", event_types)


if __name__ == "__main__":
    unittest.main()
