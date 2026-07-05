import unittest
from datetime import timedelta

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


class ParentRuntimeReadModelTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_task_row_owner_runtime_supported_keeps_remote_owner_when_active_runtime_lease_matches_for_archive_retry(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        now_value = _now()
        task = BinarySecurityTask(
            id="task-remote-archive-retry",
            project_id="p1",
            name="source",
            status="dispatching",
            task_type=TASK_TYPE_SOURCE,
            current_stage="firmware_unpack",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="remote-worker",
            current_operation_id="op-remote-archive-retry",
            lease_expires_at=now_value + timedelta(seconds=120),
        )
        operation = BinarySecurityTaskOperation(
            id="op-remote-archive-retry",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_archive_full",
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

        supported = manager._task_row_owner_is_runtime_supported(db, task, active_operation=operation)

        self.assertTrue(supported)
        self.assertEqual("remote-worker", task.dispatcher_instance_id)

    def test_task_has_supported_control_operation_runtime_uses_runtime_lease_for_archive_retry(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        now_value = _now()
        task = BinarySecurityTask(
            id="task-local-archive-retry-lease",
            project_id="p1",
            name="source",
            status="dispatching",
            task_type=TASK_TYPE_SOURCE,
            current_stage="firmware_unpack",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="local-worker",
            current_operation_id="op-local-archive-retry",
            lease_expires_at=now_value + timedelta(seconds=120),
        )
        operation = BinarySecurityTaskOperation(
            id="op-local-archive-retry",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_archive_failed_items",
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_REQUEUE_TASK,
            updated_at=now_value,
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=1,
            owner_instance_id="local-worker",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(seconds=120),
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], runtime_leases=[lease])

        supported = manager._task_has_supported_control_operation_runtime(
            db,
            task,
            active_operation=operation,
        )

        self.assertTrue(supported)

    def test_task_row_owner_runtime_supported_rejects_stale_owner_without_runtime_lease_outside_running_status(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-cancel-owner-stale",
            project_id="p1",
            name="source",
            status=task_manager_module.TASK_STATUS_CANCELLING,
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="remote-worker",
            dispatch_started_at=_now() - timedelta(minutes=5),
            lease_expires_at=_now() - timedelta(minutes=4),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[])

        supported = manager._task_row_owner_is_runtime_supported(db, task)

        self.assertFalse(supported)

    def test_task_row_owner_runtime_supported_rejects_running_task_without_owner_lease_or_local_handle(self):
        manager = TaskManager()
        manager.instance_id = "local-worker"
        task = BinarySecurityTask(
            id="task-running-no-owner-no-lease",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id=None,
            dispatch_started_at=None,
            lease_expires_at=None,
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[])

        supported = manager._task_row_owner_is_runtime_supported(db, task)

        self.assertFalse(supported)

    def test_should_skip_readless_reconcile_for_active_task_uses_runtime_lease_without_status_gate(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-readless-active",
            project_id="p1",
            name="source",
            status=task_manager_module.TASK_STATUS_CANCELLING,
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="remote-worker",
            lease_expires_at=_now() + timedelta(minutes=2),
        )

        original_lease_is_active = manager._lease_is_active
        try:
            manager._lease_is_active = lambda _task, db=None: True
            supported = manager._should_skip_readless_reconcile_for_active_task(task)
        finally:
            manager._lease_is_active = original_lease_is_active

        self.assertTrue(supported)

    def test_should_preserve_task_dispatch_ownership_uses_runtime_lease_without_status_gate(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-preserve-owner",
            project_id="p1",
            name="source",
            status=task_manager_module.TASK_STATUS_CANCELLING,
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="remote-worker",
            lease_expires_at=_now() + timedelta(minutes=2),
        )

        original_lease_is_active = manager._lease_is_active
        try:
            manager._lease_is_active = lambda _task, db=None: True
            supported = manager._should_preserve_task_dispatch_ownership(
                task,
                previous_status=task_manager_module.TASK_STATUS_CANCELLING,
                db=None,
            )
        finally:
            manager._lease_is_active = original_lease_is_active

        self.assertTrue(supported)

    def test_task_list_response_exposes_runtime_lease_and_sync_view(self):
        manager = TaskManager()
        now_value = _now()
        task = BinarySecurityTask(
            id="task-4",
            project_id="p1",
            name="demo",
            status="running",
            firmware_path="/tmp/fw.bin",
            dispatcher_instance_id="legacy-owner",
            lease_expires_at=now_value + timedelta(seconds=10),
        )
        item = BinarySecurityStageItem(
            id="si-1",
            task_id="task-4",
            project_id="p1",
            stage_run_id="sr-1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            result={
                "downstream_status_synced_at": now_value.isoformat(),
                "sync_observation": {
                    "last_synced_at": now_value.isoformat(),
                    "error_type": "timeout",
                    "error_message": "temporary timeout",
                },
            },
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id="task-4",
            execution_epoch=0,
            owner_instance_id="runtime-owner",
            heartbeat_at=now_value,
            lease_expires_at=now_value + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], runtime_leases=[lease])

        response = manager._task_list_response(db, task, stage_items=[item])

        self.assertEqual("runtime-owner", response.task_lease_owner_instance_id)
        self.assertEqual(lease.lease_expires_at, response.task_lease_expires_at)
        self.assertEqual("runtime_lease", response.task_lease_source)
        self.assertEqual(now_value, response.last_successful_downstream_sync_at)
        self.assertEqual(now_value, response.last_sync_attempt_at)
        self.assertEqual("timeout", response.last_sync_error_type)
        self.assertEqual("temporary timeout", response.last_sync_error_message)

    def test_task_list_response_does_not_expose_legacy_task_row_as_runtime_lease(self):
        manager = TaskManager()
        now_value = _now()
        task = BinarySecurityTask(
            id="task-lease-row-only",
            project_id="p1",
            name="demo",
            status="running",
            firmware_path="/tmp/fw.bin",
            dispatcher_instance_id="row-owner-only",
            lease_expires_at=now_value + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[], runtime_leases=[])

        response = manager._task_list_response(db, task, stage_items=[])

        self.assertIsNone(response.task_lease_owner_instance_id)
        self.assertIsNone(response.task_lease_expires_at)
        self.assertIsNone(response.task_lease_source)


if __name__ == "__main__":
    unittest.main()
