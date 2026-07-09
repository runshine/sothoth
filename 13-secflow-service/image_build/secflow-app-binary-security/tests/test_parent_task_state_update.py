import unittest
from datetime import timedelta
from unittest.mock import patch

from app.model import (
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TASK_ACTION_CONTINUE, TASK_ACTION_RETRY, TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


class ParentTaskStateUpdateTests(unittest.TestCase):
    def test_control_operation_runtime_lease_coverage_matches_supported_operation_set(self):
        expected_control_operations = {
            TASK_ACTION_CONTINUE,
            TASK_ACTION_RETRY,
            task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
            task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
            task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
            task_manager_module.TASK_ACTION_CANCEL,
            task_manager_module.TASK_ACTION_DELETE,
            task_manager_module.TASK_ACTION_FINISH_SUCCESS,
            task_manager_module.TASK_ACTION_CLEAR_DATAFLOW_STAGE_ITEMS,
            "force_reset_to_pending",
        }

        self.assertSetEqual(
            expected_control_operations,
            set(task_manager_module.TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES),
        )
        self.assertTrue(
            set(task_manager_module.TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES).issubset(
                set(task_manager_module.TASK_OPERATION_OWNER_GUARDED_TYPES)
            )
        )

    def test_apply_task_main_state_update_records_parent_task_state_transition_for_status_stage_and_runtime_owner(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        now_value = _now()
        task = BinarySecurityTask(
            id="task-parent-transition",
            project_id="p1",
            name="demo",
            status="pending",
            current_stage="system_analysis",
            runtime_phase="queued",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(
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

        updated = manager._apply_task_main_state_update(
            db,
            task,
            source="runtime_worker",
            reason="unit_test_parent_transition",
            status="running",
            stage_name="entry_analysis",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )

        self.assertTrue(updated)
        transition_events = [event for event in db.events if event.event_type == "parent_task_state_transition"]
        self.assertEqual(1, len(transition_events))
        payload = transition_events[0].payload or {}
        self.assertEqual("unit_test_parent_transition", payload.get("reason"))
        self.assertEqual("runtime_worker", payload.get("source"))
        self.assertEqual(
            ["status", "current_stage", "runtime_phase"],
            payload.get("changed_fields"),
        )
        self.assertEqual({"status": "pending", "current_stage": "system_analysis", "runtime_phase": "queued"}, payload.get("before"))
        self.assertEqual(
            {"status": "running", "current_stage": "entry_analysis", "runtime_phase": TASK_RUNTIME_PHASE_OWNED_EXECUTION},
            payload.get("after"),
        )
        self.assertTrue(any(event.event_type == "task_status_changed" for event in db.events))

    def test_apply_task_main_state_update_records_parent_task_state_transition_when_runtime_owner_is_cleared(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        now_value = _now()
        task = BinarySecurityTask(
            id="task-parent-owner-clear",
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
        )
        db = _ModelAwareDb(
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

        updated = manager._apply_task_main_state_update(
            db,
            task,
            source="runtime_worker",
            reason="unit_test_clear_owner",
            clear_runtime_owner=True,
        )

        self.assertTrue(updated)
        self.assertEqual("worker-a", db.runtime_leases[0].owner_instance_id)
        suppress_events = [
            event
            for event in db.events
            if event.event_type == "runtime_owner_clear_suppressed_for_running_owned"
        ]
        self.assertEqual(1, len(suppress_events))

    def test_apply_task_main_state_update_allows_pending_for_lease_loss_requeue(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-lease-loss-requeue",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        db = _AppendingModelAwareDb(tasks=[task], events=[])

        with patch.object(manager, "_task_runtime_owner_matches_current_instance", return_value=True), patch.object(
            manager,
            "_running_task_has_valid_runtime_ownership",
            return_value=False,
        ), patch.object(
            manager,
            "_task_runtime_transition_guard_active",
            return_value=False,
        ):
            changed = manager._apply_task_main_state_update(
                db,
                task,
                source="runtime_reclaim",
                reason="检测到运行中任务缺少有效租约，重置为待执行",
                status="pending",
                stage_name="entry_analysis",
                runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )

        self.assertTrue(changed)
        self.assertEqual("pending", task.status)
        allowed = [event for event in db.events if event.event_type == "task_running_downgrade_to_pending_allowed"]
        self.assertTrue(allowed)
        self.assertEqual("lease_loss_requeue", (allowed[-1].payload or {}).get("downgrade_reason_category"))
