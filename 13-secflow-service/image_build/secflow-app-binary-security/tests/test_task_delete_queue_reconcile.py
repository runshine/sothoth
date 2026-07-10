import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from app.model import BinarySecurityTask, BinarySecurityTaskOperation, TASK_TYPE_BINARY
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _ModelAwareDb


class TaskDeleteQueueReconcileTests(unittest.IsolatedAsyncioTestCase):
    async def test_reconcile_work_queues_force_requeues_stalled_delete_operation(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-stalled-delete",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws-stalled-delete",
            current_operation_id="op-delete-stalled",
        )
        task.cleanup_snapshot = {
            "delete_queued": True,
            "delete_in_progress": True,
            "delete_operation_id": "op-delete-stalled",
            "delete_mode": "delete",
            "delete_started_at": (_now() - timedelta(minutes=5)).isoformat(),
            "delete_last_progress_at": (_now() - timedelta(minutes=5)).isoformat(),
            "delete_last_progress_step": "workspace_cleanup_started",
        }
        operation = BinarySecurityTaskOperation(
            id="op-delete-stalled",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            status="queued",
            request_payload={"force_delete": False},
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[], state_events=[])
        delete_reenqueued: list[tuple[str, str | None]] = []

        class _Queue:
            async def queue_positions(self, queue_key, *, context=None):
                del queue_key, context
                return {}

            async def force_requeue_task(self, task_id, *, context=None):
                del task_id, context
                raise AssertionError("main queue reenqueue should not be used for stalled delete tasks")

            async def force_requeue_delete_task(self, task_id, *, context=None):
                delete_reenqueued.append((task_id, context))

            async def push_task(self, task_id, context=None):
                del task_id, context
                raise AssertionError("push_task should not be used for stalled delete tasks")

            async def cleanup_dedupe_orphans(self, _queue_key):
                del _queue_key
                return {}

        with (
            patch("app.service.task_manager.get_task_queue", return_value=_Queue()),
            patch.object(manager, "reconcile_orphan_parent_tasks_missing_initial_enqueue", AsyncMock(return_value=0)),
            patch.object(manager, "reconcile_released_parent_tasks_missing_takeover_enqueue", AsyncMock(return_value=0)),
            patch.object(manager, "_queue_reconcile_task_rows", return_value=[task]),
            patch.object(manager, "_queue_reconcile_operation_rows", return_value=[]),
        ):
            await manager._reconcile_work_queues_once(db, now_value=_now())

        self.assertEqual([("task-stalled-delete", "delete_queue_stalled_reconcile")], delete_reenqueued)
        event_types = [row.event_type for row in db.events]
        self.assertIn("task_delete_stalled_reconcile_detected", event_types)
        self.assertIn("task_delete_stalled_force_requeued", event_types)
        self.assertTrue(dict(operation.request_payload or {}).get("force_delete"))
