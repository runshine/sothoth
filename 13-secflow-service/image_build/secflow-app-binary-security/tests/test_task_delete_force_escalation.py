import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.model import BinarySecurityEvent, BinarySecurityTask, BinarySecurityTaskOperation, TASK_TYPE_BINARY
from app.service.task_manager import TaskManager
from test_task_manager import _AppendingModelAwareDb


class TaskDeleteForceEscalationTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_prepare_delete_task_escalates_force_delete_when_downstream_cleanup_blocks(self):
        task = BinarySecurityTask(
            id="t-delete-blocking",
            project_id="p1",
            name="delete-blocking",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/out",
            workspace_root="/tmp/ws-delete-blocking",
            current_stage="entry_analysis",
            current_operation_id="op-delete-blocking",
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-blocking",
            task_id=task.id,
            project_id="p1",
            operation_type="delete",
            target_stage="entry_analysis",
            status="running",
            request_payload={"force_delete": False},
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], state_events=[], events=[])

        async def _run():
            with (
                patch.object(self.manager, "_request_local_worker_cancel", AsyncMock()),
                patch.object(self.manager, "_cancel_downstream_refs", AsyncMock()),
                patch.object(self.manager, "_delete_downstream_refs", AsyncMock(return_value=0)),
                patch.object(self.manager, "_wait_for_task_workspace_quiesce", AsyncMock(return_value=True)),
                patch.object(self.manager, "_cleanup_task_workspace", AsyncMock(return_value="deleted")),
            ):
                setattr(
                    self.manager,
                    "_last_downstream_cleanup_results",
                    [
                        {
                            "service": "entry_analyse",
                            "task_id": "eat-blocking",
                            "stage_name": "entry_analysis",
                            "delete_status": "failed",
                            "blocking": True,
                            "error": "downstream delete still blocking",
                        }
                    ],
                )
                await self.manager._prepare_delete_task(db, task)

        asyncio.run(_run())

        self.assertEqual([], db.tasks)
        event_types = [row.event_type for row in db.events if isinstance(row, BinarySecurityEvent)]
        self.assertIn("task_delete_blocked_detected", event_types)
        self.assertIn("task_delete_auto_force_delete_fallback", event_types)
        self.assertIn("task_force_delete_completed", event_types)
        request_payload = dict(operation.request_payload or {})
        self.assertTrue(request_payload.get("force_delete"))
        self.assertEqual("downstream_delete", request_payload.get("blocking_step"))

    def test_prepare_delete_task_escalates_force_delete_when_workspace_cleanup_fails(self):
        task = BinarySecurityTask(
            id="t-delete-workspace-failed",
            project_id="p1",
            name="delete-workspace-failed",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/out",
            workspace_root="/tmp/ws-delete-workspace-failed",
            current_stage="entry_analysis",
            current_operation_id="op-delete-workspace-failed",
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-workspace-failed",
            task_id=task.id,
            project_id="p1",
            operation_type="delete",
            target_stage="entry_analysis",
            status="running",
            request_payload={"force_delete": False},
        )
        db = _AppendingModelAwareDb(tasks=[task], operations=[operation], state_events=[], events=[])

        async def _run():
            with (
                patch.object(self.manager, "_request_local_worker_cancel", AsyncMock()),
                patch.object(self.manager, "_cancel_downstream_refs", AsyncMock()),
                patch.object(self.manager, "_delete_downstream_refs", AsyncMock(return_value=0)),
                patch.object(self.manager, "_wait_for_task_workspace_quiesce", AsyncMock(return_value=True)),
                patch.object(self.manager, "_cleanup_task_workspace", AsyncMock(return_value="recreated_during_delete")),
            ):
                setattr(self.manager, "_last_downstream_cleanup_results", [])
                await self.manager._prepare_delete_task(db, task)

        asyncio.run(_run())

        self.assertEqual([], db.tasks)
        event_types = [row.event_type for row in db.events if isinstance(row, BinarySecurityEvent)]
        self.assertIn("task_delete_blocked_detected", event_types)
        self.assertIn("task_delete_auto_force_delete_fallback", event_types)
        self.assertIn("task_force_delete_completed", event_types)
        request_payload = dict(operation.request_payload or {})
        self.assertTrue(request_payload.get("force_delete"))
        self.assertEqual("workspace_cleanup", request_payload.get("blocking_step"))
