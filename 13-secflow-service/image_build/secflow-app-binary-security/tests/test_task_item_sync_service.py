import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from sqlalchemy.exc import OperationalError

from app.model import BinarySecurityTask
from app.service.task_manager import TaskManager
from test_task_manager import _AppendingModelAwareDb


class TaskItemSyncServiceTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_process_readless_reconcile_task_sync_runs_item_stage_task_order(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="p1",
            name="task",
            status="running",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        db = _AppendingModelAwareDb(tasks=[task])
        calls = []

        with (
            patch("app.service.task_manager.get_session_factory", return_value=lambda: db),
            patch.object(self.manager, "_should_skip_readless_reconcile_for_active_task", return_value=False),
            patch.object(self.manager, "_readless_reconcile_item_layer", side_effect=lambda _task_id: calls.append("item") or {"entry_analysis"}),
            patch.object(self.manager, "_readless_reconcile_stage_layer", side_effect=lambda _task_id: calls.append("stage") or {"entry_analysis"}),
            patch.object(self.manager, "_readless_reconcile_task_layer", side_effect=lambda _task_id: calls.append("task") or self.manager._task_state_snapshot(task)),
            patch.object(self.manager, "_readless_reconcile_tail_takeover", side_effect=lambda _task_id: calls.append("tail")),
        ):
            processed, changed = self.manager._process_readless_reconcile_task_sync(task.id)

        self.assertTrue(processed)
        self.assertTrue(changed)
        self.assertEqual(["item", "stage", "task", "tail"], calls)

    def test_process_readless_reconcile_task_sync_preserves_item_stage_when_task_layer_conflicts(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="p1",
            name="task",
            status="running",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        db = _AppendingModelAwareDb(tasks=[task])
        calls = []

        with (
            patch("app.service.task_manager.get_session_factory", return_value=lambda: db),
            patch.object(self.manager, "_should_skip_readless_reconcile_for_active_task", return_value=False),
            patch.object(self.manager, "_readless_reconcile_item_layer", side_effect=lambda _task_id: calls.append("item") or {"entry_analysis"}),
            patch.object(self.manager, "_readless_reconcile_stage_layer", side_effect=lambda _task_id: calls.append("stage") or {"entry_analysis"}),
            patch.object(self.manager, "_readless_reconcile_task_layer", side_effect=OperationalError("stmt", {}, Exception("lock conflict"))),
        ):
            with self.assertRaises(OperationalError):
                self.manager._process_readless_reconcile_task_sync(task.id)

        self.assertEqual(["item", "stage"], calls)


if __name__ == "__main__":
    unittest.main()
