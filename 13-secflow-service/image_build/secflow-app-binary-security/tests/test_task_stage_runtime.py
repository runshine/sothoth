import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.model import BinarySecurityStageRun, BinarySecurityTask
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskStageRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_reconcile_stage_domain_in_session_delegates_to_registered_refresh_handlers(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")

        for stage_name in [
            "firmware_unpack",
            "system_analysis",
            "binary_to_source",
            "entry_analysis",
            "dataflow_vuln_scan",
        ]:
            with self.subTest(stage_name=stage_name):
                stage_run = BinarySecurityStageRun(
                    id=f"sr-{stage_name}",
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name=stage_name,
                    sequence_no=1,
                    status="running",
                )
                db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run])

                class _Handler:
                    def __init__(self):
                        self.called = None

                    def manages_stage_refresh(self):
                        return True

                    def refresh_summary_from_items(self, manager, current_db, current_task):
                        self.called = (manager, current_db, current_task)

                handler = _Handler()
                original_registry = self.manager._stage_registry
                self.manager._stage_registry = SimpleNamespace(get=lambda name: handler if name == stage_name else None)
                try:
                    result = self.manager._reconcile_stage_domain_in_session(db, task, stage_name)
                finally:
                    self.manager._stage_registry = original_registry

                self.assertIs(result, stage_run)
                self.assertIsNotNone(handler.called)
                self.assertIs(handler.called[0], self.manager)
                self.assertIs(handler.called[1], db)
                self.assertIs(handler.called[2], task)

    def test_refresh_stage_from_authoritative_items_once_uses_streaming_tail_refresh_for_tail_stage_without_handler(self):
        task = BinarySecurityTask(
            id="task-tail",
            project_id="project-1",
            name="task",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            task_type="binary",
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}
        stage_run = BinarySecurityStageRun(
            id="sr-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=1,
            status="pending",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run])

        with (
            patch.object(self.manager, "_stage_handler", return_value=None),
            patch.object(self.manager, "_refresh_streaming_tail_stage_state") as refresh_tail,
        ):
            result = self.manager._refresh_stage_from_authoritative_items_once(db, task, "entry_analysis")

        self.assertIs(result, stage_run)
        refresh_tail.assert_called_once_with(db, task, "entry_analysis")

    def test_reconcile_retry_affected_stages_in_session_deduplicates_and_avoids_compatibility_facade(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        db = _ModelAwareDb(tasks=[task])
        reconciled_calls = []

        def _reconcile_stage(current_db, current_task, stage_name):
            reconciled_calls.append((current_db, current_task, stage_name))
            return None

        with (
            patch.object(self.manager, "_reconcile_stage_domain_in_session", side_effect=_reconcile_stage),
        ):
            reconciled = self.manager._reconcile_retry_affected_stages_in_session(
                db,
                task,
                stage_names=["entry_analysis", "entry_analysis", "", "dataflow_vuln_scan"],
            )

        self.assertFalse(hasattr(TaskManager, "_reconcile_stage_and_task_state_after_item_update"))
        self.assertEqual(["entry_analysis", "dataflow_vuln_scan"], reconciled)
        self.assertEqual(
            [
                (db, task, "entry_analysis"),
                (db, task, "dataflow_vuln_scan"),
            ],
            reconciled_calls,
        )


if __name__ == "__main__":
    unittest.main()
