import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask
from app.service import task_manager as task_manager_module
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

    def test_refresh_stage_from_authoritative_items_once_refreshes_kg_inputs_before_dataflow_tail_refresh(self):
        task = BinarySecurityTask(
            id="task-kg-tail",
            project_id="project-1",
            name="task",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            task_type="source",
            current_stage="dataflow_vuln_scan",
        )
        task.policy = {"pipeline_mode": "mixed_streaming", "pipeline_profile": "kg_source_vuln_scan"}
        stage_run = BinarySecurityStageRun(
            id="sr-dvs",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="running",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run])

        with (
            patch.object(self.manager, "_refresh_kg_streaming_inputs_if_needed") as refresh_kg_inputs,
            patch.object(self.manager, "_stage_handler", return_value=None),
            patch.object(self.manager, "_refresh_streaming_tail_stage_state") as refresh_tail,
        ):
            result = self.manager._refresh_stage_from_authoritative_items_once(db, task, "dataflow_vuln_scan")

        self.assertIs(result, stage_run)
        refresh_kg_inputs.assert_called_once_with(db, task)
        refresh_tail.assert_called_once_with(db, task, "dataflow_vuln_scan")

    def test_refresh_kg_streaming_inputs_if_needed_reseeds_dataflow_items_for_new_entries(self):
        task = BinarySecurityTask(
            id="task-kg-reseed",
            project_id="project-1",
            name="task",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            task_type="source",
            status="running",
            current_stage="dataflow_vuln_scan",
        )
        task.policy = {"pipeline_mode": "mixed_streaming", "pipeline_profile": "kg_source_vuln_scan"}
        kg_run = BinarySecurityStageRun(
            id="sr-kg",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="running",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dvs",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="running",
        )
        seeded_item = BinarySecurityStageItem(
            id="si-entry-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-b",
            item_name="fn_b",
            parent_key="mod-a",
            item_identity_key="entry-b::mod-a",
            status="queued",
            downstream_service="dataflow_vuln_scan",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[kg_run, dataflow_run], stage_items=[seeded_item], events=[])

        before_entry = {"entry_key": "entry-a", "function_name": "fn_a", "module_key": "mod-a"}
        after_entry = {"entry_key": "entry-b", "function_name": "fn_b", "module_key": "mod-a"}
        effective_inputs = [[before_entry], [before_entry, after_entry], [before_entry, after_entry]]

        with (
            patch.object(self.manager, "_streaming_mode_enabled", return_value=True),
            patch.object(self.manager, "_pipeline_profile", return_value="kg_source_vuln_scan"),
            patch.object(self.manager, "_latest_stage_run", side_effect=lambda _db, _task_id, stage: kg_run if stage == "knowledge_graph_entry_fetch" else dataflow_run if stage == "dataflow_vuln_scan" else None),
            patch.object(self.manager, "_effective_entry_inputs", side_effect=lambda *_args, **_kwargs: effective_inputs.pop(0)),
            patch.object(self.manager, "_stage_items", return_value=[seeded_item]),
            patch.object(self.manager, "_run_async_blocking", side_effect=lambda value: value),
            patch.object(self.manager, "_stage_knowledge_graph_entry_fetch") as refresh_kg,
            patch.object(self.manager, "_prepare_stage_items_for_execution", return_value=[]) as prepare_items,
            patch.object(self.manager, "_enqueue_task_sync_request", return_value={"queued": True}) as enqueue_sync,
        ):
            changed = self.manager._refresh_kg_streaming_inputs_if_needed(db, task)

        self.assertTrue(changed)
        refresh_kg.assert_called_once()
        prepare_items.assert_called_once()
        enqueue_sync.assert_called_once()
        self.assertEqual(["si-entry-b"], enqueue_sync.call_args.kwargs["item_ids"])
        payload = dict(db.events[-1].payload or {})
        self.assertTrue(payload.get("dataflow_reseeded"))
        self.assertTrue(payload.get("dataflow_child_create_enqueued"))
        self.assertEqual(["entry-b"], payload.get("new_entry_keys_sample"))

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
