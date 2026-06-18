import tempfile
import unittest
from pathlib import Path

from app.model import BinarySecurityStageItem, BinarySecurityTask
from app.service.task.results import TaskResultServiceMixin
from app.service.task_manager import TaskManager


class TaskResultServiceStructureTests(unittest.TestCase):
    def test_task_manager_result_methods_are_bound_to_result_mixin(self):
        self.assertIs(TaskManager._persist_stage_item_result, TaskResultServiceMixin._persist_stage_item_result)
        self.assertIs(TaskManager._archive_downstream_output, TaskResultServiceMixin._archive_downstream_output)
        self.assertIs(TaskManager._materialize_stage_artifact, TaskResultServiceMixin._materialize_stage_artifact)
        self.assertIs(TaskManager._resolve_downstream_output_sources, TaskResultServiceMixin._resolve_downstream_output_sources)


class TaskResultServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _task(self):
        return BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="demo",
            status="running",
            current_stage="entry_analysis",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
        )

    def _item(self):
        return BinarySecurityStageItem(
            id="item-1",
            task_id="task-1",
            project_id="project-1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="module-1",
            status="running",
            downstream_service="entry_analyse",
        )

    def test_persist_stage_item_result_keeps_small_payload_inline(self):
        task = self._task()
        item = self._item()

        stored = self.manager._persist_stage_item_result(
            task,
            item,
            stage_name="entry_analysis",
            result={"status": "ok"},
        )

        self.assertEqual("ok", stored["status"])
        self.assertEqual(0, stored["entry_count"])
        self.assertEqual([], stored["entries_preview"])
        self.assertEqual(stored, item.result)

    def test_persist_stage_item_result_externalizes_large_entry_payload(self):
        task = self._task()
        item = self._item()
        with tempfile.TemporaryDirectory() as tmpdir:
            task.workspace_root = tmpdir
            large_result = {
                "entries": [
                    {
                        "entry_key": f"entry-{index}",
                        "module_key": "module-1",
                        "module_name": "module-1",
                        "file_name": "main.c",
                        "function_name": f"func_{index}",
                        "line_no": index,
                    }
                    for index in range(200)
                ]
            }

            stored = self.manager._persist_stage_item_result(
                task,
                item,
                stage_name="entry_analysis",
                result=large_result,
            )

            self.assertIn("result_path", stored)
            self.assertTrue(Path(stored["result_path"]).is_file())
            loaded = self.manager._load_stage_item_result_payload(item)
            self.assertEqual(200, len(loaded["entries"]))

    def test_materialize_stage_artifact_prefers_external_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_root = Path(tmpdir) / "artifact"
            artifact_root.mkdir()
            external = Path(tmpdir) / "external"
            external.mkdir()
            (external / "report.md").write_text("ok\n", encoding="utf-8")

            materialized = self.manager._materialize_stage_artifact(
                artifact_root,
                "child-1",
                {"output_root": str(external)},
                task=self._task(),
                item=self._item(),
            )

            self.assertEqual(external, materialized)
