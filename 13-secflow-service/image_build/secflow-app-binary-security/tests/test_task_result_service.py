import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

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

    def test_persist_stage_item_result_preserves_sync_fields_when_requested(self):
        task = self._task()
        item = self._item()
        item.result = {
            "sync_status": "synced",
            "downstream_status": "success",
            "last_sync_result": "success",
            "sync_observation": {
                "sync_status": "synced",
                "downstream_status": "success",
                "mapped_status": "success",
                "state_applied": True,
            },
            "downstream": {"task_id": "child-1", "status": "passed"},
        }

        stored = self.manager._persist_stage_item_result(
            task,
            item,
            stage_name="entry_analysis",
            result={
                "entry_count": 3,
                "entries_preview": [{"entry_key": "e1"}],
            },
            preserve_sync_fields=True,
        )

        self.assertEqual("synced", stored["sync_status"])
        self.assertEqual("success", stored["downstream_status"])
        self.assertEqual("success", stored["sync_observation"]["downstream_status"])
        self.assertTrue(stored["sync_observation"]["state_applied"])
        self.assertEqual("child-1", stored["downstream"]["task_id"])

    def test_persist_stage_item_result_overwrites_sync_fields_by_default(self):
        task = self._task()
        item = self._item()
        item.result = {
            "sync_status": "synced",
            "downstream_status": "success",
            "sync_observation": {
                "sync_status": "synced",
                "downstream_status": "success",
                "state_applied": True,
            },
        }

        stored = self.manager._persist_stage_item_result(
            task,
            item,
            stage_name="entry_analysis",
            result={"entry_count": 1},
        )

        self.assertNotIn("sync_status", stored)
        self.assertNotIn("downstream_status", stored)
        self.assertNotIn("sync_observation", stored)

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

    def test_refresh_terminal_dataflow_result_preserves_sync_observation(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="demo",
            status="running",
            current_stage="dataflow_vuln_scan",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
        )
        item = BinarySecurityStageItem(
            id="item-1",
            task_id="task-1",
            project_id="project-1",
            stage_name="dataflow_vuln_scan",
            item_key="entry-1",
            item_name="handle",
            parent_key="module-1",
            status="success",
            downstream_service="dataflow_vuln_scan",
            input_ref={
                "entry_key": "entry-1",
                "module_key": "module-1",
                "module_name": "module-1",
                "function_name": "handle",
                "source_file": "main.c",
                "definition_file": "main.c",
                "definition_line": "12",
                "definition_kind": "definition",
                "source_root_path": "/archive/src",
                "source_dir": "/archive/src",
                "module_input_path": "/archive/src/module-1",
            },
            result={
                "sync_status": "synced",
                "downstream_status": "success",
                "last_sync_result": "success",
                "sync_observation": {
                    "sync_status": "synced",
                    "downstream_status": "success",
                    "mapped_status": "success",
                    "state_applied": True,
                },
                "downstream": {"task_id": "dfvs-1", "status": "passed"},
            },
        )

        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.object(self.manager, "_find_first", return_value=Path(tmpdir) / "final_report.md"),
        ):
            artifact_root = Path(tmpdir)
            with patch.object(self.manager, "_downstream_fetch_item_result", AsyncMock(return_value={})):
                asyncio.run(
                    self.manager._refresh_terminal_item_result_from_downstream(
                        task,
                        item,
                        {"task_id": "dfvs-1", "status": "passed"},
                        mapped_status="success",
                        archived_dir=artifact_root,
                    )
                )

        self.assertEqual("synced", item.result["sync_status"])
        self.assertEqual("success", item.result["downstream_status"])
        self.assertTrue(item.result["sync_observation"]["state_applied"])
        self.assertEqual("dfvs-1", item.result["downstream"]["task_id"])
