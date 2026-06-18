import json
import tempfile
import unittest
from pathlib import Path

from app.model import BinarySecurityStageItem, BinarySecurityTask, TASK_TYPE_BINARY, TASK_TYPE_SOURCE
from app.service.task.contracts import TaskContractServiceMixin
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskContractServiceStructureTests(unittest.TestCase):
    def test_task_manager_contract_methods_are_bound_to_contract_mixin(self):
        self.assertIs(TaskManager._compact_result_for_storage, TaskContractServiceMixin._compact_result_for_storage)
        self.assertIs(TaskManager._entry_analysis_inputs, TaskContractServiceMixin._entry_analysis_inputs)
        self.assertIs(TaskManager._build_entry_analysis_input_contract, TaskContractServiceMixin._build_entry_analysis_input_contract)
        self.assertIs(TaskManager._normalize_entry_analysis_module_input, TaskContractServiceMixin._normalize_entry_analysis_module_input)
        self.assertIs(TaskManager._build_dataflow_output_contract, TaskContractServiceMixin._build_dataflow_output_contract)


class TaskContractServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_build_entry_analysis_input_contract_requires_explicit_fields(self):
        contract = self.manager._build_entry_analysis_input_contract(
            {
                "module_dir": "/tmp/mod",
                "files_list_path": "/tmp/mod/files.list",
                "source_root": "/tmp/root",
                "source_root_path": "/tmp/root",
                "source_dir": "/tmp/root",
            }
        )
        self.assertEqual("/tmp/mod", contract["module_dir"])
        self.assertEqual("/tmp/mod/files.list", contract["files_list_path"])
        self.assertEqual("/tmp/root", contract["source_root"])

    def test_compact_result_for_storage_keeps_entry_preview_and_counts(self):
        compact = self.manager._compact_result_for_storage(
            "entry_analysis",
            {
                "entries": [
                    {"entry_key": "e1", "function_name": "main", "file_name": "a.c", "line_no": 1},
                    {"entry_key": "e2", "function_name": "sub", "file_name": "b.c", "line_no": 2},
                ]
            },
        )
        self.assertEqual(2, compact["entry_count"])
        self.assertIn("entries_preview", compact)
        self.assertNotIn("entries", compact)

    def test_parse_system_analysis_modules_builds_lightweight_rows_from_result_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            modules_dir = root / "modules" / "mod-a"
            modules_dir.mkdir(parents=True)
            (modules_dir / "files.list").write_text("a.c\n", encoding="utf-8")
            (modules_dir / "module_report.md").write_text("# mod-a\n", encoding="utf-8")
            firmware = {
                "firmware_key": "fw-1",
                "firmware_name": "fw.bin",
                "filename": "fw.bin",
                "unpacked_root": tmpdir,
                "source_root": tmpdir,
                "task_type": TASK_TYPE_BINARY,
            }

            rows = self.manager._parse_system_analysis_modules(
                root,
                firmware,
                result_payload={
                    "modules": [
                        {
                            "module_name": "mod-a",
                            "rank": 1,
                            "risk_level": "high",
                            "risk_score": 90,
                        }
                    ]
                },
            )

            self.assertEqual(1, len(rows))
            self.assertEqual("mod-a", rows[0]["module_name"])
            self.assertEqual("high", rows[0]["risk_level"])

    def test_entry_analysis_inputs_for_source_reuses_selected_modules(self):
        task = BinarySecurityTask(
            id="task-source",
            project_id="p1",
            name="source-task",
            status="running",
            current_stage="entry_analysis",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
        )
        task.summary = {
            "selected_modules": [
                {
                    "firmware_key": "src-root",
                    "source_root": "/src/root",
                    "source_root_path": "/src/root",
                    "source_dir": "/src/root",
                    "module_dir": "/src/root",
                }
            ]
        }
        db = _ModelAwareDb(tasks=[task])
        rows = self.manager._entry_analysis_inputs(db, task)
        self.assertEqual(1, len(rows))
        self.assertEqual("/src/root", rows[0]["source_root"])

    def test_normalize_entry_analysis_module_input_prepares_binary_module_descriptor(self):
        task = BinarySecurityTask(
            id="task-binary-module",
            project_id="p1",
            name="binary-module-task",
            status="running",
            current_stage="entry_analysis",
            task_type="binary_module",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/out",
            workspace_root="/ws",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_root = Path(tmpdir)
            source_dir = artifact_root / "sources"
            source_dir.mkdir()
            (source_dir / "main.c").write_text("int main() { return 0; }\n", encoding="utf-8")
            normalized = self.manager._normalize_entry_analysis_module_input(
                task,
                {
                    "module_name": "mod-a",
                    "artifact_root": str(artifact_root),
                    "archive_root": str(artifact_root),
                    "source_dir": str(source_dir),
                    "source_root": str(source_dir),
                    "module_dir": str(source_dir),
                },
            )

        self.assertTrue(normalized["entry_descriptor_ready"])
        self.assertTrue(str(normalized["entry_files_list"]).endswith("files.list"))
        self.assertEqual(str(artifact_root), normalized["source_root"])

    def test_build_dataflow_output_contract_keeps_entry_and_archive_fields(self):
        contract = self.manager._build_dataflow_output_contract(
            {
                "entry_key": "entry-1",
                "module_key": "module-1",
                "module_name": "mod-a",
                "function_name": "main",
            },
            artifact_root="/tmp/artifacts",
            archive_root="/tmp/archive",
            module_input_path="/tmp/mod",
            source_root_path="/tmp/root",
            source_file="src/main.c",
            data_flow_file="/tmp/archive/final_report.md",
            dataflow_dir="/tmp/archive/dataflow",
            source_dir="/tmp/root",
        )

        self.assertEqual("/tmp/archive", contract["archive_root"])
        self.assertEqual("/tmp/archive/dataflow", contract["dataflow_dir"])
        self.assertEqual("src/main.c", contract["source_file"])
