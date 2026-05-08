import tempfile
import unittest
import zipfile
from pathlib import Path

from app.model import (
    BinarySecurityEvent,
    BinarySecurityTask,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _FakeDb:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.added = []
        self.commits = 0

    def query(self, *args, **kwargs):
        return _FakeQuery(self.rows)

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.commits += 1


class _StageRun:
    def __init__(self, stage_name, status):
        self.stage_name = stage_name
        self.status = status


class TaskManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_parse_system_analysis_modules_from_modules_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modules_dir = root / "modules"
            (modules_dir / "busybox").mkdir(parents=True)
            (modules_dir / "dropbear").mkdir(parents=True)
            (root / "modules.list").write_text("busybox\ndropbear\n", encoding="utf-8")

            modules = self.manager._parse_system_analysis_modules(root, {
                "firmware_key": "fw1",
                "firmware_name": "fw1",
                "filename": "fw1.bin",
                "unpacked_root": str(root),
                "task_type": TASK_TYPE_BINARY,
            })

            self.assertEqual(2, len(modules))
            self.assertEqual("busybox", modules[0]["module_name"])
            self.assertTrue((root / "high_risk_modules.json").is_file())
            self.assertEqual(str((modules_dir / "busybox")), modules[0]["source_dir"])

    def test_parse_entries_prefers_json_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "result.json").write_text(
                '{"entries":[{"file_name":"main.c","function_name":"handle_req","line_no":12}]}',
                encoding="utf-8",
            )

            rows = self.manager._parse_entries(root, {"module_key": "mod", "module_name": "mod", "source_dir": "/src"})

            self.assertEqual(1, len(rows))
            self.assertEqual("handle_req", rows[0]["function_name"])
            self.assertEqual("main.c", rows[0]["file_name"])

    def test_parse_entries_falls_back_to_markdown_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "entry-list.md").write_text(
                "| idx | no | file | function | line | desc | risk |\n| --- | --- | --- | --- | --- | --- | --- |\n| 1 | 1 | app.c | parse_input | 99 | d | h |\n",
                encoding="utf-8",
            )

            rows = self.manager._parse_entries(root, {"module_key": "mod", "module_name": "mod", "source_dir": "/src"})

            self.assertEqual(1, len(rows))
            self.assertEqual("parse_input", rows[0]["function_name"])

    def test_choose_module_binary_handles_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unpacked = root / "unpacked"
            module_dir = unpacked / "modules" / "openssl"
            module_dir.mkdir(parents=True)
            target = unpacked / "bin" / "openssl.elf"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"elf")
            (module_dir / "files.list").write_text("bin/openssl.elf\n", encoding="utf-8")

            path = self.manager._choose_module_binary(
                {
                    "module_name": "openssl",
                    "module_dir": str(module_dir),
                    "files_list": str(module_dir / "files.list"),
                    "unpacked_root": str(unpacked),
                }
            )

            self.assertEqual(str(target.resolve()), path)

    def test_aggregate_stage_items_marks_partial_success(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {"status": "success", "item": {"id": "a"}},
                {"status": "failed", "item": {"id": "b"}, "error": "boom"},
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("partial_success", status)
        self.assertEqual(1, summary["success_count"])
        self.assertEqual(1, summary["failed_count"])
        self.assertEqual([{"id": "a"}], task.summary["b2s_results"])
        self.assertEqual(1, db.commits)

    def test_finalize_task_prefers_partial_success_after_vuln_stage(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        db = _FakeDb(rows=[_StageRun("binary_to_source", "failed"), _StageRun("vuln_scan", "partial_success")])

        self.manager._finalize_task(db, task)

        self.assertEqual("partial_success", task.status)
        self.assertIsNotNone(task.finished_at)
        self.assertTrue(any(isinstance(obj, BinarySecurityEvent) for obj in db.added))

    def test_stage_enabled_uses_policy_override(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.policy = {"stage_options": {"vuln_scan": {"enabled": False}}}

        self.assertFalse(self.manager._stage_enabled(task, "vuln_scan"))
        self.assertTrue(self.manager._stage_enabled(task, "entry_analysis"))

    def test_stage_sequence_uses_task_type(self):
        binary_task = BinarySecurityTask(id="b1", project_id="p1", name="binary", task_type=TASK_TYPE_BINARY, status="pending", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        source_task = BinarySecurityTask(id="s1", project_id="p1", name="source", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root="/o", workspace_root="/w")

        self.assertEqual(
            ["firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            self.manager._stage_sequence_for_task(binary_task),
        )
        self.assertEqual(
            ["system_analysis", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            self.manager._stage_sequence_for_task(source_task),
        )

    def test_source_system_analysis_inputs_use_workspace_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "input").mkdir()
            task = BinarySecurityTask(id="s1", project_id="p1", name="source-task", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root=str(workspace / "output"), workspace_root=str(workspace))

            rows = self.manager._system_analysis_inputs(task)

            self.assertEqual(1, len(rows))
            self.assertEqual(TASK_TYPE_SOURCE, rows[0]["task_type"])
            self.assertEqual(str(workspace / "input"), rows[0]["unpacked_root"])
            self.assertEqual(str(workspace / "input"), rows[0]["source_root"])

    def test_source_entry_analysis_inputs_come_from_high_risk_modules(self):
        task = BinarySecurityTask(id="s1", project_id="p1", name="source-task", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root="/o", workspace_root="/w")
        task.summary = {
            "high_risk_modules": [
                {"module_key": "m1", "module_name": "module1", "source_dir": "/src/module1"},
            ],
            "b2s_results": [
                {"module_key": "legacy", "module_name": "legacy", "source_dir": "/legacy"},
            ],
        }

        rows = self.manager._entry_analysis_inputs(task)

        self.assertEqual(1, len(rows))
        self.assertEqual("m1", rows[0]["module_key"])

    def test_normalize_source_input_files_rejects_duplicate_relative_paths(self):
        with self.assertRaisesRegex(Exception, "重复文件名"):
            self.manager._normalize_input_files(
                [
                    {"filename": "src.zip", "relative_path": "src/a.c"},
                    {"filename": "src.zip", "relative_path": "src/b.c"},
                ],
                task_type=TASK_TYPE_SOURCE,
            )

    def test_normalize_source_input_files_rejects_non_archive(self):
        with self.assertRaisesRegex(Exception, "仅支持常见压缩文件"):
            self.manager._normalize_input_files(
                [
                    {"filename": "main.c"},
                ],
                task_type=TASK_TYPE_SOURCE,
            )

    def test_materialize_source_archives_extracts_into_input_and_cleans_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            input_dir = workspace / "input"
            temp_dir = workspace / "run" / "upload-tmp"
            input_dir.mkdir(parents=True)
            temp_dir.mkdir(parents=True)
            archive_path = temp_dir / "source.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("src/main.c", "int main() { return 0; }\n")
                archive.writestr("README.md", "# demo\n")
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source-task",
                task_type=TASK_TYPE_SOURCE,
                status="pending_upload",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {
                "input_dir": "/app/secflow-app-binary-security/s1/input",
                "temp_upload_dir": "/app/secflow-app-binary-security/s1/run/upload-tmp",
            }

            files, total_bytes, extracted_count = self.manager._materialize_source_archives(
                task,
                [{"filename": "source.zip", "relative_path": "source.zip"}],
            )

            self.assertEqual(1, len(files))
            self.assertGreater(total_bytes, 0)
            self.assertEqual(2, extracted_count)
            self.assertTrue((input_dir / "src" / "main.c").is_file())
            self.assertTrue((input_dir / "README.md").is_file())
            self.assertFalse(archive_path.exists())

    def test_resolve_downstream_output_sources_prefers_output_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"workspace_root": str(workspace)},
                downstream_task_id="t123",
            )

            self.assertEqual(output_dir, rows[0])

    def test_archive_downstream_output_copies_output_contents_without_output_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "result.json").write_text("{}", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type("Item", (), {
                "downstream_service": "system_analyse",
                "stage_name": "system_analysis",
                "downstream_task_id": "down1",
                "item_key": "fw1",
                "id": "si1",
            })()
            db = _FakeDb()

            target = self.manager._archive_downstream_output(
                db,
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertIsNotNone(target)
            assert target is not None
            self.assertTrue((target / "result.json").is_file())
            self.assertFalse((target / "output").exists())
            self.assertEqual("system-analyse", target.parent.name)
            self.assertEqual("fw1__down1", target.name)

    def test_collect_downstream_refs_dedupes_same_service_and_task_id(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        items = []
        for item_id, task_id in [("i1", "down1"), ("i2", "down1"), ("i3", "down2")]:
            item = type("Item", (), {})()
            item.id = item_id
            item.downstream_service = "entry_analyse"
            item.downstream_task_id = task_id
            item.project_id = "p1"
            item.stage_name = "entry_analysis"
            items.append(item)

        refs = self.manager._collect_downstream_refs(task, items)

        self.assertEqual(2, len(refs))
        self.assertEqual(
            [
                {"service": "entry_analyse", "task_id": "down1", "project_id": "p1", "stage_name": "entry_analysis"},
                {"service": "entry_analyse", "task_id": "down2", "project_id": "p1", "stage_name": "entry_analysis"},
            ],
            refs,
        )


if __name__ == "__main__":
    unittest.main()
