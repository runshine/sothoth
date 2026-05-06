import tempfile
import unittest
from pathlib import Path

from app.model import BinarySecurityEvent, BinarySecurityTask
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

            modules = self.manager._parse_system_analysis_modules(root)

            self.assertEqual(2, len(modules))
            self.assertEqual("busybox", modules[0]["module_name"])
            self.assertTrue((root / "high_risk_modules.json").is_file())

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
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            stage_run=None,
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
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        db = _FakeDb(rows=[_StageRun("binary_to_source", "failed"), _StageRun("vuln_scan", "partial_success")])

        self.manager._finalize_task(db, task)

        self.assertEqual("partial_success", task.status)
        self.assertIsNotNone(task.finished_at)
        self.assertTrue(any(isinstance(obj, BinarySecurityEvent) for obj in db.added))

    def test_stage_enabled_uses_policy_override(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.policy = {"stage_options": {"vuln_scan": {"enabled": False}}}

        self.assertFalse(self.manager._stage_enabled(task, "vuln_scan"))
        self.assertTrue(self.manager._stage_enabled(task, "entry_analysis"))


if __name__ == "__main__":
    unittest.main()
