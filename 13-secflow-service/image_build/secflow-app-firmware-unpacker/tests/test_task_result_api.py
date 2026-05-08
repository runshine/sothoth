import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "app"
for candidate in (PROJECT_ROOT, APP_ROOT):
    candidate_text = str(candidate)
    if candidate_text not in sys.path:
        sys.path.insert(0, candidate_text)

from app.api.firmware import _get_task_result
from app.config import reload_config
from app.model import UnpackTask, UnpackTaskEvent, generate_id, get_db_session, init_database
import app.model as model_module


class TaskResultApiTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        config_path = self.root / "config.yaml"
        db_path = self.root / "tasks.db"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "database": {
                        "type": "sqlite",
                        "path": str(db_path),
                        "table_prefix": "secflow_app_firmware_unpacker_",
                    },
                }
            ),
            encoding="utf-8",
        )
        reload_config(str(config_path))
        model_module._engine = None
        model_module._SessionFactory = None
        model_module._OWNER_ID = "pod-a:123:owner"
        init_database()

    def tearDown(self):
        model_module._engine = None
        model_module._SessionFactory = None
        model_module._OWNER_ID = None
        self._tmp.cleanup()

    def _add_task(self, task_id: str, output_path: Path, *, status: str = "success"):
        db = get_db_session()
        try:
            db.add(
                UnpackTask(
                    id=task_id,
                    project_id="p1",
                    firmware_path="/tmp/fw.bin",
                    output_path=str(output_path),
                    status=status,
                    result_status=status,
                )
            )
            db.commit()
        finally:
            db.close()

    def _add_event(self, task_id: str):
        db = get_db_session()
        try:
            db.add(
                UnpackTaskEvent(
                    id=generate_id(),
                    task_id=task_id,
                    project_id="p1",
                    event_type="task_succeeded",
                    summary="任务执行成功",
                )
            )
            db.commit()
        finally:
            db.close()

    def test_get_task_result_warns_when_output_missing(self):
        output_root = self.root / "missing-task" / "output"
        self._add_task("t-missing", output_root)

        result = _get_task_result("t-missing")

        self.assertFalse(result["available"])
        self.assertIn("输出目录不存在", result["warnings"])
        self.assertEqual(0, result["summary"]["output_file_count"])
        self.assertEqual([], result["summary"]["top_level_entries"])
        self.assertEqual([], result["summary"]["largest_files"])
        self.assertEqual([], result["summary"]["file_extension_breakdown"])

    def test_get_task_result_reports_empty_output_directory(self):
        task_root = self.root / "task-empty"
        output_root = task_root / "output"
        output_root.mkdir(parents=True, exist_ok=True)
        self._add_task("t-empty", output_root)

        result = _get_task_result("t-empty")

        self.assertTrue(result["available"])
        self.assertEqual(0, result["summary"]["output_file_count"])
        self.assertEqual(0, result["summary"]["output_dir_count"])
        self.assertEqual(0, result["summary"]["output_total_size_bytes"])
        self.assertEqual([], result["summary"]["top_level_entries"])
        self.assertEqual([], result["summary"]["largest_files"])
        self.assertEqual([], result["summary"]["file_extension_breakdown"])

    def test_get_task_result_reports_output_statistics(self):
        task_root = self.root / "task-full"
        output_root = task_root / "output"
        run_root = task_root / "run"
        round0_root = run_root / "round_000"
        nested_dir = output_root / "dirA" / "nested"
        nested_dir.mkdir(parents=True, exist_ok=True)
        (output_root / "root.txt").write_bytes(b"a" * 100)
        (output_root / "dirA" / "payload.bin").write_bytes(b"b" * 6000)
        (nested_dir / "huge.img").write_bytes(b"c" * (2 * 1024 * 1024))
        (output_root / "README").write_bytes(b"d" * 10)
        (output_root / "skip-link").symlink_to(output_root / "root.txt")
        round0_root.mkdir(parents=True, exist_ok=True)
        (output_root / "summary.md").write_text("# Summary\n\nsummary", encoding="utf-8")
        (output_root / "reason.md").write_text("# Reason\n\nreason", encoding="utf-8")
        sessions_dir = run_root / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        (sessions_dir / "index.json").write_text(
            json.dumps({"version": 1, "items": [{"role": "executor", "name": "round-1"}]}),
            encoding="utf-8",
        )

        self._add_task("t-full", output_root)
        self._add_event("t-full")

        result = _get_task_result("t-full")
        summary = result["summary"]

        self.assertTrue(result["available"])
        self.assertEqual(6, summary["output_file_count"])
        self.assertEqual(2, summary["output_dir_count"])
        self.assertEqual(6, summary["top_level_entry_count"])
        self.assertEqual(str(output_root / "dirA" / "nested" / "huge.img"), summary["largest_file_path"])
        self.assertEqual(4, summary["small_file_count"])
        self.assertEqual(1, summary["medium_file_count"])
        self.assertEqual(1, summary["large_file_count"])
        self.assertEqual(1, summary["session_count"])
        self.assertEqual(1, summary["event_count"])
        self.assertEqual(str(output_root / "dirA" / "nested" / "huge.img"), summary["deepest_path"]["path"])
        self.assertEqual(3, summary["deepest_path"]["depth"])
        self.assertEqual(str(output_root / "summary.md"), result["summary_path"])
        self.assertEqual(str(output_root / "reason.md"), result["reason_path"])
        self.assertIn("Summary", result["summary_text"] or "")
        self.assertIn("Reason", result["reason_text"] or "")
        self.assertTrue(any(item["extension"] == ".img" for item in summary["file_extension_breakdown"]))
        self.assertTrue(any(item["extension"] == "(none)" for item in summary["file_extension_breakdown"]))
        self.assertEqual("dirA", summary["top_level_entries"][0]["name"])
        self.assertEqual(str(output_root / "dirA" / "nested" / "huge.img"), summary["largest_files"][0]["path"])
        self.assertGreater(summary["avg_file_size_bytes"], 0)
