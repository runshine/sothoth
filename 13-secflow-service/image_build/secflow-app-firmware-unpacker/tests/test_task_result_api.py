import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "app"
for candidate in (PROJECT_ROOT, APP_ROOT):
    candidate_text = str(candidate)
    if candidate_text not in sys.path:
        sys.path.insert(0, candidate_text)

from app.api.firmware import _get_task_metrics, _get_task_result
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

    def _add_task(
        self,
        task_id: str,
        output_path: Path,
        *,
        status: str = "success",
        owner_id: str | None = None,
        current_stage: str | None = None,
        created_at: datetime | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        last_progress_at: datetime | None = None,
    ):
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
                    owner_id=owner_id,
                    current_stage=current_stage,
                    created_at=created_at,
                    started_at=started_at,
                    completed_at=completed_at,
                    last_progress_at=last_progress_at,
                )
            )
            db.commit()
        finally:
            db.close()

    def _add_event(self, task_id: str, *, event_type: str = "task_succeeded", summary: str = "任务执行成功", created_at: datetime | None = None):
        db = get_db_session()
        try:
            db.add(
                UnpackTaskEvent(
                    id=generate_id(),
                    task_id=task_id,
                    project_id="p1",
                    event_type=event_type,
                    summary=summary,
                    created_at=created_at,
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

    def test_get_task_result_prefers_cached_summary_without_rescanning_output(self):
        task_root = self.root / "task-cache"
        output_root = task_root / "output"
        run_root = task_root / "run"
        run_root.mkdir(parents=True, exist_ok=True)
        output_root.mkdir(parents=True, exist_ok=True)
        self._add_task("t-cache", output_root)

        cache_payload = {
            "schema_version": 1,
            "task_id": "t-cache",
            "available": True,
            "status": "success",
            "output_root": str(output_root),
            "run_root": str(run_root),
            "summary_path": None,
            "reason_path": None,
            "tokens_summary_path": None,
            "summary_text": None,
            "reason_text": None,
            "warnings": [],
            "summary": {
                "output_file_count": 7,
                "output_dir_count": 3,
                "output_total_size_bytes": 12345,
                "largest_file_path": str(output_root / "largest.bin"),
                "largest_file_size_bytes": 9000,
                "top_level_entry_count": 2,
                "top_level_entries": [],
                "file_extension_breakdown": [],
                "largest_files": [],
                "deepest_path": None,
                "avg_file_size_bytes": 1763,
                "small_file_count": 4,
                "medium_file_count": 2,
                "large_file_count": 1,
                "matched_skill": None,
                "fallback_to_llm": False,
                "generated_skill_path": None,
                "promotion_success_count": 0,
                "executor_rounds": 2,
                "session_count": 0,
                "event_count": 0,
                "started_at": None,
                "completed_at": None,
                "duration_seconds": None,
            },
        }
        (run_root / "task_result_cache.json").write_text(
            json.dumps(cache_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with patch("app.api.firmware._scan_output_tree", side_effect=AssertionError("should not rescan output")):
            result = _get_task_result("t-cache")

        self.assertTrue(result["available"])
        self.assertEqual(7, result["summary"]["output_file_count"])
        self.assertEqual(12345, result["summary"]["output_total_size_bytes"])

    def test_get_task_metrics_reads_cache_sessions_and_latest_event_without_scanning_output(self):
        now = datetime.now()
        task_root = self.root / "task-metrics"
        output_root = task_root / "output"
        run_root = task_root / "run"
        sessions_dir = run_root / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        output_root.mkdir(parents=True, exist_ok=True)
        self._add_task(
            "t-metrics",
            output_root,
            status="running",
            owner_id="pod-a:123:owner",
            current_stage="llm_unpack",
            created_at=now - timedelta(seconds=30),
            started_at=now - timedelta(seconds=20),
            last_progress_at=now - timedelta(seconds=3),
        )
        (sessions_dir / "index.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "items": [
                        {"role": "executor", "name": "round-1", "status": "running"},
                        {"role": "reviewer", "name": "round-1", "status": "closed"},
                        {"role": "cleaner", "name": "default", "status": "failed"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        (run_root / "task_result_cache.json").write_text(
            json.dumps(
                {
                    "available": True,
                    "status": "running",
                    "summary": {
                        "output_file_count": 8,
                        "output_dir_count": 2,
                        "output_total_size_bytes": 4096,
                        "largest_file_size_bytes": 2048,
                        "top_level_entry_count": 3,
                        "small_file_count": 6,
                        "medium_file_count": 2,
                        "large_file_count": 0,
                        "executor_rounds": 2,
                        "fallback_to_llm": True,
                        "matched_skill": "demo.skill",
                    },
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        self._add_event("t-metrics", event_type="task_started", summary="开始执行", created_at=now - timedelta(seconds=10))
        self._add_event("t-metrics", event_type="stage_changed", summary="进入 LLM 解包", created_at=now)

        with patch("app.api.firmware._scan_output_tree", side_effect=AssertionError("metrics must not scan output")):
            with patch("app.api.firmware.get_pod_resource_usage", return_value={
                "pod_name": "pod-a",
                "namespace": "secflow-ns",
                "cpu_millicores": 500,
                "memory_mib": 1024,
                "pod_cpu_limit_millicores": 2000,
                "pod_memory_limit_mib": 4096,
                "containers": [{"name": "app", "cpu_millicores": 500, "memory_mib": 1024}],
            }):
                metrics = _get_task_metrics("t-metrics")

        self.assertEqual("running", metrics["task"]["status"])
        self.assertEqual("llm_unpack", metrics["task"]["current_stage"])
        self.assertEqual(10, metrics["task"]["queue_wait_seconds"])
        self.assertTrue(metrics["resource"]["available"])
        self.assertEqual(25.0, metrics["resource"]["cpu_usage_percent"])
        self.assertEqual(25.0, metrics["resource"]["memory_usage_percent"])
        self.assertEqual(2, metrics["events"]["event_count"])
        self.assertEqual("stage_changed", metrics["events"]["latest_event_type"])
        self.assertEqual(3, metrics["sessions"]["session_count"])
        self.assertEqual(1, metrics["sessions"]["running_session_count"])
        self.assertEqual(1, metrics["sessions"]["closed_session_count"])
        self.assertEqual(1, metrics["sessions"]["failed_session_count"])
        self.assertTrue(metrics["result"]["cache_available"])
        self.assertEqual(4096, metrics["result"]["output_total_size_bytes"])
        self.assertTrue(metrics["result"]["fallback_to_llm"])
        self.assertEqual("demo.skill", metrics["result"]["matched_skill"])

    def test_get_task_metrics_reports_missing_cache_warning(self):
        output_root = self.root / "task-no-cache" / "output"
        output_root.mkdir(parents=True, exist_ok=True)
        self._add_task("t-no-cache", output_root, status="success")

        metrics = _get_task_metrics("t-no-cache")

        self.assertFalse(metrics["result"]["cache_available"])
        self.assertFalse(metrics["health"]["result_cache_available"])
        self.assertTrue(any("结果缓存不存在" in warning for warning in metrics["health"]["warnings"]))
