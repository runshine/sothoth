import tempfile
import unittest
from pathlib import Path

from app.model import VulnVerifyTask
from app.service.task_service import build_project_stats, task_matches_result_verdict


class VulnVerifyProjectStatsTests(unittest.TestCase):
    def _make_task(self, *, task_id: str, output_dir: str, result_summary: dict | None = None) -> VulnVerifyTask:
        task = VulnVerifyTask(
            id=task_id,
            project_id="p1",
            name=f"task-{task_id}",
            status="success",
            reports_dir=output_dir,
            source_root=output_dir,
            binary_root=output_dir,
            threat_path=str(Path(output_dir) / "threat.md"),
            output_dir=output_dir,
            concurrency=1,
            resume=0,
        )
        task.result_summary = result_summary or {}
        return task

    def test_build_project_stats_aggregates_task_summaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task_a = self._make_task(
                task_id="a1",
                output_dir=str(root / "a1"),
                result_summary={
                    "result_count": 4,
                    "confirmed_count": 2,
                    "ruled_out_count": 1,
                    "unresolved_count": 1,
                    "unverified_count": 0,
                },
            )
            task_b = self._make_task(
                task_id="b1",
                output_dir=str(root / "b1"),
                result_summary={
                    "result_count": 2,
                    "confirmed_count": 0,
                    "ruled_out_count": 2,
                    "unresolved_count": 0,
                    "unverified_count": 0,
                },
            )

            stats = build_project_stats([task_a, task_b])

            self.assertEqual(2, stats["total_tasks"])
            self.assertEqual(2, stats["verified_tasks"])
            self.assertEqual(6, stats["total_results"])
            self.assertEqual(2, stats["confirmed_count"])
            self.assertEqual(3, stats["ruled_out_count"])
            self.assertEqual(1, stats["unresolved_count"])
            self.assertEqual(0, stats["unverified_count"])

    def test_build_project_stats_backfills_legacy_summary_from_result_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_root = Path(tmp) / "legacy"
            verifier_output = task_root / "verifier_output"
            groups_dir = task_root / "groups" / "group_001"
            verifier_output.mkdir(parents=True)
            groups_dir.mkdir(parents=True)
            (task_root / "threat.md").write_text("threat", encoding="utf-8")
            (task_root / "verify.log").write_text("ok", encoding="utf-8")
            (verifier_output / "result_a.json").write_text('{"verdict":"confirmed"}', encoding="utf-8")
            (verifier_output / "result_b.json").write_text('{"verdict":"ruled_out"}', encoding="utf-8")
            (verifier_output / "result_c.json").write_text('{"verdict":"unresolved"}', encoding="utf-8")
            (verifier_output / "group_001.done").write_text("done", encoding="utf-8")

            legacy_task = self._make_task(
                task_id="legacy",
                output_dir=str(task_root),
                result_summary={"result_count": 3},
            )

            stats = build_project_stats([legacy_task])

            self.assertEqual(1, stats["total_tasks"])
            self.assertEqual(1, stats["verified_tasks"])
            self.assertEqual(3, stats["total_results"])
            self.assertEqual(1, stats["confirmed_count"])
            self.assertEqual(1, stats["ruled_out_count"])
            self.assertEqual(1, stats["unresolved_count"])

    def test_task_matches_result_verdict_backfills_legacy_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_root = Path(tmp) / "legacy-filter"
            verifier_output = task_root / "verifier_output"
            verifier_output.mkdir(parents=True)
            (task_root / "threat.md").write_text("threat", encoding="utf-8")
            (verifier_output / "result_a.json").write_text('{"verdict":"ruled_out"}', encoding="utf-8")

            legacy_task = self._make_task(
                task_id="legacy-filter",
                output_dir=str(task_root),
                result_summary={"result_count": 1},
            )

            self.assertTrue(task_matches_result_verdict(legacy_task, "ruled_out"))
            self.assertFalse(task_matches_result_verdict(legacy_task, "confirmed"))
            self.assertFalse(task_matches_result_verdict(legacy_task, "unresolved"))


if __name__ == "__main__":
    unittest.main()
