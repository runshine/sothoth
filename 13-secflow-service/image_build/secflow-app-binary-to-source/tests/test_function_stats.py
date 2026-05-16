from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.model import B2STaskItem
from app.service.task_service import build_task_function_stats, refresh_item_function_stats


def _item(*, item_id: str, output_dir: str, status: str) -> B2STaskItem:
    return B2STaskItem(
        id=item_id,
        task_id="task-1",
        project_id="project-1",
        sequence_no=1,
        elf_path="/tmp/sample.elf",
        output_dir=output_dir,
        status=status,
    )


class FunctionStatsTests(unittest.TestCase):
    def test_results_json_populates_total_completed_failed_and_uncompleted(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / ".re_work_001" / "runs" / "20260516010101"
            run_dir.mkdir(parents=True)
            (run_dir / "batch_manifest.json").write_text(json.dumps({"function_count": 10}), "utf-8")
            (run_dir / "results.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {"verdict": "PASS", "func_count": 6},
                            {"verdict": "FAIL", "func_count": 2},
                        ]
                    }
                ),
                "utf-8",
            )

            item = _item(item_id="item-1", output_dir=str(root), status="partial")

            self.assertTrue(refresh_item_function_stats(item, inspect_files=True))
            self.assertEqual(
                build_task_function_stats([item]),
                {
                    "total_functions": 10,
                    "completed_functions": 6,
                    "failed_functions": 2,
                    "uncompleted_functions": 4,
                },
            )
            self.assertFalse(refresh_item_function_stats(item, inspect_files=True))

    def test_success_item_falls_back_to_file_list(self) -> None:
        item = _item(item_id="item-2", output_dir="/tmp/missing-output", status="success")
        item.extra_metadata = {"file_list": ["f1", "f2", "f3"]}

        self.assertTrue(refresh_item_function_stats(item, inspect_files=True))
        self.assertEqual(
            build_task_function_stats([item]),
            {
                "total_functions": 3,
                "completed_functions": 3,
                "failed_functions": 0,
                "uncompleted_functions": 0,
            },
        )

    def test_failed_item_without_results_keeps_failure_count_unknown(self) -> None:
        item = _item(item_id="item-3", output_dir="/tmp/missing-output", status="failed")
        item.extra_metadata = {"file_list": ["f1", "f2"]}

        self.assertTrue(refresh_item_function_stats(item, inspect_files=True))
        self.assertEqual(
            build_task_function_stats([item]),
            {
                "total_functions": 2,
                "completed_functions": 0,
                "failed_functions": None,
                "uncompleted_functions": 2,
            },
        )


if __name__ == "__main__":
    unittest.main()
