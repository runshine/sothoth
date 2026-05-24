from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.model import B2STaskItem
from app.service.task_service import build_task_item_artifacts, build_task_result_summary


def _item(*, item_id: str, output_dir: str, status: str = "success") -> B2STaskItem:
    return B2STaskItem(
        id=item_id,
        task_id="task-1",
        project_id="project-1",
        sequence_no=1,
        elf_path="/tmp/sample.elf",
        output_dir=output_dir,
        status=status,
        generated_files=[],
    )


class ResultKindSummaryTests(unittest.TestCase):
    def test_artifacts_capture_source_header_metadata_sessions_and_reviews(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "run" / "runs" / "run-1"
            review_dir = work / "review_snapshots"
            session_dir = work / "agent_sessions" / "executor"
            work.mkdir(parents=True)
            review_dir.mkdir(parents=True)
            session_dir.mkdir(parents=True)
            (root / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            (root / "main.h").write_text("#pragma once\n", encoding="utf-8")
            modules_dir = root / "modules" / "sample"
            modules_dir.mkdir(parents=True)
            (modules_dir / "files.list").write_text("main.c\nmain.h\n", encoding="utf-8")
            (work / "metadata.json").write_text("{}", encoding="utf-8")
            (work / "results.json").write_text("{}", encoding="utf-8")
            (review_dir / "batch_001_attempt_1.verdict.json").write_text("{}", encoding="utf-8")
            (session_dir / "batch_001.jsonl").write_text("{}\n", encoding="utf-8")

            artifacts = build_task_item_artifacts(_item(item_id="item-1", output_dir=str(root)))

            self.assertEqual("recovered_source", artifacts.primary_result_kind)
            self.assertIn("recovered_source", artifacts.result_kinds)
            self.assertIn("recovered_header", artifacts.result_kinds)
            self.assertIn("entry_descriptor", artifacts.result_kinds)
            self.assertIn("analysis_metadata", artifacts.result_kinds)
            self.assertIn("agent_session", artifacts.result_kinds)
            self.assertIn("review_record", artifacts.result_kinds)
            self.assertEqual(1, artifacts.result_kind_summary["recovered_source"])
            self.assertEqual(1, artifacts.result_kind_summary["recovered_header"])
            self.assertEqual(1, artifacts.result_kind_summary["entry_descriptor"])
            self.assertEqual(1, artifacts.result_kind_summary["analysis_metadata"])
            self.assertTrue(artifacts.artifact_index_path)
            index_payload = json.loads(Path(artifacts.artifact_index_path).read_text(encoding="utf-8"))
            self.assertEqual(1, index_payload["version"])
            self.assertEqual("recovered_source", index_payload["primary_result_kind"])
            self.assertTrue(index_payload["artifacts"])

    def test_entry_descriptor_becomes_primary_when_no_source_exists(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            modules_dir = root / "modules" / "sample"
            modules_dir.mkdir(parents=True)
            (modules_dir / "files.list").write_text("ghost.c\n", encoding="utf-8")

            artifacts = build_task_item_artifacts(_item(item_id="item-2", output_dir=str(root)))

            self.assertEqual("entry_descriptor", artifacts.primary_result_kind)
            self.assertEqual(["entry_descriptor"], artifacts.result_kinds)

    def test_result_summary_exposes_lightweight_type_fields(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")

            summary = build_task_result_summary([_item(item_id="item-3", output_dir=str(root))])

            self.assertEqual(1, len(summary.items))
            row = summary.items[0]
            self.assertEqual("recovered_source", row.primary_result_kind)
            self.assertEqual(["recovered_source"], row.result_kinds)
            self.assertTrue(row.artifact_index_path)
            self.assertEqual(1, row.result_summary_version)

    def test_ida_outputs_are_intermediate_not_final_results(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main_ida.c").write_text("int ida_main(void){return 0;}\n", encoding="utf-8")
            (root / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")

            artifacts = build_task_item_artifacts(_item(item_id="item-4", output_dir=str(root)))

            self.assertEqual("recovered_source", artifacts.primary_result_kind)
            self.assertEqual(1, artifacts.result_kind_summary["recovered_source"])
            self.assertNotIn("batch_intermediate", artifacts.result_kinds)
            self.assertEqual(1, artifacts.artifact_summary["ida_intermediate"])
            index_payload = json.loads(Path(artifacts.artifact_index_path).read_text(encoding="utf-8"))
            ida_rows = [row for row in index_payload["artifacts"] if row.get("kind") == "ida_intermediate"]
            self.assertEqual(1, len(ida_rows))


if __name__ == "__main__":
    unittest.main()
