from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.model import Base, B2STaskBatch, B2STaskItem
from app.schemas import AdvancedBatch, AdvancedFile, AdvancedRun, TaskItemAdvancedResponse
from app.service import task_service


def _item(sequence_no: int, *, status: str = "running") -> B2STaskItem:
    return B2STaskItem(
        id=f"item-{sequence_no}",
        task_id="task-1",
        project_id="project-1",
        sequence_no=sequence_no,
        elf_path=f"/tmp/demo-{sequence_no}.elf",
        output_dir=f"/tmp/out-{sequence_no}",
        status=status,
        phase="body",
        progress={},
    )


def _advanced(item: B2STaskItem, *, batches: list[AdvancedBatch], sessions: list[AdvancedFile]) -> TaskItemAdvancedResponse:
    return TaskItemAdvancedResponse(
        task_id=item.task_id,
        item_id=item.id,
        sequence_no=item.sequence_no,
        output_dir=item.output_dir,
        runs=[AdvancedRun(name="run-1", path=f"{item.output_dir}/run/runs/run-1", batches=batches, agent_sessions=sessions)],
        ida_files=[],
    )


def _review(path: Path, verdict: str, attempt_no: int) -> AdvancedFile:
    payload = {
        "verdict": verdict,
        "issues": [] if verdict == "PASS" else ["sub_401000: return value incorrect"],
        "total_functions": 3,
        "verified_functions": 3 if verdict == "PASS" else 1,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return AdvancedFile(
        name=path.name,
        path=str(path),
        kind="review",
        size=path.stat().st_size,
        content=json.dumps(payload),
        batch_no=1,
        attempt_no=attempt_no,
    )


class BatchObservabilityTests(unittest.TestCase):
    def test_builds_task_level_batch_rows_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine("sqlite:///:memory:")
            Base.metadata.create_all(bind=engine)
            SessionLocal = sessionmaker(bind=engine)
            db = SessionLocal()
            item1 = _item(1, status="running")
            item1.output_dir = str(Path(tmpdir) / "item1")
            item1.updated_at = datetime.now().astimezone()
            item1.progress = {"current_batch": 2, "current_attempt": 2, "current_function": "sub_402000"}
            item2 = _item(2, status="success")
            item2.output_dir = str(Path(tmpdir) / "item2")
            item2.updated_at = datetime.now().astimezone()
            db.add_all([
                B2STaskBatch(
                    id="b1",
                    task_id=item1.task_id,
                    project_id=item1.project_id,
                    item_id=item1.id,
                    sequence_no=item1.sequence_no,
                    batch_no=1,
                    status="running",
                    attempt_count=1,
                    current_attempt_no=1,
                    function_count=2,
                    duration_ms=5000,
                    last_event_at=item1.updated_at,
                ),
                B2STaskBatch(
                    id="b2",
                    task_id=item1.task_id,
                    project_id=item1.project_id,
                    item_id=item1.id,
                    sequence_no=item1.sequence_no,
                    batch_no=2,
                    status="running",
                    attempt_count=2,
                    current_attempt_no=2,
                    current_function="sub_402000",
                    function_count=4,
                    duration_ms=12500,
                    last_event_at=item1.updated_at,
                ),
                B2STaskBatch(
                    id="b3",
                    task_id=item2.task_id,
                    project_id=item2.project_id,
                    item_id=item2.id,
                    sequence_no=item2.sequence_no,
                    batch_no=1,
                    status="passed",
                    attempt_count=2,
                    latest_verdict="PASS",
                    latest_verdict_label="通过",
                    last_event_at=item2.updated_at,
                ),
                B2STaskBatch(
                    id="b4",
                    task_id=item2.task_id,
                    project_id=item2.project_id,
                    item_id=item2.id,
                    sequence_no=item2.sequence_no,
                    batch_no=2,
                    status="failed",
                    attempt_count=1,
                    latest_verdict="FAIL",
                    latest_verdict_label="失败",
                    last_event_at=item2.updated_at,
                ),
            ])
            db.commit()

            run_dir1 = Path(item1.output_dir) / "run" / "runs" / "run-1"
            run_dir2 = Path(item2.output_dir) / "run" / "runs" / "run-1"
            review_dir2 = run_dir2 / "review_snapshots"
            session_dir1 = run_dir1 / "agent_sessions"
            review_dir2.mkdir(parents=True)
            session_dir1.mkdir(parents=True)
            run_dir1.mkdir(parents=True, exist_ok=True)
            (run_dir1 / "batch_manifest.json").write_text(json.dumps({
                "batch_count": 2,
                "function_count": 6,
                "batches": [
                    {"id": 1, "total_size": 128, "functions": [{"name": "a"}, {"name": "b"}], "disasm_file": "disasm_batch_001.c", "output_file": "batch_001.c"},
                    {"id": 2, "total_size": 256, "functions": [{"name": "c"}, {"name": "d"}, {"name": "e"}, {"name": "f"}], "disasm_file": "disasm_batch_002.c", "output_file": "batch_002.c"},
                ],
            }), encoding="utf-8")
            session_path = session_dir1 / "executor_batch_002_attempt_02.jsonl"
            session_path.write_text("{}\n", encoding="utf-8")

            run_dir2.mkdir(parents=True, exist_ok=True)
            (run_dir2 / "batch_manifest.json").write_text(json.dumps({
                "batch_count": 2,
                "function_count": 5,
                "batches": [
                    {"id": 1, "total_size": 512, "functions": [{"name": "x"}, {"name": "y"}, {"name": "z"}], "disasm_file": "disasm_batch_001.c", "output_file": "batch_001.c", "result": {"attempts": 2, "verdict": "PASS", "func_count": 3}},
                    {"id": 2, "total_size": 64, "functions": [{"name": "w"}, {"name": "v"}], "disasm_file": "disasm_batch_002.c", "output_file": "batch_002.c", "result": {"attempts": 1, "verdict": "FAIL", "func_count": 2}},
                ],
            }), encoding="utf-8")
            (run_dir2 / "results.json").write_text(json.dumps({
                "results": [
                    {"batch_id": 1, "attempts": 2, "verdict": "PASS", "func_count": 3},
                    {"batch_id": 2, "attempts": 1, "verdict": "FAIL", "func_count": 2},
                ]
            }), encoding="utf-8")
            passed_review = _review(review_dir2 / "batch_001_attempt_02.verdict.json", "PASS", 2)
            failed_review = _review(review_dir2 / "batch_002_attempt_01.verdict.json", "FAIL", 1)

            advanced1 = _advanced(item1, batches=[], sessions=[
                AdvancedFile(
                    name=session_path.name,
                    path=str(session_path),
                    kind="agent_session",
                    size=session_path.stat().st_size,
                    stage="函数体恢复",
                    agent="executor agent",
                    role="executor",
                    batch_no=2,
                    attempt_no=2,
                )
            ])
            advanced2 = _advanced(item2, batches=[
                AdvancedBatch(name="batch_001", batch_no=1, reviews=[passed_review]),
                AdvancedBatch(name="batch_002", batch_no=2, reviews=[failed_review]),
            ], sessions=[])

            def fake_advanced(item: B2STaskItem, include_content: bool = False) -> TaskItemAdvancedResponse:
                return advanced1 if item.id == item1.id else advanced2

            with mock.patch.object(task_service, "build_task_item_advanced", side_effect=fake_advanced), \
                mock.patch.object(task_service, "get_db_session", return_value=db):
                summary = task_service.build_task_observability_summary([item1, item2])
            db.close()

        self.assertEqual(4, len(summary.batches))
        self.assertEqual(4, summary.batch_summary.total_batches)
        self.assertEqual(2, summary.batch_summary.running_batches)
        self.assertEqual(1, summary.batch_summary.passed_batches)
        self.assertEqual(1, summary.batch_summary.failed_batches)
        self.assertEqual(0, summary.batch_summary.pending_batches)

        runtime_running = next(row for row in summary.batches if row.item_id == item1.id and row.batch_no == 1)
        self.assertEqual("running", runtime_running.status)
        self.assertEqual(1, runtime_running.current_attempt_no)
        self.assertIsNone(runtime_running.current_function)

        running = next(row for row in summary.batches if row.item_id == item1.id and row.batch_no == 2)
        self.assertEqual("running", running.status)
        self.assertEqual(2, running.current_attempt_no)
        self.assertEqual("sub_402000", running.current_function)
        self.assertEqual(1, running.session_count)
        self.assertEqual(4, running.function_count)

        passed = next(row for row in summary.batches if row.item_id == item2.id and row.batch_no == 1)
        self.assertEqual("passed", passed.status)
        self.assertEqual("PASS", passed.latest_verdict)
        self.assertEqual(2, passed.attempt_count)

        failed = next(row for row in summary.batches if row.item_id == item2.id and row.batch_no == 2)
        self.assertEqual("failed", failed.status)
        self.assertEqual("FAIL", failed.latest_verdict)


if __name__ == "__main__":
    unittest.main()
