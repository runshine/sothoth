import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.model import BinarySecurityEvent, BinarySecurityTask
from app.service.task_manager import TaskManager
from test_task_manager import _AppendingModelAwareDb


class TaskQueryServiceTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_get_timeline_compresses_repeat_events(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="p1",
            name="task",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        events = [
            BinarySecurityEvent(
                id="evt-1",
                task_id=task.id,
                project_id=task.project_id,
                event_type="owned_execution_takeover_requeued",
                message="takeover",
                stage_name="entry_analysis",
                level="warning",
                created_at=datetime.now(timezone.utc),
            ),
            BinarySecurityEvent(
                id="evt-2",
                task_id=task.id,
                project_id=task.project_id,
                event_type="owned_execution_takeover_requeued",
                message="takeover",
                stage_name="entry_analysis",
                level="warning",
                created_at=datetime.now(timezone.utc),
            ),
        ]
        db = _AppendingModelAwareDb(tasks=[task], events=events)

        timeline = self.manager.get_timeline(db, project_id="p1", task_id=task.id)

        self.assertEqual(1, len(timeline.events))
        self.assertTrue(timeline.events[0].compressed)
        self.assertEqual(2, timeline.events[0].repeat_count)

    def test_get_artifacts_groups_b2s_results_without_write_side_effects(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_index = Path(tmpdir) / "artifact-index.json"
            artifact_index.write_text(
                '{"version": 2, "artifacts": [{"relative_path": "out/a.c", "kind": "source", "size": 12}]}',
                encoding="utf-8",
            )
            task = BinarySecurityTask(
                id="task-1",
                project_id="p1",
                name="task",
                workspace_root=tmpdir,
                output_root=tmpdir,
            )
            task.summary = {
                "b2s_results": [
                    {
                        "module_key": "m1",
                        "module_name": "mod1",
                        "artifact_index_path": str(artifact_index),
                        "artifact_kind_summary": {"source": 1},
                        "result_kind_summary": {"source": 1},
                    }
                ]
            }
            db = _AppendingModelAwareDb(tasks=[task], events=[])

            with (
                patch.object(self.manager, "_enqueue_task", side_effect=AssertionError("query path must not enqueue")),
                patch.object(self.manager, "_record_event", side_effect=AssertionError("query path must not write events")),
            ):
                response = self.manager.get_artifacts(db, project_id="p1", task_id=task.id)

            self.assertTrue(response.grouped_by_index)
            self.assertEqual("m1", response.artifact_groups[0].module_key)
            self.assertEqual("out/a.c", response.artifact_groups[0].artifacts[0].relative_path)


if __name__ == "__main__":
    unittest.main()
