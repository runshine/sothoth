import json
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
                payload={
                    "recorder": {
                        "service": "binary-security",
                        "role": "worker",
                        "instance_id": "worker-a",
                        "hostname": "worker-a",
                        "pod_name": "worker-a",
                        "node_name": "node-a",
                    }
                },
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
                payload={
                    "recorder": {
                        "service": "binary-security",
                        "role": "worker",
                        "instance_id": "worker-a",
                        "hostname": "worker-a",
                        "pod_name": "worker-a",
                        "node_name": "node-a",
                    }
                },
                created_at=datetime.now(timezone.utc),
            ),
        ]
        db = _AppendingModelAwareDb(tasks=[task], events=events)

        timeline = self.manager.get_timeline(db, project_id="p1", task_id=task.id)

        self.assertEqual(1, len(timeline.events))
        self.assertTrue(timeline.events[0].compressed)
        self.assertEqual(2, timeline.events[0].repeat_count)
        self.assertEqual("worker-a", timeline.events[0].recorder_pod_name)

    def test_get_timeline_does_not_compress_events_from_different_recorders(self):
        task = BinarySecurityTask(
            id="task-2",
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
                payload={"recorder": {"pod_name": "worker-a", "hostname": "worker-a", "instance_id": "worker-a", "role": "worker"}},
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
                payload={"recorder": {"pod_name": "worker-b", "hostname": "worker-b", "instance_id": "worker-b", "role": "worker"}},
                created_at=datetime.now(timezone.utc),
            ),
        ]
        db = _AppendingModelAwareDb(tasks=[task], events=events)

        timeline = self.manager.get_timeline(db, project_id="p1", task_id=task.id)

        self.assertEqual(2, len(timeline.events))
        self.assertFalse(any(event.compressed for event in timeline.events))
        self.assertTrue(all(event.payload_available for event in timeline.events))
        self.assertFalse(hasattr(timeline.events[0], "payload"))

    def test_get_timeline_event_returns_full_payload_for_single_record(self):
        task = BinarySecurityTask(
            id="task-3",
            project_id="p1",
            name="task",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        event = BinarySecurityEvent(
            id="evt-detail-1",
            task_id=task.id,
            project_id=task.project_id,
            event_type="parent_task_state_transition",
            message="state updated",
            stage_name="system_analysis",
            level="info",
            payload={"changed_fields": ["status", "dispatcher_instance_id"], "raw": {"hello": "world"}},
            created_at=datetime.now(timezone.utc),
        )
        db = _AppendingModelAwareDb(tasks=[task], events=[event])

        detail = self.manager.get_timeline_event(db, project_id="p1", task_id=task.id, event_id=event.id)

        self.assertEqual(event.id, detail.id)
        self.assertTrue(detail.payload_available)
        self.assertEqual({"changed_fields": ["status", "dispatcher_instance_id"], "raw": {"hello": "world"}}, detail.payload)
        self.assertIn("status", detail.message)

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

    def test_list_delete_queue_returns_cross_project_items_and_project_names(self):
        queued = BinarySecurityTask(
            id="task-delete-queued",
            project_id="p1",
            name="queued-task",
            task_type="source",
            status="delete_requested",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        queued.cleanup_snapshot_json = json.dumps(
            {
                "delete_queued": True,
                "delete_queue_requested_at": "2026-06-28T12:00:00Z",
            }
        )
        running = BinarySecurityTask(
            id="task-delete-running",
            project_id="p2",
            name="running-task",
            task_type="source",
            status="deleting",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        running.cleanup_snapshot_json = json.dumps(
            {
                "delete_queued": True,
                "delete_in_progress": True,
                "delete_queue_requested_at": "2026-06-28T12:00:00Z",
                "delete_started_at": "2026-06-28T12:05:00Z",
            }
        )
        failed = BinarySecurityTask(
            id="task-delete-failed",
            project_id="p3",
            name="failed-task",
            task_type="source",
            status="delete_failed",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            last_error="cleanup failed",
        )
        failed.cleanup_snapshot_json = json.dumps(
            {
                "delete_queued": True,
                "delete_queue_requested_at": "2026-06-28T12:00:00Z",
                "delete_last_error": "cleanup failed",
            }
        )
        db = _AppendingModelAwareDb(tasks=[queued, running, failed], events=[])

        with patch.object(
            self.manager,
            "_task_list_project_names",
            return_value={"p1": "Project One", "p2": "Project Two", "p3": "Project Three"},
        ) as names_mock:
            response = self.manager.list_delete_queue(
                db,
                token="token-1",
                page=1,
                page_size=20,
            )

        self.assertEqual(3, response.total)
        self.assertEqual({"queued_total": 1, "running_total": 1, "blocked_total": 0, "failed_total": 1}, response.stats)
        self.assertEqual(["task-delete-queued", "task-delete-running", "task-delete-failed"], [item.id for item in response.items])
        self.assertEqual("Project One", response.items[0].project_name)
        self.assertEqual("queued", response.items[0].delete_status)
        self.assertEqual("running", response.items[1].delete_status)
        self.assertEqual("failed", response.items[2].delete_status)
        names_mock.assert_called_once()

    def test_list_delete_queue_filters_project_and_task_type(self):
        source_task = BinarySecurityTask(
            id="source-delete",
            project_id="p1",
            name="source-delete",
            task_type="source",
            status="delete_requested",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        source_task.cleanup_snapshot_json = json.dumps({"delete_queued": True})
        kg_task = BinarySecurityTask(
            id="kg-delete",
            project_id="p1",
            name="kg-delete",
            task_type="source",
            status="delete_requested",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        kg_task.policy_json = json.dumps({"pipeline_profile": "kg_source_vuln_scan"})
        kg_task.cleanup_snapshot_json = json.dumps({"delete_queued": True})
        other_project = BinarySecurityTask(
            id="other-project-delete",
            project_id="p2",
            name="other-project-delete",
            task_type="source",
            status="delete_requested",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        other_project.cleanup_snapshot_json = json.dumps({"delete_queued": True})
        db = _AppendingModelAwareDb(tasks=[source_task, kg_task, other_project], events=[])

        response = self.manager.list_delete_queue(
            db,
            project_id="p1",
            task_type="kg_source_vuln_scan_e2e",
            page=1,
            page_size=20,
        )

        self.assertEqual(1, response.total)
        self.assertEqual("kg-delete", response.items[0].id)
        self.assertEqual("kg_source_vuln_scan_e2e", response.items[0].task_type)

    def test_list_delete_queue_project_name_lookup_failure_does_not_fail_response(self):
        task = BinarySecurityTask(
            id="task-delete-1",
            project_id="p1",
            name="delete-task",
            task_type="source",
            status="delete_failed",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
        )
        task.cleanup_snapshot_json = json.dumps(
            {
                "delete_queued": True,
                "delete_queue_requested_at": "2026-06-28T12:00:00Z",
            }
        )
        db = _AppendingModelAwareDb(tasks=[task], events=[])

        with patch.object(self.manager, "_task_list_project_names", return_value={"p1": None}):
            response = self.manager.list_delete_queue(
                db,
                token="token-1",
                task_type="source_scan_e2e",
                page=1,
                page_size=20,
            )

        self.assertEqual(1, response.total)
        self.assertEqual("task-delete-1", response.items[0].id)
        self.assertEqual("failed", response.items[0].delete_status)
        self.assertIsNone(response.items[0].project_name)

    def test_list_delete_queue_sorts_by_updated_at(self):
        older = BinarySecurityTask(
            id="older-task",
            project_id="p1",
            name="older",
            task_type="binary_module",
            status="delete_requested",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            updated_at=datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc),
        )
        older.cleanup_snapshot_json = json.dumps({"delete_queued": True})
        newer = BinarySecurityTask(
            id="newer-task",
            project_id="p1",
            name="newer",
            task_type="binary_module",
            status="delete_requested",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            updated_at=datetime(2026, 6, 28, 13, 0, 0, tzinfo=timezone.utc),
        )
        newer.cleanup_snapshot_json = json.dumps({"delete_queued": True})
        db = _AppendingModelAwareDb(tasks=[older, newer], events=[])

        response = self.manager.list_delete_queue(
            db,
            task_type="binary_module_e2e",
            sort_by="updated_at",
            sort_direction="asc",
            page=1,
            page_size=20,
        )

        self.assertEqual(["older-task", "newer-task"], [item.id for item in response.items])


if __name__ == "__main__":
    unittest.main()
