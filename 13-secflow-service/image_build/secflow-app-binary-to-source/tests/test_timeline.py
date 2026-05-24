from __future__ import annotations

import asyncio
from datetime import timedelta
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import tasks as tasks_api
from app.model import Base, B2STask, B2STaskEvent, B2STaskItem
from app.schemas import B2SAgentSessionRuntimeSummary, TaskBatchDeleteRequest, TokenUser
from app.service import task_service
from app.time_utils import now_local


def _token() -> TokenUser:
    return TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")


class TimelineServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        self.Session = sessionmaker(bind=engine)
        self.db = self.Session()
        self.task = B2STask(id="task-1", project_id="project-1", name="demo", status="running")
        self.item = B2STaskItem(
            id="item-1",
            task_id="task-1",
            project_id="project-1",
            sequence_no=1,
            elf_path="/tmp/demo.elf",
            output_dir="/tmp/out",
            status="running",
            phase="body",
        )
        self.db.add(self.task)
        self.db.add(self.item)
        self.db.flush()

    def tearDown(self) -> None:
        self.db.close()

    def _event(self, event_id: str, event_type: str, created_at_offset: int = 0) -> B2STaskEvent:
        event = B2STaskEvent(
            id=event_id,
            task_id=self.task.id,
            project_id=self.task.project_id,
            item_id=self.item.id,
            sequence_no=self.item.sequence_no,
            source="b2s",
            level="info",
            event_type=event_type,
            phase="body",
            status="running",
            message=event_type,
            dedupe_key=f"{self.task.id}|{event_id}|{event_type}",
            created_at=now_local() + timedelta(seconds=created_at_offset),
        )
        event.payload = {"offset": created_at_offset}
        return event

    def test_get_task_timeline_returns_events(self) -> None:
        self.db.add(self._event("evt-1", "task_created", 0))
        self.db.add(self._event("evt-2", "phase_changed", 1))
        self.db.commit()

        timeline = task_service.get_task_timeline(self.db, self.task)

        self.assertEqual(self.task.id, timeline.task_id)
        self.assertEqual(["phase_changed", "task_created"], [event.event_type for event in timeline.events])

    def test_clear_and_delete_timeline_event(self) -> None:
        self.db.add(self._event("evt-1", "task_created"))
        self.db.add(self._event("evt-2", "phase_changed"))
        self.db.commit()

        deleted_one = task_service.delete_task_timeline_event(self.db, self.task, "evt-1")
        self.db.commit()
        deleted_all = task_service.clear_task_timeline(self.db, self.task)

        self.assertEqual(1, deleted_one)
        self.assertEqual(1, deleted_all)

    def test_build_task_detail_exposes_phase_timings(self) -> None:
        started_at = now_local() - timedelta(minutes=15)
        finished_at = now_local() - timedelta(minutes=1)
        self.item.phase = "body"
        self.item.status = "running"
        self.item.started_at = started_at
        self.item.finished_at = None
        completed = B2STaskItem(
            id="item-2",
            task_id=self.task.id,
            project_id=self.task.project_id,
            sequence_no=2,
            elf_path="/tmp/demo2.elf",
            output_dir="/tmp/out2",
            status="success",
            phase="header",
            started_at=started_at,
            finished_at=finished_at,
        )
        self.db.add(completed)
        self.db.commit()

        with (
            mock.patch.object(
                task_service,
                "build_task_agent_session_runtime",
                return_value=mock.Mock(summary=B2SAgentSessionRuntimeSummary(task_id=self.task.id)),
            ),
            mock.patch.object(task_service, "build_task_config_snapshot", return_value=None),
            mock.patch.object(task_service, "build_effective_llm_provider", return_value=None),
            mock.patch.object(task_service, "build_agent_runtime_summary", return_value=None),
            mock.patch.object(task_service, "build_task_result_summary", return_value=None),
        ):
            detail = task_service.build_task_detail(self.db, self.task)

        header = next(row for row in detail.phase_timings if row.phase == "header")
        body = next(row for row in detail.phase_timings if row.phase == "body")
        self.assertEqual(1, header.current_items)
        self.assertIsNotNone(header.started_at)
        self.assertIsNotNone(header.finished_at)
        self.assertGreaterEqual(int(header.duration_ms or 0), 0)
        self.assertEqual(1, body.current_items)
        self.assertTrue(body.is_active)
        self.assertIsNotNone(body.started_at)

    def test_build_task_detail_exposes_item_phase_observability_from_events(self) -> None:
        base = now_local()
        self.item.status = "success"
        self.item.phase = "completed"
        self.item.started_at = base
        self.item.finished_at = base + timedelta(minutes=6)
        self.db.add(self._event("evt-q", "phase_changed", 0))
        queued = self.db.query(B2STaskEvent).filter_by(id="evt-q").one()
        queued.phase = "queued"
        self.db.add(self._event("evt-ida", "phase_changed", 60))
        ida = self.db.query(B2STaskEvent).filter_by(id="evt-ida").one()
        ida.phase = "ida"
        self.db.add(self._event("evt-body", "phase_changed", 180))
        body = self.db.query(B2STaskEvent).filter_by(id="evt-body").one()
        body.phase = "body"
        self.db.add(self._event("evt-merge", "phase_changed", 300))
        merge = self.db.query(B2STaskEvent).filter_by(id="evt-merge").one()
        merge.phase = "merge"
        self.db.add(self._event("evt-done", "job_completed", 360))
        done = self.db.query(B2STaskEvent).filter_by(id="evt-done").one()
        done.phase = "completed"
        self.db.commit()

        with (
            mock.patch.object(
                task_service,
                "build_task_agent_session_runtime",
                return_value=mock.Mock(summary=B2SAgentSessionRuntimeSummary(task_id=self.task.id)),
            ),
            mock.patch.object(task_service, "build_task_config_snapshot", return_value=None),
            mock.patch.object(task_service, "build_effective_llm_provider", return_value=None),
            mock.patch.object(task_service, "build_agent_runtime_summary", return_value=None),
            mock.patch.object(task_service, "build_task_result_summary", return_value=None),
        ):
            detail = task_service.build_task_detail(self.db, self.task)

        item = detail.items[0]
        queued_phase = next(row for row in item.phase_observability if row.phase == "queued")
        ida_phase = next(row for row in item.phase_observability if row.phase == "ida")
        merge_phase = next(row for row in item.phase_observability if row.phase == "merge")
        self.assertIsNotNone(queued_phase.started_at)
        self.assertIsNotNone(queued_phase.finished_at)
        self.assertGreaterEqual(int(queued_phase.duration_ms or 0), 0)
        self.assertIsNotNone(ida_phase.started_at)
        self.assertIsNotNone(merge_phase.finished_at)

    def test_record_item_snapshot_events_uses_body_phase_batch_events(self) -> None:
        previous = {
            "progress": {
                "phase": "header",
                "current_batch": None,
                "current_attempt": None,
                "current_function": None,
                "completed_batches": 0,
            }
        }
        self.item.phase = "body"
        self.item.status = "running"
        self.item.progress = {
            "phase": "body",
            "current_batch": 2,
            "current_attempt": 1,
            "current_function": "sub_401000",
            "completed_batches": 0,
            "completed_functions": 1,
        }
        self.item.updated_at = now_local()

        task_service._record_item_snapshot_events(
            self.db,
            task=self.task,
            item=self.item,
            previous=previous,
            source="b2s",
        )
        self.db.commit()

        event_types = [row.event_type for row in self.db.query(B2STaskEvent).order_by(B2STaskEvent.created_at.asc()).all()]
        self.assertIn("body_batch_started", event_types)
        self.assertIn("batch_attempt_started", event_types)
        self.assertIn("function_progress", event_types)
        self.assertNotIn("batch_started", event_types)
        self.assertNotIn("batch_completed", event_types)

    def test_delete_task_returns_deleted_event_count(self) -> None:
        self.db.add(self._event("evt-1", "task_created"))
        self.db.add(self._event("evt-2", "phase_changed"))
        self.db.commit()

        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir) / "project-1"
            task_root = project_root / "secflow-app-binary-to-source" / self.task.id
            task_root.mkdir(parents=True)
            (task_root / "marker.txt").write_text("ok")

            with (
                mock.patch.object(task_service, "project_root", return_value=project_root),
                mock.patch.object(task_service, "app_task_root", return_value=task_root),
            ):
                deleted_event_count = asyncio.run(task_service.delete_task(self.db, self.task))

        self.assertEqual(2, deleted_event_count)
        self.assertEqual([], self.db.query(B2STaskEvent).all())
        self.assertEqual([], self.db.query(B2STaskItem).all())
        self.assertEqual([], self.db.query(B2STask).all())


class TimelineBatchDeleteApiTests(unittest.TestCase):
    def test_batch_delete_sums_deleted_event_count(self) -> None:
        class _FakeQuery:
            def __init__(self, rows):
                self._rows = list(rows)

            def filter(self, *_args, **_kwargs):
                return self

            def first(self):
                return self._rows.pop(0) if self._rows else None

        class _FakeDb:
            def __init__(self):
                self.rows = [mock.Mock(id="task-a"), mock.Mock(id="task-b")]
                self.rollback_count = 0

            def query(self, *_args, **_kwargs):
                return _FakeQuery(self.rows)

            def rollback(self):
                self.rollback_count += 1

        fake_db = _FakeDb()

        async def _run():
            with mock.patch.object(tasks_api, "delete_task", new=mock.AsyncMock(side_effect=[2, 3])):
                return await tasks_api.batch_delete_b2s_tasks(
                    "project-1",
                    TaskBatchDeleteRequest(task_ids=["task-a", "task-b"]),
                    _token(),
                    fake_db,
                )

        response = asyncio.run(_run())

        self.assertEqual("ok", response.status)
        self.assertEqual(2, response.deleted_count)
        self.assertEqual(5, response.deleted_event_count)
        self.assertEqual([2, 3], [item.deleted_event_count for item in response.results])


if __name__ == "__main__":
    unittest.main()
