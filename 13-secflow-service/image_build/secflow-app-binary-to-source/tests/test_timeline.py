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
from app.schemas import TaskBatchDeleteRequest, TokenUser
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
