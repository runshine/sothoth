from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

from pydantic import ValidationError

from app.api import tasks as tasks_api
from app.schemas import TaskBatchDeleteRequest, TokenUser


PROJECT_ID = "project-1"


class _FakeQuery:
    def __init__(self, db: "_FakeDb") -> None:
        self.db = db

    def filter(self, *_args, **_kwargs) -> "_FakeQuery":
        return self

    def first(self):
        if not self.db.tasks:
            return None
        return self.db.tasks.pop(0)


class _FakeDb:
    def __init__(self, tasks) -> None:
        self.tasks = list(tasks)
        self.rollback_count = 0

    def query(self, *_args, **_kwargs) -> _FakeQuery:
        return _FakeQuery(self)

    def rollback(self) -> None:
        self.rollback_count += 1


def _token() -> TokenUser:
    return TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")


class BatchDeleteTests(unittest.TestCase):
    def test_batch_delete_deletes_existing_tasks_and_reports_missing(self) -> None:
        db = _FakeDb([SimpleNamespace(id="task-a"), None, SimpleNamespace(id="task-c")])

        async def run():
            with mock.patch.object(tasks_api, "delete_task", new=mock.AsyncMock()) as delete_mock:
                response = await tasks_api.batch_delete_b2s_tasks(
                    PROJECT_ID,
                    TaskBatchDeleteRequest(task_ids=["task-a", "missing", "task-c"]),
                    _token(),
                    db,
                )
            return response, delete_mock

        response, delete_mock = asyncio.run(run())

        self.assertEqual(response.status, "partial")
        self.assertEqual(response.deleted_count, 2)
        self.assertEqual(response.failed_count, 1)
        self.assertEqual([item.status for item in response.results], ["ok", "failed", "ok"])
        self.assertEqual(delete_mock.await_count, 2)

    def test_batch_delete_rolls_back_failed_item_and_continues(self) -> None:
        db = _FakeDb([SimpleNamespace(id="task-a"), SimpleNamespace(id="task-b")])

        async def delete_side_effect(_db, task):
            if task.id == "task-a":
                raise RuntimeError("delete failed")

        async def run():
            with mock.patch.object(tasks_api, "delete_task", new=mock.AsyncMock(side_effect=delete_side_effect)) as delete_mock:
                response = await tasks_api.batch_delete_b2s_tasks(
                    PROJECT_ID,
                    TaskBatchDeleteRequest(task_ids=["task-a", "task-b"]),
                    _token(),
                    db,
                )
            return response, delete_mock

        response, delete_mock = asyncio.run(run())

        self.assertEqual(response.status, "partial")
        self.assertEqual(response.deleted_count, 1)
        self.assertEqual(response.failed_count, 1)
        self.assertEqual(db.rollback_count, 1)
        self.assertEqual(delete_mock.await_count, 2)
        self.assertIn("delete failed", response.results[0].message or "")

    def test_batch_delete_deduplicates_task_ids(self) -> None:
        db = _FakeDb([SimpleNamespace(id="task-a")])

        async def run():
            with mock.patch.object(tasks_api, "delete_task", new=mock.AsyncMock()) as delete_mock:
                response = await tasks_api.batch_delete_b2s_tasks(
                    PROJECT_ID,
                    TaskBatchDeleteRequest(task_ids=["task-a", "task-a"]),
                    _token(),
                    db,
                )
            return response, delete_mock

        response, delete_mock = asyncio.run(run())

        self.assertEqual(response.status, "ok")
        self.assertEqual(response.deleted_count, 1)
        self.assertEqual(response.failed_count, 0)
        self.assertEqual(len(response.results), 1)
        self.assertEqual(delete_mock.await_count, 1)

    def test_batch_delete_rejects_empty_task_ids(self) -> None:
        with self.assertRaises(ValidationError):
            TaskBatchDeleteRequest(task_ids=[])


if __name__ == "__main__":
    unittest.main()
