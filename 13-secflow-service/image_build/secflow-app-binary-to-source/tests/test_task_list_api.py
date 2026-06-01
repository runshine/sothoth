from __future__ import annotations

import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import tasks as tasks_api
from app.schemas import TaskResponse, TokenUser


PROJECT_ID = "44f9029d00650a10"


class _FakeQuery:
    def __init__(self, tasks: list[SimpleNamespace]) -> None:
        self._tasks = tasks

    def filter(self, *args, **kwargs):
        return self

    def count(self) -> int:
        return len(self._tasks)

    def order_by(self, *args, **kwargs):
        return self

    def offset(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def all(self) -> list[SimpleNamespace]:
        return self._tasks


class _FakeSession:
    def __init__(self, tasks: list[SimpleNamespace]) -> None:
        self._tasks = tasks

    def query(self, *args, **kwargs):
        return _FakeQuery(self._tasks)


class TaskListApiTests(unittest.TestCase):
    def test_list_tasks_created_at_sort_does_not_touch_missing_task_columns(self) -> None:
        app = FastAPI()
        app.include_router(tasks_api.router)

        fake_task = SimpleNamespace(
            id="b2s-task-001",
            project_id=PROJECT_ID,
            task_origin_type="binary_module",
            parent_project_id=None,
            parent_task_id=None,
            parent_task_type=None,
            parent_stage_name=None,
            parent_stage_item_id=None,
            parent_stage_item_key=None,
            name="demo task",
            status="running",
            created_at=datetime(2026, 6, 2, 12, 0, 0),
            updated_at=datetime(2026, 6, 2, 12, 5, 0),
            latest_abnormal_reason=None,
        )

        fake_response = TaskResponse(
            id=fake_task.id,
            project_id=PROJECT_ID,
            name="demo task",
            status="running",
            total_items=1,
            pending_items=0,
            queued_items=0,
            running_items=1,
            success_items=0,
            partial_items=0,
            failed_items=0,
            cancelled_items=0,
            created_at=fake_task.created_at,
            updated_at=fake_task.updated_at,
            input_filenames=[],
        )

        async def fake_context(project_id: str, authorization: str | None = None) -> TokenUser:
            self.assertEqual(project_id, PROJECT_ID)
            return TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")

        def fake_db():
            yield _FakeSession([fake_task])

        app.dependency_overrides[tasks_api.get_current_context] = fake_context
        app.dependency_overrides[tasks_api.get_db] = fake_db

        with mock.patch.object(tasks_api, "build_task_response", return_value=fake_response):
            client = TestClient(app)
            resp = client.get(
                f"/api/app/binary-to-source/projects/{PROJECT_ID}/tasks?sort_by=created_at&sort_order=desc&limit=20&offset=0",
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["items"][0]["id"], fake_task.id)


if __name__ == "__main__":
    unittest.main()
