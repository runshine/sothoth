from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import tasks as tasks_api
from app.schemas import TaskItemAdvancedResponse, TaskObservabilitySummary, TokenUser
from app.service import task_service


PROJECT_ID = "2abc83006a7ca7a4"
TASK_ID = "ad38c8d3115f4967"
ITEM_ID = "6a0e2f5132a447b2"


def _empty_advanced_response() -> TaskItemAdvancedResponse:
    return TaskItemAdvancedResponse(
        task_id=TASK_ID,
        item_id=ITEM_ID,
        sequence_no=1,
        mode="deep",
        mode_label="深度模式",
        output_dir="/tmp/b2s/output",
        work_dir=None,
        runs=[],
        ida_files=[],
    )


class ReviewAnalyticsEmptyTests(unittest.TestCase):
    def test_build_review_analytics_without_review_files_returns_empty(self) -> None:
        item = SimpleNamespace(task_id=TASK_ID, id=ITEM_ID)
        with mock.patch.object(task_service, "build_task_item_advanced", return_value=_empty_advanced_response()):
            response = task_service.build_task_item_review_analytics(item)

        self.assertEqual(response.status, "empty")
        self.assertEqual(response.summary.final_verdict, "UNKNOWN")
        self.assertEqual(response.summary.final_verdict_label, "未评审")
        self.assertEqual(response.summary.attempt_count, 0)
        self.assertEqual(response.attempts, [])

    def test_review_analytics_endpoint_without_review_files_returns_empty(self) -> None:
        app = FastAPI()
        app.include_router(tasks_api.router)

        fake_task = SimpleNamespace(id=TASK_ID, project_id=PROJECT_ID, status="failed")
        fake_item = SimpleNamespace(id=ITEM_ID, task_id=TASK_ID, project_id=PROJECT_ID)

        async def fake_context(project_id: str, authorization: str | None = None) -> TokenUser:
            self.assertEqual(project_id, PROJECT_ID)
            return TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")

        def fake_db():
            yield object()

        app.dependency_overrides[tasks_api.get_current_context] = fake_context
        app.dependency_overrides[tasks_api.get_db] = fake_db

        with (
            mock.patch.object(tasks_api, "get_task_or_404", return_value=fake_task),
            mock.patch.object(tasks_api, "get_task_item_or_404", return_value=fake_item),
            mock.patch.object(task_service, "build_task_item_advanced", return_value=_empty_advanced_response()),
        ):
            client = TestClient(app)
            resp = client.get(
                f"/api/app/binary-to-source/projects/{PROJECT_ID}/tasks/{TASK_ID}/items/{ITEM_ID}/review-analytics",
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["status"], "empty")
        self.assertEqual(payload["summary"]["final_verdict"], "UNKNOWN")
        self.assertEqual(payload["summary"]["final_verdict_label"], "未评审")
        self.assertEqual(payload["summary"]["attempt_count"], 0)
        self.assertEqual(payload["attempts"], [])

    def test_item_observability_endpoint_returns_item_scoped_payload(self) -> None:
        app = FastAPI()
        app.include_router(tasks_api.router)

        fake_task = SimpleNamespace(id=TASK_ID, project_id=PROJECT_ID, status="running")
        fake_item = SimpleNamespace(id=ITEM_ID, task_id=TASK_ID, project_id=PROJECT_ID)
        fake_summary = TaskObservabilitySummary(task_id=TASK_ID, items=[], batches=[])

        async def fake_context(project_id: str, authorization: str | None = None) -> TokenUser:
            self.assertEqual(project_id, PROJECT_ID)
            return TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")

        def fake_db():
            yield object()

        app.dependency_overrides[tasks_api.get_current_context] = fake_context
        app.dependency_overrides[tasks_api.get_db] = fake_db

        with (
            mock.patch.object(tasks_api, "get_task_or_404", return_value=fake_task),
            mock.patch.object(tasks_api, "get_task_item_or_404", return_value=fake_item),
            mock.patch.object(tasks_api, "build_task_item_observability_summary", return_value=fake_summary) as build_summary,
        ):
            client = TestClient(app)
            resp = client.get(
                f"/api/app/binary-to-source/projects/{PROJECT_ID}/tasks/{TASK_ID}/items/{ITEM_ID}/observability",
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["task_id"], TASK_ID)
        build_summary.assert_called_once_with(fake_item)


if __name__ == "__main__":
    unittest.main()
