import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api.tasks as tasks_api_module
from app.api.tasks import get_current_context, get_current_user
from app.api.tasks import router as tasks_router
from app.exception import setup_exception_handlers
from app.model import get_db
from app.schemas import (
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityServiceConfigPayload,
    BinarySecurityServiceConfigResponse,
    BinarySecurityStageItemPageResponse,
    BinarySecurityStageItemResponse,
    BinarySecurityStageSummary,
    BinarySecurityTaskDetailResponse,
    TokenUser,
)


class _RouteManagerStub:
    def __init__(self):
        self.calls = []

    def get_task_detail(self, db, project_id, task_id):
        self.calls.append(("get_task_detail", db, project_id, task_id))
        return BinarySecurityTaskDetailResponse(
            id=task_id,
            project_id=project_id,
            task_type="source",
            name="streaming-task",
            status="pending",
            current_stage="dataflow_analysis",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            stage_summaries=[
                BinarySecurityStageSummary(
                    stage_name="dataflow_analysis",
                    sequence_no=3,
                    status="running",
                    running_items=1,
                )
            ],
            manual_operation_state={
                "overall": "blocked",
                "blocking_code": "task_running",
                "can_continue": False,
                "can_retry": False,
                "can_retry_failed_items": False,
            },
            policy={"pipeline_mode": "mixed_streaming"},
        )

    def get_task_stage_items_page(self, db, project_id, task_id, stage_name, page, per_page):
        self.calls.append(("get_task_stage_items_page", db, project_id, task_id, stage_name, page, per_page))
        return BinarySecurityStageItemPageResponse(
            task_id=task_id,
            stage_name=stage_name,
            total=1,
            page=page,
            per_page=per_page,
            items=[
                BinarySecurityStageItemResponse(
                    id="i-df-1",
                    stage_name=stage_name,
                    item_key="entry-a",
                    item_name="func_a",
                    parent_key="mod-a",
                    status="queued",
                    downstream_service="dataflow_analyse",
                    downstream_task_id="dfa-1",
                    input_ref={"upstream_item_id": "i-entry-1"},
                    sync_status="pending",
                    last_synced_at=None,
                )
            ],
        )

    def get_project_config(self, db, project_id):
        self.calls.append(("get_project_config", db, project_id))
        return BinarySecurityProjectConfigResponse(
            project_id=project_id,
            config=BinarySecurityProjectConfigPayload(pipeline_mode="mixed_streaming"),
        )

    def save_project_config(self, db, project_id, payload):
        self.calls.append(("save_project_config", db, project_id, payload))
        return BinarySecurityProjectConfigResponse(
            project_id=project_id,
            config=BinarySecurityProjectConfigPayload(
                pipeline_mode=payload.pipeline_mode,
                max_stage_parallelism=payload.max_stage_parallelism,
                max_retries_per_item=payload.max_retries_per_item,
                continue_on_item_failure=payload.continue_on_item_failure,
                partial_success_stage_advancement=payload.partial_success_stage_advancement,
                stage_parallelism=payload.stage_parallelism,
                stage_options=payload.stage_options,
            ),
        )

    def get_orchestration_observability(self, db, project_id, task_id):
        self.calls.append(("get_orchestration_observability", db, project_id, task_id))
        return {
            "state_events": {
                "status_counts": {"processing": 1, "retryable": 1},
                "oldest_active_age_seconds": 12.5,
                "processing": [{"id": "se-1", "stage_name": "dataflow_analysis"}],
                "dead_letters": [],
                "recent": [{"id": "se-2", "status": "retryable"}],
            },
            "task_state_lock": {
                "active": True,
                "owner_id": "reducer-1",
                "operation": "reduce",
                "lease_expires_at": None,
                "heartbeat_at": None,
            },
            "archive": {
                "by_stage": {
                    "dataflow_analysis": {"success": 1},
                }
            },
            "reconcile": {
                "latest_event_type": "downstream_status_synced",
                "latest_event_at": None,
                "latest_message": "streaming tail synced",
            },
            "files": {
                "summary_path": "/w/task-summary.json",
                "metadata_path": "/w/input/task-metadata.json",
            },
        }

    def get_service_config(self, db):
        self.calls.append(("get_service_config", db))
        return BinarySecurityServiceConfigResponse(
            config=BinarySecurityServiceConfigPayload(
                max_concurrent_tasks=12,
                dispatch_timeout_seconds=60,
                lease_timeout_seconds=90,
            )
        )


class TaskApiRouteTests(unittest.TestCase):
    def _build_client(self):
        app = FastAPI()
        app.include_router(tasks_router)
        setup_exception_handlers(app)

        fake_db = object()

        async def _context_override(project_id: str = "p1", authorization: str | None = None):
            del project_id, authorization
            return TokenUser(user_id="u1", username="tester", token_type="user")

        async def _user_override(authorization: str | None = None):
            del authorization
            return TokenUser(user_id="u1", username="tester", token_type="user")

        def _db_override():
            yield fake_db

        app.dependency_overrides[get_current_context] = _context_override
        app.dependency_overrides[get_current_user] = _user_override
        app.dependency_overrides[get_db] = _db_override
        return app, fake_db

    def test_get_task_detail_route_returns_streaming_tail_snapshot(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("mixed_streaming", payload["policy"]["pipeline_mode"])
        self.assertEqual("running", payload["stage_summaries"][0]["status"])
        self.assertEqual("task_running", payload["manual_operation_state"]["blocking_code"])
        self.assertEqual(("get_task_detail", fake_db, "p1", "t1"), manager.calls[0])

    def test_get_task_stage_items_route_preserves_pagination_and_lineage(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1/stage-items",
                    params={"stage_name": "dataflow_analysis", "page": 2, "per_page": 5},
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual(2, payload["page"])
        self.assertEqual(5, payload["per_page"])
        self.assertEqual("i-entry-1", payload["items"][0]["input_ref"]["upstream_item_id"])
        self.assertEqual(
            ("get_task_stage_items_page", fake_db, "p1", "t1", "dataflow_analysis", 2, 5),
            manager.calls[0],
        )

    def test_put_project_config_route_round_trips_pipeline_mode(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.put(
                    "/api/app/binary-security/projects/p1/config",
                    json={"pipeline_mode": "mixed_streaming"},
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("mixed_streaming", payload["config"]["pipeline_mode"])
        self.assertEqual("save_project_config", manager.calls[0][0])
        self.assertIs(fake_db, manager.calls[0][1])
        self.assertEqual("p1", manager.calls[0][2])
        self.assertEqual("mixed_streaming", manager.calls[0][3].pipeline_mode)

    def test_get_project_config_route_returns_pipeline_mode(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/config",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("mixed_streaming", payload["config"]["pipeline_mode"])
        self.assertEqual(("get_project_config", fake_db, "p1"), manager.calls[0])

    def test_get_orchestration_observability_route_returns_streaming_snapshot(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1/orchestration-observability",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual(1, payload["state_events"]["status_counts"]["processing"])
        self.assertTrue(payload["task_state_lock"]["active"])
        self.assertEqual("downstream_status_synced", payload["reconcile"]["latest_event_type"])
        self.assertEqual(
            ("get_orchestration_observability", fake_db, "p1", "t1"),
            manager.calls[0],
        )

    def test_get_service_config_route_returns_defaults(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/service/config",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual(12, payload["config"]["max_concurrent_tasks"])
        self.assertEqual(("get_service_config", fake_db), manager.calls[0])


if __name__ == "__main__":
    unittest.main()
