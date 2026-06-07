import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

import app.api.tasks as tasks_api_module
from app.api.tasks import get_current_context, get_current_user
from app.api.tasks import router as tasks_router
from app.exception import UpstreamError, setup_exception_handlers
from app.model import get_db
from app.service.project import ProjectService
from app.schemas import (
    BinarySecurityAbnormalReasonHistoryResponse,
    BinarySecurityArchiveJobPageResponse,
    BinarySecurityEntrySelectionResponse,
    BinarySecurityOverviewResponse,
    BinarySecurityProjectStats,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityServiceConfigPayload,
    BinarySecurityServiceConfigResponse,
    BinarySecurityStageItemPageResponse,
    BinarySecurityStageItemResponse,
    BinarySecurityStageSummary,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskResponse,
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
            current_stage="dataflow_vuln_scan",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            stage_summaries=[
                BinarySecurityStageSummary(
                    stage_name="dataflow_vuln_scan",
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
                    downstream_service="dataflow_vuln_scan",
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
                "processing": [{"id": "se-1", "stage_name": "dataflow_vuln_scan"}],
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
                    "dataflow_vuln_scan": {"success": 1},
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

    def get_task_overview(self, db, project_id, task_id):
        self.calls.append(("get_task_overview", db, project_id, task_id))
        return BinarySecurityOverviewResponse(task_id=task_id, nodes=[])

    def get_task_archive_jobs_page(self, db, project_id, task_id, stage_name, page, per_page):
        self.calls.append(("get_task_archive_jobs_page", db, project_id, task_id, stage_name, page, per_page))
        return BinarySecurityArchiveJobPageResponse(
            task_id=task_id,
            stage_name=stage_name,
            total=0,
            page=page,
            per_page=per_page,
            items=[],
        )

    def get_task_abnormal_reason_history(self, db, project_id, task_id):
        self.calls.append(("get_task_abnormal_reason_history", db, project_id, task_id))
        return BinarySecurityAbnormalReasonHistoryResponse(task_id=task_id, items=[])

    def get_entry_selection(self, db, project_id, task_id):
        self.calls.append(("get_entry_selection", db, project_id, task_id))
        return BinarySecurityEntrySelectionResponse(
            task_id=task_id,
            status="pending_entry_confirmation",
            selection_mode="manual_confirm",
            requires_confirmation=True,
            candidate_entries=[
                {
                    "entry_key": "mod-a:func_a",
                    "module_key": "mod-a",
                    "function_name": "func_a",
                    "file_path": "src/a.c",
                    "line_no": 12,
                    "reason": "network handler",
                },
                {
                    "entry_key": "mod-b:func_b",
                    "module_key": "mod-b",
                    "function_name": "func_b",
                    "file_path": "src/b.c",
                    "line_no": 34,
                    "reason": "ioctl entry",
                },
            ],
            selected_entry_keys=["mod-a:func_a"],
            selected_entries=[
                {
                    "entry_key": "mod-a:func_a",
                    "module_key": "mod-a",
                    "function_name": "func_a",
                }
            ],
            entry_results=[{"entry_key": "mod-a:func_a"}, {"entry_key": "mod-b:func_b"}],
        )

    def confirm_entry_selection(self, db, project_id, task_id, selected_entry_keys):
        self.calls.append(("confirm_entry_selection", db, project_id, task_id, selected_entry_keys))
        return BinarySecurityTaskDetailResponse(
            id=task_id,
            project_id=project_id,
            task_type="source",
            name="entry-confirmed-task",
            status="pending",
            current_stage="dataflow_vuln_scan",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            entry_selection_mode="manual_confirm",
            candidate_entry_count=2,
            selected_entry_count=len(selected_entry_keys),
            stage_summaries=[
                BinarySecurityStageSummary(
                    stage_name="entry_analysis",
                    sequence_no=2,
                    status="waiting_confirmation",
                )
            ],
            manual_operation_state={
                "overall": "allowed",
                "can_continue": False,
                "can_retry": False,
                "can_retry_failed_items": False,
            },
            policy={"entry_selection_mode": "manual_confirm"},
        )

    def get_service_config(self, db):
        self.calls.append(("get_service_config", db))
        return BinarySecurityServiceConfigResponse(
            config=BinarySecurityServiceConfigPayload(
                max_concurrent_tasks=12,
                dispatch_timeout_seconds=60,
                lease_timeout_seconds=90,
            )
        )

    def list_tasks(
        self,
        db,
        project_id,
        status=None,
        task_type=None,
        search=None,
        sort_by="created_at",
        sort_order="desc",
        page=1,
        page_size=50,
    ):
        self.calls.append(("list_tasks", db, project_id, status, task_type, search, sort_by, sort_order, page, page_size))
        return BinarySecurityTaskListResponse(
            total=1,
            page=page,
            page_size=page_size,
            total_pages=1,
            running_count=1,
            queued_count=0,
            max_concurrent_tasks=12,
            project_stats=BinarySecurityProjectStats(total=1, running=1),
            project_stage_aggregates=[],
            items=[
                BinarySecurityTaskResponse(
                    id="t-list-1",
                    project_id=project_id,
                    task_type=task_type or "source",
                    name="list-task",
                    status="running",
                    current_stage="entry_analysis",
                    firmware_path="/src",
                    stage_summaries=[
                        BinarySecurityStageSummary(
                            stage_name="entry_analysis",
                            sequence_no=2,
                            status="running",
                            running_items=1,
                        )
                    ],
                    manual_operation_state={
                        "overall": "blocked",
                        "blocking_code": "task_running",
                        "can_delete": False,
                    },
                )
            ],
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

    def test_list_tasks_route_preserves_filters_and_pagination(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks",
                    params={"task_type": "source", "status": "running", "page": 2, "page_size": 20},
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual(2, payload["page"])
        self.assertEqual(20, payload["page_size"])
        self.assertEqual("task_running", payload["items"][0]["manual_operation_state"]["blocking_code"])
        self.assertEqual(
            ("list_tasks", fake_db, "p1", "running", "source", None, "created_at", "desc", 2, 20),
            manager.calls[0],
        )

    def test_get_task_stage_items_route_preserves_pagination_and_lineage(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1/stage-items",
                    params={"stage_name": "dataflow_vuln_scan", "page": 2, "per_page": 10},
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual(2, payload["page"])
        self.assertEqual(10, payload["per_page"])
        self.assertEqual("i-entry-1", payload["items"][0]["input_ref"]["upstream_item_id"])
        self.assertEqual(
            ("get_task_stage_items_page", fake_db, "p1", "t1", "dataflow_vuln_scan", 2, 10),
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

    def test_get_task_overview_route_delegates_to_manager(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1/overview",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        self.assertEqual(("get_task_overview", fake_db, "p1", "t1"), manager.calls[0])

    def test_get_task_archive_jobs_route_preserves_filters(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1/archive-jobs",
                    params={"stage_name": "dataflow_vuln_scan", "page": 3, "per_page": 10},
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            ("get_task_archive_jobs_page", fake_db, "p1", "t1", "dataflow_vuln_scan", 3, 10),
            manager.calls[0],
        )

    def test_get_task_abnormal_reason_history_route_delegates_to_manager(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1/abnormal-reason-history",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        self.assertEqual(("get_task_abnormal_reason_history", fake_db, "p1", "t1"), manager.calls[0])

    def test_get_entry_selection_route_returns_confirmation_snapshot(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1/entry-selection",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("manual_confirm", payload["selection_mode"])
        self.assertTrue(payload["requires_confirmation"])
        self.assertEqual(2, len(payload["candidate_entries"]))
        self.assertEqual("mod-a:func_a", payload["selected_entry_keys"][0])
        self.assertEqual(("get_entry_selection", fake_db, "p1", "t1"), manager.calls[0])

    def test_confirm_entry_selection_route_passes_selected_keys(self):
        app, fake_db = self._build_client()
        manager = _RouteManagerStub()

        with patch.object(tasks_api_module, "get_task_manager", return_value=manager):
            with TestClient(app) as client:
                response = client.post(
                    "/api/app/binary-security/projects/p1/tasks/t1/entry-selection/confirm",
                    json={"selected_entry_keys": ["mod-a:func_a", "mod-b:func_b"]},
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual("manual_confirm", payload["entry_selection_mode"])
        self.assertEqual(2, payload["selected_entry_count"])
        self.assertEqual(
            ("confirm_entry_selection", fake_db, "p1", "t1", ["mod-a:func_a", "mod-b:func_b"]),
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

    def test_get_task_detail_route_returns_502_when_project_service_disconnects(self):
        app = FastAPI()
        app.include_router(tasks_router)
        setup_exception_handlers(app)

        fake_db = object()

        class _AuthStub:
            async def validate_token(self, token):
                del token
                return {"user_id": "u1", "username": "tester", "token_type": "user"}

        class _ProjectStub:
            async def require_access(self, token, project_id):
                del token, project_id
                raise UpstreamError("Project 服务请求失败: Server disconnected without sending a response")

        def _db_override():
            yield fake_db

        app.dependency_overrides[get_db] = _db_override

        with patch.object(tasks_api_module, "get_auth_service", return_value=_AuthStub()), patch.object(
            tasks_api_module, "get_project_service", return_value=_ProjectStub()
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/api/app/binary-security/projects/p1/tasks/t1",
                    headers={"Authorization": "Bearer token"},
                )

        self.assertEqual(502, response.status_code)
        self.assertIn("Project 服务请求失败", response.json()["error"])

    def test_project_service_require_access_retries_once_after_request_error(self):
        service = ProjectService()

        class _ClientStub:
            def __init__(self):
                self.calls = 0

            async def get(self, url, headers=None):
                del url, headers
                self.calls += 1
                if self.calls == 1:
                    request = SimpleNamespace(url="http://secflow-platform-project/api/project/p1")
                    raise httpx.RemoteProtocolError(
                        "Server disconnected without sending a response", request=request
                    )
                return SimpleNamespace(status_code=200, json=lambda: {"id": "p1"})

        client = _ClientStub()

        async def _client_factory(name, timeout=None):
            del name, timeout
            return client

        async def _run():
            with patch("app.service.project.get_shared_async_client", side_effect=_client_factory):
                result = await service.require_access("token", "p1")
            self.assertEqual({"id": "p1"}, result)
            self.assertEqual(2, client.calls)

        import asyncio

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
