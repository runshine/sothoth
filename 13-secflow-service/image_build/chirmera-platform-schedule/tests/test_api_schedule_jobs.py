from __future__ import annotations

from unittest.mock import AsyncMock, patch


def _auth_headers():
    return {"Authorization": "Bearer test-token"}


async def _fake_validate_token(token: str):
    return {"user_id": "u1", "username": "alice", "token_type": "human"}


async def _fake_require_access(token: str, project_id: str):
    return {"id": project_id}


def test_schedule_job_crud_and_trigger(client):
    payload = {
        "name": "job-a",
        "trigger_type": "manual",
        "target_method": "POST",
        "target_url": "http://example/api/tasks",
        "target_body_template": {"project": "{project_id}"},
        "success_status_codes": [200],
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)

        create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/jobs", json=payload, headers=_auth_headers())
        assert create_resp.status_code == 200, create_resp.text
        job = create_resp.json()
        assert job["project_id"] == "proj1"

        list_resp = client.get("/api/chirmera-platform-schedule/projects/proj1/jobs", headers=_auth_headers())
        assert list_resp.status_code == 200
        assert list_resp.json()["total"] == 1

        with patch("app.service.schedule_manager.get_shared_async_client") as client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=type("Resp", (), {"status_code": 200, "json": lambda self: {"task_id": "t-1"}, "text": ""})())
            client_factory.return_value = mock_client
            trigger_resp = client.post(
                f"/api/chirmera-platform-schedule/projects/proj1/jobs/{job['id']}/trigger",
                json={"trigger_source": "manual"},
                headers=_auth_headers(),
            )
        assert trigger_resp.status_code == 200, trigger_resp.text
        execution = trigger_resp.json()
        assert execution["status"] == "queued"
        assert execution["downstream_task_id"] is None


def test_user_task_create_requires_existing_input_binding(client):
    payload = {
        "task_type": "binary_firmware_e2e",
        "name": "firmware-task-a",
        "description": "demo",
        "input_upload_ids": ["upload-001"],
        "policy": {},
        "dispatch_policy": {},
        "task_key_ref": "123",
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)

        with patch("app.service.user_task_manager.ProjectInputResolver.resolve_single", new=AsyncMock(return_value=type("Resolved", (), {
            "upload_id": "upload-001",
            "project_id": "proj1",
            "input_type": "software",
            "status": "succeeded",
            "keep_original": False,
            "target_path": "/data/files/proj1/user_input/software/upload-001",
            "latest_batch_id": "batch-001",
            "display_name": "/user_input/software/upload-001",
        })())):
            create_resp = client.post(
                "/api/chirmera-platform-schedule/projects/proj1/user-tasks",
                json=payload,
                headers=_auth_headers(),
            )

        assert create_resp.status_code == 200, create_resp.text
        body = create_resp.json()
        assert body["project_id"] == "proj1"
        assert body["create_status"] == "created"
        assert body["dispatch_status"] == "ready_for_dispatch"
        assert body["input_upload_count"] == 1
        assert body["inputs"][0]["input_upload_id"] == "upload-001"
