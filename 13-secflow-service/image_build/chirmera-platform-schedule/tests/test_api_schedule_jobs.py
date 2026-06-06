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
