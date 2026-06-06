from __future__ import annotations

from unittest.mock import AsyncMock, patch


def _auth_headers():
    return {"Authorization": "Bearer test-token"}


async def _fake_validate_token(token: str):
    return {"user_id": "u1", "username": "alice", "token_type": "human"}


async def _fake_require_access(token: str, project_id: str):
    return {"id": project_id}


def test_create_disable_and_sync_key(client):
    payload = {
        "name": "key-a",
        "alias": "alias-a",
        "models": ["gpt-4o-mini"],
        "metadata": {"team": "sec"},
        "duration": "7d",
        "budget_config": {"max_budget": 10},
    }
    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=_fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=_fake_require_access)

        with patch("app.service.litellm.get_shared_async_client") as client_factory:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=type("Resp", (), {"status_code": 200, "json": lambda self: {"key": "sk-test-1234", "key_id": "kid-1"}})())
            mock_client.get = AsyncMock(return_value=type("Resp", (), {"status_code": 200, "json": lambda self: {"key_id": "kid-1", "disabled": True}})())
            client_factory.return_value = mock_client

            create_resp = client.post("/api/chirmera-platform-schedule/projects/proj1/keys", json=payload, headers=_auth_headers())
            assert create_resp.status_code == 200, create_resp.text
            created = create_resp.json()
            assert created["plain_text_key"] == "sk-test-1234"
            key_id = created["id"]

            get_resp = client.get(f"/api/chirmera-platform-schedule/projects/proj1/keys/{key_id}", headers=_auth_headers())
            assert get_resp.status_code == 200
            assert "plain_text_key" not in get_resp.json()

            disable_resp = client.post(f"/api/chirmera-platform-schedule/projects/proj1/keys/{key_id}/disable", headers=_auth_headers())
            assert disable_resp.status_code == 200
            assert disable_resp.json()["status"] == "disabled"

            sync_resp = client.post(f"/api/chirmera-platform-schedule/projects/proj1/keys/{key_id}/sync", headers=_auth_headers())
            assert sync_resp.status_code == 200
            assert sync_resp.json()["status"] == "disabled"
