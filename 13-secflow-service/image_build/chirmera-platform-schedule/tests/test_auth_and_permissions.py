from __future__ import annotations

from unittest.mock import AsyncMock, patch


def test_missing_auth_header_returns_401(client):
    response = client.get("/api/chirmera-platform-schedule/projects/proj1/jobs")
    assert response.status_code == 401


def test_project_permission_denied_returns_403(client):
    async def fake_validate_token(token: str):
        return {"user_id": "u1", "username": "alice", "token_type": "human"}

    async def fake_require_access(token: str, project_id: str):
        raise __import__("app.exception", fromlist=["ForbiddenError"]).ForbiddenError("denied")

    with patch("app.api.routes.get_auth_service") as auth_factory, patch("app.api.routes.get_project_service") as project_factory:
        auth_factory.return_value.validate_token = AsyncMock(side_effect=fake_validate_token)
        project_factory.return_value.require_access = AsyncMock(side_effect=fake_require_access)
        response = client.get(
            "/api/chirmera-platform-schedule/projects/proj1/jobs",
            headers={"Authorization": "Bearer test-token"},
        )
    assert response.status_code == 403
