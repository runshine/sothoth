from types import SimpleNamespace
import asyncio

import httpx
import pytest

from app.api.projects import AuthServiceError, get_current_user
from app.exception import DependencyUnavailableError
from app.service.auth import AuthService

from app.api.projects import get_project_with_permission


class _FakeQuery:
    def __init__(self, project_obj):
        self._project_obj = project_obj

    def options(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._project_obj


class _FakeDB:
    def __init__(self, project_obj):
        self._project_obj = project_obj

    def query(self, *args, **kwargs):
        return _FakeQuery(self._project_obj)


def test_get_project_with_permission_allows_global_machine_token():
    project = SimpleNamespace(id="p1", status="active")
    db = _FakeDB(project)
    current_user = {
        "token_type": "machine",
        "token_scope": "global",
        "project_id": None,
    }

    result = get_project_with_permission(db, "p1", current_user, require_manage=False)

    assert result is project


def test_get_current_user_maps_auth_transport_failure_to_dependency_error(monkeypatch):
    class _AuthStub:
        async def validate_token_async(self, token, project_id=None):
            del token, project_id
            raise AuthServiceError("认证服务请求失败: Server disconnected without sending a response")

    monkeypatch.setattr("app.api.projects.get_auth_service", lambda: _AuthStub())

    with pytest.raises(DependencyUnavailableError) as exc_info:
        asyncio.run(get_current_user(authorization="Bearer test-token", project_id="p1"))

    assert exc_info.value.status_code == 502
    assert exc_info.value.message == "认证服务暂时不可用"
    assert exc_info.value.details["reason"].startswith("认证服务请求失败:")


def test_auth_service_validate_token_async_retries_once_on_request_error(monkeypatch):
    service = AuthService()

    class _Response:
        status_code = 200

        @staticmethod
        def json():
            return {"id": "u1", "username": "tester"}

    class _AsyncClientStub:
        def __init__(self):
            self.calls = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers=None, params=None):
            del url, headers, params
            self.calls += 1
            if self.calls == 1:
                raise httpx.RemoteProtocolError(
                    "Server disconnected without sending a response",
                    request=SimpleNamespace(url="http://auth/api/auth/validate-token"),
                )
            return _Response()

    client = _AsyncClientStub()
    monkeypatch.setattr(service, "_async_client", lambda: client)

    result = asyncio.run(service.validate_token_async("token", project_id="p1"))

    assert result["id"] == "u1"
    assert client.calls == 2
