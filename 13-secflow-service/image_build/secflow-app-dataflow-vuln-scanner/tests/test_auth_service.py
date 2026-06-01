from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

from app.api.dependencies import get_current_or_machine_subject
from app.config import get_config
from app.services.auth import AuthService
from app.services.http_client import get_shared_async_client, invalidate_shared_async_client


class _FakeClient:
    def __init__(self, responder):
        self._responder = responder
        self.calls = []

    async def post(self, url, headers=None):
        self.calls.append((url, headers))
        return await self._responder(url, headers)


@pytest.mark.asyncio
async def test_human_token_cached_after_first_success(service_config_path, monkeypatch):
    get_config().auth_service.enabled = True
    service = AuthService()
    calls = {"count": 0}

    async def _responder(url, headers):
        calls["count"] += 1
        return httpx.Response(200, json={"user_id": "u1", "project_ids": ["p1"]})

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    payload1, token1 = await service.validate_human_authorization("Bearer abc")
    payload2, token2 = await service.validate_human_authorization("Bearer abc")

    assert token1 == token2 == "abc"
    assert payload1["user_id"] == "u1"
    assert payload2["user_id"] == "u1"
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_machine_token_cached_after_first_success(service_config_path, monkeypatch):
    get_config().auth_service.enabled = True
    service = AuthService()
    calls = {"count": 0}

    async def _responder(url, headers):
        calls["count"] += 1
        return httpx.Response(200, json={"token_type": "machine", "project_ids": ["p1"]})

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    await service.validate_machine_authorization("Bearer machine-token")
    await service.validate_machine_authorization("Bearer machine-token")

    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_token_expiry_triggers_remote_revalidation(service_config_path, monkeypatch):
    config = get_config().auth_service
    config.enabled = True
    config.token_cache_ttl_seconds = 0
    service = AuthService()
    calls = {"count": 0}

    async def _responder(url, headers):
        calls["count"] += 1
        return httpx.Response(200, json={"user_id": f"u{calls['count']}"})

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    payload1, _ = await service.validate_human_authorization("Bearer abc")
    payload2, _ = await service.validate_human_authorization("Bearer abc")

    assert payload1["user_id"] == "u1"
    assert payload2["user_id"] == "u2"
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_cache_evicts_oldest_entry_when_full(service_config_path, monkeypatch):
    config = get_config().auth_service
    config.enabled = True
    config.token_cache_max_entries = 1
    service = AuthService()
    calls = {"count": 0}

    async def _responder(url, headers):
        calls["count"] += 1
        token = headers["Authorization"].split(" ", 1)[1]
        return httpx.Response(200, json={"user_id": token})

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    await service.validate_human_authorization("Bearer a")
    await service.validate_human_authorization("Bearer b")
    await service.validate_human_authorization("Bearer a")

    assert calls["count"] == 3


@pytest.mark.asyncio
async def test_auth_401_maps_to_http_401(service_config_path, monkeypatch):
    get_config().auth_service.enabled = True
    service = AuthService()

    async def _responder(url, headers):
        return httpx.Response(401, json={"detail": "invalid"})

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    with pytest.raises(HTTPException) as exc:
        await service.validate_human_authorization("Bearer bad")
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_auth_500_maps_to_http_503(service_config_path, monkeypatch):
    get_config().auth_service.enabled = True
    service = AuthService()

    async def _responder(url, headers):
        return httpx.Response(500, text="boom")

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    with pytest.raises(HTTPException) as exc:
        await service.validate_human_authorization("Bearer bad")
    assert exc.value.status_code == 503
    assert exc.value.detail == "auth_service_unavailable"


@pytest.mark.asyncio
async def test_connect_error_maps_to_http_503(service_config_path, monkeypatch):
    get_config().auth_service.enabled = True
    service = AuthService()

    async def _responder(url, headers):
        raise httpx.ConnectError("dns failed")

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    with pytest.raises(HTTPException) as exc:
        await service.validate_human_authorization("Bearer bad")
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_invalid_json_maps_to_http_502(service_config_path, monkeypatch):
    get_config().auth_service.enabled = True
    service = AuthService()

    async def _responder(url, headers):
        return httpx.Response(200, content=b"not-json", headers={"content-type": "application/json"})

    fake_client = _FakeClient(_responder)
    monkeypatch.setattr("app.services.auth.get_shared_async_client", lambda *args, **kwargs: fake_client)

    with pytest.raises(HTTPException) as exc:
        await service.validate_human_authorization("Bearer bad")
    assert exc.value.status_code == 502
    assert exc.value.detail == "auth_service_bad_response"


@pytest.mark.asyncio
async def test_get_current_or_machine_subject_fallbacks_only_on_401(service_config_path, monkeypatch):
    class _Auth401:
        async def validate_human_authorization(self, authorization):
            raise HTTPException(status_code=401, detail="human token invalid")

        async def validate_machine_authorization(self, authorization):
            return {"token_type": "machine"}, "machine"

    monkeypatch.setattr("app.api.dependencies.get_auth_service", lambda: _Auth401())
    payload, token = await get_current_or_machine_subject("Bearer token")
    assert payload["token_type"] == "machine"
    assert token == "machine"

    class _Auth503:
        async def validate_human_authorization(self, authorization):
            raise HTTPException(status_code=503, detail="auth_service_unavailable")

        async def validate_machine_authorization(self, authorization):
            raise AssertionError("should not fallback on 503")

    monkeypatch.setattr("app.api.dependencies.get_auth_service", lambda: _Auth503())
    with pytest.raises(HTTPException) as exc:
        await get_current_or_machine_subject("Bearer token")
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_shared_async_client_reused_and_recreated(service_config_path):
    client1 = await get_shared_async_client("auth-service", timeout=1)
    client2 = await get_shared_async_client("auth-service", timeout=1)
    assert client1 is client2

    await invalidate_shared_async_client("auth-service")

    client3 = await get_shared_async_client("auth-service", timeout=1)
    assert client3 is not client1
    await invalidate_shared_async_client("auth-service")
