from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import httpx
from fastapi import HTTPException, status

from app.config import get_config
from app.observability.service_ops import (
    observe_auth_token_cache,
    observe_auth_token_validation,
    observe_auth_upstream_request,
)
from app.services.http_client import get_shared_async_client


@dataclass
class TokenCacheEntry:
    payload: dict
    expires_at: float
    validated_at: float
    token_type: str

    def expired(self, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        return current >= self.expires_at


class AuthUnauthorizedError(RuntimeError):
    pass


class AuthUpstreamError(RuntimeError):
    def __init__(self, error_type: str, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.status_code = status_code


class AuthService:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._cache: dict[str, TokenCacheEntry] = {}

    def _service_headers(self) -> dict[str, str]:
        token = get_config().auth_service.service_machine_token
        if not token:
            return {}
        return {"X-Service-Authorization": f"Bearer {token}"}

    def _cache_key(self, token_type: str, token: str) -> str:
        return f"{token_type}:{token}"

    async def _prune_cache_locked(self) -> None:
        config = get_config().auth_service
        now = time.time()
        expired_keys = [key for key, entry in self._cache.items() if entry.expired(now)]
        for key in expired_keys:
            self._cache.pop(key, None)
            observe_auth_token_cache("expired")
        max_entries = max(int(config.token_cache_max_entries or 0), 0)
        if max_entries and len(self._cache) > max_entries:
            overflow = len(self._cache) - max_entries
            ordered = sorted(self._cache.items(), key=lambda item: item[1].validated_at)
            for key, _ in ordered[:overflow]:
                self._cache.pop(key, None)
                observe_auth_token_cache("evict")

    async def _cache_get(self, token_type: str, token: str) -> dict | None:
        config = get_config().auth_service
        if not config.token_cache_enabled:
            return None
        async with self._lock:
            await self._prune_cache_locked()
            entry = self._cache.get(self._cache_key(token_type, token))
            if entry is None:
                observe_auth_token_cache("miss")
                return None
            if entry.expired():
                self._cache.pop(self._cache_key(token_type, token), None)
                observe_auth_token_cache("expired")
                observe_auth_token_cache("miss")
                return None
            observe_auth_token_cache("hit")
            observe_auth_token_validation(result="cache_hit", source="runtime", token_type=token_type)
            return dict(entry.payload)

    async def _cache_store(self, token_type: str, token: str, payload: dict) -> None:
        config = get_config().auth_service
        if not config.token_cache_enabled:
            return
        now = time.time()
        ttl = max(int(config.token_cache_ttl_seconds or 0), 0)
        async with self._lock:
            await self._prune_cache_locked()
            self._cache[self._cache_key(token_type, token)] = TokenCacheEntry(
                payload=dict(payload),
                expires_at=now + ttl,
                validated_at=now,
                token_type=token_type,
            )
            await self._prune_cache_locked()
        observe_auth_token_cache("store")

    async def _request_auth(self, *, operation: str, url: str, token: str, token_type: str) -> dict:
        config = get_config().auth_service
        started = time.perf_counter()
        try:
            client = await get_shared_async_client("auth-service", timeout=config.timeout)
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {token}", **self._service_headers()},
            )
        except httpx.TimeoutException as exc:
            observe_auth_token_validation(result="timeout", source="runtime", token_type=token_type)
            observe_auth_upstream_request(status="timeout", operation=operation, duration_seconds=time.perf_counter() - started)
            raise AuthUpstreamError("timeout", "auth service timeout") from exc
        except httpx.ConnectError as exc:
            observe_auth_token_validation(result="connect_error", source="runtime", token_type=token_type)
            observe_auth_upstream_request(status="connect_error", operation=operation, duration_seconds=time.perf_counter() - started)
            raise AuthUpstreamError("connect_error", "auth service unavailable") from exc
        except httpx.RequestError as exc:
            observe_auth_token_validation(result="transport_error", source="runtime", token_type=token_type)
            observe_auth_upstream_request(status="transport_error", operation=operation, duration_seconds=time.perf_counter() - started)
            raise AuthUpstreamError("transport_error", "auth service unavailable") from exc

        observe_auth_upstream_request(
            status=str(response.status_code),
            operation=operation,
            duration_seconds=time.perf_counter() - started,
        )
        if response.status_code in {401, 403}:
            observe_auth_token_validation(result="unauthorized", source="runtime", token_type=token_type)
            raise AuthUnauthorizedError("token invalid")
        if 500 <= response.status_code <= 599:
            observe_auth_token_validation(result="http_5xx", source="runtime", token_type=token_type)
            raise AuthUpstreamError("http_5xx", "auth service unavailable", status_code=response.status_code)
        if response.status_code != 200:
            observe_auth_token_validation(result="http_4xx", source="runtime", token_type=token_type)
            raise AuthUpstreamError("http_4xx", "auth service bad response", status_code=response.status_code)
        try:
            payload = response.json() if response.text else {}
        except ValueError as exc:
            observe_auth_token_validation(result="invalid_response", source="runtime", token_type=token_type)
            raise AuthUpstreamError("invalid_response", "auth service bad response", status_code=response.status_code) from exc
        observe_auth_token_validation(result="success", source="runtime", token_type=token_type)
        return payload if isinstance(payload, dict) else {}

    def _map_auth_exception(self, exc: Exception) -> HTTPException:
        if isinstance(exc, AuthUnauthorizedError):
            return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="human token invalid")
        if isinstance(exc, AuthUpstreamError):
            if exc.error_type in {"timeout", "connect_error", "transport_error", "http_5xx"}:
                return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="auth_service_unavailable")
            return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="auth_service_bad_response")
        return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="auth_service_bad_response")

    async def startup_validate(self) -> None:
        config = get_config().auth_service
        if not config.enabled:
            return
        machine_token = config.service_machine_token
        if not machine_token:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="auth_service_machine_token_missing")
        try:
            await self._request_auth(
                operation="startup_validate",
                url=config.machine_validate_url,
                token=machine_token,
                token_type="machine",
            )
        except Exception as exc:
            raise self._map_auth_exception(exc) from exc

    async def validate_human_authorization(self, authorization: Optional[str]) -> Tuple[dict, str]:
        config = get_config().auth_service
        if not config.enabled:
            return {"user_id": "test-user", "project_ids": ["default", "project-1"]}, authorization or ""
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
        token = authorization.split(" ", 1)[1]
        cached = await self._cache_get("human", token)
        if cached is not None:
            return cached, token
        try:
            payload = await self._request_auth(
                operation="validate_human_token",
                url=config.human_validate_url,
                token=token,
                token_type="human",
            )
        except Exception as exc:
            raise self._map_auth_exception(exc) from exc
        await self._cache_store("human", token, payload)
        return payload, token

    async def validate_machine_authorization(self, authorization: Optional[str]) -> Tuple[dict, str]:
        config = get_config().auth_service
        if not config.enabled:
            return {"token_type": "machine", "project_ids": ["default", "project-1"]}, authorization or ""
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
        token = authorization.split(" ", 1)[1]
        cached = await self._cache_get("machine", token)
        if cached is not None:
            return cached, token
        try:
            payload = await self._request_auth(
                operation="validate_machine_token",
                url=config.machine_validate_url,
                token=token,
                token_type="machine",
            )
        except Exception as exc:
            mapped = self._map_auth_exception(exc)
            if mapped.status_code == status.HTTP_401_UNAUTHORIZED:
                mapped.detail = "machine token invalid"
            raise mapped from exc
        await self._cache_store("machine", token, payload)
        return payload, token


_auth_service: AuthService | None = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
