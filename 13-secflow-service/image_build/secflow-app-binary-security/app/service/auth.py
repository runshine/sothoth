"""Auth service client."""

from __future__ import annotations

import time
from typing import Optional

import httpx

from app.config import get_config
from app.exception import UnauthorizedError, UpstreamError
from app.observability import observe_auth_token_cache, observe_auth_token_validation, observe_downstream_request
from app.service.http_client import get_shared_async_client


class TokenCacheEntry:
    def __init__(self, user_info: dict, ttl_seconds: int):
        self.user_info = user_info
        self.expiry_time = time.time() + ttl_seconds

    def expired(self) -> bool:
        return time.time() > self.expiry_time


class AuthService:
    def __init__(self):
        self.config = get_config().auth_service
        self.cache: dict[str, TokenCacheEntry] = {}

    async def validate_token(self, token: str) -> dict:
        if self.config.token_cache_enabled:
            cached = self.cache.get(token)
            if cached and not cached.expired():
                observe_auth_token_cache(result="hit", entries=len(self.cache))
                observe_auth_token_validation(result="cache_hit", source="runtime")
                return cached.user_info
            observe_auth_token_cache(result="miss", entries=len(self.cache))

        started = time.perf_counter()
        try:
            client = await get_shared_async_client("auth-service", timeout=self.config.timeout)
            resp = await client.post(
                self.config.validate_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.TimeoutException:
            observe_auth_token_validation(result="timeout", source="runtime")
            observe_downstream_request(
                service="auth_service",
                method="POST",
                operation="validate_token",
                status="timeout",
                duration_seconds=time.perf_counter() - started,
            )
            raise UpstreamError("认证服务请求超时")
        except httpx.ConnectError as exc:
            observe_auth_token_validation(result="connect_error", source="runtime")
            observe_downstream_request(
                service="auth_service",
                method="POST",
                operation="validate_token",
                status="connect_error",
                duration_seconds=time.perf_counter() - started,
            )
            raise UpstreamError(f"无法连接认证服务: {exc}")

        observe_downstream_request(
            service="auth_service",
            method="POST",
            operation="validate_token",
            status=str(resp.status_code),
            duration_seconds=time.perf_counter() - started,
        )
        if resp.status_code == 401:
            observe_auth_token_validation(result="unauthorized", source="runtime")
            raise UnauthorizedError("Token 无效或已过期")
        if resp.status_code != 200:
            observe_auth_token_validation(result="failed", source="runtime")
            raise UpstreamError(f"认证服务返回异常状态码: {resp.status_code}")
        data = resp.json()
        if self.config.token_cache_enabled:
            self.cache[token] = TokenCacheEntry(data, self.config.token_cache_ttl_minutes * 60)
            observe_auth_token_cache(result="store", entries=len(self.cache))
        observe_auth_token_validation(result="success", source="runtime")
        return data


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
