"""Auth service client."""

from __future__ import annotations

import time
from typing import Optional

import httpx

from app.config import get_config
from app.exception import UnauthorizedError, UpstreamError


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
                return cached.user_info
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(
                    self.config.validate_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
        except httpx.TimeoutException:
            raise UpstreamError("认证服务请求超时")
        except httpx.ConnectError as exc:
            raise UpstreamError(f"无法连接认证服务: {exc}")
        if resp.status_code == 401:
            raise UnauthorizedError("Token无效或已过期")
        if resp.status_code != 200:
            raise UpstreamError(f"认证服务返回异常状态码: {resp.status_code}")
        data = resp.json()
        if self.config.token_cache_enabled:
            self.cache[token] = TokenCacheEntry(data, self.config.token_cache_ttl_minutes * 60)
        return data


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
