"""Authentication service client."""

from __future__ import annotations

import time
from typing import Dict, Optional

import httpx

from app.config import get_config
from app.services.observability import record_auth_token_cache


class AuthServiceError(Exception):
    pass


class TokenInvalidError(AuthServiceError):
    pass


class TokenCacheEntry:
    def __init__(self, payload: dict, ttl_seconds: int):
        self.payload = payload
        self.expiry_time = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expiry_time


class AuthService:
    def __init__(self):
        self.config = get_config().auth_service
        self._cache_enabled = bool(self.config.token_cache_enabled)
        self._cache_ttl_seconds = int(self.config.token_cache_ttl_minutes) * 60
        self._token_cache: Dict[str, TokenCacheEntry] = {}

    def _cache_key(self, token: str, project_id: Optional[str]) -> str:
        return f"{token}::{project_id or ''}"

    def _get_cached_user(self, token: str, project_id: Optional[str]) -> Optional[dict]:
        if not self._cache_enabled:
            record_auth_token_cache("disabled")
            return None
        entry = self._token_cache.get(self._cache_key(token, project_id))
        if entry is None:
            record_auth_token_cache("miss")
            return None
        if entry.is_expired():
            self._token_cache.pop(self._cache_key(token, project_id), None)
            record_auth_token_cache("expired")
            return None
        record_auth_token_cache("hit")
        return entry.payload

    def _set_cached_user(self, token: str, payload: dict, project_id: Optional[str]) -> None:
        if not self._cache_enabled:
            return
        if payload.get("token_type") == "machine":
            return
        self._token_cache[self._cache_key(token, project_id)] = TokenCacheEntry(
            payload,
            self._cache_ttl_seconds,
        )

    async def validate_token_async(
        self,
        token: str,
        project_id: Optional[str] = None,
    ) -> dict:
        if not self.config.enabled:
            return {
                "id": "anonymous",
                "username": "anonymous",
                "token_type": "user",
            }

        cached = self._get_cached_user(token, project_id)
        if cached is not None:
            return cached

        headers = {"Authorization": f"Bearer {token}"}
        params = {"project_id": project_id} if project_id else None

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    self.config.validate_url,
                    headers=headers,
                    params=params,
                )
        except httpx.TimeoutException as exc:
            raise AuthServiceError(f"认证服务请求超时: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AuthServiceError(f"认证服务不可用: {exc}") from exc

        if response.status_code == 401:
            raise TokenInvalidError("Token已过期或无效")
        if response.status_code != 200:
            raise AuthServiceError(
                f"认证服务返回异常状态码: {response.status_code}"
            )

        payload = response.json() if response.content else {}
        self._set_cached_user(token, payload, project_id)
        return payload


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
