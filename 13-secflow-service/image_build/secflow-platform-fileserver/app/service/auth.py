"""Auth service client."""

import logging
import time
from typing import Dict, Optional

import httpx

from app.config import get_config


logger = logging.getLogger(__name__)


class AuthServiceError(Exception):
    pass


class TokenInvalidError(AuthServiceError):
    pass


class TokenCacheEntry:
    def __init__(self, user_info: dict, ttl_seconds: int):
        self.user_info = user_info
        self.expiry_time = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expiry_time


class AuthService:
    def __init__(self):
        self.config = get_config().auth_service
        self.client = httpx.Client(timeout=self.config.timeout)
        self._token_cache: Dict[str, TokenCacheEntry] = {}
        self._cache_enabled = self.config.token_cache_enabled
        self._cache_ttl_seconds = self.config.token_cache_ttl_minutes * 60

    def _get_cached_user(self, token: str) -> Optional[dict]:
        if not self._cache_enabled:
            return None
        cache_entry = self._token_cache.get(token)
        if cache_entry is None:
            return None
        if cache_entry.is_expired():
            del self._token_cache[token]
            return None
        return cache_entry.user_info

    def _set_cached_user(self, token: str, user_info: dict):
        if self._cache_enabled:
            self._token_cache[token] = TokenCacheEntry(user_info, self._cache_ttl_seconds)

    async def validate_token_async(self, token: str) -> dict:
        cached_user = self._get_cached_user(token)
        if cached_user is not None:
            return cached_user

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            try:
                response = await client.post(
                    self.config.validate_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
                if response.status_code == 401:
                    raise TokenInvalidError("Token已过期或无效")
                if response.status_code != 200:
                    raise AuthServiceError(f"认证服务返回异常状态码: {response.status_code}")
                data = response.json()
                self._set_cached_user(token, data)
                return data
            except httpx.TimeoutException:
                raise AuthServiceError("认证服务请求超时")
            except httpx.ConnectError as exc:
                raise AuthServiceError(f"无法连接到认证服务: {exc}")


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
