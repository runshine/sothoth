"""Auth service client and dependencies."""

import logging
import time
from typing import Dict, Optional

import httpx
from fastapi import Depends, Header

from app.config import get_config
from app.exception import ForbiddenError, UnauthorizedError


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
        self._token_cache: Dict[str, TokenCacheEntry] = {}
        self._cache_enabled = self.config.token_cache_enabled
        self._cache_ttl_seconds = self.config.token_cache_ttl_minutes * 60

    def _get_cached_user(self, token: str) -> Optional[dict]:
        if not self._cache_enabled:
            return None
        entry = self._token_cache.get(token)
        if entry is None:
            return None
        if entry.is_expired():
            del self._token_cache[token]
            return None
        return entry.user_info

    def _set_cached_user(self, token: str, user_info: dict):
        if self._cache_enabled:
            self._token_cache[token] = TokenCacheEntry(user_info, self._cache_ttl_seconds)

    async def validate_token_async(self, token: str) -> dict:
        cached = self._get_cached_user(token)
        if cached is not None:
            return cached

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
            except httpx.TimeoutException as exc:
                raise AuthServiceError("认证服务请求超时") from exc
            except httpx.ConnectError as exc:
                raise AuthServiceError(f"无法连接到认证服务: {exc}") from exc


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service


def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise UnauthorizedError("未提供认证Token")
    try:
        scheme, token = authorization.split()
    except ValueError as exc:
        raise UnauthorizedError("认证头格式不正确") from exc
    if scheme.lower() != "bearer":
        raise UnauthorizedError("仅支持 Bearer Token")
    return token


def _is_super_admin(user_info: dict) -> bool:
    if not user_info:
        return False
    if int(user_info.get("id", 0) or 0) == 1:
        return True
    role_names = [str(item).lower() for item in (user_info.get("role") or [])]
    platform_role = str(user_info.get("platform_role") or "").lower()
    return platform_role == "super_admin" or any(name in {"super_admin", "admin", "管理员", "超级管理员"} for name in role_names)


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    token = _extract_bearer_token(authorization)
    try:
        return await get_auth_service().validate_token_async(token)
    except TokenInvalidError as exc:
        raise UnauthorizedError("Token无效或已过期") from exc
    except AuthServiceError as exc:
        raise ForbiddenError(f"认证服务异常: {exc}") from exc


async def get_current_super_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("token_type") != "human":
        raise UnauthorizedError("当前接口仅支持人机Token访问")
    if not _is_super_admin(current_user):
        raise ForbiddenError("只有超级管理员可以访问配置中心")
    return current_user


async def get_machine_client(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("token_type") != "machine":
        raise UnauthorizedError("当前接口仅支持机机Token访问")
    return current_user
