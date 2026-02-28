"""
认证服务模块
"""

import logging
import time
from typing import Optional, Dict

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class AuthServiceError(Exception):
    """认证服务错误"""
    pass


class TokenInvalidError(AuthServiceError):
    """Token无效错误"""
    pass


class TokenCacheEntry:
    """Token缓存条目"""
    def __init__(self, user_info: dict, ttl_seconds: int):
        self.user_info = user_info
        self.expiry_time = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expiry_time


class AuthService:
    """认证服务客户端"""

    def __init__(self):
        self.config = get_config().auth_service
        self.client = httpx.Client(timeout=self.config.timeout)
        self._token_cache: Dict[str, TokenCacheEntry] = {}
        self._cache_enabled = self.config.token_cache_enabled
        self._cache_ttl_seconds = self.config.token_cache_ttl_minutes * 60

    def _get_cached_user(self, token: str) -> Optional[dict]:
        """从缓存获取用户信息"""
        if not self._cache_enabled:
            return None

        cache_entry = self._token_cache.get(token)
        if cache_entry is None:
            return None

        if cache_entry.is_expired():
            del self._token_cache[token]
            logger.debug("Token缓存已过期，从缓存移除")
            return None

        logger.debug("Token缓存命中，直接返回缓存的用户信息")
        return cache_entry.user_info

    def _set_cached_user(self, token: str, user_info: dict):
        """将用户信息缓存"""
        if not self._cache_enabled:
            return

        self._token_cache[token] = TokenCacheEntry(user_info, self._cache_ttl_seconds)
        logger.debug(f"Token已缓存，TTL={self._cache_ttl_seconds}秒")

    def validate_token(self, token: str) -> dict:
        """
        验证用户Token（带缓存）

        Args:
            token: Bearer Token

        Returns:
            用户信息字典

        Raises:
            TokenInvalidError: Token无效
            AuthServiceError: 认证服务异常
        """
        # 先检查缓存
        cached_user = self._get_cached_user(token)
        if cached_user is not None:
            return cached_user

        # 缓存未命中，调用认证服务
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = self.client.post(
                self.config.validate_url,
                headers=headers
            )

            if response.status_code == 401:
                raise TokenInvalidError("Token已过期或无效")

            if response.status_code != 200:
                raise AuthServiceError(
                    f"认证服务返回异常状态码: {response.status_code}"
                )

            data = response.json()

            # 缓存验证结果
            self._set_cached_user(token, data)

            return data

        except httpx.TimeoutException:
            raise AuthServiceError("认证服务请求超时")
        except httpx.ConnectError as e:
            raise AuthServiceError(f"无法连接到认证服务: {e}")

    async def validate_token_async(self, token: str) -> dict:
        """
        异步验证用户Token（带缓存）

        Args:
            token: Bearer Token

        Returns:
            用户信息字典
        """
        # 先检查缓存
        cached_user = self._get_cached_user(token)
        if cached_user is not None:
            return cached_user

        # 缓存未命中，调用认证服务
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = await client.post(
                    self.config.validate_url,
                    headers=headers
                )

                if response.status_code == 401:
                    raise TokenInvalidError("Token已过期或无效")

                if response.status_code != 200:
                    raise AuthServiceError(
                        f"认证服务返回异常状态码: {response.status_code}"
                    )

                data = response.json()

                # 缓存验证结果
                self._set_cached_user(token, data)

                return data

            except httpx.TimeoutException:
                raise AuthServiceError("认证服务请求超时")
            except httpx.ConnectError as e:
                raise AuthServiceError(f"无法连接到认证服务: {e}")


# 单例实例
_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    """获取认证服务实例"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service