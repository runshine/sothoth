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
        self.client = httpx.Client(
            timeout=self.config.timeout,
            limits=httpx.Limits(
                max_connections=max(1, int(self.config.max_connections)),
                max_keepalive_connections=max(0, int(self.config.max_keepalive_connections)),
                keepalive_expiry=max(0.0, float(self.config.keepalive_expiry_seconds)),
            ),
        )
        self._token_cache: Dict[str, TokenCacheEntry] = {}
        self._cache_enabled = self.config.token_cache_enabled
        self._cache_ttl_seconds = self.config.token_cache_ttl_minutes * 60

    def _async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.config.timeout,
            limits=httpx.Limits(
                max_connections=max(1, int(self.config.max_connections)),
                max_keepalive_connections=max(0, int(self.config.max_keepalive_connections)),
                keepalive_expiry=max(0.0, float(self.config.keepalive_expiry_seconds)),
            ),
        )

    def _get_cache_key(self, token: str, project_id: Optional[str] = None) -> str:
        return f"{token}::{project_id or ''}"

    def _get_cached_user(self, token: str, project_id: Optional[str] = None) -> Optional[dict]:
        """从缓存获取用户信息"""
        if not self._cache_enabled:
            return None

        cache_entry = self._token_cache.get(self._get_cache_key(token, project_id))
        if cache_entry is None:
            return None

        if cache_entry.is_expired():
            # cache key includes project_id; use safe pop to avoid KeyError on stale entries
            self._token_cache.pop(self._get_cache_key(token, project_id), None)
            logger.debug("Token缓存已过期，从缓存移除")
            return None

        logger.debug("Token缓存命中，直接返回缓存的用户信息")
        return cache_entry.user_info

    def _set_cached_user(self, token: str, user_info: dict, project_id: Optional[str] = None):
        """将用户信息缓存"""
        if not self._cache_enabled:
            return

        if user_info.get("token_type") == "machine":
            logger.debug("机机Token不进入缓存，确保刷新/禁用即时生效")
            return

        self._token_cache[self._get_cache_key(token, project_id)] = TokenCacheEntry(user_info, self._cache_ttl_seconds)
        logger.debug(f"Token已缓存，TTL={self._cache_ttl_seconds}秒")

    def validate_token(self, token: str, project_id: Optional[str] = None) -> dict:
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
        cached_user = self._get_cached_user(token, project_id)
        if cached_user is not None:
            return cached_user

        headers = {"Authorization": f"Bearer {token}"}
        params = {"project_id": project_id} if project_id else None
        retry_count = max(0, int(self.config.retry_count))
        last_error: httpx.RequestError | None = None
        for attempt in range(retry_count + 1):
            try:
                response = self.client.post(self.config.validate_url, headers=headers, params=params)
                if response.status_code == 401:
                    raise TokenInvalidError("Token已过期或无效")
                if response.status_code != 200:
                    raise AuthServiceError(f"认证服务返回异常状态码: {response.status_code}")
                data = response.json()
                self._set_cached_user(token, data, project_id)
                if attempt > 0:
                    logger.warning(
                        "auth_service request recovered after retry",
                        extra={"target_service": "auth_service", "operation": "validate_token", "retried": True, "final_result": "retry_success"},
                    )
                return data
            except httpx.TimeoutException:
                logger.warning(
                    "auth_service timeout",
                    extra={"target_service": "auth_service", "operation": "validate_token", "exception_type": "TimeoutException", "retried": False, "final_result": "timeout"},
                )
                raise AuthServiceError("认证服务请求超时")
            except httpx.ConnectError as e:
                logger.warning(
                    "auth_service connect error",
                    extra={"target_service": "auth_service", "operation": "validate_token", "exception_type": type(e).__name__, "retried": False, "final_result": "connect_error"},
                )
                raise AuthServiceError(f"无法连接到认证服务: {e}")
            except httpx.RequestError as e:
                last_error = e
                if attempt < retry_count:
                    logger.warning(
                        "auth_service transient request error, retrying",
                        extra={"target_service": "auth_service", "operation": "validate_token", "exception_type": type(e).__name__, "retried": True, "final_result": "retrying"},
                    )
                    continue
                logger.warning(
                    "auth_service request failed after retries",
                    extra={"target_service": "auth_service", "operation": "validate_token", "exception_type": type(e).__name__, "retried": retry_count > 0, "final_result": "retry_failed"},
                )
                raise AuthServiceError(f"认证服务请求失败: {e}")
        raise AuthServiceError(f"认证服务请求失败: {last_error}")

    async def validate_token_async(self, token: str, project_id: Optional[str] = None) -> dict:
        """
        异步验证用户Token（带缓存）

        Args:
            token: Bearer Token

        Returns:
            用户信息字典
        """
        # 先检查缓存
        cached_user = self._get_cached_user(token, project_id)
        if cached_user is not None:
            return cached_user

        headers = {"Authorization": f"Bearer {token}"}
        params = {"project_id": project_id} if project_id else None
        retry_count = max(0, int(self.config.retry_count))
        last_error: httpx.RequestError | None = None
        async with self._async_client() as client:
            for attempt in range(retry_count + 1):
                try:
                    response = await client.post(self.config.validate_url, headers=headers, params=params)
                    if response.status_code == 401:
                        raise TokenInvalidError("Token已过期或无效")
                    if response.status_code != 200:
                        raise AuthServiceError(f"认证服务返回异常状态码: {response.status_code}")
                    data = response.json()
                    self._set_cached_user(token, data, project_id)
                    if attempt > 0:
                        logger.warning(
                            "auth_service async request recovered after retry",
                            extra={"target_service": "auth_service", "operation": "validate_token_async", "retried": True, "final_result": "retry_success"},
                        )
                    return data
                except httpx.TimeoutException:
                    logger.warning(
                        "auth_service async timeout",
                        extra={"target_service": "auth_service", "operation": "validate_token_async", "exception_type": "TimeoutException", "retried": False, "final_result": "timeout"},
                    )
                    raise AuthServiceError("认证服务请求超时")
                except httpx.ConnectError as e:
                    logger.warning(
                        "auth_service async connect error",
                        extra={"target_service": "auth_service", "operation": "validate_token_async", "exception_type": type(e).__name__, "retried": False, "final_result": "connect_error"},
                    )
                    raise AuthServiceError(f"无法连接到认证服务: {e}")
                except httpx.RequestError as e:
                    last_error = e
                    if attempt < retry_count:
                        logger.warning(
                            "auth_service async transient request error, retrying",
                            extra={"target_service": "auth_service", "operation": "validate_token_async", "exception_type": type(e).__name__, "retried": True, "final_result": "retrying"},
                        )
                        continue
                    logger.warning(
                        "auth_service async request failed after retries",
                        extra={"target_service": "auth_service", "operation": "validate_token_async", "exception_type": type(e).__name__, "retried": retry_count > 0, "final_result": "retry_failed"},
                    )
                    raise AuthServiceError(f"认证服务请求失败: {e}")
        raise AuthServiceError(f"认证服务请求失败: {last_error}")

    def ensure_project_token(self, project_id: str, project_name: Optional[str] = None) -> dict:
        """通知认证服务为项目创建项目级Token。"""
        machine_token = getattr(self.config, "service_machine_token", None)
        if not machine_token:
            raise AuthServiceError("未配置auth_service.service_machine_token")

        url = f"http://{self.config.host}:{self.config.port}/api/auth/machine-tokens/projects/ensure"
        headers = {"Authorization": f"Bearer {machine_token}"}
        payload = {
            "project_id": project_id,
            "project_name": project_name,
        }

        try:
            response = self.client.post(url, headers=headers, json=payload)
            if response.status_code not in (200, 201):
                raise AuthServiceError(f"认证服务创建项目级Token失败: {response.text}")
            return response.json()
        except httpx.TimeoutException:
            raise AuthServiceError("认证服务请求超时")
        except httpx.ConnectError as e:
            raise AuthServiceError(f"无法连接到认证服务: {e}")
        except httpx.RequestError as e:
            raise AuthServiceError(f"认证服务请求失败: {e}")


# 单例实例
_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    """获取认证服务实例"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
