"""Authentication service for token validation with caching support."""

import time
import threading
from typing import Optional
from app.schemas import TokenPayload

# httpx is imported inside methods to avoid circular imports issues


class TokenCache:
    """Token缓存管理器，支持TTL过期机制。"""

    def __init__(self, ttl_seconds: int = 900):
        """
        初始化Token缓存。

        Args:
            ttl_seconds: 缓存有效期（秒），默认15分钟
        """
        self.ttl_seconds = ttl_seconds
        self._cache: dict[str, tuple[TokenPayload, float]] = {}
        self._lock = threading.RLock()

    def get(self, token: str) -> Optional[TokenPayload]:
        """获取缓存的TokenPayload，如果过期返回None。"""
        with self._lock:
            if token not in self._cache:
                return None
            payload, expires_at = self._cache[token]
            if time.time() > expires_at:
                # 缓存已过期，删除
                del self._cache[token]
                return None
            return payload

    def set(self, token: str, payload: TokenPayload):
        """缓存TokenPayload。"""
        with self._lock:
            expires_at = time.time() + self.ttl_seconds
            self._cache[token] = (payload, expires_at)

    def invalidate(self, token: str):
        """使单个Token缓存失效。"""
        with self._lock:
            self._cache.pop(token, None)

    def clear_expired(self):
        """清理所有过期的缓存项。"""
        with self._lock:
            current_time = time.time()
            expired_keys = [
                token for token, (_, expires_at) in self._cache.items()
                if current_time > expires_at
            ]
            for key in expired_keys:
                del self._cache[key]

    def clear_all(self):
        """清空所有缓存。"""
        with self._lock:
            self._cache.clear()


# 全局缓存实例
_token_cache: Optional[TokenCache] = None


def get_token_cache() -> TokenCache:
    """获取Token缓存实例。"""
    global _token_cache
    if _token_cache is None:
        raise RuntimeError("Token cache not initialized")
    return _token_cache


def init_token_cache(ttl_seconds: int = 900):
    """初始化Token缓存。"""
    global _token_cache
    _token_cache = TokenCache(ttl_seconds=ttl_seconds)


class AuthService:
    """认证服务，用于验证用户Token，支持缓存。"""

    def __init__(
        self,
        base_url: str,
        validate_path: str = "/api/auth/validate-human-token",
        timeout: int = 10,
        token_cache_ttl: int = 900
    ):
        """
        初始化认证服务。

        Args:
            base_url: 认证服务的基础URL
            validate_path: Token验证路径
            timeout: 请求超时时间（秒）
            token_cache_ttl: Token缓存有效期（秒），默认15分钟
        """
        self.base_url = base_url.rstrip("/")
        self.validate_path = validate_path
        self.timeout = timeout
        self._cache = None

    def _get_cache(self) -> Optional[TokenCache]:
        """获取缓存实例（懒加载）。"""
        if self._cache is None:
            try:
                self._cache = get_token_cache()
            except RuntimeError:
                pass
        return self._cache

    async def validate_token(self, token: str) -> Optional[TokenPayload]:
        """
        验证用户Token的有效性。

        支持缓存机制：在缓存有效期内直接从缓存返回，不再请求auth服务。

        Args:
            token: Bearer Token

        Returns:
            TokenPayload: 验证成功返回用户信息
            None: 验证失败返回None
        """
        import httpx

        # 先检查缓存
        cache = self._get_cache()
        if cache:
            cached_payload = cache.get(token)
            if cached_payload is not None:
                return cached_payload

        # 缓存未命中或已过期，请求auth服务
        url = f"{self.base_url}{self.validate_path}"
        headers = {"Authorization": f"Bearer {token}"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    headers=headers,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()
                    payload = TokenPayload(**data)

                    # 存入缓存
                    if cache:
                        cache.set(token, payload)

                    return payload
                else:
                    return None

        except Exception as e:
            # 记录日志，生产环境应使用logging
            print(f"Token验证失败: {e}")
            return None

    async def invalidate_token(self, token: str):
        """使Token缓存失效（用于登出等场景）。"""
        cache = self._get_cache()
        if cache:
            cache.invalidate(token)


# 全局认证服务实例（由配置文件初始化）
_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    """获取认证服务实例。"""
    global _auth_service
    if _auth_service is None:
        raise RuntimeError("Auth service not initialized")
    return _auth_service


def init_auth_service(
    base_url: str,
    validate_path: str = "/api/auth/validate-human-token",
    timeout: int = 10,
    token_cache_ttl: int = 900
):
    """初始化认证服务实例。"""
    global _auth_service
    # 先初始化缓存
    init_token_cache(ttl_seconds=token_cache_ttl)
    # 创建认证服务
    _auth_service = AuthService(
        base_url=base_url,
        validate_path=validate_path,
        timeout=timeout,
        token_cache_ttl=token_cache_ttl
    )