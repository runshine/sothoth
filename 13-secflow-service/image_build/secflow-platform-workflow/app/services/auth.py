"""
Authentication service module
"""

import logging
import time
from typing import Optional, Dict

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class AuthServiceError(Exception):
    """Auth service error"""
    pass


class TokenInvalidError(AuthServiceError):
    """Token invalid error"""
    pass


class TokenCacheEntry:
    """Token cache entry"""
    def __init__(self, user_info: dict, ttl_seconds: int):
        self.user_info = user_info
        self.expiry_time = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expiry_time


class AuthService:
    """Authentication service client"""

    def __init__(self):
        self.config = get_config().auth_service
        self.client = httpx.Client(timeout=self.config.timeout)
        self._token_cache: Dict[str, TokenCacheEntry] = {}
        self._cache_enabled = self.config.token_cache_enabled
        self._cache_ttl_seconds = self.config.token_cache_ttl_minutes * 60

    def _get_cached_user(self, token: str) -> Optional[dict]:
        """Get user info from cache"""
        if not self._cache_enabled:
            return None

        cache_entry = self._token_cache.get(token)
        if cache_entry is None:
            return None

        if cache_entry.is_expired():
            del self._token_cache[token]
            logger.debug("Token cache expired, removed from cache")
            return None

        logger.debug("Token cache hit")
        return cache_entry.user_info

    def _set_cached_user(self, token: str, user_info: dict):
        """Cache user info"""
        if not self._cache_enabled:
            return

        self._token_cache[token] = TokenCacheEntry(user_info, self._cache_ttl_seconds)
        logger.debug(f"Token cached, TTL={self._cache_ttl_seconds}s")

    def validate_token(self, token: str) -> dict:
        """
        Validate user token (with cache)

        Args:
            token: Bearer Token

        Returns:
            User info dict

        Raises:
            TokenInvalidError: Token invalid
            AuthServiceError: Auth service exception
        """
        # Check cache first
        cached_user = self._get_cached_user(token)
        if cached_user is not None:
            return cached_user

        # Cache miss, call auth service
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = self.client.post(
                self.config.validate_human_url,
                headers=headers
            )

            if response.status_code == 401:
                raise TokenInvalidError("Token expired or invalid")

            if response.status_code != 200:
                raise AuthServiceError(
                    f"Auth service returned abnormal status code: {response.status_code}"
                )

            data = response.json()

            # Cache validation result
            self._set_cached_user(token, data)

            return data

        except httpx.TimeoutException:
            raise AuthServiceError("Auth service request timeout")
        except httpx.ConnectError as e:
            raise AuthServiceError(f"Cannot connect to auth service: {e}")

    async def validate_token_async(self, token: str) -> dict:
        """
        Validate user token asynchronously (with cache)

        Args:
            token: Bearer Token

        Returns:
            User info dict
        """
        # Check cache first
        cached_user = self._get_cached_user(token)
        if cached_user is not None:
            return cached_user

        # Cache miss, call auth service
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = await client.post(
                    self.config.validate_human_url,
                    headers=headers
                )

                if response.status_code == 401:
                    raise TokenInvalidError("Token expired or invalid")

                if response.status_code != 200:
                    raise AuthServiceError(
                        f"Auth service returned abnormal status code: {response.status_code}"
                    )

                data = response.json()

                # Cache validation result
                self._set_cached_user(token, data)

                return data

            except httpx.TimeoutException:
                raise AuthServiceError("Auth service request timeout")
            except httpx.ConnectError as e:
                raise AuthServiceError(f"Cannot connect to auth service: {e}")


# Singleton instance
_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    """Get auth service instance"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
