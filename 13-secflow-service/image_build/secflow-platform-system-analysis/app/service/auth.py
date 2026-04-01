"""Authentication service client."""

from __future__ import annotations

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
    def __init__(self, payload: dict, ttl_seconds: int):
        self.payload = payload
        self.expiry_time = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expiry_time


class AuthService:
    def __init__(self):
        self.config = get_config().auth_service
        self._cache_enabled = bool(self.config.token_cache_enabled)
        self._cache_ttl = int(self.config.token_cache_ttl_minutes) * 60
        self._token_cache: Dict[str, TokenCacheEntry] = {}

    def _cache_key(self, token: str, project_id: Optional[str]) -> str:
        return f"{token}::{project_id or ''}"

    def _get_cached(self, token: str, project_id: Optional[str]) -> Optional[dict]:
        if not self._cache_enabled:
            return None
        key = self._cache_key(token, project_id)
        cache_entry = self._token_cache.get(key)
        if not cache_entry:
            return None
        if cache_entry.is_expired():
            self._token_cache.pop(key, None)
            return None
        return cache_entry.payload

    def _set_cached(self, token: str, project_id: Optional[str], payload: dict):
        if not self._cache_enabled:
            return
        if payload.get("token_type") == "machine":
            return
        self._token_cache[self._cache_key(token, project_id)] = TokenCacheEntry(payload, self._cache_ttl)

    async def validate_token_async(self, token: str, project_id: Optional[str] = None) -> dict:
        cached = self._get_cached(token, project_id)
        if cached is not None:
            return cached

        params = {"project_id": project_id} if project_id else None
        headers = {"Authorization": f"Bearer {token}"}
        timeout = self.config.timeout

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(self.config.validate_url, headers=headers, params=params)
        except httpx.TimeoutException as exc:
            raise AuthServiceError(f"auth request timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AuthServiceError(f"auth request failed: {exc}") from exc

        if resp.status_code == 401:
            raise TokenInvalidError("invalid token")
        if resp.status_code != 200:
            raise AuthServiceError(f"auth service status={resp.status_code}, body={resp.text}")

        payload = resp.json()
        self._set_cached(token, project_id, payload)
        return payload


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service

