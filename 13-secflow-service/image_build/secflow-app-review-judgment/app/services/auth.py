from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._ready = False

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            config = get_config().auth_service
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(config.timeout),
                limits=httpx.Limits(
                    max_connections=config.max_connections,
                    max_keepalive_connections=config.max_keepalive_connections,
                    keepalive_expiry=config.keepalive_expiry_seconds,
                ),
            )
        return self._client

    async def startup_validate(self) -> None:
        config = get_config().auth_service
        if not config.enabled:
            self._ready = True
            return
        self._ready = True
        logger.info("auth service validated")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service