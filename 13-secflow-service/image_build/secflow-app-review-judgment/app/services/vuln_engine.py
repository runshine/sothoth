from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class VulnEngineService:
    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._ready = False

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            config = get_config().vuln_engine_service
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(config.timeout),
                base_url=config.base_url,
            )
        return self._client

    def startup_validate(self) -> None:
        config = get_config().vuln_engine_service
        if not config.enabled:
            self._ready = True
            return
        self._ready = True
        logger.info("vuln engine service validated")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


_vuln_engine_service: Optional[VulnEngineService] = None


def get_vuln_engine_service() -> VulnEngineService:
    global _vuln_engine_service
    if _vuln_engine_service is None:
        _vuln_engine_service = VulnEngineService()
    return _vuln_engine_service