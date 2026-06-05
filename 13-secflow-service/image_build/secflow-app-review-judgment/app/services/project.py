from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class ProjectService:
    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._ready = False

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            config = get_config().project_service
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(config.timeout))
        return self._client

    def startup_validate(self) -> None:
        config = get_config().project_service
        if not config.enabled:
            self._ready = True
            return
        self._ready = True
        logger.info("project service validated")

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


_project_service: Optional[ProjectService] = None


def get_project_service() -> ProjectService:
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service