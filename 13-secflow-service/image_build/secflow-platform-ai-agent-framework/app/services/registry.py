from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.config import get_config

logger = logging.getLogger(__name__)


class RegistryService:
    def __init__(self):
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if not get_config().registry.enabled:
            return
        logger.info("registry service start requested")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass


_registry_service: RegistryService | None = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
