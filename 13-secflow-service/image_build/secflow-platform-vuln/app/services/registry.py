"""Menu registry service."""

import asyncio
from typing import Optional

import httpx

from app.config import get_config


class RegistryService:
    def __init__(self):
        self.config = get_config().registry
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def _register_payload(self) -> dict:
        menu = self.config.menu
        return {
            "service_id": self.config.service_id,
            "service_name": self.config.service_name,
            "api_prefix": self.config.api_prefix,
            "host": self.config.host,
            "port": self.config.port,
            "maturity": self.config.maturity,
            "description": self.config.description,
            "menu_item": {
                "id": menu.id,
                "path": menu.path,
                "icon": menu.icon,
                "order": menu.order,
                "level1": menu.level1.model_dump() if menu.level1 else None,
                "level2": menu.level2.model_dump() if menu.level2 else None,
                "level3": menu.level3.model_dump() if menu.level3 else None,
            } if menu else None,
        }

    async def register(self) -> None:
        if not self.config.enabled:
            return
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{self.config.menu_service_url}/api/menu/register", json=self._register_payload())

    async def heartbeat(self) -> None:
        if not self.config.enabled:
            return
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{self.config.menu_service_url}/api/menu/heartbeat/{self.config.service_id}")

    async def unregister(self) -> None:
        if not self.config.enabled:
            return
        async with httpx.AsyncClient(timeout=10) as client:
            await client.delete(f"{self.config.menu_service_url}/api/menu/unregister/{self.config.service_id}")

    async def _loop(self) -> None:
        while self._running:
            await asyncio.sleep(30)
            try:
                await self.heartbeat()
            except Exception:
                await self.register()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        try:
            await self.register()
        except Exception:
            pass
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        try:
            await self.unregister()
        except Exception:
            pass


_registry_service: Optional[RegistryService] = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
