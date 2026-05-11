"""Service registry integration with the menu service."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from app.config import get_config


class RegistryService:
    def __init__(self):
        self.config = get_config().registry
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def _register_url(self) -> str:
        return f"{self.config.menu_service_url}/api/menu/register"

    def _heartbeat_url(self) -> str:
        return (
            f"{self.config.menu_service_url}/api/menu/heartbeat/"
            f"{self.config.service_id}"
        )

    def _unregister_url(self) -> str:
        return (
            f"{self.config.menu_service_url}/api/menu/unregister/"
            f"{self.config.service_id}"
        )

    def _payload(self) -> dict:
        menu = self.config.menu
        actual_host = "127.0.0.1" if self.config.host == "0.0.0.0" else self.config.host
        return {
            "service_id": self.config.service_id,
            "service_name": self.config.service_name,
            "host": actual_host,
            "port": self.config.port,
            "maturity": self.config.maturity,
            "description": self.config.description,
            "api_prefix": self.config.api_prefix,
            "menu_item": {
                "id": menu.id,
                "name": "/".join(
                    [
                        item
                        for item in [
                            menu.level1.name,
                            menu.level2.name,
                            menu.level3.name,
                        ]
                        if item
                    ]
                )
                or self.config.service_name,
                "name_en": "/".join(
                    [
                        item
                        for item in [
                            menu.level1.name_en,
                            menu.level2.name_en,
                            menu.level3.name_en,
                        ]
                        if item
                    ]
                )
                or self.config.service_name,
                "path": menu.path,
                "parent_id": menu.parent_id,
                "icon": menu.icon,
                "order": menu.order,
                "level1_name": menu.level1.name,
                "level1_name_en": menu.level1.name_en,
                "level2_name": menu.level2.name,
                "level2_name_en": menu.level2.name_en,
                "level3_name": menu.level3.name,
                "level3_name_en": menu.level3.name_en,
            },
        }

    async def register(self) -> bool:
        if not self.config.enabled:
            return True
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self._register_url(), json=self._payload())
        except httpx.HTTPError:
            return False
        return response.status_code in (200, 201)

    async def heartbeat(self) -> bool:
        if not self.config.enabled:
            return True
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self._heartbeat_url())
        except httpx.HTTPError:
            return False
        if response.status_code == 404:
            await self.register()
            return False
        return response.status_code == 200

    async def unregister(self) -> bool:
        if not self.config.enabled:
            return True
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.delete(self._unregister_url())
        except httpx.HTTPError:
            return False
        return response.status_code in (200, 404)

    async def _heartbeat_loop(self):
        interval = max(5, int(self.config.heartbeat_interval_seconds))
        while self._running:
            await asyncio.sleep(interval)
            await self.heartbeat()

    async def start(self):
        if self._running or not self.config.enabled:
            return
        self._running = True
        await self.register()
        self._task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self):
        if not self._running:
            return
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self.config.unregister_on_shutdown:
            await self.unregister()


_registry_service: Optional[RegistryService] = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
