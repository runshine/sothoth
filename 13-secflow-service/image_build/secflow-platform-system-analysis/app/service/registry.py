"""Menu registry service client."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class RegistryService:
    def __init__(self):
        self.config = get_config().registry
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def _register_url(self) -> str:
        return f"{self.config.menu_service_url}/api/menu/register"

    def _heartbeat_url(self) -> str:
        return f"{self.config.menu_service_url}/api/menu/heartbeat/{self.config.service_id}"

    def _unregister_url(self) -> str:
        return f"{self.config.menu_service_url}/api/menu/unregister/{self.config.service_id}"

    def _payload(self) -> dict:
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
                "name": menu.level2.name or self.config.service_name,
                "path": menu.path,
                "icon": menu.icon,
                "order": menu.order,
                "level1": {"name": menu.level1.name, "name_en": menu.level1.name_en},
                "level2": {"name": menu.level2.name, "name_en": menu.level2.name_en},
                "level3": {"name": menu.level3.name, "name_en": menu.level3.name_en},
            },
        }

    async def register(self) -> bool:
        if not self.config.enabled:
            return True
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self._register_url(), json=self._payload())
            ok = resp.status_code in (200, 201)
            if not ok:
                logger.warning("menu register failed: status=%s body=%s", resp.status_code, resp.text)
            return ok
        except Exception as exc:
            logger.warning("menu register error: %s", exc)
            return False

    async def heartbeat(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self._heartbeat_url())
            if resp.status_code == 404:
                await self.register()
                return False
            return resp.status_code == 200
        except Exception:
            return False

    async def unregister(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.delete(self._unregister_url())
            return resp.status_code in (200, 404)
        except Exception:
            return False

    async def _heartbeat_loop(self):
        interval = max(5, int(self.config.heartbeat_interval_seconds))
        while self._running:
            await asyncio.sleep(interval)
            await self.heartbeat()

    async def start(self):
        if self._running:
            return
        if not self.config.enabled:
            return
        self._running = True
        await self.register()
        self._task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self):
        if not self._running:
            return
        self._running = False
        if self._task:
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

