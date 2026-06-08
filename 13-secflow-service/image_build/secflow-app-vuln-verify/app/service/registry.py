"""Service registry client for secflow-platform-menu."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


def _level_to_dict(level) -> Optional[dict]:
    if not level:
        return None
    if hasattr(level, "model_dump"):
        return level.model_dump()
    return {"name": getattr(level, "name", None), "name_en": getattr(level, "name_en", None)}


class RegistryService:
    def __init__(self) -> None:
        self.config = get_config().registry
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running = False

    def _payload(self) -> dict:
        menu = self.config.menu
        menu_item = None
        if menu:
            menu_item = {
                "id": menu.id,
                "name": menu.level3.name if menu.level3 else menu.path,
                "path": menu.path,
                "icon": menu.icon,
                "order": menu.order,
                "level1": _level_to_dict(menu.level1),
                "level2": _level_to_dict(menu.level2),
                "level3": _level_to_dict(menu.level3),
            }
        return {
            "service_id": self.config.service_id,
            "service_name": self.config.service_name,
            "api_prefix": self.config.api_prefix,
            "host": self.config.host,
            "port": self.config.port,
            "maturity": self.config.maturity,
            "description": self.config.description,
            "menu_item": menu_item,
        }

    async def register(self) -> bool:
        if not self.config.enabled:
            return True
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(f"{self.config.menu_service_url}/api/menu/register", json=self._payload())
                if response.status_code in (200, 201):
                    logger.info("服务注册成功: %s", json.dumps(self._payload(), ensure_ascii=False))
                    return True
                logger.warning("服务注册失败: %s %s", response.status_code, response.text)
                return False
        except Exception as exc:
            logger.warning("服务注册异常: %s", exc)
            return False

    async def heartbeat(self) -> bool:
        if not self.config.enabled:
            return True
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(f"{self.config.menu_service_url}/api/menu/heartbeat/{self.config.service_id}")
                if response.status_code == 404:
                    return await self.register()
                return response.status_code == 200
        except Exception as exc:
            logger.warning("心跳异常: %s", exc)
            return False

    async def unregister(self) -> bool:
        if not self.config.enabled:
            return True
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.delete(f"{self.config.menu_service_url}/api/menu/unregister/{self.config.service_id}")
                return response.status_code in (200, 404)
        except Exception:
            return False

    async def _heartbeat_loop(self) -> None:
        while self._running:
            await asyncio.sleep(30)
            await self.heartbeat()

    async def start(self) -> None:
        if self._running or not self.config.enabled:
            return
        self._running = True
        await self.register()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        await self.unregister()


_registry_service: Optional[RegistryService] = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
