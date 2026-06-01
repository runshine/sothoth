from __future__ import annotations

import asyncio
import logging

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class RegistryService:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._running = False

    def _register_url(self) -> str:
        cfg = get_config().registry
        return f"{cfg.menu_service_url}/api/menu/register"

    def _heartbeat_url(self) -> str:
        cfg = get_config().registry
        return f"{cfg.menu_service_url}/api/menu/heartbeat/{cfg.service_id}"

    def _unregister_url(self) -> str:
        cfg = get_config().registry
        return f"{cfg.menu_service_url}/api/menu/unregister/{cfg.service_id}"

    async def _register_once(self) -> None:
        cfg = get_config().registry
        if not cfg.enabled:
            return
        payload = {
            "service_id": cfg.service_id,
            "service_name": cfg.service_name,
            "api_prefix": cfg.api_prefix,
            "host": cfg.host,
            "port": cfg.port,
            "maturity": cfg.maturity,
            "description": cfg.description,
            "menu_item": {
                "id": cfg.menu.id,
                "name": cfg.menu.level3_name or cfg.menu.path,
                "path": cfg.menu.path,
                "icon": cfg.menu.icon,
                "order": cfg.menu.order,
                "level1": {
                    "name": cfg.menu.level1_name,
                    "name_en": None,
                },
                "level2": {
                    "name": cfg.menu.level2_name,
                    "name_en": None,
                },
                "level3": {
                    "name": cfg.menu.level3_name,
                    "name_en": None,
                } if cfg.menu.level3_name else None,
            },
        }
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                response = await client.post(self._register_url(), json=payload)
                if response.status_code not in (200, 201):
                    logger.warning("registry register failed: status=%s body=%s", response.status_code, response.text)
            except Exception as exc:
                logger.warning("registry register failed: %s", exc)

    async def _heartbeat_loop(self) -> None:
        cfg = get_config().registry
        while self._running:
            await asyncio.sleep(cfg.heartbeat_interval_seconds)
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.post(self._heartbeat_url())
                    if response.status_code == 404:
                        await self._register_once()
            except Exception as exc:
                logger.warning("registry heartbeat failed: %s", exc)

    async def start(self) -> None:
        if self._running or not get_config().registry.enabled:
            return
        self._running = True
        await self._register_once()
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._heartbeat_loop(), name="binary-evolution-registry-heartbeat")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        cfg = get_config().registry
        if not cfg.enabled:
            return
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                await client.delete(self._unregister_url())
            except Exception:
                pass


_registry_service: RegistryService | None = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
