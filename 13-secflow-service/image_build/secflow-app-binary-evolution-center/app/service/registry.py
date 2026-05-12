from __future__ import annotations

import asyncio
import logging

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class RegistryService:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None

    async def _register_once(self) -> None:
        cfg = get_config().registry
        if not cfg.enabled:
            return
        payload = {
            "service_id": cfg.service_id,
            "service_name": cfg.service_name,
            "service_type": "execution",
            "endpoint": f"http://{cfg.host}:{cfg.port}",
            "healthcheck_url": f"http://{cfg.host}:{cfg.port}{cfg.api_prefix}/health",
            "callback_mode": "manual",
            "auth_mode": "machine_token",
            "version": "1.0.0",
            "meta": {"maturity": cfg.maturity, "description": cfg.description},
            "capabilities": [],
        }
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                await client.post(f"{cfg.menu_service_url}/api/menu/services/register", json=payload)
            except Exception as exc:
                logger.warning("registry register failed: %s", exc)

    async def _heartbeat_loop(self) -> None:
        cfg = get_config().registry
        while True:
            await asyncio.sleep(cfg.heartbeat_interval_seconds)
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.post(f"{cfg.menu_service_url}/api/menu/heartbeat/{cfg.service_id}")
            except Exception as exc:
                logger.warning("registry heartbeat failed: %s", exc)

    async def start(self) -> None:
        if not get_config().registry.enabled:
            return
        await self._register_once()
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._heartbeat_loop(), name="binary-evolution-registry-heartbeat")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


_registry_service: RegistryService | None = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
