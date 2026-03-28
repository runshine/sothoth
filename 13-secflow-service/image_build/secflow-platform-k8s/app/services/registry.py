"""
Menu注册中心服务模块
"""

import asyncio
import json
import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class RegistryService:
    """Menu注册中心服务客户端"""

    def __init__(self):
        self.config = get_config().registry
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running = False

    def get_register_url(self) -> str:
        return f"{self.config.menu_service_url}/api/menu/register"

    def get_heartbeat_url(self) -> str:
        return f"{self.config.menu_service_url}/api/menu/heartbeat/{self.config.service_id}"

    def get_unregister_url(self) -> str:
        return f"{self.config.menu_service_url}/api/menu/unregister/{self.config.service_id}"

    def build_menu_item(self) -> dict:
        if not self.config.menu:
            return {}

        menu = self.config.menu
        display_name = (
            (menu.level3.name if menu.level3 and menu.level3.name else None)
            or (menu.level2.name if menu.level2 and menu.level2.name else None)
            or (menu.level1.name if menu.level1 and menu.level1.name else None)
            or self.config.service_name
        )
        menu_item = {
            "id": menu.id,
            "name": display_name,
            "path": menu.path,
            "icon": menu.icon,
            "order": menu.order,
            "parent_id": None,
            "level1": {
                "name": menu.level1.name if menu.level1 else None,
                "name_en": menu.level1.name_en if menu.level1 else None,
            } if menu.level1 else None,
            "level2": {
                "name": menu.level2.name if menu.level2 else None,
                "name_en": menu.level2.name_en if menu.level2 else None,
            } if menu.level2 else None,
            "level3": {
                "name": menu.level3.name if menu.level3 else None,
                "name_en": menu.level3.name_en if menu.level3 else None,
            } if menu.level3 else None,
        }

        if menu.level3 and menu.level2:
            menu_item["parent_id"] = menu.level2.id if hasattr(menu.level2, 'id') else menu.level2.name
        elif menu.level2 and menu.level1:
            menu_item["parent_id"] = menu.level1.id if hasattr(menu.level1, 'id') else menu.level1.name

        return menu_item

    def get_register_payload(self) -> dict:
        return {
            "service_id": self.config.service_id,
            "service_name": self.config.service_name,
            "api_prefix": self.config.api_prefix,
            "host": self.config.host,
            "port": self.config.port,
            "maturity": self.config.maturity,
            "description": self.config.description,
            "menu_item": self.build_menu_item(),
        }

    async def register(self) -> bool:
        if not self.config.enabled:
            logger.info("注册中心未启用，跳过注册")
            return True

        try:
            payload = self.get_register_payload()
            logger.info("向Menu注册中心注册服务: %s", json.dumps(payload, ensure_ascii=False))
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.get_register_url(), json=payload)
                if response.status_code in (200, 201):
                    logger.info("服务 %s 注册成功", self.config.service_id)
                    return True
                logger.warning("服务注册失败: %s, %s", response.status_code, response.text)
                return False
        except Exception as exc:
            logger.error("服务注册异常: %s", exc)
            return False

    async def heartbeat(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.get_heartbeat_url())
                if response.status_code == 200:
                    return True
                if response.status_code == 404:
                    logger.warning("心跳返回404，服务可能未注册，正在重新注册...")
                    await self.register()
                    return False
                logger.warning("心跳失败: %s", response.status_code)
                return False
        except Exception as exc:
            logger.error("心跳异常: %s", exc)
            return False

    async def unregister(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.delete(self.get_unregister_url())
                return response.status_code in (200, 404)
        except Exception as exc:
            logger.error("注销异常: %s", exc)
            return False

    async def _heartbeat_loop(self):
        while self._running:
            await asyncio.sleep(30)
            await self.heartbeat()

    async def start(self):
        if self._running:
            return
        if not self.config.enabled:
            logger.info("注册中心未启用，跳过注册")
            return
        self._running = True
        await self.register()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Menu注册中心心跳任务已启动")

    async def stop(self):
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
        logger.info("Menu注册中心心跳任务已停止")


_registry_service: Optional[RegistryService] = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
