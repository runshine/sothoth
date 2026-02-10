"""
Menu注册中心服务模块
"""

import asyncio
import json
import logging
from typing import Optional

import httpx

from config import get_config

logger = logging.getLogger(__name__)


class RegistryError(Exception):
    """注册中心错误"""
    pass


class RegistryService:
    """Menu注册中心服务客户端"""

    def __init__(self):
        self.config = get_config().registry
        self.client: Optional[httpx.AsyncClient] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running = False

    def get_register_url(self) -> str:
        """获取注册URL"""
        return f"{self.config.menu_service_url}/api/menu/register"

    def get_heartbeat_url(self) -> str:
        """获取心跳URL"""
        return f"{self.config.menu_service_url}/api/menu/heartbeat/{self.config.service_id}"

    def get_unregister_url(self) -> str:
        """获取注销URL"""
        return f"{self.config.menu_service_url}/api/menu/unregister/{self.config.service_id}"

    def build_menu_item(self) -> dict:
        """构建菜单项"""
        if not self.config.menu:
            return {}

        menu = self.config.menu
        menu_item = {
            "id": menu.id,
            "name": menu.level3.name if menu.level3 else (menu.level2.name if menu.level2 else menu.level1.name),
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

        # 设置父级ID
        if menu.level3 and menu.level2:
            menu_item["parent_id"] = menu.level2.id if hasattr(menu.level2, 'id') else menu.level2.name
        elif menu.level2 and menu.level1:
            menu_item["parent_id"] = menu.level1.id if hasattr(menu.level1, 'id') else menu.level1.name

        return menu_item

    def get_register_payload(self) -> dict:
        """获取注册请求载荷"""
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
        """
        向Menu注册中心注册服务

        Returns:
            是否注册成功
        """
        if not self.config.enabled:
            logger.info("注册中心未启用，跳过注册")
            return True

        try:
            payload = self.get_register_payload()
            logger.info(f"向Menu注册中心注册服务: {json.dumps(payload, ensure_ascii=False)}")

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    self.get_register_url(),
                    json=payload
                )
                if response.status_code in (200, 201):
                    logger.info(f"服务 {self.config.service_id} 注册成功")
                    return True
                else:
                    logger.warning(f"服务注册失败: {response.status_code}, {response.text}")
                    return False
        except Exception as e:
            logger.error(f"服务注册异常: {e}")
            return False

    async def heartbeat(self) -> bool:
        """
        向Menu注册中心发送心跳

        Returns:
            是否成功
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.get_heartbeat_url())
                if response.status_code == 200:
                    logger.debug(f"心跳发送成功")
                    return True
                elif response.status_code == 404:
                    logger.warning(f"心跳返回404，服务可能未注册，正在重新注册...")
                    # 404 表示服务未注册，需要重新注册
                    await self.register()
                    return False
                else:
                    logger.warning(f"心跳失败: {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"心跳异常: {e}")
            return False

    async def unregister(self) -> bool:
        """
        向Menu注册中心注销服务

        Returns:
            是否成功
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.delete(self.get_unregister_url())
                if response.status_code in (200, 404):
                    logger.info(f"服务 {self.config.service_id} 已注销")
                    return True
                else:
                    logger.warning(f"注销失败: {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"注销异常: {e}")
            return False

    async def _heartbeat_loop(self):
        """心跳循环"""
        while self._running:
            await asyncio.sleep(30)  # 默认30秒心跳间隔
            await self.heartbeat()

    async def start(self):
        """启动心跳任务"""
        if self._running:
            return

        # 检查是否启用
        if not self.config.enabled:
            logger.info("注册中心未启用，跳过注册")
            return

        self._running = True
        # 立即注册
        await self.register()
        # 启动心跳任务
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Menu注册中心心跳任务已启动")

    async def stop(self):
        """停止心跳任务并注销服务"""
        if not self._running:
            return

        # 取消心跳任务
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # 注销服务
        await self.unregister()
        logger.info("Menu注册中心心跳任务已停止")


# 单例实例
_registry_service: Optional[RegistryService] = None


def get_registry_service() -> RegistryService:
    """获取注册服务实例"""
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
