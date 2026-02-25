"""
Menu registration service module
"""

import asyncio
import json
import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class RegistryError(Exception):
    """Registry error"""
    pass


class RegistryService:
    """Menu registration service client"""

    def __init__(self):
        self.config = get_config().registry
        self.client: Optional[httpx.AsyncClient] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running = False

    def get_register_url(self) -> str:
        """Get registration URL"""
        return f"{self.config.menu_service_url}/api/menu/register"

    def get_heartbeat_url(self) -> str:
        """Get heartbeat URL"""
        return f"{self.config.menu_service_url}/api/menu/heartbeat/{self.config.service_id}"

    def get_unregister_url(self) -> str:
        """Get unregister URL"""
        return f"{self.config.menu_service_url}/api/menu/unregister/{self.config.service_id}"

    def build_menu_item(self) -> dict:
        """Build menu item"""
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

        # Set parent ID
        if menu.level3 and menu.level2:
            menu_item["parent_id"] = menu.level2.id if hasattr(menu.level2, 'id') else menu.level2.name
        elif menu.level2 and menu.level1:
            menu_item["parent_id"] = menu.level1.id if hasattr(menu.level1, 'id') else menu.level1.name

        return menu_item

    def get_register_payload(self) -> dict:
        """Get registration payload"""
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
        Register service to Menu registration center

        Returns:
            Whether registration succeeded
        """
        if not self.config.enabled:
            logger.info("Registration center not enabled, skipping registration")
            return True

        try:
            payload = self.get_register_payload()
            logger.info(f"Registering service to Menu center: {json.dumps(payload, ensure_ascii=False)}")

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    self.get_register_url(),
                    json=payload
                )
                if response.status_code in (200, 201):
                    logger.info(f"Service {self.config.service_id} registered successfully")
                    return True
                else:
                    logger.warning(f"Service registration failed: {response.status_code}, {response.text}")
                    return False
        except Exception as e:
            logger.error(f"Service registration exception: {e}")
            return False

    async def heartbeat(self) -> bool:
        """
        Send heartbeat to Menu registration center

        Returns:
            Whether succeeded
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.get_heartbeat_url())
                if response.status_code == 200:
                    logger.debug("Heartbeat sent successfully")
                    return True
                elif response.status_code == 404:
                    logger.warning("Heartbeat returned 404, service may not be registered, re-registering...")
                    # 404 means service not registered, need to re-register
                    await self.register()
                    return False
                else:
                    logger.warning(f"Heartbeat failed: {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Heartbeat exception: {e}")
            return False

    async def unregister(self) -> bool:
        """
        Unregister service from Menu registration center

        Returns:
            Whether succeeded
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.delete(self.get_unregister_url())
                if response.status_code in (200, 404):
                    logger.info(f"Service {self.config.service_id} unregistered")
                    return True
                else:
                    logger.warning(f"Unregister failed: {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Unregister exception: {e}")
            return False

    async def _heartbeat_loop(self):
        """Heartbeat loop"""
        while self._running:
            await asyncio.sleep(30)  # Default 30 second heartbeat interval
            await self.heartbeat()

    async def start(self):
        """Start heartbeat task"""
        if self._running:
            return

        # Check if enabled
        if not self.config.enabled:
            logger.info("Registration center not enabled, skipping registration")
            return

        self._running = True
        # Register immediately
        await self.register()
        # Start heartbeat task
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Menu registration center heartbeat task started")

    async def stop(self):
        """Stop heartbeat task and unregister service"""
        if not self._running:
            return

        # Cancel heartbeat task
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Unregister service
        await self.unregister()
        logger.info("Menu registration center heartbeat task stopped")


# Singleton instance
_registry_service: Optional[RegistryService] = None


def get_registry_service() -> RegistryService:
    """Get registry service instance"""
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
