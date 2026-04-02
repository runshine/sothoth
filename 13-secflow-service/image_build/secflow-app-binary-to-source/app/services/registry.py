"""Service registry integration with menu service."""

import asyncio
import contextlib
import json
import logging
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.config import get_config


logger = logging.getLogger(__name__)


class RegistryService:
    def __init__(self):
        self.cfg = get_config().registry
        self.task: asyncio.Task | None = None

    def _build_payload(self) -> dict:
        menu = self.cfg.menu
        menu_name_cn = []
        menu_name_en = []
        if menu and menu.level1 and menu.level1.name:
            menu_name_cn.append(menu.level1.name)
            menu_name_en.append(menu.level1.name_en or "")
        if menu and menu.level2 and menu.level2.name:
            menu_name_cn.append(menu.level2.name)
            menu_name_en.append(menu.level2.name_en or "")
        if menu and menu.level3 and menu.level3.name:
            menu_name_cn.append(menu.level3.name)
            menu_name_en.append(menu.level3.name_en or "")

        return {
            "service_id": self.cfg.service_id,
            "service_name": self.cfg.service_name,
            "host": self.cfg.host,
            "port": self.cfg.port,
            "maturity": self.cfg.maturity,
            "description": self.cfg.description,
            "api_prefix": self.cfg.api_prefix,
            "menu_item": {
                "id": menu.id if menu else self.cfg.service_id,
                "name": "/".join(menu_name_cn) if menu_name_cn else self.cfg.service_name,
                "name_en": "/".join(menu_name_en) if menu_name_en else self.cfg.service_name,
                "path": menu.path if menu else f"/{self.cfg.service_id}",
                "icon": menu.icon if menu else "cpu",
                "order": menu.order if menu else 0,
                "level1_name": menu.level1.name if menu and menu.level1 else None,
                "level1_name_en": menu.level1.name_en if menu and menu.level1 else None,
                "level2_name": menu.level2.name if menu and menu.level2 else None,
                "level2_name_en": menu.level2.name_en if menu and menu.level2 else None,
                "level3_name": menu.level3.name if menu and menu.level3 else None,
                "level3_name_en": menu.level3.name_en if menu and menu.level3 else None,
            },
        }

    def register_once(self):
        if not self.cfg.enabled:
            return
        register_url = f"{self.cfg.menu_service_url}/api/menu/register"
        payload = self._build_payload()
        try:
            req = Request(
                register_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    logger.warning("register menu service non-200: %s", resp.status)
        except (HTTPError, URLError) as exc:
            logger.warning("register menu service failed: %s", exc)

    async def _heartbeat_loop(self):
        while True:
            try:
                self.register_once()
            except Exception as exc:
                logger.warning("registry heartbeat failed: %s", exc)
            await asyncio.sleep(30)

    async def start(self):
        if not self.cfg.enabled:
            return
        self.register_once()
        self.task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(Exception):
                await self.task


_registry_service: RegistryService | None = None


def get_registry_service() -> RegistryService:
    global _registry_service
    if _registry_service is None:
        _registry_service = RegistryService()
    return _registry_service
