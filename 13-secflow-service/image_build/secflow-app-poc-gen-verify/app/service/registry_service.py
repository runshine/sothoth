"""Menu-service registration via HTTP heartbeat (mirrors dvs registry_service).

Optional (gated by REGISTRY_ENABLED). The frontend works without it — the atomic
capability catalog points at the service directly — but registering makes the
service appear in the platform's menu/sidebar.
"""
from __future__ import annotations

import logging
import threading

import httpx

from app.config import get_service_yaml

logger = logging.getLogger("poc.registry")


class RegistryService:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._registered = False

    def _payload(self) -> dict:
        r = get_service_yaml().registry
        return {
            "service_id": r.service_id,
            "service_name": r.service_name,
            "host": r.host,
            "port": r.port,
            "maturity": r.maturity,
            "description": r.description,
            "api_prefix": r.api_prefix,
            "menu": {
                "id": r.menu.id,
                "path": r.menu.path,
                "icon": r.menu.icon,
                "order": r.menu.order,
                "level1": {"name": r.menu.level1.name, "name_en": r.menu.level1.name_en},
                "level2": {"name": r.menu.level2.name, "name_en": r.menu.level2.name_en},
                "level3": {"name": r.menu.level3.name, "name_en": r.menu.level3.name_en},
            },
        }

    def register(self) -> None:
        svc = get_service_yaml()
        if not svc.registry.enabled:
            return
        try:
            httpx.post(
                f"{svc.registry.menu_service_url}/api/menu/register",
                json=self._payload(), timeout=10,
            )
            self._registered = True
            logger.info("registered with menu service: %s", svc.registry.service_id)
        except Exception as exc:
            logger.warning("menu register failed: %s (will retry on heartbeat)", exc)

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._heartbeat_loop, name="poc_registry", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _heartbeat_loop(self) -> None:
        interval = get_service_yaml().registry.heartbeat_interval_seconds
        while not self._stop.wait(interval):
            svc = get_service_yaml()
            try:
                httpx.post(
                    f"{svc.registry.menu_service_url}/api/menu/heartbeat/{svc.registry.service_id}",
                    timeout=10,
                )
            except Exception:
                logger.debug("menu heartbeat failed", exc_info=True)


_registry: RegistryService | None = None


def get_registry_service() -> RegistryService:
    global _registry
    if _registry is None:
        _registry = RegistryService()
    return _registry
