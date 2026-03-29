import threading
import time
from typing import Any, Dict, Optional

import requests


class MenuRegistryService:
    """向 secflow-platform-menu 注册并维持 heartbeat。"""

    def __init__(self, config: Dict[str, Any], logger):
        self.config = config or {}
        self.logger = logger
        self.registry_config = dict(self.config.get("registry") or {})
        self.enabled = bool(self.registry_config.get("enabled", False))
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _build_menu_payload(self) -> Dict[str, Any]:
        registry = self.registry_config
        payload: Dict[str, Any] = {
            "service_id": registry.get("service_id", "secflow-platform-agent"),
            "service_name": registry.get("service_name", "Agent 中心"),
            "host": self.config.get("host", "0.0.0.0"),
            "port": int(self.config.get("port", 8080)),
            "maturity": registry.get("maturity", "已上线"),
            "description": registry.get("description", "提供环境服务、Agent 管理、模板与任务调度能力"),
            "api_prefix": registry.get("api_prefix", "/api/agent"),
            "health_path": registry.get("health_path", "/api/agent/health"),
            "health_timeout_seconds": float(registry.get("health_timeout_seconds", 5)),
            "health_interval_seconds": float(registry.get("health_interval_seconds", 30)),
        }

        menu_item = registry.get("menu_item")
        if isinstance(menu_item, dict) and menu_item.get("id") and menu_item.get("path"):
            payload["menu_item"] = menu_item
        return payload

    def _menu_url(self, suffix: str) -> str:
        base = str(self.registry_config.get("menu_service_url") or "").rstrip("/")
        return f"{base}{suffix}"

    def register(self) -> bool:
        if not self.enabled:
            return False
        response = requests.post(
            self._menu_url("/api/menu/register"),
            json=self._build_menu_payload(),
            timeout=(5, 10),
        )
        response.raise_for_status()
        return True

    def heartbeat(self) -> bool:
        if not self.enabled:
            return False
        service_id = self.registry_config.get("service_id", "secflow-platform-agent")
        response = requests.post(
            self._menu_url(f"/api/menu/heartbeat/{service_id}"),
            timeout=(5, 10),
        )
        if response.status_code == 404:
            self.logger.warning("menu heartbeat returned 404 for %s, re-registering", service_id)
            self.register()
            return True
        response.raise_for_status()
        return True

    def unregister(self) -> bool:
        if not self.enabled:
            return False
        service_id = self.registry_config.get("service_id", "secflow-platform-agent")
        response = requests.delete(
            self._menu_url(f"/api/menu/unregister/{service_id}"),
            timeout=(5, 10),
        )
        if response.status_code not in (200, 404):
            response.raise_for_status()
        return True

    def _loop(self) -> None:
        interval = max(5, int(self.registry_config.get("heartbeat_interval_sec", 30)))
        while not self._stop_event.wait(interval):
            try:
                self.heartbeat()
            except Exception as exc:  # pragma: no cover - 运行时兜底
                self.logger.warning("menu heartbeat failed, retry with register: %s", exc)
                try:
                    self.register()
                except Exception as register_exc:
                    self.logger.warning("menu register retry failed: %s", register_exc)

    def start(self) -> None:
        if not self.enabled or self._thread:
            return
        self._stop_event.clear()
        try:
            self.register()
        except Exception as exc:  # pragma: no cover - 启动时兜底
            self.logger.warning("initial menu register failed: %s", exc)
        self._thread = threading.Thread(target=self._loop, daemon=True, name="menu-registry-heartbeat")
        self._thread.start()
        self.logger.info("menu registry heartbeat thread started")

    def stop(self) -> None:
        if not self._thread:
            return
        self._stop_event.set()
        self._thread.join(timeout=5)
        self._thread = None
        try:
            self.unregister()
        except Exception as exc:  # pragma: no cover - 关闭时兜底
            self.logger.warning("menu unregister failed: %s", exc)
