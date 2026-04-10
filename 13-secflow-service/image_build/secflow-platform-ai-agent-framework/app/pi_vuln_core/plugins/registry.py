"""
插件注册表

负责加载和管理所有插件实例。
"""

from __future__ import annotations

import importlib
from typing import Any

from app.pi_vuln_core.plugins.base import BasePlugin
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("plugin_registry")


class PluginLoadError(Exception):
    """插件加载错误"""
    pass


class PluginRegistry:
    """
    插件注册表

    - 从 JSON 配置动态加载插件类
    - 缓存插件实例
    - 提供按 ID 查找
    """

    def __init__(self):
        self._plugins: dict[str, BasePlugin] = {}
        self._configs: dict[str, dict[str, Any]] = {}

    def register_from_config(self, plugins_config: list[dict]) -> None:
        """从 JSON 配置批量注册插件"""
        for plugin_cfg in plugins_config:
            pid = plugin_cfg["id"]
            module_path = plugin_cfg["module_path"]
            if module_path.startswith("src."):
                module_path = module_path.replace("src.", "app.pi_vuln_core.", 1)
            class_name = plugin_cfg["class_name"]
            config = plugin_cfg.get("config", {})

            try:
                # 动态导入模块
                module = importlib.import_module(module_path)
                plugin_class = getattr(module, class_name)

                if not issubclass(plugin_class, BasePlugin):
                    raise PluginLoadError(
                        f"类 {class_name} 不是 BasePlugin 的子类")

                # 实例化插件
                instance = plugin_class()
                self._plugins[pid] = instance
                self._configs[pid] = config

                logger.info("plugin_registered",
                            plugin_id=pid,
                            module=module_path,
                            cls=class_name)

            except (ImportError, AttributeError) as e:
                raise PluginLoadError(
                    f"加载插件 '{pid}' 失败: {module_path}.{class_name} - {e}")

    def register_instance(self, plugin_id: str, instance: BasePlugin,
                          config: dict | None = None) -> None:
        """直接注册插件实例（用于测试或内置插件）"""
        self._plugins[plugin_id] = instance
        self._configs[plugin_id] = config or {}

    def get(self, plugin_id: str) -> BasePlugin:
        """获取插件实例"""
        if plugin_id not in self._plugins:
            raise PluginLoadError(
                f"插件 '{plugin_id}' 未注册. "
                f"已注册: {list(self._plugins.keys())}")
        return self._plugins[plugin_id]

    def get_config(self, plugin_id: str) -> dict:
        """获取插件配置"""
        return self._configs.get(plugin_id, {})

    def has(self, plugin_id: str) -> bool:
        return plugin_id in self._plugins

    @property
    def plugin_ids(self) -> list[str]:
        return list(self._plugins.keys())
