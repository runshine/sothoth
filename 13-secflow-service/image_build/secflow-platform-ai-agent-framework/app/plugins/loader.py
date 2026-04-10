from __future__ import annotations

import importlib
from typing import Dict

from app.models.config_models import FrameworkConfig, PluginDefinition
from app.plugins.base import BasePlugin
from app.plugins.builtin import BUILTIN_PLUGINS


class PluginLoader:
    def __init__(self, framework_config: FrameworkConfig):
        self.framework_config = framework_config
        self._definitions: Dict[str, PluginDefinition] = {plugin.id: plugin for plugin in framework_config.plugins}

    def resolve(self, plugin_id: str) -> BasePlugin:
        builtin_cls = BUILTIN_PLUGINS.get(plugin_id)
        if builtin_cls:
            return builtin_cls()
        plugin_definition = self._definitions.get(plugin_id)
        if not plugin_definition:
            raise KeyError(plugin_id)
        if plugin_definition.kind == "builtin":
            builtin_cls = BUILTIN_PLUGINS.get(plugin_definition.id)
            if not builtin_cls:
                raise KeyError(plugin_definition.id)
            return builtin_cls(plugin_definition)

        module = importlib.import_module(plugin_definition.module)
        plugin_cls = getattr(module, plugin_definition.class_name)
        return plugin_cls(plugin_definition)
