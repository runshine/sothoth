from __future__ import annotations

import os

from app.models.contracts import PluginResult, PluginStatus
from app.plugins.base import BasePlugin, PluginExecutionContext


class WorkflowControlPlugin(BasePlugin):
    def execute(self, ctx: PluginExecutionContext) -> PluginResult:
        env_name = self.config.get("export_env")
        env_value = self.config.get("export_value")
        if env_name and env_value is not None:
            os.environ[str(env_name)] = str(env_value)
        return PluginResult(
            status=PluginStatus(self.config.get("status", "SUCCESS_NEXT")),
            message=str(self.config.get("message", self.plugin_id)),
            payload=dict(self.config.get("payload", {})),
        )


class TaskMetadataPlugin(BasePlugin):
    def execute(self, ctx: PluginExecutionContext) -> PluginResult:
        key = str(self.config.get("key", "task_title"))
        ctx.shared_state[key] = ctx.task.title
        return PluginResult(
            status=PluginStatus.SUCCESS_NEXT,
            message=f"stored task metadata into shared_state[{key}]",
            payload={"key": key, "value": ctx.task.title},
        )
