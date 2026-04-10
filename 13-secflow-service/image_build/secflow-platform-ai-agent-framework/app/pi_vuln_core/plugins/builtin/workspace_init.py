"""内置插件: 工作目录初始化"""

import os
from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode


class WorkspaceInitPlugin(BasePlugin):
    """确保工作目录子结构完整"""

    @property
    def plugin_id(self) -> str:
        return "workspace_init"

    async def execute(self, ctx: PluginContext) -> PluginResult:
        subdirs = ctx.plugin_config.get(
            "create_subdirs",
            ["input", "working", "results", "reviews", "output"])

        created = []
        for subdir in subdirs:
            path = os.path.join(ctx.working_dir, subdir)
            os.makedirs(path, exist_ok=True)
            created.append(subdir)

        return PluginResult(
            code=PluginResultCode.OK_NEXT,
            message=f"初始化 {len(created)} 个子目录",
            data={"created_dirs": created},
        )
