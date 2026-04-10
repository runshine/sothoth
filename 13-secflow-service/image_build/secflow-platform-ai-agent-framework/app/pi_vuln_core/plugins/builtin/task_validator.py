"""内置插件: 输入任务校验"""

import os
from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode


class TaskValidatorPlugin(BasePlugin):
    """校验输入任务文件"""

    @property
    def plugin_id(self) -> str:
        return "task_validator"

    async def execute(self, ctx: PluginContext) -> PluginResult:
        if not ctx.task_file:
            return PluginResult(
                code=PluginResultCode.ERROR_EXIT,
                message="未指定输入任务文件")

        if not os.path.exists(ctx.task_file):
            return PluginResult(
                code=PluginResultCode.ERROR_EXIT,
                message=f"输入任务文件不存在: {ctx.task_file}")

        # 检查文件大小
        size = os.path.getsize(ctx.task_file)
        if size == 0:
            return PluginResult(
                code=PluginResultCode.ERROR_EXIT,
                message=f"输入任务文件为空: {ctx.task_file}")

        return PluginResult(
            code=PluginResultCode.OK_NEXT,
            message=f"任务文件校验通过 ({size} bytes)",
            data={"task_file_size": size},
        )
