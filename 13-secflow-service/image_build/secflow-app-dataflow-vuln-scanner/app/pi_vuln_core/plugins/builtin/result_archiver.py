"""内置插件: 结果归档"""

import os
import shutil
from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode


class ResultArchiverPlugin(BasePlugin):
    """归档结果文件"""

    @property
    def plugin_id(self) -> str:
        return "result_archiver"

    async def execute(self, ctx: PluginContext) -> PluginResult:
        archive_format = ctx.plugin_config.get("archive_format", "tar.gz")

        if not ctx.results_dir or not os.path.isdir(ctx.results_dir):
            return PluginResult(
                code=PluginResultCode.OK_NEXT,
                message="无结果目录，跳过归档")

        try:
            fmt_map = {"tar.gz": "gztar", "zip": "zip", "tar": "tar"}
            fmt = fmt_map.get(archive_format, "gztar")

            archive_path = os.path.join(ctx.working_dir, "results_archive")
            result_path = shutil.make_archive(
                archive_path, fmt, ctx.results_dir)

            return PluginResult(
                code=PluginResultCode.OK_NEXT,
                message=f"结果已归档: {result_path}",
                data={"archive_path": result_path},
            )
        except Exception as e:
            return PluginResult(
                code=PluginResultCode.ERROR_CONTINUE,
                message=f"归档失败: {e}",
                error_detail=str(e),
            )
