"""内置插件: 环境变量设置"""

from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode
import os


class EnvSetupPlugin(BasePlugin):
    """设置环境变量"""

    @property
    def plugin_id(self) -> str:
        return "env_setup"

    async def execute(self, ctx: PluginContext) -> PluginResult:
        extra_vars = ctx.plugin_config.get("extra_vars", {})
        env_file = ctx.plugin_config.get("env_file")
        vars_set = []

        # 从配置设置
        for key, value in extra_vars.items():
            os.environ[key] = str(value)
            vars_set.append(key)

        # 从 .env 文件加载
        if env_file and os.path.exists(env_file):
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ[k.strip()] = v.strip()
                        vars_set.append(k.strip())

        return PluginResult(
            code=PluginResultCode.OK_NEXT,
            message=f"设置 {len(vars_set)} 个环境变量",
            data={"vars_set": vars_set},
        )
