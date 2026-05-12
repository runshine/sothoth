"""
插件链执行器

串行执行插件链，根据每个插件的返回码决定后续行为。
支持6种返回码的完整处理逻辑 (R8)。
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Optional

from app.pi_vuln_core.plugins.base import BasePlugin, PluginContext, PluginResult, PluginResultCode
from app.pi_vuln_core.plugins.registry import PluginRegistry
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("plugin_executor")


@dataclass
class PluginChainResult:
    """插件链执行结果"""
    action: str
    # completed            - 所有插件正常执行完毕
    # end_stage_normal     - 某插件返回 OK_END_STAGE
    # end_stage_skip_next  - 某插件返回 ERROR_END_NEXT
    # exit_workflow        - 某插件返回 ERROR_EXIT

    results: list[PluginResult] = field(default_factory=list)
    error: Optional[str] = None


class PluginChainExecutor:
    """
    插件链执行器 (R5a, R8)

    串行执行插件列表，根据返回码决定：
    - OK_NEXT:          继续下一个插件
    - OK_END_STAGE:     跳过后续插件，正常结束阶段
    - ERROR_CONTINUE:   记录错误但继续下一个插件
    - ERROR_END_NEXT:   结束当前阶段，进入下一阶段
    - ERROR_RESTART:    历史兼容码；按失败退出处理，禁止自动重启整个工作流
    - ERROR_EXIT:       立即退出工作流
    """

    def __init__(self, plugin_registry: PluginRegistry):
        self.registry = plugin_registry

    async def execute_chain(
        self,
        plugin_ids: list[str],
        base_ctx: PluginContext,
        phase: str,  # "start" | "end"
        recorder: Optional[object] = None,
    ) -> PluginChainResult:
        """
        串行执行插件链

        Args:
            plugin_ids:  插件ID列表，按序执行
            base_ctx:    基础上下文（plugin_config 会被替换为每个插件自己的）
            phase:       "start" 或 "end"
            recorder:    执行记录器（可选）

        Returns:
            PluginChainResult
        """
        results: list[PluginResult] = []

        for i, plugin_id in enumerate(plugin_ids):
            plugin = self.registry.get(plugin_id)
            plugin_config = self.registry.get_config(plugin_id)

            # 为每个插件设置自己的 config
            ctx = PluginContext(
                workflow_id=base_ctx.workflow_id,
                task_id=base_ctx.task_id,
                execution_id=base_ctx.execution_id,
                working_dir=base_ctx.working_dir,
                task_file=base_ctx.task_file,
                plugin_config=plugin_config,
                shared_state=base_ctx.shared_state,
                global_config=base_ctx.global_config,
                cycle_number=base_ctx.cycle_number,
                summary_file=base_ctx.summary_file,
                results_dir=base_ctx.results_dir,
                review_records_dir=base_ctx.review_records_dir,
                agent_registry=base_ctx.agent_registry,
            )

            start_time = time.monotonic()

            try:
                result = await plugin.execute(ctx)
                result.duration_ms = int((time.monotonic() - start_time) * 1000)
            except Exception:
                result = PluginResult(
                    code=PluginResultCode.ERROR_EXIT,
                    message=f"插件 '{plugin_id}' 抛出未捕获异常",
                    error_detail=traceback.format_exc(),
                    duration_ms=int((time.monotonic() - start_time) * 1000),
                )
            finally:
                try:
                    await plugin.cleanup(ctx)
                except Exception as ce:
                    logger.warning("plugin_cleanup_failed",
                                   plugin_id=plugin_id, error=str(ce))

            # 记录插件执行结果 (R8)
            if recorder and hasattr(recorder, "record_plugin"):
                await recorder.record_plugin(
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    phase=phase,
                    plugin_id=plugin_id,
                    sequence=i + 1,
                    result=result,
                )

            logger.info("plugin_executed",
                         plugin_id=plugin_id,
                         phase=phase,
                         sequence=i + 1,
                         code=result.code.value,
                         duration_ms=result.duration_ms,
                         message=result.message)

            results.append(result)

            # 更新共享状态
            if result.data:
                base_ctx.shared_state.update(result.data)

            # ═══ 根据返回码决定下一步 ═══
            match result.code:
                case PluginResultCode.OK_NEXT:
                    continue

                case PluginResultCode.OK_END_STAGE:
                    logger.info("plugin_end_stage", plugin_id=plugin_id,
                                reason="OK_END_STAGE")
                    return PluginChainResult(
                        action="end_stage_normal", results=results)

                case PluginResultCode.ERROR_CONTINUE:
                    logger.warning("plugin_error_continue",
                                   plugin_id=plugin_id,
                                   error=result.message)
                    continue

                case PluginResultCode.ERROR_END_NEXT:
                    logger.warning("plugin_error_end_next",
                                   plugin_id=plugin_id,
                                   error=result.message)
                    return PluginChainResult(
                        action="end_stage_skip_next",
                        results=results,
                        error=result.message)

                case PluginResultCode.ERROR_RESTART:
                    logger.error("plugin_error_restart_blocked",
                                 plugin_id=plugin_id,
                                 error=result.message)
                    return PluginChainResult(
                        action="exit_workflow",
                        results=results,
                        error=result.message or "自动重启整个工作流已禁用")

                case PluginResultCode.ERROR_EXIT:
                    logger.error("plugin_error_exit",
                                 plugin_id=plugin_id,
                                 error=result.message,
                                 detail=result.error_detail)
                    return PluginChainResult(
                        action="exit_workflow",
                        results=results,
                        error=result.message)

        # 所有插件正常执行完毕
        return PluginChainResult(action="completed", results=results)
