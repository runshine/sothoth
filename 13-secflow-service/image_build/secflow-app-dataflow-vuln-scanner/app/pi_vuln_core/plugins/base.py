"""
插件系统基础定义

包含：
- PluginResultCode: 6种返回码 (R8)
- PluginResult: 插件执行结果
- PluginContext: 插件执行上下文
- BasePlugin: 插件抽象基类
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class PluginResultCode(Enum):
    """
    插件执行结果码 — 6种 (R8)

    正常路径:
        OK_NEXT          - 正常，执行下一个插件
        OK_END_STAGE     - 正常，结束当前阶段（跳过后续插件）

    异常但可继续:
        ERROR_CONTINUE   - 异常，但允许执行下一个插件
        ERROR_END_NEXT   - 异常，结束当前阶段并进入下一阶段

    异常需退出:
        ERROR_RESTART    - 历史兼容码；当前按失败退出处理，不允许自动重启整个工作流
        ERROR_EXIT       - 异常，立即退出工作流
    """
    OK_NEXT = "ok_next"
    OK_END_STAGE = "ok_end_stage"
    ERROR_CONTINUE = "error_continue"
    ERROR_END_NEXT = "error_end_next_stage"
    ERROR_RESTART = "error_restart"
    ERROR_EXIT = "error_exit"


@dataclass
class PluginResult:
    """插件执行结果"""
    code: PluginResultCode
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error_detail: Optional[str] = None
    duration_ms: int = 0


@dataclass
class PluginContext:
    """
    插件执行上下文

    在整个插件链执行期间共享，插件可通过 shared_state 传递数据
    """
    workflow_id: str
    task_id: str
    execution_id: str
    working_dir: str
    task_file: str
    plugin_config: dict[str, Any]        # 当前插件的配置
    shared_state: dict[str, Any]         # 插件间共享状态（可读写）
    global_config: dict[str, Any]        # 全局配置
    cycle_number: int = 1                # 当前循环轮次

    # 仅结束阶段可用
    summary_file: Optional[str] = None
    results_dir: Optional[str] = None
    review_records_dir: Optional[str] = None

    # Agent 运行时引用（供需要 AI 的插件使用）
    agent_registry: Any = None


class BasePlugin(ABC):
    """
    插件抽象基类 (R5a)

    所有启动/结束阶段插件必须继承此类并实现 execute()。
    execute() 必须返回 PluginResult，明确指定 PluginResultCode。
    """

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """插件 ID，与 JSON 配置中的 id 对应"""

    @property
    def plugin_name(self) -> str:
        """插件名称（默认同 plugin_id）"""
        return self.plugin_id

    @abstractmethod
    async def execute(self, ctx: PluginContext) -> PluginResult:
        """
        执行插件逻辑

        Args:
            ctx: 插件执行上下文

        Returns:
            PluginResult: 必须包含明确的 PluginResultCode
        """

    async def cleanup(self, ctx: PluginContext) -> None:
        """清理钩子，无论结果如何都会调用"""
        pass
