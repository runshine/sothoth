"""
智能体运行时注册表

根据 agent type 自动实例化对应 Runtime，管理所有智能体的生命周期。
"""

from __future__ import annotations

from typing import Type

from app.pi_vuln_core.agents.base import BaseAgentRuntime, AgentRuntimeError
from app.pi_vuln_core.agents.runtimes.claude_code import ClaudeCodeRuntime
from app.pi_vuln_core.agents.runtimes.codex import CodexRuntime
from app.pi_vuln_core.agents.runtimes.opencode import OpenCodeRuntime
from app.pi_vuln_core.agents.runtimes.pi_agent import PiAgentRuntime
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("agent_registry")


class AgentRuntimeRegistry:
    """
    智能体运行时注册表 (R2)

    - 根据 agent.type 自动选择并实例化运行时
    - 管理所有运行时实例的生命周期
    - 支持扩展新的 agent type
    """

    RUNTIME_MAP: dict[str, Type[BaseAgentRuntime]] = {
        "claude_code": ClaudeCodeRuntime,
        "codex": CodexRuntime,
        "opencode": OpenCodeRuntime,
        "pi_agent": PiAgentRuntime,
    }

    def __init__(self):
        self._instances: dict[str, BaseAgentRuntime] = {}

    def register_runtime_type(self, agent_type: str,
                               runtime_class: Type[BaseAgentRuntime]) -> None:
        """注册新的智能体类型（扩展用）"""
        self.RUNTIME_MAP[agent_type] = runtime_class
        logger.info("runtime_type_registered", agent_type=agent_type,
                     runtime_class=runtime_class.__name__)

    def register_from_config(self, agents_config: list[dict]) -> None:
        """从 JSON 配置批量注册智能体实例"""
        for agent_cfg in agents_config:
            agent_id = agent_cfg["id"]
            agent_type = agent_cfg["type"]

            if agent_type not in self.RUNTIME_MAP:
                raise AgentRuntimeError(
                    f"未知的智能体类型: '{agent_type}' (agent_id={agent_id}). "
                    f"支持的类型: {list(self.RUNTIME_MAP.keys())}")

            runtime_class = self.RUNTIME_MAP[agent_type]
            instance = runtime_class(agent_cfg)
            self._instances[agent_id] = instance

            logger.info("agent_registered",
                         agent_id=agent_id,
                         agent_type=agent_type,
                         runtime=runtime_class.__name__)

    def get(self, agent_id: str) -> BaseAgentRuntime:
        """获取智能体运行时实例"""
        if agent_id not in self._instances:
            raise AgentRuntimeError(
                f"智能体 '{agent_id}' 未注册. "
                f"已注册: {list(self._instances.keys())}")
        return self._instances[agent_id]

    def has(self, agent_id: str) -> bool:
        """检查智能体是否已注册"""
        return agent_id in self._instances

    @property
    def agent_ids(self) -> list[str]:
        """所有已注册的智能体 ID"""
        return list(self._instances.keys())

    async def initialize_all(self) -> None:
        """初始化所有已注册的运行时"""
        for agent_id, runtime in self._instances.items():
            logger.info("initializing_agent", agent_id=agent_id)
            await runtime.initialize()
        logger.info("all_agents_initialized", count=len(self._instances))

    async def shutdown_all(self) -> None:
        """关闭所有运行时"""
        for agent_id, runtime in self._instances.items():
            try:
                await runtime.shutdown()
            except Exception as e:
                logger.error("agent_shutdown_failed",
                             agent_id=agent_id, error=str(e))
        self._instances.clear()
        logger.info("all_agents_shutdown")
