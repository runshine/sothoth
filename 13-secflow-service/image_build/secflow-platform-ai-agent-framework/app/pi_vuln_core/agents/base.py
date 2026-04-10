"""
智能体运行时抽象基类

每种 Agent 类型（claude_code / codex / opencode / pi_agent）
继承此基类实现具体的 SDK 适配。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("agent_runtime")


class AgentRuntimeError(Exception):
    """智能体运行时错误"""
    pass


class BaseAgentRuntime(ABC):
    """
    智能体运行时抽象基类 (R2)

    核心接口：
    - create_session()      创建新会话
    - send_message()        发送单条消息（用于评审等单轮场景）
    - multi_turn_execute()  多轮执行直到任务完成（用于 Worker）
    - close_session()       关闭会话
    """

    def __init__(self, agent_config: dict):
        self.agent_id: str = agent_config["id"]
        self.agent_name: str = agent_config["name"]
        self.agent_type: str = agent_config["type"]
        self.reset_context: bool = agent_config.get("reset_context", False)
        self.runtime_config: dict = agent_config.get("runtime_config", {})
        self._sessions: dict[str, dict] = {}  # session_id → session_data
        self._initialized: bool = False

    @abstractmethod
    async def initialize(self) -> None:
        """
        初始化运行时（验证 API Key、预热连接等）
        在首次使用前调用一次
        """

    @abstractmethod
    async def create_session(self) -> str:
        """
        创建新会话，返回 session_id
        """

    @abstractmethod
    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        """
        发送单条消息并获取响应

        Args:
            message:      用户消息内容
            system_prompt: 系统提示（首次发送时设置）
            session_id:    会话ID（用于多轮，None则自动创建新会话）
            working_dir:   工作目录

        Returns:
            AgentResponse
        """

    @abstractmethod
    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        """
        多轮执行直到任务完成或达到 max_turns (R6c)

        这是 Worker 阶段的核心调用方式。
        Agent 会自动使用工具（读写文件、执行命令等）直到任务完成。

        Args:
            system_prompt: 系统提示
            user_prompt:   用户任务描述
            working_dir:   工作目录（Agent 在此读写文件）
            max_turns:     最大交互轮数
            session_id:    复用的会话ID

        Returns:
            AgentResponse (finished=True 表示任务完成)
        """

    @abstractmethod
    async def close_session(self, session_id: str) -> None:
        """关闭并清理会话"""

    async def reset(self) -> None:
        """重置所有会话（当 reset_context=True 时调用）"""
        session_ids = list(self._sessions.keys())
        for sid in session_ids:
            try:
                await self.close_session(sid)
            except Exception as e:
                logger.warning("session_close_failed",
                               agent_id=self.agent_id, session_id=sid,
                               error=str(e))
        self._sessions.clear()

    @abstractmethod
    async def shutdown(self) -> None:
        """关闭运行时，释放所有资源"""

    def should_reset_context(self, override: Optional[bool] = None) -> bool:
        """
        判断是否应该重置上下文 (R12)
        override (来自角色定义) 优先于 agent 级别设置
        """
        if override is not None:
            return override
        return self.reset_context

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.agent_id} type={self.agent_type}>"
