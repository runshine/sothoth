"""
Mock Agent Runtime — 用于测试

不调用真实 AI，返回可控的预设响应
"""

from __future__ import annotations

import uuid
from typing import Optional, Callable

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse


class MockAgentRuntime(BaseAgentRuntime):
    """
    Mock 运行时 — 用于单元测试和集成测试

    支持设置预定义响应或自定义响应函数
    """

    def __init__(self, agent_config: dict | None = None,
                 default_response: str = "Mock response",
                 response_fn: Callable | None = None):
        config = agent_config or {
            "id": "mock-agent",
            "name": "Mock Agent",
            "type": "mock",
            "reset_context": True,
            "runtime_config": {},
        }
        super().__init__(config)
        self.default_response = default_response
        self.response_fn = response_fn
        self.call_history: list[dict] = []
        self._initialized = True

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"mock_{uuid.uuid4().hex[:8]}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    async def send_message(
        self, message: str, system_prompt: Optional[str] = None,
        session_id: Optional[str] = None, working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()

        self.call_history.append({
            "method": "send_message",
            "message": message,
            "system_prompt": system_prompt,
            "session_id": session_id,
            "working_dir": working_dir,
        })

        session = self._sessions.get(session_id, {"turns": 0})
        session["turns"] += 1
        self._sessions[session_id] = session

        if self.response_fn:
            content = self.response_fn(message, system_prompt)
        else:
            content = self.default_response

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )

    async def multi_turn_execute(
        self, system_prompt: str, user_prompt: str,
        working_dir: str, max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()
        return await self.send_message(
            message=user_prompt, system_prompt=system_prompt,
            session_id=session_id, working_dir=working_dir)

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def shutdown(self) -> None:
        self._sessions.clear()
        self._initialized = False
