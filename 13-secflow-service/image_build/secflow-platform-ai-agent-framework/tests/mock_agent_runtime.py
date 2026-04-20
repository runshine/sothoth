"""
Mock Agent Runtime — 用于测试

不调用真实 AI，返回可控的预设响应
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
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
            content = self._auto_response(
                message=message,
                system_prompt=system_prompt,
                working_dir=working_dir,
            )

        if content is None:
            content = self.default_response

        return AgentResponse(
            content=content,
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )

    def _auto_response(
        self,
        *,
        message: str,
        system_prompt: Optional[str],
        working_dir: Optional[str],
    ) -> Optional[str]:
        agent_id = self.agent_id.lower()
        message_text = message or ""
        system_text = system_prompt or ""

        if "advisor" in agent_id or "评审" in system_text or "review" in system_text.lower():
            return json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "Mock review passed",
                    "confidence": 0.95,
                },
                ensure_ascii=False,
            )

        if working_dir and "请整理所有漏洞分析结果" in message_text:
            work_dir = Path(working_dir)
            results_dir = work_dir / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            (work_dir / "summary.md").write_text(
                "# Mock Summary\n\n## Findings\n- result_001.md\n- result_002.md\n",
                encoding="utf-8",
            )
            (results_dir / "result_001.md").write_text(
                "# Mock Result 001\n\nEvidence chain.\n",
                encoding="utf-8",
            )
            (results_dir / "result_002.md").write_text(
                "# Mock Result 002\n\nEvidence chain.\n",
                encoding="utf-8",
            )
            return "Mock summary generated"

        if "reflect" in message_text.lower() or "反思" in message_text:
            return "Mock reflection done"

        if "漏洞挖掘任务" in message_text or "攻击面" in message_text or "Analyze mock binary" in message_text:
            return "Mock worker analysis completed"

        return None

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
