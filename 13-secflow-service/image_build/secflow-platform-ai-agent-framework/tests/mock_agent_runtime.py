from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse


class MockAgentRuntime(BaseAgentRuntime):
    def __init__(self, agent_config: dict | None = None):
        config = agent_config or {
            "id": "mock-agent",
            "name": "Mock Agent",
            "type": "claude_code",
            "reset_context": False,
            "runtime_config": {},
        }
        super().__init__(config)
        self.call_history: list[dict] = []
        self._initialized = True

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"mock_{uuid.uuid4().hex[:8]}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    def _build_response(self, message: str, working_dir: Optional[str]) -> str:
        lower = message.lower()
        if "请将分析结果总结输出" in message or "summary" in lower:
            summary_match = re.search(r"将总结报告写入:\s*(.+)", message)
            results_match = re.search(r"将每个独立的漏洞报告写入:\s*(.+?)/\s*目录", message)
            summary_path = summary_match.group(1).strip() if summary_match else str(Path(working_dir or ".") / "summary.md")
            results_dir = results_match.group(1).strip() if results_match else str(Path(working_dir or ".") / "results")
            summary_target = Path(summary_path)
            summary_target.parent.mkdir(parents=True, exist_ok=True)
            summary_target.write_text("# Summary\n\nMock summary output.\n", encoding="utf-8")
            results_root = Path(results_dir)
            results_root.mkdir(parents=True, exist_ok=True)
            (results_root / "result_001.md").write_text("# Result 001\n\nMock finding A.\n", encoding="utf-8")
            (results_root / "result_002.md").write_text("# Result 002\n\nMock finding B.\n", encoding="utf-8")
            return '{"action":"summary","status":"done"}'
        if "评审" in message or "review" in lower:
            return '{"passed": true, "feedback": "mock review passed"}'
        if "反思" in message or "reflect" in lower:
            return "mock reflection done"
        return "mock worker done"

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()
        session = self._sessions.get(session_id, {"turns": 0})
        session["turns"] += 1
        self._sessions[session_id] = session
        self.call_history.append(
            {
                "message": message,
                "system_prompt": system_prompt,
                "session_id": session_id,
                "working_dir": working_dir,
            }
        )
        return AgentResponse(
            content=self._build_response(message, working_dir),
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )

    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        return await self.send_message(
            message=user_prompt,
            system_prompt=system_prompt,
            session_id=session_id,
            working_dir=working_dir,
        )

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def shutdown(self) -> None:
        self._sessions.clear()
        self._initialized = False
