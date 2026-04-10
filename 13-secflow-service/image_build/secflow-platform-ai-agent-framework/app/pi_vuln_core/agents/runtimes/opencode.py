"""
OpenCode CLI 运行时适配
"""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("runtime.opencode")


class OpenCodeRuntime(BaseAgentRuntime):
    """OpenCode CLI 运行时"""

    async def initialize(self) -> None:
        api_key_env = self.runtime_config.get("api_key_env", "ANTHROPIC_API_KEY")
        if not os.environ.get(api_key_env):
            logger.warning("api_key_not_set", env_var=api_key_env,
                           agent_id=self.agent_id)
        try:
            proc = await asyncio.create_subprocess_exec(
                "opencode", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            logger.info("opencode_cli_available",
                        version=stdout.decode().strip(),
                        agent_id=self.agent_id)
        except FileNotFoundError:
            logger.warning("opencode_cli_not_found", agent_id=self.agent_id)
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"oc_{uuid.uuid4().hex[:12]}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    async def send_message(
        self, message: str, system_prompt: Optional[str] = None,
        session_id: Optional[str] = None, working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()

        sdk_cfg = self.runtime_config.get("sdk_specific", {})
        provider = sdk_cfg.get("provider", "anthropic")
        model = self.runtime_config.get("model", "claude-sonnet-4-20250514")

        full_prompt = message
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{message}"

        cmd = [
            "opencode",
            "--provider", provider,
            "--model", model,
            "--prompt", full_prompt,
            "--non-interactive",
        ]

        timeout = self.runtime_config.get("timeout_seconds", 300)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout)

            output = stdout.decode("utf-8", errors="replace")
            session = self._sessions.get(session_id, {"turns": 0})
            session["turns"] += 1
            self._sessions[session_id] = session

            return AgentResponse(
                content=output,
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
            )
        except asyncio.TimeoutError:
            return AgentResponse(content="", error=f"OpenCode 超时 ({timeout}s)")
        except FileNotFoundError:
            return AgentResponse(content="", error="opencode CLI 未安装")

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
        await self.reset()
        self._initialized = False
