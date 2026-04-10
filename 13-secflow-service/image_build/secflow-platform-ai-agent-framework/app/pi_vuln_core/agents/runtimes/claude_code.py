"""
Claude Code 运行时适配

通过 subprocess 调用 claude CLI 实现多轮会话。
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime, AgentRuntimeError
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("runtime.claude_code")


class ClaudeCodeRuntime(BaseAgentRuntime):
    """Claude Code CLI 运行时"""

    async def initialize(self) -> None:
        """验证 claude CLI 可用"""
        api_key_env = self.runtime_config.get("api_key_env", "ANTHROPIC_API_KEY")
        if not os.environ.get(api_key_env):
            logger.warning("api_key_not_set", env_var=api_key_env,
                           agent_id=self.agent_id)

        # 检查 claude 命令是否可用
        try:
            proc = await asyncio.create_subprocess_exec(
                "claude", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            logger.info("claude_cli_available", version=stdout.decode().strip(),
                        agent_id=self.agent_id)
        except FileNotFoundError:
            logger.warning("claude_cli_not_found", agent_id=self.agent_id,
                           msg="将使用 mock 模式")
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"cc_{uuid.uuid4().hex[:12]}"
        self._sessions[session_id] = {"turns": 0, "history": []}
        logger.debug("session_created", agent_id=self.agent_id,
                      session_id=session_id)
        return session_id

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()

        session = self._sessions.get(session_id, {"turns": 0, "history": []})

        cmd = ["claude", "-p", message, "--output-format", "json"]

        if system_prompt and session["turns"] == 0:
            cmd.extend(["--system-prompt", system_prompt])

        model = self.runtime_config.get("model")
        if model:
            cmd.extend(["--model", model])

        max_tokens = self.runtime_config.get("max_tokens")
        if max_tokens:
            cmd.extend(["--max-turns", str(max_tokens)])

        if session_id:
            cmd.extend(["--conversation-id", session_id])

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
            session["turns"] += 1
            session["history"].append({"role": "user", "content": message})
            session["history"].append({"role": "assistant", "content": output})
            self._sessions[session_id] = session

            # 尝试解析 JSON 输出
            try:
                parsed = json.loads(output)
                content = parsed.get("result", output)
                token_usage = {
                    "input": parsed.get("input_tokens", 0),
                    "output": parsed.get("output_tokens", 0),
                }
            except (json.JSONDecodeError, TypeError):
                content = output
                token_usage = {}

            return AgentResponse(
                content=content,
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
                token_usage=token_usage,
            )

        except asyncio.TimeoutError:
            return AgentResponse(
                content="",
                error=f"Claude Code 执行超时 ({timeout}s)",
                conversation_id=session_id,
            )
        except FileNotFoundError:
            return AgentResponse(
                content="",
                error="claude CLI 未安装",
                conversation_id=session_id,
            )

    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        """Claude Code 的多轮执行 — 实际上 claude -p 已是多轮模式"""
        if session_id is None:
            session_id = await self.create_session()

        return await self.send_message(
            message=user_prompt,
            system_prompt=system_prompt,
            session_id=session_id,
            working_dir=working_dir,
        )

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        logger.debug("session_closed", agent_id=self.agent_id,
                      session_id=session_id)

    async def shutdown(self) -> None:
        await self.reset()
        self._initialized = False
