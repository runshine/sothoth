"""
Claude Code 运行时适配

通过 subprocess 调用 claude CLI 实现多轮会话。
统一 trace: 每次调用都在 sessions/<session_id>/calls/ 下落盘完整命令、prompt 与输出。
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.runtime_trace import RuntimeTraceContext, command_display, now_iso
from app.pi_vuln_core.utils.logger import get_logger
from app.pi_vuln_core.utils.win_compat import create_subprocess as create_subprocess_compat

logger = get_logger("runtime.claude_code")


class ClaudeCodeRuntime(BaseAgentRuntime):
    """Claude Code CLI 运行时"""

    async def initialize(self) -> None:
        api_key_env = self.runtime_config.get("api_key_env", "ANTHROPIC_API_KEY")
        if not os.environ.get(api_key_env):
            logger.warning("api_key_not_set", env_var=api_key_env, agent_id=self.agent_id)

        try:
            proc = await create_subprocess_compat(
                "claude",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                logger.info("claude_cli_available", version=stdout.decode().strip(), agent_id=self.agent_id)
            else:
                logger.warning(
                    "claude_cli_not_found",
                    agent_id=self.agent_id,
                    error=stderr.decode("utf-8", errors="replace")[:300],
                    msg="将使用 mock 模式",
                )
        except FileNotFoundError:
            logger.warning("claude_cli_not_found", agent_id=self.agent_id, msg="将使用 mock 模式")
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"cc_{uuid.uuid4().hex[:12]}"
        self._sessions[session_id] = {"turns": 0, "history": []}
        logger.debug("session_created", agent_id=self.agent_id, session_id=session_id)
        return session_id

    async def create_session_with_hint(self, session_hint: Optional[str] = None) -> str:
        if not session_hint:
            return await self.create_session()
        session_id = self._reserve_session_id(session_hint)
        self._sessions[session_id] = {"turns": 0, "history": []}
        logger.debug("session_created", agent_id=self.agent_id, session_id=session_id)
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
        timeout = self.runtime_config.get("timeout_seconds", 3600)
        turn_number = session["turns"] + 1
        include_system_prompt = bool(system_prompt and session["turns"] == 0)

        trace_context = RuntimeTraceContext.create(
            runtime="claude_code",
            agent_id=self.agent_id,
            session_id=session_id,
            turn_number=turn_number,
            working_dir=working_dir,
            user_prompt=message,
            system_prompt=system_prompt,
            write_system_prompt=include_system_prompt,
        )

        cmd = ["claude", "-p", message, "--output-format", "json"]
        if include_system_prompt:
            cmd.extend(["--system-prompt", system_prompt])

        model = self.runtime_config.get("model")
        if model:
            cmd.extend(["--model", model])

        max_tokens = self.runtime_config.get("max_tokens")
        if max_tokens:
            cmd.extend(["--max-turns", str(max_tokens)])

        cmd.extend(["--conversation-id", session_id])
        cmd_display = command_display(cmd)
        started_monotonic = time.monotonic()

        try:
            trace_context.write_request(
                {
                    "agent_id": self.agent_id,
                    "runtime": "claude_code",
                    "session_id": session_id,
                    "turn_number": turn_number,
                    "started_at": now_iso(),
                    "working_dir": trace_context.working_dir,
                    "session_dir": trace_context.session_dir,
                    "call_dir": trace_context.call_dir,
                    "model": model,
                    "timeout_seconds": timeout,
                    "max_tokens": max_tokens,
                    "output_format": "json",
                    "is_continuation": session["turns"] > 0,
                    "user_prompt_len": len(message),
                    "sys_prompt_len": len(system_prompt) if system_prompt else 0,
                    "has_system_prompt": include_system_prompt,
                    "user_prompt_file": trace_context.user_prompt_file,
                    "system_prompt_file": trace_context.system_prompt_file,
                    "command_argv": cmd,
                    "command_display": cmd_display,
                }
            )

            logger.info(
                "runtime_execute",
                runtime="claude_code",
                agent_id=self.agent_id,
                model=model,
                cwd=working_dir,
                user_prompt_len=len(message),
                sys_prompt_len=len(system_prompt) if system_prompt else 0,
                has_system_prompt=include_system_prompt,
                is_continuation=session["turns"] > 0,
                session_turns=session["turns"],
                session_dir=trace_context.session_dir,
                call_dir=trace_context.call_dir,
                user_prompt_file=trace_context.user_prompt_file,
                system_prompt_file=trace_context.system_prompt_file,
                command=cmd_display,
            )

            proc = await create_subprocess_compat(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            raw_output = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            session["turns"] += 1
            session["history"].append({"role": "user", "content": message})

            token_usage: dict[str, int] = {}
            parsed_payload: dict | None = None
            try:
                parsed_payload = json.loads(raw_output)
                content = parsed_payload.get("result", raw_output)
                token_usage = {
                    "input": parsed_payload.get("input_tokens", 0),
                    "output": parsed_payload.get("output_tokens", 0),
                }
            except (json.JSONDecodeError, TypeError):
                content = raw_output

            session["history"].append({"role": "assistant", "content": content})
            self._sessions[session_id] = session

            if proc.returncode != 0 and not raw_output:
                error = f"claude exit code={proc.returncode}: {stderr_text[:500]}"
                trace_context.write_result(
                    stdout_text=raw_output,
                    stderr_text=stderr_text,
                    response_text="",
                    payload={
                        "status": "error",
                        "finished_at": now_iso(),
                        "duration_ms": duration_ms,
                        "return_code": proc.returncode,
                        "output_len": len(raw_output),
                        "stderr_len": len(stderr_text),
                        "response_len": 0,
                        "conversation_id": session_id,
                        "turn_count": session["turns"],
                        "finished": False,
                        "error": error,
                        "token_usage": token_usage,
                    },
                )
                return AgentResponse(content="", error=error, conversation_id=session_id)

            trace_context.write_result(
                stdout_text=raw_output,
                stderr_text=stderr_text,
                response_text=content,
                payload={
                    "status": "completed",
                    "finished_at": now_iso(),
                    "duration_ms": duration_ms,
                    "return_code": proc.returncode,
                    "output_len": len(raw_output),
                    "stderr_len": len(stderr_text),
                    "response_len": len(content),
                    "conversation_id": session_id,
                    "turn_count": session["turns"],
                    "finished": True,
                    "error": None,
                    "token_usage": token_usage,
                },
            )

            logger.info(
                "runtime_execute_done",
                runtime="claude_code",
                agent_id=self.agent_id,
                output_len=len(content),
                return_code=proc.returncode,
                call_dir=trace_context.call_dir,
                duration_ms=duration_ms,
            )

            return AgentResponse(
                content=content,
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
                token_usage=token_usage,
                raw_response=parsed_payload if parsed_payload is not None else raw_output,
            )

        except asyncio.TimeoutError:
            trace_context.write_result(
                stdout_text="",
                stderr_text="",
                response_text="",
                payload={
                    "status": "timeout",
                    "finished_at": now_iso(),
                    "duration_ms": None,
                    "return_code": None,
                    "output_len": 0,
                    "stderr_len": 0,
                    "response_len": 0,
                    "conversation_id": session_id,
                    "turn_count": session.get("turns", 0),
                    "finished": False,
                    "error": f"Claude Code 执行超时 ({timeout}s)",
                },
            )
            return AgentResponse(
                content="",
                error=f"Claude Code 执行超时 ({timeout}s)",
                conversation_id=session_id,
            )
        except FileNotFoundError:
            trace_context.write_result(
                stdout_text="",
                stderr_text="",
                response_text="",
                payload={
                    "status": "error",
                    "finished_at": now_iso(),
                    "duration_ms": None,
                    "return_code": None,
                    "output_len": 0,
                    "stderr_len": 0,
                    "response_len": 0,
                    "conversation_id": session_id,
                    "turn_count": session.get("turns", 0),
                    "finished": False,
                    "error": "claude CLI 未安装",
                },
            )
            return AgentResponse(content="", error="claude CLI 未安装", conversation_id=session_id)
        finally:
            trace_context.cleanup()

    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
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
        logger.debug("session_closed", agent_id=self.agent_id, session_id=session_id)

    async def shutdown(self) -> None:
        await self.reset()
        self._initialized = False
