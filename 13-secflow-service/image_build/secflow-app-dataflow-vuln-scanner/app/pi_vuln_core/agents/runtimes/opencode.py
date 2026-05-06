"""
OpenCode CLI 运行时适配

统一 trace: 每次调用都在 sessions/<session_id>/calls/ 下落盘完整命令、prompt 与输出。
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.runtime_trace import RuntimeTraceContext, command_display, now_iso
from app.pi_vuln_core.utils.logger import get_logger
from app.pi_vuln_core.utils.win_compat import create_subprocess as create_subprocess_compat

logger = get_logger("runtime.opencode")


class OpenCodeRuntime(BaseAgentRuntime):
    """OpenCode CLI 运行时"""

    async def initialize(self) -> None:
        api_key_env = self.runtime_config.get("api_key_env", "ANTHROPIC_API_KEY")
        if not os.environ.get(api_key_env):
            logger.warning("api_key_not_set", env_var=api_key_env, agent_id=self.agent_id)
        try:
            proc = await create_subprocess_compat(
                "opencode",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                logger.info("opencode_cli_available", version=stdout.decode().strip(), agent_id=self.agent_id)
            else:
                logger.warning(
                    "opencode_cli_not_found",
                    agent_id=self.agent_id,
                    error=stderr.decode("utf-8", errors="replace")[:300],
                )
        except FileNotFoundError:
            logger.warning("opencode_cli_not_found", agent_id=self.agent_id)
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"oc_{uuid.uuid4().hex[:12]}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    async def create_session_with_hint(self, session_hint: Optional[str] = None) -> str:
        if not session_hint:
            return await self.create_session()
        session_id = self._reserve_session_id(session_hint)
        self._sessions[session_id] = {"turns": 0}
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

        session = self._sessions.get(session_id, {"turns": 0})
        timeout = self.runtime_config.get("timeout_seconds", 3600)
        sdk_cfg = self.runtime_config.get("sdk_specific", {})
        provider = sdk_cfg.get("provider", "anthropic")
        model = self.runtime_config.get("model", "claude-sonnet-4-20250514")
        full_prompt = f"{system_prompt}\n\n{message}" if system_prompt else message
        turn_number = session["turns"] + 1

        trace_context = RuntimeTraceContext.create(
            runtime="opencode",
            agent_id=self.agent_id,
            session_id=session_id,
            turn_number=turn_number,
            working_dir=working_dir,
            user_prompt=message,
            system_prompt=system_prompt,
            write_system_prompt=bool(system_prompt),
        )
        effective_prompt_file = trace_context.write_text_artifact("effective_prompt.md", full_prompt)

        cmd = [
            "opencode",
            "--provider", provider,
            "--model", model,
            "--prompt", full_prompt,
            "--non-interactive",
        ]
        cmd_display = command_display(cmd)
        started_monotonic = time.monotonic()

        try:
            trace_context.write_request(
                {
                    "agent_id": self.agent_id,
                    "runtime": "opencode",
                    "session_id": session_id,
                    "turn_number": turn_number,
                    "started_at": now_iso(),
                    "working_dir": trace_context.working_dir,
                    "session_dir": trace_context.session_dir,
                    "call_dir": trace_context.call_dir,
                    "provider": provider,
                    "model": model,
                    "timeout_seconds": timeout,
                    "supports_cli_session": False,
                    "is_continuation": session["turns"] > 0,
                    "user_prompt_len": len(message),
                    "sys_prompt_len": len(system_prompt) if system_prompt else 0,
                    "effective_prompt_len": len(full_prompt),
                    "has_system_prompt": bool(system_prompt),
                    "user_prompt_file": trace_context.user_prompt_file,
                    "system_prompt_file": trace_context.system_prompt_file,
                    "effective_prompt_file": effective_prompt_file,
                    "command_argv": cmd,
                    "command_display": cmd_display,
                }
            )

            logger.info(
                "runtime_execute",
                runtime="opencode",
                agent_id=self.agent_id,
                provider=provider,
                model=model,
                cwd=working_dir,
                user_prompt_len=len(message),
                sys_prompt_len=len(system_prompt) if system_prompt else 0,
                effective_prompt_len=len(full_prompt),
                has_system_prompt=bool(system_prompt),
                is_continuation=session["turns"] > 0,
                session_turns=session["turns"],
                session_dir=trace_context.session_dir,
                call_dir=trace_context.call_dir,
                user_prompt_file=trace_context.user_prompt_file,
                system_prompt_file=trace_context.system_prompt_file,
                effective_prompt_file=effective_prompt_file,
                command=cmd_display,
            )

            proc = await create_subprocess_compat(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            output = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            session["turns"] += 1
            self._sessions[session_id] = session

            if proc.returncode != 0 and not output:
                error = f"opencode exit code={proc.returncode}: {stderr_text[:500]}"
                trace_context.write_result(
                    stdout_text=output,
                    stderr_text=stderr_text,
                    response_text="",
                    payload={
                        "status": "error",
                        "finished_at": now_iso(),
                        "duration_ms": duration_ms,
                        "return_code": proc.returncode,
                        "output_len": len(output),
                        "stderr_len": len(stderr_text),
                        "response_len": 0,
                        "conversation_id": session_id,
                        "turn_count": session["turns"],
                        "finished": False,
                        "error": error,
                    },
                )
                return AgentResponse(content="", error=error, conversation_id=session_id)

            trace_context.write_result(
                stdout_text=output,
                stderr_text=stderr_text,
                response_text=output,
                payload={
                    "status": "completed",
                    "finished_at": now_iso(),
                    "duration_ms": duration_ms,
                    "return_code": proc.returncode,
                    "output_len": len(output),
                    "stderr_len": len(stderr_text),
                    "response_len": len(output),
                    "conversation_id": session_id,
                    "turn_count": session["turns"],
                    "finished": True,
                    "error": None,
                },
            )

            logger.info(
                "runtime_execute_done",
                runtime="opencode",
                agent_id=self.agent_id,
                output_len=len(output),
                return_code=proc.returncode,
                call_dir=trace_context.call_dir,
                duration_ms=duration_ms,
            )
            return AgentResponse(
                content=output,
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
                raw_response=output,
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
                    "error": f"OpenCode 超时 ({timeout}s)",
                },
            )
            return AgentResponse(content="", error=f"OpenCode 超时 ({timeout}s)", conversation_id=session_id)
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
                    "error": "opencode CLI 未安装",
                },
            )
            return AgentResponse(content="", error="opencode CLI 未安装", conversation_id=session_id)
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

    async def shutdown(self) -> None:
        await self.reset()
        self._initialized = False
