"""
Pi Agent 运行时适配 (跨平台: Linux / Windows)

命令格式:
  首次调用:
    pi --provider <provider> --model <model> -p --thinking <level>
       --system-prompt @sys.md --session-dir <dir>
       --tools read,bash,edit,write @user.md

  续接调用 (同 session 的后续消息):
    pi --provider <provider> --model <model> -p --thinking <level>
       --session-dir <dir> --continue
       --tools read,bash,edit,write @user.md

关键设计:
  - system_prompt 通过 --system-prompt @file 独立传入 (仅首次)
  - user_message 通过 @file 传入
  - 续接调用通过 --continue 加载已有会话上下文, 不重复传 system_prompt
  - Linux: create_subprocess_exec (直接执行)
  - Windows: create_subprocess_shell (处理 .cmd 文件)
  - --session-dir 保存每次调用的会话记录到工作目录
  - 统一 trace: 每次调用都在 sessions/<session_id>/calls/ 下落盘完整命令、prompt 与输出
"""

from __future__ import annotations

import asyncio
import platform
import time
import uuid
from typing import Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.runtime_trace import RuntimeTraceContext, command_display, now_iso
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("runtime.pi_agent")

IS_WINDOWS = platform.system() == "Windows"


class PiAgentRuntime(BaseAgentRuntime):
    """Pi Coding Agent CLI 运行时 (跨平台)"""

    async def initialize(self) -> None:
        try:
            if IS_WINDOWS:
                proc = await asyncio.create_subprocess_shell(
                    "pi --version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "pi",
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, _ = await proc.communicate()
            logger.info(
                "pi_cli_available",
                version=stdout.decode().strip(),
                agent_id=self.agent_id,
                platform=platform.system(),
            )
        except FileNotFoundError:
            logger.warning("pi_cli_not_found", agent_id=self.agent_id)
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"pi_{uuid.uuid4().hex[:12]}"
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
        timeout = self.runtime_config.get("timeout_seconds", 600)
        sdk_cfg = self.runtime_config.get("sdk_specific", {})
        provider = sdk_cfg.get("provider", "github-copilot")
        thinking = sdk_cfg.get("thinking", "high")
        tools = sdk_cfg.get("tools", "read,bash,edit,write")
        model = self.runtime_config.get("model", "gpt-5-mini")

        is_continuation = session["turns"] > 0
        turn_number = session["turns"] + 1
        trace_context = RuntimeTraceContext.create(
            runtime="pi_agent",
            agent_id=self.agent_id,
            session_id=session_id,
            turn_number=turn_number,
            working_dir=working_dir,
            user_prompt=message,
            system_prompt=system_prompt,
            write_system_prompt=not is_continuation,
        )

        try:
            cmd_args = [
                "pi",
                "--provider", provider,
                "--model", model,
                "-p",
                "--thinking", thinking,
                "--tools", tools,
            ]

            if trace_context.system_prompt_file:
                cmd_args.extend(["--system-prompt", f"@{trace_context.system_prompt_file}"])

            if trace_context.session_dir:
                cmd_args.extend(["--session-dir", trace_context.session_dir])
                if is_continuation:
                    cmd_args.append("--continue")
            else:
                cmd_args.append("--no-session")

            cmd_args.append(f"@{trace_context.user_prompt_file}")

            cmd_display = command_display(cmd_args)
            started_monotonic = time.monotonic()

            trace_context.write_request(
                {
                    "agent_id": self.agent_id,
                    "runtime": "pi_agent",
                    "session_id": session_id,
                    "turn_number": turn_number,
                    "started_at": now_iso(),
                    "working_dir": trace_context.working_dir,
                    "session_dir": trace_context.session_dir,
                    "call_dir": trace_context.call_dir,
                    "provider": provider,
                    "model": model,
                    "thinking": thinking,
                    "tools": tools,
                    "timeout_seconds": timeout,
                    "is_continuation": is_continuation,
                    "user_prompt_len": len(message),
                    "sys_prompt_len": len(system_prompt) if system_prompt else 0,
                    "has_system_prompt": trace_context.system_prompt_file is not None,
                    "user_prompt_file": trace_context.user_prompt_file,
                    "system_prompt_file": trace_context.system_prompt_file,
                    "command_argv": cmd_args,
                    "command_display": cmd_display,
                }
            )

            logger.info(
                "runtime_execute",
                runtime="pi_agent",
                agent_id=self.agent_id,
                provider=provider,
                model=model,
                cwd=working_dir,
                user_prompt_len=len(message),
                sys_prompt_len=len(system_prompt) if system_prompt else 0,
                has_system_prompt=(trace_context.system_prompt_file is not None),
                is_continuation=is_continuation,
                session_turns=session["turns"],
                session_dir=trace_context.session_dir,
                call_dir=trace_context.call_dir,
                user_prompt_file=trace_context.user_prompt_file,
                system_prompt_file=trace_context.system_prompt_file,
                command=cmd_display,
            )

            if IS_WINDOWS:
                proc = await asyncio.create_subprocess_shell(
                    cmd_display,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=working_dir,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=working_dir,
                )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            stdout_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)

            session["turns"] += 1
            self._sessions[session_id] = session

            if proc.returncode != 0 and not stdout_text:
                error = f"pi exit code={proc.returncode}: {stderr_text[:500]}"
                trace_context.write_result(
                    stdout_text=stdout_text,
                    stderr_text=stderr_text,
                    response_text="",
                    payload={
                        "status": "error",
                        "finished_at": now_iso(),
                        "duration_ms": duration_ms,
                        "return_code": proc.returncode,
                        "output_len": len(stdout_text),
                        "stderr_len": len(stderr_text),
                        "response_len": 0,
                        "conversation_id": session_id,
                        "turn_count": session["turns"],
                        "finished": False,
                        "error": error,
                    },
                )
                return AgentResponse(
                    content="",
                    error=error,
                    conversation_id=session_id,
                    turn_count=session["turns"],
                )

            trace_context.write_result(
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                response_text=stdout_text,
                payload={
                    "status": "completed",
                    "finished_at": now_iso(),
                    "duration_ms": duration_ms,
                    "return_code": proc.returncode,
                    "output_len": len(stdout_text),
                    "stderr_len": len(stderr_text),
                    "response_len": len(stdout_text),
                    "conversation_id": session_id,
                    "turn_count": session["turns"],
                    "finished": True,
                    "error": None,
                },
            )

            logger.info(
                "runtime_execute_done",
                runtime="pi_agent",
                agent_id=self.agent_id,
                output_len=len(stdout_text),
                return_code=proc.returncode,
                call_dir=trace_context.call_dir,
                duration_ms=duration_ms,
            )

            return AgentResponse(
                content=stdout_text,
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True,
                raw_response=stdout_text,
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
                    "error": f"Pi Agent 超时 ({timeout}s)",
                },
            )
            return AgentResponse(
                content="",
                error=f"Pi Agent 超时 ({timeout}s)",
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
                    "error": "pi CLI 未安装",
                },
            )
            return AgentResponse(
                content="",
                error="pi CLI 未安装",
                conversation_id=session_id,
            )
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
