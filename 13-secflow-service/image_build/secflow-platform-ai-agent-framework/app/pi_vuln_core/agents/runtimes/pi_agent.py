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
"""

from __future__ import annotations

import asyncio
import os
import platform
import tempfile
import uuid
from typing import Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("runtime.pi_agent")

IS_WINDOWS = platform.system() == "Windows"


def _tmp_path(prefix: str) -> str:
    """生成临时文件路径"""
    return os.path.join(
        tempfile.gettempdir(),
        f"{prefix}_{uuid.uuid4().hex[:8]}.md")


class PiAgentRuntime(BaseAgentRuntime):
    """Pi Coding Agent CLI 运行时 (跨平台)"""

    async def initialize(self) -> None:
        try:
            if IS_WINDOWS:
                proc = await asyncio.create_subprocess_shell(
                    "pi --version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
            else:
                proc = await asyncio.create_subprocess_exec(
                    "pi", "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            logger.info("pi_cli_available",
                        version=stdout.decode().strip(),
                        agent_id=self.agent_id,
                        platform=platform.system())
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

        # ═══ 写 user message 到临时文件 (通过 @file 传入) ═══
        user_file = _tmp_path("pi_user")
        with open(user_file, "w", encoding="utf-8") as f:
            f.write(message)

        # ═══ 写 system prompt 到临时文件 (通过 --system-prompt @file 传入) ═══
        # 仅首次调用需要: 续接时 session 已包含 system prompt
        sys_file = None
        if system_prompt and not is_continuation:
            sys_file = _tmp_path("pi_sys")
            with open(sys_file, "w", encoding="utf-8") as f:
                f.write(system_prompt)

        # ═══ Session 目录 ═══
        session_dir = None
        if working_dir:
            session_dir = os.path.join(working_dir, "sessions", session_id)
            os.makedirs(session_dir, exist_ok=True)

        try:
            # ═══ 构建命令 ═══
            cmd_args = [
                "pi",
                "--provider", provider,
                "--model", model,
                "-p",
                "--thinking", thinking,
                "--tools", tools,
            ]

            # system prompt: 通过 pi 原生 --system-prompt 传入, 仅首次
            if sys_file:
                cmd_args.extend(["--system-prompt", f"@{sys_file}"])

            # session 管理
            if session_dir:
                cmd_args.extend(["--session-dir", session_dir])
                if is_continuation:
                    cmd_args.append("--continue")
            else:
                cmd_args.append("--no-session")

            # user message: 通过 @file 传入
            cmd_args.append(f"@{user_file}")

            logger.info("pi_execute",
                        agent_id=self.agent_id,
                        provider=provider, model=model,
                        cwd=working_dir,
                        user_prompt_len=len(message),
                        sys_prompt_len=len(system_prompt) if system_prompt else 0,
                        has_system_prompt=(sys_file is not None),
                        is_continuation=is_continuation,
                        session_turns=session["turns"],
                        session_dir=session_dir)

            # ═══ 跨平台 subprocess ═══
            if IS_WINDOWS:
                cmd_str = ' '.join(
                    f'"{c}"' if (' ' in c or '@' in c or '\\' in c) else c
                    for c in cmd_args)
                proc = await asyncio.create_subprocess_shell(
                    cmd_str,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=working_dir)
            else:
                proc = await asyncio.create_subprocess_exec(
                    *cmd_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=working_dir)

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout)

            output = stdout.decode("utf-8", errors="replace")
            err_output = stderr.decode("utf-8", errors="replace")

            session["turns"] += 1
            self._sessions[session_id] = session

            if proc.returncode != 0 and not output:
                return AgentResponse(
                    content="",
                    error=f"pi exit code={proc.returncode}: {err_output[:500]}",
                    conversation_id=session_id,
                    turn_count=session["turns"])

            logger.info("pi_execute_done",
                        agent_id=self.agent_id,
                        output_len=len(output),
                        return_code=proc.returncode)

            return AgentResponse(
                content=output,
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=True)

        except asyncio.TimeoutError:
            return AgentResponse(
                content="", error=f"Pi Agent 超时 ({timeout}s)",
                conversation_id=session_id)
        except FileNotFoundError:
            return AgentResponse(
                content="", error="pi CLI 未安装",
                conversation_id=session_id)
        finally:
            for f in [user_file, sys_file]:
                if f:
                    try:
                        os.unlink(f)
                    except OSError:
                        pass

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
