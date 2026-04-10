from __future__ import annotations

import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from app.models.contracts import SessionMode
from app.runtime.session_pipe_manager import SessionPipeManager
from app.runtime.session_pty_manager import SessionPtyManager
from app.runtime.session_store import SessionStore


@dataclass
class RuntimeBackendConfig:
    backend_id: str
    adapter: str
    command: str
    args: list[str]
    cwd: Optional[str]
    env: dict[str, str] = field(default_factory=dict)
    session_mode_default: SessionMode = SessionMode.INVOKE
    reset_context: bool = True


@dataclass
class RuntimeResponse:
    success: bool
    output: str
    error: str = ""
    timed_out: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)


class BaseAgentRuntime(ABC):
    def __init__(self, backend_config: RuntimeBackendConfig, quiet_window_ms: int, max_window_ms: int):
        self.backend_config = backend_config
        self.quiet_window_ms = quiet_window_ms
        self.max_window_ms = max_window_ms
        self.session_store = SessionStore()
        self.pipe_manager = SessionPipeManager()
        self.pty_manager = SessionPtyManager()

    def healthcheck(self) -> Dict[str, Any]:
        command = self.backend_config.command
        exists = Path(command).exists() if os.path.isabs(command) else shutil.which(command) is not None
        return {
            "backend_id": self.backend_config.backend_id,
            "adapter": self.backend_config.adapter,
            "command": command,
            "installed": exists,
        }

    def create_session(self, session_mode: Optional[SessionMode] = None, cwd_override: Optional[str] = None) -> str:
        mode = session_mode or self.backend_config.session_mode_default
        session = self.session_store.create(self.backend_config.backend_id, mode.value)
        command = self.build_command()
        env = self.build_env()
        cwd = cwd_override or self.backend_config.cwd
        if mode == SessionMode.PIPE:
            pid = self.pipe_manager.create_session(session.session_id, command, cwd, env)
            self.session_store.patch(session.session_id, pid=pid)
        elif mode == SessionMode.PTY:
            pid = self.pty_manager.create_session(session.session_id, command, cwd, env)
            self.session_store.patch(session.session_id, pid=pid)
        return session.session_id

    def send_message(self, session_id: str, prompt: str) -> RuntimeResponse:
        session = self.session_store.get(session_id)
        if not session:
            raise KeyError(session_id)
        mode = SessionMode(session.session_mode)
        if mode == SessionMode.INVOKE:
            return self.invoke_once(prompt, mode)
        if mode == SessionMode.PIPE:
            self.pipe_manager.write_stdin(session_id, prompt)
            payload = self.pipe_manager.read_until_idle(session_id, self.quiet_window_ms, self.max_window_ms)
            return RuntimeResponse(success=True, output=str(payload.get("output", "")), timed_out=bool(payload.get("timed_out", False)), raw=payload)
        self.pty_manager.write_stdin(session_id, prompt)
        payload = self.pty_manager.read_until_idle(session_id, self.quiet_window_ms, self.max_window_ms)
        return RuntimeResponse(success=True, output=str(payload.get("output", "")), timed_out=bool(payload.get("timed_out", False)), raw=payload)

    def invoke_once(
        self,
        prompt: str,
        session_mode: Optional[SessionMode] = None,
        cwd_override: Optional[str] = None,
    ) -> RuntimeResponse:
        mode = session_mode or SessionMode.INVOKE
        command = self.build_command(prompt if mode == SessionMode.INVOKE else None)
        env = self.build_env()
        try:
            completed = subprocess.run(
                command,
                cwd=cwd_override or self.backend_config.cwd or None,
                env=env,
                text=True,
                capture_output=True,
                timeout=max(30, self.max_window_ms // 1000 + 5),
            )
        except FileNotFoundError:
            return RuntimeResponse(success=False, output="", error=f"backend command not found: {self.backend_config.command}")
        except subprocess.TimeoutExpired:
            return RuntimeResponse(success=False, output="", error="backend invoke timeout", timed_out=True)
        success = completed.returncode == 0
        output = completed.stdout.strip() or completed.stderr.strip()
        return RuntimeResponse(
            success=success,
            output=output if success else "",
            error="" if success else output,
            raw={
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            },
        )

    def close_session(self, session_id: str) -> None:
        session = self.session_store.get(session_id)
        if session:
            mode = SessionMode(session.session_mode)
            if mode == SessionMode.PIPE:
                self.pipe_manager.close_session(session_id)
            elif mode == SessionMode.PTY:
                self.pty_manager.close_session(session_id)
            self.session_store.delete(session_id)

    def build_command(self, prompt: str | None = None) -> list[str]:
        command = [self.backend_config.command, *self.backend_config.args]
        if prompt:
            command.append(prompt)
        return command

    def build_env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(self.backend_config.env)
        return env


class CliAgentRuntime(BaseAgentRuntime, ABC):
    @abstractmethod
    def runtime_type(self) -> str:
        raise NotImplementedError


class CodexRuntime(CliAgentRuntime):
    def runtime_type(self) -> str:
        return "codex"


class ClaudeCodeRuntime(CliAgentRuntime):
    def runtime_type(self) -> str:
        return "claude_code"


class OpenCodeRuntime(CliAgentRuntime):
    def runtime_type(self) -> str:
        return "opencode"


class PiAgentRuntime(CliAgentRuntime):
    def runtime_type(self) -> str:
        return "pi_agent"
