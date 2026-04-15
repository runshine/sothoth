from __future__ import annotations

import os
import platform
import shlex
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.utils.file_ops import write_file, write_json

IS_WINDOWS = platform.system() == "Windows"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def command_display(cmd_args: list[str]) -> str:
    if IS_WINDOWS:
        return subprocess.list2cmdline(cmd_args)
    return shlex.join(cmd_args)


def temp_markdown_path(prefix: str) -> str:
    return os.path.join(
        tempfile.gettempdir(),
        f"{prefix}_{uuid.uuid4().hex[:8]}.md",
    )


@dataclass
class RuntimeTraceContext:
    runtime: str
    agent_id: str
    session_id: str
    turn_number: int
    working_dir: Optional[str]
    session_dir: Optional[str]
    call_dir: Optional[str]
    user_prompt_file: str
    system_prompt_file: Optional[str]
    cleanup_files: list[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        *,
        runtime: str,
        agent_id: str,
        session_id: str,
        turn_number: int,
        working_dir: Optional[str],
        user_prompt: str,
        system_prompt: Optional[str] = None,
        write_system_prompt: bool = True,
    ) -> "RuntimeTraceContext":
        cleanup_files: list[str] = []
        call_dir: Optional[str] = None
        working_dir_abs = os.path.abspath(working_dir) if working_dir else None
        session_dir = None

        if working_dir_abs:
            session_dir = os.path.join(working_dir_abs, "sessions", session_id)
            os.makedirs(session_dir, exist_ok=True)
            call_dir = os.path.join(
                session_dir,
                "calls",
                f"{turn_number:03d}_{uuid.uuid4().hex[:8]}",
            )
            os.makedirs(call_dir, exist_ok=True)
            user_prompt_file = os.path.join(call_dir, "user_prompt.md")
        else:
            user_prompt_file = temp_markdown_path(f"{runtime}_user")
            cleanup_files.append(user_prompt_file)

        write_file(user_prompt_file, user_prompt)

        system_prompt_file = None
        if system_prompt and write_system_prompt:
            if call_dir:
                system_prompt_file = os.path.join(call_dir, "system_prompt.md")
            else:
                system_prompt_file = temp_markdown_path(f"{runtime}_sys")
                cleanup_files.append(system_prompt_file)
            write_file(system_prompt_file, system_prompt)

        return cls(
            runtime=runtime,
            agent_id=agent_id,
            session_id=session_id,
            turn_number=turn_number,
            working_dir=working_dir_abs,
            session_dir=session_dir,
            call_dir=call_dir,
            user_prompt_file=user_prompt_file,
            system_prompt_file=system_prompt_file,
            cleanup_files=cleanup_files,
        )

    def write_text_artifact(self, filename: str, content: str) -> Optional[str]:
        if not self.call_dir:
            return None
        path = Path(self.call_dir) / filename
        write_file(path, content)
        return str(path)

    def write_request(self, payload: dict) -> None:
        if not self.call_dir:
            return
        write_json(Path(self.call_dir) / "request.json", payload)
        if "command_display" in payload:
            write_file(Path(self.call_dir) / "command.txt", payload["command_display"] + "\n")

    def write_result(
        self,
        *,
        stdout_text: str,
        stderr_text: str,
        response_text: str,
        payload: dict,
    ) -> None:
        if not self.call_dir:
            return
        write_file(Path(self.call_dir) / "stdout.txt", stdout_text)
        write_file(Path(self.call_dir) / "stderr.txt", stderr_text)
        write_file(Path(self.call_dir) / "response.txt", response_text)
        write_json(Path(self.call_dir) / "response.json", payload)

    def cleanup(self) -> None:
        for path in self.cleanup_files:
            try:
                os.unlink(path)
            except OSError:
                pass
