from __future__ import annotations

import os
import platform
import shlex
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.utils.file_ops import write_file, write_json
from app.time_utils import isoformat_local, now_local

IS_WINDOWS = platform.system() == "Windows"
DEFAULT_STDOUT_TRACE_LIMIT_BYTES = 16 * 1024 * 1024
DEFAULT_STDERR_TRACE_LIMIT_BYTES = 4 * 1024 * 1024
DEFAULT_RESPONSE_TRACE_LIMIT_BYTES = 16 * 1024 * 1024


def now_iso() -> str:
    return isoformat_local(now_local()) or ""


def command_display(cmd_args: list[str]) -> str:
    if IS_WINDOWS:
        return subprocess.list2cmdline(cmd_args)
    return shlex.join(cmd_args)


def temp_markdown_path(prefix: str) -> str:
    return os.path.join(
        tempfile.gettempdir(),
        f"{prefix}_{uuid.uuid4().hex[:8]}.md",
    )


def _coerce_limit(value: object, default: int) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _write_limited_text(path: Path, content: str, *, limit_bytes: int) -> dict:
    raw = content.encode("utf-8", errors="replace")
    original_bytes = len(raw)
    truncated = limit_bytes >= 0 and original_bytes > limit_bytes
    if truncated:
        marker = (
            "\n\n[trace truncated: original_bytes="
            f"{original_bytes}, retained_bytes={limit_bytes}]\n"
        ).encode("utf-8")
        retained = raw[:limit_bytes] + marker
        write_file(path, retained.decode("utf-8", errors="replace"))
    else:
        write_file(path, content)
    return {
        "path": str(path),
        "original_bytes": original_bytes,
        "written_bytes": min(original_bytes, limit_bytes) if truncated else original_bytes,
        "truncated": truncated,
        "limit_bytes": limit_bytes,
    }


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
        self.write_heartbeat("started", {"turn_number": self.turn_number})

    def write_heartbeat(self, status: str, detail: dict | None = None) -> None:
        if not self.call_dir:
            return
        payload = {
            "timestamp": now_iso(),
            "runtime": self.runtime,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "turn_number": self.turn_number,
            "status": status,
            "detail": detail or {},
        }
        write_json(Path(self.call_dir) / "heartbeat.json", payload)

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
        trace_limits = payload.get("trace_limits") or {}
        stdout_limit = _coerce_limit(
            trace_limits.get("stdout_bytes"),
            DEFAULT_STDOUT_TRACE_LIMIT_BYTES,
        )
        stderr_limit = _coerce_limit(
            trace_limits.get("stderr_bytes"),
            DEFAULT_STDERR_TRACE_LIMIT_BYTES,
        )
        response_limit = _coerce_limit(
            trace_limits.get("response_bytes"),
            DEFAULT_RESPONSE_TRACE_LIMIT_BYTES,
        )

        artifacts = {
            "stdout": _write_limited_text(
                Path(self.call_dir) / "stdout.txt",
                stdout_text,
                limit_bytes=stdout_limit,
            ),
            "stderr": _write_limited_text(
                Path(self.call_dir) / "stderr.txt",
                stderr_text,
                limit_bytes=stderr_limit,
            ),
            "response": _write_limited_text(
                Path(self.call_dir) / "response.txt",
                response_text,
                limit_bytes=response_limit,
            ),
        }
        payload = dict(payload)
        payload["trace_artifacts"] = artifacts
        payload["trace_truncated"] = any(item["truncated"] for item in artifacts.values())
        write_json(Path(self.call_dir) / "response.json", payload)
        self.write_heartbeat(str(payload.get("status") or "finished"), {
            "finished": payload.get("finished", False),
            "error": payload.get("error"),
            "error_code": payload.get("error_code", ""),
        })

    def cleanup(self) -> None:
        for path in self.cleanup_files:
            try:
                os.unlink(path)
            except OSError:
                pass
