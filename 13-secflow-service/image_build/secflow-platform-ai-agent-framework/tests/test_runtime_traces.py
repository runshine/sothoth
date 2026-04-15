from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from app.pi_vuln_core.agents.runtimes.claude_code import ClaudeCodeRuntime
from app.pi_vuln_core.agents.runtimes.codex import CodexRuntime
from app.pi_vuln_core.agents.runtimes.opencode import OpenCodeRuntime


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr


@pytest.mark.asyncio
async def test_claude_code_runtime_trace_records_request_and_parsed_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = ClaudeCodeRuntime(
        {
            "id": "claude-test",
            "name": "Claude Test",
            "type": "claude_code",
            "reset_context": False,
            "runtime_config": {
                "model": "claude-sonnet-test",
                "timeout_seconds": 30,
            },
        }
    )

    captured: dict[str, object] = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        captured["cwd"] = kwargs.get("cwd")
        return _FakeProc(
            stdout=b'{"result":"assistant output","input_tokens":11,"output_tokens":7}',
            stderr=b"",
            returncode=0,
        )

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="user prompt body",
        system_prompt="system prompt body",
        session_id="cc_trace_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "assistant output"
    assert response.token_usage == {"input": 11, "output": 7}

    call_dir = next((tmp_path / "sessions" / "cc_trace_session" / "calls").iterdir())
    assert (call_dir / "user_prompt.md").read_text(encoding="utf-8") == "user prompt body"
    assert (call_dir / "system_prompt.md").read_text(encoding="utf-8") == "system prompt body"
    assert (call_dir / "stdout.txt").read_text(encoding="utf-8") == '{"result":"assistant output","input_tokens":11,"output_tokens":7}'
    assert (call_dir / "response.txt").read_text(encoding="utf-8") == "assistant output"

    request_payload = json.loads((call_dir / "request.json").read_text(encoding="utf-8"))
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))

    assert request_payload["command_argv"] == captured["args"]
    assert request_payload["working_dir"] == str(tmp_path)
    assert request_payload["has_system_prompt"] is True
    assert "--system-prompt" in request_payload["command_argv"]
    assert response_payload["status"] == "completed"
    assert response_payload["token_usage"] == {"input": 11, "output": 7}


@pytest.mark.asyncio
async def test_codex_runtime_trace_records_effective_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = CodexRuntime(
        {
            "id": "codex-test",
            "name": "Codex Test",
            "type": "codex",
            "reset_context": False,
            "runtime_config": {
                "model": "o3-mini",
                "timeout_seconds": 30,
                "sdk_specific": {"sandbox": True},
            },
        }
    )

    captured: dict[str, object] = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        return _FakeProc(stdout=b"assistant output", stderr=b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="user prompt body",
        system_prompt="system prompt body",
        session_id="codex_trace_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "assistant output"

    call_dir = next((tmp_path / "sessions" / "codex_trace_session" / "calls").iterdir())
    effective_prompt = (call_dir / "effective_prompt.md").read_text(encoding="utf-8")
    assert effective_prompt == "system prompt body\n\nuser prompt body"

    request_payload = json.loads((call_dir / "request.json").read_text(encoding="utf-8"))
    assert request_payload["command_argv"] == captured["args"]
    assert request_payload["supports_cli_session"] is False
    assert request_payload["effective_prompt_file"] == str(call_dir / "effective_prompt.md")
    assert "--sandbox" in request_payload["command_argv"]
    assert (call_dir / "response.txt").read_text(encoding="utf-8") == "assistant output"


@pytest.mark.asyncio
async def test_opencode_runtime_trace_records_effective_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = OpenCodeRuntime(
        {
            "id": "opencode-test",
            "name": "OpenCode Test",
            "type": "opencode",
            "reset_context": False,
            "runtime_config": {
                "model": "claude-sonnet-test",
                "timeout_seconds": 30,
                "sdk_specific": {"provider": "anthropic"},
            },
        }
    )

    captured: dict[str, object] = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        return _FakeProc(stdout=b"assistant output", stderr=b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="user prompt body",
        system_prompt="system prompt body",
        session_id="opencode_trace_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "assistant output"

    call_dir = next((tmp_path / "sessions" / "opencode_trace_session" / "calls").iterdir())
    effective_prompt = (call_dir / "effective_prompt.md").read_text(encoding="utf-8")
    assert effective_prompt == "system prompt body\n\nuser prompt body"

    request_payload = json.loads((call_dir / "request.json").read_text(encoding="utf-8"))
    assert request_payload["command_argv"] == captured["args"]
    assert request_payload["supports_cli_session"] is False
    assert request_payload["effective_prompt_file"] == str(call_dir / "effective_prompt.md")
    assert "--non-interactive" in request_payload["command_argv"]
    assert (call_dir / "response.txt").read_text(encoding="utf-8") == "assistant output"
