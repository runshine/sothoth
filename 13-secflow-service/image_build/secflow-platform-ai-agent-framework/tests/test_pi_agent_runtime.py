from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from app.pi_vuln_core.agents.runtimes.pi_agent import PiAgentRuntime


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr


@pytest.mark.asyncio
async def test_pi_agent_runtime_records_command_and_prompts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime = PiAgentRuntime(
        {
            "id": "pi-test",
            "name": "Pi Test",
            "type": "pi_agent",
            "reset_context": False,
            "runtime_config": {
                "model": "claude-test",
                "timeout_seconds": 30,
                "sdk_specific": {
                    "provider": "anthropic",
                    "thinking": "high",
                    "tools": "read,bash",
                },
            },
        }
    )

    captured: dict[str, object] = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        captured["cwd"] = kwargs.get("cwd")
        return _FakeProc(stdout=b"assistant output", stderr=b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="user prompt body",
        system_prompt="system prompt body",
        session_id="pi_test_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "assistant output"

    session_dir = tmp_path / "sessions" / "pi_test_session"
    call_dirs = sorted((session_dir / "calls").iterdir())
    assert len(call_dirs) == 1
    call_dir = call_dirs[0]

    user_prompt_path = call_dir / "user_prompt.md"
    system_prompt_path = call_dir / "system_prompt.md"
    assert user_prompt_path.read_text(encoding="utf-8") == "user prompt body"
    assert system_prompt_path.read_text(encoding="utf-8") == "system prompt body"
    assert (call_dir / "response.txt").read_text(encoding="utf-8") == "assistant output"
    assert (call_dir / "stdout.txt").read_text(encoding="utf-8") == "assistant output"
    assert (call_dir / "stderr.txt").read_text(encoding="utf-8") == ""

    request_payload = json.loads((call_dir / "request.json").read_text(encoding="utf-8"))
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))

    assert request_payload["command_argv"] == captured["args"]
    assert request_payload["working_dir"] == str(tmp_path)
    assert request_payload["user_prompt_file"] == str(user_prompt_path)
    assert request_payload["system_prompt_file"] == str(system_prompt_path)
    assert f"@{user_prompt_path}" in request_payload["command_display"]
    assert f"@{system_prompt_path}" in request_payload["command_display"]
    assert response_payload["status"] == "completed"
    assert response_payload["return_code"] == 0
    assert response_payload["turn_count"] == 1


@pytest.mark.asyncio
async def test_pi_agent_runtime_records_continuation_without_resending_system_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = PiAgentRuntime(
        {
            "id": "pi-test",
            "name": "Pi Test",
            "type": "pi_agent",
            "reset_context": False,
            "runtime_config": {
                "model": "claude-test",
                "timeout_seconds": 30,
                "sdk_specific": {
                    "provider": "anthropic",
                    "thinking": "high",
                },
            },
        }
    )

    proc_results = [
        _FakeProc(stdout=b"first output", stderr=b"", returncode=0),
        _FakeProc(stdout=b"second output", stderr=b"", returncode=0),
    ]

    async def fake_exec(*args, **kwargs):
        return proc_results.pop(0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    session_id = await runtime.create_session()
    await runtime.send_message(
        message="first user prompt",
        system_prompt="shared system prompt",
        session_id=session_id,
        working_dir=str(tmp_path),
    )
    await runtime.send_message(
        message="second user prompt",
        system_prompt="shared system prompt",
        session_id=session_id,
        working_dir=str(tmp_path),
    )

    call_dirs = sorted((tmp_path / "sessions" / session_id / "calls").iterdir())
    assert len(call_dirs) == 2

    first_request = json.loads((call_dirs[0] / "request.json").read_text(encoding="utf-8"))
    second_request = json.loads((call_dirs[1] / "request.json").read_text(encoding="utf-8"))

    assert first_request["has_system_prompt"] is True
    assert second_request["has_system_prompt"] is False
    assert second_request["system_prompt_file"] is None
    assert "--continue" in second_request["command_argv"]
    assert not (call_dirs[1] / "system_prompt.md").exists()
    assert (call_dirs[1] / "user_prompt.md").read_text(encoding="utf-8") == "second user prompt"
