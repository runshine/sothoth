from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from app.pi_vuln_core.agents.runtimes.pi_agent import PiAgentRuntime, _AttemptResult


class _FakeStream:
    """Async-readable stream mock for _FakeProc."""
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""
        if n < 0:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
        else:
            chunk = self._data[self._pos:self._pos + n]
            self._pos += len(chunk)
        return chunk


class _FakeRpcStdin:
    def __init__(self) -> None:
        self.writes: list[str] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data.decode("utf-8"))

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeRpcStdout:
    def __init__(self, events: list[dict]) -> None:
        self._data = b"".join(
            json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n"
            for event in events
        )
        self._pos = 0

    async def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._data):
            await asyncio.sleep(0)
            return b""
        if n < 0:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
            return chunk
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    async def readline(self) -> bytes:
        if self._pos >= len(self._data):
            await asyncio.sleep(0)
            return b""
        next_newline = self._data.find(b"\n", self._pos)
        if next_newline == -1:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
            return chunk
        chunk = self._data[self._pos:next_newline + 1]
        self._pos = next_newline + 1
        return chunk


class _FakeProc:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int | None = 0,
        *,
        rpc_events: list[dict] | None = None,
    ):
        self.stdout = _FakeRpcStdout(rpc_events) if rpc_events is not None else _FakeStream(stdout)
        self.stderr = _FakeStream(stderr)
        self.stdin = _FakeRpcStdin()
        self._stdout_raw = stdout
        self._stderr_raw = stderr
        self.returncode = returncode
        self.killed = False
        self.wait_called = False

    async def communicate(self):
        return self._stdout_raw, self._stderr_raw

    def kill(self):
        self.killed = True
        self.returncode = -9

    def terminate(self):
        self.killed = True
        self.returncode = -15

    async def wait(self):
        self.wait_called = True
        return self.returncode


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
    assert "--mode" in request_payload["command_argv"]
    assert request_payload["command_argv"][request_payload["command_argv"].index("--mode") + 1] == "json"
    assert "--provider" not in request_payload["command_argv"]
    assert request_payload["command_argv"][request_payload["command_argv"].index("--model") + 1] == "anthropic/claude-test"
    assert request_payload["working_dir"] == str(tmp_path)
    assert request_payload["user_prompt_file"] == str(user_prompt_path)
    assert request_payload["system_prompt_file"] == str(system_prompt_path)
    assert f"@{user_prompt_path}" in request_payload["command_display"]
    assert "--append-system-prompt" in request_payload["command_display"]
    assert str(system_prompt_path) in request_payload["command_display"]
    assert f"@{system_prompt_path}" not in request_payload["command_display"]
    assert response_payload["status"] == "completed"
    assert response_payload["return_code"] == 0
    assert response_payload["turn_count"] == 1


@pytest.mark.asyncio
async def test_pi_agent_runtime_omits_thinking_argument_when_unresolved(
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
                "model": "mock/no-thinking",
                "timeout_seconds": 30,
                "sdk_specific": {"tools": "read,bash"},
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
        session_id="pi_test_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert "--thinking" not in captured["args"]


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


@pytest.mark.asyncio
async def test_pi_agent_runtime_create_session_with_hint_uses_human_readable_id(
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

    async def fake_exec(*args, **kwargs):
        return _FakeProc(stdout=b"semantic output", stderr=b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    session_id = await runtime.create_session_with_hint("worker_cycle_001")
    assert session_id == "worker_cycle_001"

    response = await runtime.send_message(
        message="prompt",
        system_prompt="system",
        session_id=session_id,
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert (tmp_path / "sessions" / "worker_cycle_001" / "calls").is_dir()


@pytest.mark.asyncio
async def test_pi_agent_runtime_restores_existing_session_from_disk(
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

    session_id = "pi_existing_session"
    calls_root = tmp_path / "sessions" / session_id / "calls"
    for idx in (1, 2):
        call_dir = calls_root / f"{idx:03d}_existing"
        call_dir.mkdir(parents=True, exist_ok=True)
        (call_dir / "response.json").write_text(
            json.dumps({"status": "completed"}, ensure_ascii=False),
            encoding="utf-8",
        )

    captured: dict[str, object] = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = list(args)
        captured["cwd"] = kwargs.get("cwd")
        return _FakeProc(stdout=b"resumed output", stderr=b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="resume prompt",
        system_prompt="system prompt should not be resent",
        session_id=session_id,
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "resumed output"

    call_dirs = sorted((tmp_path / "sessions" / session_id / "calls").iterdir())
    assert len(call_dirs) == 3
    resumed_call_dir = call_dirs[-1]

    request_payload = json.loads((resumed_call_dir / "request.json").read_text(encoding="utf-8"))
    response_payload = json.loads((resumed_call_dir / "response.json").read_text(encoding="utf-8"))

    assert request_payload["has_system_prompt"] is False
    assert request_payload["system_prompt_file"] is None
    assert "--continue" in request_payload["command_argv"]
    assert not (resumed_call_dir / "system_prompt.md").exists()
    assert os.path.basename(str(resumed_call_dir)).startswith("003_")
    assert response_payload["turn_count"] == 3


@pytest.mark.asyncio
async def test_pi_agent_runtime_ignores_legacy_timeout_config(
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
                "timeout_seconds": 0.01,
                "sdk_specific": {
                    "provider": "anthropic",
                    "thinking": "high",
                },
            },
        }
    )

    proc = _FakeProc(stdout=b"assistant output", stderr=b"", returncode=0)

    async def fake_exec(*args, **kwargs):
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="legacy timeout prompt",
        system_prompt="system",
        session_id="worker_cycle_001",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "assistant output"
    assert proc.killed is False

    call_dir = next((tmp_path / "sessions" / "worker_cycle_001" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "completed"
    assert response_payload["turn_count"] == 1


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_reuses_long_lived_process(
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
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "sdk_specific": {"thinking": "high"},
            },
        }
    )

    def rpc_message(text: str) -> dict:
        return {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "stopReason": "stop",
                "content": [{"type": "text", "text": text}],
            },
        }

    proc = _FakeProc(
        returncode=None,
        rpc_events=[
            {"type": "response", "command": "set_auto_retry", "success": True},
            {"type": "response", "command": "prompt", "success": True},
            rpc_message("first response"),
            {"type": "agent_end", "messages": []},
            {"type": "response", "command": "prompt", "success": True},
            rpc_message("second response"),
            {"type": "agent_end", "messages": []},
        ],
    )
    spawn_count = 0

    async def fake_exec(*args, **kwargs):
        nonlocal spawn_count
        spawn_count += 1
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    first = await runtime.send_message(
        message="first prompt",
        system_prompt="system",
        session_id="rpc_session",
        working_dir=str(tmp_path),
    )
    second = await runtime.send_message(
        message="second prompt",
        system_prompt="system",
        session_id="rpc_session",
        working_dir=str(tmp_path),
    )

    assert first.success is True
    assert first.content == "first response"
    assert second.success is True
    assert second.content == "second response"
    assert spawn_count == 1
    written_commands = [json.loads(item) for item in proc.stdin.writes]
    assert written_commands[0] == {"type": "set_auto_retry", "enabled": True}
    assert [cmd["message"] for cmd in written_commands if cmd.get("type") == "prompt"] == [
        "first prompt",
        "second prompt",
    ]

    await runtime.close_session("rpc_session")
    assert proc.killed is True


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_uses_pi_native_timeout_without_framework_timeout(
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
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    proc = _FakeProc(
        returncode=None,
        rpc_events=[
            {"type": "response", "command": "set_auto_retry", "success": True},
            {"type": "response", "command": "prompt", "success": True},
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": "error",
                    "errorMessage": "provider request timed out",
                    "content": [],
                },
            },
            {"type": "agent_end", "messages": []},
        ],
    )

    async def fake_exec(*args, **kwargs):
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    session: dict = {}

    result = await runtime._execute_once_rpc(
        cmd_args=["pi", "--mode", "rpc"],
        message="timeout prompt",
        working_dir=str(tmp_path),
        session_id="rpc_timeout_session",
        call_dir=str(tmp_path / "call"),
        session=session,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        max_event_count=100,
        max_single_line_bytes=1024 * 1024,
        max_internal_turns=0,
        heartbeat_interval_seconds=30,
    )

    assert result.status == "error"
    assert result.error_code == "runtime_timeout"
    assert result.timeout is False
    assert proc.killed is False
    assert session.get("rpc_proc") is proc
    assert session.get("rpc_stale_agent_ends_to_skip") in {None, 0}


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_timeout_retry_resends_to_same_process_after_interval(
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
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "timeout_max_retries": 2,
                "timeout_retry_interval_seconds": 0.25,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    calls = 0
    closed = 0
    sleeps: list[float] = []

    async def fake_execute_once_rpc(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _AttemptResult(
                error="runtime no-progress timeout after 1.0s",
                status="timeout",
                timeout=True,
                error_code="runtime_timeout",
            )
        return _AttemptResult(response_text="retry ok", status="completed")

    async def fake_close(_session):
        nonlocal closed
        closed += 1

    async def fake_sleep(delay: float):
        sleeps.append(delay)

    monkeypatch.setattr(runtime, "_execute_once_rpc", fake_execute_once_rpc)
    monkeypatch.setattr(runtime, "_close_rpc_process_for_session", fake_close)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    response = await runtime.send_message(
        message="retry same rpc process",
        system_prompt="system",
        session_id="rpc_retry_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "retry ok"
    assert calls == 2
    assert closed == 0
    assert sleeps == [0.25]

    call_dir = next((tmp_path / "sessions" / "rpc_retry_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["timeout_retry_interval_seconds"] == 0.25
    assert response_payload["attempts"][0]["retry_kind"] == "pi_timeout_rpc_resend_same_process"
    assert response_payload["attempts"][0]["rpc_process_preserved"] is True
    assert response_payload["attempts"][0]["process_restarted"] is False


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_request_trace_omits_legacy_watchdog_timeouts(
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
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "api_max_retries": -1,
                "pi_max_retries": -1,
                "no_progress_timeout_seconds": 60,
                "max_wall_seconds": 120,
                "max_retry_wall_seconds": 300,
                "timeout_max_retries": 2,
                "timeout_retry_interval_seconds": 7,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    async def fake_execute_once_rpc(**_kwargs):
        return _AttemptResult(response_text="rpc ok", status="completed")

    monkeypatch.setattr(runtime, "_execute_once_rpc", fake_execute_once_rpc)

    response = await runtime.send_message(
        message="rpc trace cleanup",
        system_prompt="system",
        session_id="rpc_trace_session",
        working_dir=str(tmp_path),
        no_progress_timeout_seconds=1,
        max_wall_seconds=1,
    )

    assert response.success is True
    call_dir = next((tmp_path / "sessions" / "rpc_trace_session" / "calls").iterdir())
    request_payload = json.loads((call_dir / "request.json").read_text(encoding="utf-8"))
    runtime_limits = request_payload["runtime_limits"]

    assert request_payload["mode"] == "rpc"
    assert request_payload["api_max_retries"] == 0
    assert request_payload["pi_max_retries"] == 0
    assert runtime_limits["timeout_max_retries"] == 2
    assert runtime_limits["timeout_retry_interval_seconds"] == 7
    assert "no_progress_timeout_seconds" not in runtime_limits
    assert "max_wall_seconds" not in runtime_limits
    assert "max_retry_wall_seconds" not in runtime_limits


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_timeout_retry_reuses_same_session_for_reset_context_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = PiAgentRuntime(
        {
            "id": "pi-test",
            "name": "Pi Test",
            "type": "pi_agent",
            "reset_context": True,
            "runtime_config": {
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "timeout_max_retries": 2,
                "timeout_retry_interval_seconds": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    calls = 0
    closed = 0
    session_ids: list[str] = []

    async def fake_execute_once_rpc(**kwargs):
        nonlocal calls
        calls += 1
        session_ids.append(kwargs["session_id"])
        if calls == 1:
            return _AttemptResult(
                error="provider request timed out",
                status="error",
                error_code="runtime_timeout",
            )
        return _AttemptResult(response_text="advisor retry ok", status="completed")

    async def fake_close(_session):
        nonlocal closed
        closed += 1

    monkeypatch.setattr(runtime, "_execute_once_rpc", fake_execute_once_rpc)
    monkeypatch.setattr(runtime, "_close_rpc_process_for_session", fake_close)

    response = await runtime.send_message(
        message="advisor timeout prompt",
        system_prompt="system",
        session_id="advisor_rpc_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "advisor retry ok"
    assert closed == 0
    assert session_ids == ["advisor_rpc_session", "advisor_rpc_session"]

    call_dir = next((tmp_path / "sessions" / "advisor_rpc_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["effective_session_id"] == "advisor_rpc_session"
    assert response_payload["timeout_retry_sessions"] == []
    assert response_payload["attempts"][0]["fresh_session"] is False
    assert response_payload["attempts"][0]["rpc_process_preserved"] is True
    assert response_payload["attempts"][0]["process_restarted"] is False


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_handles_very_large_single_jsonl_event(
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
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "sdk_specific": {"thinking": "high"},
            },
        }
    )

    huge_text = "A" * 300_000
    proc = _FakeProc(
        returncode=None,
        rpc_events=[
            {"type": "response", "command": "set_auto_retry", "success": True},
            {"type": "response", "command": "prompt", "success": True},
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": "stop",
                    "content": [{"type": "text", "text": huge_text}],
                },
            },
            {"type": "agent_end", "messages": []},
        ],
    )

    async def fake_exec(*args, **kwargs):
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="huge rpc prompt",
        system_prompt="system",
        session_id="rpc_huge_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == huge_text
    call_dir = next((tmp_path / "sessions" / "rpc_huge_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "completed"
    assert response_payload["response_len"] == len(huge_text)


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_truncates_verbose_stdout_without_failing(
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
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "max_stdout_bytes": 256,
                "max_single_line_bytes": 10_000,
                "sdk_specific": {"thinking": "high"},
            },
        }
    )

    update_events = []
    for idx in range(30):
        update_events.append(
            {
                "type": "message_update",
                "assistantMessageEvent": {
                    "type": "text_delta",
                    "contentIndex": 0,
                    "delta": "x" * 128,
                    "partial": {
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "growing partial " + ("y" * 512)}
                        ],
                    },
                },
                "message": {"role": "assistant", "content": "z" * 512, "idx": idx},
            }
        )

    proc = _FakeProc(
        returncode=None,
        rpc_events=[
            {"type": "response", "command": "set_auto_retry", "success": True},
            {"type": "response", "command": "prompt", "success": True},
            *update_events,
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": "stop",
                    "content": [{"type": "text", "text": "final response"}],
                },
            },
            {"type": "agent_end", "messages": []},
        ],
    )

    async def fake_exec(*args, **kwargs):
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="verbose rpc prompt",
        system_prompt="system",
        session_id="rpc_verbose_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "final response"

    call_dir = next((tmp_path / "sessions" / "rpc_verbose_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "completed"
    assert response_payload["output_total_bytes"] > 256
    assert response_payload["stdout_truncated"] is True
    assert "trace truncated" in (call_dir / "stdout.txt").read_text(encoding="utf-8")

    events = json.loads((call_dir / "stdout_events.json").read_text(encoding="utf-8"))
    update_trace = next(event for event in events if event.get("type") == "message_update")
    assert "partial" not in update_trace["assistantMessageEvent"]
    assert "partial_summary" in update_trace["assistantMessageEvent"]


@pytest.mark.asyncio
async def test_pi_agent_runtime_rpc_stdout_soft_limit_does_not_abort_call(
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
                "model": "anthropic/claude-test",
                "transport": "rpc",
                "max_stdout_bytes": 4096,
                "max_single_line_bytes": 10_000,
                "pi_max_retries": 0,
                "api_max_retries": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    proc = _FakeProc(
        returncode=None,
        rpc_events=[
            {"type": "response", "command": "set_auto_retry", "success": True},
            {"type": "response", "command": "prompt", "success": True},
            *[
                {
                    "type": "message_update",
                    "message": {"role": "assistant", "content": "x" * 512, "idx": idx},
                }
                for idx in range(20)
            ],
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": "stop",
                    "content": [{"type": "text", "text": "final after verbose stream"}],
                },
            },
            {"type": "agent_end", "messages": []},
        ],
    )

    async def fake_exec(*args, **kwargs):
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="verbose reflection prompt",
        system_prompt="system",
        session_id="rpc_abort_session",
        working_dir=str(tmp_path),
        rpc_stdout_trace_bytes=512,
        rpc_stdout_abort_bytes=1024,
    )

    assert response.success is True
    assert response.content == "final after verbose stream"

    call_dir = next((tmp_path / "sessions" / "rpc_abort_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "completed"
    assert response_payload["output_total_bytes"] > 1024
    assert response_payload["stdout_truncated"] is True
    assert response_payload["stdout_soft_limit_exceeded"] is True


@pytest.mark.asyncio
async def test_pi_agent_runtime_parses_json_mode_output_and_retries_api_errors(
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
                "model": "anthropic/claude-test",
                "timeout_seconds": 30,
                "api_retry_delay": 0,
                "api_max_retries": 1,
                "pi_max_retries": 0,
                "sdk_specific": {"thinking": "high"},
            },
        }
    )

    api_error = {
        "type": "message_end",
        "message": {
            "role": "assistant",
            "stopReason": "error",
            "errorMessage": "rate limit 429",
            "content": [],
        },
    }
    success = {
        "type": "message_end",
        "message": {
            "role": "assistant",
            "stopReason": "end_turn",
            "usage": {"input": 11, "output": 7, "cacheRead": 3, "cacheWrite": 2},
            "content": [{"type": "text", "text": "parsed assistant text"}],
        },
    }
    proc_results = [
        _FakeProc(stdout=(json.dumps(api_error) + "\n").encode(), stderr=b"", returncode=0),
        _FakeProc(stdout=(json.dumps(success) + "\n").encode(), stderr=b"", returncode=0),
    ]
    captured_args: list[list[str]] = []

    async def fake_exec(*args, **kwargs):
        captured_args.append(list(args))
        return proc_results.pop(0)

    async def fake_sleep(_delay):
        return None

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    response = await runtime.send_message(
        message="json prompt",
        system_prompt="system",
        session_id="json_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "parsed assistant text"
    assert response.token_usage == {
        "input": 11,
        "output": 7,
        "cache_read": 3,
        "cache_write": 2,
    }
    assert len(captured_args) == 2
    assert "--provider" not in captured_args[-1]
    assert captured_args[-1][captured_args[-1].index("--model") + 1] == "anthropic/claude-test"

    call_dir = next((tmp_path / "sessions" / "json_session" / "calls").iterdir())
    assert (call_dir / "response.txt").read_text(encoding="utf-8") == "parsed assistant text"
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "completed"
    assert response_payload["api_failures"] == 1
    assert len(response_payload["attempts"]) == 2
    assert response_payload["token_usage"]["input"] == 11
    assert (call_dir / "stdout_events.json").is_file()


@pytest.mark.asyncio
async def test_pi_agent_runtime_truncates_stdout_without_aborting_json_mode(
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
                "model": "anthropic/claude-test",
                "max_stdout_bytes": 32,
                "max_stderr_bytes": 1024,
                "max_single_line_bytes": 1024,
                "pi_max_retries": 0,
                "api_max_retries": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    stdout = (
        json.dumps(
            {
                "type": "message_update",
                "message": {"role": "assistant", "content": "x" * 64},
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": "stop",
                    "content": [{"type": "text", "text": "json final"}],
                },
            }
        )
        + "\n"
    ).encode()

    async def fake_exec(*args, **kwargs):
        return _FakeProc(stdout=stdout, stderr=b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="large output prompt",
        system_prompt="system",
        session_id="limit_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "json final"

    call_dir = next((tmp_path / "sessions" / "limit_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "completed"
    assert response_payload["trace_truncated"] is True
    assert response_payload["output_total_bytes"] == len(stdout)
    assert response_payload["stdout_soft_limit_exceeded"] is True
    assert "trace truncated" in (call_dir / "stdout.txt").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_pi_agent_runtime_enforces_stderr_output_limit(
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
                "model": "anthropic/claude-test",
                "max_stdout_bytes": 1024,
                "max_stderr_bytes": 32,
                "max_single_line_bytes": 1024,
                "pi_max_retries": 0,
                "api_max_retries": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    async def fake_exec(*args, **kwargs):
        return _FakeProc(stdout=b"", stderr=b"E" * 128, returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    response = await runtime.send_message(
        message="large stderr prompt",
        system_prompt="system",
        session_id="stderr_limit_session",
        working_dir=str(tmp_path),
    )

    assert response.success is False
    assert response.error_code == "runtime_output_limit"

    call_dir = next((tmp_path / "sessions" / "stderr_limit_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "runtime_output_limit"
    assert response_payload["stderr_total_bytes"] == 128
    assert "trace truncated" in (call_dir / "stderr.txt").read_text(encoding="utf-8")


def test_pi_agent_runtime_error_classification_is_actionable() -> None:
    assert PiAgentRuntime._classify_error_code("ContextWindowExceeded: too many tokens") == "blocked_context_window"
    assert PiAgentRuntime._classify_error_code("403 quota exceeded") == "blocked_quota"
    assert PiAgentRuntime._classify_error_code("rate limit 429") == "provider_rate_limited"
    assert PiAgentRuntime._is_pi_process_failure(_AttemptResult(timeout=True, error_code="runtime_timeout")) is False


@pytest.mark.asyncio
async def test_pi_agent_runtime_timeout_restarts_process_before_failing(
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
                "model": "anthropic/claude-test",
                "api_max_retries": -1,
                "pi_max_retries": -1,
                "api_retry_delay": 0,
                "pi_retry_delay": 0,
                "timeout_max_retries": 3,
                "timeout_retry_delay": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    calls = 0

    async def fake_execute_once(**_kwargs):
        nonlocal calls
        calls += 1
        return _AttemptResult(
            error="runtime no-progress timeout after 1.0s",
            status="timeout",
            timeout=True,
            error_code="runtime_timeout",
        )

    monkeypatch.setattr(runtime, "_execute_once", fake_execute_once)

    response = await runtime.send_message(
        message="timeout prompt",
        system_prompt="system",
        session_id="timeout_session",
        working_dir=str(tmp_path),
    )

    assert response.success is False
    assert response.error_code == "runtime_timeout"
    assert response.metadata["timeout_retry_exhausted"] is True
    assert calls == 3

    call_dir = next((tmp_path / "sessions" / "timeout_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "timeout"
    assert response_payload["error_code"] == "runtime_timeout"
    assert response_payload["timeout_failures"] == 3
    assert response_payload["timeout_max_retries"] == 3
    assert len(response_payload["attempts"]) == 3
    assert [attempt.get("will_retry") for attempt in response_payload["attempts"]] == [
        True,
        True,
        False,
    ]


@pytest.mark.asyncio
async def test_pi_agent_runtime_timeout_restart_reuses_worker_session_dir(
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
                "model": "anthropic/claude-test",
                "timeout_max_retries": 3,
                "timeout_retry_delay": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    captured_session_dirs: list[str] = []
    results = [
        _AttemptResult(
            error="runtime no-progress timeout after 1.0s",
            status="timeout",
            timeout=True,
            error_code="runtime_timeout",
        ),
        _AttemptResult(
            error="runtime no-progress timeout after 1.0s",
            status="timeout",
            timeout=True,
            error_code="runtime_timeout",
        ),
        _AttemptResult(response_text="ok", status="completed"),
    ]

    async def fake_execute_once(**kwargs):
        cmd_args = kwargs["cmd_args"]
        captured_session_dirs.append(cmd_args[cmd_args.index("--session-dir") + 1])
        return results.pop(0)

    monkeypatch.setattr(runtime, "_execute_once", fake_execute_once)

    response = await runtime.send_message(
        message="worker timeout prompt",
        system_prompt="system",
        session_id="worker_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "ok"
    assert len(captured_session_dirs) == 3
    assert captured_session_dirs == [captured_session_dirs[0]] * 3

    session_dir = tmp_path / "sessions" / "worker_session"
    call_dirs = sorted((session_dir / "calls").iterdir())
    assert len(call_dirs) == 1
    response_payload = json.loads((call_dirs[0] / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "completed"
    assert response_payload["timeout_failures"] == 2
    assert len(response_payload["attempts"]) == 3
    assert {attempt["session_id"] for attempt in response_payload["attempts"]} == {"worker_session"}


@pytest.mark.asyncio
async def test_pi_agent_runtime_timeout_restart_uses_fresh_session_dir_for_reset_context_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = PiAgentRuntime(
        {
            "id": "pi-test",
            "name": "Pi Test",
            "type": "pi_agent",
            "reset_context": True,
            "runtime_config": {
                "model": "anthropic/claude-test",
                "timeout_max_retries": 3,
                "timeout_retry_delay": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    captured_session_dirs: list[str] = []
    results = [
        _AttemptResult(
            error="runtime no-progress timeout after 1.0s",
            status="timeout",
            timeout=True,
            error_code="runtime_timeout",
        ),
        _AttemptResult(response_text="advisor ok", status="completed"),
    ]

    async def fake_execute_once(**kwargs):
        cmd_args = kwargs["cmd_args"]
        captured_session_dirs.append(cmd_args[cmd_args.index("--session-dir") + 1])
        return results.pop(0)

    monkeypatch.setattr(runtime, "_execute_once", fake_execute_once)

    response = await runtime.send_message(
        message="advisor timeout prompt",
        system_prompt="system",
        session_id="advisor_session",
        working_dir=str(tmp_path),
    )

    assert response.success is True
    assert response.content == "advisor ok"
    assert len(captured_session_dirs) == 2
    assert captured_session_dirs[0] != captured_session_dirs[1]
    assert captured_session_dirs[0].endswith("advisor_session")
    assert "advisor_session_timeout_retry_001" in captured_session_dirs[1]

    call_dir = next((tmp_path / "sessions" / "advisor_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["timeout_retry_fresh_session"] is True
    assert response_payload["effective_session_id"].startswith("advisor_session_timeout_retry_001")
    assert response_payload["timeout_retry_sessions"][0]["session_id"].startswith(
        "advisor_session_timeout_retry_001"
    )
    assert [attempt["session_id"] for attempt in response_payload["attempts"]] == [
        "advisor_session",
        response_payload["effective_session_id"],
    ]


@pytest.mark.asyncio
async def test_pi_agent_runtime_launch_failure_does_not_retry_forever(
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
                "model": "anthropic/claude-test",
                "api_max_retries": -1,
                "pi_max_retries": -1,
                "api_retry_delay": 0,
                "pi_retry_delay": 0,
                "sdk_specific": {"thinking": "low"},
            },
        }
    )

    calls = 0

    async def fake_exec(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise FileNotFoundError("pi")

    async def fail_sleep(_delay):
        raise AssertionError("pi launch failure must not retry")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(asyncio, "sleep", fail_sleep)

    response = await runtime.send_message(
        message="launch prompt",
        system_prompt="system",
        session_id="launch_session",
        working_dir=str(tmp_path),
    )

    assert response.success is False
    assert response.error_code == "runtime_launch_failed"
    assert calls == 1

    call_dir = next((tmp_path / "sessions" / "launch_session" / "calls").iterdir())
    response_payload = json.loads((call_dir / "response.json").read_text(encoding="utf-8"))
    assert response_payload["status"] == "error"
    assert response_payload["error_code"] == "runtime_launch_failed"
    assert response_payload["pi_failures"] == 1
    assert response_payload["attempts"] == [
        {
            "attempt": 1,
            "status": "launch_error",
            "error": "pi CLI 未安装",
            "error_code": "runtime_launch_failed",
        }
    ]
