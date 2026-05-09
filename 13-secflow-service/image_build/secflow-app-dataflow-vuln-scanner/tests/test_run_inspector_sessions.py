import json
from pathlib import Path

from app.services.run_inspector import inspect_session_file, inspect_sessions


def _write_jsonl(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, ensure_ascii=False) if not isinstance(row, str) else row for row in rows), encoding="utf-8")


def test_inspect_session_file_matches_agent_session_shape(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    atomic = run_root / "workspace" / "atomic"
    (atomic / "_meta").mkdir(parents=True)
    session_file = atomic / "sessions" / "worker" / "abc.jsonl"
    _write_jsonl(
        session_file,
        [
            {"type": "session", "id": "abc", "version": "1", "timestamp": "2026-05-09T00:00:00Z", "cwd": "/work"},
            {"type": "model_change", "timestamp": "2026-05-09T00:00:01Z", "provider": "openai", "modelId": "gpt-test"},
            {"type": "thinking_level_change", "timestamp": "2026-05-09T00:00:02Z", "thinkingLevel": "high"},
            {"type": "model", "timestamp": "2026-05-09T00:00:02Z", "data": {"provider": "anthropic", "model_id": "claude-test"}},
            {"type": "reasoning_effort", "timestamp": "2026-05-09T00:00:02Z", "payload": {"level": "medium"}},
            {"type": "message", "timestamp": "2026-05-09T00:00:03Z", "message": {"role": "user", "content": "hello"}},
            {
                "type": "message_end",
                "timestamp": "2026-05-09T00:00:03Z",
                "message": {"role": "assistant", "content": [{"type": "text", "text": "rpc final"}]},
            },
            {
                "type": "message",
                "timestamp": "2026-05-09T00:00:04Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "checking"},
                        {"type": "toolCall", "name": "bash", "id": "tc1", "arguments": {"cmd": "id"}},
                        {"type": "text", "text": "done"},
                    ],
                },
            },
            {
                "type": "message",
                "timestamp": "2026-05-09T00:00:05Z",
                "message": {"role": "toolResult", "toolCallId": "tc1", "toolName": "bash", "isError": True, "content": "boom"},
            },
            "{bad json",
        ],
    )

    payload = inspect_session_file(run_root, "sessions/worker/abc.jsonl")

    assert payload["session_meta"]["id"] == "abc"
    assert payload["line_count"] == 10
    assert payload["warnings"] == ["第 10 行 JSON 解析失败"]
    assert payload["events"][0]["type"] == "model_change"
    assert payload["events"][0]["event_index"] == 2
    assert payload["events"][1]["thinkingLevelClass"] == "thinking-high"
    assert payload["events"][2]["provider"] == "anthropic"
    assert payload["events"][2]["modelId"] == "claude-test"
    assert payload["events"][3]["thinkingLevel"] == "medium"
    assert payload["events"][4]["parts"] == [{"type": "text", "text": "hello"}]
    assert payload["events"][5]["parts"] == [{"type": "text", "text": "rpc final"}]
    assert payload["events"][6]["parts"][0] == {"type": "thinking", "text": "checking"}
    assert payload["events"][7]["toolCallId"] == "tc1"
    assert payload["events"][7]["toolName"] == "bash"
    assert payload["events"][7]["isError"] is True
    assert payload["events"][8]["type"] == "raw"


def test_inspect_sessions_returns_jsonl_metadata(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    atomic = run_root / "workspace" / "atomic"
    (atomic / "_meta").mkdir(parents=True)
    _write_jsonl(
        atomic / "sessions" / "worker" / "abc.jsonl",
        [
            {"type": "session", "id": "abc", "timestamp": "2026-05-09T00:00:00Z", "model": "session/model", "thinking": "low"},
            {"type": "message", "timestamp": "2026-05-09T00:00:01Z", "message": {"role": "user", "content": "hello"}},
            "{bad json",
        ],
    )
    request_dir = atomic / "sessions" / "worker" / "calls" / "001_first"
    request_dir.mkdir(parents=True)
    (request_dir / "request.json").write_text(
        json.dumps(
            {
                "model": "provider/runtime-model",
                "raw_model": "runtime-model",
                "thinking": "high",
                "command_display": "pi --model provider/runtime-model --thinking high",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    sessions = inspect_sessions(run_root)
    jsonl_session = next(item for item in sessions if item["format"] == "jsonl")

    assert jsonl_session["session_id"] == "abc"
    assert jsonl_session["worker_id"] == "worker"
    assert jsonl_session["jsonl_path"] == "sessions/worker/abc.jsonl"
    assert jsonl_session["event_count"] == 2
    assert jsonl_session["line_count"] == 3
    assert jsonl_session["warnings"] == ["第 3 行 JSON 解析失败"]
    assert jsonl_session["display_name"] == "worker"
    assert jsonl_session["stage_group"] == "worker"
    assert jsonl_session["model"] == "provider/runtime-model"
    assert jsonl_session["raw_model"] == "runtime-model"
    assert jsonl_session["provider"] == "provider"
    assert jsonl_session["thinking"] == "high"
