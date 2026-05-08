"""Logging and process helpers for firmware unpacking."""

from __future__ import annotations

import json
import os
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from app.logging_utils import log_event
from app.unpacker_engine_config import LOG_OUTPUT_DIR
from app.unpacker_engine_session import get_session_dir


_STREAM_LOG_STATE: dict[str, dict[str, Any]] = {}


def get_log_dir(output_path: str) -> Path:
    output_dir = Path(output_path)
    if output_dir.name == "output":
        log_dir = output_dir.parent / "run"
    else:
        log_dir = LOG_OUTPUT_DIR / output_dir.name
    log_dir.mkdir(parents=True, exist_ok=True)
    get_session_dir(log_dir)
    return log_dir


def stringify_message_content(block: Any) -> str:
    if isinstance(block, str):
        return block.strip()
    if not isinstance(block, dict):
        return ""

    block_type = str(block.get("type") or "").strip()
    if block_type in {"text", "input_text", "output_text"}:
        return str(block.get("text") or block.get("content") or "").strip()
    if block_type in {"thinking", "reasoning"}:
        text = str(block.get("text") or block.get("content") or "").strip()
        return f"[thinking]\n{text}" if text else ""
    if block_type in {"tool_call", "tool_use"}:
        tool_name = str(block.get("name") or block.get("tool_name") or block.get("tool") or "").strip()
        tool_input = block.get("input") or block.get("arguments") or block.get("args")
        rendered_input = ""
        if tool_input not in (None, ""):
            try:
                rendered_input = json.dumps(tool_input, ensure_ascii=False, indent=2)
            except Exception:
                rendered_input = str(tool_input)
        header = f"[tool_call] {tool_name}".strip()
        return f"{header}\n{rendered_input}".strip()
    if block_type in {"tool_result", "tool_output"}:
        tool_name = str(block.get("name") or block.get("tool_name") or block.get("tool") or "").strip()
        output = block.get("output") or block.get("content") or block.get("result")
        rendered_output = ""
        if output not in (None, ""):
            try:
                rendered_output = json.dumps(output, ensure_ascii=False, indent=2)
            except Exception:
                rendered_output = str(output)
        header = f"[tool_result] {tool_name}".strip()
        return f"{header}\n{rendered_output}".strip()

    for key in ("text", "content", "message"):
        value = block.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    try:
        return json.dumps(block, ensure_ascii=False, indent=2)
    except Exception:
        return str(block).strip()


def render_messages_transcript(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""

    sections: list[str] = []
    for index, message in enumerate(messages, start=1):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "unknown").strip() or "unknown"
        stop_reason = str(message.get("stopReason") or "").strip()
        header = f"[{index}] {role}"
        if stop_reason:
            header += f" stopReason={stop_reason}"

        contents = message.get("content")
        body_parts: list[str] = []
        if isinstance(contents, list):
            for block in contents:
                rendered = stringify_message_content(block)
                if rendered:
                    body_parts.append(rendered)
        elif contents:
            rendered = stringify_message_content(contents)
            if rendered:
                body_parts.append(rendered)
        elif message.get("text"):
            body_parts.append(str(message.get("text")).strip())

        body = "\n\n".join(part for part in body_parts if part)
        sections.append(header if not body else f"{header}\n{body}")

    return "\n\n".join(sections).strip()


def save_agent_log(client: Any, log, log_dir: Path | None, name: str) -> dict[str, Any]:
    if log_dir is None:
        return {}

    token_stats: dict[str, Any] = {}
    try:
        messages = client.get_messages()
        if messages is not None:
            (log_dir / f"{name}_messages.json").write_text(
                json.dumps(messages, ensure_ascii=False, indent=2)
            )
            transcript = render_messages_transcript(messages)
            if transcript:
                (log_dir / f"{name}_transcript.log").write_text(
                    transcript,
                    encoding="utf-8",
                )
    except Exception as exc:
        log_event(
            log,
            30,
            "failed to save agent messages",
            event="agent_log_fail",
            name=name,
            error=str(exc),
        )

    try:
        stats = client.get_token_stats()
        if stats and "tokens" in stats:
            token_stats = stats["tokens"]
            (log_dir / f"{name}_tokens.json").write_text(
                json.dumps(token_stats, indent=2)
            )
    except Exception as exc:
        log_event(
            log,
            30,
            "failed to get token stats",
            event="token_stats_fail",
            name=name,
            error=str(exc),
        )

    return token_stats


def write_token_summary(log_dir: Path | None) -> None:
    if log_dir is None:
        return

    total = {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "total": 0}
    by_agent: dict[str, dict[str, Any]] = {}
    for token_file in sorted(log_dir.glob("*_tokens.json")):
        key = token_file.stem.replace("_tokens", "")
        try:
            token_data = json.loads(token_file.read_text())
            by_agent[key] = token_data
            for field in total:
                total[field] = total.get(field, 0) + token_data.get(field, 0)
        except Exception:
            continue

    summary = {"by_agent": by_agent, "grand_total": total}
    output_file = log_dir / "tokens_summary.json"
    output_file.write_text(json.dumps(summary, indent=2))


def kill_process_tree(proc: subprocess.Popen[Any]) -> None:
    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass


def is_review_success(review_text: str) -> bool:
    lowered = str(review_text or "").strip().lower()
    return '"result":"success"' in lowered or '"result": "success"' in lowered


def write_json_log(log_dir: Path | None, name: str, payload: dict[str, Any]) -> None:
    if log_dir is None:
        return
    (log_dir / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2))


def append_stage_log(log_dir: Path | None, filename: str, message: str, **fields: Any) -> None:
    if log_dir is None:
        return
    stamp = datetime.utcnow().isoformat()
    line = f"[{stamp}] {message}"
    if fields:
        rendered = " ".join(
            f"{key}={json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}"
            for key, value in fields.items()
            if value is not None
        )
        if rendered:
            line = f"{line} {rendered}"
    with (log_dir / filename).open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def append_stream_delta(log_dir: Path | None, filename: str, actor: str, event: dict[str, Any]) -> None:
    if log_dir is None:
        return
    event_type = str(event.get("type") or "").strip()
    log_path = log_dir / filename
    state_key = f"{log_path}:{actor}"
    state = _STREAM_LOG_STATE.setdefault(
        state_key,
        {"open": False, "delta_type": None},
    )

    if event_type == "message_update":
        delta_info = event.get("assistantMessageEvent", {})
        delta_type = str(delta_info.get("type") or "").strip()
        delta = str(delta_info.get("delta") or "")
        if not delta_type or not delta:
            return

        label_map = {
            "thinking_delta": "thinking",
            "text_delta": "assistant",
            "toolcall_delta": "toolcall",
        }
        rendered_type = label_map.get(delta_type, delta_type)
        with log_path.open("a", encoding="utf-8") as fh:
            if state.get("open") and state.get("delta_type") != delta_type:
                fh.write("\n")
                state["open"] = False
            if not state.get("open"):
                stamp = datetime.utcnow().isoformat()
                fh.write(f"[{stamp}] [stream][{actor}][{rendered_type}] ")
                state["open"] = True
                state["delta_type"] = delta_type
            fh.write(delta.replace("\r\n", "\n").replace("\r", "\n"))
        return

    if event_type in {"message_end", "agent_end"} and state.get("open"):
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write("\n\n")
        state["open"] = False
        state["delta_type"] = None
