"""Logging and process helpers for firmware unpacking."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from app.logging_utils import log_event
from app.unpacker_engine_config import LOG_OUTPUT_DIR
from app.unpacker_engine_session import get_session_dir


_STREAM_LOG_STATE: dict[str, dict[str, Any]] = {}
TOKEN_FIELDS = ("input", "output", "cacheRead", "cacheWrite", "total")
TASK_RESULT_CACHE_FILENAME = "task_result_cache.json"


def get_log_dir(output_path: str) -> Path:
    output_dir = Path(output_path)
    if output_dir.name == "output":
        log_dir = output_dir.parent / "run"
    else:
        log_dir = LOG_OUTPUT_DIR / output_dir.name
    log_dir.mkdir(parents=True, exist_ok=True)
    get_session_dir(log_dir)
    return log_dir


def round_dir_name(round_id: int) -> str:
    return f"round_{max(0, int(round_id)):03d}"


def get_round_dir(log_dir: Path | None, round_id: int) -> Path | None:
    if log_dir is None:
        return None
    round_dir = log_dir / round_dir_name(round_id)
    round_dir.mkdir(parents=True, exist_ok=True)
    return round_dir


def list_round_dirs(log_dir: Path | None) -> list[Path]:
    if log_dir is None or not log_dir.exists():
        return []
    round_dirs = [
        path for path in log_dir.iterdir()
        if path.is_dir() and path.name.startswith("round_")
    ]
    return sorted(round_dirs, key=lambda item: item.name)


def atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding=encoding,
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(content)
        temp_path = Path(handle.name)
    temp_path.replace(path)


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))


def read_text_tail(path: Path, max_bytes: int, *, encoding: str = "utf-8") -> str:
    if max_bytes <= 0:
        return ""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            read_size = min(size, max_bytes)
            handle.seek(-read_size, os.SEEK_END)
            payload = handle.read(read_size)
        text = payload.decode(encoding, errors="replace")
        if size > max_bytes:
            return f"[truncated,last_bytes={read_size},total_bytes={size}]\n{text}"
        return text
    except Exception:
        return ""


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
    log_dir.mkdir(parents=True, exist_ok=True)

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

    total = {field: 0 for field in TOKEN_FIELDS}
    by_agent: dict[str, dict[str, Any]] = {}
    for token_file in sorted(log_dir.glob("round_*/*_tokens.json")):
        try:
            rel_key = str(token_file.relative_to(log_dir))
        except Exception:
            rel_key = token_file.name
        key = rel_key.replace("_tokens.json", "")
        try:
            token_data = json.loads(token_file.read_text())
            by_agent[key] = token_data
            for field in TOKEN_FIELDS:
                total[field] = total.get(field, 0) + token_data.get(field, 0)
        except Exception:
            continue

    summary = {"by_agent": by_agent, "grand_total": total}
    output_file = get_round_dir(log_dir, 0)
    if output_file is None:
        return
    atomic_write_json(output_file / "tokens_summary.json", summary)


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
    atomic_write_json(log_dir / name, payload)


def append_stage_log(log_dir: Path | None, filename: str, message: str, **fields: Any) -> None:
    if log_dir is None:
        return
    from app.time_utils import isoformat_local, now_local

    stamp = isoformat_local(now_local()) or ""
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
                from app.time_utils import isoformat_local, now_local

                stamp = isoformat_local(now_local()) or ""
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


def read_json_file(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _normalize_extension(path: Path) -> str:
    suffix = path.suffix.lower()
    return suffix if suffix else "(none)"


def _relative_depth(root: Path, path: Path) -> int:
    try:
        return len(path.relative_to(root).parts)
    except Exception:
        return 0


def _scan_path_tree(root: Path) -> tuple[int, int, int]:
    file_count = 0
    dir_count = 0
    total_size = 0
    if not root.exists():
        return file_count, dir_count, total_size
    for current_root, dirs, files in os.walk(root, followlinks=False):
        current = Path(current_root)
        real_dirs: list[str] = []
        for directory in dirs:
            child = current / directory
            if child.is_symlink():
                continue
            dir_count += 1
            real_dirs.append(directory)
        dirs[:] = real_dirs
        for filename in files:
            child = current / filename
            if child.is_symlink():
                continue
            try:
                size = child.stat().st_size
            except Exception:
                continue
            file_count += 1
            total_size += size
    return file_count, dir_count, total_size


def scan_output_tree(output_root: Path) -> dict[str, Any]:
    file_count = 0
    dir_count = 0
    total_size = 0
    largest_file_path: str | None = None
    largest_file_size = 0
    deepest_path: str | None = None
    deepest_depth = 0
    small_file_count = 0
    medium_file_count = 0
    large_file_count = 0
    extension_stats: dict[str, dict[str, int | str]] = {}
    largest_files: list[dict[str, Any]] = []
    top_level_entries: list[dict[str, Any]] = []

    def _entry_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
        kind = 0 if str(item.get("kind") or "") == "dir" else 1
        return (-int(item.get("total_size_bytes") or 0), kind, str(item.get("name") or ""))

    top_level_paths = sorted(output_root.iterdir(), key=lambda item: item.name) if output_root.exists() else []
    top_level_entry_count = len(top_level_paths)
    for top_level_path in top_level_paths:
        if top_level_path.is_symlink():
            continue
        kind = "dir" if top_level_path.is_dir() else "file"
        file_stats = _scan_path_tree(top_level_path)
        top_level_entries.append(
            {
                "name": top_level_path.name,
                "kind": kind,
                "file_count": int(file_stats[0]),
                "dir_count": int(file_stats[1]),
                "total_size_bytes": int(file_stats[2]),
            }
        )

    for root, dirs, files in os.walk(output_root, followlinks=False):
        root_path = Path(root)
        real_dirs: list[str] = []
        for directory in dirs:
            path = root_path / directory
            if path.is_symlink():
                continue
            dir_count += 1
            real_dirs.append(directory)
            depth = _relative_depth(output_root, path)
            if depth > deepest_depth:
                deepest_depth = depth
                deepest_path = str(path)
        dirs[:] = real_dirs

        for filename in files:
            path = root_path / filename
            if path.is_symlink():
                continue
            try:
                size = path.stat().st_size
            except Exception:
                continue
            file_count += 1
            total_size += size
            if size > largest_file_size:
                largest_file_size = size
                largest_file_path = str(path)
            depth = _relative_depth(output_root, path)
            if depth > deepest_depth:
                deepest_depth = depth
                deepest_path = str(path)

            if size < 4 * 1024:
                small_file_count += 1
            elif size < 1024 * 1024:
                medium_file_count += 1
            else:
                large_file_count += 1

            extension = _normalize_extension(path)
            stats = extension_stats.setdefault(extension, {"extension": extension, "file_count": 0, "total_size_bytes": 0})
            stats["file_count"] = int(stats["file_count"]) + 1
            stats["total_size_bytes"] = int(stats["total_size_bytes"]) + size
            largest_files.append({"path": str(path), "size_bytes": size})

    top_level_entries.sort(key=_entry_sort_key)
    file_extension_breakdown = sorted(
        extension_stats.values(),
        key=lambda item: (
            -int(item.get("total_size_bytes") or 0),
            -int(item.get("file_count") or 0),
            str(item.get("extension") or ""),
        ),
    )
    largest_files.sort(key=lambda item: (-int(item.get("size_bytes") or 0), str(item.get("path") or "")))
    avg_file_size_bytes = int(total_size / file_count) if file_count > 0 else 0

    return {
        "exists": output_root.exists() and output_root.is_dir(),
        "output_file_count": file_count,
        "output_dir_count": dir_count,
        "output_total_size_bytes": total_size,
        "largest_file_path": largest_file_path,
        "largest_file_size_bytes": largest_file_size,
        "top_level_entry_count": top_level_entry_count,
        "top_level_entries": top_level_entries,
        "file_extension_breakdown": file_extension_breakdown,
        "largest_files": largest_files[:10],
        "deepest_path": (
            {"path": deepest_path, "depth": deepest_depth}
            if deepest_path is not None
            else None
        ),
        "avg_file_size_bytes": avg_file_size_bytes,
        "small_file_count": small_file_count,
        "medium_file_count": medium_file_count,
        "large_file_count": large_file_count,
    }


def build_output_manifest(output_root: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    if not output_root.exists() or not output_root.is_dir():
        return {"items": items}

    for root, dirs, files in os.walk(output_root, followlinks=False):
        root_path = Path(root)
        real_dirs: list[str] = []
        for directory in sorted(dirs):
            path = root_path / directory
            if path.is_symlink():
                continue
            real_dirs.append(directory)
            items.append(
                {
                    "path": str(path),
                    "relative_path": str(path.relative_to(output_root)),
                    "kind": "dir",
                    "size_bytes": 0,
                    "mtime": datetime.fromtimestamp(path.stat().st_mtime).isoformat() if path.exists() else None,
                    "depth": _relative_depth(output_root, path),
                    "extension": "(none)",
                }
            )
        dirs[:] = real_dirs

        for filename in sorted(files):
            path = root_path / filename
            if path.is_symlink():
                continue
            try:
                stat = path.stat()
            except Exception:
                continue
            items.append(
                {
                    "path": str(path),
                    "relative_path": str(path.relative_to(output_root)),
                    "kind": "file",
                    "size_bytes": int(stat.st_size),
                    "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "depth": _relative_depth(output_root, path),
                    "extension": _normalize_extension(path),
                }
            )
    return {"items": items}


def _diff_names(current_items: list[dict[str, Any]], previous_items: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    current_names = {str(item.get("name") or item.get("extension") or "") for item in current_items}
    previous_names = {str(item.get("name") or item.get("extension") or "") for item in previous_items}
    return sorted(current_names - previous_names), sorted(previous_names - current_names)


def compute_output_delta(current: dict[str, Any], previous: dict[str, Any] | None, *, baseline_round: int | None) -> dict[str, Any]:
    if not previous:
        return {
            "baseline_round": baseline_round,
            "file_count_delta": 0,
            "dir_count_delta": 0,
            "total_size_bytes_delta": 0,
            "largest_file_changed": False,
            "new_top_level_entries": [],
            "removed_top_level_entries": [],
            "new_extensions": [],
            "removed_extensions": [],
        }
    top_added, top_removed = _diff_names(
        list(current.get("top_level_entries") or []),
        list(previous.get("top_level_entries") or []),
    )
    ext_added, ext_removed = _diff_names(
        list(current.get("file_extension_breakdown") or []),
        list(previous.get("file_extension_breakdown") or []),
    )
    return {
        "baseline_round": baseline_round,
        "file_count_delta": int(current.get("output_file_count") or 0) - int(previous.get("output_file_count") or 0),
        "dir_count_delta": int(current.get("output_dir_count") or 0) - int(previous.get("output_dir_count") or 0),
        "total_size_bytes_delta": int(current.get("output_total_size_bytes") or 0) - int(previous.get("output_total_size_bytes") or 0),
        "largest_file_changed": str(current.get("largest_file_path") or "") != str(previous.get("largest_file_path") or ""),
        "new_top_level_entries": top_added,
        "removed_top_level_entries": top_removed,
        "new_extensions": ext_added,
        "removed_extensions": ext_removed,
    }


def copy_optional_text_file(source: Path, target: Path) -> bool:
    if not source.exists():
        return False
    try:
        atomic_write_text(target, source.read_text(encoding="utf-8"), encoding="utf-8")
        return True
    except Exception:
        return False


def write_round_result(
    round_dir: Path | None,
    *,
    task_id: str,
    round_id: int,
    status: str,
    created_at: str,
    started_at: str | None,
    completed_at: str | None,
    duration_seconds: float | None,
    output_root: Path,
    paths: dict[str, str | None],
    executor: dict[str, Any],
    reviewer: dict[str, Any],
    tokens: dict[str, Any],
    artifacts: dict[str, Any],
    context: dict[str, Any],
) -> None:
    if round_dir is None:
        return
    previous_round = round_id - 1 if round_id > 1 else None
    previous_summary = None
    if previous_round is not None:
        previous_path = round_dir.parent / round_dir_name(previous_round) / "results.json"
        previous_payload = read_json_file(previous_path)
        if isinstance(previous_payload, dict):
            previous_summary = previous_payload.get("output_snapshot")

    output_snapshot = scan_output_tree(output_root) if output_root.exists() and output_root.is_dir() else {
        "exists": False,
        "output_file_count": 0,
        "output_dir_count": 0,
        "output_total_size_bytes": 0,
        "largest_file_path": None,
        "largest_file_size_bytes": 0,
        "top_level_entry_count": 0,
        "top_level_entries": [],
        "file_extension_breakdown": [],
        "largest_files": [],
        "deepest_path": None,
        "avg_file_size_bytes": 0,
        "small_file_count": 0,
        "medium_file_count": 0,
        "large_file_count": 0,
    }
    manifest_payload = {
        "schema_version": 1,
        "task_id": task_id,
        "round": round_id,
        "generated_at": created_at,
        **build_output_manifest(output_root),
    }
    atomic_write_json(round_dir / "output_manifest.json", manifest_payload)
    payload = {
        "schema_version": 1,
        "task_id": task_id,
        "round": round_id,
        "status": status,
        "created_at": created_at,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration_seconds,
        "paths": paths,
        "executor": executor,
        "reviewer": reviewer,
        "tokens": tokens,
        "output_snapshot": output_snapshot,
        "output_delta": compute_output_delta(output_snapshot, previous_summary, baseline_round=previous_round),
        "artifacts": artifacts,
        "context": context,
    }
    atomic_write_json(round_dir / "results.json", payload)
