from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from app.pi_vuln_core.utils.win_compat import from_msys_path


_RUNNING_WORKFLOW_STATES = {
    "created",
    "start_plugins",
    "worker",
    "reflect",
    "summary",
    "global_review",
    "result_review",
    "end_plugins",
    "running",
    "queued",
    "pending",
}

_TERMINAL_STATUSES = {
    "completed",
    "succeeded",
    "failed",
    "interrupted",
    "cancelled",
    "stopped",
    "review_error",
    "review_plateau",
    "summary_incomplete",
    "runtime_output_limit",
    "runtime_timeout",
    "blocked_context_window",
    "blocked_quota",
    "provider_rate_limited",
    "model_contract_violation",
    "blocked_external_source",
    "no_workspace",
    "error",
}

_GENERIC_TERMINAL_STATUSES = {"failed", "error"}


def _is_profile_gate_issue(issue: dict[str, Any]) -> bool:
    issue_id = str(issue.get("id") or "").strip().upper()
    category = str(issue.get("category") or "").strip().lower()
    blocking_type = str(issue.get("blocking_type") or "").strip().lower()
    return (
        issue_id.startswith("PROFILE-")
        or category == "profile_evidence_gate"
        or blocking_type
        in {
            "summary_only_evidence",
            "metadata_sync",
        }
    )


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def derive_profile_gate_summary(global_review: dict[str, Any], metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    metrics = metrics or {}
    provided_gate = global_review.get("profile_gate") if isinstance(global_review.get("profile_gate"), dict) else {}
    advisor_results = [
        item for item in (global_review.get("advisor_results") or [])
        if isinstance(item, dict)
    ]
    total_advisors = _safe_int(
        global_review.get("total_advisor_count")
        or provided_gate.get("total_advisor_count")
        or len(advisor_results)
    )
    passed_advisors = _safe_int(
        global_review.get("passed_advisor_count")
        or provided_gate.get("passed_advisor_count")
        or len([item for item in advisor_results if item.get("passed", False)])
    )
    advisors_all_passed = total_advisors > 0 and passed_advisors == total_advisors
    issues = [
        item for item in (global_review.get("issues") or metrics.get("issues") or [])
        if isinstance(item, dict)
    ]
    profile_issues = [dict(item) for item in issues if _is_profile_gate_issue(item)]
    if not profile_issues:
        profile_issues = [
            dict(item) for item in (provided_gate.get("issues") or [])
            if isinstance(item, dict)
        ]
    feedback = str(
        global_review.get("feedback_preview")
        or provided_gate.get("feedback_preview")
        or metrics.get("global_feedback_preview")
        or ""
    )
    feedback_mentions_gate = (
        "框架范围验收硬门槛未通过" in feedback
        or "[profile_min_discovery_cycles]" in feedback
        or "PROFILE-" in feedback
    )
    global_passed = bool(global_review.get("passed", False))
    failed = (not global_passed) and (
        bool(provided_gate.get("failed"))
        or bool(profile_issues)
        or feedback_mentions_gate
        or str(global_review.get("aggregate_status") or "") == "profile_gate_failed"
    )
    status = "failed" if failed else "passed" if global_passed else "not_applicable"
    return {
        "status": status,
        "failed": failed,
        "passed": global_passed and not failed,
        "advisor_all_passed": advisors_all_passed,
        "passed_advisor_count": passed_advisors,
        "total_advisor_count": total_advisors,
        "feedback_preview": feedback[:500],
        "issue_count": len(profile_issues),
        "issues": profile_issues,
    }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _read_text(path: Path, max_bytes: int = 0) -> str:
    try:
        if max_bytes > 0:
            with path.open("r", encoding="utf-8", errors="replace") as file:
                return file.read(max_bytes)
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _tail_lines(path: Path, n: int = 300) -> str:
    try:
        with path.open("rb") as file:
            file.seek(0, 2)
            size = file.tell()
            chunk = min(size, max(n, 1) * 500)
            file.seek(max(0, size - chunk))
            data = file.read().decode("utf-8", errors="replace")
        return "\n".join(data.splitlines()[-n:])
    except Exception:
        return ""


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _file_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    if suffix == ".md":
        return "markdown"
    return "text"


def _parse_iso_timestamp(value: str) -> float:
    if not value:
        return 0
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
    ):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return 0


def _parse_timestamp_from_name(name: str) -> str:
    match = re.search(r"(\d{8})_(\d{6})(?:$|\D)", name) or re.search(r"(\d{8})_(\d{6})", name)
    if not match:
        return ""
    date, time = match.group(1), match.group(2)
    return f"{date[:4]}-{date[4:6]}-{date[6:8]} {time[:2]}:{time[2:4]}:{time[4:6]}"


def _parse_start_time_from_name(name: str) -> float:
    text = _parse_timestamp_from_name(name)
    if not text:
        return 0
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return 0


def _sorted_json_files(directory: Path, pattern: str = "cycle_*.json") -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(directory.glob(pattern))


def _runtime_dir(run_dir: Path) -> Path:
    runtime = run_dir / "run"
    if runtime.is_dir() and (
        (runtime / "config.json").exists()
        or (runtime / "_meta").exists()
        or (runtime / "workspace").exists()
        or (runtime / "ws").exists()
    ):
        return runtime
    return run_dir


def _atomic_candidate_search_roots(run_dir: Path, config: dict[str, Any]) -> list[Path]:
    runtime = _runtime_dir(run_dir)
    workspace_candidates: list[Path] = []
    workspace_root = str((config.get("global") or {}).get("workspace_root") or "").strip()
    if workspace_root:
        workspace_candidates.append(Path(from_msys_path(workspace_root) or workspace_root))
        workspace_name = Path(workspace_root).name
        if workspace_name:
            workspace_candidates.append(runtime / workspace_name)
            workspace_candidates.append(run_dir / workspace_name)
    workspace_candidates.extend([runtime / "workspace", runtime / "ws", runtime, run_dir / "workspace", run_dir / "ws", run_dir])

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in workspace_candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_dir():
            unique.append(candidate)
    return unique


def _atomic_candidate_score(candidate: Path) -> tuple[int, int]:
    score = 0
    evidence = 0

    def mark(points: int, condition: bool) -> None:
        nonlocal score, evidence
        if condition:
            score += points
            evidence += 1

    mark(12, (candidate / "input" / "task.md").is_file())
    mark(10, (candidate / "results").is_dir() or (candidate / "final_output" / "results").is_dir())
    mark(8, (candidate / "reviews").is_dir())
    mark(7, (candidate / "sessions").is_dir())
    mark(6, (candidate / "removed_results").is_dir() or (candidate / "final_output" / "removed_results").is_dir())
    mark(5, (candidate / "supporting_docs").is_dir() or (candidate / "final_output" / "supporting_docs").is_dir())
    mark(4, (candidate / "output").is_dir() or (candidate / "working").is_dir() or (candidate / "summary.md").is_file())
    mark(4, (candidate / "_meta" / "workflow_result.json").is_file())
    mark(3, (candidate / "_meta" / "state.json").is_file())
    mark(3, (candidate / "_meta" / "review_summaries").is_dir())
    mark(2, (candidate / "_meta" / "cycle_metrics").is_dir())
    mark(2, (candidate / "_meta" / "review_feedback").is_dir())

    return score, evidence


def _find_atomic_work_dir(run_dir: Path) -> Path | None:
    runtime = _runtime_dir(run_dir)
    config = _read_json(runtime / "config.json") or _read_json(run_dir / "config.json")
    candidates: list[tuple[int, int, int, Path]] = []
    fallback_candidates: list[tuple[int, Path]] = []
    seen: set[str] = set()

    for search_root in _atomic_candidate_search_roots(run_dir, config):
        meta_dirs: list[Path] = []
        if (search_root / "_meta").is_dir():
            meta_dirs.append(search_root / "_meta")
        meta_dirs.extend(path for path in search_root.rglob("_meta") if path.is_dir())
        for meta_dir in meta_dirs:
            candidate = meta_dir.parent
            key = str(candidate.resolve())
            if key in seen:
                continue
            seen.add(key)
            score, evidence = _atomic_candidate_score(candidate)
            try:
                depth = len(candidate.relative_to(run_dir).parts)
            except ValueError:
                depth = len(candidate.parts)
            if score > 0 and evidence >= 2:
                candidates.append((score, evidence, depth, candidate))
            fallback_candidates.append((depth, candidate))

    if candidates:
        candidates.sort(key=lambda item: (item[0], item[1], item[2], len(str(item[3]))), reverse=True)
        return candidates[0][3]
    if fallback_candidates:
        fallback_candidates.sort(key=lambda item: (item[0], len(str(item[1]))), reverse=True)
        return fallback_candidates[0][1]
    return None


_SESSION_THINKING_LEVEL_MAP = {
    "off": "off",
    "minimal": "minimal",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "x-high": "xhigh",
    "xhigh": "xhigh",
}


def _nested_dict(value: dict[str, Any], key: str) -> dict[str, Any]:
    nested = value.get(key)
    return nested if isinstance(nested, dict) else {}


def _first_string(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value is not None and not isinstance(value, (dict, list, tuple, set)):
            text = str(value).strip()
            if text:
                return text
    return ""


def _nested_sdk_specific(*records: dict[str, Any]) -> dict[str, Any]:
    for record in records:
        sdk = _nested_dict(record, "sdk_specific")
        if sdk:
            return sdk
        runtime = _nested_dict(record, "runtime_config")
        runtime_sdk = _nested_dict(runtime, "sdk_specific")
        if runtime_sdk:
            return runtime_sdk
    return {}


def _parse_session_message_parts(content: Any) -> list[dict[str, Any]]:
    parts: list[dict[str, Any]] = []
    if isinstance(content, str):
        parts.append({"type": "text", "text": content})
        return parts
    if not isinstance(content, list):
        return parts
    for item in content:
        if not isinstance(item, dict):
            continue
        part_type = str(item.get("type") or "")
        if part_type == "text":
            parts.append({"type": "text", "text": item.get("text", "")})
        elif part_type == "thinking":
            parts.append({"type": "thinking", "text": item.get("thinking", item.get("text", ""))})
        elif part_type == "toolCall":
            parts.append(
                {
                    "type": "toolCall",
                    "name": item.get("name", ""),
                    "id": item.get("id", ""),
                    "arguments": item.get("arguments", {}),
                }
            )
        elif part_type == "toolResult":
            parts.append({"type": "toolResult", "text": item.get("text", "")})
        else:
            parts.append({"type": "unknown", "detail": json.dumps(item, ensure_ascii=False)[:200]})
    return parts


def _map_session_jsonl_object(obj: dict[str, Any], raw_line: str, line_no: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    event_type = str(obj.get("type") or "")
    timestamp = str(obj.get("timestamp") or "")
    payload = _nested_dict(obj, "payload")
    data = _nested_dict(obj, "data")
    config = _nested_dict(obj, "config")
    metadata = _nested_dict(obj, "metadata")
    options = _nested_dict(obj, "options")
    settings = _nested_dict(obj, "settings")
    message = obj.get("message", {})
    if not isinstance(message, dict):
        message = {}
    sdk = _nested_sdk_specific(obj, payload, data, config, metadata, options, settings)
    model_provider = _first_string(
        obj.get("provider"),
        obj.get("modelProvider"),
        obj.get("model_provider"),
        payload.get("provider"),
        data.get("provider"),
        config.get("provider"),
        metadata.get("provider"),
        options.get("provider"),
        settings.get("provider"),
        message.get("provider"),
        sdk.get("provider"),
    )
    model_id = _first_string(
        obj.get("modelId"),
        obj.get("modelID"),
        obj.get("model_id"),
        obj.get("model"),
        obj.get("modelName"),
        obj.get("model_name"),
        payload.get("modelId"),
        payload.get("model_id"),
        payload.get("model"),
        data.get("modelId"),
        data.get("model_id"),
        data.get("model"),
        config.get("model"),
        metadata.get("modelId"),
        metadata.get("model_id"),
        metadata.get("model"),
        options.get("modelId"),
        options.get("model_id"),
        options.get("model"),
        settings.get("modelId"),
        settings.get("model_id"),
        settings.get("model"),
        message.get("modelId"),
        message.get("model_id"),
        message.get("model"),
        sdk.get("model"),
    )
    thinking_level = _first_string(
        obj.get("thinkingLevel"),
        obj.get("thinking_level"),
        obj.get("thinking"),
        obj.get("reasoningEffort"),
        obj.get("reasoning_effort"),
        obj.get("level"),
        payload.get("thinkingLevel"),
        payload.get("thinking_level"),
        payload.get("thinking"),
        payload.get("reasoning_effort"),
        payload.get("level"),
        data.get("thinkingLevel"),
        data.get("thinking_level"),
        data.get("thinking"),
        data.get("reasoning_effort"),
        data.get("level"),
        config.get("thinkingLevel"),
        config.get("thinking_level"),
        config.get("thinking"),
        config.get("reasoning_effort"),
        config.get("level"),
        metadata.get("thinkingLevel"),
        metadata.get("thinking_level"),
        metadata.get("thinking"),
        metadata.get("reasoning_effort"),
        metadata.get("level"),
        options.get("thinkingLevel"),
        options.get("thinking_level"),
        options.get("thinking"),
        options.get("reasoning_effort"),
        options.get("level"),
        settings.get("thinkingLevel"),
        settings.get("thinking_level"),
        settings.get("thinking"),
        settings.get("reasoning_effort"),
        settings.get("level"),
        message.get("thinkingLevel"),
        message.get("thinking_level"),
        message.get("thinking"),
        message.get("reasoning_effort"),
        message.get("level"),
        sdk.get("thinking"),
        sdk.get("reasoning_effort"),
        sdk.get("level"),
    )
    if event_type == "session":
        return {
            "id": obj.get("id", ""),
            "version": obj.get("version", ""),
            "timestamp": timestamp,
            "cwd": obj.get("cwd", ""),
            "provider": model_provider,
            "model": model_id,
            "thinking": thinking_level,
        }, None
    if event_type in {"model_change", "model", "model_changed", "set_model"} or (model_id and not event_type.startswith("message")):
        return None, {
            "type": "model_change",
            "line": line_no,
            "event_index": line_no,
            "timestamp": timestamp,
            "display_timestamp": timestamp,
            "provider": model_provider,
            "modelId": model_id,
            "raw_line": raw_line,
        }
    if event_type in {"thinking_level_change", "thinking_level", "thinking", "reasoning_effort_change", "reasoning_effort"} or (thinking_level and not event_type.startswith("message")):
        level = thinking_level
        return None, {
            "type": "thinking_level_change",
            "line": line_no,
            "event_index": line_no,
            "timestamp": timestamp,
            "display_timestamp": timestamp,
            "thinkingLevel": level,
            "thinkingLevelClass": f"thinking-{_SESSION_THINKING_LEVEL_MAP.get(level.lower(), 'off')}",
            "raw_line": raw_line,
        }
    if event_type in {"message", "message_end"}:
        role = str(message.get("role") or "")
        event = {
            "type": "message",
            "line": line_no,
            "event_index": line_no,
            "timestamp": timestamp,
            "display_timestamp": timestamp,
            "role": role,
            "render_role": role,
            "parts": _parse_session_message_parts(message.get("content", [])),
            "raw_line": raw_line,
        }
        if role == "toolResult":
            event["toolCallId"] = message.get("toolCallId") or message.get("tool_call_id") or ""
            event["toolName"] = message.get("toolName") or message.get("tool_name") or ""
            event["isError"] = bool(message.get("isError", message.get("is_error", False)))
        return None, event
    return None, {
        "type": event_type or "unknown_event",
        "line": line_no,
        "event_index": line_no,
        "timestamp": timestamp,
        "display_timestamp": timestamp,
        "summary": json.dumps(obj, ensure_ascii=False)[:200],
        "raw_line": raw_line[:200],
    }


def _parse_session_jsonl_lines(lines: list[str]) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    session_meta: dict[str, Any] = {}
    line_count = 0
    for line_no, raw_line in enumerate(lines, 1):
        line_count = line_no
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            warnings.append(f"第 {line_no} 行 JSON 解析失败")
            events.append({"type": "raw", "line": line_no, "event_index": line_no, "raw_line": line[:200], "summary": line[:200]})
            continue
        if not isinstance(obj, dict):
            events.append({"type": "raw", "line": line_no, "event_index": line_no, "raw_line": line[:200], "summary": line[:200]})
            continue
        mapped_meta, mapped_event = _map_session_jsonl_object(obj, line, line_no)
        if mapped_meta is not None:
            session_meta = mapped_meta
        if mapped_event is not None:
            events.append(mapped_event)
    return {"session_meta": session_meta, "events": events, "warnings": warnings, "line_count": line_count}


def _parse_session_jsonl_file(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            return _parse_session_jsonl_lines(file.read().splitlines())
    except Exception:
        return {"session_meta": {}, "events": [], "warnings": ["会话文件读取失败"], "line_count": 0}


def _session_display_name(worker_id: str, session_id: str, jsonl_path: str) -> str:
    if worker_id:
        return worker_id
    if session_id:
        return session_id
    return Path(jsonl_path).name or "Session"


def _session_runtime_metadata(session_dir: Path) -> dict[str, Any]:
    calls_dir = session_dir / "calls"
    if not calls_dir.is_dir():
        return {}
    for request_path in sorted(calls_dir.glob("*/request.json")):
        request = _read_json(request_path)
        if not request:
            continue
        model = _first_string(request.get("model"), request.get("raw_model"))
        raw_model = _first_string(request.get("raw_model"), request.get("model"))
        thinking = _first_string(request.get("thinking"), request.get("reasoning_effort"))
        provider = _first_string(request.get("provider"))
        if not provider and "/" in model:
            provider = model.split("/", 1)[0]
        command = request.get("command_argv")
        return {
            "model": model,
            "raw_model": raw_model,
            "provider": provider,
            "thinking": thinking,
            "command": command if isinstance(command, list) else [],
            "command_display": str(request.get("command_display") or ""),
        }
    return {}


def _summarize_global_review_advisors(config: dict[str, Any]) -> list[dict[str, Any]]:
    advisors: list[dict[str, Any]] = []
    for workflow in ((config.get("workflows") or {}).get("atomic") or []):
        group = (((workflow.get("roles") or {}).get("advisors") or {}).get("global_review") or [])
        for advisor in group:
            advisors.append(
                {
                    "instance_id": advisor.get("instance_id", ""),
                    "role_name": advisor.get("role_name", ""),
                    "score_fields": advisor.get("score_fields", []),
                    "score_thresholds": advisor.get("score_thresholds", {}),
                    "score_thresholds_start": advisor.get("score_thresholds_start", {}),
                }
            )
    return advisors


def _extract_config_summary(config: dict[str, Any]) -> dict[str, Any]:
    agents = config.get("agents", [])
    worker = next((item for item in agents if str(item.get("id", "")).endswith("worker")), agents[0] if agents else {})
    runtime = worker.get("runtime_config", {})
    sdk = runtime.get("sdk_specific", {})
    global_cfg = config.get("global", {})
    execution_cfg = config.get("execution", {})
    review_profile = "balanced"
    for workflow in ((config.get("workflows") or {}).get("atomic") or []):
        if not isinstance(workflow, dict):
            continue
        engine = workflow.get("engine") or {}
        if isinstance(engine, dict) and (engine.get("review_profile") or workflow.get("id") == "vuln_scan"):
            review_profile = str(engine.get("review_profile") or "balanced")
            break
    return {
        "model": runtime.get("model", ""),
        "provider": sdk.get("provider", ""),
        "thinking": sdk.get("thinking", ""),
        "review_profile": review_profile,
        "timeout_seconds": runtime.get("timeout_seconds", 0),
        "max_review_cycles": global_cfg.get("max_review_cycles", 0),
        "parallel_result_review": global_cfg.get("parallel_result_review", False),
        "parallel_result_review_limit": global_cfg.get("parallel_result_review_limit", 0),
        "execution_id": execution_cfg.get("execution_id", ""),
        "task_file": (execution_cfg.get("input_task") or {}).get("task_file", ""),
        "global_review_advisors": _summarize_global_review_advisors(config),
    }


def _read_run_timestamps(run_dir: Path) -> dict[str, Any]:
    runtime = _runtime_dir(run_dir)
    return _read_json(runtime / "_meta" / "run_timestamps.json") or _read_json(run_dir / "_meta" / "run_timestamps.json")


def _normalize_run_status(raw_status: str, run_meta: dict[str, Any] | None = None) -> str:
    run_meta = run_meta or {}
    text = str(raw_status or "").strip().lower()
    meta_status = str(run_meta.get("status") or "").strip().lower()
    # The control/timestamps file is written by the managed task runtime and by
    # stale-runtime reconciliation.  Treat a terminal control status as
    # authoritative even when the original run_vuln_scan.py process disappeared
    # before it could fill finished_at; otherwise stale state.json entries such
    # as current_state=running keep resurrecting a dead Run as "running".
    if meta_status in _TERMINAL_STATUSES:
        if meta_status in _GENERIC_TERMINAL_STATUSES and text in (_TERMINAL_STATUSES - _GENERIC_TERMINAL_STATUSES):
            return text
        return meta_status
    if not run_meta.get("finished_at") and meta_status in _RUNNING_WORKFLOW_STATES:
        return "running" if meta_status == "in_progress" else meta_status
    if text in _TERMINAL_STATUSES:
        return text
    if text in _RUNNING_WORKFLOW_STATES:
        return "running" if text not in {"pending", "queued"} else text
    return text or "pending"


def _find_last_activity(atomic: Path | None, run_dir: Path) -> str:
    candidates: list[str] = []
    if atomic:
        state = _read_json(atomic / "_meta" / "state.json")
        if state.get("timestamp"):
            candidates.append(str(state["timestamp"]))
        summaries = _sorted_json_files(atomic / "_meta" / "review_summaries")
        if summaries:
            latest = _read_json(summaries[-1])
            if latest.get("timestamp"):
                candidates.append(str(latest["timestamp"]))
        for jsonl in sorted(atomic.rglob("*.jsonl")):
            try:
                with jsonl.open("rb") as file:
                    file.seek(0, 2)
                    size = file.tell()
                    file.seek(max(0, size - 4096))
                    tail = file.read().decode("utf-8", errors="replace")
                for line in reversed(tail.splitlines()):
                    try:
                        event = json.loads(line.strip())
                    except json.JSONDecodeError:
                        continue
                    if event.get("timestamp"):
                        candidates.append(str(event["timestamp"]))
                        break
            except Exception:
                continue
    runtime = _runtime_dir(run_dir)
    log_path = runtime / "run.log"
    if not log_path.is_file():
        log_path = run_dir / "run.log"
    if log_path.is_file():
        try:
            candidates.append(datetime.fromtimestamp(log_path.stat().st_mtime, tz=timezone.utc).isoformat())
        except Exception:
            pass
    return max(candidates) if candidates else ""


def _find_run_start_epoch(run_dir: Path, run_meta: dict[str, Any] | None = None) -> float:
    run_meta = run_meta or {}
    started_at = _parse_iso_timestamp(str(run_meta.get("started_at") or ""))
    if started_at:
        return started_at
    parsed = _parse_start_time_from_name(run_dir.name)
    if parsed:
        return parsed
    try:
        return run_dir.stat().st_mtime
    except OSError:
        return 0


def _find_run_end_epoch(atomic: Path | None, run_dir: Path, status: str, run_meta: dict[str, Any] | None = None) -> float:
    if status == "running":
        return datetime.now(tz=timezone.utc).timestamp()
    run_meta = run_meta or {}
    finished_at = _parse_iso_timestamp(str(run_meta.get("finished_at") or ""))
    if finished_at:
        return finished_at
    candidates: list[float] = []
    if atomic:
        for meta_name in ("workflow_result.json", "abnormal_exit.json"):
            timestamp = _parse_iso_timestamp(str(_read_json(atomic / "_meta" / meta_name).get("timestamp") or ""))
            if timestamp:
                candidates.append(timestamp)
        state_timestamp = _parse_iso_timestamp(str(_read_json(atomic / "_meta" / "state.json").get("timestamp") or ""))
        if state_timestamp:
            candidates.append(state_timestamp)
    last_activity = _parse_iso_timestamp(_find_last_activity(atomic, run_dir))
    if last_activity:
        candidates.append(last_activity)
    return max(candidates) if candidates else 0


def _compute_duration(run_dir: Path, atomic: Path | None, status: str, run_meta: dict[str, Any] | None = None) -> int:
    start = _find_run_start_epoch(run_dir, run_meta)
    end = _find_run_end_epoch(atomic, run_dir, status, run_meta)
    if not start or not end or end < start:
        return 0
    return int(end - start)


def _manifest_path_summary(atomic: Path, path: Path) -> dict[str, Any]:
    return {"path": str(path.relative_to(atomic)), "exists": path.is_file()}


def _load_manifest_summary(atomic: Path) -> dict[str, Any]:
    relations_path = atomic / "_meta" / "result_relations_manifest.json"
    results_path = atomic / "_meta" / "results_manifest.json"
    vuln_list_path = atomic / "_meta" / "vulnerability_list.json"
    relations = _read_json(relations_path)
    results = _read_json(results_path)
    vuln_list = _read_json(vuln_list_path)
    return {
        "result_relations_manifest": _manifest_path_summary(atomic, relations_path),
        "results_manifest": _manifest_path_summary(atomic, results_path),
        "vulnerability_list": _manifest_path_summary(atomic, vuln_list_path),
        "vulnerability_status_counts": vuln_list.get("counts", {}),
        "total_result_files": results.get("total_result_files", len(relations.get("all_results", []))),
        "active_result_count": results.get("active_result_count", 0),
        "inactive_result_count": results.get("inactive_result_count", len(relations.get("inactive_results", []))),
        "taskable_result_count": results.get("taskable_result_count", len(relations.get("taskable_results", []))),
        "supplemental_result_count": results.get("supplemental_result_count", len(relations.get("supplemental_results", []))),
        "excluded_result_count": len(results.get("excluded_results", relations.get("excluded_results", [])) or []),
        "missing_referenced_results": [],
        "unreferenced_active_results": [],
    }


_CHECKPOINT_PHASE_ORDER = {
    "worker": 10,
    "reflect": 20,
    "summary": 30,
    "global_review": 40,
    "result_review": 50,
}


def _load_current_step_checkpoint(atomic: Path) -> dict[str, Any]:
    payload = _read_json(atomic / "_meta" / "checkpoints" / "current_step.json")
    if not payload:
        return {}
    return _enrich_checkpoint_timing({
        **payload,
        "path": "_meta/checkpoints/current_step.json",
    })


def _enrich_checkpoint_timing(item: dict[str, Any]) -> dict[str, Any]:
    payload = dict(item)
    started_epoch = _safe_float(payload.get("started_epoch"))
    finished_epoch = _safe_float(payload.get("finished_epoch"))
    status = str(payload.get("status") or "").strip().lower()
    if started_epoch > 0 and finished_epoch <= 0 and status in {"started", "running"}:
        payload["elapsed_seconds"] = max(int(time.time() - started_epoch), 0)
    return payload


def _checkpoint_identity(item: dict[str, Any]) -> tuple[int, str, str, str]:
    return (
        _safe_int(item.get("cycle")),
        str(item.get("phase") or ""),
        str(item.get("step_key") or ""),
        str(item.get("status") or ""),
    )


def _collect_step_checkpoints(atomic: Path, limit: int = 240) -> list[dict[str, Any]]:
    steps_root = atomic / "_meta" / "checkpoints" / "steps"
    if not steps_root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for checkpoint_path in steps_root.rglob("*.json"):
        payload = _read_json(checkpoint_path)
        if not payload:
            continue
        try:
            mtime = checkpoint_path.stat().st_mtime
        except OSError:
            mtime = 0.0
        items.append(
            _enrich_checkpoint_timing({
                **payload,
                "path": _rel_to_atomic(checkpoint_path, atomic),
                "mtime": mtime,
            })
        )
    items.sort(
        key=lambda item: (
            int(item.get("cycle") or 0),
            _CHECKPOINT_PHASE_ORDER.get(str(item.get("phase") or ""), 90),
            str(item.get("step_key") or ""),
            float(item.get("mtime") or 0.0),
        )
    )
    return items[-limit:]


def _collect_cycle_timing(step_history: list[dict[str, Any]], current_step: dict[str, Any] | None = None) -> dict[str, Any]:
    now_epoch = time.time()
    items = [item for item in step_history if isinstance(item, dict)]
    if current_step:
        current_identity = _checkpoint_identity(current_step)
        if current_identity and not any(_checkpoint_identity(item) == current_identity for item in items):
            items.append(current_step)

    grouped: dict[int, list[dict[str, Any]]] = {}
    for item in items:
        cycle = _safe_int(item.get("cycle"))
        if cycle <= 0:
            continue
        if _safe_float(item.get("started_epoch")) <= 0:
            continue
        grouped.setdefault(cycle, []).append(item)

    timing: dict[str, Any] = {}
    for cycle, cycle_items in sorted(grouped.items()):
        starts = [_safe_float(item.get("started_epoch")) for item in cycle_items]
        starts = [value for value in starts if value > 0]
        if not starts:
            continue
        finishes = [_safe_float(item.get("finished_epoch")) for item in cycle_items]
        finishes = [value for value in finishes if value > 0]
        running_items = [
            item for item in cycle_items
            if str(item.get("status") or "").strip().lower() in {"started", "running"}
            and _safe_float(item.get("finished_epoch")) <= 0
        ]
        started_epoch = min(starts)
        finished_epoch = max(finishes) if finishes else 0.0
        running = bool(running_items)
        entry: dict[str, Any] = {
            "cycle": cycle,
            "started_epoch": started_epoch,
            "started_at": min((str(item.get("started_at") or "") for item in cycle_items if item.get("started_at")), default=""),
            "finished_at": "",
            "node_count": len(cycle_items),
            "running": running,
        }
        if running:
            entry["elapsed_seconds"] = max(int(now_epoch - started_epoch), 0)
        elif finished_epoch > 0:
            entry["finished_epoch"] = finished_epoch
            entry["finished_at"] = max((str(item.get("finished_at") or "") for item in cycle_items if item.get("finished_at")), default="")
            entry["duration_seconds"] = max(int(round(finished_epoch - started_epoch)), 0)
        timing[str(cycle)] = entry
    return timing


def _rel_to_atomic(path: Path, atomic: Path) -> str:
    return str(path.relative_to(atomic))


_RESULT_MARKDOWN_RE = re.compile(r"^result_\d+\.md$")
_RESULT_CYCLE_DIR_RE = re.compile(r"cycle_(\d+)$")


def _result_filename_from_review(result_dir: Path, payload: dict[str, Any]) -> str:
    filename = str(payload.get("result_file") or f"{result_dir.name}.md").strip()
    if filename and not filename.endswith(".md"):
        filename = f"{filename}.md"
    return filename


def _extract_markdown_title(path: Path) -> str:
    for line in _read_text(path, max_bytes=600).splitlines():
        if line.startswith("#"):
            return re.sub(r"^#+\s*", "", line).strip()
    return ""


def _result_manifest_entries_by_name(atomic: Path) -> dict[str, dict[str, Any]]:
    results_manifest = _read_json(atomic / "_meta" / "results_manifest.json")
    relations_manifest = _read_json(atomic / "_meta" / "result_relations_manifest.json")
    entries = results_manifest.get("entries") or relations_manifest.get("relationships") or []
    return {
        str(item.get("filename") or ""): item
        for item in entries
        if isinstance(item, dict)
    }


def _collect_results(atomic: Path) -> list[dict[str, Any]]:
    results_dir = atomic / "results"
    if not results_dir.is_dir():
        results_dir = atomic / "final_output" / "results"
    if not results_dir.is_dir():
        return []
    entry_by_name = _result_manifest_entries_by_name(atomic)
    vuln_list = _read_json(atomic / "_meta" / "vulnerability_list.json")
    vuln_by_name = {
        str(item.get("result_file") or ""): item
        for item in (vuln_list.get("entries") or [])
        if isinstance(item, dict)
    }
    results: list[dict[str, Any]] = []
    for file_path in sorted(results_dir.glob("result_*.md")):
        review_dir = atomic / "reviews" / "results" / file_path.stem
        latest_review: dict[str, Any] = {}
        latest_review_path: Path | None = None
        if review_dir.is_dir():
            for cycle_dir in sorted(review_dir.glob("cycle_*"), reverse=True):
                for review_file in sorted(cycle_dir.glob("*.json")):
                    latest_review = _read_json(review_file)
                    latest_review_path = review_file
                    break
                if latest_review:
                    break
        title = _extract_markdown_title(file_path)
        manifest_entry = entry_by_name.get(file_path.name, {})
        vuln_entry = vuln_by_name.get(file_path.name, {})
        vulnerability_status = str(vuln_entry.get("status") or "")
        results.append(
            {
                "filename": file_path.name,
                "path": _rel_to_atomic(file_path, atomic),
                "title": title,
                "size": file_path.stat().st_size,
                "passed": (True if vulnerability_status == "confirmed" else False if vulnerability_status == "false_positive" else latest_review.get("passed")),
                "verdict": vuln_entry.get("verdict") or latest_review.get("verdict", ""),
                "confidence": latest_review.get("confidence", 0),
                "review_cycle": latest_review.get("cycle", 0),
                "feedback": latest_review.get("feedback", ""),
                "feedback_detail": latest_review.get("feedback_detail", ""),
                "schema_valid": latest_review.get("schema_valid"),
                "parser_mode": latest_review.get("parser_mode", ""),
                "review_path": _rel_to_atomic(latest_review_path, atomic) if latest_review_path else "",
                "role": manifest_entry.get("role", ""),
                "lifecycle_status": manifest_entry.get("lifecycle_status", ""),
                "active": manifest_entry.get("active", True),
                "taskable": False if vulnerability_status in {"false_positive", "pending_review"} else manifest_entry.get("taskable", True),
                "vuln_id": vuln_entry.get("vuln_id", ""),
                "vulnerability_status": vulnerability_status,
                "status_label": vuln_entry.get("status_label", ""),
                "delivery_bucket": manifest_entry.get("delivery_bucket", "results"),
                "multi_finding": manifest_entry.get("multi_finding", False),
                "vulnerability_headings": manifest_entry.get("vulnerability_headings", []),
                "related_to": manifest_entry.get("related_to", ""),
            }
        )
    return results


def _collect_removed_results(atomic: Path) -> list[dict[str, Any]]:
    removed_root = atomic / "removed_results"
    if not removed_root.is_dir():
        return []
    removed: list[dict[str, Any]] = []
    for meta_path in sorted(removed_root.glob("cycle_*/*.json")):
        data = _read_json(meta_path)
        md_path = meta_path.with_suffix(".md")
        cycle = data.get("removed_in_cycle")
        if not cycle:
            match = re.search(r"cycle_(\d+)", str(meta_path.parent.name))
            cycle = int(match.group(1)) if match else 0
        removed.append(
            {
                "filename": data.get("original_filename") or md_path.name,
                "path": _rel_to_atomic(md_path, atomic) if md_path.is_file() else "",
                "meta_path": _rel_to_atomic(meta_path, atomic),
                "cycle": cycle,
                "lifecycle_status": data.get("lifecycle_status", "inactive"),
                "reason": data.get("reason", ""),
                "signals": data.get("signals", []),
            }
        )
    return removed


def collect_new_results_by_cycle(atomic: str | Path) -> dict[int, list[dict[str, Any]]]:
    atomic_path = Path(atomic)
    result_root = atomic_path / "reviews" / "results"
    if not result_root.is_dir():
        return {}

    first_reviews: dict[str, dict[str, Any]] = {}
    latest_reviews: dict[str, dict[str, Any]] = {}
    for result_dir in sorted(item for item in result_root.iterdir() if item.is_dir()):
        for cycle_dir in sorted(item for item in result_dir.iterdir() if item.is_dir()):
            match = _RESULT_CYCLE_DIR_RE.match(cycle_dir.name)
            dir_cycle = _safe_int(match.group(1)) if match else 0
            for review_file in sorted(cycle_dir.glob("*.json")):
                payload = _read_json(review_file)
                filename = _result_filename_from_review(result_dir, payload)
                if not _RESULT_MARKDOWN_RE.match(filename):
                    continue
                review_cycle = _safe_int(payload.get("cycle"), dir_cycle)
                if review_cycle <= 0:
                    review_cycle = dir_cycle
                if review_cycle <= 0:
                    continue
                review_item = {
                    "filename": filename,
                    "cycle": review_cycle,
                    "path": _rel_to_atomic(review_file, atomic_path),
                    "passed": payload.get("passed"),
                    "verdict": str(payload.get("verdict") or ""),
                    "confidence": _safe_float(payload.get("confidence")),
                }
                first_key = (
                    _safe_int(first_reviews.get(filename, {}).get("cycle"), default=10**9),
                    str(first_reviews.get(filename, {}).get("path") or ""),
                )
                current_key = (review_cycle, review_item["path"])
                if filename not in first_reviews or current_key < first_key:
                    first_reviews[filename] = review_item
                latest_key = (
                    _safe_int(latest_reviews.get(filename, {}).get("cycle")),
                    str(latest_reviews.get(filename, {}).get("path") or ""),
                )
                if filename not in latest_reviews or current_key >= latest_key:
                    latest_reviews[filename] = review_item

    active_by_name = {str(item.get("filename") or ""): item for item in _collect_results(atomic_path)}
    removed_by_name: dict[str, dict[str, Any]] = {}
    for item in _collect_removed_results(atomic_path):
        filename = str(item.get("filename") or "")
        if not filename:
            continue
        previous = removed_by_name.get(filename)
        if previous is None or _safe_int(item.get("cycle")) >= _safe_int(previous.get("cycle")):
            removed_by_name[filename] = item
    manifest_by_name = _result_manifest_entries_by_name(atomic_path)

    by_cycle: dict[int, list[dict[str, Any]]] = {}
    for filename, first in first_reviews.items():
        latest = latest_reviews.get(filename, first)
        active = active_by_name.get(filename, {})
        removed = removed_by_name.get(filename, {})
        manifest = manifest_by_name.get(filename, {})
        path = str(active.get("path") or removed.get("path") or "")
        title = str(active.get("title") or "")
        if not title and path:
            markdown_path = atomic_path / path
            if markdown_path.is_file():
                title = _extract_markdown_title(markdown_path)
        is_removed = bool(removed)
        lifecycle_status = str(
            active.get("lifecycle_status")
            or removed.get("lifecycle_status")
            or manifest.get("lifecycle_status")
            or ("inactive" if is_removed else "")
        )
        candidate = {
            "filename": filename,
            "title": title,
            "path": path,
            "first_seen_cycle": _safe_int(first.get("cycle")),
            "first_review_path": str(first.get("path") or ""),
            "first_review_verdict": str(first.get("verdict") or ""),
            "first_review_passed": first.get("passed"),
            "first_review_confidence": _safe_float(first.get("confidence")),
            "current_review_cycle": _safe_int(latest.get("cycle")),
            "current_verdict": str(latest.get("verdict") or active.get("verdict") or ""),
            "current_passed": latest.get("passed") if "passed" in latest else active.get("passed"),
            "current_confidence": _safe_float(latest.get("confidence", active.get("confidence", 0))),
            "active": bool(active.get("active", manifest.get("active", not is_removed))) and not is_removed,
            "taskable": bool(active.get("taskable", manifest.get("taskable", not is_removed))) and not is_removed,
            "lifecycle_status": lifecycle_status,
            "removed": is_removed,
            "removed_cycle": _safe_int(removed.get("cycle")) if is_removed else 0,
            "vulnerability_headings": list(active.get("vulnerability_headings") or manifest.get("vulnerability_headings") or []),
            "related_to": str(active.get("related_to") or manifest.get("related_to") or ""),
        }
        by_cycle.setdefault(candidate["first_seen_cycle"], []).append(candidate)

    for items in by_cycle.values():
        items.sort(key=lambda item: str(item.get("filename") or ""))
    return dict(sorted(by_cycle.items(), key=lambda item: item[0]))


def inspect_run_summary(workspace_root: str | Path) -> dict[str, Any]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        return {"status": "pending", "cycles_used": 0, "result_count": 0}
    runtime = _runtime_dir(run_dir)
    config = _read_json(runtime / "config.json") or _read_json(run_dir / "config.json")
    cfg_summary = _extract_config_summary(config)
    atomic = _find_atomic_work_dir(run_dir)
    run_meta = _read_run_timestamps(run_dir)
    status = "pending"
    cycles_used = 0
    result_count = 0
    passed_count = 0
    failed_count = 0
    workflow_mode = ""
    last_activity = ""
    if atomic:
        workflow_result = _read_json(atomic / "_meta" / "workflow_result.json")
        state = _read_json(atomic / "_meta" / "state.json")
        status = workflow_result.get("status", state.get("current_state", "running"))
        summaries = _sorted_json_files(atomic / "_meta" / "review_summaries")
        if summaries:
            latest = _read_json(summaries[-1])
            result_review = latest.get("result_review", {})
            result_count = result_review.get("total", 0)
            passed_count = result_review.get("passed_count", 0)
            failed_count = result_review.get("failed_count", 0)
            workflow_mode = latest.get("workflow_mode", "")
            cycles_used = latest.get("cycle", 0)
        result_manifest = _read_json(atomic / "_meta" / "results_manifest.json")
        if result_manifest:
            result_count = result_manifest.get("taskable_result_count", result_count)
        if workflow_result:
            cycles_used = (workflow_result.get("detail") or {}).get("cycles_used", cycles_used)
        last_activity = _find_last_activity(atomic, run_dir)
    status = _normalize_run_status(status, run_meta)
    return {
        "name": run_dir.name,
        "status": status,
        "start_time": _parse_timestamp_from_name(run_dir.name),
        "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0),
        "duration_seconds": _compute_duration(run_dir, atomic, status, run_meta),
        "last_activity": last_activity,
        "model": cfg_summary["model"],
        "provider": cfg_summary["provider"],
        "thinking": cfg_summary["thinking"],
        "review_profile": cfg_summary["review_profile"],
        "max_cycles": cfg_summary["max_review_cycles"],
        "cycles_used": cycles_used,
        "result_count": result_count,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "workflow_mode": workflow_mode,
    }


def inspect_run_detail(workspace_root: str | Path) -> dict[str, Any]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        raise HTTPException(404, "run workspace not found")
    runtime = _runtime_dir(run_dir)
    config = _read_json(runtime / "config.json") or _read_json(run_dir / "config.json")
    cfg_summary = _extract_config_summary(config)
    atomic = _find_atomic_work_dir(run_dir)
    run_meta = _read_run_timestamps(run_dir)
    if not atomic:
        status = _normalize_run_status("no_workspace", run_meta)
        return {
            "name": run_dir.name,
            "config": cfg_summary,
            "status": status,
            "start_time": _parse_timestamp_from_name(run_dir.name),
            "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0),
            "duration_seconds": _compute_duration(run_dir, None, status, run_meta),
            "last_activity": "",
            "cycles": [],
            "results": [],
            "removed_results": [],
            "latest_issues": [],
            "manifests": {},
            "atomic_work_path": "",
            "atomic_work_dir": "",
            "current_step": {},
            "step_history": [],
            "cycle_timing": {},
        }

    workflow_result = _read_json(atomic / "_meta" / "workflow_result.json")
    state = _read_json(atomic / "_meta" / "state.json")
    status = _normalize_run_status(workflow_result.get("status", state.get("current_state", "running")), run_meta)
    cycles: list[dict[str, Any]] = []
    new_results_by_cycle = collect_new_results_by_cycle(atomic)
    for summary_file in _sorted_json_files(atomic / "_meta" / "review_summaries"):
        summary = _read_json(summary_file)
        cycle_num = int(summary.get("cycle", 0) or 0)
        metrics = _read_json(atomic / "_meta" / "cycle_metrics" / f"cycle_{cycle_num:03d}.json")
        issue_data = _read_json(atomic / "_meta" / "review_feedback" / f"cycle_{cycle_num:03d}.json")
        global_review = summary.get("global_review", {})
        result_review = summary.get("result_review", {})
        metrics_with_issues = dict(metrics)
        metrics_with_issues["issues"] = issue_data.get("issues", [])
        profile_gate = derive_profile_gate_summary(global_review, metrics_with_issues)
        cycles.append(
            {
                "cycle": cycle_num,
                "timestamp": summary.get("timestamp", ""),
                "outcome": summary.get("outcome", ""),
                "workflow_mode": summary.get("workflow_mode", ""),
                "global_passed": global_review.get("passed", False),
                "global_advisors": global_review.get("advisor_results", []),
                "global_feedback_preview": global_review.get("feedback_preview", ""),
                "global_advisor_total": global_review.get("total_advisor_count", 0),
                "global_advisor_passed": global_review.get("passed_advisor_count", 0),
                "global_aggregate_status": global_review.get("aggregate_status", ""),
                "profile_gate": profile_gate,
                "failed_advisor_id": global_review.get("failed_advisor_id", ""),
                "failed_role_name": global_review.get("failed_role_name", ""),
                "result_total": result_review.get("total", 0),
                "result_passed": result_review.get("passed_count", 0),
                "result_failed": result_review.get("failed_count", 0),
                "passed_files": result_review.get("passed_files", []),
                "failed_files": result_review.get("failed_files", []),
                "scores": metrics.get("scores", {}),
                "global_failure_scope": metrics.get("global_failure_scope", ""),
                "failed_result_count": metrics.get("failed_result_count", result_review.get("failed_count", 0)),
                "current_failed_result_count": metrics.get("current_failed_result_count", result_review.get("failed_count", 0)),
                "historical_removed_result_count": metrics.get("historical_removed_result_count", 0),
                "unreviewed_new_result_count": metrics.get("unreviewed_new_result_count", 0),
                "unreviewed_new_result_files": metrics.get("unreviewed_new_result_files", []),
                "issue_count": metrics.get("issue_count", len(issue_data.get("issues", []))),
                "issue_ids": metrics.get("issue_ids", []),
                "summary_size": metrics.get("summary_size", 0),
                "plateau_status": summary.get("plateau_status", {}),
                "issues": issue_data.get("issues", []),
                "new_result_count": len(new_results_by_cycle.get(cycle_num, [])),
                "new_results": new_results_by_cycle.get(cycle_num, []),
            }
        )
    feedback_files = _sorted_json_files(atomic / "_meta" / "review_feedback")
    latest_issues = _read_json(feedback_files[-1]).get("issues", []) if feedback_files else []
    last_activity = _find_last_activity(atomic, run_dir)
    current_step = _load_current_step_checkpoint(atomic)
    step_history = _collect_step_checkpoints(atomic)
    cycle_timing = _collect_cycle_timing(step_history, current_step)
    return {
        "name": run_dir.name,
        "config": cfg_summary,
        "status": status,
        "start_time": _parse_timestamp_from_name(run_dir.name),
        "start_epoch": int(_find_run_start_epoch(run_dir, run_meta) or 0),
        "duration_seconds": _compute_duration(run_dir, atomic, status, run_meta),
        "last_activity": last_activity,
        "cycles_used": (workflow_result.get("detail") or {}).get("cycles_used", len(cycles)),
        "error": (workflow_result.get("detail") or {}).get("error", workflow_result.get("error")),
        "cycles": cycles,
        "results": _collect_results(atomic),
        "removed_results": _collect_removed_results(atomic),
        "manifests": _load_manifest_summary(atomic),
        "latest_issues": latest_issues,
        "atomic_work_path": str(atomic),
        "atomic_work_dir": str(atomic),
        "current_step": current_step,
        "step_history": step_history,
        "cycle_timing": cycle_timing,
    }


def inspect_cycle_detail(workspace_root: str | Path, cycle: int) -> dict[str, Any]:
    run_dir = Path(workspace_root)
    atomic = _find_atomic_work_dir(run_dir)
    if not atomic:
        raise HTTPException(404, "atomic work dir not found")
    summary = _read_json(atomic / "_meta" / "review_summaries" / f"cycle_{cycle:03d}.json")
    metrics = _read_json(atomic / "_meta" / "cycle_metrics" / f"cycle_{cycle:03d}.json")
    issue_data = _read_json(atomic / "_meta" / "review_feedback" / f"cycle_{cycle:03d}.json")
    global_review_summary = summary.get("global_review", {}) if isinstance(summary.get("global_review"), dict) else {}
    metrics_with_issues = dict(metrics)
    metrics_with_issues["issues"] = issue_data.get("issues", [])
    profile_gate = derive_profile_gate_summary(global_review_summary, metrics_with_issues)
    global_reviews: list[dict[str, Any]] = []
    global_dir = atomic / "reviews" / "global" / f"cycle_{cycle:03d}"
    if global_dir.is_dir():
        for review_file in sorted(global_dir.glob("*.json")):
            data = _read_json(review_file)
            global_reviews.append(
                {
                    "advisor_id": data.get("advisor_instance_id", review_file.stem),
                    "path": _rel_to_atomic(review_file, atomic),
                    "role_name": data.get("role_name", ""),
                    "passed": data.get("passed", False),
                    "verdict": data.get("verdict", ""),
                    "scores": data.get("scores", {}),
                    "confidence": data.get("confidence", 0),
                    "feedback": data.get("feedback", ""),
                    "feedback_detail": data.get("feedback_detail", ""),
                    "schema_valid": data.get("schema_valid"),
                    "parser_mode": data.get("parser_mode", ""),
                    "repair_attempts": data.get("repair_attempts", 0),
                    "issues": data.get("issues", []),
                    "resolved_issue_ids": data.get("resolved_issue_ids", []),
                }
            )
    result_reviews: list[dict[str, Any]] = []
    result_root = atomic / "reviews" / "results"
    if result_root.is_dir():
        for result_dir in sorted(item for item in result_root.iterdir() if item.is_dir()):
            cycle_dir = result_dir / f"cycle_{cycle:03d}"
            if not cycle_dir.is_dir():
                continue
            for review_file in sorted(cycle_dir.glob("*.json")):
                data = _read_json(review_file)
                result_reviews.append(
                    {
                        "result_file": data.get("result_file", f"{result_dir.name}.md"),
                        "path": _rel_to_atomic(review_file, atomic),
                        "advisor_id": data.get("advisor_instance_id", review_file.stem),
                        "passed": data.get("passed", False),
                        "verdict": data.get("verdict", ""),
                        "confidence": data.get("confidence", 0),
                        "feedback": data.get("feedback", ""),
                        "feedback_detail": data.get("feedback_detail", ""),
                        "schema_valid": data.get("schema_valid"),
                        "parser_mode": data.get("parser_mode", ""),
                        "repair_attempts": data.get("repair_attempts", 0),
                    }
                )
    snapshot_path = atomic / "_meta" / "summary_snapshots" / f"cycle_{cycle:03d}_after_summary.md"
    new_results = collect_new_results_by_cycle(atomic).get(cycle, [])
    return {
        "cycle": cycle,
        "global_reviews": global_reviews,
        "result_reviews": result_reviews,
        "summary_snapshot": _read_text(snapshot_path, max_bytes=50_000) if snapshot_path.is_file() else "",
        "metrics": metrics,
        "global_review_summary": global_review_summary,
        "profile_gate": profile_gate,
        "new_result_count": len(new_results),
        "new_results": new_results,
    }


def inspect_sessions(workspace_root: str | Path) -> list[dict[str, Any]]:
    run_dir = Path(workspace_root)
    atomic = _find_atomic_work_dir(run_dir)
    if not atomic:
        return []
    sessions_root = atomic / "sessions"
    if not sessions_root.is_dir():
        return []
    sessions: list[dict[str, Any]] = []
    for jsonl_file in sorted(sessions_root.rglob("*.jsonl")):
        rel_path = str(jsonl_file.relative_to(atomic))
        parts = jsonl_file.relative_to(sessions_root).parts
        worker_id = parts[0] if len(parts) >= 2 else jsonl_file.stem
        stat = jsonl_file.stat()
        parsed_session = _parse_session_jsonl_file(jsonl_file)
        warnings = list(parsed_session.get("warnings") or [])
        event_count = len(parsed_session.get("events") or [])
        line_count = int(parsed_session.get("line_count") or 0)
        runtime_meta = _session_runtime_metadata(jsonl_file.parent)
        session_meta = parsed_session.get("session_meta") if isinstance(parsed_session.get("session_meta"), dict) else {}
        model = _first_string(runtime_meta.get("model"), session_meta.get("model"))
        raw_model = _first_string(runtime_meta.get("raw_model"), model)
        provider = _first_string(runtime_meta.get("provider"), session_meta.get("provider"))
        thinking = _first_string(runtime_meta.get("thinking"), session_meta.get("thinking"))
        sessions.append(
            {
                "session_id": jsonl_file.stem,
                "format": "jsonl",
                "worker_id": worker_id,
                "jsonl_path": rel_path,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "event_count": event_count,
                "line_count": line_count,
                "warnings": warnings,
                "display_name": _session_display_name(worker_id, jsonl_file.stem, rel_path),
                "stage_group": worker_id or "root",
                "role_name": worker_id,
                "model": model,
                "raw_model": raw_model,
                "provider": provider,
                "thinking": thinking,
                "calls": [],
            }
        )
    for session_dir in sorted(item for item in sessions_root.iterdir() if item.is_dir()):
        calls_dir = session_dir / "calls"
        if not calls_dir.is_dir():
            continue
        calls: list[dict[str, Any]] = []
        for call_dir in sorted(item for item in calls_dir.iterdir() if item.is_dir()):
            request = _read_json(call_dir / "request.json")
            response = _read_json(call_dir / "response.json")
            files: dict[str, str] = {}
            for key, filename in {
                "request": "request.json",
                "response": "response.json",
                "user_prompt": "user_prompt.md",
                "system_prompt": "system_prompt.md",
                "stdout": "stdout.txt",
                "stderr": "stderr.txt",
                "stdout_events": "stdout_events.json",
            }.items():
                file_path = call_dir / filename
                if file_path.is_file():
                    files[key] = _rel_to_atomic(file_path, atomic)
            calls.append(
                {
                    "call_id": call_dir.name,
                    "turn": request.get("turn_number", 0),
                    "agent_id": request.get("agent_id", ""),
                    "is_continuation": request.get("is_continuation", False),
                    "user_prompt_len": request.get("user_prompt_len", 0),
                    "sys_prompt_len": request.get("sys_prompt_len", 0),
                    "status": response.get("status", ""),
                    "duration_ms": response.get("duration_ms"),
                    "output_len": response.get("output_len", 0),
                    "error": response.get("error"),
                    "error_code": response.get("error_code", ""),
                    "mode": response.get("mode", ""),
                    "attempts": response.get("attempts", []),
                    "api_failures": response.get("api_failures", 0),
                    "pi_failures": response.get("pi_failures", 0),
                    "timeout_failures": response.get("timeout_failures", 0),
                    "token_usage": response.get("token_usage", {}),
                    "timeout_max_retries": response.get("timeout_max_retries", 0),
                    "timeout_retry_fresh_session": response.get("timeout_retry_fresh_session", False),
                    "output_total_bytes": response.get("output_total_bytes", response.get("stdout_total_bytes", 0)),
                    "stderr_total_bytes": response.get("stderr_total_bytes", 0),
                    "stdout_truncated": response.get("stdout_truncated", False),
                    "stderr_truncated": response.get("stderr_truncated", False),
                    "stdout_soft_limit_exceeded": response.get("stdout_soft_limit_exceeded", False),
                    "trace_limits": response.get("trace_limits", {}),
                    "events_truncated_count": response.get("events_truncated_count", 0),
                    "messages_truncated_count": response.get("messages_truncated_count", 0),
                    "non_json_truncated_count": response.get("non_json_truncated_count", 0),
                    "effective_session_id": response.get("effective_session_id", ""),
                    "effective_session_dir": response.get("effective_session_dir", ""),
                    "event_total_count": response.get("event_total_count", 0),
                    "internal_turn_count": response.get("internal_turn_count", 0),
                    "files": files,
                }
            )
        if calls:
            sessions.append({"session_id": session_dir.name, "format": "calls", "calls": calls})
    return sessions


def inspect_files(workspace_root: str | Path, limit: int = 1200) -> list[dict[str, Any]]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        raise HTTPException(404, "run workspace not found")
    atomic = _find_atomic_work_dir(run_dir)
    entries: list[dict[str, Any]] = []

    def add(path: Path, base: Path, category: str) -> None:
        if not path.is_file() or len(entries) >= limit:
            return
        stat = path.stat()
        entries.append(
            {
                "category": category,
                "path": str(path.relative_to(base)),
                "name": path.name,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "type": _file_type(path),
            }
        )

    def add_glob(base_dir: Path, pattern: str, base: Path, category: str) -> None:
        if not base_dir.is_dir():
            return
        for path in sorted(base_dir.glob(pattern)):
            add(path, base, category)
            if len(entries) >= limit:
                return

    runtime = _runtime_dir(run_dir)
    add(runtime / "config.json", run_dir, "Run")
    add(runtime / "run.log", run_dir, "Run")
    add(run_dir / "config.json", run_dir, "Run Root")
    add(run_dir / "run.log", run_dir, "Run Root")
    add(runtime / "execution_meta.json", run_dir, "Run")
    add(run_dir / "execution_meta.json", run_dir, "Run Root")
    add_glob(run_dir / "input", "**/*.md", run_dir, "Input")
    add_glob(runtime / "input", "**/*.md", run_dir, "Run / Input")
    add_glob(run_dir / "trigger_inputs", "**/*.md", run_dir, "Input")
    if atomic:
        add(atomic / "summary.md", atomic, "Outputs")
        add(atomic / "final_output" / "summary.md", atomic, "Outputs")
        add_glob(atomic / "results", "*.md", atomic, "Outputs / Results")
        add_glob(atomic / "final_output" / "results", "*.md", atomic, "Outputs / Results")
        add_glob(atomic / "supporting_docs", "*.md", atomic, "Outputs / Supporting Docs")
        add(atomic / "_meta" / "state.json", atomic, "Meta")
        add(atomic / "_meta" / "workflow_result.json", atomic, "Meta")
        add(atomic / "_meta" / "abnormal_exit.json", atomic, "Meta")
        add(atomic / "_meta" / "result_relations_manifest.json", atomic, "Meta / Result Manifests")
        add(atomic / "_meta" / "results_manifest.json", atomic, "Meta / Result Manifests")
        add_glob(atomic / "_meta" / "reflections", "*.json", atomic, "Meta / Reflections")
        add_glob(atomic / "_meta" / "review_summaries", "*.json", atomic, "Meta / Review Summaries")
        add_glob(atomic / "_meta" / "cycle_metrics", "*.json", atomic, "Meta / Cycle Metrics")
        add_glob(atomic / "_meta" / "review_feedback", "*.json", atomic, "Meta / Review Feedback")
        add_glob(atomic / "_meta" / "summary_snapshots", "*.md", atomic, "Meta / Summary Snapshots")
        add_glob(atomic / "reviews" / "global", "cycle_*/*.json", atomic, "Reviews / Global")
        add_glob(atomic / "reviews" / "results", "result_*/cycle_*/*.json", atomic, "Reviews / Results")
        add_glob(atomic / "sessions", "*/*.jsonl", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/*.json", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/*.md", atomic, "Sessions")
        add_glob(atomic / "sessions", "*/calls/*/*.txt", atomic, "Sessions")
    return entries


def _resolve_run_file(workspace_root: str | Path, path: str) -> tuple[Path, Path]:
    run_dir = Path(workspace_root)
    if not run_dir.is_dir():
        raise HTTPException(404, "run workspace not found")
    atomic = _find_atomic_work_dir(run_dir)
    candidates = [run_dir / path]
    if atomic:
        candidates.append(atomic / path)
    target: Path | None = None
    root = run_dir.resolve()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file() and _is_within(resolved, root):
            target = resolved
            break
    if target is None:
        raise HTTPException(404, f"file not found: {path}")
    return run_dir, target


def inspect_file(workspace_root: str | Path, path: str) -> dict[str, Any]:
    run_dir, target = _resolve_run_file(workspace_root, path)
    return {
        "path": str(target.relative_to(run_dir)),
        "type": _file_type(target),
        "content": _read_text(target, max_bytes=500_000),
    }


def inspect_session_file(workspace_root: str | Path, path: str) -> dict[str, Any]:
    run_dir, target = _resolve_run_file(workspace_root, path)
    if _file_type(target) != "jsonl":
        raise HTTPException(400, "not a .jsonl file")
    content = _read_text(target)
    parsed = _parse_session_jsonl_lines(content.splitlines())
    return {
        "path": str(target.relative_to(run_dir)),
        "content": content,
        "session_meta": parsed["session_meta"],
        "events": parsed["events"],
        "warnings": parsed["warnings"],
        "line_count": parsed["line_count"],
    }


def inspect_log(workspace_root: str | Path, lines: int = 300) -> dict[str, str]:
    run_dir = Path(workspace_root)
    runtime = _runtime_dir(run_dir)
    log_path = runtime / "run.log"
    if not log_path.is_file():
        log_path = run_dir / "run.log"
    if not log_path.is_file():
        return {"content": "(no log file)"}
    return {"content": _tail_lines(log_path, lines)}
