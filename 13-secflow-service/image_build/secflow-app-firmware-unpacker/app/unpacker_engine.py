"""Firmware unpacking execution engine used by the task manager."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from app.logging_utils import log_event
from app.preprocess import detect_format, run_preprocess
from app.skill_store import DEFAULT_PROMOTION_THRESHOLD, save_candidate_skill
from app.subprocess_utils import StreamingLineSink, run_streaming_process
from app.tool_dispatcher import dispatch_tool_by_magic, ensure_dispatcher_environment
from app.tool_store import compute_family_id
from app.unpacker_engine_config import (
    AUTHOR_AGENT_DEF,
    AUTHOR_PROMPT_TMPL,
    CLEAN_AGENT_DEF,
    CLEAN_PROMPT_TMPL,
    DISPATCHER_DIR,
    DISPATCHER_RULES_PATH,
    EXEC_AGENT_DEF,
    EXEC_FIRST_TMPL,
    EXEC_RETRY_TMPL,
    LOG_OUTPUT_DIR,
    PI_AGENT_DIR_ENV,
    ROLE_CONFIG_FILE_KEYS,
    ROLE_MODEL_CONFIG_KEYS,
    TOOLS_ACTIVE_DIR,
    TOOLS_DIR,
    TOOLS_ROOT_DIR,
    TOOLS_STORE_DIR,
    VAL_AGENT_DEF,
    VAL_LLM_PROMPT_TMPL,
    VAL_TOOL_PROMPT_TMPL,
    VAL_PROMPT_TMPL,
    build_settings_json as _build_settings_json,
    get_max_retries as _get_max_retries,
    get_reuse_agent_between_rounds as _get_reuse_agent_between_rounds,
    load_agent_def,
    preview_text as _preview_text,
    render_prompt,
    render_template,
    resolve_provider_model as _resolve_provider_model,
    resolve_provider_selector as _resolve_provider_selector,
    slug_session_part as _slug_session_part,
)
from app.unpacker_engine_logs import (
    append_stage_log as _append_stage_log,
    append_stream_delta as _append_stream_delta,
    copy_optional_text_file as _copy_optional_text_file,
    get_log_dir,
    get_round_dir as _get_round_dir,
    is_review_success as _is_review_success,
    kill_process_tree as _kill_process_tree,
    read_json_file as _read_json_file,
    round_dir_name as _round_dir_name,
    save_agent_log as _save_agent_log,
    write_round_result as _write_round_result,
    write_json_log as _write_json_log,
    write_token_summary as _write_token_summary,
)
from app.unpacker_engine_pi import PiRpcClient
from app.unpacker_engine_pi import PiPromptResult
from app.unpacker_engine_session import build_session_artifacts, update_session_index


log = logging.getLogger("unpacker.engine")
SKILL_GENERATION_CONTEXT_FILENAME = "stage5_skill_generation_context.json"
RECURSIVE_EXPAND_MAX_ROUNDS = 2
RECURSIVE_7Z_MAX_BYTES = 64 * 1024 * 1024
RECURSIVE_ARCHIVE_FORMATS = {
    "tar",
    "zip",
    "gzip",
    "bzip2",
    "xz",
    "zstd",
    "lzop",
    "lzma",
    "7zip",
    "cab",
}
REDUNDANT_ZLIB_BASENAME_RE = re.compile(r"^[0-9A-Fa-f]{6,}\.zlib$")
REDUNDANT_ZLIB_MIN_BYTES = 1024 * 1024
REDUNDANT_ARTIFACT_SOURCE_RE = re.compile(r"^[0-9A-Fa-f]{6,}\.(gz|7z|lzma|zlib)$")
PROGRESS_KEEPALIVE_INTERVAL_SECONDS = 8.0


def _safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def _eligible_recursive_format(path: Path) -> str | None:
    info = detect_format(str(path))
    fmt = str(info.get("fmt") or "").strip().lower()
    if fmt in RECURSIVE_ARCHIVE_FORMATS:
        return fmt
    return None


def _decompressed_output_name(path: Path, fmt: str) -> str:
    name = path.name
    if fmt == "gzip" and name.endswith(".gz"):
        return name[:-3] or f"{name}.raw"
    if fmt == "bzip2" and name.endswith(".bz2"):
        return name[:-4] or f"{name}.raw"
    if fmt == "xz" and name.endswith(".xz"):
        return name[:-3] or f"{name}.raw"
    if fmt == "zstd" and (name.endswith(".zst") or name.endswith(".zstd")):
        return name.rsplit(".", 1)[0] or f"{name}.raw"
    if fmt == "lzop" and (name.endswith(".lzo") or name.endswith(".lzop")):
        return name.rsplit(".", 1)[0] or f"{name}.raw"
    if fmt == "lzma" and name.endswith(".lzma"):
        return name[:-5] or f"{name}.raw"
    return f"{name}.out"


def _count_tree_entries(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return 1
    total = 0
    for _root, dirs, files in os.walk(path, followlinks=False):
        total += len(dirs) + len(files)
    return total


def _cleanup_known_artifact_sources(output_path: str) -> dict[str, Any]:
    output_root = Path(output_path)
    deleted_files: list[str] = []
    deleted_bytes = 0
    failed_files: list[dict[str, str]] = []
    if not output_root.exists():
        return {
            "deleted_count": 0,
            "deleted_bytes": 0,
            "deleted_files": deleted_files,
            "failed_files": failed_files,
        }
    for path in output_root.rglob("*"):
        if not path.is_file():
            continue
        if not REDUNDANT_ARTIFACT_SOURCE_RE.match(path.name):
            continue
        try:
            size_bytes = int(path.stat().st_size)
        except Exception as exc:
            failed_files.append({"path": str(path), "error": str(exc)})
            continue
        if path.suffix.lower() == ".zlib" and size_bytes < REDUNDANT_ZLIB_MIN_BYTES:
            continue
        try:
            path.unlink()
            deleted_files.append(str(path))
            deleted_bytes += size_bytes
        except Exception as exc:
            failed_files.append({"path": str(path), "error": str(exc)})
    return {
        "deleted_count": len(deleted_files),
        "deleted_bytes": deleted_bytes,
        "deleted_files": deleted_files,
        "failed_files": failed_files,
    }


class _ProgressKeepalive:
    def __init__(
        self,
        *,
        stage: str,
        activity_callback: Optional[Callable[[str], None]] = None,
        interval_seconds: float = PROGRESS_KEEPALIVE_INTERVAL_SECONDS,
    ) -> None:
        self._stage = stage
        self._activity_callback = activity_callback
        self._interval_seconds = max(float(interval_seconds), 1.0)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "_ProgressKeepalive":
        if self._activity_callback is None:
            return self

        def _run() -> None:
            while not self._stop_event.wait(self._interval_seconds):
                try:
                    self._activity_callback(self._stage)
                except Exception:
                    pass

        self._thread = threading.Thread(
            target=_run,
            name=f"unpacker-keepalive-{self._stage}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=0.2)


def _run_recursive_expand_command(
    command: list[str],
    *,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
    activity_stage: str = "recursive_expand",
) -> subprocess.CompletedProcess[str]:
    with _ProgressKeepalive(stage=activity_stage, activity_callback=activity_callback):
        result = run_streaming_process(
            command,
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
            kill_process_tree=_kill_process_tree,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    return subprocess.CompletedProcess(command, result.returncode, result.stdout, result.stderr)


def _expand_one_recursive_file(
    source_path: Path,
    fmt: str,
    *,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    if fmt == "7zip":
        try:
            source_size = source_path.stat().st_size
        except Exception:
            source_size = 0
        if source_size >= RECURSIVE_7Z_MAX_BYTES:
            return {
                "handler": "7z x (skipped large candidate)",
                "success": False,
                "output_dir": None,
                "error": f"skip large 7z candidate >= {RECURSIVE_7Z_MAX_BYTES} bytes",
                "skipped": True,
            }
    output_dir = source_path.parent / f"{source_path.name}.extracted"
    output_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "tar":
        proc = _run_recursive_expand_command(
            ["tar", "-xf", str(source_path), "-C", str(output_dir)],
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
            activity_callback=activity_callback,
        )
        return {"handler": "tar", "success": proc.returncode == 0, "output_dir": str(output_dir), "error": proc.stderr.strip() or None}
    if fmt == "zip":
        proc = _run_recursive_expand_command(
            ["7z", "x", str(source_path), f"-o{output_dir}", "-y"],
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
            activity_callback=activity_callback,
        )
        return {"handler": "7z x", "success": proc.returncode == 0, "output_dir": str(output_dir), "error": proc.stderr.strip() or None}
    if fmt in {"gzip", "bzip2", "xz", "zstd", "lzop", "lzma"}:
        target_file = output_dir / _decompressed_output_name(source_path, fmt)
        command_map = {
            "gzip": ["gzip", "-dc", str(source_path)],
            "bzip2": ["bzip2", "-dc", str(source_path)],
            "xz": ["xz", "-dc", str(source_path)],
            "zstd": ["zstd", "-dc", str(source_path)],
            "lzop": ["lzop", "-dc", str(source_path)],
            "lzma": ["lzma", "-dc", str(source_path)],
        }
        with target_file.open("wb") as handle:
            with _ProgressKeepalive(stage="recursive_expand", activity_callback=activity_callback):
                result = run_streaming_process(
                    command_map[fmt],
                    cancel_check=cancel_check,
                    register_cancel_hook=register_cancel_hook,
                    kill_process_tree=_kill_process_tree,
                    stdout_file=handle,
                    stderr=subprocess.PIPE,
                    text=False,
                )
        stderr_text = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        trailing_garbage_ignored = fmt == "gzip" and "trailing garbage ignored" in stderr_text.lower()
        success = result.returncode == 0 or (trailing_garbage_ignored and target_file.exists() and target_file.stat().st_size > 0)
        if not success and target_file.exists():
            target_file.unlink(missing_ok=True)
        return {
            "handler": f"{fmt} -dc",
            "success": success,
            "output_dir": str(output_dir),
            "error": stderr_text or None,
        }
    if fmt in {"7zip", "cab"}:
        proc = _run_recursive_expand_command(
            ["7z", "x", str(source_path), f"-o{output_dir}", "-y"],
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
            activity_callback=activity_callback,
        )
        return {"handler": "7z x", "success": proc.returncode == 0, "output_dir": str(output_dir), "error": proc.stderr.strip() or None}
    return {"handler": fmt, "success": False, "output_dir": str(output_dir), "error": f"unsupported recursive format: {fmt}"}


def _run_recursive_expand(
    output_path: str,
    round_dir: Path,
    *,
    max_rounds: int = RECURSIVE_EXPAND_MAX_ROUNDS,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    event_callback: Optional[Callable[..., None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    output_root = Path(output_path)
    round_dir.mkdir(parents=True, exist_ok=True)
    processed: set[str] = set()
    failed_blacklist: set[str] = set()
    failed_items: list[dict[str, Any]] = []
    completed_rounds = 0
    stopped_reason = "no_new_files"
    attempted_items = 0
    successful_items = 0
    deleted_source_items = 0
    failed_items_count = 0
    skipped_blacklist_items = 0
    total_new_paths = 0
    pre_cleanup_result = _cleanup_known_artifact_sources(output_path)
    _append_stage_log(
        round_dir,
        "recursive_expand.log",
        "recursive expand pre-cleanup completed",
        deleted_count=pre_cleanup_result.get("deleted_count", 0),
        deleted_bytes=pre_cleanup_result.get("deleted_bytes", 0),
        failed_count=len(pre_cleanup_result.get("failed_files", [])),
    )
    if event_callback:
        event_callback(
            "recursive_expand_started",
            "开始递归展开确定性可识别文件",
            stage_key="recursive_expand",
            status="running",
            detail={
                "max_rounds": max_rounds,
                "pre_cleanup_deleted_count": pre_cleanup_result.get("deleted_count", 0),
            },
        )
    for round_index in range(1, max_rounds + 1):
        if cancel_check and cancel_check():
            raise RuntimeError("__CANCELLED__")
        if activity_callback is not None:
            activity_callback("recursive_expand")
        before_snapshot: set[str] = set()
        for root, dirs, files in os.walk(output_root, followlinks=False):
            root_path = Path(root)
            for directory in dirs:
                before_snapshot.add(str(root_path / directory))
            for filename in files:
                before_snapshot.add(str(root_path / filename))
        expanded_this_round = 0
        for root, dirs, files in os.walk(output_root, followlinks=False):
            dirs[:] = sorted([name for name in dirs if not (Path(root) / name).is_symlink()])
            for filename in sorted(files):
                candidate = Path(root) / filename
                if candidate.is_symlink():
                    continue
                resolved = str(candidate.resolve())
                if resolved in processed:
                    continue
                if resolved in failed_blacklist:
                    skipped_blacklist_items += 1
                    _append_stage_log(
                        round_dir,
                        "recursive_expand.log",
                        "recursive expand item skipped",
                        round=round_index,
                        source_path=str(candidate),
                        resolved_path=resolved,
                        reason="failed_blacklist",
                    )
                    continue
                fmt = _eligible_recursive_format(candidate)
                if not fmt:
                    continue
                processed.add(resolved)
                attempted_items += 1
                result = _expand_one_recursive_file(
                    candidate,
                    fmt,
                    cancel_check=cancel_check,
                    register_cancel_hook=register_cancel_hook,
                    activity_callback=activity_callback,
                )
                new_paths_count = _count_tree_entries(Path(str(result.get("output_dir") or ""))) if result.get("success") else 0
                retained_source = True
                if result.get("success") and new_paths_count > 0:
                    successful_items += 1
                    total_new_paths += int(new_paths_count)
                    try:
                        candidate.unlink()
                        retained_source = False
                        deleted_source_items += 1
                    except Exception as exc:
                        result["error"] = (
                            f"{result.get('error')}\nsource cleanup failed: {exc}".strip()
                            if result.get("error")
                            else f"source cleanup failed: {exc}"
                        )
                item = {
                    "round": round_index,
                    "source_path": str(candidate),
                    "detected_format": fmt,
                    "handler": result.get("handler"),
                    "attempted": True,
                    "success": bool(result.get("success")),
                    "output_dir": result.get("output_dir"),
                    "new_paths_count": int(new_paths_count),
                    "retained_source": retained_source,
                    "error": result.get("error"),
                }
                if not result.get("success"):
                    failed_items_count += 1
                    failed_blacklist.add(resolved)
                    failed_items.append(
                        {
                            "round": round_index,
                            "source_path": str(candidate),
                            "resolved_path": resolved,
                            "detected_format": fmt,
                            "handler": result.get("handler"),
                            "error": result.get("error"),
                        }
                    )
                _append_stage_log(round_dir, "recursive_expand.log", "recursive expand item processed", **item)
                if result.get("success") and new_paths_count > 0:
                    expanded_this_round += 1
        completed_rounds = round_index
        after_snapshot: set[str] = set()
        for root, dirs, files in os.walk(output_root, followlinks=False):
            root_path = Path(root)
            for directory in dirs:
                after_snapshot.add(str(root_path / directory))
            for filename in files:
                after_snapshot.add(str(root_path / filename))
        new_paths_total = len(after_snapshot - before_snapshot)
        _append_stage_log(
            round_dir,
            "recursive_expand.log",
            "recursive expand round completed",
            round=round_index,
            expanded_items=expanded_this_round,
            new_paths_total=new_paths_total,
        )
        if expanded_this_round <= 0 or new_paths_total <= 0:
            stopped_reason = "no_new_files"
            break
        if round_index == max_rounds:
            stopped_reason = "round_limit_reached"
    manifest = {
        "version": 1,
        "max_rounds": max_rounds,
        "completed_rounds": completed_rounds,
        "stopped_reason": stopped_reason,
        "stats": {
            "attempted_items": attempted_items,
            "successful_items": successful_items,
            "failed_items": failed_items_count,
            "skipped_blacklist_items": skipped_blacklist_items,
            "deleted_source_items": deleted_source_items,
            "total_new_paths": total_new_paths,
        },
        "pre_cleanup": pre_cleanup_result,
        "failed_blacklist": sorted(failed_blacklist),
        "failed_items": failed_items,
    }
    _write_json_log(round_dir, "recursive_expand_manifest.json", manifest)
    if event_callback:
        event_callback(
            "recursive_expand_completed",
            "递归展开阶段已完成",
            stage_key="recursive_expand",
            status="success",
            detail={
                "completed_rounds": completed_rounds,
                "stopped_reason": stopped_reason,
                "processed_items": attempted_items,
            },
        )
    return manifest


def _reviewer_session_name(suffix: str) -> tuple[str, int | None]:
    normalized = str(suffix or "").strip().replace("_", "-")
    import re

    match = re.fullmatch(r"round-(\d+)", normalized)
    if match:
        return normalized, int(match.group(1))
    return normalized or "default", None


def _write_system_prompt(content: str, prefix: str) -> str:
    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=prefix,
        suffix=".md",
        delete=False,
    )
    temp_file.write(content)
    temp_file.flush()
    temp_file.close()
    return temp_file.name


def _copy_round_report(output_path: str, round_dir: Path | None, filename: str) -> str | None:
    if round_dir is None:
        return None
    source = Path(output_path) / filename
    target = round_dir / filename
    return str(target) if _copy_optional_text_file(source, target) else None


def _preview_markdown(path: Path, limit: int = 1000) -> str | None:
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if not text:
        return ""
    return text[:limit]


def _emit_agent_runtime_events(
    event_callback: Optional[Callable[[str, str], None]],
    *,
    result: Any,
    stage: str,
    role: str,
    model: str,
) -> None:
    if event_callback is None:
        return
    payload = {
        "role": role,
        "runtime_dir": str(getattr(result, "runtime_dir", "") or ""),
        "model": model,
        "context_window": int(getattr(result, "context_window", 0) or 0),
    }
    proxy_reserved_tokens = int(getattr(result, "proxy_reserved_tokens", 0) or 0)
    if getattr(result, "compaction_requested", False):
        event_callback("task_context_compaction_requested", "智能体上下文超限，已请求会话压缩", stage_key=stage, detail=dict(payload, proxy_reserved_tokens=proxy_reserved_tokens))
    if getattr(result, "compaction_completed", False):
        event_callback("task_context_compaction_completed", "智能体会话压缩已完成", stage_key=stage, detail=payload)
    if getattr(result, "context_budget_exceeded_preflight", False):
        event_callback("task_context_budget_exceeded_preflight", "智能体请求在发送前已判定超出上下文预算", stage_key=stage, detail=dict(payload, proxy_reserved_tokens=proxy_reserved_tokens, error=str(getattr(result, "error", "") or "")))
    if getattr(result, "context_overflow_retrying", False):
        event_callback("task_context_overflow_retrying", "智能体上下文超限，压缩后正在重试", stage_key=stage, detail=dict(payload, proxy_reserved_tokens=proxy_reserved_tokens))
    if getattr(result, "context_overflow_failed_after_compaction", False):
        event_callback("task_context_overflow_failed_after_compaction", "智能体上下文压缩后仍超出预算，请求已终止", stage_key=stage, detail=dict(payload, proxy_reserved_tokens=proxy_reserved_tokens, error=str(getattr(result, "error", "") or "")))


def _normalize_prompt_result(value: Any) -> PiPromptResult:
    if isinstance(value, PiPromptResult):
        return value
    result = PiPromptResult()
    result.output = str(value or "")
    return result


def _normalize_output_reports(output_path: str) -> None:
    output_root = Path(output_path)
    for legacy_name, canonical_name in (("summary.txt", "summary.md"), ("reason.txt", "reason.md")):
        legacy_path = output_root / legacy_name
        canonical_path = output_root / canonical_name
        if legacy_path.exists():
            if canonical_path.exists():
                legacy_path.unlink(missing_ok=True)
            else:
                shutil.move(str(legacy_path), str(canonical_path))


def extract_firmware_features(
    firmware_path: str,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
) -> dict:
    path = Path(firmware_path)
    info = detect_format(firmware_path)
    features = {
        "filename": path.name,
        "ext": info["ext"],
        "ext2": info["ext2"],
        "fmt": info["fmt"] or "unknown",
        "size": 0,
        "magic_hex": info["magic"].hex()[:8] if info["magic"] else "",
        "binwalk_sigs": [],
    }
    try:
        features["size"] = os.path.getsize(firmware_path)
    except RuntimeError:
        raise
    except Exception:
        pass
    try:
        result = run_streaming_process(
            ["binwalk", "-B", firmware_path],
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
            kill_process_tree=_kill_process_tree,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout = result.stdout or ""
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("-"):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    features["binwalk_sigs"].append(parts[2][:100].lower())
    except Exception:
        pass
    return features


def _run_reviewer(
    task_id: str,
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    round_dir: Path | None,
    suffix: str,
    val_def: dict[str, Any],
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
    reviewer: PiRpcClient | None = None,
    session_artifacts_override: dict[str, Any] | None = None,
    review_kind: str = "llm",
) -> tuple[bool, str, dict[str, Any]]:
    stage_log_dir = _get_round_dir(log_dir, 0)
    _append_stage_log(
        stage_log_dir,
        "stage4_llm_review.log",
        "starting review round",
        suffix=suffix,
        firmware_path=firmware_path,
        output_path=output_path,
    )
    session_name, round_id = _reviewer_session_name(suffix)
    session_artifacts = session_artifacts_override or build_session_artifacts(
        log_dir,
        role="reviewer",
        name=session_name,
        provider_role="reviewer",
        phase="review",
        round_id=round_id,
    )
    validator = reviewer or PiRpcClient(
        system_prompt_file=val_sp,
        model=val_def["model"],
        tools=val_def["tools"],
        provider_role="reviewer",
        llm_binding_snapshot=llm_binding_snapshot,
        session_dir=session_artifacts["session_dir"],
        session_path=session_artifacts["session_path"],
        session_role=session_artifacts["session_role"],
        session_name=session_artifacts["session_name"],
        session_phase=session_artifacts["phase"],
        session_round=session_artifacts["round"],
        session_skill_name=session_artifacts["skill_name"],
        task_id=task_id,
    )
    if bind_cancel_client:
        bind_cancel_client(validator)
    try:
        def _stream_review_event(event: dict[str, Any]) -> None:
            _append_stream_delta(
                stage_log_dir,
                "stage4_llm_review.log",
                f"reviewer:{suffix}",
                event,
            )
            if activity_callback is not None:
                activity_callback("review")

        started_at = datetime.utcnow().isoformat()
        started_monotonic = time.perf_counter()
        prompt_template = VAL_TOOL_PROMPT_TMPL if str(review_kind).strip().lower() == "tool" else VAL_LLM_PROMPT_TMPL
        review_prompt = render_prompt(prompt_template, firmware_path, output_path)
        recursive_manifest_path = round_dir / "recursive_expand_manifest.json" if round_dir is not None else None
        if str(review_kind).strip().lower() == "tool" and recursive_manifest_path is not None and recursive_manifest_path.exists():
            review_prompt += (
                "\n\nRecursive expansion context:\n"
                f"- You must read `{recursive_manifest_path}` before judging completeness for tool-stage review.\n"
            )
        with _ProgressKeepalive(stage="review", activity_callback=activity_callback):
            verify_result = _normalize_prompt_result(validator.prompt(
                review_prompt,
                stream_callback=_stream_review_event,
            ))
        _emit_agent_runtime_events(
            None,
            result=verify_result,
            stage="review",
            role="reviewer",
            model=val_def["model"],
        )
        token_stats = _save_agent_log(validator, log, round_dir, "reviewer")
        completed_at = datetime.utcnow().isoformat()
        return _is_review_success(verify_result.output), verify_result.output, {
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": round(time.perf_counter() - started_monotonic, 3),
            "token_stats": token_stats,
            "session_file": session_artifacts["session_path"].name,
            "session_role": session_artifacts["session_role"],
            "session_name": session_artifacts["session_name"],
            "provider_role": session_artifacts["provider_role"],
        }
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        if reviewer is None:
            validator.close()


def _run_skill_unpack(
    task_id: str,
    skill_meta: dict[str, Any],
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    val_def: dict[str, Any],
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    global_round_dir = _get_round_dir(log_dir, 0)
    _append_stage_log(
        global_round_dir,
        "skill_exec.log",
        "starting skill execution",
        skill=skill_meta.get("path"),
        family_id=skill_meta.get("family_id"),
        skill_version=skill_meta.get("skill_version"),
        firmware_path=firmware_path,
        output_path=output_path,
    )
    skill_sp = _write_system_prompt(str(skill_meta.get("system_prompt") or ""), "firmware-skill-")
    skill_name = _slug_session_part(Path(str(skill_meta.get("path") or "skill")).stem, fallback="skill")
    session_artifacts = build_session_artifacts(
        log_dir,
        role="skill-executor",
        name=skill_name,
        provider_role="skill_executor",
        phase="tool_match",
        skill_name=skill_name,
    )
    executor = PiRpcClient(
        system_prompt_file=skill_sp,
        model=skill_meta.get("model"),
        tools=skill_meta.get("tools"),
        provider_role="skill_executor",
        llm_binding_snapshot=llm_binding_snapshot,
        session_dir=session_artifacts["session_dir"],
        session_path=session_artifacts["session_path"],
        session_role=session_artifacts["session_role"],
        session_name=session_artifacts["session_name"],
        session_phase=session_artifacts["phase"],
        session_round=session_artifacts["round"],
        session_skill_name=session_artifacts["skill_name"],
        task_id=task_id,
    )
    if bind_cancel_client:
        bind_cancel_client(executor)
    try:
        def _stream_skill_event(_event: dict[str, Any]) -> None:
            if activity_callback is not None:
                activity_callback("tool_match")

        with _ProgressKeepalive(stage="tool_match", activity_callback=activity_callback):
            exec_result = _normalize_prompt_result(executor.prompt(
                render_prompt(EXEC_FIRST_TMPL, firmware_path, output_path),
                stream_callback=_stream_skill_event,
            ))
        _save_agent_log(executor, log, global_round_dir, "skill_executor")
        passed, review_result, _review_meta = _run_reviewer(
            task_id,
            firmware_path,
            output_path,
            log_dir,
            global_round_dir,
            "skill",
            val_def,
            val_sp,
            llm_binding_snapshot=llm_binding_snapshot,
            bind_cancel_client=bind_cancel_client,
            activity_callback=activity_callback,
            review_kind="tool",
        )
        result = {
            "success": passed,
            "method": f"skill:{skill_meta.get('filename')}",
            "response": exec_result.output,
            "review": review_result,
        }
        _append_stage_log(
            global_round_dir,
            "skill_exec.log",
            "skill execution completed",
            success=passed,
            response_preview=_preview_text(exec_result.output),
            review_preview=_preview_text(review_result),
        )
        _write_json_log(
            global_round_dir,
            "skill_exec.json",
            {
                "skill": skill_meta.get("path"),
                "family_id": skill_meta.get("family_id"),
                "skill_version": skill_meta.get("skill_version"),
                "success": passed,
                "response_preview": _preview_text(exec_result.output),
                "review_preview": _preview_text(review_result),
            },
        )
        return result
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        executor.close()
        try:
            Path(skill_sp).unlink()
        except FileNotFoundError:
            pass


def _tool_manifest_path(output_path: str) -> Path:
    output_dir = Path(str(output_path or "").strip())
    return output_dir.parent / "input" / "task.json"


def _run_python_tool_unpack(
    firmware_path: str,
    output_path: str,
    tool_meta: dict[str, Any],
    log_dir: Path | None,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    global_round_dir = _get_round_dir(log_dir, 0)
    tool_path = Path(str(tool_meta.get("path") or "")).resolve()
    manifest_path = _tool_manifest_path(output_path)
    run_path = Path(output_path).parent / "run"
    tool_log_path = run_path / "tool.log"
    if not tool_path.is_file():
        raise FileNotFoundError(f"tool not found: {tool_path}")
    if not manifest_path.is_file():
        raise FileNotFoundError(f"task manifest not found: {manifest_path}")

    env = os.environ.copy()
    env["SECFLOW_TOOL_INPUT_PATH"] = firmware_path
    env["SECFLOW_TOOL_OUTPUT_PATH"] = output_path
    env["SECFLOW_TOOL_RUN_PATH"] = str(run_path)
    env["SECFLOW_TOOL_LOG_PATH"] = str(tool_log_path)
    env["SECFLOW_TOOL_LOG_FILE_PATH"] = str(tool_log_path)
    env["SECFLOW_TOOL_MANIFEST_PATH"] = str(manifest_path)

    _append_stage_log(
        global_round_dir,
        "skill_exec.log",
        "starting python tool execution",
        tool=str(tool_path),
        firmware_path=firmware_path,
        output_path=output_path,
        manifest_path=str(manifest_path),
        log_file_path=str(tool_log_path),
    )
    output_lines: list[str] = []
    line_sink = StreamingLineSink(
        lambda text: (
            output_lines.append(text),
            _append_stage_log(global_round_dir, "skill_exec.log", text),
        )
    )
    try:
        with _ProgressKeepalive(stage="tool_match", activity_callback=activity_callback):
            result = run_streaming_process(
                [sys.executable, str(tool_path), str(manifest_path)],
                cancel_check=cancel_check,
                register_cancel_hook=register_cancel_hook,
                kill_process_tree=_kill_process_tree,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                stdout_callback=line_sink.feed,
            )
        line_sink.flush()
        return_code = result.returncode
    finally:
        line_sink.flush()

    result = {
        "success": return_code == 0,
        "method": f"python_tool:{tool_meta.get('filename')}",
        "return_code": return_code,
        "response": "\n".join(output_lines).strip(),
    }
    _write_json_log(
        global_round_dir,
        "skill_exec.json",
        {
            "tool": str(tool_path),
            "success": result["success"],
            "return_code": return_code,
            "response_preview": _preview_text(result["response"]),
        },
    )
    return result


def _run_generic_unpack(
    task_id: str,
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    bind_cancel_client: Callable[[PiRpcClient | None], None],
    should_cancel: Optional[Callable[[], bool]],
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]],
    exec_def: dict[str, Any],
    val_def: dict[str, Any],
    exec_sp: str,
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    event_callback: Optional[Callable[[str, str], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
) -> tuple[bool, int, str]:
    stage_log_dir = _get_round_dir(log_dir, 0)
    _append_stage_log(
        stage_log_dir,
        "stage3_llm_unpack.log",
        "starting generic llm unpack",
        firmware_path=firmware_path,
        output_path=output_path,
    )
    max_retries = _get_max_retries()
    reuse_executor_between_rounds = _get_reuse_agent_between_rounds("executor")
    reuse_reviewer_between_rounds = _get_reuse_agent_between_rounds("reviewer")
    session_artifacts = build_session_artifacts(
        log_dir,
        role="executor",
        name="shared" if reuse_executor_between_rounds else "round-1",
        provider_role="executor",
        phase="llm_unpack",
        round_id=None if reuse_executor_between_rounds else 1,
    )
    executor = PiRpcClient(
        system_prompt_file=exec_sp,
        model=exec_def["model"],
        tools=exec_def["tools"],
        provider_role="executor",
        llm_binding_snapshot=llm_binding_snapshot,
        session_dir=session_artifacts["session_dir"],
        session_path=session_artifacts["session_path"],
        session_role=session_artifacts["session_role"],
        session_name=session_artifacts["session_name"],
        session_phase=session_artifacts["phase"],
        session_round=session_artifacts["round"],
        session_skill_name=session_artifacts["skill_name"],
        task_id=task_id,
    )
    bind_cancel_client(executor)
    passed = False
    final_round = 0
    last_reason = ""
    reviewer: PiRpcClient | None = None
    reviewer_session_artifacts: dict[str, Any] | None = None
    if reuse_reviewer_between_rounds:
        reviewer_session_artifacts = build_session_artifacts(
            log_dir,
            role="reviewer",
            name="shared",
            provider_role="reviewer",
            phase="review",
            round_id=None,
        )
        reviewer = PiRpcClient(
            system_prompt_file=val_sp,
            model=val_def["model"],
            tools=val_def["tools"],
            provider_role="reviewer",
            llm_binding_snapshot=llm_binding_snapshot,
            session_dir=reviewer_session_artifacts["session_dir"],
            session_path=reviewer_session_artifacts["session_path"],
            session_role=reviewer_session_artifacts["session_role"],
            session_name=reviewer_session_artifacts["session_name"],
            session_phase=reviewer_session_artifacts["phase"],
            session_round=reviewer_session_artifacts["round"],
            session_skill_name=reviewer_session_artifacts["skill_name"],
            task_id=task_id,
        )
    try:
        for attempt in range(1, max_retries + 1):
            round_dir = _get_round_dir(log_dir, attempt)
            if should_cancel and should_cancel():
                executor.close()
                bind_cancel_client(None)
                raise RuntimeError("__CANCELLED__")
            final_round = attempt
            if attempt > 1 and not reuse_executor_between_rounds:
                round_artifacts = build_session_artifacts(
                    log_dir,
                    role="executor",
                    name=f"round-{attempt}",
                    provider_role="executor",
                    phase="llm_unpack",
                    round_id=attempt,
                )
                executor.close()
                executor = PiRpcClient(
                    system_prompt_file=exec_sp,
                    model=exec_def["model"],
                    tools=exec_def["tools"],
                    provider_role="executor",
                    llm_binding_snapshot=llm_binding_snapshot,
                    session_dir=round_artifacts["session_dir"],
                    session_path=round_artifacts["session_path"],
                    session_role=round_artifacts["session_role"],
                    session_name=round_artifacts["session_name"],
                    session_phase=round_artifacts["phase"],
                    session_round=round_artifacts["round"],
                    session_skill_name=round_artifacts["skill_name"],
                    task_id=task_id,
                )
                session_artifacts = round_artifacts
                bind_cancel_client(executor)
            exec_msg = render_prompt(
                EXEC_FIRST_TMPL if attempt == 1 else EXEC_RETRY_TMPL,
                firmware_path,
                output_path,
            )
            def _stream_unpack_event(event: dict[str, Any], *, round_id: int = attempt) -> None:
                _append_stream_delta(
                    stage_log_dir,
                    "stage3_llm_unpack.log",
                    f"executor:round_{round_id}",
                    event,
                )
                if activity_callback is not None:
                    activity_callback("llm_unpack")

            executor_started_at = datetime.utcnow().isoformat()
            executor_started_monotonic = time.perf_counter()
            with _ProgressKeepalive(stage="llm_unpack", activity_callback=activity_callback):
                exec_result = _normalize_prompt_result(executor.prompt(
                    exec_msg,
                    stream_callback=_stream_unpack_event,
                ))
            _emit_agent_runtime_events(
                event_callback,
                result=exec_result,
                stage="llm_unpack",
                role="executor",
                model=exec_def["model"],
            )
            executor_token_stats = _save_agent_log(executor, log, round_dir, "executor")
            executor_completed_at = datetime.utcnow().isoformat()
            executor_duration_seconds = round(time.perf_counter() - executor_started_monotonic, 3)
            _append_stage_log(
                stage_log_dir,
                "stage3_llm_unpack.log",
                "executor round completed",
                attempt=attempt,
                response_preview=_preview_text(exec_result.output),
            )
            if event_callback:
                event_callback(
                    "executor_round_completed",
                    f"执行轮次 {attempt} 已完成",
                    stage_key="llm_unpack",
                    status="running",
                    detail={
                        "round": attempt,
                        "response_preview": _preview_text(exec_result.output),
                    },
                )
            if round_dir is not None:
                transcript_path = round_dir / "executor_transcript.log"
                if transcript_path.exists():
                    _append_stage_log(
                        stage_log_dir,
                        "stage3_llm_unpack.log",
                        "executor conversation transcript captured",
                        attempt=attempt,
                        transcript_file=transcript_path.name,
                    )
            _run_recursive_expand(
                output_path,
                round_dir,
                cancel_check=should_cancel,
                register_cancel_hook=register_cancel_hook,
                event_callback=event_callback,
                activity_callback=activity_callback,
            )
            passed, verify_result, reviewer_meta = _run_reviewer(
                task_id,
                firmware_path,
                output_path,
                log_dir,
                round_dir,
                f"round_{attempt}",
                val_def,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                bind_cancel_client=bind_cancel_client,
                activity_callback=activity_callback,
                reviewer=reviewer,
                session_artifacts_override=reviewer_session_artifacts,
                review_kind="llm",
            )
            log_event(
                log,
                logging.INFO,
                "executor attempt completed",
                event="executor_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(exec_result.output),
            )
            log_event(
                log,
                logging.INFO,
                "verifier attempt completed",
                event="verifier_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(verify_result),
            )
            _append_stage_log(
                stage_log_dir,
                "stage4_llm_review.log",
                "review round completed",
                attempt=attempt,
                passed=passed,
                review_preview=_preview_text(verify_result),
            )
            if event_callback:
                event_callback(
                    "review_round_completed",
                    f"评审轮次 {attempt} 已完成",
                    stage_key="review",
                    status="success" if passed else "running",
                    detail={
                        "round": attempt,
                        "passed": passed,
                        "review_preview": _preview_text(verify_result),
                    },
                )
            if round_dir is not None:
                _normalize_output_reports(output_path)
                reviewer_transcript_path = round_dir / "reviewer_transcript.log"
                if reviewer_transcript_path.exists():
                    _append_stage_log(
                        stage_log_dir,
                        "stage4_llm_review.log",
                        "reviewer conversation transcript captured",
                        attempt=attempt,
                        transcript_file=reviewer_transcript_path.name,
                    )
                summary_round_path = _copy_round_report(output_path, round_dir, "summary.md")
                reason_round_path = _copy_round_report(output_path, round_dir, "reason.md")
                executor_tokens = dict(executor_token_stats or {})
                reviewer_tokens = dict(reviewer_meta.get("token_stats") or {})
                round_total_tokens = {
                    field: int(executor_tokens.get(field, 0) or 0) + int(reviewer_tokens.get(field, 0) or 0)
                    for field in ("input", "output", "cacheRead", "cacheWrite", "total")
                }
                warnings: list[str] = []
                if not summary_round_path:
                    warnings.append("summary.md not generated yet")
                if not reason_round_path:
                    warnings.append("reason.md not generated yet")
                _write_round_result(
                    round_dir,
                    task_id=task_id,
                    round_id=attempt,
                    status="review_passed" if passed else "review_failed",
                    created_at=reviewer_meta["completed_at"],
                    started_at=executor_started_at,
                    completed_at=reviewer_meta["completed_at"],
                    duration_seconds=round(
                        executor_duration_seconds + float(reviewer_meta.get("duration_seconds") or 0.0),
                        3,
                    ),
                    output_root=Path(output_path),
                    paths={
                        "run_root": str(log_dir) if log_dir is not None else None,
                        "round_root": str(round_dir),
                        "output_root": output_path,
                        "executor_messages_path": str(round_dir / "executor_messages.json"),
                        "executor_transcript_path": str(round_dir / "executor_transcript.log"),
                        "executor_tokens_path": str(round_dir / "executor_tokens.json"),
                        "reviewer_messages_path": str(round_dir / "reviewer_messages.json"),
                        "reviewer_transcript_path": str(round_dir / "reviewer_transcript.log"),
                        "reviewer_tokens_path": str(round_dir / "reviewer_tokens.json"),
                        "summary_path": summary_round_path,
                        "reason_path": reason_round_path,
                        "output_manifest_path": str(round_dir / "output_manifest.json"),
                    },
                    executor={
                        "provider_role": session_artifacts["provider_role"],
                        "session_role": session_artifacts["session_role"],
                        "session_name": session_artifacts["session_name"],
                        "session_file": session_artifacts["session_path"].name,
                        "prompt_type": "initial" if attempt == 1 else "retry",
                        "response_preview": _preview_text(exec_result.output),
                        "duration_seconds": executor_duration_seconds,
                        "tokens": executor_tokens,
                        "started_at": executor_started_at,
                        "completed_at": executor_completed_at,
                    },
                    reviewer={
                        "provider_role": reviewer_meta["provider_role"],
                        "session_role": reviewer_meta["session_role"],
                        "session_name": reviewer_meta["session_name"],
                        "session_file": reviewer_meta["session_file"],
                        "passed": passed,
                        "review_result": verify_result,
                        "review_preview": _preview_text(verify_result),
                        "duration_seconds": reviewer_meta["duration_seconds"],
                        "tokens": reviewer_tokens,
                        "started_at": reviewer_meta["started_at"],
                        "completed_at": reviewer_meta["completed_at"],
                    },
                    tokens={
                        "executor": executor_tokens,
                        "reviewer": reviewer_tokens,
                        "round_total": round_total_tokens,
                    },
                    artifacts={
                        "summary_present": bool(summary_round_path),
                        "summary_preview": _preview_markdown(Path(summary_round_path)) if summary_round_path else None,
                        "reason_present": bool(reason_round_path),
                        "reason_preview": _preview_markdown(Path(reason_round_path)) if reason_round_path else None,
                        "tokens_summary_present": False,
                        "warnings": warnings,
                    },
                    context={
                        "matched_skill": None,
                        "fallback_to_llm": True,
                        "executor_rounds_planned": max_retries,
                        "firmware_path": firmware_path,
                        "output_path": output_path,
                    },
                )
            if passed:
                break
            last_reason = verify_result
        return passed, final_round, last_reason
    finally:
        bind_cancel_client(None)
        if reviewer is not None:
            reviewer.close()
        executor.close()


def _extract_markdown_document(text: str) -> str:
    import re

    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", raw)
        raw = re.sub(r"\n```$", "", raw)
    return raw.strip()


def _extract_generated_skill_path(text: str) -> Path | None:
    import re

    raw = str(text or "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    if candidate.is_absolute() and candidate.suffix.lower() == ".md":
        return candidate
    match = re.search(r"(/[^\s`\"']+\.md)\b", raw)
    if not match:
        return None
    return Path(match.group(1))


def _resolve_skill_document(raw_output: str) -> tuple[str, Path | None]:
    skill_path = _extract_generated_skill_path(raw_output)
    if skill_path and skill_path.exists():
        return skill_path.read_text(encoding="utf-8"), skill_path
    return _extract_markdown_document(raw_output), None


def _generate_candidate_skill(
    task_id: str,
    firmware_path: str,
    output_path: str,
    features: dict[str, Any],
    review_result: str,
    log_dir: Path | None,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
) -> dict[str, Any] | None:
    _append_stage_log(
        log_dir,
        "stage5_skill_generate.log",
        "starting candidate skill generation",
        firmware_path=firmware_path,
        output_path=output_path,
        family_id=compute_family_id(features),
    )
    try:
        author_def = load_agent_def(AUTHOR_AGENT_DEF)
        summary_path = Path(output_path) / "summary.md"
        summary_text = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
        prompt = render_template(
            AUTHOR_PROMPT_TMPL,
            {
                "$input": firmware_path,
                "$output": output_path,
                "$tools": str(TOOLS_DIR),
                "$summary": summary_text,
                "$features": json.dumps(features, ensure_ascii=False, indent=2),
                "$review_result": review_result,
                "$family_id": compute_family_id(features),
                "$promotion_threshold": str(DEFAULT_PROMOTION_THRESHOLD),
            },
        )
        author_sp = _write_system_prompt(author_def["system_prompt"], "firmware-skill-author-")
        session_artifacts = build_session_artifacts(
            log_dir,
            role="skill-author",
            name="default",
            provider_role="skill_author",
            phase="skill_author",
        )
        author = PiRpcClient(
            system_prompt_file=author_sp,
            model=author_def["model"],
            tools=author_def["tools"],
            provider_role="skill_author",
            llm_binding_snapshot=llm_binding_snapshot,
            session_dir=session_artifacts["session_dir"],
            session_path=session_artifacts["session_path"],
            session_role=session_artifacts["session_role"],
            session_name=session_artifacts["session_name"],
            session_phase=session_artifacts["phase"],
            session_round=session_artifacts["round"],
            session_skill_name=session_artifacts["skill_name"],
            task_id=task_id,
        )
        if bind_cancel_client:
            bind_cancel_client(author)
        try:
            def _stream_skill_author_event(_event: dict[str, Any]) -> None:
                if activity_callback is not None:
                    activity_callback("skill_author")

            with _ProgressKeepalive(stage="skill_author", activity_callback=activity_callback):
                raw_doc = _normalize_prompt_result(author.prompt(
                    prompt,
                    stream_callback=_stream_skill_author_event,
                ))
            _emit_agent_runtime_events(
                event_callback,
                result=raw_doc,
                stage="skill_author",
                role="skill_author",
                model=author_def["model"],
            )
            _save_agent_log(author, log, log_dir, "skill_author")
        finally:
            if bind_cancel_client:
                bind_cancel_client(None)
            author.close()
            try:
                Path(author_sp).unlink()
            except FileNotFoundError:
                pass
        skill_document, authored_skill_path = _resolve_skill_document(raw_doc)
        saved = save_candidate_skill(
            TOOLS_DIR,
            skill_document,
            {"family_id": compute_family_id(features)},
        )
        if authored_skill_path:
            try:
                if authored_skill_path.resolve() != Path(str(saved.get("path") or "")).resolve():
                    authored_skill_path.unlink(missing_ok=True)
            except Exception:
                pass
        _write_json_log(
            log_dir,
            "stage5_skill_generate.json",
            {
                "authored_skill_path": str(authored_skill_path) if authored_skill_path else None,
                "generated_skill_path": saved.get("path"),
                "family_id": saved.get("family_id"),
                "skill_version": saved.get("skill_version"),
                "skill_status": saved.get("skill_status"),
            },
        )
        _append_stage_log(
            log_dir,
            "stage5_skill_generate.log",
            "candidate skill generated",
            authored_skill_path=str(authored_skill_path) if authored_skill_path else None,
            generated_skill_path=saved.get("path"),
            skill_status=saved.get("skill_status"),
            promotion_success_count=saved.get("promotion_success_count"),
        )
        return saved
    except Exception as exc:
        _write_json_log(
            log_dir,
            "stage5_skill_generate.json",
            {"error": str(exc), "family_id": compute_family_id(features)},
        )
        _append_stage_log(
            log_dir,
            "stage5_skill_generate.log",
            "candidate skill generation failed",
            error=str(exc),
        )
        raise


def _run_cleaner(
    task_id: str,
    output_path: str,
    log_dir: Path | None = None,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    event_callback: Optional[Callable[[str, str], None]] = None,
    activity_callback: Optional[Callable[[str], None]] = None,
) -> str:
    session_log_dir = log_dir
    if (
        session_log_dir is not None
        and session_log_dir.name.startswith("round_")
        and session_log_dir.parent is not None
    ):
        session_log_dir = session_log_dir.parent
    _append_stage_log(
        log_dir,
        "cleaner.log",
        "starting cleanup",
        output_path=output_path,
    )
    redundant_zlib_cleanup = _cleanup_known_artifact_sources(output_path)
    _append_stage_log(
        log_dir,
        "cleaner.log",
        "pre-cleaned known artifact sources",
        deleted_count=redundant_zlib_cleanup.get("deleted_count"),
        deleted_bytes=redundant_zlib_cleanup.get("deleted_bytes"),
        failed_count=len(list(redundant_zlib_cleanup.get("failed_files") or [])),
    )
    clean_def = load_agent_def(CLEAN_AGENT_DEF)
    clean_sp = "/tmp/firmware-extract-cleanup.md"
    Path(clean_sp).write_text(clean_def["system_prompt"])
    session_artifacts = build_session_artifacts(
        session_log_dir,
        role="cleaner",
        name="default",
        provider_role="cleaner",
        phase="llm_cleanup",
    )
    cleaner = PiRpcClient(
        system_prompt_file=clean_sp,
        model=clean_def["model"],
        tools=clean_def["tools"],
        provider_role="cleaner",
        llm_binding_snapshot=llm_binding_snapshot,
        session_dir=session_artifacts["session_dir"],
        session_path=session_artifacts["session_path"],
        session_role=session_artifacts["session_role"],
        session_name=session_artifacts["session_name"],
        session_phase=session_artifacts["phase"],
        session_round=session_artifacts["round"],
        session_skill_name=session_artifacts["skill_name"],
        task_id=task_id,
    )
    if bind_cancel_client:
        bind_cancel_client(cleaner)
    result = ""
    try:
        clean_msg = render_prompt(CLEAN_PROMPT_TMPL, output_path, "")
        log_event(log, logging.INFO, "cleanup started", event="cleanup_start")
        if event_callback:
            event_callback(
                "cleanup_started",
                "开始执行清理收尾",
                stage_key="cleanup",
                status="running",
                detail={
                    "output_path": output_path,
                    "redundant_zlib_deleted_count": redundant_zlib_cleanup.get("deleted_count"),
                    "redundant_zlib_deleted_bytes": redundant_zlib_cleanup.get("deleted_bytes"),
                },
            )
        def _stream_cleanup_event(_event: dict[str, Any]) -> None:
            _append_stream_delta(
                log_dir,
                "cleaner.log",
                "cleaner",
                _event,
            )
            if activity_callback is not None:
                activity_callback("cleanup")

        with _ProgressKeepalive(stage="cleanup", activity_callback=activity_callback):
            result = _normalize_prompt_result(cleaner.prompt(clean_msg, stream_callback=_stream_cleanup_event))
        _emit_agent_runtime_events(
            event_callback,
            result=result,
            stage="cleanup",
            role="cleaner",
            model=clean_def["model"],
        )
        log_event(
            log,
            logging.INFO,
            "cleanup completed",
            event="cleanup_complete",
            response_preview=_preview_text(result.output),
        )
        _append_stage_log(
            log_dir,
            "cleaner.log",
            "cleanup completed",
            response_preview=_preview_text(result),
            redundant_zlib_deleted_count=redundant_zlib_cleanup.get("deleted_count"),
            redundant_zlib_deleted_bytes=redundant_zlib_cleanup.get("deleted_bytes"),
        )
        if event_callback:
            event_callback(
                "cleanup_completed",
                "清理收尾已完成",
                stage_key="cleanup",
                status="success",
                detail={
                    "response_preview": _preview_text(result),
                    "redundant_zlib_deleted_count": redundant_zlib_cleanup.get("deleted_count"),
                    "redundant_zlib_deleted_bytes": redundant_zlib_cleanup.get("deleted_bytes"),
                },
            )
        return result
    finally:
        try:
            _save_agent_log(cleaner, log, log_dir, "cleaner")
        except Exception as exc:
            _append_stage_log(
                log_dir,
                "cleaner.log",
                "failed to persist cleaner session artifacts",
                error=str(exc),
            )
        if bind_cancel_client:
            bind_cancel_client(None)
        cleaner.close()


def run_unpack(
    task_id: str,
    firmware_path: str,
    output_path: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    event_callback: Optional[Callable[..., None]] = None,
) -> dict:
    """Execute the firmware unpacking pipeline."""

    active_client: PiRpcClient | None = None

    def _bind_cancel_client(client: PiRpcClient | None) -> None:
        nonlocal active_client
        active_client = client
        if register_cancel_hook is None:
            return
        if client is None:
            register_cancel_hook(None)
            return
        register_cancel_hook(lambda: client.close())

    def _check_cancel(executor: PiRpcClient | None = None) -> None:
        if executor is not None:
            _bind_cancel_client(executor)
        elif executor is None and active_client is None:
            _bind_cancel_client(None)
        if cancel_check and cancel_check():
            target = executor or active_client
            if target is not None:
                target.close()
            _bind_cancel_client(None)
            raise RuntimeError("__CANCELLED__")

    def _report_progress(stage: str) -> None:
        if progress_callback is None:
            return
        try:
            progress_callback(stage)
        except Exception:
            pass

    progress_activity_interval_seconds = 10.0
    last_activity_reported_at: dict[str, float] = {}

    def _report_activity(stage: str, *, force: bool = False) -> None:
        now_monotonic = time.monotonic()
        previous = last_activity_reported_at.get(stage)
        if not force and previous is not None and (now_monotonic - previous) < progress_activity_interval_seconds:
            return
        last_activity_reported_at[stage] = now_monotonic
        _report_progress(stage)

    os.makedirs(output_path, exist_ok=True)
    try:
        log_dir = get_log_dir(output_path)
    except Exception:
        log_dir = None
    global_round_dir = _get_round_dir(log_dir, 0)

    _check_cancel()
    _report_activity("preprocess", force=True)

    try:
        pre_result = run_preprocess(
            firmware_path,
            output_path,
            log_dir=global_round_dir,
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
        )
    except Exception as exc:
        pre_result = {"success": False, "method": None}
        log_event(
            log,
            logging.WARNING,
            "quick pre-process exception",
            event="quick_preprocess_exception",
            error=str(exc),
        )

    if pre_result.get("success"):
        return {
            "status": "success",
            "message": f"Extracted by quick pre-process: {pre_result['method']}",
            "rounds": 0,
        }

    _check_cancel()
    _report_activity("feature_extract", force=True)

    features: dict[str, Any] = {}
    try:
        ensure_dispatcher_environment(
            tools_root_dir=TOOLS_ROOT_DIR,
            tools_store_dir=TOOLS_STORE_DIR,
            tools_active_dir=TOOLS_ACTIVE_DIR,
            dispatcher_dir=DISPATCHER_DIR,
            dispatcher_rules_path=DISPATCHER_RULES_PATH,
        )
        features = extract_firmware_features(
            firmware_path,
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
        )
        features["family_id"] = compute_family_id(features)
        skill_meta, skill_match = dispatch_tool_by_magic(features, DISPATCHER_RULES_PATH)
        skill_score = None
    except RuntimeError as exc:
        if str(exc) == "__CANCELLED__":
            raise
        skill_meta = None
        skill_score = None
        skill_match = {"reasons": []}
        log_event(
            log,
            logging.WARNING,
            "fast mode feature extraction exception",
            event="fast_mode_exception",
            error=str(exc),
        )
    except Exception as exc:
        skill_meta = None
        skill_score = None
        skill_match = {"reasons": []}
        log_event(
            log,
            logging.WARNING,
            "fast mode feature extraction exception",
            event="fast_mode_exception",
            error=str(exc),
        )
    _append_stage_log(
        global_round_dir,
        "skill_match.log",
        "feature extraction and tool match completed",
        features=features,
        matched_tool=skill_meta.get("path") if skill_meta else None,
        matched_tool_score=skill_score,
        reasons=skill_match.get("reasons"),
        dispatch_rule_id=skill_match.get("dispatch_rule_id"),
    )

    _write_json_log(
        global_round_dir,
        "skill_match.json",
        {
            "features": features,
            "matched_tool": skill_meta.get("path") if skill_meta else None,
            "matched_tool_score": skill_score,
            "reasons": skill_match.get("reasons"),
            "dispatch_rule_id": skill_match.get("dispatch_rule_id"),
        },
    )

    _check_cancel()
    _report_activity("skill_match", force=True)

    try:
        exec_def = load_agent_def(EXEC_AGENT_DEF)
        val_def = load_agent_def(VAL_AGENT_DEF)
    except Exception as exc:
        return {
            "status": "failed",
            "message": f"Agent definition load failed: {exc}",
            "rounds": 0,
        }

    exec_sp = "/tmp/firmware-unpacker.md"
    val_sp = "/tmp/firmware-unpack-reviewer.md"
    Path(exec_sp).write_text(exec_def["system_prompt"])
    Path(val_sp).write_text(val_def["system_prompt"])

    passed = False
    final_round = 0
    last_reason = ""
    fallback_to_llm = False
    matched_skill = skill_meta
    promotion_success_count = None

    try:
        if skill_meta:
            if event_callback:
                event_callback(
                    "tool_matched",
                    f"命中工具：{Path(str(skill_meta.get('path') or '')).name}",
                    stage_key="tool_match",
                    status="running",
                    detail={
                        "matched_tool": skill_meta.get("path"),
                        "matched_tool_score": skill_score,
                        "dispatch_rule_id": skill_meta.get("dispatch_rule_id"),
                    },
                )
            _check_cancel()
            _report_activity("tool_match", force=True)
            _append_stage_log(
                global_round_dir,
                "skill_match.log",
                "matched python tool selected for execution",
                tool=skill_meta.get("path"),
            )
            skill_result = _run_python_tool_unpack(
                firmware_path,
                output_path,
                skill_meta,
                log_dir,
                cancel_check=cancel_check,
                register_cancel_hook=register_cancel_hook,
                activity_callback=_report_activity,
            )
            review_result = ""
            if skill_result.get("success"):
                _run_recursive_expand(
                    output_path,
                    global_round_dir,
                    cancel_check=cancel_check,
                    register_cancel_hook=register_cancel_hook,
                    event_callback=event_callback,
                    activity_callback=_report_activity,
                )
                passed, review_result, _review_meta = _run_reviewer(
                    task_id,
                    firmware_path,
                    output_path,
                    log_dir,
                    global_round_dir,
                    "tool",
                    val_def,
                    val_sp,
                    llm_binding_snapshot=llm_binding_snapshot,
                    bind_cancel_client=_bind_cancel_client,
                    activity_callback=_report_activity,
                    review_kind="tool",
                )
                final_round = 0 if passed else final_round
                last_reason = review_result
            else:
                fallback_to_llm = True
                last_reason = str(skill_result.get("response") or "")
            if not passed:
                fallback_to_llm = True
                if not last_reason:
                    last_reason = str(review_result or "")
                if event_callback:
                    event_callback(
                        "tool_fallback_to_llm",
                        "工具执行失败，已回退到 LLM 解包",
                        stage_key="tool_match",
                        status="running",
                        detail={
                            "matched_tool": skill_meta.get("path"),
                            "reason": _preview_text(last_reason, 400),
                        },
                    )
                _append_stage_log(
                    global_round_dir,
                    "stage3_llm_unpack.log",
                    "fallback to llm triggered after python tool execution failure",
                    matched_tool=skill_meta.get("path"),
                    reason_preview=_preview_text(last_reason, 400),
                )
                _write_json_log(
                    global_round_dir,
                    "fallback.json",
                    {
                        "matched_tool": skill_meta.get("path"),
                        "reason": _preview_text(last_reason, 400),
                    },
                )

        if not passed:
            _report_activity("llm_unpack", force=True)
            generic_passed, final_round, last_reason = _run_generic_unpack(
                task_id,
                firmware_path,
                output_path,
                log_dir,
                _bind_cancel_client,
                cancel_check,
                register_cancel_hook,
                exec_def,
                val_def,
                exec_sp,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                event_callback=event_callback,
                activity_callback=_report_activity,
            )
            passed = generic_passed
            if not passed:
                _append_stage_log(
                    global_round_dir,
                    "stage3_llm_unpack.log",
                    "generic llm unpack finished without verified success",
                    rounds=final_round,
                    last_reason_preview=_preview_text(last_reason, 400),
                )

        _check_cancel()
        _report_activity("cleanup", force=True)
        _run_cleaner(
            task_id,
            output_path,
            log_dir=global_round_dir,
            llm_binding_snapshot=llm_binding_snapshot,
            bind_cancel_client=_bind_cancel_client,
            event_callback=event_callback,
            activity_callback=_report_activity,
        )
        _normalize_output_reports(output_path)
        _write_token_summary(
            log_dir,
            cumulative_agent_names={"executor"} if _get_reuse_agent_between_rounds("executor") else set(),
        )

    except RuntimeError as exc:
        if str(exc) == "__CANCELLED__":
            return {
                "status": "cancelled",
                "message": "Task was cancelled",
                "rounds": final_round,
            }
        raise
    finally:
        _bind_cancel_client(None)

    return {
        "status": "success" if passed else "max_retries_reached",
        "message": (
            "Unpacking verified successfully"
            if passed
            else f"Max retries reached. Last reason: {last_reason}"
        ),
        "rounds": final_round,
        "matched_skill": matched_skill.get("path") if matched_skill else None,
        "matched_skill_version": matched_skill.get("tool_version") if matched_skill else None,
        "matched_skill_score": skill_score if matched_skill else None,
        "fallback_to_llm": fallback_to_llm,
        "generated_skill_path": None,
        "generated_skill_status": None,
        "promotion_success_count": None,
    }


__all__ = [
    "AUTHOR_AGENT_DEF",
    "CLEAN_AGENT_DEF",
    "EXEC_AGENT_DEF",
    "LOG_OUTPUT_DIR",
    "PI_AGENT_DIR_ENV",
    "ROLE_CONFIG_FILE_KEYS",
    "ROLE_MODEL_CONFIG_KEYS",
    "build_session_artifacts",
    "TOOLS_DIR",
    "update_session_index",
    "VAL_AGENT_DEF",
    "PiRpcClient",
    "_build_settings_json",
    "_resolve_provider_model",
    "_resolve_provider_selector",
    "extract_firmware_features",
    "get_log_dir",
    "load_agent_def",
    "render_prompt",
    "render_template",
    "run_unpack",
    "SKILL_GENERATION_CONTEXT_FILENAME",
    "_generate_candidate_skill",
]
