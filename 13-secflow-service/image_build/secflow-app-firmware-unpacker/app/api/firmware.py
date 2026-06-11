"""Firmware unpacker API routes."""

from __future__ import annotations

import json
import logging
import mimetypes
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import or_
from sqlalchemy.orm import load_only

from app.api.dependencies import ensure_project_access, get_current_subject
from app.build_info import build_service_meta
from app.exception import ForbiddenError, InternalError, NotFoundError, ValidationError
from app.model import FirmwareEvolutionJob, FirmwareEvolutionRound, ServiceConfig, TaskCleanupScan, TaskStatus, UnpackTask, UnpackTaskEvent, get_db_session
from app.runtime import runtime_snapshot
from app.schemas import (
    ActionResponse,
    BatchDeleteRequest,
    ClusterInfoResponse,
    CleanupScanResponse,
    ConfigBatchUpdateItem,
    ConfigEntryResponse,
    ConfigListResponse,
    ConfigUpdateRequest,
    HealthResponse,
    EvolutionJobListResponse,
    EvolutionJobResponse,
    EvolutionJobSubmitResponse,
    EvolutionRoundResponse,
    EvolutionSessionIndexResponse,
    LlmConfigFileSummaryListResponse,
    LlmProviderSummaryListResponse,
    ReadyResponse,
    TaskEventListResponse,
    TaskListResponse,
    TaskLogResponse,
    TaskMetricsResponse,
    TaskProgressResponse,
    TaskResultResponse,
    TaskResourceUsageResponse,
    TaskResponse,
    TaskSubmitResponse,
    ToolListResponse,
    UnpackRequest,
)
from app.services.pod_metrics import get_pod_resource_usage
from app.services.configcenter import get_configcenter_client
from app.services.observability import generate_metrics_payload, metrics_content_type
from app.metrics_summary import build_ai_summary, build_generic_observability_summary, build_rest_api_summary, parse_prometheus_metrics
from app.services.task_events import list_task_events
from app.services.task_manager import (
    cancel_task,
    cancel_evolution_job,
    confirm_evolution_tool_replacement,
    delete_evolution_job,
    delete_tasks,
    get_evolution_job,
    get_evolution_log,
    get_evolution_sessions,
    list_all_evolution_jobs,
    list_evolution_jobs,
    list_evolution_rounds,
    request_task_result_cache_refresh,
    retry_evolution_job,
    retry_task,
    submit_evolution_job,
    submit_unpack_task,
)
from app.services.worker import get_cluster_snapshot, get_worker_id
from app.services.worker import request_worker_drain
from app.tool_store import list_python_tools
from app.tool_dispatcher import parse_tool_version, read_family_manifest, resolve_active_tool_target
from app.time_utils import ensure_local, now_local
from app.unpacker_engine_config import TOOLS_STORE_DIR, get_max_retries
from app.unpacker_engine import TOOLS_DIR
from app.unpacker_engine_logs import TASK_RESULT_CACHE_FILENAME, TOKEN_FIELDS, list_round_dirs as _list_round_dirs, read_text_tail


router = APIRouter(tags=["Firmware Unpacker"])
logger = logging.getLogger(__name__)
MAX_LOG_RENDER_BYTES = 128 * 1024
RUNTIME_ROOT_PATH = Path("/data/secflow-app-firmware-unpacker")
RUNTIME_FILE_LIST_LIMIT = 2000
RUNTIME_ALLOWED_ROOTS = [
    Path("/data/secflow-app-firmware-unpacker"),
    Path("/data/files"),
]


@router.get("/metrics", include_in_schema=False)
@router.get("/api/app/firmware-unpacker/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(content=generate_metrics_payload(), media_type=metrics_content_type())


@router.get("/api/app/firmware-unpacker/metrics/summary", include_in_schema=False)
async def metrics_summary() -> dict[str, Any]:
    rows = parse_prometheus_metrics(generate_metrics_payload())
    return build_generic_observability_summary(rows, title="固件解包")


@router.get("/api/app/firmware-unpacker/metrics/rest-api-summary", include_in_schema=False)
async def metrics_rest_api_summary() -> dict[str, Any]:
    rows = parse_prometheus_metrics(generate_metrics_payload())
    return build_rest_api_summary(rows)


@router.get("/api/app/firmware-unpacker/metrics/ai-summary", include_in_schema=False)
async def metrics_ai_summary() -> dict[str, Any]:
    rows = parse_prometheus_metrics(generate_metrics_payload())
    return build_ai_summary(rows, coverage_text="固件解包 AI 指标覆盖工具调用、任务执行与 token/cost。")


def _normalize_project_id(project_id: Optional[str]) -> Optional[str]:
    value = str(project_id or "").strip()
    return value or None


def _normalize_runtime_path(path: str) -> str:
    value = str(path or "").strip()
    legacy_prefix = "/data/fileserver/files"
    runtime_prefix = "/data/files"
    if value == legacy_prefix:
        return runtime_prefix
    if value.startswith(f"{legacy_prefix}/"):
        return f"{runtime_prefix}{value[len(legacy_prefix):]}"
    return value


def _ensure_valid_request_payload(request: UnpackRequest) -> None:
    request.firmware_path = _normalize_runtime_path(request.firmware_path)
    if request.output_path is not None:
        request.output_path = _normalize_runtime_path(request.output_path)
    if not request.firmware_path.strip():
        raise ValidationError("firmware_path 不能为空")
    if not os.path.exists(request.firmware_path):
        raise NotFoundError("固件文件", request.firmware_path)
    if not _normalize_project_id(request.project_id):
        raise ValidationError("project_id 不能为空")


def _infer_value_type(value: str) -> str:
    lowered = str(value or "").strip().lower()
    if lowered in ("true", "false", "1", "0", "yes", "no"):
        return "bool"
    if str(value or "").strip().isdigit():
        return "int"
    return "string"


def _normalize_runtime_config_value(key: str, value: str) -> str:
    normalized = str(value or "").strip()
    if key == "agent_run_timeout_seconds":
        try:
            timeout_seconds = int(normalized)
        except Exception as exc:
            raise ValidationError("agent_run_timeout_seconds 必须是整数秒数") from exc
        if timeout_seconds == 0 or timeout_seconds < -1:
            raise ValidationError("agent_run_timeout_seconds 仅支持 -1 或大于 0 的整数")
        return str(timeout_seconds)
    if key == "agent_timeout_max_retries":
        try:
            max_retries = int(normalized)
        except Exception as exc:
            raise ValidationError("agent_timeout_max_retries 必须是整数") from exc
        if max_retries < -1:
            raise ValidationError("agent_timeout_max_retries 仅支持 -1 或大于等于 0 的整数")
        return str(max_retries)
    if key == "agent_timeout_retry_enabled":
        lowered = normalized.lower()
        if lowered not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
            raise ValidationError("agent_timeout_retry_enabled 仅支持 true/false")
        return "true" if lowered in {"1", "true", "yes", "on"} else "false"
    if key == "max_retries_reached_action":
        lowered = normalized.lower()
        if lowered not in {"success", "failed"}:
            raise ValidationError("max_retries_reached_action 仅支持 success 或 failed")
        return lowered
    return normalized


def _resolve_runtime_root(root: Optional[str] = None) -> Path:
    raw = _normalize_runtime_path(str(root or "").strip())
    candidate = Path(raw or str(RUNTIME_ROOT_PATH)).resolve()
    for allowed in RUNTIME_ALLOWED_ROOTS:
        try:
            candidate.relative_to(allowed.resolve())
            return candidate
        except Exception:
            continue
    raise ValidationError("非法 runtime 根目录")


def _list_runtime_root_files(limit: int = RUNTIME_FILE_LIST_LIMIT, root: Optional[str] = None) -> dict:
    root_path = _resolve_runtime_root(root)
    items: list[dict[str, Any]] = []
    if not root_path.exists():
        return {"root": str(root_path), "total": 0, "truncated": False, "items": items}
    normalized_limit = max(1, min(int(limit or RUNTIME_FILE_LIST_LIMIT), 10000))
    for current_root, dirs, files in os.walk(root_path, followlinks=False):
        dirs.sort()
        files.sort()
        root_dir = Path(current_root)
        for name in dirs + files:
            path = root_dir / name
            try:
                stat = path.lstat()
            except Exception:
                continue
            kind = "symlink" if path.is_symlink() else ("dir" if path.is_dir() else "file")
            rel_path = str(path.relative_to(root_path))
            items.append(
                {
                    "path": rel_path,
                    "kind": kind,
                    "size_bytes": int(stat.st_size),
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            )
            if len(items) >= normalized_limit:
                return {
                    "root": str(root_path),
                    "total": len(items),
                    "truncated": True,
                    "items": items,
                }
    return {"root": str(root_path), "total": len(items), "truncated": False, "items": items}


def _resolve_runtime_root_entry(relative_path: str, root: Optional[str] = None) -> Path:
    root_path = _resolve_runtime_root(root)
    normalized = str(relative_path or "").strip().lstrip("/")
    raw_target = root_path / normalized
    target = raw_target.resolve()
    try:
        target.relative_to(root_path)
    except Exception as exc:
        if raw_target.is_symlink():
            raise ValidationError("当前运行时文件为指向 runtime 根目录外部的链接，暂不支持直接预览") from exc
        raise ValidationError("非法 runtime 文件路径") from exc
    if not target.exists():
        raise NotFoundError("运行时文件", normalized or "/")
    return target


def _build_runtime_file_content_response(relative_path: str, max_bytes: int, root: Optional[str] = None) -> Response:
    target = _resolve_runtime_root_entry(relative_path, root)
    if target.is_dir():
        raise ValidationError("目录不支持内容预览")
    if not target.is_file():
        raise ValidationError("仅普通文件支持内容预览")
    total_size = target.stat().st_size
    with target.open("rb") as handle:
        payload = handle.read(max_bytes)
    media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    headers = {
        "X-Runtime-Preview-Path": str(relative_path),
        "X-Runtime-Preview-Truncated": "true" if total_size > len(payload) else "false",
    }
    return Response(content=payload, media_type=media_type, headers=headers)


def _get_task_or_404(task_id: str) -> dict:
    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if not task:
            raise NotFoundError("任务", task_id)
        payload = task.to_dict()
        output_path = str(payload.get("output_path") or "").strip()
        firmware_path = str(payload.get("firmware_path") or "").strip()
        run_path = str(Path(output_path).parent / "run") if output_path.endswith("/output") else ""
        task_root = str(Path(output_path).parent) if output_path else ""
        input_dir = str(Path(task_root) / "input") if task_root else ""
        workspace_root = str(Path(run_path) / "workspace") if run_path else ""
        payload["input_path"] = input_dir or None
        payload["run_path"] = run_path or None
        payload["task_root"] = task_root or None
        payload["run_root"] = run_path or None
        payload["workspace_root"] = workspace_root or None
        payload["input_summary"] = {
            "firmware_path": firmware_path or None,
            "input_dir": input_dir or None,
        }
        payload["output_summary"] = {
            "task_root": task_root or None,
            "output_root": output_path or None,
            "run_root": run_path or None,
            "workspace_root": workspace_root or None,
            "archive_root": payload.get("archive_root"),
            "runtime_root": payload.get("runtime_root"),
        }
        payload["task_metadata"] = {
            "status": payload.get("status"),
            "result_status": payload.get("result_status"),
            "current_stage": payload.get("current_stage"),
            "matched_skill": payload.get("matched_skill"),
            "generated_skill_path": payload.get("generated_skill_path"),
            "generated_skill_status": payload.get("generated_skill_status"),
        }
        latest = (
            db.query(FirmwareEvolutionJob)
            .filter(FirmwareEvolutionJob.task_id == task.id)
            .order_by(FirmwareEvolutionJob.created_at.desc())
            .first()
        )
        if latest is not None:
            payload["latest_evolution_job_id"] = latest.id
            payload["latest_evolution_status"] = latest.status
            payload["latest_evolution_started_at"] = str(latest.started_at.isoformat()) if latest.started_at else None
            payload["latest_evolution_completed_at"] = str(latest.completed_at.isoformat()) if latest.completed_at else None
            payload["latest_evolution_final_skill_path"] = latest.final_skill_path
        return payload
    finally:
        db.close()


def _get_task_resource_usage(task_id: str) -> dict:
    task = _get_task_or_404(task_id)
    owner_id = str(task.get("owner_id") or "").strip() or None
    pod_name = owner_id.split(":", 1)[0] if owner_id else None
    if not pod_name:
        return {
            "task_id": task_id,
            "owner_id": None,
            "available": False,
            "message": "任务当前未绑定运行中的 Worker，无法获取资源使用情况",
            "containers": [],
        }

    metrics = get_pod_resource_usage(pod_name)
    if not metrics:
        return {
            "task_id": task_id,
            "owner_id": owner_id,
            "available": False,
            "pod_name": pod_name,
            "message": "未获取到任务所在 Worker Pod 的资源指标",
            "containers": [],
        }

    return {
        "task_id": task_id,
        "owner_id": owner_id,
        "available": True,
        **metrics,
    }


def _phase_payload(
    key: str,
    label: str,
    status: str,
    detail: Optional[str] = None,
    updated_at: Optional[str] = None,
    current_round: Optional[int] = None,
    total_rounds: Optional[int] = None,
    duration_seconds: Optional[int] = None,
    token_total: Optional[int] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
) -> dict:
    return {
        "key": key,
        "label": label,
        "status": status,
        "detail": detail,
        "updated_at": updated_at,
        "current_round": current_round,
        "total_rounds": total_rounds,
        "duration_seconds": duration_seconds,
        "token_total": token_total,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }


def _read_json_file(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_token_total(path: Path) -> Optional[int]:
    payload = _read_json_file(path)
    if not isinstance(payload, dict):
        return None
    return _normalize_round_tokens(payload)["total"]


def _token_delta(current: dict, previous: Optional[dict] = None) -> dict[str, int]:
    previous = previous or {}
    return {
        field: max(0, _safe_int(current.get(field)) - _safe_int(previous.get(field)))
        for field in TOKEN_FIELDS
    }


def _uses_shared_executor_session(run_root: Path) -> bool:
    payload = _read_json_file(run_root / "sessions" / "index.json")
    items = payload.get("items") if isinstance(payload, dict) else []
    if not isinstance(items, list):
        return False
    return any(
        isinstance(item, dict)
        and str(item.get("role") or "").strip().lower() == "executor"
        and str(item.get("name") or "").strip().lower() == "shared"
        for item in items
    )


def _read_executor_round_token_total(run_root: Path, round_id: int) -> Optional[int]:
    current = _read_json_file(_round_dir(run_root, round_id) / "executor_tokens.json")
    if not isinstance(current, dict):
        return None
    if not _uses_shared_executor_session(run_root) or round_id <= 1:
        return _normalize_round_tokens(current)["total"]
    previous = _read_json_file(_round_dir(run_root, round_id - 1) / "executor_tokens.json")
    return _normalize_round_tokens(_token_delta(current, previous if isinstance(previous, dict) else None))["total"]


def _read_executor_round_token_breakdown(run_root: Path, round_id: int) -> dict[str, int]:
    current_path = _round_dir(run_root, round_id) / "executor_tokens.json"
    if not current_path.exists():
        return {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "total": 0}
    previous = None
    if _uses_shared_executor_session(run_root) and round_id > 1:
        previous = _read_json_file(_round_dir(run_root, round_id - 1) / "executor_tokens.json")
    return _token_breakdown_from_path(
        current_path,
        previous=previous if isinstance(previous, dict) else None,
        shared_executor=_uses_shared_executor_session(run_root) and round_id > 1,
    )


def _read_token_breakdown(path: Path) -> dict[str, int]:
    return _token_breakdown_from_path(path)


def _read_run_token_total(run_root: Path) -> int:
    shared_executor = _uses_shared_executor_session(run_root)
    previous_executor: dict = {}
    total = 0
    for token_file in sorted(run_root.glob("round_*/*_tokens.json")):
        payload = _read_json_file(token_file)
        if not isinstance(payload, dict):
            continue
        if token_file.name == "executor_tokens.json" and shared_executor:
            total += _normalize_round_tokens(_token_delta(payload, previous_executor))["total"]
            previous_executor = payload
        else:
            total += _normalize_round_tokens(payload)["total"]
    return total


def _read_run_token_breakdown(run_root: Path) -> dict[str, int]:
    shared_executor = _uses_shared_executor_session(run_root)
    previous_executor: dict = {}
    totals = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "total": 0}
    for token_file in sorted(run_root.glob("round_*/*_tokens.json")):
        payload = _read_json_file(token_file)
        if not isinstance(payload, dict):
            continue
        normalized = (
            _normalize_round_tokens(_token_delta(payload, previous_executor))
            if token_file.name == "executor_tokens.json" and shared_executor
            else _normalize_round_tokens(payload)
        )
        if token_file.name == "executor_tokens.json" and shared_executor:
            previous_executor = payload
        for key in totals:
            totals[key] += _safe_int(normalized.get(key))
    return totals


def _token_breakdown_from_path(path: Path, *, previous: Optional[dict] = None, shared_executor: bool = False) -> dict[str, int]:
    payload = _read_json_file(path)
    if not isinstance(payload, dict):
        return {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "total": 0}
    normalized = _normalize_round_tokens(_token_delta(payload, previous)) if shared_executor else _normalize_round_tokens(payload)
    return {
        "input": _safe_int(normalized.get("input")),
        "output": _safe_int(normalized.get("output")),
        "cache_read": _safe_int(normalized.get("cache_read")),
        "cache_write": _safe_int(normalized.get("cache_write")),
        "total": _safe_int(normalized.get("total")),
    }


def _mtime_iso(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    try:
        return path.stat().st_mtime_ns and path.stat().st_mtime
    except Exception:
        return None


def _mtime_iso_text(path: Path) -> Optional[str]:
    try:
        timestamp = _mtime_iso(path)
        if not timestamp:
            return None
        from datetime import datetime

        return datetime.fromtimestamp(timestamp).isoformat()
    except Exception:
        return None


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return ensure_local(datetime.fromisoformat(raw))
    except Exception:
        return None


def _log_time_bounds(path: Path) -> tuple[Optional[datetime], Optional[datetime]]:
    if not path.exists() or not path.is_file():
        return None, None
    first: Optional[datetime] = None
    last: Optional[datetime] = None
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if not line.startswith("["):
                    continue
                end = line.find("]")
                if end <= 1:
                    continue
                ts = _parse_iso_datetime(line[1:end])
                if ts is None:
                    continue
                if first is None or ensure_local(ts) < ensure_local(first):
                    first = ts
                if last is None or ensure_local(ts) > ensure_local(last):
                    last = ts
    except Exception:
        return None, None
    return first, last


def _log_duration_seconds(path: Path) -> Optional[int]:
    started_at, completed_at = _log_time_bounds(path)
    if started_at is None or completed_at is None:
        return None
    return max(0, int(round((completed_at - started_at).total_seconds())))


def _derive_run_path(task: dict) -> Path:
    output_path = str(task.get("output_path") or "").strip()
    if not output_path:
        return Path("/tmp")
    output_dir = Path(output_path)
    return output_dir.parent / "run" if output_dir.name == "output" else output_dir.parent / "run"


def _round_dir(run_dir: Path, round_id: int) -> Path:
    return run_dir / f"round_{max(0, int(round_id)):03d}"


def _round_log_path(run_dir: Path, round_id: int, filename: str) -> Path:
    return _round_dir(run_dir, round_id) / filename


def _existing_round_dirs(run_dir: Path) -> list[Path]:
    return _list_round_dirs(run_dir)


def _llm_round_dirs(run_dir: Path) -> list[Path]:
    return [path for path in _existing_round_dirs(run_dir) if path.name != "round_000"]


def _read_final_round_result(run_dir: Path, final_round: int) -> dict | None:
    candidate_dirs: list[Path] = []
    if final_round > 0:
        candidate_dirs.append(_round_dir(run_dir, final_round))
    for path in reversed(_llm_round_dirs(run_dir)):
        if path not in candidate_dirs:
            candidate_dirs.append(path)
    for round_path in candidate_dirs:
        payload = _read_json_file(round_path / "results.json")
        if isinstance(payload, dict):
            return payload
    return None


def _get_task_progress(task_id: str) -> dict:
    task = _get_task_or_404(task_id)
    db = get_db_session()
    try:
        all_task_events = (
            db.query(UnpackTaskEvent)
            .filter(UnpackTaskEvent.task_id == task_id)
            .order_by(UnpackTaskEvent.created_at.asc())
            .all()
        )
    finally:
        db.close()
    run_window_start: Optional[datetime] = None
    for event in reversed(all_task_events):
        event_type = str(getattr(event, "event_type", "") or "").strip().lower()
        if event_type in {"task_started", "task_retry_requested", "task_created"}:
            candidate = ensure_local(getattr(event, "created_at", None))
            if candidate is not None:
                run_window_start = candidate
                break
    if run_window_start is not None:
        task_events = [
            event
            for event in all_task_events
            if (ensure_local(getattr(event, "created_at", None)) or run_window_start) >= run_window_start
        ]
    else:
        task_events = all_task_events
    run_dir = _derive_run_path(task)
    round_zero = _round_dir(run_dir, 0)
    stage1_path = _round_log_path(run_dir, 0, "preprocess.json")
    stage2_path = _round_log_path(run_dir, 0, "skill_match.json")
    stage3_path = _round_log_path(run_dir, 0, "skill_exec.json")
    stage3_llm_unpack_log = _round_log_path(run_dir, 0, "stage3_llm_unpack.log")
    stage4_llm_review_log = _round_log_path(run_dir, 0, "stage4_llm_review.log")
    stage4_path = _round_log_path(run_dir, 0, "fallback.json")
    stage5_path = _round_log_path(run_dir, 0, "stage5_skill_generate.json")
    cleaner_path = _round_log_path(run_dir, 0, "cleaner_messages.json")
    cleaner_log_path = _round_log_path(run_dir, 0, "cleaner.log")
    cleaner_tokens_path = _round_log_path(run_dir, 0, "cleaner_tokens.json")
    cleaner_token_total = _read_token_total(cleaner_tokens_path)
    cleaner_token_breakdown = _read_token_breakdown(cleaner_tokens_path)
    cleaner_log_artifact_path = cleaner_log_path if cleaner_log_path.exists() else cleaner_path
    tool_reviewer_messages = _round_log_path(run_dir, 0, "reviewer_messages.json")
    tool_reviewer_transcript = _round_log_path(run_dir, 0, "reviewer_transcript.log")
    tool_reviewer_tokens_path = _round_log_path(run_dir, 0, "reviewer_tokens.json")
    tool_reviewer_token_total = _read_token_total(tool_reviewer_tokens_path)
    tool_reviewer_token_breakdown = _read_token_breakdown(tool_reviewer_tokens_path)
    round_dirs = _llm_round_dirs(run_dir)
    executor_logs = [path / "executor_messages.json" for path in round_dirs if (path / "executor_messages.json").exists()]
    verifier_logs = [path / "reviewer_messages.json" for path in round_dirs if (path / "reviewer_messages.json").exists()]
    has_tool_review = tool_reviewer_messages.exists() or tool_reviewer_transcript.exists()

    def _cleaner_session_closed() -> bool:
        session_index = _read_json_file(run_dir / "sessions" / "index.json")
        items = session_index.get("items") if isinstance(session_index, dict) else []
        if not isinstance(items, list):
            return False
        for item in items:
            if not isinstance(item, dict):
                continue
            role = str(item.get("role") or "").strip().lower()
            phase = str(item.get("phase") or "").strip().lower()
            status = str(item.get("status") or "").strip().lower()
            if (role == "cleaner" or phase in {"cleanup", "llm_cleanup"}) and status == "closed":
                return True
        return False

    task_status = str(task.get("status") or "").lower()
    task_result = str(task.get("result_status") or "").lower()
    task_current_stage = str(task.get("current_stage") or "").strip().lower()
    result_message = str(task.get("result_message") or "")
    quick_preprocess_success = "quick pre-process" in result_message.lower()
    matched_skill = str(task.get("matched_skill") or "").strip()
    matched_tool = matched_skill
    matched_tool_score = task.get("matched_skill_score")
    fallback_to_llm = bool(task.get("fallback_to_llm"))
    generated_skill_path = str(task.get("generated_skill_path") or "").strip()
    final_round = int(task.get("rounds") or 0)
    total_llm_rounds = max(1, int(get_max_retries() or 1))
    final_round_result = _read_final_round_result(run_dir, final_round)
    final_round_result_status = str((final_round_result or {}).get("status") or "").strip().lower()
    phase_start_times: dict[str, Optional[datetime]] = {
        "preprocess": _parse_iso_datetime(task.get("started_at")),
        "tool_match": None,
        "recursive_expand_tool": None,
        "llm_unpack": None,
        "llm_review": None,
        "llm_review_tool": None,
        "llm_cleanup": None,
    }

    def _remember_phase_start(phase_key: str, created_at: Optional[datetime]) -> None:
        if phase_key not in phase_start_times or created_at is None:
            return
        created_at = ensure_local(created_at)
        current = phase_start_times.get(phase_key)
        if current is None or created_at >= ensure_local(current):
            phase_start_times[phase_key] = created_at

    for event in task_events:
        event_type = str(getattr(event, "event_type", "") or "").strip().lower()
        stage_key = str(getattr(event, "stage_key", "") or "").strip().lower()
        created_at = ensure_local(getattr(event, "created_at", None))
        if event_type == "task_started":
            _remember_phase_start("preprocess", created_at)
        if event_type != "stage_changed":
            continue
        if stage_key == "preprocess":
            _remember_phase_start("preprocess", created_at)
        elif stage_key in {"feature_extract", "skill_match", "tool_match"}:
            _remember_phase_start("tool_match", created_at)
        elif stage_key == "recursive_expand":
            _remember_phase_start("recursive_expand_tool", created_at)
        elif stage_key == "llm_unpack":
            _remember_phase_start("llm_unpack", created_at)
        elif stage_key in {"review", "llm_review"}:
            _remember_phase_start("llm_review", created_at)
            _remember_phase_start("llm_review_tool", created_at)
        elif stage_key in {"cleanup", "llm_cleanup"}:
            _remember_phase_start("llm_cleanup", created_at)

    def _clamp_round(value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        return max(1, min(int(value), total_llm_rounds))

    def _running_unpack_round() -> Optional[int]:
        if task_current_stage != "llm_unpack":
            return None
        return _clamp_round(len(executor_logs) + 1)

    def _running_review_round() -> Optional[int]:
        if task_current_stage != "review":
            return None
        has_llm_round_evidence = bool(
            executor_logs
            or verifier_logs
            or round_items
            or final_round > 0
            or fallback_to_llm
        )
        if not has_llm_round_evidence:
            return None
        base = max(len(executor_logs), len(verifier_logs) + 1, final_round, 1)
        return _clamp_round(base)

    def _completed_round() -> Optional[int]:
        if final_round > 0:
            return _clamp_round(final_round)
        if verifier_logs:
            return _clamp_round(max(len(verifier_logs), len(executor_logs), 1))
        if executor_logs:
            return _clamp_round(max(len(executor_logs), 1))
        return None

    def _tool_review_duration_seconds() -> Optional[int]:
        transcript_duration = _log_duration_seconds(tool_reviewer_transcript)
        if transcript_duration is not None:
            return transcript_duration
        started_at, _ = _log_time_bounds(tool_reviewer_transcript)
        message_updated_at = _parse_iso_datetime(_mtime_iso_text(tool_reviewer_messages))
        if started_at is not None and message_updated_at is not None:
            return max(0, int(round((ensure_local(message_updated_at) - ensure_local(started_at)).total_seconds())))
        return None

    phases = [
        _phase_payload("preprocess", "预处理", "pending"),
        _phase_payload("tool_match", "工具匹配执行", "pending"),
        _phase_payload("recursive_expand_tool", "递归解包（工具后）", "pending"),
    ]

    if task_status == "retry_preparing":
        phases[0]["status"] = "running"
        phases[0]["detail"] = "正在后台重置工作目录并准备重试"
        phases[1]["status"] = "pending"
        phases[1]["detail"] = "等待重试准备完成后重新开始"
        phases[2]["status"] = "pending"
        phases[2]["detail"] = "等待重试准备完成后重新开始"
        phases.extend(
            [
                _phase_payload("llm_unpack", "LLM 解包", "pending", "等待重试准备完成后重新开始"),
                _phase_payload("recursive_expand_llm", "递归解包（LLM后）", "pending", "等待重试准备完成后重新开始"),
                _phase_payload("llm_review", "LLM 评审", "pending", "等待重试准备完成后重新开始"),
                _phase_payload("llm_cleanup", "LLM 清理", "pending", "等待重试准备完成后重新开始"),
            ]
        )
        return {
            "task_id": task_id,
            "current_phase": "preprocess",
            "summary": "任务正在重置工作目录并准备重试",
            "current_round": None,
            "total_rounds": total_llm_rounds,
            "token_total": _read_run_token_total(run_dir),
            "input_tokens": _read_run_token_breakdown(run_dir).get("input", 0),
            "output_tokens": _read_run_token_breakdown(run_dir).get("output", 0),
            "phases": phases,
        }

    if task_status in {"claimed", "retry_preparing", "running", "cancelling", "success", "failed", "cancelled"}:
        phases[0]["status"] = "running"
        if task_status == "retry_preparing":
            phases[0]["detail"] = "正在后台重置工作目录并准备重试"
        elif task_status == "claimed":
            phases[0]["detail"] = "任务已被调度器认领，正在等待执行进程启动"
        else:
            phases[0]["detail"] = "正在识别固件格式并尝试确定性预处理"

    if stage1_path.exists():
        stage1_data = _read_json_file(stage1_path)
        phase1_detail = None
        if isinstance(stage1_data, list):
            success_steps = [
                str(item.get("tool") or item.get("method") or "")
                for item in stage1_data
                if isinstance(item, dict) and item.get("success")
            ]
            if success_steps:
                phase1_detail = f"已完成，成功步骤：{success_steps[-1]}"
            else:
                phase1_detail = "已完成，但未直接完成解包"
        phases[0] = _phase_payload(
            "preprocess",
            "预处理",
            "success",
            phase1_detail or "预处理已完成",
            _mtime_iso_text(stage1_path),
        )

    if quick_preprocess_success:
        phases[1]["status"] = "skipped"
        phases[1]["detail"] = "预处理已直接完成解包，跳过"
        phases[2]["status"] = "skipped"
        phases[2]["detail"] = "预处理已直接完成解包，跳过"
        phases.extend(
            [
                _phase_payload("llm_unpack", "LLM 解包", "skipped", "预处理已直接完成解包，跳过"),
                _phase_payload("recursive_expand_llm", "递归解包（LLM后）", "skipped", "预处理已直接完成解包，跳过"),
                _phase_payload("llm_review", "LLM 评审", "skipped", "预处理已直接完成解包，跳过"),
                _phase_payload(
                    "llm_cleanup",
                    "LLM 清理",
                    "success" if cleaner_path.exists() or _cleaner_session_closed() else ("running" if task_status == "running" else "pending"),
                    "正在收尾清理输出目录" if task_status == "running" and not (cleaner_path.exists() or _cleaner_session_closed()) else "清理已完成",
                    _mtime_iso_text(cleaner_path) or _mtime_iso_text(cleaner_log_artifact_path),
                    token_total=cleaner_token_total,
                    input_tokens=cleaner_token_breakdown.get("input", 0),
                    output_tokens=cleaner_token_breakdown.get("output", 0),
                ),
            ]
        )
    else:
        if stage2_path.exists():
            stage2_data = _read_json_file(stage2_path)
            matched_path = matched_tool
            matched_score = matched_tool_score
            if isinstance(stage2_data, dict):
                matched_path = str(
                    stage2_data.get("matched_tool")
                    or stage2_data.get("matched_skill")
                    or matched_path
                    or ""
                )
                matched_score = stage2_data.get(
                    "matched_tool_score",
                    stage2_data.get("matched_skill_score", matched_score),
                )
            matched_tool = matched_path
            matched_tool_score = matched_score
            if matched_path:
                status = "success"
                detail = f"命中工具：{Path(matched_path).name}"
                if matched_score is not None:
                    detail += f"（得分 {matched_score}）"
                if fallback_to_llm:
                    status = "failed"
                    detail += "，执行失败后已回退 LLM"
                elif task_status == "running" and not stage3_path.exists():
                    status = "running"
                    detail += "，正在执行"
                phases[1] = _phase_payload(
                    "tool_match",
                    "工具匹配执行",
                    status,
                    detail,
                    _mtime_iso_text(stage3_path if stage3_path.exists() else stage2_path),
                )
            elif executor_logs or task_status in {"claimed", "retry_preparing", "running", "success", "failed", "cancelled"}:
                phases[1] = _phase_payload(
                    "tool_match",
                    "工具匹配执行",
                    "pending" if task_status in {"claimed", "retry_preparing"} else "skipped",
                    "正在等待执行进程启动" if task_status == "claimed" else ("正在等待重试准备完成" if task_status == "retry_preparing" else "未命中可复用工具，转入 LLM 解包"),
                    _mtime_iso_text(stage2_path),
                )

        tool_recursive_manifest = round_zero / "recursive_expand_manifest.json"
        tool_recursive_log = round_zero / "recursive_expand.log"
        tool_recursive_duration = _log_duration_seconds(tool_recursive_log)
        if tool_recursive_manifest.exists() or task_current_stage == "recursive_expand":
            recursive_status = "running" if task_current_stage == "recursive_expand" and not executor_logs else "success"
            recursive_detail = "正在递归展开可识别归档与文件系统"
            if tool_recursive_manifest.exists() and recursive_status != "running":
                manifest_payload = _read_json_file(tool_recursive_manifest)
                completed_rounds = (
                    int(manifest_payload.get("completed_rounds") or 0)
                    if isinstance(manifest_payload, dict)
                    else 0
                )
                recursive_detail = (
                    f"已完成 {completed_rounds} 轮工具后递归解包"
                    if completed_rounds > 0
                    else "工具后递归解包已完成"
                )
            phases[2] = _phase_payload(
                "recursive_expand_tool",
                "递归解包（工具后）",
                recursive_status,
                recursive_detail,
                _mtime_iso_text(tool_recursive_manifest) or _mtime_iso_text(tool_recursive_log),
                duration_seconds=tool_recursive_duration,
            )
        elif matched_tool and not fallback_to_llm and not executor_logs:
            phases[2] = _phase_payload("recursive_expand_tool", "递归解包（工具后）", "pending", "等待工具执行后进入递归展开")
        elif executor_logs or fallback_to_llm or task_current_stage in {"llm_unpack", "review", "cleanup"}:
            phases[2] = _phase_payload("recursive_expand_tool", "递归解包（工具后）", "skipped", "当前任务已进入 LLM 阶段")

        round_metrics = _read_round_metrics(run_dir)
        round_items = {
            int(item.get("round") or 0): item
            for item in list((round_metrics or {}).get("items") or [])
            if isinstance(item, dict) and int(item.get("round") or 0) > 0
        }
        started_rounds = max(
            len(executor_logs),
            len(verifier_logs),
            max(round_items.keys(), default=0),
            _running_unpack_round() or 0,
            _running_review_round() or 0,
            final_round,
        )

        llm_phases: list[dict[str, Any]] = []

        def _round_metric_time(round_id: int, role: str, field: str) -> Optional[datetime]:
            payload = round_items.get(round_id) or {}
            role_payload = payload.get(role) if isinstance(payload.get(role), dict) else {}
            return _parse_iso_datetime(role_payload.get(field))

        def _round_metric_duration(round_id: int, role: str) -> Optional[int]:
            payload = round_items.get(round_id) or {}
            role_payload = payload.get(role) if isinstance(payload.get(role), dict) else {}
            value = role_payload.get("duration_seconds")
            if value is None:
                return None
            try:
                return max(0, int(round(float(value))))
            except Exception:
                return None

        def _round_metric_token_total(round_id: int, role: str) -> Optional[int]:
            if role == "executor":
                return _read_executor_round_token_total(run_dir, round_id)
            token_total = _read_token_total(_round_dir(run_dir, round_id) / f"{role}_tokens.json")
            return token_total if token_total is not None else None

        tool_review_phase: dict[str, Any] | None = None
        if has_tool_review:
            review_status = "success"
            review_detail = "工具执行后的评审已通过"
            if task_current_stage == "review" and not fallback_to_llm and not (executor_logs or verifier_logs or round_items):
                review_status = "running"
                review_detail = "正在执行 tool 评审"
            elif fallback_to_llm:
                review_status = "failed"
                review_detail = "工具执行后的评审未通过，已回退到 LLM"
            elif task_status == "failed" and not fallback_to_llm and not (executor_logs or verifier_logs or round_items):
                review_status = "failed"
                review_detail = "工具执行后的评审未通过"
            tool_review_phase = _phase_payload(
                "llm_review_tool",
                "tool评审",
                review_status,
                review_detail,
                _mtime_iso_text(tool_reviewer_messages),
                duration_seconds=_tool_review_duration_seconds(),
                token_total=tool_reviewer_token_total,
                input_tokens=tool_reviewer_token_breakdown.get("input", 0),
                output_tokens=tool_reviewer_token_breakdown.get("output", 0),
            )
        elif not matched_tool and (
            executor_logs
            or verifier_logs
            or round_items
            or task_current_stage in {"llm_unpack", "review", "cleanup"}
            or fallback_to_llm
            or task_status in {"success", "failed", "cancelled"}
        ):
            tool_review_phase = _phase_payload(
                "llm_review_tool",
                "tool评审",
                "skipped",
                "未进入工具执行链路，跳过 tool 评审",
                _mtime_iso_text(stage2_path),
            )
        elif matched_tool and not fallback_to_llm:
            tool_review_phase = _phase_payload(
                "llm_review_tool",
                "tool评审",
                "pending",
                "等待工具执行及工具后递归解包完成后进入评审",
                None,
            )

        if started_rounds > 0:
            running_unpack_round = _running_unpack_round()
            running_review_round = _running_review_round()
            running_llm_recursive_round = None
            if task_current_stage == "recursive_expand":
                running_llm_recursive_round = max(
                    len(executor_logs),
                    max(round_items.keys(), default=0),
                    1,
                )
            if tool_review_phase is not None:
                llm_phases.append(tool_review_phase)
            for round_id in range(1, started_rounds + 1):
                round_dir = _round_dir(run_dir, round_id)
                executor_path = round_dir / "executor_messages.json"
                recursive_manifest_path = round_dir / "recursive_expand_manifest.json"
                recursive_log_path = round_dir / "recursive_expand.log"
                reviewer_path = round_dir / "reviewer_messages.json"
                metric = round_items.get(round_id) or {}
                metric_status = str(metric.get("status") or "").strip().lower()
                executor_done = executor_path.exists() or bool(metric)
                reviewer_done = reviewer_path.exists() or bool(metric.get("reviewer")) if isinstance(metric, dict) else reviewer_path.exists()

                if executor_done or (task_current_stage == "llm_unpack" and running_unpack_round == round_id):
                    unpack_status = "running" if task_current_stage == "llm_unpack" and running_unpack_round == round_id else "success"
                    unpack_detail = "LLM 正在执行当前轮解包" if unpack_status == "running" else "当前轮解包已完成"
                    if task_status == "failed" and round_id == started_rounds and not reviewer_done:
                        unpack_status = "failed"
                        unpack_detail = "当前轮解包执行失败"
                    unpack_duration = _round_metric_duration(round_id, "executor")
                    if unpack_status == "running" and unpack_duration is None:
                        phase_start = phase_start_times.get("llm_unpack")
                        if phase_start is not None:
                            unpack_duration = max(0, int(round((now_local() - ensure_local(phase_start)).total_seconds())))
                    llm_phases.append(
                        _phase_payload(
                            f"llm_unpack_round_{round_id}",
                            f"LLM 解包（第{round_id}轮）",
                            unpack_status,
                            unpack_detail,
                            _mtime_iso_text(executor_path) or _mtime_iso_text(stage3_llm_unpack_log),
                            current_round=round_id,
                            total_rounds=total_llm_rounds,
                            duration_seconds=unpack_duration,
                            token_total=_round_metric_token_total(round_id, "executor"),
                            input_tokens=_read_executor_round_token_breakdown(run_dir, round_id).get("input", 0),
                            output_tokens=_read_executor_round_token_breakdown(run_dir, round_id).get("output", 0),
                        )
                    )

                recursive_done = recursive_manifest_path.exists()
                if recursive_done or (task_current_stage == "recursive_expand" and running_llm_recursive_round == round_id):
                    recursive_status = "running" if task_current_stage == "recursive_expand" and running_llm_recursive_round == round_id else "success"
                    recursive_detail = "正在递归展开当前轮 LLM 解包产物" if recursive_status == "running" else "当前轮 LLM 后递归解包已完成"
                    if recursive_done and recursive_status != "running":
                        recursive_manifest_payload = _read_json_file(recursive_manifest_path)
                        completed_rounds = (
                            int(recursive_manifest_payload.get("completed_rounds") or 0)
                            if isinstance(recursive_manifest_payload, dict)
                            else 0
                        )
                        if completed_rounds > 0:
                            recursive_detail = f"已完成第{round_id}轮后的 {completed_rounds} 轮递归解包"
                    llm_phases.append(
                        _phase_payload(
                            f"recursive_expand_llm_round_{round_id}",
                            f"递归解包（第{round_id}轮后）",
                            recursive_status,
                            recursive_detail,
                            _mtime_iso_text(recursive_manifest_path) or _mtime_iso_text(recursive_log_path),
                            current_round=round_id,
                            total_rounds=total_llm_rounds,
                            duration_seconds=_log_duration_seconds(recursive_log_path),
                        )
                    )

                if reviewer_done or (task_current_stage == "review" and running_review_round == round_id):
                    review_status = "running" if task_current_stage == "review" and running_review_round == round_id and not metric_status else "success"
                    review_detail = "LLM 正在评审当前轮解包结果" if review_status == "running" else "当前轮评审已通过"
                    if metric_status in {"review_failed", "failed", "error"} or (task_status == "failed" and round_id == started_rounds):
                        review_status = "failed"
                        review_detail = "当前轮评审未通过"
                    elif metric_status in {"review_passed", "success", "completed"}:
                        review_status = "success"
                        review_detail = "当前轮评审已通过"
                    review_duration = _round_metric_duration(round_id, "reviewer")
                    if review_status == "running" and review_duration is None:
                        phase_start = phase_start_times.get("llm_review")
                        if phase_start is not None:
                            review_duration = max(0, int(round((now_local() - ensure_local(phase_start)).total_seconds())))
                    llm_phases.append(
                        _phase_payload(
                            f"llm_review_round_{round_id}",
                            f"LLM 评审（第{round_id}轮）",
                            review_status,
                            review_detail,
                            _mtime_iso_text(reviewer_path) or _mtime_iso_text(stage4_llm_review_log),
                            current_round=round_id,
                            total_rounds=total_llm_rounds,
                            duration_seconds=review_duration,
                            token_total=_round_metric_token_total(round_id, "reviewer"),
                            input_tokens=_read_token_breakdown(_round_dir(run_dir, round_id) / "reviewer_tokens.json").get("input", 0),
                            output_tokens=_read_token_breakdown(_round_dir(run_dir, round_id) / "reviewer_tokens.json").get("output", 0),
                        )
                    )
                elif executor_done or recursive_done or (task_current_stage == "recursive_expand" and running_llm_recursive_round == round_id):
                    llm_phases.append(
                        _phase_payload(
                            f"llm_review_round_{round_id}",
                            f"LLM 评审（第{round_id}轮）",
                            "pending",
                            "等待当前轮递归解包完成后进入评审",
                            None,
                            current_round=round_id,
                            total_rounds=total_llm_rounds,
                        )
                    )

        elif matched_tool and not fallback_to_llm:
            llm_phases.append(_phase_payload("llm_unpack", "LLM 解包", "skipped", "工具执行成功，跳过 LLM 解包"))
            llm_phases.append(_phase_payload("recursive_expand_llm", "递归解包（LLM后）", "skipped", "未进入 LLM 解包，跳过"))
            if tool_review_phase is not None:
                llm_phases.append(tool_review_phase)
            else:
                llm_phases.append(_phase_payload("llm_review", "LLM 评审", "not_executed", "工具执行成功后，LLM 评审未执行"))
        elif tool_review_phase is not None:
            llm_phases.append(tool_review_phase)

        phases.extend(llm_phases)

        cleanup_status = "pending"
        cleanup_detail = None
        cleaner_done = cleaner_path.exists() or _cleaner_session_closed()
        if task_status == "success" or cleaner_done:
            cleanup_status = "success"
            cleanup_detail = "清理已完成"
        elif task_current_stage == "cleanup" and task_status == "running":
            cleanup_status = "running"
            cleanup_detail = "正在清理中间产物和重复文件"
        elif task_status in {"failed", "cancelled"}:
            cleanup_status = "skipped"
            cleanup_detail = "任务未正常完成，未进入清理阶段"
        phases.append(_phase_payload(
            "llm_cleanup",
            "LLM 清理",
            cleanup_status,
            cleanup_detail,
            _mtime_iso_text(cleaner_path) or _mtime_iso_text(cleaner_log_artifact_path),
            token_total=cleaner_token_total,
            input_tokens=cleaner_token_breakdown.get("input", 0),
            output_tokens=cleaner_token_breakdown.get("output", 0),
        ))

    terminal_task_status = task_status if task_status in {"success", "failed", "cancelled"} else None
    if terminal_task_status:
        active_phase_index = next(
            (index for index, phase in enumerate(phases) if str(phase.get("status") or "") == "running"),
            None,
        )
        if active_phase_index is not None:
            active_phase = phases[active_phase_index]
            if terminal_task_status == "success":
                active_phase["status"] = "success"
                if not active_phase.get("detail"):
                    active_phase["detail"] = "阶段已完成"
            else:
                active_phase["status"] = terminal_task_status
                if terminal_task_status == "failed":
                    failure_reason = str(task.get("error_message") or task.get("result_message") or "").strip()
                    active_phase["detail"] = failure_reason or "任务在当前阶段失败"
                else:
                    active_phase["detail"] = "任务已取消"
        for index, phase in enumerate(phases):
            if active_phase_index is not None and index <= active_phase_index:
                continue
            if str(phase.get("status") or "") in {"pending", "running"}:
                phase["status"] = "skipped" if terminal_task_status != "cancelled" else "cancelled"
                if not phase.get("detail"):
                    phase["detail"] = (
                        "任务已完成，后续阶段未执行"
                        if terminal_task_status == "success"
                        else ("任务失败，后续阶段未执行" if terminal_task_status == "failed" else "任务已取消")
                    )

    current_phase = None
    for phase in phases:
        if phase["status"] == "running":
            current_phase = phase["key"]
            break
    if current_phase is None:
        for phase in reversed(phases):
            if phase["status"] in {"success", "failed"}:
                current_phase = phase["key"]
                break

    summary_parts: list[str] = []
    if matched_tool:
        summary_parts.append(f"命中工具：{Path(matched_tool).name}")
    if fallback_to_llm:
        summary_parts.append("已回退到 LLM 解包")
    if generated_skill_path:
        summary_parts.append(f"生成候选工具：{Path(generated_skill_path).name}")
    summary = "；".join(summary_parts) if summary_parts else "根据运行目录推导当前阶段进展"

    overall_current_round = None
    overall_total_rounds = None
    for phase in phases:
        phase_key = str(phase.get("key") or "")
        if (
            phase_key in {"llm_unpack", "llm_review", "recursive_expand_llm"}
            or phase_key.startswith("llm_unpack_round_")
            or phase_key.startswith("recursive_expand_llm_round_")
            or phase_key.startswith("llm_review_round_")
        ) and phase.get("current_round") is not None:
            overall_current_round = phase.get("current_round")
            overall_total_rounds = phase.get("total_rounds")
            if phase["status"] == "running":
                break
    if overall_current_round is None:
        completed_round = _completed_round()
        if completed_round is not None:
            overall_current_round = completed_round
            overall_total_rounds = total_llm_rounds

    task_completed_at = _parse_iso_datetime(task.get("completed_at"))
    for index, phase in enumerate(phases):
        phase_key = str(phase.get("key") or "")
        phase_status = str(phase.get("status") or "")
        phase_start = phase_start_times.get(phase_key)
        if phase_start is None:
            if phase_key.startswith("llm_unpack_round_"):
                phase_start = _round_metric_time(int(phase_key.rsplit("_", 1)[-1]), "executor", "started_at")
                if phase_start is None:
                    phase_start = phase_start_times.get("llm_unpack")
            elif phase_key.startswith("llm_review_round_"):
                phase_start = _round_metric_time(int(phase_key.rsplit("_", 1)[-1]), "reviewer", "started_at")
                if phase_start is None:
                    phase_start = phase_start_times.get("llm_review")
            elif phase_key.startswith("recursive_expand_llm_round_"):
                round_id = int(phase_key.rsplit("_", 1)[-1])
                phase_start, _ = _log_time_bounds(_round_dir(run_dir, round_id) / "recursive_expand.log")
            elif phase_key == "llm_review_tool":
                phase_start, _ = _log_time_bounds(tool_reviewer_transcript)
                if phase_start is None:
                    phase_start, _ = _log_time_bounds(stage4_llm_review_log)
        if phase_start is None or phase_status in {"pending", "skipped", "not_executed"}:
            continue
        if phase.get("duration_seconds") is not None and phase_status != "running":
            continue
        if phase_status == "running":
            phase_end = now_local()
        else:
            phase_end = _parse_iso_datetime(phase.get("updated_at"))
            if phase_end is None:
                for next_phase in phases[index + 1:]:
                    next_start = phase_start_times.get(str(next_phase.get("key") or ""))
                    if next_start is not None:
                        phase_end = next_start
                        break
            if phase_end is None:
                phase_end = task_completed_at or phase_start
        phase_start = ensure_local(phase_start)
        phase_end = ensure_local(phase_end)
        duration_seconds = max(0, int(round((phase_end - phase_start).total_seconds())))
        phase["duration_seconds"] = duration_seconds

    run_token_breakdown = _read_run_token_breakdown(run_dir)
    return {
        "task_id": task_id,
        "current_phase": current_phase,
        "summary": summary,
        "current_round": overall_current_round,
        "total_rounds": overall_total_rounds,
        "token_total": run_token_breakdown.get("total", 0),
        "input_tokens": run_token_breakdown.get("input", 0),
        "output_tokens": run_token_breakdown.get("output", 0),
        "phases": phases,
    }


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _format_log_file(path: Path) -> str:
    try:
        file_size = path.stat().st_size
    except Exception:
        file_size = 0
    if path.suffix.lower() == ".json" and file_size <= MAX_LOG_RENDER_BYTES:
        payload = _read_json_file(path)
        if payload is not None:
            try:
                return json.dumps(payload, ensure_ascii=False, indent=2)
            except Exception:
                pass
    if file_size > MAX_LOG_RENDER_BYTES:
        return read_text_tail(path, MAX_LOG_RENDER_BYTES, encoding="utf-8")
    return _read_text_file(path)


def _phase_log_files(run_dir: Path, phase: Optional[str]) -> list[Path]:
    phase_key = str(phase or "").strip()
    round_zero = _round_dir(run_dir, 0)
    llm_round_dirs = _llm_round_dirs(run_dir)
    if not phase_key:
        files: list[Path] = [
            round_zero / "preprocess.json",
            round_zero / "skill_match.json",
            round_zero / "skill_exec.json",
            round_zero / "fallback.json",
            round_zero / "stage5_skill_generate.json",
            round_zero / "cleaner_messages.json",
            round_zero / "summary.md",
            round_zero / "reason.md",
        ]
        for llm_round_dir in llm_round_dirs:
            files.extend(
                [
                    llm_round_dir / "executor_messages.json",
                    llm_round_dir / "executor_transcript.log",
                    llm_round_dir / "executor_tokens.json",
                    llm_round_dir / "reviewer_messages.json",
                    llm_round_dir / "reviewer_transcript.log",
                    llm_round_dir / "reviewer_tokens.json",
                    llm_round_dir / "results.json",
                    llm_round_dir / "summary.md",
                    llm_round_dir / "reason.md",
                ]
            )
        files.extend(sorted(round_zero.glob("*.log")))
        return files

    mapping: dict[str, list[Path]] = {
        "preprocess": [round_zero / "preprocess.log", round_zero / "preprocess.json"],
        "tool_match": [round_zero / "skill_match.log", round_zero / "skill_match.json", round_zero / "skill_exec.log", round_zero / "skill_exec.json"],
        "recursive_expand": [
            round_zero / "recursive_expand.log",
            round_zero / "recursive_expand_manifest.json",
            *[path / "recursive_expand.log" for path in llm_round_dirs],
            *[path / "recursive_expand_manifest.json" for path in llm_round_dirs],
        ],
        "llm_unpack": [
            round_zero / "stage3_llm_unpack.log",
            round_zero / "fallback.json",
            *[path / "executor_transcript.log" for path in llm_round_dirs],
            *[path / "executor_messages.json" for path in llm_round_dirs],
        ],
        "llm_review": [
            round_zero / "stage4_llm_review.log",
            *[path / "reviewer_transcript.log" for path in llm_round_dirs],
            *[path / "reviewer_messages.json" for path in llm_round_dirs],
            *[path / "reason.md" for path in llm_round_dirs],
            *[path / "summary.md" for path in llm_round_dirs],
        ],
        "llm_cleanup": [
            round_zero / "cleaner.log",
            round_zero / "cleaner_transcript.log",
            round_zero / "cleaner_messages.json",
            round_zero / "stage5_skill_generate.log",
            round_zero / "stage5_skill_generate.json",
            round_zero / "skill_author_transcript.log",
            round_zero / "skill_author_messages.json",
        ],
    }
    if phase_key == "recursive_expand_tool":
        return mapping.get("recursive_expand", [])[:3]
    if phase_key == "recursive_expand_llm":
        return mapping.get("recursive_expand", [])[3:]
    if phase_key == "llm_review_tool":
        return [round_zero / "stage4_llm_review.log", round_zero / "reviewer_messages.json", round_zero / "reason.md", round_zero / "summary.md"]
    if phase_key.startswith("llm_unpack_round_"):
        round_id = int(phase_key.rsplit("_", 1)[-1])
        round_dir = _round_dir(run_dir, round_id)
        return [
            round_zero / "stage3_llm_unpack.log",
            round_dir / "executor_transcript.log",
            round_dir / "executor_messages.json",
            round_dir / "results.json",
        ]
    if phase_key.startswith("recursive_expand_llm_round_"):
        round_id = int(phase_key.rsplit("_", 1)[-1])
        round_dir = _round_dir(run_dir, round_id)
        return [
            round_dir / "recursive_expand.log",
            round_dir / "recursive_expand_manifest.json",
        ]
    if phase_key.startswith("llm_review_round_"):
        round_id = int(phase_key.rsplit("_", 1)[-1])
        round_dir = _round_dir(run_dir, round_id)
        return [
            round_zero / "stage4_llm_review.log",
            round_dir / "reviewer_transcript.log",
            round_dir / "reviewer_messages.json",
            round_dir / "reason.md",
            round_dir / "summary.md",
            round_dir / "results.json",
        ]
    return mapping.get(phase_key, [])


def _get_task_logs(task_id: str, phase: Optional[str] = None) -> dict:
    task = _get_task_or_404(task_id)
    run_dir = _derive_run_path(task)
    if not run_dir.exists() or not run_dir.is_dir():
        return {
            "task_id": task_id,
            "run_path": str(run_dir),
            "available": False,
            "log_text": "",
            "files": [],
            "phase": phase,
            "message": "运行日志目录不存在",
        }

    known_files = _phase_log_files(run_dir, phase)

    deduped_files: list[Path] = []
    seen: set[str] = set()
    for path in known_files:
        key = str(path)
        if not path.exists() or key in seen:
            continue
        seen.add(key)
        deduped_files.append(path)

    if not deduped_files:
        return {
            "task_id": task_id,
            "run_path": str(run_dir),
            "available": False,
            "log_text": "",
            "files": [],
            "phase": phase,
            "message": "当前阶段尚未生成可读日志文件" if phase else "当前任务尚未生成可读日志文件",
        }

    sections: list[str] = []
    file_names: list[str] = []
    for path in deduped_files:
        rendered = _format_log_file(path).strip()
        if not rendered:
            continue
        file_names.append(path.name)
        sections.append(f"===== {path.name} =====\n{rendered}")

    if not sections:
        return {
            "task_id": task_id,
            "run_path": str(run_dir),
            "available": False,
            "log_text": "",
            "files": file_names,
            "phase": phase,
            "message": "日志文件存在，但当前没有可展示内容",
        }

    return {
        "task_id": task_id,
        "run_path": str(run_dir),
        "available": True,
        "log_text": "\n\n".join(sections),
        "files": file_names,
        "phase": phase,
        "message": None,
    }


def _get_task_events(task_id: str, limit: int) -> dict:
    _get_task_or_404(task_id)
    return list_task_events(task_id, limit=limit)


def _count_task_events(task_id: str) -> int:
    return int(list_task_events(task_id, limit=1).get("total") or 0)


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return None


def _now_iso_like(value: Optional[str]) -> str:
    parsed = _parse_iso_datetime(value)
    if parsed and parsed.tzinfo is not None:
        return datetime.now(parsed.tzinfo).isoformat()
    return datetime.now().isoformat()


def _seconds_between(start: Optional[str], end: Optional[str]) -> Optional[int]:
    start_dt = _parse_iso_datetime(start)
    end_dt = _parse_iso_datetime(end)
    if not start_dt or not end_dt:
        return None
    if (start_dt.tzinfo is None) != (end_dt.tzinfo is None):
        start_dt = start_dt.replace(tzinfo=None)
        end_dt = end_dt.replace(tzinfo=None)
    return max(0, int((end_dt - start_dt).total_seconds()))


def _seconds_since(start: Optional[str]) -> Optional[int]:
    start_dt = _parse_iso_datetime(start)
    if not start_dt:
        return None
    now = datetime.now(start_dt.tzinfo) if start_dt.tzinfo is not None else datetime.now()
    return max(0, int((now - start_dt).total_seconds()))


def _usage_percent(used: Optional[int], limit: Optional[int]) -> Optional[float]:
    if used is None or limit is None or int(limit) <= 0:
        return None
    return round(max(0.0, float(used) / float(limit) * 100.0), 2)


def _get_latest_task_event(task_id: str) -> Optional[dict]:
    db = get_db_session()
    try:
        event = (
            db.query(UnpackTaskEvent)
            .filter(UnpackTaskEvent.task_id == task_id)
            .order_by(UnpackTaskEvent.created_at.desc())
            .first()
        )
        return event.to_dict() if event else None
    finally:
        db.close()


def _get_session_metrics(run_root: Path) -> dict:
    items = _read_json_index_items(run_root / "sessions" / "index.json")
    running = 0
    failed = 0
    closed = 0
    for item in items:
        status_value = str(item.get("status") or "").strip().lower()
        if status_value == "running":
            running += 1
        elif status_value == "failed":
            failed += 1
        elif status_value == "closed":
            closed += 1
    return {
        "session_count": len(items),
        "running_session_count": running,
        "failed_session_count": failed,
        "closed_session_count": closed,
    }


def _get_cached_result_metrics(run_root: Path) -> dict:
    cache_path = run_root / TASK_RESULT_CACHE_FILENAME
    payload = _read_json_file(cache_path)
    summary = payload.get("summary") if isinstance(payload, dict) and isinstance(payload.get("summary"), dict) else {}
    if not isinstance(payload, dict):
        return {
            "cache_available": False,
            "cache_updated_at": None,
            "output_file_count": 0,
            "output_dir_count": 0,
            "output_total_size_bytes": 0,
            "largest_file_size_bytes": 0,
            "top_level_entry_count": 0,
            "small_file_count": 0,
            "medium_file_count": 0,
            "large_file_count": 0,
            "executor_rounds": 0,
            "fallback_to_llm": False,
            "matched_skill": None,
            "generated_skill_path": None,
            "generated_skill_status": None,
            "promotion_success_count": 0,
            "skill_generation_status": None,
        }
    return {
        "cache_available": True,
        "cache_updated_at": _mtime_iso_text(cache_path),
        "output_file_count": int(summary.get("output_file_count") or 0),
        "output_dir_count": int(summary.get("output_dir_count") or 0),
        "output_total_size_bytes": int(summary.get("output_total_size_bytes") or 0),
        "largest_file_size_bytes": int(summary.get("largest_file_size_bytes") or 0),
        "top_level_entry_count": int(summary.get("top_level_entry_count") or 0),
        "small_file_count": int(summary.get("small_file_count") or 0),
        "medium_file_count": int(summary.get("medium_file_count") or 0),
        "large_file_count": int(summary.get("large_file_count") or 0),
        "executor_rounds": int(summary.get("executor_rounds") or 0),
        "fallback_to_llm": bool(summary.get("fallback_to_llm")),
        "matched_skill": str(summary.get("matched_skill") or "").strip() or None,
        "generated_skill_path": str(summary.get("generated_skill_path") or "").strip() or None,
        "generated_skill_status": str(summary.get("generated_skill_status") or "").strip() or None,
        "promotion_success_count": int(summary.get("promotion_success_count") or 0),
        "skill_generation_status": str(summary.get("skill_generation_status") or "").strip() or None,
    }


def _safe_int(value, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _round_metric_empty(warnings: Optional[list[str]] = None) -> dict:
    return {
        "available": False,
        "round_count": 0,
        "completed_round_count": 0,
        "failed_round_count": 0,
        "running_round": None,
        "total_duration_seconds": 0.0,
        "total_tokens": 0,
        "total_cost": 0.0,
        "output_growth_bytes": 0,
        "latest_round": None,
        "summary": {
            "status_counts": {},
            "stage_summary": {},
        },
        "items": [],
        "warnings": list(warnings or []),
    }


def _normalize_round_tokens(payload: dict) -> dict:
    source = payload if isinstance(payload, dict) else {}
    input_tokens = _safe_int(source.get("input"))
    output_tokens = _safe_int(source.get("output"))
    cache_read = _safe_int(source.get("cache_read", source.get("cacheRead")))
    cache_write = _safe_int(source.get("cache_write", source.get("cacheWrite")))
    total = _safe_int(source.get("total"))
    if total <= 0:
        total = input_tokens + output_tokens + cache_read + cache_write
    return {
        "input": input_tokens,
        "output": output_tokens,
        "cache_read": cache_read,
        "cache_write": cache_write,
        "total": total,
        "cost": _safe_float(source.get("cost")),
    }


def _token_total_from_mapping(value) -> int:
    if not isinstance(value, dict):
        return 0
    return _normalize_round_tokens(value)["total"]


def _round_number_from_dir(path: Path) -> Optional[int]:
    name = path.name
    if not name.startswith("round_"):
        return None
    try:
        return int(name.split("_", 1)[1])
    except (IndexError, ValueError):
        return None


def _read_round_metrics(run_root: Path) -> dict:
    warnings: list[str] = []
    if not run_root.exists() or not run_root.is_dir():
        return _round_metric_empty()

    items: list[dict] = []
    shared_executor = _uses_shared_executor_session(run_root)
    previous_executor_tokens: dict = {}
    for round_dir in _list_round_dirs(run_root):
        round_id = _round_number_from_dir(round_dir)
        if round_id is None or round_id == 0:
            continue
        result_path = round_dir / "results.json"
        if not result_path.exists():
            continue
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception as exc:
            warning = f"{result_path.relative_to(run_root)} 读取失败: {exc}"
            warnings.append(warning)
            continue
        if not isinstance(payload, dict):
            warnings.append(f"{result_path.relative_to(run_root)} 格式不是对象")
            continue

        executor = payload.get("executor") if isinstance(payload.get("executor"), dict) else {}
        reviewer = payload.get("reviewer") if isinstance(payload.get("reviewer"), dict) else {}
        tokens_payload = payload.get("tokens") if isinstance(payload.get("tokens"), dict) else {}
        raw_executor_tokens = tokens_payload.get("executor") if isinstance(tokens_payload.get("executor"), dict) else {}
        executor_tokens = (
            _token_delta(raw_executor_tokens, previous_executor_tokens)
            if shared_executor
            else raw_executor_tokens
        )
        previous_executor_tokens = raw_executor_tokens
        reviewer_tokens = tokens_payload.get("reviewer") if isinstance(tokens_payload.get("reviewer"), dict) else {}
        round_tokens = _normalize_round_tokens(
            {
                field: _safe_int(executor_tokens.get(field)) + _safe_int(reviewer_tokens.get(field))
                for field in TOKEN_FIELDS
            }
        )
        output_snapshot = payload.get("output_snapshot") if isinstance(payload.get("output_snapshot"), dict) else {}
        output_delta = payload.get("output_delta") if isinstance(payload.get("output_delta"), dict) else {}
        artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
        context = payload.get("context") if isinstance(payload.get("context"), dict) else {}
        paths = payload.get("paths") if isinstance(payload.get("paths"), dict) else {}

        summary_path_raw = str(paths.get("summary_path") or "").strip()
        reason_path_raw = str(paths.get("reason_path") or "").strip()
        summary_text = _read_text_file(Path(summary_path_raw)).strip() if summary_path_raw else ""
        reason_text = _read_text_file(Path(reason_path_raw)).strip() if reason_path_raw else ""

        size_delta = _safe_int(
            output_delta.get("size_bytes_delta", output_delta.get("output_total_size_bytes_delta"))
        )
        file_delta = _safe_int(
            output_delta.get("file_count_delta", output_delta.get("output_file_count_delta"))
        )
        dir_delta = _safe_int(
            output_delta.get("dir_count_delta", output_delta.get("output_dir_count_delta"))
        )
        item = {
            "round": _safe_int(payload.get("round"), round_id),
            "status": str(payload.get("status") or "unknown"),
            "started_at": payload.get("started_at"),
            "completed_at": payload.get("completed_at"),
            "duration_seconds": _safe_float(payload.get("duration_seconds")),
            "executor": {
                "status": str(executor.get("status") or "completed"),
                "duration_seconds": _safe_float(executor.get("duration_seconds")),
                "response_preview": executor.get("response_preview"),
                "provider_role": executor.get("provider_role"),
                "session_file": executor.get("session_file"),
            },
            "reviewer": {
                "passed": bool(reviewer.get("passed")),
                "duration_seconds": _safe_float(reviewer.get("duration_seconds")),
                "review_preview": reviewer.get("review_preview"),
                "provider_role": reviewer.get("provider_role"),
                "session_file": reviewer.get("session_file"),
            },
            "tokens": round_tokens,
            "executor_tokens": _normalize_round_tokens(executor_tokens),
            "reviewer_tokens": _normalize_round_tokens(reviewer_tokens),
            "output_snapshot": {
                "output_file_count": _safe_int(output_snapshot.get("output_file_count")),
                "output_dir_count": _safe_int(output_snapshot.get("output_dir_count")),
                "output_total_size_bytes": _safe_int(output_snapshot.get("output_total_size_bytes")),
                "largest_file_size_bytes": _safe_int(output_snapshot.get("largest_file_size_bytes")),
            },
            "output_delta": {
                "file_count_delta": file_delta,
                "dir_count_delta": dir_delta,
                "size_bytes_delta": size_delta,
                "baseline_round": output_delta.get("baseline_round"),
            },
            "artifacts": {
                "summary_present": bool(artifacts.get("summary_present")),
                "reason_present": bool(artifacts.get("reason_present")),
                "warnings": [
                    str(item)
                    for item in (artifacts.get("warnings") or [])
                    if str(item).strip()
                ],
                "summary_preview": artifacts.get("summary_preview"),
                "reason_preview": artifacts.get("reason_preview"),
                "summary_text": summary_text or None,
                "reason_text": reason_text or None,
            },
            "context": {
                "matched_skill": context.get("matched_skill"),
                "fallback_to_llm": bool(context.get("fallback_to_llm")),
                "provider_role": context.get("provider_role") or executor.get("provider_role"),
            },
            "source_path": str(result_path),
            "raw": payload,
        }
        items.append(item)

    items.sort(key=lambda item: int(item.get("round") or 0))
    if not items:
        return _round_metric_empty(warnings)

    status_counts: dict[str, int] = defaultdict(int)
    completed = 0
    failed = 0
    running_round = None
    total_duration = 0.0
    total_tokens = 0
    total_cost = 0.0
    output_growth = 0
    stage_summary = {
        "llm_unpack": {"round_count": 0, "duration_seconds": 0.0, "token_total": 0},
        "review": {"round_count": 0, "duration_seconds": 0.0, "token_total": 0},
    }
    for item in items:
        status_value = str(item.get("status") or "unknown")
        status_counts[status_value] += 1
        if status_value in {"review_passed", "success", "completed"}:
            completed += 1
        elif status_value in {"review_failed", "failed", "error"}:
            failed += 1
        else:
            running_round = item.get("round")
        duration = _safe_float(item.get("duration_seconds"))
        total_duration += duration
        tokens = item.get("tokens") if isinstance(item.get("tokens"), dict) else {}
        total_tokens += _safe_int(tokens.get("total"))
        total_cost += _safe_float(tokens.get("cost"))
        delta = item.get("output_delta") if isinstance(item.get("output_delta"), dict) else {}
        output_growth += _safe_int(delta.get("size_bytes_delta"))

        executor = item.get("executor") if isinstance(item.get("executor"), dict) else {}
        reviewer = item.get("reviewer") if isinstance(item.get("reviewer"), dict) else {}
        stage_summary["llm_unpack"]["round_count"] += 1
        stage_summary["llm_unpack"]["duration_seconds"] += _safe_float(executor.get("duration_seconds"))
        stage_summary["llm_unpack"]["token_total"] += _token_total_from_mapping(
            item.get("executor_tokens")
        )
        stage_summary["review"]["round_count"] += 1
        stage_summary["review"]["duration_seconds"] += _safe_float(reviewer.get("duration_seconds"))
        stage_summary["review"]["token_total"] += _token_total_from_mapping(
            item.get("reviewer_tokens")
        )

    return {
        "available": True,
        "round_count": len(items),
        "completed_round_count": completed,
        "failed_round_count": failed,
        "running_round": running_round,
        "total_duration_seconds": round(total_duration, 3),
        "total_tokens": total_tokens,
        "total_cost": round(total_cost, 6),
        "output_growth_bytes": output_growth,
        "latest_round": items[-1].get("round"),
        "summary": {
            "status_counts": dict(status_counts),
            "stage_summary": stage_summary,
        },
        "items": items,
        "warnings": warnings,
    }


def _get_task_metrics(task_id: str) -> dict:
    task = _get_task_or_404(task_id)
    status_value = str(task.get("status") or "unknown")
    terminal = status_value in {"success", "failed", "cancelled", "max_retries_reached"}
    owner_id = str(task.get("owner_id") or "").strip() or None
    run_root = _derive_run_path(task)
    warnings: list[str] = []

    created_at = str(task.get("created_at") or "").strip() or None
    started_at = str(task.get("started_at") or "").strip() or None
    completed_at = str(task.get("completed_at") or "").strip() or None
    duration_end = completed_at if completed_at else (_now_iso_like(started_at) if started_at else None)

    try:
        resource_payload = _get_task_resource_usage(task_id)
    except Exception as exc:
        logger.warning("failed to collect task resource metrics for %s: %s", task_id, exc)
        resource_payload = {
            "available": False,
            "message": "资源指标不可用",
            "containers": [],
        }
    resource_available = bool(resource_payload.get("available"))
    resource_message = str(resource_payload.get("message") or "").strip() or None
    if not resource_available and resource_message:
        warnings.append(resource_message)

    cpu_millicores = resource_payload.get("cpu_millicores")
    memory_mib = resource_payload.get("memory_mib")
    cpu_limit = resource_payload.get("pod_cpu_limit_millicores")
    memory_limit = resource_payload.get("pod_memory_limit_mib")
    resource = {
        "available": resource_available,
        "pod_name": resource_payload.get("pod_name"),
        "namespace": resource_payload.get("namespace"),
        "cpu_millicores": cpu_millicores,
        "memory_mib": memory_mib,
        "pod_cpu_limit_millicores": cpu_limit,
        "pod_memory_limit_mib": memory_limit,
        "cpu_usage_percent": _usage_percent(cpu_millicores, cpu_limit),
        "memory_usage_percent": _usage_percent(memory_mib, memory_limit),
        "containers": list(resource_payload.get("containers") or []),
        "message": resource_message,
    }

    try:
        progress_payload = _get_task_progress(task_id)
    except Exception as exc:
        logger.warning("failed to collect task progress metrics for %s: %s", task_id, exc)
        progress_payload = {"phases": []}
        warnings.append("阶段进展指标不可用")
    phases = [phase for phase in (progress_payload.get("phases") or []) if isinstance(phase, dict)]
    progress = {
        "current_phase": progress_payload.get("current_phase"),
        "current_round": progress_payload.get("current_round"),
        "total_rounds": progress_payload.get("total_rounds"),
        "phase_count": len(phases),
        "completed_phase_count": sum(1 for phase in phases if phase.get("status") == "success"),
        "failed_phase_count": sum(1 for phase in phases if phase.get("status") == "failed"),
        "running_phase_count": sum(1 for phase in phases if phase.get("status") == "running"),
    }

    event_count = _count_task_events(task_id)
    latest_event = _get_latest_task_event(task_id) or {}
    events = {
        "event_count": event_count,
        "latest_event_type": latest_event.get("event_type"),
        "latest_event_summary": latest_event.get("summary"),
        "latest_event_at": latest_event.get("created_at"),
    }

    sessions_index_path = run_root / "sessions" / "index.json"
    sessions = _get_session_metrics(run_root)
    if started_at and not sessions_index_path.exists():
        warnings.append("会话索引不存在")

    result = _get_cached_result_metrics(run_root)
    if not result["cache_available"]:
        warnings.append("结果缓存不存在，请在结果页手动刷新或等待后台刷新")

    rounds = _read_round_metrics(run_root)
    warnings.extend(str(item) for item in rounds.get("warnings") or [] if str(item).strip())

    if not terminal and not owner_id:
        warnings.append("非终态任务缺少 owner")

    return {
        "task_id": task_id,
        "task": {
            "status": status_value,
            "result_status": task.get("result_status"),
            "current_stage": task.get("current_stage"),
            "owner_id": owner_id,
            "created_at": created_at,
            "started_at": started_at,
            "completed_at": completed_at,
            "last_progress_at": str(task.get("last_progress_at") or "").strip() or None,
            "duration_seconds": _seconds_between(started_at, duration_end),
            "queue_wait_seconds": _seconds_between(created_at, started_at),
            "running_seconds": _seconds_since(started_at) if started_at and not terminal else _seconds_between(started_at, completed_at),
        },
        "resource": resource,
        "progress": progress,
        "events": events,
        "sessions": sessions,
        "result": result,
        "rounds": rounds,
        "health": {
            "is_terminal": terminal,
            "has_owner": bool(owner_id),
            "resource_available": resource_available,
            "result_cache_available": bool(result["cache_available"]),
            "warnings": warnings,
        },
    }


def _read_json_index_items(path: Path) -> list[dict]:
    payload = _read_json_file(path)
    if not isinstance(payload, dict):
        return []
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return []
    return [item for item in raw_items if isinstance(item, dict)]


def _normalize_extension(path: Path) -> str:
    suffix = str(path.suffix or "").strip().lower()
    return suffix or "(none)"


def _relative_depth(output_root: Path, path: Path) -> int:
    try:
        relative = path.relative_to(output_root)
    except Exception:
        return 0
    parts = [part for part in relative.parts if part not in {"", "."}]
    return len(parts)


def _entry_sort_key(item: dict) -> tuple[int, int, str]:
    return (
        -int(item.get("total_size_bytes") or 0),
        -int(item.get("file_count") or 0),
        str(item.get("name") or ""),
    )


def _scan_path_tree(root_path: Path) -> tuple[int, int, int]:
    file_count = 0
    dir_count = 0
    total_size = 0

    if not root_path.exists():
        return file_count, dir_count, total_size

    if root_path.is_file() and not root_path.is_symlink():
        try:
            return 1, 0, root_path.stat().st_size
        except Exception:
            return 0, 0, 0

    if not root_path.is_dir():
        return 0, 0, 0

    for current_root, dirs, files in os.walk(root_path, followlinks=False):
        current_path = Path(current_root)
        real_dirs: list[str] = []
        for directory in dirs:
            path = current_path / directory
            if path.is_symlink():
                continue
            dir_count += 1
            real_dirs.append(directory)
        dirs[:] = real_dirs

        for filename in files:
            path = current_path / filename
            if path.is_symlink():
                continue
            try:
                size = path.stat().st_size
            except Exception:
                continue
            file_count += 1
            total_size += size

    return file_count, dir_count, total_size


def _scan_output_tree(output_root: Path) -> dict:
    file_count = 0
    dir_count = 0
    total_size = 0
    largest_file_path: Optional[str] = None
    largest_file_size = 0
    top_level_entry_count = 0
    largest_files: list[dict] = []
    extension_stats: dict[str, dict[str, int | str]] = defaultdict(
        lambda: {"extension": "(none)", "file_count": 0, "total_size_bytes": 0}
    )
    top_level_entries: list[dict] = []
    deepest_path: Optional[str] = None
    deepest_depth = 0
    small_file_count = 0
    medium_file_count = 0
    large_file_count = 0

    if not output_root.exists() or not output_root.is_dir():
        return {
            "output_file_count": file_count,
            "output_dir_count": dir_count,
            "output_total_size_bytes": total_size,
            "largest_file_path": largest_file_path,
            "largest_file_size_bytes": largest_file_size,
            "top_level_entry_count": top_level_entry_count,
            "top_level_entries": top_level_entries,
            "file_extension_breakdown": [],
            "largest_files": [],
            "deepest_path": None,
            "avg_file_size_bytes": 0,
            "small_file_count": small_file_count,
            "medium_file_count": medium_file_count,
            "large_file_count": large_file_count,
        }

    top_level_paths: list[Path] = []
    try:
        top_level_paths = list(output_root.iterdir())
        top_level_entry_count = len(top_level_paths)
    except Exception:
        top_level_entry_count = 0
        top_level_paths = []

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
            stats = extension_stats[extension]
            stats["extension"] = extension
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


def _get_task_result(task_id: str) -> dict:
    task = _get_task_or_404(task_id)
    output_root = Path(str(task.get("output_path") or "").strip())
    run_root = _derive_run_path(task)
    cache_path = run_root / TASK_RESULT_CACHE_FILENAME
    summary_path = output_root / "summary.md"
    reason_path = output_root / "reason.md"
    tokens_summary_path = _round_log_path(run_root, 0, "tokens_summary.json")
    sessions_index_path = run_root / "sessions" / "index.json"

    cached_payload = _read_json_file(cache_path)
    if isinstance(cached_payload, dict):
        summary = cached_payload.get("summary") if isinstance(cached_payload.get("summary"), dict) else {}
        summary["event_count"] = _count_task_events(task_id)
        run_tokens = _read_run_token_breakdown(run_root)
        summary["token_total"] = run_tokens.get("total", 0)
        summary["input_tokens"] = run_tokens.get("input", 0)
        summary["output_tokens"] = run_tokens.get("output", 0)
        return {
            "task_id": task_id,
            "available": bool(cached_payload.get("available", False)),
            "status": str(cached_payload.get("status") or task.get("status") or "unknown"),
            "output_root": cached_payload.get("output_root"),
            "run_root": cached_payload.get("run_root"),
            "summary_path": cached_payload.get("summary_path"),
            "reason_path": cached_payload.get("reason_path"),
            "tokens_summary_path": cached_payload.get("tokens_summary_path"),
            "summary_text": cached_payload.get("summary_text"),
            "reason_text": cached_payload.get("reason_text"),
            "warnings": list(cached_payload.get("warnings") or []),
            "summary": summary,
        }

    warnings: list[str] = []
    task_status = str(task.get("status") or "").strip() or "unknown"
    session_count = len(_read_json_index_items(sessions_index_path))
    event_count = _count_task_events(task_id)

    available = task_status in {"success", "failed", "cancelled"}
    if not output_root.exists() or not output_root.is_dir():
        warnings.append("输出目录不存在")
        available = False

    output_stats = {
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
    if output_root.exists() and output_root.is_dir():
        output_stats = _scan_output_tree(output_root)

    summary_text = _read_text_file(summary_path).strip() or None
    reason_text = _read_text_file(reason_path).strip() or None
    if summary_path.exists() and not summary_text:
        warnings.append("summary.md 存在但为空")
    if reason_path.exists() and not reason_text:
        warnings.append("reason.md 存在但为空")
    if sessions_index_path.exists() and session_count == 0:
        warnings.append("会话索引存在但未解析到任何会话")

    started_at = str(task.get("started_at") or "").strip() or None
    completed_at = str(task.get("completed_at") or "").strip() or None
    duration_seconds: Optional[int] = None
    if started_at and completed_at:
        try:
            duration_seconds = max(0, int((datetime.fromisoformat(completed_at) - datetime.fromisoformat(started_at)).total_seconds()))
        except Exception:
            duration_seconds = None

    return {
        "task_id": task_id,
        "available": available,
        "status": task_status,
        "output_root": str(output_root) if str(output_root) else None,
        "run_root": str(run_root),
        "summary_path": str(summary_path) if summary_path.exists() else None,
        "reason_path": str(reason_path) if reason_path.exists() else None,
        "tokens_summary_path": str(tokens_summary_path) if tokens_summary_path.exists() else None,
        "summary_text": summary_text,
        "reason_text": reason_text,
        "warnings": warnings,
        "summary": {
            **output_stats,
            "matched_skill": str(task.get("matched_skill") or "").strip() or None,
            "fallback_to_llm": bool(task.get("fallback_to_llm")),
            "generated_skill_path": str(task.get("generated_skill_path") or "").strip() or None,
            "generated_skill_status": str(task.get("generated_skill_status") or "").strip() or None,
            "promotion_success_count": int(task.get("promotion_success_count") or 0),
            "skill_generation_status": str(task.get("skill_generation_status") or "").strip() or None,
            "skill_generation_error": str(task.get("skill_generation_error") or "").strip() or None,
            "skill_generation_job_id": str(task.get("skill_generation_job_id") or "").strip() or None,
            "skill_generation_started_at": str(task.get("skill_generation_started_at") or "").strip() or None,
            "skill_generation_completed_at": str(task.get("skill_generation_completed_at") or "").strip() or None,
            "executor_rounds": int(task.get("rounds") or 0),
            "session_count": session_count,
            "event_count": event_count,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": duration_seconds,
            "token_total": _read_run_token_breakdown(run_root).get("total", 0),
            "input_tokens": _read_run_token_breakdown(run_root).get("input", 0),
            "output_tokens": _read_run_token_breakdown(run_root).get("output", 0),
        },
    }


async def _get_task_with_access(task_id: str, token: str) -> dict:
    task = _get_task_or_404(task_id)
    project_id = _normalize_project_id(task.get("project_id"))
    if project_id:
        await ensure_project_access(project_id, token)
    return task


def _submit_task(project_id: Optional[str], request: UnpackRequest) -> dict:
    if project_id and not _normalize_project_id(request.project_id):
        request.project_id = project_id
    _ensure_valid_request_payload(request)
    try:
        result = submit_unpack_task(
            firmware_path=request.firmware_path,
            project_id=project_id,
            llm_binding_snapshot={
                "agent_task_key": {
                    "id": request.agent_task_key_id,
                    "name": request.agent_task_key_name,
                    "prefix": request.agent_task_key_prefix,
                    "secret": request.agent_task_key_secret,
                    "source": request.agent_task_key_source,
                }
            } if any(
                value is not None for value in (
                    request.agent_task_key_id,
                    request.agent_task_key_name,
                    request.agent_task_key_prefix,
                    request.agent_task_key_secret,
                    request.agent_task_key_source,
                )
            ) else None,
            task_origin_type=request.task_origin_type,
            parent_project_id=request.parent_project_id,
            parent_task_id=request.parent_task_id,
            parent_task_type=request.parent_task_type,
            parent_stage_name=request.parent_stage_name,
            parent_stage_item_id=request.parent_stage_item_id,
            parent_stage_item_key=request.parent_stage_item_key,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    except Exception as exc:
        logger.exception("failed to submit firmware unpack task for project %s", project_id)
        raise InternalError("任务提交失败，请检查服务日志") from exc
    return {
        "task_id": result["task_id"],
        "status": "pending",
        "message": "任务已提交，请轮询任务状态接口获取进度。",
        "input_path": result.get("input_path"),
        "output_path": result.get("output_path"),
        "run_path": result.get("run_path"),
    }


def _list_tasks(
    project_id: Optional[str],
    status_filter: Optional[str],
    owner_id: Optional[str],
    origin_mode: Optional[str],
    search: Optional[str],
    limit: int,
    offset: int,
) -> dict:
    db = get_db_session()
    try:
        query = db.query(UnpackTask)
        if project_id:
            query = query.filter(UnpackTask.project_id == project_id)
        if status_filter:
            query = query.filter(UnpackTask.status == status_filter)
        if owner_id:
            query = query.filter(UnpackTask.owner_id == owner_id)
        normalized_origin_mode = str(origin_mode or "").strip().lower()
        if normalized_origin_mode == "manual":
            query = query.filter(
                or_(
                    UnpackTask.task_origin_type.is_(None),
                    UnpackTask.task_origin_type == "",
                    UnpackTask.task_origin_type == "manual",
                )
            )
        elif normalized_origin_mode == "linked":
            query = query.filter(
                and_(
                    UnpackTask.task_origin_type.is_not(None),
                    UnpackTask.task_origin_type != "",
                    UnpackTask.task_origin_type != "manual",
                )
            )
        if search:
            like_value = f"%{search}%"
            query = query.filter(
                or_(
                    UnpackTask.id.like(like_value),
                    UnpackTask.firmware_path.like(like_value),
                    UnpackTask.output_path.like(like_value),
                )
            )

        total = query.count()
        tasks = (
            query.options(
                load_only(
                    UnpackTask.id,
                    UnpackTask.project_id,
                    UnpackTask.task_origin_type,
                    UnpackTask.parent_project_id,
                    UnpackTask.parent_task_id,
                    UnpackTask.parent_task_type,
                    UnpackTask.parent_stage_name,
                    UnpackTask.parent_stage_item_id,
                    UnpackTask.parent_stage_item_key,
                    UnpackTask.firmware_path,
                    UnpackTask.output_path,
                    UnpackTask.status,
                    UnpackTask.owner_id,
                    UnpackTask.current_stage,
                    UnpackTask.lease_expires_at,
                    UnpackTask.cancel_requested_at,
                    UnpackTask.last_progress_at,
                    UnpackTask.runner_pid,
                    UnpackTask.runner_started_at,
                    UnpackTask.runner_heartbeat_at,
                    UnpackTask.cancel_grace_deadline,
                    UnpackTask.cancel_force_deadline,
                    UnpackTask.result_status,
                    UnpackTask.result_message,
                    UnpackTask.rounds,
                    UnpackTask.error_message,
                    UnpackTask.matched_skill,
                    UnpackTask.matched_skill_version,
                    UnpackTask.matched_skill_score,
                    UnpackTask.fallback_to_llm,
                    UnpackTask.generated_skill_path,
                    UnpackTask.generated_skill_status,
                    UnpackTask.promotion_success_count,
                    UnpackTask.skill_generation_status,
                    UnpackTask.skill_generation_error,
                    UnpackTask.skill_generation_job_id,
                    UnpackTask.skill_generation_started_at,
                    UnpackTask.skill_generation_completed_at,
                    UnpackTask.created_at,
                    UnpackTask.started_at,
                    UnpackTask.completed_at,
                )
            )
            .order_by(UnpackTask.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [task.to_dict() for task in tasks],
        }
    finally:
        db.close()


def _get_config_entries() -> dict:
    db = get_db_session()
    try:
        items = (
            db.query(ServiceConfig)
            .order_by(ServiceConfig.key.asc())
            .all()
        )
        return {
            "total": len(items),
            "items": [item.to_dict() for item in items],
        }
    finally:
        db.close()


def _update_config_entry(key: str, payload: ConfigUpdateRequest) -> dict:
    normalized_value = _normalize_runtime_config_value(key, payload.value)
    db = get_db_session()
    try:
        row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
        if row is None:
            row = ServiceConfig(
                key=key,
                value=normalized_value,
                value_type=_infer_value_type(normalized_value),
                description=payload.description,
            )
            db.add(row)
        else:
            row.value = normalized_value
            if payload.description is not None:
                row.description = payload.description
        db.commit()
        db.refresh(row)
        return row.to_dict()
    finally:
        db.close()


def _batch_update_config_entries(items: list[ConfigBatchUpdateItem]) -> dict:
    updated: list[dict] = []
    for item in items:
        updated.append(
            _update_config_entry(
                item.key,
                ConfigUpdateRequest(value=item.value, description=item.description),
            )
        )
    return {"total": len(updated), "items": updated}


def _list_tools() -> dict:
    items: list[dict] = []
    for meta in list_python_tools(TOOLS_DIR):
        family_id = str(meta.get("format_id") or meta.get("name") or "").strip()
        resolved_path = resolve_active_tool_target(Path(str(meta.get("path") or "")))
        manifest = read_family_manifest(TOOLS_STORE_DIR, family_id) if family_id else {}
        items.append(
            {
                "filename": str(meta.get("filename") or ""),
                "path": str(meta.get("path") or ""),
                "name": str(meta.get("name") or ""),
                "format_id": str(meta.get("format_id") or ""),
                "description": str(meta.get("description") or ""),
                "extensions": list(meta.get("extensions") or []),
                "magic_hex": str(meta.get("magic_hex") or ""),
                "keywords": list(meta.get("keywords") or []),
                "binwalk_sigs": list(meta.get("binwalk_sigs") or []),
                "skill_status": "python",
                "skill_version": parse_tool_version(resolved_path) or 1,
                "family_id": family_id,
                "promotion_success_count": 0,
                "promotion_threshold": 0,
                "store_path": str(resolved_path),
                "current_version": str(manifest.get("current_version") or "") or None,
            }
        )
    return {"total": len(items), "items": items}


def _list_llm_provider_summaries() -> dict:
    payload = get_configcenter_client().list_llm_providers()
    raw_items = payload.get("items") if isinstance(payload.get("items"), list) else []
    items: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "provider_key": str(item.get("provider_key") or "").strip(),
                "display_name": str(item.get("display_name") or "").strip(),
                "provider_type": str(item.get("provider_type") or "").strip(),
                "enabled": bool(item.get("enabled", False)),
                "is_default": bool(item.get("is_default", False)),
                "model": str(item.get("model") or "").strip(),
                "description": str(item.get("description") or "").strip() or None,
                "updated_at": str(item.get("updated_at") or "").strip() or None,
            }
        )
    return {
        "total": len(items),
        "default_provider_key": str(payload.get("default_provider_key") or "").strip() or None,
        "items": items,
    }


def _list_llm_config_file_summaries() -> dict:
    payload = get_configcenter_client().list_llm_config_files()
    raw_items = payload.get("items") if isinstance(payload.get("items"), list) else []
    items: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        model_options_raw = item.get("model_options") if isinstance(item.get("model_options"), list) else []
        items.append(
            {
                "config_file_key": str(item.get("config_file_key") or "").strip(),
                "display_name": str(item.get("display_name") or "").strip(),
                "provider_type": str(item.get("provider_type") or "").strip(),
                "enabled": bool(item.get("enabled", False)),
                "is_default": bool(item.get("is_default", False)),
                "default_model": str(item.get("default_model") or "").strip() or None,
                "description": str(item.get("description") or "").strip() or None,
                "updated_at": str(item.get("updated_at") or "").strip() or None,
                "model_options": [
                    {
                        "value": str(option.get("value") or "").strip(),
                        "label": str(option.get("label") or option.get("value") or "").strip(),
                        "source": str(option.get("source") or "").strip() or None,
                    }
                    for option in model_options_raw
                    if isinstance(option, dict) and str(option.get("value") or "").strip()
                ],
            }
        )
    return {"total": len(items), "items": items}


@router.get("/health", response_model=HealthResponse)
@router.get("/api/app/firmware-unpacker/health", response_model=HealthResponse)
async def health_check():
    runtime = runtime_snapshot()
    ready = bool(runtime.get("running")) and not bool(runtime.get("shutting_down")) and not str(runtime.get("startup_error") or "").strip()
    return {
        "status": "ok" if runtime.get("running") and not runtime.get("shutting_down") else "degraded",
        "owner_id": get_worker_id(),
        "service": "secflow-app-firmware-unpacker",
        "role": ",".join(runtime.get("roles") or []),
        "started_at": runtime.get("started_at"),
        "updated_at": now_local().isoformat(),
        "shutting_down": bool(runtime.get("shutting_down")),
        "startup_phase": "ready" if ready else ("stopping" if runtime.get("shutting_down") else "booting"),
        "liveness_ok": bool(runtime.get("running")) and not bool(runtime.get("shutting_down")),
        "readiness_ok": ready,
        "last_error": runtime.get("startup_error"),
        "reason": None if ready else (runtime.get("startup_error") or "runtime not ready"),
        "checks": {
            "registry": {"ok": bool(runtime.get("registry"))},
            "dispatcher": {"ok": bool(runtime.get("dispatcher"))},
            "worker_heartbeat": {"ok": bool(runtime.get("worker_heartbeat"))},
            "cluster_maintenance": {"ok": bool(runtime.get("cluster_maintenance"))},
            "cleanup_loop": {"ok": bool(runtime.get("cleanup_loop"))},
            "evolution_loop": {"ok": bool(runtime.get("evolution_loop"))},
        },
        **build_service_meta(),
    }


@router.get("/ready", response_model=ReadyResponse)
@router.get("/api/app/firmware-unpacker/ready", response_model=ReadyResponse)
async def ready_check():
    runtime = runtime_snapshot()
    ready = bool(runtime.get("running")) and not bool(runtime.get("shutting_down")) and not str(runtime.get("startup_error") or "").strip()
    return {
        "status": "ready" if ready else "not_ready",
        "owner_id": get_worker_id(),
        "service": "secflow-app-firmware-unpacker",
        "role": ",".join(runtime.get("roles") or []),
        "started_at": runtime.get("started_at"),
        "updated_at": now_local().isoformat(),
        "shutting_down": bool(runtime.get("shutting_down")),
        "last_error": runtime.get("startup_error"),
        "reason": None if ready else (runtime.get("startup_error") or "runtime not ready"),
    }


@router.get("/api/app/firmware-unpacker/cluster", response_model=ClusterInfoResponse)
async def get_cluster_info(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return get_cluster_snapshot()


@router.get("/api/app/firmware-unpacker/workers/cluster-capacity", response_model=ClusterInfoResponse)
@router.get("/api/app/firmware-unpacker/workers/cluster-capacity/summary", response_model=ClusterInfoResponse)
@router.get("/api/app/firmware-unpacker/workers/slot-cluster", response_model=ClusterInfoResponse)
async def get_worker_cluster_info(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return get_cluster_snapshot()


@router.post("/api/app/firmware-unpacker/workers/{worker_id}/drain", response_model=ActionResponse)
async def drain_worker(
    worker_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    success = request_worker_drain(worker_id, reason="api_request")
    if not success:
        raise NotFoundError("worker", worker_id)
    return {"message": "worker drain requested"}


@router.post("/api/app/firmware-unpacker/workers/reconcile", response_model=ActionResponse)
async def reconcile_workers(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    snapshot = get_cluster_snapshot()
    return {"message": f"reconciled {snapshot.get('total_workers', 0)} workers"}


@router.get("/api/app/firmware-unpacker/tasks/{task_id}/worker-runtime")
async def get_task_worker_runtime(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    task = _get_task_or_404(task_id)
    cluster = get_cluster_snapshot()
    worker_id = str(task.get("assigned_worker_id") or task.get("owner_id") or "").strip()
    worker = next((item for item in cluster.get("workers", []) if str(item.get("worker_id") or "") == worker_id), None)
    return {
        "task_id": task_id,
        "assigned_worker_id": worker_id or None,
        "assigned_pod_name": task.get("assigned_pod_name"),
        "dispatch_lease_expires_at": task.get("dispatch_lease_expires_at"),
        "run_lease_expires_at": task.get("run_lease_expires_at"),
        "worker": worker,
    }


@router.get("/api/app/firmware-unpacker/tasks/{task_id}/cleanup-scans", response_model=list[CleanupScanResponse])
async def list_task_cleanup_scans(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    db = get_db_session()
    try:
        rows = (
            db.query(TaskCleanupScan)
            .filter(TaskCleanupScan.task_id == task_id)
            .order_by(TaskCleanupScan.started_at.asc(), TaskCleanupScan.id.asc())
            .all()
        )
        return [row.to_dict() for row in rows]
    finally:
        db.close()


@router.get("/api/app/firmware-unpacker/tasks/{task_id}/cleanup-scans/{scan_id}", response_model=CleanupScanResponse)
async def get_task_cleanup_scan(
    task_id: str,
    scan_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    db = get_db_session()
    try:
        row = (
            db.query(TaskCleanupScan)
            .filter(TaskCleanupScan.id == scan_id, TaskCleanupScan.task_id == task_id)
            .first()
        )
        if row is None:
            raise NotFoundError("cleanup scan", scan_id)
        return row.to_dict()
    finally:
        db.close()


@router.get("/api/app/firmware-unpacker/config", response_model=ConfigListResponse)
async def get_runtime_config(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return _get_config_entries()


@router.get(
    "/api/app/firmware-unpacker/llm/providers",
    response_model=LlmProviderSummaryListResponse,
)
async def get_llm_provider_summaries(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return _list_llm_provider_summaries()


@router.get(
    "/api/app/firmware-unpacker/llm/config-files",
    response_model=LlmConfigFileSummaryListResponse,
)
async def get_llm_config_file_summaries(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return _list_llm_config_file_summaries()


@router.get("/api/app/firmware-unpacker/tools", response_model=ToolListResponse)
async def get_unpacker_tools(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return _list_tools()


@router.get("/api/app/firmware-unpacker/projects/{project_id}/runtime-files")
async def list_project_runtime_files(
    project_id: str,
    limit: int = Query(default=RUNTIME_FILE_LIST_LIMIT, ge=1, le=10000),
    root: Optional[str] = Query(default=None),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    return _list_runtime_root_files(limit, root)


@router.get("/api/app/firmware-unpacker/runtime-files")
async def list_runtime_files_legacy(
    project_id: Optional[str] = Query(default=None),
    limit: int = Query(default=RUNTIME_FILE_LIST_LIMIT, ge=1, le=10000),
    root: Optional[str] = Query(default=None),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    normalized_project_id = _normalize_project_id(project_id)
    if normalized_project_id:
        await ensure_project_access(normalized_project_id, token)
    return _list_runtime_root_files(limit, root)


@router.get("/api/app/firmware-unpacker/projects/{project_id}/runtime-files/content")
async def get_project_runtime_file_content(
    project_id: str,
    path: str = Query(...),
    root: Optional[str] = Query(default=None),
    max_bytes: int = Query(default=262144, ge=1, le=1048576),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    return _build_runtime_file_content_response(path, max_bytes, root)


@router.get("/api/app/firmware-unpacker/runtime-files/content")
async def get_runtime_file_content_legacy(
    path: str = Query(...),
    project_id: Optional[str] = Query(default=None),
    root: Optional[str] = Query(default=None),
    max_bytes: int = Query(default=262144, ge=1, le=1048576),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    normalized_project_id = _normalize_project_id(project_id)
    if normalized_project_id:
        await ensure_project_access(normalized_project_id, token)
    return _build_runtime_file_content_response(path, max_bytes, root)


@router.put(
    "/api/app/firmware-unpacker/config/{key}",
    response_model=ConfigEntryResponse,
)
async def update_runtime_config(
    key: str,
    request: ConfigUpdateRequest,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return _update_config_entry(key, request)


@router.post(
    "/api/app/firmware-unpacker/config/batch-update",
    response_model=ConfigListResponse,
)
async def batch_update_runtime_config(
    request: list[ConfigBatchUpdateItem],
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return _batch_update_config_entries(request)


@router.post(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks",
    response_model=TaskSubmitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_project_task(
    project_id: str,
    request: UnpackRequest,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    request_project_id = _normalize_project_id(request.project_id)
    if request_project_id and request_project_id != project_id:
        raise ValidationError("请求体中的 project_id 与路径参数不一致")

    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    return _submit_task(project_id, request)


@router.get(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks",
    response_model=TaskListResponse,
)
async def list_project_tasks(
    project_id: str,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    owner_id: Optional[str] = Query(default=None),
    origin_mode: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=10, le=1000),
    offset: int = Query(default=0, ge=0),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    return _list_tasks(project_id, status_filter, owner_id, origin_mode, search, limit, offset)


@router.get(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}",
    response_model=TaskResponse,
)
async def get_project_task(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    snapshot = task.get("llm_binding_snapshot")
    if isinstance(snapshot, str):
        try:
            snapshot = json.loads(snapshot)
        except Exception:
            snapshot = None
    return {
        **task,
        **_agent_runtime_payload_from_snapshot(snapshot if isinstance(snapshot, dict) else None),
    }


@router.get(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/events",
    response_model=TaskEventListResponse,
)
async def get_project_task_events(
    project_id: str,
    task_id: str,
    limit: int = Query(default=200, ge=1, le=200),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    return _get_task_events(task_id, limit)


@router.get(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/result",
    response_model=TaskResultResponse,
)
async def get_project_task_result(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    return _get_task_result(task_id)


@router.get(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/metrics",
    response_model=TaskMetricsResponse,
)
async def get_project_task_metrics(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    return _get_task_metrics(task_id)


@router.post(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/refresh-result-cache",
    response_model=ActionResponse,
)
async def refresh_project_task_result_cache(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    ok, message = request_task_result_cache_refresh(task_id)
    if not ok:
        raise ValidationError(message)
    return {"message": message, "task_id": task_id}


@router.post(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/evolution",
    response_model=EvolutionJobSubmitResponse,
)
async def create_project_task_evolution(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    try:
        return submit_evolution_job(task_id)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


@router.get(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/evolution-jobs",
    response_model=EvolutionJobListResponse,
)
async def list_project_task_evolution_jobs(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    items = list_evolution_jobs(task_id)
    return {"total": len(items), "items": items}


@router.delete(
    "/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}",
    response_model=ActionResponse,
)
async def delete_project_task(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    deleted_count, skipped_ids = delete_tasks([task_id])
    if deleted_count == 0:
        raise ForbiddenError("运行中的任务不能删除，请先取消")
    return {
        "message": "任务删除已受理，目录清理将在后台完成",
        "task_id": task_id,
        "deleted_count": deleted_count,
        "skipped_ids": skipped_ids,
    }


@router.post("/api/app/firmware-unpacker/unpack", response_model=TaskSubmitResponse)
async def submit_unpack_legacy(
    request: UnpackRequest,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    project_id = _normalize_project_id(request.project_id)
    if project_id:
        await ensure_project_access(project_id, token)
    return _submit_task(project_id, request)


@router.post(
    "/api/app/firmware-unpacker/tasks/{task_id}/evolution",
    response_model=EvolutionJobSubmitResponse,
)
async def create_task_evolution_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    try:
        return submit_evolution_job(task_id)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


@router.get(
    "/api/app/firmware-unpacker/projects/{project_id}/evolution-jobs",
    response_model=EvolutionJobListResponse,
)
async def list_project_evolution_jobs(
    project_id: str,
    status: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=10, le=1000),
    offset: int = Query(default=0, ge=0),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    return list_all_evolution_jobs(
        project_id=project_id,
        status=str(status or "").strip() or None,
        search=str(search or "").strip() or None,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/api/app/firmware-unpacker/tasks/{task_id}/evolution-jobs",
    response_model=EvolutionJobListResponse,
)
async def list_task_evolution_jobs_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    items = list_evolution_jobs(task_id)
    return {"total": len(items), "items": items}


@router.get(
    "/api/app/firmware-unpacker/evolution-jobs",
    response_model=EvolutionJobListResponse,
)
async def list_evolution_jobs_legacy(
    project_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=10, le=1000),
    offset: int = Query(default=0, ge=0),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    normalized_project_id = _normalize_project_id(project_id)
    if normalized_project_id:
        await ensure_project_access(normalized_project_id, token)
    payload = list_all_evolution_jobs(
        project_id=normalized_project_id,
        status=str(status or "").strip() or None,
        search=str(search or "").strip() or None,
        limit=limit,
        offset=offset,
    )
    if not normalized_project_id:
        filtered_items = []
        for item in payload.get("items", []):
            task = item.get("source_task") if isinstance(item, dict) else None
            task_project_id = _normalize_project_id((task or {}).get("project_id") if isinstance(task, dict) else item.get("project_id"))
            if task_project_id:
                await ensure_project_access(task_project_id, token)
            filtered_items.append(item)
        payload["items"] = filtered_items
        payload["total"] = len(filtered_items)
    return payload


@router.get(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}",
    response_model=EvolutionJobResponse,
)
async def get_evolution_job_legacy(
    job_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    return job


@router.get(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}/rounds",
    response_model=list[EvolutionRoundResponse],
)
async def list_evolution_rounds_legacy(
    job_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    return list_evolution_rounds(job_id)


@router.get(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}/sessions",
    response_model=EvolutionSessionIndexResponse,
)
async def get_evolution_sessions_legacy(
    job_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    payload = get_evolution_sessions(job_id)
    if payload is None:
        raise NotFoundError("进化任务会话", job_id)
    return payload


@router.get(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}/logs",
    response_model=TaskLogResponse,
)
async def get_evolution_logs_legacy(
    job_id: str,
    round: int = Query(default=1, ge=1),
    role: str = Query(default="tool_executor"),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    try:
        payload = get_evolution_log(job_id, round, role)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc
    if payload is None:
        raise NotFoundError("进化任务日志", job_id)
    return payload


@router.post(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}/cancel",
    response_model=ActionResponse,
)
async def cancel_evolution_job_legacy(
    job_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    try:
        return cancel_evolution_job(job_id)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


@router.post(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}/retry",
    response_model=ActionResponse,
)
async def retry_evolution_job_legacy(
    job_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    try:
        return retry_evolution_job(job_id)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


@router.delete(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}",
    response_model=ActionResponse,
)
async def delete_evolution_job_legacy(
    job_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    try:
        return delete_evolution_job(job_id)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


@router.post(
    "/api/app/firmware-unpacker/evolution-jobs/{job_id}/confirm-replacement",
    response_model=ActionResponse,
)
async def confirm_evolution_tool_replacement_legacy(
    job_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    job = get_evolution_job(job_id)
    if job is None:
        raise NotFoundError("进化任务", job_id)
    await _get_task_with_access(str(job.get("task_id") or ""), token)
    try:
        return confirm_evolution_tool_replacement(job_id)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


@router.get("/api/app/firmware-unpacker/tasks", response_model=TaskListResponse)
async def list_tasks_legacy(
    project_id: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    owner_id: Optional[str] = Query(default=None),
    origin_mode: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=10, le=1000),
    offset: int = Query(default=0, ge=0),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    normalized_project_id = _normalize_project_id(project_id)
    if normalized_project_id:
        await ensure_project_access(normalized_project_id, token)
    return _list_tasks(
        normalized_project_id,
        status_filter,
        owner_id,
        origin_mode,
        search,
        limit,
        offset,
    )


@router.get("/api/app/firmware-unpacker/tasks/{task_id}", response_model=TaskResponse)
async def get_task_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    return await _get_task_with_access(task_id, token)


@router.get(
    "/api/app/firmware-unpacker/tasks/{task_id}/resource-usage",
    response_model=TaskResourceUsageResponse,
)
async def get_task_resource_usage_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    return _get_task_resource_usage(task_id)


@router.get(
    "/api/app/firmware-unpacker/tasks/{task_id}/progress",
    response_model=TaskProgressResponse,
)
async def get_task_progress_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    return _get_task_progress(task_id)


@router.get(
    "/api/app/firmware-unpacker/tasks/{task_id}/events",
    response_model=TaskEventListResponse,
)
async def get_task_events_legacy(
    task_id: str,
    limit: int = Query(default=200, ge=1, le=200),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    return _get_task_events(task_id, limit)


@router.get(
    "/api/app/firmware-unpacker/tasks/{task_id}/result",
    response_model=TaskResultResponse,
)
async def get_task_result_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    return _get_task_result(task_id)


@router.get(
    "/api/app/firmware-unpacker/tasks/{task_id}/metrics",
    response_model=TaskMetricsResponse,
)
async def get_task_metrics_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    return _get_task_metrics(task_id)


@router.post(
    "/api/app/firmware-unpacker/tasks/{task_id}/refresh-result-cache",
    response_model=ActionResponse,
)
async def refresh_task_result_cache_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    ok, message = request_task_result_cache_refresh(task_id)
    if not ok:
        raise ValidationError(message)
    return {"message": message, "task_id": task_id}


@router.get(
    "/api/app/firmware-unpacker/tasks/{task_id}/logs",
    response_model=TaskLogResponse,
)
async def get_task_logs_legacy(
    task_id: str,
    phase: Optional[str] = Query(default=None),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    return _get_task_logs(task_id, phase)


@router.delete("/api/app/firmware-unpacker/tasks/{task_id}", response_model=ActionResponse)
async def delete_task_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    deleted_count, skipped_ids = delete_tasks([task_id])
    if deleted_count == 0:
        raise ForbiddenError("运行中的任务不能删除，请先取消")
    return {
        "message": "任务删除成功",
        "task_id": task_id,
        "deleted_count": deleted_count,
        "skipped_ids": skipped_ids,
    }


@router.post(
    "/api/app/firmware-unpacker/tasks/{task_id}/cancel",
    response_model=ActionResponse,
)
async def cancel_task_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    ok, message = cancel_task(task_id)
    if not ok:
        raise ValidationError(message)
    return {"message": message, "task_id": task_id}


@router.post(
    "/api/app/firmware-unpacker/tasks/{task_id}/retry",
    response_model=ActionResponse,
)
async def retry_task_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    ok, retried_task_id, message = retry_task(task_id)
    if not ok or not retried_task_id:
        raise ValidationError(message)
    return {
        "message": message,
        "task_id": retried_task_id,
    }


@router.post(
    "/api/app/firmware-unpacker/tasks/batch-delete",
    response_model=ActionResponse,
)
async def batch_delete_task_legacy(
    request: BatchDeleteRequest,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    for task_id in request.task_ids:
        await _get_task_with_access(task_id, token)
    deleted_count, skipped_ids = delete_tasks(request.task_ids)
    return {
        "message": "批量删除已受理，目录清理将在后台完成",
        "deleted_count": deleted_count,
        "skipped_ids": skipped_ids,
    }
