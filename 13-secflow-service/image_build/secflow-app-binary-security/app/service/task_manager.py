"""Binary Security task orchestration manager."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import logging
import os
import re
import shutil
import tarfile
import time
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import func, or_, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, load_only

from app.config import get_config
from app.exception import ConflictError, NotFoundError, ValidationError
from app.model import (
    STAGE_SEQUENCE,
    TASK_TERMINAL_STATUSES,
    TASK_STAGE_SEQUENCES,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
    BinarySecurityEvent,
    BinarySecurityArchiveJob,
    BinarySecurityProjectConfig,
    BinarySecurityServiceConfig,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityStateEvent,
    BinarySecurityTask,
    BinarySecurityTaskStateLease,
    build_archive_job_dedupe_key,
    build_stage_item_identity_key,
    get_engine,
    get_session_factory,
)
from app.observability import (
    observe_archive_action,
    observe_archive_duration,
    observe_archive_job_statuses,
    observe_downstream_reconcile_observation,
    observe_heartbeat_update,
    observe_queue_depths,
    observe_scheduler_loop,
    observe_slot_usage,
    observe_stage_duration,
    observe_state_dead_letter,
    observe_state_event,
    observe_state_event_lag,
    observe_state_event_queues,
    observe_state_file_write,
    observe_state_reducer_event,
    observe_state_reducer_run,
    observe_task_state_lock,
    observe_task_duration,
    observe_task_error,
    observe_task_lifecycle,
    observe_task_operation,
    observe_worker_counts,
)
from app.schemas import (
    BinarySecurityActionResponse,
    BinarySecurityArchiveJobResponse,
    BinarySecurityArtifactsResponse,
    BinarySecurityInputFile,
    BinarySecurityModuleSelectionResponse,
    BinarySecurityOverviewArchiveDetail,
    BinarySecurityOverviewBusinessDetail,
    BinarySecurityOverviewNode,
    BinarySecurityProjectStageAggregate,
    BinarySecurityProjectStats,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityServiceConfigPayload,
    BinarySecurityServiceConfigResponse,
    BinarySecurityStageItemResponse,
    BinarySecurityStageSummary,
    BinarySecurityTaskCreate,
    BinarySecurityTaskConcurrencyUpdatePayload,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskEventResponse,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskPolicyUpdatePayload,
    BinarySecurityTaskResponse,
    BinarySecurityTimelineResponse,
    BinarySecurityUploadCompletePayload,
)
from app.service.binary_to_source import get_binary_to_source_client
from app.service.dataflow_analyse import get_dataflow_analyse_client
from app.service.dataflow_vuln_scanner import get_dataflow_vuln_scanner_client
from app.service.entry_analyse import get_entry_analyse_client
from app.service.fileserver import get_fileserver_client
from app.service.firmware_unpacker import get_firmware_unpacker_client
from app.service.security import app_task_root, ensure_dir, validate_task_id
from app.service.system_analyse import get_system_analyse_client
from app.service.task_queue import get_task_queue
from app.time_utils import now_local

logger = logging.getLogger(__name__)

DB_SUMMARY_ITEM_LIMIT = 50
DB_FAILURE_ITEM_LIMIT = 20
DB_ENTRY_PREVIEW_LIMIT = 50
DB_ARTIFACT_PREVIEW_LIMIT = 50


def _now() -> datetime:
    return now_local()


def _isoformat_or_none(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _elapsed_seconds_since(value: datetime | None) -> float | None:
    """Return elapsed seconds for naive DB datetimes across UTC/UTC+8 writers.

    Older rows may have been written as UTC naive values while newer code writes
    UTC+8 naive values. Calculate both interpretations and use the smallest
    non-negative age so fresh locks are not reclaimed early and stale locks can
    still expire.
    """
    if value is None:
        return None
    candidates = [
        (_now() - value).total_seconds(),
        (datetime.utcnow() - value).total_seconds(),
    ]
    non_negative = [age for age in candidates if age >= 0]
    if non_negative:
        return min(non_negative)
    return max(candidates)


def _seconds_until(value: datetime | None) -> float | None:
    if value is None:
        return None
    candidates = [
        (value - _now()).total_seconds(),
        (value - datetime.utcnow()).total_seconds(),
    ]
    non_negative = [remaining for remaining in candidates if remaining >= 0]
    if non_negative:
        # Prefer the smallest non-negative interpretation so UTC+8 naive values
        # do not incorrectly look fresh for ~8 extra hours when compared using
        # datetime.utcnow().
        return min(non_negative)
    return min(candidates)


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value or "").strip("-")
    return cleaned[:120] or uuid.uuid4().hex[:12]


def _normalize_entry_function_name(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    matches = re.findall(r"([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\(", raw)
    if matches:
        return matches[-1]
    return raw


def _entry_signature_params(entry: dict[str, Any]) -> list[str]:
    raw_params = (
        entry.get("signature_params")
        or entry.get("parameters")
        or entry.get("params")
        or entry.get("input_params")
        or []
    )
    params: list[str] = []
    if isinstance(raw_params, list):
        for value in raw_params:
            if isinstance(value, dict):
                candidate = value.get("name") or value.get("param") or value.get("parameter")
            else:
                candidate = value
            name = _normalize_parameter_name(candidate)
            if name:
                params.append(name)
    if not params:
        signature = str(
            entry.get("raw_function_name")
            or entry.get("function_signature")
            or entry.get("signature")
            or entry.get("function")
            or entry.get("function_name")
            or ""
        )
        params.extend(_parse_signature_param_names(signature))
    return _deduplicate_strings(params)


def _parse_signature_param_names(signature: str) -> list[str]:
    match = re.search(r"\((.*)\)", signature or "")
    if not match:
        return []
    return [_normalize_parameter_name(part) for part in _split_signature_params(match.group(1)) if _normalize_parameter_name(part)]


def _split_signature_params(raw: str) -> list[str]:
    params: list[str] = []
    current: list[str] = []
    depth = 0
    for char in raw:
        if char in "([{<":
            depth += 1
        elif char in ")]}>" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            params.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        params.append("".join(current).strip())
    return params


def _default_entry_function_description(function_name: str) -> str:
    fn = function_name.strip() or "该函数"
    return f"{fn} 是当前识别到的外部入口函数，具体职责需结合源码进一步确认。"


def _default_entry_reason(tag: str, function_name: str) -> str:
    fn = function_name.strip() or "该函数"
    if str(tag or "").strip().upper() == "A":
        return f"{fn} 被判定为主动拉取型入口，函数内部存在外部输入读取或接收行为。"
    return f"{fn} 被判定为被动回调型入口，参数中携带来自外部的可控输入。"


def _entry_description_source(raw_value: object) -> str:
    return "agent" if str(raw_value or "").strip() else "default"


def _normalize_entry_taint_details(entry: dict[str, Any], taint_params: list[str]) -> list[dict[str, Any]]:
    raw_details = entry.get("taint_details") or entry.get("taint_descriptions") or []
    detail_map: dict[str, dict[str, Any]] = {}

    if isinstance(raw_details, dict):
        for raw_name, raw_value in raw_details.items():
            name = str(raw_name or "").strip()
            if not name:
                continue
            if isinstance(raw_value, dict):
                description = str(raw_value.get("description") or "").strip()
                source_kind = str(raw_value.get("source_kind") or "").strip()
            else:
                description = str(raw_value or "").strip()
                source_kind = ""
            detail_map[name] = {
                "name": name,
                "description": description,
                "description_source": "agent" if description else "default",
                **({"source_kind": source_kind} if source_kind else {}),
            }
    elif isinstance(raw_details, list):
        for raw_item in raw_details:
            if not isinstance(raw_item, dict):
                continue
            name = str(raw_item.get("name") or raw_item.get("taint") or raw_item.get("param") or "").strip()
            if not name:
                continue
            description = str(raw_item.get("description") or raw_item.get("summary") or "").strip()
            source_kind = str(raw_item.get("source_kind") or "").strip()
            detail_map[name] = {
                "name": name,
                "description": description,
                "description_source": "agent" if description else "default",
                **({"source_kind": source_kind} if source_kind else {}),
            }

    normalized: list[dict[str, Any]] = []
    for taint in taint_params:
        item = dict(detail_map.get(taint) or {})
        item["name"] = taint
        if not str(item.get("description") or "").strip():
            item["description"] = f"参数 `{taint}` 被识别为外部可控污点，需要在下游继续追踪其传播与使用。"
            item["description_source"] = "default"
        source_kind = str(item.get("source_kind") or "").strip()
        if source_kind:
            item["source_kind"] = source_kind
        else:
            item.pop("source_kind", None)
        normalized.append(item)
    return normalized


def _normalize_parameter_name(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw or raw.lower() in {"void", "..."}:
        return ""
    raw = raw.split("=", 1)[0].strip()
    raw = raw.split(":", 1)[0].strip()
    raw = re.sub(r"\[[^\]]*\]", "", raw).strip()
    raw = raw.replace("*", " ").replace("&", " ")
    tokens = [token for token in re.split(r"\s+", raw) if token]
    if not tokens:
        return ""
    candidate = tokens[-1]
    match = re.search(r"([A-Za-z_]\w*)$", candidate)
    return match.group(1) if match else ""


def _deduplicate_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _entry_key_with_suffix(base_key: str, suffix_source: Any, fallback_index: int) -> str:
    suffix = _slug(str(suffix_source or fallback_index))[:32]
    if not suffix:
        suffix = str(fallback_index)
    max_base_len = max(1, 119 - len(suffix))
    return f"{base_key[:max_base_len].rstrip('-')}-{suffix}"


def _deduplicate_entry_keys(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep legacy entry keys unless a module produces colliding function/line keys."""
    buckets: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, entry in enumerate(entries):
        buckets.setdefault(str(entry.get("entry_key") or ""), []).append((index, entry))

    used: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        current = dict(entry)
        base_key = str(current.get("entry_key") or "")
        bucket = buckets.get(base_key) or []
        if base_key and len(bucket) == 1 and base_key not in used:
            used.add(base_key)
            deduped.append(current)
            continue

        suffix_source = (
            current.get("raw_function_name")
            or current.get("function_qualifier")
            or current.get("file_name")
            or current.get("function_name")
            or index
        )
        candidate = _entry_key_with_suffix(base_key or _slug(str(suffix_source)), suffix_source, index + 1)
        attempt = 2
        while candidate in used:
            candidate = _entry_key_with_suffix(base_key or _slug(str(suffix_source)), f"{suffix_source}-{attempt}", index + 1)
            attempt += 1
        current["entry_key"] = candidate
        used.add(candidate)
        deduped.append(current)
    return deduped


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def _copytree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    if src.is_symlink():
        ensure_dir(dst.parent)
        if dst.exists() or dst.is_symlink():
            if dst.is_dir() and not dst.is_symlink():
                shutil.rmtree(dst)
            else:
                dst.unlink()
        os.symlink(os.readlink(src), dst)
        return
    if src.is_file():
        ensure_dir(dst.parent)
        shutil.copy2(src, dst, follow_symlinks=False)
        return
    shutil.copytree(
        src,
        dst,
        dirs_exist_ok=True,
        symlinks=True,
        ignore_dangling_symlinks=True,
    )


def _copytree_best_effort(src: Path, dst: Path, *, error_limit: int = 200) -> dict[str, Any]:
    stats: dict[str, Any] = {
        "copied_files": 0,
        "copied_dirs": 0,
        "copied_symlinks": 0,
        "skipped_errors": 0,
        "errors": [],
    }

    def record_error(source: Path, target: Path, exc: BaseException) -> None:
        stats["skipped_errors"] += 1
        if len(stats["errors"]) < error_limit:
            stats["errors"].append(
                {
                    "source": str(source),
                    "target": str(target),
                    "error": str(exc),
                }
            )

    def copy_one(source: Path, target: Path) -> None:
        try:
            if source.is_symlink():
                ensure_dir(target.parent)
                if target.exists() or target.is_symlink():
                    if target.is_dir() and not target.is_symlink():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                os.symlink(os.readlink(source), target)
                stats["copied_symlinks"] += 1
                return
            if source.is_file():
                ensure_dir(target.parent)
                shutil.copy2(source, target, follow_symlinks=False)
                stats["copied_files"] += 1
                return
            if source.is_dir():
                ensure_dir(target)
                stats["copied_dirs"] += 1
        except Exception as exc:
            record_error(source, target, exc)

    if not src.exists() and not src.is_symlink():
        return stats
    if src.is_file() or src.is_symlink():
        copy_one(src, dst)
        return stats

    ensure_dir(dst)
    for current_root, dirnames, filenames in os.walk(src, followlinks=False):
        current_path = Path(current_root)
        try:
            relative_root = current_path.relative_to(src)
        except ValueError:
            relative_root = Path()
        target_root = dst / relative_root
        ensure_dir(target_root)
        for dirname in list(dirnames):
            source_dir = current_path / dirname
            target_dir = target_root / dirname
            copy_one(source_dir, target_dir)
            if source_dir.is_symlink():
                dirnames.remove(dirname)
        for filename in filenames:
            source_file = current_path / filename
            target_file = target_root / filename
            copy_one(source_file, target_file)
    return stats


def _path_has_content(path: Path) -> bool:
    if path.is_file():
        return True
    if not path.is_dir():
        return False
    return any(path.iterdir())


def _count_files(path: Path) -> int:
    if path.is_file():
        return 1
    if not path.is_dir():
        return 0
    return sum(1 for child in path.rglob("*") if child.is_file())


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    started = time.perf_counter()
    target = path.name or "json"
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        observe_state_file_write(target=target, result="success", duration_seconds=time.perf_counter() - started)
    except Exception:
        observe_state_file_write(target=target, result="failed", duration_seconds=time.perf_counter() - started)
        raise
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass


def _is_within_path(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _stage_item_attr(item: Any, field: str) -> Any:
    if item is None:
        return None
    if isinstance(item, dict):
        return item.get(field)
    state = getattr(item, "__dict__", None) or {}
    if field in state:
        return state.get(field)
    try:
        return getattr(item, field)
    except Exception:
        return None


def _downstream_origin_payload(task: BinarySecurityTask, item: BinarySecurityStageItem) -> dict[str, Any]:
    return {
        "task_origin_type": "binary_security",
        "parent_project_id": task.project_id,
        "parent_task_id": task.id,
        "parent_task_type": task.task_type,
        "parent_stage_name": _stage_item_attr(item, "stage_name"),
        "parent_stage_item_id": _stage_item_attr(item, "id"),
        "parent_stage_item_key": _stage_item_attr(item, "item_key"),
    }


def _normalize_module_risk_levels(values: list[str] | None) -> list[str]:
    ordered: list[str] = []
    for value in values or []:
        normalized = str(value or "").strip()
        if normalized in ALLOWED_MODULE_RISK_LEVELS and normalized not in ordered:
            ordered.append(normalized)
    return ordered or ["高"]


NO_CANDIDATE_MODULES_FAILURE_CODE = "no_candidate_modules"
NO_CANDIDATE_MODULES_FAILURE_CATEGORY = "business"
NO_CANDIDATE_MODULES_FAILURE_MESSAGE = "系统分析已完成，但未发现匹配所选风险等级的风险模块"


def _no_candidate_modules_failure() -> dict[str, str]:
    return {
        "failure_code": NO_CANDIDATE_MODULES_FAILURE_CODE,
        "failure_category": NO_CANDIDATE_MODULES_FAILURE_CATEGORY,
        "failure_message": NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
        "error": NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
    }


STAGE_RETRY_ALLOWED_STATUSES = {"success", "failed", "partial_success", "cancelled"}
STAGE_RETRY_BLOCKED_TASK_STATUSES = {"pending", "dispatching", "running", "pending_upload", "uploading", "ready_to_start"}
TASK_STATUS_PENDING_MODULE_CONFIRMATION = "pending_module_confirmation"
TASK_STATUS_CONTINUE_PREPARING = "continue_preparing"
TASK_STATUS_RETRY_PREPARING = "retry_preparing"
TASK_PREPARING_STATUSES = {TASK_STATUS_CONTINUE_PREPARING, TASK_STATUS_RETRY_PREPARING}
TASK_ACTION_CONTINUE = "continue"
TASK_ACTION_RETRY = "retry"
TASK_ACTION_RETRY_FAILED_ITEMS = "retry_failed_items"
TASK_ACTION_RETRY_STAGE_FAILED_ITEMS = "retry_stage_failed_items"
TASK_ACTION_RETRY_STAGE_FULL = "retry_stage_full"
TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS = "retry_archive_failed_items"
TASK_ACTION_RETRY_ARCHIVE_FULL = "retry_archive_full"
TASK_PENDING_ACTIONS = {
    TASK_ACTION_CONTINUE,
    TASK_ACTION_RETRY,
    TASK_ACTION_RETRY_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FULL,
    TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
    TASK_ACTION_RETRY_ARCHIVE_FULL,
}
TASK_OPERATION_LOCK_TTL_SECONDS = 1800
TASK_OPERATION_LOCK_HEARTBEAT_SECONDS = 20
STATE_EVENT_LEASE_SECONDS = 120
TASK_STATE_LEASE_SECONDS = 300
STATE_EVENT_MAX_ATTEMPTS = 5
MODULE_SELECTION_MODE_AUTO = "auto"
MODULE_SELECTION_MODE_MANUAL_CONFIRM = "manual_confirm"
ALLOWED_MODULE_RISK_LEVELS = ("高", "中", "低")
STAGE_SUMMARY_RESULT_KEYS = {
    "firmware_unpack": ["firmware_unpack_results"],
    "system_analysis": ["system_analysis_results", "high_risk_modules", "system_analysis_modules", "candidate_modules", "selected_modules"],
    "binary_to_source": ["b2s_results"],
    "entry_analysis": ["entry_results"],
    "dataflow_analysis": ["dataflow_results"],
    "vuln_scan": ["vuln_results"],
}
STAGE_METRIC_RESETTERS = {
    "firmware_unpack": {"unpacked_firmware_count": 0, "failed_firmware_count": 0},
    "system_analysis": {
        "high_risk_module_count": 0,
        "medium_risk_module_count": 0,
        "low_risk_module_count": 0,
        "candidate_module_count": 0,
        "selected_module_count": 0,
    },
    "entry_analysis": {"entry_count": 0},
    "vuln_scan": {"vuln_result_count": 0},
}
STAGE_TITLES = {
    "firmware_unpack": "固件解包",
    "system_analysis": "系统分析",
    "binary_to_source": "二进制逆向",
    "entry_analysis": "入口分析",
    "dataflow_analysis": "数据流分析",
    "vuln_scan": "漏洞扫描",
}

FAILED_ITEM_RETRYABLE_STATUSES = {"failed", "cancelled", "downstream_missing", "pending", "queued", "running", "dispatching"}
ARCHIVE_ACTIVE_STATUSES = {"pending", "running", "archived", "applying"}
ARCHIVE_SUCCESS_MAPPED_STATUSES = {"success", "partial_success"}


def _preparing_status_for_action(action: str) -> str:
    return TASK_STATUS_CONTINUE_PREPARING if action == TASK_ACTION_CONTINUE else TASK_STATUS_RETRY_PREPARING


def _retry_mode_needs_plan(mode: str | None) -> bool:
    return bool(mode in {"task_retry_failed_items", "stage_retry_failed_items", "stage_retry_full"})
STAGE_RETRY_ENDPOINTS = {
    "firmware_unpack": ("firmware_unpacker", "retry"),
    "system_analysis": ("system_analyse", "restart"),
    "binary_to_source": ("binary_to_source", "retry"),
    "entry_analysis": ("entry_analyse", "restart"),
    "dataflow_analysis": ("dataflow_analyse", "restart"),
    "vuln_scan": ("dataflow_vuln_scanner", "retry"),
}
SOURCE_TASK_INPUT_KEY = "source_project"
SERVICE_OUTPUT_FOLDERS = {
    "firmware_unpacker": "firmware-unpacker",
    "system_analyse": "system-analyse",
    "binary_to_source": "binary-to-source",
    "entry_analyse": "entry-analyse",
    "dataflow_analyse": "dataflow-analyse",
    "dataflow_vuln_scanner": "dataflow-vuln-scanner",
}
STAGE_OUTPUT_SERVICES = {
    "firmware_unpack": ["firmware_unpacker"],
    "system_analysis": ["system_analyse"],
    "binary_to_source": ["binary_to_source"],
    "entry_analysis": ["entry_analyse"],
    "dataflow_analysis": ["dataflow_analyse"],
    "vuln_scan": ["dataflow_vuln_scanner"],
}
DOWNSTREAM_APP_ROOTS = {
    "firmware_unpacker": "secflow-app-firmware-unpacker",
    "system_analyse": "secflow-app-system-analyse",
    "binary_to_source": "secflow-app-binary-to-source",
    "entry_analyse": "secflow-app-entry-analyse",
    "dataflow_analyse": "secflow-app-dataflow-analyse",
    "dataflow_vuln_scanner": "secflow-app-dataflow-vuln-scanner",
}
SOURCE_ARCHIVE_FORMATS = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
PARTIAL_SUCCESS_ADVANCEMENT_STAGES = (
    "binary_to_source",
    "entry_analysis",
    "dataflow_analysis",
)
DEFAULT_PARTIAL_SUCCESS_STAGE_ADVANCEMENT = {
    stage_name: False for stage_name in PARTIAL_SUCCESS_ADVANCEMENT_STAGES
}


class StaleTaskExecution(RuntimeError):
    """Raised when a stale task worker observes that its dispatch token is no longer current."""


class TaskManager:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.instance_id = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME") or f"binary-security-{uuid.uuid4().hex[:12]}"
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._archive_loop_task: Optional[asyncio.Task] = None
        self._downstream_reconcile_task: Optional[asyncio.Task] = None
        self._action_loop_task: Optional[asyncio.Task] = None
        self._state_reducer_loop_task: Optional[asyncio.Task] = None
        self._workers: dict[str, asyncio.Task] = {}
        self._action_workers: dict[str, asyncio.Task] = {}
        self._archive_workers: set[asyncio.Task] = set()
        self._worker_lock = asyncio.Lock()
        self._action_worker_lock = asyncio.Lock()
        self._archive_worker_lock = asyncio.Lock()
        self._last_task_heartbeat_at: dict[str, datetime] = {}
        self._last_queue_reconcile_at: datetime | None = None

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        observe_worker_counts(task_workers=0, action_workers=0, archive_workers=0)
        role = str(os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or "all").strip().lower()
        run_worker_loops = role in {"", "all", "worker"}
        run_reducer_loop = role in {"", "all", "reducer"}
        if run_worker_loops:
            self._loop_task = asyncio.create_task(self._dispatch_loop(), name="binary-security-dispatcher")
            self._archive_loop_task = asyncio.create_task(self._archive_dispatch_loop(), name="binary-security-archive-dispatcher")
            self._action_loop_task = asyncio.create_task(
                self._blocking_action_dispatch_loop(),
                name="binary-security-blocking-action-dispatcher",
            )
            self._downstream_reconcile_task = asyncio.create_task(
                self._downstream_reconcile_loop(),
                name="binary-security-downstream-reconcile",
            )
        if run_reducer_loop:
            self._state_reducer_loop_task = asyncio.create_task(
                self._state_reducer_loop(),
                name="binary-security-state-reducer",
            )
        if run_worker_loops:
            await self._seed_work_queues()

    async def stop(self) -> None:
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        if self._archive_loop_task:
            self._archive_loop_task.cancel()
            try:
                await self._archive_loop_task
            except asyncio.CancelledError:
                pass
        if self._action_loop_task:
            self._action_loop_task.cancel()
            try:
                await self._action_loop_task
            except asyncio.CancelledError:
                pass
        if self._downstream_reconcile_task:
            self._downstream_reconcile_task.cancel()
            try:
                await self._downstream_reconcile_task
            except asyncio.CancelledError:
                pass
        if self._state_reducer_loop_task:
            self._state_reducer_loop_task.cancel()
            try:
                await self._state_reducer_loop_task
            except asyncio.CancelledError:
                pass
        archive_active = list(self._archive_workers)
        for task in archive_active:
            task.cancel()
        if archive_active:
            await asyncio.gather(*archive_active, return_exceptions=True)
        active = list(self._workers.values())
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
        action_active = list(self._action_workers.values())
        for task in action_active:
            task.cancel()
        if action_active:
            await asyncio.gather(*action_active, return_exceptions=True)
        observe_worker_counts(task_workers=0, action_workers=0, archive_workers=0)

    def prepare_task_id(self, db: Session, project_id: str) -> str:
        for _ in range(10):
            task_id = uuid.uuid4().hex[:16]
            exists = db.query(BinarySecurityTask.id).filter(
                BinarySecurityTask.project_id == project_id,
                BinarySecurityTask.id == task_id,
            ).first()
            if not exists:
                return task_id
        raise ValidationError("无法生成唯一任务 ID，请重试")

    def _task_type(self, task: BinarySecurityTask | str | None) -> str:
        raw = task if isinstance(task, str) else getattr(task, "task_type", None)
        return raw if raw in TASK_STAGE_SEQUENCES else TASK_TYPE_BINARY

    def _stage_sequence_for_task(self, task: BinarySecurityTask | str | None) -> list[str]:
        return list(TASK_STAGE_SEQUENCES[self._task_type(task)])

    def _validate_task_type(self, task_type: str | None) -> str:
        normalized = str(task_type or TASK_TYPE_BINARY).strip().lower()
        if normalized not in TASK_STAGE_SEQUENCES:
            raise ValidationError(f"不支持的任务类型: {task_type}")
        return normalized

    async def create_task(
        self,
        db: Session,
        *,
        project_id: str,
        payload: BinarySecurityTaskCreate,
        created_by: str,
        authorization_token: str,
    ) -> BinarySecurityTaskDetailResponse:
        task_id = validate_task_id(payload.task_id) if payload.task_id else self.prepare_task_id(db, project_id)
        task_type = self._validate_task_type(payload.task_type)
        if db.query(BinarySecurityTask.id).filter(
            BinarySecurityTask.project_id == project_id,
            BinarySecurityTask.id == task_id,
        ).first():
            raise ValidationError("任务 ID 已存在")
        self._validate_and_normalize_partial_success_stage_advancement_overrides(
            payload.policy_overrides.partial_success_stage_advancement,
            task_type=task_type,
        )
        input_files = self._normalize_input_files(payload.input_files, task_type=task_type)
        workspace_root = app_task_root(project_id, task_id)
        output_root = self._resolve_output_root(workspace_root, payload.output_root)
        input_dir = workspace_root / "input"
        run_dir = workspace_root / "run"
        await self._init_workspace_async(workspace_root)
        await self._ensure_task_directories(project_id, task_id, authorization_token)
        metadata_path = input_dir / "task-metadata.json"
        policy_overrides = payload.policy_overrides.model_dump(exclude_none=True)
        policy_overrides["task_type"] = task_type
        policy = self._merge_policy(db, project_id, policy_overrides, payload.stage_options)

        task = BinarySecurityTask(
            id=task_id,
            project_id=project_id,
            task_type=task_type,
            name=payload.name,
            description=payload.description,
            created_by=created_by,
            status="pending_upload",
            current_stage=None,
            firmware_name=f"{len(input_files)} files",
            firmware_source="project_filesystem",
            firmware_path=str(input_dir),
            output_root=str(output_root),
            workspace_root=str(workspace_root),
        )
        task.policy = policy
        task.summary = {
            "fileserver_project_path": str(workspace_root),
            "task_root_path": str(workspace_root),
            "input_dir": str(input_dir),
            "output_dir": str(output_root),
            "run_dir": str(run_dir),
            "temp_upload_dir": str(run_dir / "upload-tmp") if task_type == TASK_TYPE_SOURCE else None,
            "input_manifest_path": str(metadata_path),
            "input_files": input_files,
            "input_kind": "source_archives" if task_type == TASK_TYPE_SOURCE else "firmware_files",
            "downstream_task_ids": {},
            "system_analysis_modules": [],
            "candidate_modules": [],
            "selected_modules": [],
        }
        task.metrics = {
            "high_risk_module_count": 0,
            "medium_risk_module_count": 0,
            "low_risk_module_count": 0,
            "candidate_module_count": 0,
            "selected_module_count": 0,
            "entry_count": 0,
            "vuln_result_count": 0,
            "input_file_count": len(input_files),
            "uploaded_file_count": 0,
            "input_total_bytes": int(sum(int(item.get("size") or 0) for item in input_files)),
            "firmware_item_count": len(input_files),
            "unpacked_firmware_count": 0,
            "failed_firmware_count": 0,
        }
        task.stage_summary = {}
        db.add(task)
        db.commit()
        await self._write_task_metadata_async(task, metadata_path, status="pending_upload")
        self._record_event(db, task, "task_created", f"创建任务 {task.id}", payload={"input_files": input_files})
        self._record_event(db, task, "task_upload_pending", "任务创建完成，等待上传文件")
        observe_task_lifecycle("created", status=task.status, task_type=self._task_type(task))
        db.commit()
        return self.get_task_detail(db, project_id=project_id, task_id=task.id)

    async def complete_uploads(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityUploadCompletePayload,
        updated_by: str,
        authorization_token: str,
    ) -> BinarySecurityTaskDetailResponse:
        del updated_by, authorization_token
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"pending_upload", "uploading", "ready_to_start"}:
            raise ValidationError(f"当前状态不允许确认上传完成: {task.status}")
        declared = self._normalize_input_files(
            payload.files or [BinarySecurityInputFile(**item) for item in task.summary.get("input_files") or []],
            task_type=self._task_type(task),
        )
        input_dir = Path(task.workspace_root) / "input"
        self._record_event(db, task, "task_upload_started", "开始校验上传文件")
        if self._task_type(task) == TASK_TYPE_SOURCE:
            actual_files, total_bytes, extracted_count = await self._materialize_source_archives(task, declared)
            self._record_event(
                db,
                task,
                "source_archives_extracted",
                "源码压缩包已解压到任务输入目录",
                payload={"archive_count": len(actual_files), "extracted_file_count": extracted_count},
            )
        else:
            actual_files = []
            total_bytes = 0
            for file_info in declared:
                filename = str(file_info["filename"])
                relative_path = str(file_info.get("relative_path") or filename).strip().replace("\\", "/")
                local_path = input_dir / relative_path
                if not await asyncio.to_thread(local_path.is_file):
                    raise ValidationError(f"上传文件缺失: {relative_path}")
                stat = await asyncio.to_thread(local_path.stat)
                self._validate_uploaded_archive_size(filename, stat.st_size, source_task=False)
                self._check_storage_free_space(required_bytes=stat.st_size)
                total_bytes += stat.st_size
                actual_files.append(
                    {
                        **file_info,
                        "size": stat.st_size,
                        "uploaded": True,
                        "path": f"{task.summary.get('input_dir')}/{relative_path}",
                    }
                )
        task.status = "ready_to_start"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        task.summary = {
            **task.summary,
            "input_files": actual_files,
        }
        task.metrics = {
            **task.metrics,
            "input_file_count": len(actual_files),
            "uploaded_file_count": len(actual_files),
            "input_total_bytes": total_bytes,
            "firmware_item_count": len(actual_files),
        }
        await self._write_task_metadata_async(task, input_dir / "task-metadata.json", status="ready_to_start")
        self._record_event(db, task, "task_upload_completed", "输入文件上传完成", payload={"uploaded_files": len(actual_files)})
        self._record_event(db, task, "task_ready_to_start", "任务已就绪，准备自动启动")
        db.commit()
        return self.start_task(db, project_id=project_id, task_id=task_id)

    def start_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"ready_to_start", "failed", "partial_success"}:
            if task.status in {"pending", "running"}:
                return self.get_task_detail(db, project_id=project_id, task_id=task_id)
            raise ValidationError(f"当前状态不允许启动任务: {task.status}")
        input_files = task.summary.get("input_files") or []
        if not input_files:
            raise ValidationError("没有可用的输入文件")
        task.status = "pending"
        task.current_stage = self._stage_sequence_for_task(task)[0]
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        task.started_at = None
        task.finished_at = None
        task.summary = {
            **task.summary,
            "stale_stages": [],
            "stale_reason": None,
            "stale_from_stage": None,
            "stage_retry_context": {},
        }
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
        self._record_event(db, task, "task_start_requested", "任务已进入调度队列")
        observe_task_lifecycle("queued", status=task.status, task_type=self._task_type(task))
        if self._task_type(task) == TASK_TYPE_BINARY:
            self._record_event(db, task, "firmware_items_initialized", f"已初始化 {len(input_files)} 个固件输入")
        else:
            self._record_event(db, task, "source_tree_initialized", f"已初始化源码工程输入，共 {len(input_files)} 个文件")
        db.commit()
        self._enqueue_task(task.id)
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def list_tasks(self, db: Session, *, project_id: str, status: str | None = None, task_type: str | None = None) -> BinarySecurityTaskListResponse:
        base_query = db.query(BinarySecurityTask).filter(BinarySecurityTask.project_id == project_id)
        normalized_task_type = self._validate_task_type(task_type) if task_type else None
        if normalized_task_type:
            if normalized_task_type == TASK_TYPE_BINARY:
                base_query = base_query.filter(
                    or_(
                        BinarySecurityTask.task_type == TASK_TYPE_BINARY,
                        BinarySecurityTask.task_type.is_(None),
                    )
                )
            else:
                base_query = base_query.filter(BinarySecurityTask.task_type == normalized_task_type)
        stats_tasks = base_query.options(
            load_only(
                BinarySecurityTask.id,
                BinarySecurityTask.task_type,
                BinarySecurityTask.status,
                BinarySecurityTask.metrics_json,
            )
        ).all()
        query = base_query
        if status:
            query = query.filter(BinarySecurityTask.status == status)
        tasks = query.options(
            load_only(
                BinarySecurityTask.id,
                BinarySecurityTask.project_id,
                BinarySecurityTask.task_type,
                BinarySecurityTask.name,
                BinarySecurityTask.status,
                BinarySecurityTask.current_stage,
                BinarySecurityTask.pending_action,
                BinarySecurityTask.firmware_path,
                BinarySecurityTask.policy_json,
                BinarySecurityTask.metrics_json,
                BinarySecurityTask.dispatcher_instance_id,
                BinarySecurityTask.created_by,
                BinarySecurityTask.created_at,
                BinarySecurityTask.updated_at,
                BinarySecurityTask.started_at,
                BinarySecurityTask.finished_at,
                BinarySecurityTask.execution_mode,
                BinarySecurityTask.target_stage_name,
            )
        ).order_by(BinarySecurityTask.created_at.desc()).all()
        queue_info = self._build_queue_info(db, project_id=project_id)
        service_config = self._load_service_config(db)
        return BinarySecurityTaskListResponse(
            total=len(tasks),
            running_count=queue_info["running_count"],
            queued_count=queue_info["queued_count"],
            max_concurrent_tasks=service_config.max_concurrent_tasks,
            project_stats=self._build_project_stats(stats_tasks),
            project_stage_aggregates=self._build_project_stage_aggregates(db, stats_tasks, normalized_task_type),
            items=[self._task_response(db, task, queue_info=queue_info) for task in tasks],
        )

    def get_task_detail(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).order_by(
            BinarySecurityStageItem.created_at.asc()
        ).all()
        archive_jobs = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.task_id == task.id).order_by(
            BinarySecurityArchiveJob.created_at.asc()
        ).all()
        queue_info = self._build_queue_info(db, project_id=project_id)
        base = self._task_response(db, task, queue_info=queue_info).model_dump()
        archive_job_responses: list[BinarySecurityArchiveJobResponse] = []
        for job in archive_jobs:
            retry_supported, retry_reason = self._archive_job_retry_support(db, task, job)
            archive_job_responses.append(
                BinarySecurityArchiveJobResponse(
                    id=job.id,
                    stage_name=job.stage_name,
                    item_id=job.item_id,
                    item_key=job.item_key,
                    downstream_service=job.downstream_service,
                    downstream_task_id=job.downstream_task_id,
                    archive_status=job.archive_status,
                    archive_root=job.archive_root,
                    error_message=job.error_message,
                    attempts=job.attempts or 0,
                    created_at=job.created_at,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                    updated_at=job.updated_at,
                    retry_supported=retry_supported,
                    retry_reason=retry_reason,
                    retry_failed_supported=retry_supported,
                    retry_failed_reason=retry_reason,
                    copy_stats=dict((job.payload or {}).get("archive_copy_stats") or {}),
                )
            )
        return BinarySecurityTaskDetailResponse(
            **base,
            description=task.description,
            output_root=task.output_root,
            workspace_root=task.workspace_root,
            fileserver_subproject_name=task.fileserver_subproject_name,
            policy=task.policy,
            summary=task.summary,
            metrics=task.metrics,
            item_stats=self._item_stats(items),
            stage_items=[self._stage_item_response(item) for item in items],
            archive_jobs=archive_job_responses,
            overview_nodes=self._build_stage_overview_nodes(
                db,
                task,
                [BinarySecurityStageSummary(**summary) if isinstance(summary, dict) else summary for summary in base.get("stage_summaries", [])],
                archive_job_responses,
                items,
            ),
            orchestration_observability=self._build_orchestration_observability(db, task),
        )

    def get_orchestration_observability(self, db: Session, *, project_id: str, task_id: str) -> dict[str, Any]:
        task = self._task_or_404(db, project_id, task_id)
        return self._build_orchestration_observability(db, task)

    def _build_orchestration_observability(self, db: Session, task: BinarySecurityTask) -> dict[str, Any]:
        now_value = _now()
        events = (
            db.query(BinarySecurityStateEvent)
            .filter(BinarySecurityStateEvent.task_id == task.id)
            .order_by(BinarySecurityStateEvent.created_at.desc())
            .limit(50)
            .all()
        )
        status_counts: dict[str, int] = {}
        oldest_pending_at = None
        processing: list[dict[str, Any]] = []
        dead_letters: list[dict[str, Any]] = []
        recent_events: list[dict[str, Any]] = []
        for event in events:
            status = str(event.status or "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            if status in {"pending", "retryable", "processing"} and (oldest_pending_at is None or event.created_at < oldest_pending_at):
                oldest_pending_at = event.created_at
            row = {
                "id": event.id,
                "event_type": event.event_type,
                "status": event.status,
                "stage_name": event.stage_name,
                "item_id": event.item_id,
                "archive_job_id": event.archive_job_id,
                "attempts": int(event.attempts or 0),
                "leased_by": event.leased_by,
                "lease_expires_at": event.lease_expires_at,
                "created_at": event.created_at,
                "processed_at": event.processed_at,
                "error_message": event.error_message,
            }
            recent_events.append(row)
            if status == "processing":
                processing.append(row)
            if status == "dead_letter":
                dead_letters.append(row)
        archive_rows = (
            db.query(BinarySecurityArchiveJob.stage_name, BinarySecurityArchiveJob.archive_status, func.count(BinarySecurityArchiveJob.id))
            .filter(BinarySecurityArchiveJob.task_id == task.id)
            .group_by(BinarySecurityArchiveJob.stage_name, BinarySecurityArchiveJob.archive_status)
            .all()
        )
        archive_by_stage: dict[str, dict[str, int]] = {}
        for stage_name, status, count in archive_rows:
            stage_bucket = archive_by_stage.setdefault(str(stage_name or "unknown"), {})
            stage_bucket[str(status or "unknown")] = int(count or 0)
        lease = db.query(BinarySecurityTaskStateLease).filter(BinarySecurityTaskStateLease.task_id == task.id).first()
        latest_reconcile = (
            db.query(BinarySecurityEvent)
            .filter(
                BinarySecurityEvent.task_id == task.id,
                BinarySecurityEvent.event_type.in_([
                    "downstream_status_synced",
                    "downstream_status_sync_skipped",
                    "downstream_archive_job_queued",
                    "downstream_archive_job_reused",
                    "downstream_status_sync_failed",
                ]),
            )
            .order_by(BinarySecurityEvent.created_at.desc())
            .first()
        )
        return {
            "state_events": {
                "status_counts": status_counts,
                "oldest_active_age_seconds": max(0.0, (now_value - oldest_pending_at).total_seconds()) if oldest_pending_at else 0.0,
                "processing": processing[:10],
                "dead_letters": dead_letters[:10],
                "recent": recent_events[:20],
            },
            "task_state_lock": {
                "active": bool(lease and lease.lease_expires_at and lease.lease_expires_at > now_value),
                "owner_id": lease.owner_id if lease else None,
                "operation": lease.operation if lease else None,
                "lease_expires_at": lease.lease_expires_at if lease else None,
                "heartbeat_at": lease.heartbeat_at if lease else None,
            },
            "archive": {
                "by_stage": archive_by_stage,
            },
            "reconcile": {
                "latest_event_type": latest_reconcile.event_type if latest_reconcile else None,
                "latest_event_at": latest_reconcile.created_at if latest_reconcile else None,
                "latest_message": latest_reconcile.message if latest_reconcile else None,
            },
            "files": {
                "summary_path": str(Path(task.workspace_root) / BinarySecurityTask.SUMMARY_FILENAME) if task.workspace_root else None,
                "metadata_path": str(Path(task.workspace_root) / "input" / "task-metadata.json") if task.workspace_root else None,
            },
        }

    def update_task_concurrency(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityTaskConcurrencyUpdatePayload,
    ) -> BinarySecurityTaskDetailResponse:
        with self._task_operation_lock(db, task_id, operation="update_concurrency"):
            task = self._task_or_404(db, project_id, task_id)
            stage_sequence = self._stage_sequence_for_task(task)
            allowed_stages = set(stage_sequence)
            requested = payload.stage_parallelism or {}
            invalid_stage = next((stage for stage in requested if stage not in allowed_stages), None)
            if invalid_stage:
                raise ValidationError(f"阶段不属于当前任务流程: {invalid_stage}")

            policy = dict(task.policy or {})
            current_parallelism = policy.get("stage_parallelism") if isinstance(policy.get("stage_parallelism"), dict) else {}
            before = {
                stage: max(1, int(current_parallelism.get(stage) or policy.get("max_stage_parallelism") or 1))
                for stage in stage_sequence
            }
            updated = dict(before)
            for stage_name, raw_value in requested.items():
                try:
                    value = int(raw_value)
                except (TypeError, ValueError):
                    raise ValidationError(f"阶段 {stage_name} 并发必须是 1 到 32 之间的整数") from None
                if value < 1 or value > 32:
                    raise ValidationError(f"阶段 {stage_name} 并发必须是 1 到 32 之间的整数")
                updated[stage_name] = value

            policy["stage_parallelism"] = updated
            policy["max_stage_parallelism"] = max(updated.values()) if updated else 1
            self._enqueue_state_event(
                db,
                task_id=task.id,
                project_id=task.project_id,
                event_type="manual_policy_update_requested",
                idempotency_key=f"manual_policy_update_requested:{task.id}:concurrency:{uuid.uuid4().hex}",
                payload={
                    "mode": "concurrency",
                    "before": dict(task.policy or {}),
                    "after": policy,
                    "concurrency_before": before,
                    "concurrency_after": updated,
                },
            )
            db.commit()
            return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def _task_policy_update_support(self, task: BinarySecurityTask) -> tuple[bool, str | None]:
        blocked_statuses = {"dispatching", "running"} | TASK_PREPARING_STATUSES
        if task.status in blocked_statuses:
            return False, f"任务运行中，当前状态不允许修改任务策略: {task.status}"
        return True, None

    def update_task_policy(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityTaskPolicyUpdatePayload,
    ) -> BinarySecurityTaskDetailResponse:
        with self._task_operation_lock(db, task_id, operation="update_policy"):
            task = self._task_or_404(db, project_id, task_id)
            supported, reason = self._task_policy_update_support(task)
            if not supported:
                raise ValidationError(reason or "当前任务不允许修改任务策略")

            stage_sequence = self._stage_sequence_for_task(task)
            allowed_stages = set(stage_sequence)
            requested_parallelism = payload.stage_parallelism or {}
            requested_stage_options = payload.stage_options or {}

            invalid_parallelism_stage = next((stage for stage in requested_parallelism if stage not in allowed_stages), None)
            if invalid_parallelism_stage:
                raise ValidationError(f"阶段不属于当前任务流程: {invalid_parallelism_stage}")
            invalid_stage_option = next((stage for stage in requested_stage_options if stage not in allowed_stages), None)
            if invalid_stage_option:
                raise ValidationError(f"阶段不属于当前任务流程: {invalid_stage_option}")
            normalized_partial_success_advancement = self._validate_and_normalize_partial_success_stage_advancement_overrides(
                payload.partial_success_stage_advancement,
                task_type=task,
            )

            policy = dict(task.policy or {})
            before = json.loads(json.dumps(policy))

            current_parallelism = policy.get("stage_parallelism") if isinstance(policy.get("stage_parallelism"), dict) else {}
            merged_parallelism = {
                stage: max(1, int(current_parallelism.get(stage) or policy.get("max_stage_parallelism") or 1))
                for stage in stage_sequence
            }
            for stage_name, raw_value in requested_parallelism.items():
                try:
                    value = int(raw_value)
                except (TypeError, ValueError):
                    raise ValidationError(f"阶段 {stage_name} 并发必须是 1 到 32 之间的整数") from None
                if value < 1 or value > 32:
                    raise ValidationError(f"阶段 {stage_name} 并发必须是 1 到 32 之间的整数")
                merged_parallelism[stage_name] = value
            policy["stage_parallelism"] = merged_parallelism
            policy["max_stage_parallelism"] = max(merged_parallelism.values()) if merged_parallelism else 1

            current_stage_options = policy.get("stage_options") if isinstance(policy.get("stage_options"), dict) else {}
            merged_stage_options = {
                stage: dict(current_stage_options.get(stage) or {})
                for stage in stage_sequence
                if stage in current_stage_options
            }
            for stage_name, option in requested_stage_options.items():
                normalized_option = option.model_dump(mode="json") if hasattr(option, "model_dump") else dict(option or {})
                merged_stage_options[stage_name] = {"enabled": bool(normalized_option.get("enabled", True))}
            if merged_stage_options:
                policy["stage_options"] = merged_stage_options

            if payload.max_retries_per_item is not None:
                policy["max_retries_per_item"] = int(payload.max_retries_per_item)
            if payload.continue_on_item_failure is not None:
                policy["continue_on_item_failure"] = bool(payload.continue_on_item_failure)
            if normalized_partial_success_advancement:
                current_partial_success_advancement = policy.get("partial_success_stage_advancement")
                if not isinstance(current_partial_success_advancement, dict):
                    current_partial_success_advancement = self._default_partial_success_stage_advancement_for_task(task)
                policy["partial_success_stage_advancement"] = {
                    **self._normalized_partial_success_stage_advancement_map(
                        current_partial_success_advancement,
                        allowed_stages=self._partial_success_advancement_stages_for_task(task),
                        default_map=self._default_partial_success_stage_advancement_for_task(task),
                        strict=False,
                    ),
                    **normalized_partial_success_advancement,
                }
            if payload.module_selection_mode is not None:
                selection_mode = str(payload.module_selection_mode or MODULE_SELECTION_MODE_AUTO).strip()
                if selection_mode not in {MODULE_SELECTION_MODE_AUTO, MODULE_SELECTION_MODE_MANUAL_CONFIRM}:
                    selection_mode = MODULE_SELECTION_MODE_AUTO
                policy["module_selection_mode"] = selection_mode
            if payload.module_risk_levels is not None:
                normalized_levels = _normalize_module_risk_levels(payload.module_risk_levels)
                if not normalized_levels:
                    raise ValidationError("至少选择一个模块风险等级")
                policy["module_risk_levels"] = normalized_levels

            self._enqueue_state_event(
                db,
                task_id=task.id,
                project_id=task.project_id,
                event_type="manual_policy_update_requested",
                idempotency_key=f"manual_policy_update_requested:{task.id}:policy:{uuid.uuid4().hex}",
                payload={
                    "mode": "policy",
                    "before": before,
                    "after": policy,
                    "effective_scope": "future_stages_only",
                },
            )
            db.commit()
            return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def get_module_selection(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityModuleSelectionResponse:
        task = self._task_or_404(db, project_id, task_id)
        summary = task.summary or {}
        return BinarySecurityModuleSelectionResponse(
            task_id=task.id,
            status=task.status,
            selection_mode=self._module_selection_mode(task),
            risk_levels=self._module_risk_levels(task),
            requires_confirmation=task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION,
            system_analysis_modules=list(summary.get("system_analysis_modules") or []),
            candidate_modules=list(summary.get("candidate_modules") or []),
            selected_modules=list(summary.get("selected_modules") or []),
        )

    def confirm_module_selection(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        selected_module_keys: list[str],
    ) -> BinarySecurityTaskDetailResponse:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="confirm_module_selection")
        try:
            task = self._task_or_404(db, project_id, task_id)
            if task.status != TASK_STATUS_PENDING_MODULE_CONFIRMATION:
                raise ValidationError("当前任务不处于等待模块确认状态")
            summary = dict(task.summary or {})
            candidate_modules = list(summary.get("candidate_modules") or [])
            if not candidate_modules:
                raise ValidationError("当前任务没有可确认的候选模块")
            requested = [str(key or "").strip() for key in selected_module_keys if str(key or "").strip()]
            if not requested:
                raise ValidationError("至少选择 1 个模块")
            candidate_map = {str(module.get("module_key") or ""): dict(module) for module in candidate_modules if str(module.get("module_key") or "").strip()}
            invalid = [key for key in requested if key not in candidate_map]
            if invalid:
                raise ValidationError(f"存在不属于候选集合的模块: {invalid[0]}")
            self._enqueue_state_event(
                db,
                task_id=task.id,
                project_id=task.project_id,
                stage_name="system_analysis",
                event_type="manual_module_selection_confirmed",
                idempotency_key=f"manual_module_selection_confirmed:{task.id}:{operation_token}:{','.join(requested)}",
                payload={
                    "operation_token": operation_token,
                    "selected_module_keys": requested,
                },
            )
            db.commit()
            return self.get_task_detail(db, project_id=project_id, task_id=task_id)
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    def get_timeline(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTimelineResponse:
        task = self._task_or_404(db, project_id, task_id)
        events = db.query(BinarySecurityEvent).filter(BinarySecurityEvent.task_id == task.id).order_by(BinarySecurityEvent.created_at.asc()).all()
        return BinarySecurityTimelineResponse(
            task_id=task.id,
            events=[
                BinarySecurityTaskEventResponse(
                    id=event.id,
                    stage_name=event.stage_name,
                    item_id=event.item_id,
                    item_key=event.item_key,
                    level=event.level,
                    event_type=event.event_type,
                    message=event.message,
                    payload=event.payload,
                    created_at=event.created_at,
                )
                for event in events
            ],
        )

    def clear_timeline(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        deleted_count = (
            db.query(BinarySecurityEvent)
            .filter(BinarySecurityEvent.task_id == task.id)
            .delete(synchronize_session=False)
        )
        db.commit()
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"事件时间线已清空，共删除 {deleted_count} 条事件",
            deleted_event_count=int(deleted_count or 0),
        )

    def delete_timeline_event(self, db: Session, *, project_id: str, task_id: str, event_id: str) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        deleted_count = (
            db.query(BinarySecurityEvent)
            .filter(
                BinarySecurityEvent.task_id == task.id,
                BinarySecurityEvent.id == event_id,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        if not deleted_count:
            raise NotFoundError("事件不存在或已删除")
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"事件 {event_id} 已删除",
            deleted_event_count=int(deleted_count or 0),
        )

    def get_artifacts(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        limit: int = 200,
        offset: int = 0,
    ) -> BinarySecurityArtifactsResponse:
        task = self._task_or_404(db, project_id, task_id)
        page = self._list_artifact_page(Path(task.workspace_root), limit=max(1, limit), offset=max(0, offset))
        return BinarySecurityArtifactsResponse(
            task_id=task.id,
            workspace_root=task.workspace_root,
            output_root=task.output_root,
            fileserver_path=(task.summary or {}).get("fileserver_project_path"),
            total=page["total"],
            limit=page["limit"],
            offset=page["offset"],
            has_more=page["has_more"],
            files=page["files"],
        )

    async def cancel_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="cancel", ttl_seconds=TASK_OPERATION_LOCK_TTL_SECONDS)
        try:
            task = self._task_or_404(db, project_id, task_id)
            if task.status == "cancelled":
                active_item_count = db.query(BinarySecurityStageItem).filter(
                    BinarySecurityStageItem.task_id == task.id,
                    BinarySecurityStageItem.status.in_(["pending", "queued", "running", "dispatching"]),
                ).count()
                active_stage_count = db.query(BinarySecurityStageRun).filter(
                    BinarySecurityStageRun.task_id == task.id,
                    BinarySecurityStageRun.status.in_(["pending", "dispatching", "queued", "running"]),
                ).count()
                if active_item_count <= 0 and active_stage_count <= 0:
                    observe_task_operation("cancel", "already_cancelled")
                    self._release_task_operation_lease(db, task_id, token=operation_token)
                    return BinarySecurityActionResponse(task_id=task_id, message="任务已取消")
            self._enqueue_state_event(
                db,
                task_id=task.id,
                project_id=task.project_id,
                stage_name=task.current_stage,
                event_type="manual_cancel_requested",
                idempotency_key=f"manual_cancel_requested:{task.id}:{operation_token}",
                payload={
                    "operation_token": operation_token,
                    "current_stage": task.current_stage,
                },
            )
            db.commit()
            observe_task_operation("cancel", "accepted")
            return BinarySecurityActionResponse(
                task_id=task_id,
                accepted=True,
                action="cancel",
                status="cancel_requested",
                message="任务取消已受理，等待 reducer 串行应用",
            )
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    async def delete_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="delete", ttl_seconds=TASK_OPERATION_LOCK_TTL_SECONDS)
        try:
            task = self._task_or_404(db, project_id, task_id)
            self._enqueue_state_event(
                db,
                task_id=task.id,
                project_id=task.project_id,
                stage_name=task.current_stage,
                event_type="manual_delete_requested",
                idempotency_key=f"manual_delete_requested:{task.id}:{operation_token}",
                payload={
                    "operation_token": operation_token,
                    "current_stage": task.current_stage,
                },
            )
            db.commit()
            return BinarySecurityActionResponse(
                task_id=task_id,
                accepted=True,
                action="delete",
                status="delete_requested",
                message="任务删除已受理，等待 reducer 串行清理",
            )
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    async def continue_task(self, db: Session, *, project_id: str, task_id: str) -> str:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="continue")
        try:
            task = self._task_or_404(db, project_id, task_id)
            supported, reason, target_stage = self._task_continue_support(db, task)
            if not supported:
                observe_task_operation("continue", "rejected")
                raise ValidationError(reason or "当前任务不可继续")
            if not target_stage:
                observe_task_operation("continue", "rejected")
                raise ValidationError("当前任务未找到可继续的阶段")
            self._accept_blocking_action(
                db,
                task,
                action="continue",
                preparing_status=TASK_STATUS_CONTINUE_PREPARING,
                target_stage=target_stage,
                message=f"继续任务已受理，后台正在准备从阶段 {target_stage} 继续",
                event_type="task_continue_accepted",
                event_payload={"target_stage": target_stage},
            )
            observe_task_operation("continue", "accepted")
            return target_stage
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    async def _prepare_continue_task(self, db: Session, task: BinarySecurityTask, target_stage: str) -> list[str]:
        stage_sequence = self._stage_sequence_for_task(task)
        stage_runs = {
            row.stage_name: row
            for row in db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
            ).all()
        }
        target_index = stage_sequence.index(target_stage)
        affected_stages = stage_sequence[target_index:]
        self._invalidate_task_execution(task)
        db.flush()
        downstream_refs = self._downstream_refs_for_stages(db, task, affected_stages)
        if downstream_refs:
            await self._delete_downstream_refs(db, task, downstream_refs, self._service_token())
        self._clear_stage_outputs_from(task, target_stage, mark_stale=False)
        self._delete_archive_children_for_stages(db, task, affected_stages)
        self._delete_stage_items_for_stages(db, task.id, affected_stages)
        for stage_name in affected_stages:
            stage_run = stage_runs.get(stage_name)
            if stage_run:
                self._reset_stage_run_for_retry(task, stage_run, increment_retry=False)
        return affected_stages

    def retry_task(self, db: Session, *, project_id: str, task_id: str) -> None:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="retry")
        try:
            task = self._task_or_404(db, project_id, task_id)
            supported, reason, stage_name = self._task_retry_support(db, task)
            if not supported or not stage_name:
                observe_task_operation("retry", "rejected")
                observe_task_error("retry", stage=str(task.current_stage or "none"), result="rejected")
                raise ValidationError(reason or "当前任务不支持安全重试")
            first_stage = self._stage_sequence_for_task(task)[0]
            self._accept_blocking_action(
                db,
                task,
                action="retry",
                preparing_status=TASK_STATUS_RETRY_PREPARING,
                target_stage=first_stage,
                message=f"清空并从头开始已受理，后台正在准备从阶段 {first_stage} 重新排队",
                event_type="task_retry_accepted",
                event_payload={"target_stage": first_stage},
            )
            observe_task_operation("retry", "accepted")
            observe_task_error("retry", stage=first_stage, result="accepted")
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    def retry_failed_items(self, db: Session, *, project_id: str, task_id: str) -> str:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation=TASK_ACTION_RETRY_FAILED_ITEMS)
        try:
            task = self._task_or_404(db, project_id, task_id)
            supported, reason, stage_name, items = self._task_retry_failed_items_support(db, task)
            if not supported or not stage_name:
                observe_task_operation(TASK_ACTION_RETRY_FAILED_ITEMS, "rejected")
                raise ValidationError(reason or "当前任务不支持重试失败项")
            item_keys = sorted({self._stage_item_identity(item.item_key, item.parent_key) for item in items})
            self._set_retry_plan(
                task,
                {
                    "target_stage": stage_name,
                    "mode": TASK_ACTION_RETRY_FAILED_ITEMS,
                    "retry_item_keys": item_keys,
                    "preserve_success_items": True,
                    "archive_mode": "linked_failed_items",
                    "cleared_business_stages": [],
                    "cleared_archive_stages": [],
                },
            )
            self._accept_blocking_action(
                db,
                task,
                action=TASK_ACTION_RETRY_FAILED_ITEMS,
                preparing_status=TASK_STATUS_RETRY_PREPARING,
                target_stage=stage_name,
                message=f"重试失败项已受理，后台正在准备从阶段 {stage_name} 重新排队",
                event_type="task_retry_failed_items_accepted",
                event_payload={"target_stage": stage_name, "retry_item_count": len(item_keys)},
            )
            observe_task_operation(TASK_ACTION_RETRY_FAILED_ITEMS, "accepted")
            return stage_name
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    async def _prepare_retry_task(self, db: Session, task: BinarySecurityTask) -> list[str]:
        stage_sequence = self._stage_sequence_for_task(task)
        first_stage = stage_sequence[0]
        self._invalidate_task_execution(task)
        downstream_refs = self._downstream_refs_for_stages(db, task, stage_sequence)
        if downstream_refs:
            await self._cleanup_downstream_refs(db, task, downstream_refs, self._service_token())
        self._clear_stage_outputs_from(task, first_stage, mark_stale=False)
        self._delete_archive_children_for_stages(db, task, stage_sequence)
        self._delete_stage_items_for_stages(db, task.id, stage_sequence)
        for current_stage in stage_sequence:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == current_stage,
            ).first()
            if stage_run:
                self._reset_stage_run_for_retry(task, stage_run, increment_retry=True)
        return stage_sequence

    async def _prepare_retry_failed_items(self, db: Session, task: BinarySecurityTask, target_stage: str) -> list[str]:
        stage_sequence = self._stage_sequence_for_task(task)
        if target_stage not in stage_sequence:
            raise ValidationError(f"无效阶段: {target_stage}")
        plan = self._retry_plan(task)
        retry_item_keys = set(plan.get("retry_item_keys") or [])
        if not retry_item_keys:
            raise ValidationError("失败项重试缺少目标子任务")
        stage_items = self._stage_items(db, task.id, target_stage)
        retry_items = [
            item for item in stage_items
            if self._stage_item_identity(item.item_key, item.parent_key) in retry_item_keys
        ]
        if not retry_items:
            raise ValidationError("失败项重试未找到目标阶段子任务")
        item_ids = [item.id for item in retry_items]
        downstream_refs = self._collect_downstream_refs(task, retry_items)
        await self.sync_downstream_status(
            db,
            project_id=task.project_id,
            task_id=task.id,
            stage_name=target_stage,
            force=True,
            token=self._service_token(),
            record_request_event=False,
            record_noop_events=False,
        )
        target_index = stage_sequence.index(target_stage)
        affected_stages = stage_sequence[target_index:]
        downstream_stages = stage_sequence[target_index + 1:]
        all_downstream_refs = downstream_refs + self._downstream_refs_for_stages(db, task, downstream_stages)
        self._invalidate_task_execution(task)
        if all_downstream_refs:
            await self._cleanup_downstream_refs(db, task, all_downstream_refs, self._service_token())
        self._clear_single_stage_runtime_state(task, target_stage)
        if downstream_stages:
            self._clear_stage_outputs_from(task, downstream_stages[0], mark_stale=False)
            self._delete_archive_children_for_stages(db, task, downstream_stages)
            self._delete_stage_items_for_stages(db, task.id, downstream_stages)
        self._clear_archive_jobs_for_stage_items(db, task.id, target_stage, item_ids)
        self._delete_stage_items_by_ids(db, item_ids)
        target_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == target_stage,
        ).first()
        if target_run:
            self._reset_stage_run_for_retry(task, target_run, increment_retry=True)
        for downstream_stage in downstream_stages:
            downstream_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == downstream_stage,
            ).first()
            if downstream_run:
                self._reset_stage_run_for_retry(task, downstream_run, increment_retry=False)
        self._set_retry_plan(
            task,
            {
                **plan,
                "cleared_business_stages": [target_stage, *downstream_stages],
                "cleared_archive_stages": [target_stage, *downstream_stages],
            },
        )
        return affected_stages

    async def _prepare_retry_stage_full(self, db: Session, task: BinarySecurityTask, target_stage: str) -> list[str]:
        stage_sequence = self._stage_sequence_for_task(task)
        if target_stage not in stage_sequence:
            raise ValidationError(f"无效阶段: {target_stage}")
        target_index = stage_sequence.index(target_stage)
        affected_stages = stage_sequence[target_index:]
        self._invalidate_task_execution(task)
        downstream_refs = self._downstream_refs_for_stages(db, task, affected_stages)
        if downstream_refs:
            await self._cleanup_downstream_refs(db, task, downstream_refs, self._service_token())
        self._clear_stage_outputs_from(task, target_stage, mark_stale=False)
        self._delete_archive_children_for_stages(db, task, affected_stages)
        self._delete_stage_items_for_stages(db, task.id, affected_stages)
        for stage_name in affected_stages:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            if stage_run:
                self._reset_stage_run_for_retry(task, stage_run, increment_retry=(stage_name == target_stage))
        plan = self._retry_plan(task)
        self._set_retry_plan(
            task,
            {
                **plan,
                "cleared_business_stages": affected_stages,
                "cleared_archive_stages": affected_stages,
            },
        )
        return affected_stages

    def retry_stage(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        self.retry_stage_full(db, project_id=project_id, task_id=task_id, stage_name=stage_name)

    def retry_stage_failed_items(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation=TASK_ACTION_RETRY_STAGE_FAILED_ITEMS)
        try:
            task = self._task_or_404(db, project_id, task_id)
            supported, reason, items = self._stage_retry_failed_items_support(db, task, stage_name)
            if not supported:
                raise ValidationError(reason or f"阶段 {stage_name} 不支持重试失败项")
            item_keys = sorted({self._stage_item_identity(item.item_key, item.parent_key) for item in items})
            self._set_retry_plan(
                task,
                {
                    "target_stage": stage_name,
                    "mode": TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                    "retry_item_keys": item_keys,
                    "preserve_success_items": True,
                    "archive_mode": "linked_failed_items",
                    "cleared_business_stages": [],
                    "cleared_archive_stages": [],
                },
            )
            self._accept_blocking_action(
                db,
                task,
                action=TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                preparing_status=TASK_STATUS_RETRY_PREPARING,
                target_stage=stage_name,
                message=f"阶段 {stage_name} 的失败项重试已受理，后台正在准备重新排队",
                event_type="stage_retry_failed_items_accepted",
                event_payload={"target_stage": stage_name, "retry_item_count": len(item_keys)},
            )
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    def retry_stage_full(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation=TASK_ACTION_RETRY_STAGE_FULL)
        try:
            task = self._task_or_404(db, project_id, task_id)
            supported, reason = self._stage_retry_support(db, task, stage_name)
            if not supported:
                raise ValidationError(reason or f"阶段 {stage_name} 不支持完全重试")
            self._set_retry_plan(
                task,
                {
                    "target_stage": stage_name,
                    "mode": TASK_ACTION_RETRY_STAGE_FULL,
                    "retry_item_keys": [],
                    "preserve_success_items": False,
                    "archive_mode": "linked_full",
                    "cleared_business_stages": [],
                    "cleared_archive_stages": [],
                },
            )
            self._accept_blocking_action(
                db,
                task,
                action=TASK_ACTION_RETRY_STAGE_FULL,
                preparing_status=TASK_STATUS_RETRY_PREPARING,
                target_stage=stage_name,
                message=f"阶段 {stage_name} 的完全重试已受理，后台正在清理旧子任务并重建输入",
                event_type="stage_retry_full_accepted",
                event_payload={"target_stage": stage_name},
            )
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    def retry_stage_archive(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        self.retry_stage_archive_failed_items(db, project_id=project_id, task_id=task_id, stage_name=stage_name)

    def retry_stage_archive_failed_items(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="retry_stage_archive")
        try:
            task = self._task_or_404(db, project_id, task_id)
            stage_sequence = self._stage_sequence_for_task(task)
            if stage_name not in stage_sequence:
                observe_archive_action("retry_stage", "rejected")
                raise ValidationError(f"无效阶段: {stage_name}")
            supported, reason, jobs = self._archive_retry_support(db, task, stage_name, ignore_operation_lock=True)
            if not supported:
                observe_archive_action("retry_stage", "rejected")
                raise ValidationError(reason or f"阶段 {stage_name} 暂无可重试的归档任务")
            self._enqueue_manual_archive_retry_event(
                db,
                task,
                mode="failed_items",
                stage_name=stage_name,
                operation_token=operation_token,
                payload={"retryable_job_ids": [job.id for job in jobs]},
            )
            db.commit()
            observe_archive_action("retry_stage", "accepted")
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    def retry_stage_archive_full(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="retry_stage_archive_full")
        try:
            task = self._task_or_404(db, project_id, task_id)
            supported, reason, jobs, stage_items = self._archive_full_retry_support(db, task, stage_name, ignore_operation_lock=True)
            if not supported:
                observe_archive_action("retry_stage_full", "rejected")
                raise ValidationError(reason or f"阶段 {stage_name} 暂无可完全重试的归档任务")
            self._enqueue_manual_archive_retry_event(
                db,
                task,
                mode="full",
                stage_name=stage_name,
                operation_token=operation_token,
                payload={
                    "existing_job_ids": [job.id for job in jobs],
                    "stage_item_ids": [item.id for item in stage_items],
                },
            )
            db.commit()
            observe_archive_action("retry_stage_full", "accepted")
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    def retry_archive_job(self, db: Session, *, project_id: str, task_id: str, archive_job_id: str) -> str:
        operation_token = self._acquire_task_operation_lease(db, task_id, operation="retry_archive_job")
        try:
            task = self._task_or_404(db, project_id, task_id)
            job = db.query(BinarySecurityArchiveJob).filter(
                BinarySecurityArchiveJob.task_id == task.id,
                BinarySecurityArchiveJob.id == archive_job_id,
            ).first()
            if job is None:
                observe_archive_action("retry_job", "rejected")
                raise NotFoundError("归档任务不存在")
            supported, reason = self._archive_job_retry_support(db, task, job, ignore_operation_lock=True)
            if not supported:
                observe_archive_action("retry_job", "rejected")
                raise ValidationError(reason or "当前归档任务不可重试")
            self._enqueue_manual_archive_retry_event(
                db,
                task,
                mode="job",
                stage_name=job.stage_name,
                archive_job_id=job.id,
                operation_token=operation_token,
            )
            db.commit()
            observe_archive_action("retry_job", "accepted")
            return job.stage_name
        except Exception:
            self._release_task_operation_lease(db, task_id, token=operation_token)
            raise

    def _run_sync(self, coro):
        return asyncio.run(coro)

    async def _run_scheduled_coroutine(self, coro, *, label: str) -> None:
        try:
            await coro
        except Exception:
            logger.exception("binary-security scheduled coroutine failed: %s", label)

    def _schedule_coroutine(self, coro, *, label: str) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                asyncio.run(coro)
            except Exception:
                logger.exception("binary-security scheduled coroutine failed: %s", label)
            return
        loop.create_task(self._run_scheduled_coroutine(coro, label=label))

    def _enqueue_task(self, task_id: str) -> None:
        if not self.cfg.queue.enabled:
            return
        self._schedule_coroutine(get_task_queue().push_task(task_id), label=f"enqueue-task:{task_id}")

    def _enqueue_action(self, task_id: str) -> None:
        if not self.cfg.queue.enabled:
            return
        self._schedule_coroutine(get_task_queue().push_action(task_id), label=f"enqueue-action:{task_id}")

    def _stage_items_for_stages(
        self,
        db: Session,
        task_id: str,
        stage_names: list[str],
    ) -> list[BinarySecurityStageItem]:
        if not stage_names:
            return []
        return db.query(BinarySecurityStageItem).options(
            load_only(
                BinarySecurityStageItem.id,
                BinarySecurityStageItem.task_id,
                BinarySecurityStageItem.stage_name,
                BinarySecurityStageItem.item_key,
                BinarySecurityStageItem.status,
                BinarySecurityStageItem.retry_count,
                BinarySecurityStageItem.downstream_service,
                BinarySecurityStageItem.downstream_task_id,
                BinarySecurityStageItem.error_message,
                BinarySecurityStageItem.started_at,
                BinarySecurityStageItem.finished_at,
                BinarySecurityStageItem.created_at,
            )
        ).filter(
            BinarySecurityStageItem.task_id == task_id,
            BinarySecurityStageItem.stage_name.in_(stage_names),
        ).all()

    async def _cleanup_downstream_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
    ) -> None:
        if not refs:
            return
        await self._cancel_downstream_refs(db, task, refs, token)
        await self._ensure_downstream_refs_inactive(db, task, refs, token)
        await self._delete_downstream_refs(db, task, refs, token)

    async def _seed_work_queues(self) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            await self._reconcile_work_queues(db, force=True)
        finally:
            db.close()

    async def _reconcile_work_queues(self, db: Session, *, force: bool = False) -> None:
        if not self.cfg.queue.enabled:
            return
        now = _now()
        interval = max(5, int(self.cfg.queue.reconcile_interval_seconds or 30))
        if not force and self._last_queue_reconcile_at and (now - self._last_queue_reconcile_at).total_seconds() < interval:
            return
        self._last_queue_reconcile_at = now
        stale_dispatching_reclaimed = self._reclaim_stale_dispatching_locked(db)
        stale_running_reclaimed = self._reclaim_stale_running_locked(db)
        if stale_dispatching_reclaimed or stale_running_reclaimed:
            # Persist the reclaimed task state before seeding Redis queues.
            # Otherwise the surrounding loop closes the session and rolls the
            # reclaim back, leaving tasks permanently stuck on dead workers.
            db.commit()
        seed_batch = max(1, int(self.cfg.queue.seed_batch_size or 20))
        pending_ids = [
            row[0]
            for row in db.query(BinarySecurityTask.id)
            .filter(BinarySecurityTask.status == "pending")
            .order_by(BinarySecurityTask.updated_at.asc(), BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
            .limit(seed_batch)
            .all()
        ]
        preparing_ids = [
            row[0]
            for row in db.query(BinarySecurityTask.id)
            .filter(BinarySecurityTask.status.in_(list(TASK_PREPARING_STATUSES)))
            .order_by(BinarySecurityTask.updated_at.asc(), BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
            .limit(seed_batch)
            .all()
        ]
        for task_id in pending_ids:
            await get_task_queue().push_task(task_id)
        for task_id in preparing_ids:
            await get_task_queue().push_action(task_id)

    async def sync_downstream_status(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str | None = None,
        item_id: str | None = None,
        force: bool = False,
        token: str | None = None,
        record_request_event: bool = True,
        record_noop_events: bool = True,
    ) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        query = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id)
        if stage_name:
            if stage_name not in self._stage_sequence_for_task(task):
                raise ValidationError(f"无效阶段: {stage_name}")
            query = query.filter(BinarySecurityStageItem.stage_name == stage_name)
        if item_id:
            query = query.filter(BinarySecurityStageItem.id == item_id)
        items = query.order_by(BinarySecurityStageItem.created_at.asc()).all()
        if item_id and not items:
            raise NotFoundError("阶段子任务不存在")

        if record_request_event:
            self._record_event(
                db,
                task,
                "downstream_status_sync_requested",
                "请求同步下游子任务状态",
                stage_name=stage_name,
                payload={"stage_name": stage_name, "item_id": item_id, "force": force},
            )
            db.commit()

        synced_count = 0
        skipped_count = 0
        failed_count = 0
        touched_stages: set[str] = set()
        auth_token = token or self._service_token()
        ready_items: list[BinarySecurityStageItem] = []
        for item in items:
            item_stage_name = item.stage_name
            item_downstream_service = item.downstream_service
            item_downstream_task_id = item.downstream_task_id
            if not item.downstream_service or not item.downstream_task_id:
                skipped_count += 1
                if record_noop_events:
                    self._record_event(
                        db,
                        task,
                        "downstream_status_sync_skipped",
                        "跳过同步：子任务缺少下游服务或任务ID",
                        level="warning",
                        stage_name=item.stage_name,
                        item=item,
                    )
                continue
            ready_items.append(item)

        fetch_results = await self._run_with_limits(
            ready_items,
            lambda current_item: self._fetch_downstream_task_payload(task, current_item, auth_token),
            concurrency=self.cfg.scheduler.downstream_sync_concurrency,
            timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
        )
        for item, payload, exc in fetch_results:
            item_stage_name = item.stage_name
            item_downstream_service = item.downstream_service
            item_downstream_task_id = item.downstream_task_id
            before_status = item.status
            try:
                if exc is not None:
                    raise exc
                assert isinstance(payload, dict)
                downstream_status = str(payload.get("status") or "").lower()
                mapped_status = self._map_downstream_status(downstream_status)
                observe_downstream_reconcile_observation(
                    stage=item_stage_name,
                    service=item_downstream_service,
                    result=mapped_status or downstream_status or "unknown",
                )
                if not mapped_status:
                    skipped_count += 1
                    if record_noop_events:
                        self._record_event(
                            db,
                            task,
                            "downstream_status_sync_skipped",
                            f"跳过同步：无法识别下游状态 {downstream_status or '-'}",
                            level="warning",
                            stage_name=item.stage_name,
                            item=item,
                            payload={
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "downstream_status": downstream_status,
                            },
                        )
                    continue
                terminal_status = mapped_status in {"success", "partial_success", "failed", "cancelled", "downstream_missing"}
                if terminal_status:
                    if mapped_status == "downstream_missing":
                        if mapped_status != before_status or force:
                            self._enqueue_downstream_terminal_event(
                                db,
                                task=task,
                                item=item,
                                mapped_status=mapped_status,
                                before_status=before_status,
                                downstream_status=downstream_status,
                                payload=payload,
                                error_message="下游子任务不存在",
                                force=force,
                            )
                            synced_count += 1
                        else:
                            skipped_count += 1
                        if force or mapped_status != before_status or record_noop_events:
                            self._record_event(
                                db,
                                task,
                                "downstream_status_synced" if (force or mapped_status != before_status) else "downstream_status_sync_skipped",
                                "下游子任务不存在，已更新当前阶段子任务状态" if (force or mapped_status != before_status) else "下游子任务不存在，当前状态未变化",
                                stage_name=item.stage_name,
                                item=item,
                                level="warning",
                                payload={
                                    "downstream_service": item.downstream_service,
                                    "downstream_task_id": item.downstream_task_id,
                                    "before_status": before_status,
                                    "downstream_status": downstream_status,
                                    "after_status": mapped_status,
                                },
                            )
                        continue
                    if mapped_status not in ARCHIVE_SUCCESS_MAPPED_STATUSES:
                        if mapped_status != before_status or force:
                            self._enqueue_downstream_terminal_event(
                                db,
                                task=task,
                                item=item,
                                mapped_status=mapped_status,
                                before_status=before_status,
                                downstream_status=downstream_status,
                                payload=payload,
                                error_message=payload.get("error") or payload.get("error_message") or payload.get("message") or item.error_message,
                                force=force,
                            )
                            synced_count += 1
                        else:
                            skipped_count += 1
                        if force or mapped_status != before_status or record_noop_events:
                            self._record_event(
                                db,
                                task,
                                "downstream_status_synced" if (force or mapped_status != before_status) else "downstream_status_sync_skipped",
                                "下游终态已同步，当前子任务不再进入归档" if (force or mapped_status != before_status) else "下游终态未变化，当前子任务不进入归档",
                                stage_name=item.stage_name,
                                item=item,
                                level="warning" if mapped_status in {"failed", "cancelled"} else "info",
                                payload={
                                    "downstream_service": item.downstream_service,
                                    "downstream_task_id": item.downstream_task_id,
                                    "before_status": before_status,
                                    "downstream_status": downstream_status,
                                    "after_status": mapped_status,
                                    "archive_skipped": True,
                                },
                            )
                        continue
                    job = self._ensure_downstream_archive_job(
                        db,
                        task,
                        item,
                        payload=payload,
                        mapped_status=mapped_status,
                        before_status=before_status,
                        force=force,
                    )
                    if job.archive_status == "success":
                        # The archive job may already have finished in an earlier
                        # reconcile pass while the item/stage/task state was not
                        # fully applied back to the orchestrator. Re-apply the
                        # persisted archive result idempotently so the main task
                        # can leave the stale running state.
                        db.commit()
                        await self._apply_archive_job_status(job.id, job.archive_root)
                        db.expire_all()
                        synced_count += 1
                        continue
                    if job.archive_status == "failed":
                        if force or mapped_status != before_status or record_noop_events:
                            self._record_event(
                                db,
                                task,
                                "downstream_status_sync_skipped",
                                "下游状态已获取，但当前阶段的归档失败需要人工处理；不会自动重新排队",
                                stage_name=item.stage_name,
                                item=item,
                                level="warning",
                                payload={
                                    "archive_job_id": job.id,
                                    "archive_status": job.archive_status,
                                    "downstream_service": item.downstream_service,
                                    "downstream_task_id": item.downstream_task_id,
                                    "downstream_status": downstream_status,
                                    "mapped_status": mapped_status,
                                    "archive_retry_required": True,
                                },
                            )
                        skipped_count += 1
                        continue
                    if record_noop_events or force or mapped_status != before_status:
                        self._record_event(
                            db,
                            task,
                            "downstream_archive_job_queued" if job.archive_status in {"pending", "running"} else "downstream_archive_job_reused",
                            "下游状态已获取，等待产物归档完成后更新状态",
                            stage_name=item.stage_name,
                            item=item,
                            payload={
                                "archive_job_id": job.id,
                                "archive_status": job.archive_status,
                                "downstream_service": item.downstream_service,
                                "downstream_task_id": item.downstream_task_id,
                                "downstream_status": downstream_status,
                                "mapped_status": mapped_status,
                            },
                        )
                    skipped_count += 1
                    continue
                if mapped_status != before_status:
                    self._enqueue_downstream_status_event(
                        db,
                        task=task,
                        item=item,
                        mapped_status=mapped_status,
                        before_status=before_status,
                        downstream_status=downstream_status,
                        payload=payload,
                        error_message=None if mapped_status in {"queued", "running", "success"} else (
                            payload.get("error") or payload.get("error_message") or payload.get("message") or item.error_message
                        ),
                        force=force,
                    )
                    synced_count += 1
                else:
                    skipped_count += 1
                if force or mapped_status != before_status or record_noop_events:
                    self._record_event(
                        db,
                        task,
                        "downstream_status_synced" if (force or mapped_status != before_status) else "downstream_status_sync_skipped",
                        "下游子任务状态已同步" if (force or mapped_status != before_status) else "下游子任务状态一致，无需同步",
                        stage_name=item.stage_name,
                        item=item,
                        payload={
                            "downstream_service": item.downstream_service,
                            "downstream_task_id": item.downstream_task_id,
                            "before_status": before_status,
                            "downstream_status": downstream_status,
                            "after_status": mapped_status,
                        },
                    )
            except NotFoundError:
                # The exception is raised by downstream fetch only. Rolling the
                # whole session back here would also discard already-synced
                # sibling items from earlier loop iterations.
                self._enqueue_downstream_terminal_event(
                    db,
                    task=task,
                    item=item,
                    mapped_status="downstream_missing",
                    before_status=before_status,
                    downstream_status="downstream_missing",
                    payload={"status": "downstream_missing", "error": "下游子任务不存在"},
                    error_message="下游子任务不存在",
                    force=True,
                )
                synced_count += 1
                self._record_event(
                    db,
                    task,
                    "downstream_status_synced",
                    "下游子任务不存在，已投递 reducer 串行更新事件",
                    level="warning",
                    stage_name=item_stage_name,
                    item=item,
                    payload={
                        "downstream_service": item_downstream_service,
                        "downstream_task_id": item_downstream_task_id,
                        "before_status": before_status,
                        "downstream_status": "downstream_missing",
                        "after_status": "downstream_missing",
                    },
                )
            except Exception as exc:
                # Keep previously synchronized item updates intact; this branch
                # only records the current item's fetch failure.
                failed_count += 1
                self._record_event(
                    db,
                    task,
                    "downstream_status_sync_failed",
                    f"同步下游子任务状态失败: {exc}",
                    level="warning",
                    stage_name=item_stage_name,
                    item=item,
                    payload={
                        "downstream_service": item_downstream_service,
                        "downstream_task_id": item_downstream_task_id,
                        "error": str(exc),
                    },
                )
        for current_stage in touched_stages:
            if current_stage == "system_analysis":
                self._refresh_system_analysis_stage_from_synced_items(db, task)
            else:
                self._refresh_stage_run_from_items(db, task, current_stage)
        if touched_stages:
            self._refresh_task_status_after_sync(db, task)
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
        db.commit()
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"下游状态同步完成：更新 {synced_count} 个，跳过 {skipped_count} 个，失败 {failed_count} 个",
            synced_downstream_count=synced_count,
            skipped_downstream_count=skipped_count,
            failed_downstream_count=failed_count,
        )

    def _clear_archive_jobs_for_stages(self, db: Session, task_id: str, stage_names: list[str]) -> int:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return 0
        return int(
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task_id,
                BinarySecurityArchiveJob.stage_name.in_(normalized),
            )
            .delete(synchronize_session=False)
            or 0
        )

    def _clear_archive_jobs_for_stage_items(self, db: Session, task_id: str, stage_name: str, item_ids: list[str]) -> int:
        normalized_item_ids = [str(item_id or "").strip() for item_id in item_ids if str(item_id or "").strip()]
        if not normalized_item_ids:
            return 0
        return int(
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task_id,
                BinarySecurityArchiveJob.stage_name == stage_name,
                BinarySecurityArchiveJob.item_id.in_(normalized_item_ids),
            )
            .delete(synchronize_session=False)
            or 0
        )

    def _delete_archive_children_for_stages(self, db: Session, task: BinarySecurityTask, stage_names: list[str]) -> int:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return 0
        self._clear_stage_output_artifacts(task, normalized)
        return self._clear_archive_jobs_for_stages(db, task.id, normalized)

    def _archive_retry_blocked_reason(self, task: BinarySecurityTask) -> str | None:
        now_value = _now()
        if task.status in TASK_PREPARING_STATUSES:
            return f"当前任务正在执行 {task.pending_action or task.status}，暂不可重试归档"
        if task.status in {"dispatching", "running"}:
            return f"当前任务正在执行中，当前状态 {task.status} 下不可手工重试归档"
        if bool(task.operation_lock_expires_at and task.operation_lock_expires_at > now_value):
            return f"当前任务正在执行 {task.operation_lock_type or task.pending_action or '未知'} 操作，请稍后重试"
        if task.status in {"pending_upload", "uploading", "ready_to_start", "pending"}:
            return f"当前任务状态不允许重试归档: {task.status}"
        return None

    def _archive_job_retry_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        job: BinarySecurityArchiveJob,
        *,
        ignore_operation_lock: bool = False,
    ) -> tuple[bool, str | None]:
        del db
        if not ignore_operation_lock:
            blocked_reason = self._archive_retry_blocked_reason(task)
            if blocked_reason:
                return False, blocked_reason
        if job.task_id != task.id:
            return False, "归档任务不属于当前任务"
        if str(job.archive_status or "").strip() != "failed":
            return False, f"当前归档任务状态不允许重试: {job.archive_status or '-'}"
        mapped_status = str((job.payload or {}).get("mapped_status") or "").strip()
        if mapped_status not in {"success", "partial_success"}:
            return False, f"当前归档任务目标状态不允许重试: {mapped_status or '-'}"
        return True, None

    def _archive_retry_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        ignore_operation_lock: bool = False,
    ) -> tuple[bool, str | None, list[BinarySecurityArchiveJob]]:
        if not ignore_operation_lock:
            blocked_reason = self._archive_retry_blocked_reason(task)
            if blocked_reason:
                return False, blocked_reason, []
        jobs = (
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task.id,
                BinarySecurityArchiveJob.stage_name == stage_name,
            )
            .order_by(BinarySecurityArchiveJob.created_at.asc())
            .all()
        )
        jobs = [
            job
            for job in jobs
            if str(job.task_id or "") == str(task.id) and str(job.stage_name or "") == str(stage_name)
        ]
        if not jobs:
            return False, "当前阶段暂无归档任务", []
        retryable_jobs: list[BinarySecurityArchiveJob] = []
        for job in jobs:
            supported, _ = self._archive_job_retry_support(db, task, job, ignore_operation_lock=ignore_operation_lock)
            if supported:
                retryable_jobs.append(job)
        if not retryable_jobs:
            return False, "当前阶段暂无可重试的失败归档任务", []
        return True, None, retryable_jobs

    def _archive_full_retry_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        ignore_operation_lock: bool = False,
    ) -> tuple[bool, str | None, list[BinarySecurityArchiveJob], list[BinarySecurityStageItem]]:
        if not ignore_operation_lock:
            blocked_reason = self._archive_retry_blocked_reason(task)
            if blocked_reason:
                return False, blocked_reason, [], []
        jobs = (
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task.id,
                BinarySecurityArchiveJob.stage_name == stage_name,
            )
            .order_by(BinarySecurityArchiveJob.created_at.asc())
            .all()
        )
        jobs = [
            job
            for job in jobs
            if str(job.task_id or "") == str(task.id) and str(job.stage_name or "") == str(stage_name)
        ]
        stage_items = [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if self._normalize_item_status(item.status) in ARCHIVE_SUCCESS_MAPPED_STATUSES
        ]
        if not jobs and not stage_items:
            return False, "当前阶段暂无可重建的归档子任务", [], []
        return True, None, jobs, stage_items

    def _requeue_archive_jobs(
        self,
        db: Session,
        task: BinarySecurityTask,
        jobs: list[BinarySecurityArchiveJob],
        *,
        stage_name: str,
        event_type: str,
        event_message: str,
    ) -> None:
        if not jobs:
            return
        now = _now()
        touched_stage_names: set[str] = set()
        for job in jobs:
            item = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.id == job.item_id).first()
            mapped_status = str((job.payload or {}).get("mapped_status") or "success").strip()
            if item is not None:
                item.status = mapped_status
                item.error_message = None
                item.started_at = item.started_at or now
                item.finished_at = item.finished_at or now
                if item.stage_name == "firmware_unpack":
                    self._refresh_firmware_unpack_item_result(task, item, archived_dir=Path(job.archive_root) if job.archive_root else None)
                touched_stage_names.add(item.stage_name)
            job.archive_status = "pending"
            job.owner_id = None
            job.error_message = None
            job.archive_root = None
            job.started_at = None
            job.completed_at = None
            job.updated_at = now
            self._record_event(
                db,
                task,
                event_type,
                event_message,
                stage_name=stage_name,
                item=item,
                payload={
                    "archive_job_id": job.id,
                    "downstream_service": job.downstream_service,
                    "downstream_task_id": job.downstream_task_id,
                    "mapped_status": mapped_status,
                },
            )
        for current_stage in sorted(touched_stage_names):
            if current_stage == "system_analysis":
                self._refresh_system_analysis_stage_from_synced_items(db, task)
            else:
                self._refresh_stage_run_from_items(db, task, current_stage)
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    def _enqueue_manual_archive_retry_event(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        mode: str,
        stage_name: str,
        operation_token: str,
        archive_job_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        event_payload = {
            "mode": mode,
            "stage_name": stage_name,
            "archive_job_id": archive_job_id,
            "operation_token": operation_token,
            **(payload or {}),
        }
        self._enqueue_state_event(
            db,
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_name,
            archive_job_id=archive_job_id,
            event_type="manual_archive_retry_requested",
            idempotency_key=f"manual_archive_retry_requested:{task.id}:{mode}:{stage_name}:{archive_job_id or ''}:{operation_token}",
            payload=event_payload,
        )

    def _apply_manual_archive_retry_request_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        mode = str(payload.get("mode") or "").strip()
        stage_name = str(payload.get("stage_name") or event.stage_name or "").strip()
        operation_token = str(payload.get("operation_token") or "").strip()
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        if operation_token:
            current_operation_token = str(task.operation_lock_token or "").strip()
            if current_operation_token and current_operation_token != operation_token:
                self._record_event(
                    db,
                    task,
                    "manual_archive_retry_ignored",
                    "归档重试事件已过期，当前任务操作锁已变化",
                    level="warning",
                    stage_name=stage_name,
                    payload={"mode": mode, "state_event_id": event.id},
                )
                return
        try:
            if mode == "failed_items":
                supported, reason, jobs = self._archive_retry_support(db, task, stage_name, ignore_operation_lock=True)
                if not supported:
                    raise ValidationError(reason or f"阶段 {stage_name} 暂无可重试的归档任务")
                self._requeue_archive_jobs(
                    db,
                    task,
                    jobs,
                    stage_name=stage_name,
                    event_type="archive_stage_retry_requested",
                    event_message="阶段归档任务已重新排队",
                )
                self._mark_task_waiting_for_archive_retry(db, task, stage_name)
                observe_archive_action("retry_stage", "reduced")
                return
            if mode == "full":
                supported, reason, jobs, stage_items = self._archive_full_retry_support(db, task, stage_name, ignore_operation_lock=True)
                if not supported:
                    raise ValidationError(reason or f"阶段 {stage_name} 暂无可完全重试的归档任务")
                if jobs:
                    self._clear_archive_jobs_for_stages(db, task.id, [stage_name])
                rebuilt = self._rebuild_archive_jobs_for_stage(db, task, stage_name, stage_items)
                self._mark_task_waiting_for_archive_retry(db, task, stage_name)
                self._record_event(
                    db,
                    task,
                    "archive_stage_full_retry_requested",
                    "阶段归档任务已清空并重建",
                    stage_name=stage_name,
                    payload={
                        "stage_name": stage_name,
                        "rebuild_count": rebuilt,
                        "retry_semantics": "archive_full",
                        "state_event_id": event.id,
                    },
                )
                observe_archive_action("retry_stage_full", "reduced")
                return
            if mode == "job":
                archive_job_id = str(payload.get("archive_job_id") or event.archive_job_id or "").strip()
                job = db.query(BinarySecurityArchiveJob).filter(
                    BinarySecurityArchiveJob.task_id == task.id,
                    BinarySecurityArchiveJob.id == archive_job_id,
                ).first()
                if job is None:
                    raise NotFoundError("归档任务不存在")
                supported, reason = self._archive_job_retry_support(db, task, job, ignore_operation_lock=True)
                if not supported:
                    raise ValidationError(reason or "当前归档任务不可重试")
                self._requeue_archive_jobs(
                    db,
                    task,
                    [job],
                    stage_name=job.stage_name,
                    event_type="archive_job_retry_requested",
                    event_message="归档任务已重新排队",
                )
                self._mark_task_waiting_for_archive_retry(db, task, job.stage_name)
                observe_archive_action("retry_job", "reduced")
                return
            raise ValidationError(f"不支持的归档重试模式: {mode or '-'}")
        finally:
            if operation_token:
                self._release_task_operation_lease(db, task.id, token=operation_token)

    def _retry_failed_archive_jobs_for_stage(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        event_type: str = "downstream_archive_retry_requested",
    ) -> bool:
        supported, _, jobs = self._archive_retry_support(db, task, stage_name)
        if not supported:
            return False
        self._requeue_archive_jobs(
            db,
            task,
            jobs,
            stage_name=stage_name,
            event_type=event_type,
            event_message="产物归档已重新排队",
        )
        return True

    def _rebuild_archive_jobs_for_stage(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        stage_items: list[BinarySecurityStageItem],
    ) -> int:
        rebuilt = 0
        for item in stage_items:
            mapped_status = self._normalize_item_status(item.status)
            if mapped_status not in ARCHIVE_SUCCESS_MAPPED_STATUSES:
                continue
            payload = dict((item.result or {}).get("downstream") or {})
            payload.setdefault("status", mapped_status)
            job = self._queue_downstream_archive_job(
                db,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status=mapped_status,
            )
            rebuilt += 1 if job else 0
        return rebuilt

    def _mark_task_waiting_for_archive_retry(self, db: Session, task: BinarySecurityTask, stage_name: str) -> None:
        task.status = "running"
        task.current_stage = stage_name
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        task.finished_at = None
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="running")
        self._record_event(
            db,
            task,
            "task_archive_retry_requeued",
            "失败任务的产物归档已重新排队，等待归档 worker 完成后继续推进",
            stage_name=stage_name,
            payload={"stage_name": stage_name, "retry_semantics": "archive_retry"},
        )

    def _ensure_downstream_archive_job(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        payload: dict[str, Any],
        mapped_status: str,
        before_status: str | None,
        force: bool = False,
        extra_paths: list[str | Path] | None = None,
    ) -> BinarySecurityArchiveJob:
        downstream_task_id = str(item.downstream_task_id or "").strip()
        job_dedupe_key = build_archive_job_dedupe_key(item.id, downstream_task_id)
        next_payload = self._build_archive_job_payload(
            mapped_status=mapped_status,
            before_status=before_status,
            force=force,
            payload=payload,
            extra_paths=extra_paths,
        )
        lock_digest = hashlib.sha1(f"{item.id}:{downstream_task_id}".encode("utf-8")).hexdigest()
        lock_name = f"bs_archive:{lock_digest}"
        locked = False
        try:
            try:
                locked = bool(db.execute(text("SELECT GET_LOCK(:name, :timeout)"), {"name": lock_name, "timeout": 5}).scalar())
            except Exception:
                locked = False
            if not locked:
                # Avoid a best-effort local race when the DB lock is unavailable
                # (for example in tests or if the DB rejects named locks).
                import time as _time
                _time.sleep(0.05)
            existing = (
                db.query(BinarySecurityArchiveJob)
                .filter(
                    BinarySecurityArchiveJob.task_id == task.id,
                    BinarySecurityArchiveJob.stage_name == item.stage_name,
                    BinarySecurityArchiveJob.job_dedupe_key == job_dedupe_key,
                    BinarySecurityArchiveJob.archive_status.in_(["pending", "running", "archived", "applying", "success"]),
                )
                .order_by(BinarySecurityArchiveJob.created_at.desc())
                .first()
            )
            if existing is not None:
                try:
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                return existing
            failed = (
                db.query(BinarySecurityArchiveJob)
                .filter(
                    BinarySecurityArchiveJob.task_id == task.id,
                    BinarySecurityArchiveJob.stage_name == item.stage_name,
                    BinarySecurityArchiveJob.job_dedupe_key == job_dedupe_key,
                    BinarySecurityArchiveJob.archive_status == "failed",
                )
                .order_by(BinarySecurityArchiveJob.created_at.desc())
                .first()
            )
            if failed is not None:
                try:
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                return failed
            job = BinarySecurityArchiveJob(
                id=f"aj_{uuid.uuid4().hex[:24]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_name=item.stage_name,
                item_id=item.id,
                item_key=item.item_key,
                downstream_service=item.downstream_service,
                downstream_task_id=downstream_task_id,
                job_dedupe_key=job_dedupe_key,
            )
            job.task_id = task.id
            job.project_id = task.project_id
            job.stage_name = item.stage_name
            job.item_key = item.item_key
            job.downstream_service = item.downstream_service
            job.downstream_task_id = downstream_task_id
            job.job_dedupe_key = job_dedupe_key
            job.archive_status = "pending"
            job.owner_id = None
            job.error_message = None
            job.archive_root = None
            job.started_at = None
            job.completed_at = None
            job.updated_at = _now()
            job.payload = self._build_archive_job_payload(
                mapped_status=mapped_status,
                before_status=before_status,
                force=force,
                payload=payload,
                extra_paths=extra_paths,
            )
            db.add(job)
            try:
                with self._savepoint(db):
                    db.flush()
            except IntegrityError:
                existing = (
                    db.query(BinarySecurityArchiveJob)
                    .filter(
                        BinarySecurityArchiveJob.task_id == task.id,
                        BinarySecurityArchiveJob.stage_name == item.stage_name,
                        BinarySecurityArchiveJob.job_dedupe_key == job_dedupe_key,
                    )
                    .order_by(BinarySecurityArchiveJob.created_at.desc())
                    .first()
                )
                if existing is None:
                    raise
                return existing
            # The archive worker may run in another process/session. Persist the
            # queued job before releasing the named lock so a concurrent sync path
            # can observe and reuse it instead of creating a duplicate job.
            try:
                db.commit()
            except Exception:
                db.rollback()
                raise
            return job
        finally:
            if locked:
                try:
                    db.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": lock_name})
                except Exception:
                    pass

    def _queue_downstream_archive_job(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        payload: dict[str, Any],
        mapped_status: str,
        before_status: str | None,
        extra_paths: list[str | Path] | None = None,
    ) -> BinarySecurityArchiveJob:
        if mapped_status not in ARCHIVE_SUCCESS_MAPPED_STATUSES:
            raise ValidationError(f"当前状态不生成归档任务: {mapped_status}")
        job = self._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload=payload,
            mapped_status=mapped_status,
            before_status=before_status,
            force=False,
            extra_paths=extra_paths,
        )
        self._record_event(
            db,
            task,
            "downstream_archive_job_queued" if job.archive_status in {"pending", "running"} else "downstream_archive_job_reused",
            "下游子任务已终态，产物归档已入队",
            stage_name=item.stage_name,
            item=item,
            payload={
                "archive_job_id": job.id,
                "archive_status": job.archive_status,
                "downstream_service": item.downstream_service,
                "downstream_task_id": item.downstream_task_id,
                "mapped_status": mapped_status,
            },
        )
        return job

    async def _queue_archive_and_wait(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        payload: dict[str, Any],
        mapped_status: str,
        before_status: str | None,
        extra_paths: list[str | Path] | None = None,
    ) -> tuple[Path | None, BinarySecurityArchiveJob | None]:
        if mapped_status not in ARCHIVE_SUCCESS_MAPPED_STATUSES:
            return None, None
        job = self._queue_downstream_archive_job(
            db,
            task,
            item,
            payload=payload,
            mapped_status=mapped_status,
            before_status=before_status,
            extra_paths=extra_paths,
        )
        db.commit()
        completed = await self._wait_archive_job_completion(job.id, task.id)
        try:
            db.refresh(item)
        except Exception:
            db.rollback()
        if completed is None or completed.archive_status != "success":
            error = completed.error_message if completed is not None else "归档任务不存在"
            self._record_event(
                db,
                task,
                "downstream_archive_blocking_failed",
                "总任务产物归档未完成，阶段结果不能用于后续推进",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={"archive_job_id": job.id, "error": error or "下游产物归档失败"},
            )
            db.commit()
            return None, completed
        return Path(completed.archive_root) if completed.archive_root else None, completed

    def get_project_config(self, db: Session, project_id: str) -> BinarySecurityProjectConfigResponse:
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        config = BinarySecurityProjectConfigPayload(**(row.config if row else {}))
        config.partial_success_stage_advancement = self._normalized_partial_success_stage_advancement_map(
            config.partial_success_stage_advancement,
            allowed_stages=PARTIAL_SUCCESS_ADVANCEMENT_STAGES,
            default_map=DEFAULT_PARTIAL_SUCCESS_STAGE_ADVANCEMENT,
        )
        return BinarySecurityProjectConfigResponse(project_id=project_id, config=config)

    def save_project_config(self, db: Session, project_id: str, payload: BinarySecurityProjectConfigPayload) -> BinarySecurityProjectConfigResponse:
        normalized_payload = payload.model_copy(deep=True)
        normalized_payload.partial_success_stage_advancement = self._normalized_partial_success_stage_advancement_map(
            payload.partial_success_stage_advancement,
            allowed_stages=PARTIAL_SUCCESS_ADVANCEMENT_STAGES,
            default_map=DEFAULT_PARTIAL_SUCCESS_STAGE_ADVANCEMENT,
        )
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        if row is None:
            row = BinarySecurityProjectConfig(project_id=project_id)
            db.add(row)
        row.config = normalized_payload.model_dump(mode="json")
        db.commit()
        return BinarySecurityProjectConfigResponse(project_id=project_id, config=normalized_payload)

    def get_service_config(self, db: Session) -> BinarySecurityServiceConfigResponse:
        return BinarySecurityServiceConfigResponse(config=self._load_service_config(db))

    def save_service_config(self, db: Session, payload: BinarySecurityServiceConfigPayload) -> BinarySecurityServiceConfigResponse:
        row = db.query(BinarySecurityServiceConfig).filter(BinarySecurityServiceConfig.config_key == "global").first()
        if row is None:
            row = BinarySecurityServiceConfig(config_key="global")
            db.add(row)
        row.config = payload.model_dump(mode="json")
        db.commit()
        return BinarySecurityServiceConfigResponse(config=payload)

    def _accept_blocking_action(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        action: str,
        preparing_status: str,
        target_stage: str | None,
        message: str,
        event_type: str,
        event_payload: dict[str, Any] | None = None,
    ) -> None:
        if action not in TASK_PENDING_ACTIONS:
            raise ValidationError(f"不支持的任务阻塞动作: {action}")
        operation_token = str(task.operation_lock_token or "").strip()
        self._enqueue_state_event(
            db,
            task_id=task.id,
            project_id=task.project_id,
            stage_name=target_stage,
            event_type="manual_blocking_action_requested",
            idempotency_key=f"manual_blocking_action_requested:{task.id}:{action}:{target_stage or ''}:{operation_token}",
            payload={
                "action": action,
                "preparing_status": preparing_status or _preparing_status_for_action(action),
                "target_stage": target_stage,
                "message": message,
                "accepted_event_type": event_type,
                "event_payload": event_payload or {},
                "operation_token": operation_token,
            },
        )
        db.commit()

    def _apply_blocking_action_request_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        action = str(payload.get("action") or "").strip()
        if action not in TASK_PENDING_ACTIONS:
            raise ValidationError(f"不支持的任务阻塞动作: {action}")
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        target_stage = str(payload.get("target_stage") or "").strip() or None
        preparing_status = str(payload.get("preparing_status") or "").strip() or _preparing_status_for_action(action)
        message = str(payload.get("message") or "").strip() or "任务手工操作已受理"
        accepted_event_type = str(payload.get("accepted_event_type") or "").strip() or "manual_blocking_action_accepted"
        event_payload = dict(payload.get("event_payload") or {})
        expected_operation_token = str(payload.get("operation_token") or "").strip()
        current_operation_token = str(task.operation_lock_token or "").strip()
        if expected_operation_token and current_operation_token and expected_operation_token != current_operation_token:
            self._record_event(
                db,
                task,
                "manual_blocking_action_ignored",
                "手工操作事件已过期，当前任务操作锁已变化",
                level="warning",
                stage_name=target_stage,
                payload={"action": action, "target_stage": target_stage, "state_event_id": event.id},
            )
            return
        self._invalidate_task_execution(task)
        task.status = preparing_status
        task.pending_action = action
        task.current_stage = target_stage or task.current_stage
        task.last_error = None
        task.finished_at = None
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
        self._record_event(
            db,
            task,
            accepted_event_type,
            message,
            stage_name=target_stage,
            payload={"action": action, "target_stage": target_stage, "state_event_id": event.id, **event_payload},
        )
        self._enqueue_action(task.id)

    async def _blocking_action_dispatch_loop(self) -> None:
        session_factory = get_session_factory()
        while self._running:
            task_id = None
            db = session_factory()
            try:
                with observe_scheduler_loop("action_dispatch"):
                    task_id = await get_task_queue().pop_action(self.cfg.queue.block_timeout_seconds)
                    if task_id:
                        claimed_id = self._claim_preparing_task_by_id(db, task_id)
                        if claimed_id:
                            async with self._action_worker_lock:
                                if claimed_id not in self._action_workers or self._action_workers[claimed_id].done():
                                    self._action_workers[claimed_id] = asyncio.create_task(
                                        self._run_preparing_action(claimed_id),
                                        name=f"binary-security-action-{claimed_id}",
                                    )
                    else:
                        await self._reconcile_work_queues(db)
                    await self._observe_runtime_metrics(db)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("binary-security action dispatch loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                db.close()

    async def _dispatch_loop(self) -> None:
        session_factory = get_session_factory()
        while self._running:
            task_id = None
            db = session_factory()
            try:
                with observe_scheduler_loop("task_dispatch"):
                    task_id = await get_task_queue().pop_task(self.cfg.queue.block_timeout_seconds)
                    if task_id:
                        claimed_id = self._dispatch_task_by_id(db, task_id)
                        if claimed_id:
                            async with self._worker_lock:
                                if claimed_id not in self._workers or self._workers[claimed_id].done():
                                    self._workers[claimed_id] = asyncio.create_task(
                                        self._run_task(claimed_id),
                                        name=f"binary-security-{claimed_id}",
                                    )
                    else:
                        await self._reconcile_work_queues(db)
                    await self._observe_runtime_metrics(db)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("binary-security task dispatch loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                db.close()

    def _claim_preparing_tasks(self, db: Session) -> list[str]:
        lease_expires_at = self._next_lease_expiry(db)
        candidates = (
            db.query(BinarySecurityTask.id)
            .filter(
                BinarySecurityTask.status.in_(list(TASK_PREPARING_STATUSES)),
                self._lease_filter_available(),
            )
            .order_by(BinarySecurityTask.updated_at.asc(), BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
            .limit(max(1, int(self.cfg.scheduler.task_concurrency or 2)))
            .all()
        )
        claimed: list[str] = []
        started_at = _now()
        for row in candidates:
            task_id = row[0]
            updated = (
                db.query(BinarySecurityTask)
                .filter(
                    BinarySecurityTask.id == task_id,
                    BinarySecurityTask.status.in_(list(TASK_PREPARING_STATUSES)),
                    self._lease_filter_available(),
                )
                .update(
                    {
                        BinarySecurityTask.dispatcher_instance_id: self.instance_id,
                        BinarySecurityTask.dispatch_started_at: started_at,
                        BinarySecurityTask.lease_expires_at: lease_expires_at,
                        BinarySecurityTask.updated_at: started_at,
                    },
                    synchronize_session=False,
                )
            )
            if updated:
                claimed.append(task_id)
        if claimed:
            db.commit()
        return claimed

    def _claim_preparing_task_by_id(self, db: Session, task_id: str) -> str | None:
        started_at = _now()
        lease_expires_at = self._next_lease_expiry(db, now_value=started_at)
        updated = (
            db.query(BinarySecurityTask)
            .filter(
                BinarySecurityTask.id == task_id,
                BinarySecurityTask.status.in_(list(TASK_PREPARING_STATUSES)),
                self._lease_filter_available(),
            )
            .update(
                {
                    BinarySecurityTask.dispatcher_instance_id: self.instance_id,
                    BinarySecurityTask.dispatch_started_at: started_at,
                    BinarySecurityTask.lease_expires_at: lease_expires_at,
                    BinarySecurityTask.updated_at: started_at,
                },
                synchronize_session=False,
            )
        )
        if updated:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is not None:
                wait_seconds = _elapsed_seconds_since(task.created_at)
                observe_task_duration(
                    phase="queue_wait",
                    duration_seconds=wait_seconds,
                    status="dispatching",
                    task_type=self._task_type(task),
                )
            db.commit()
            return task_id
        return None

    async def _run_preparing_action(self, task_id: str) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        operation_token: str | None = None
        action: str | None = None
        heartbeat_task: asyncio.Task | None = None
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if (
                task is None
                or task.status not in TASK_PREPARING_STATUSES
                or task.dispatcher_instance_id != self.instance_id
                or not self._lease_is_active(task)
            ):
                return
            action = str(task.pending_action or "").strip()
            if action not in TASK_PENDING_ACTIONS:
                raise ValidationError("任务 preparing 状态缺少有效 pending_action")
            operation_token = str(task.operation_lock_token or "").strip() or None
            if not operation_token:
                raise ValidationError("任务 preparing 状态缺少有效 operation lock")
            renewed = self._renew_task_operation_lease(task.id, token=operation_token, operation=action)
            if not renewed:
                raise ValidationError("任务 preparing 操作锁已失效，请重新发起操作")
            heartbeat_task = asyncio.create_task(
                self._task_operation_lease_heartbeat(task.id, token=operation_token, operation=action),
                name=f"binary-security-operation-lock-{task.id}",
            )
            target_stage = str(task.current_stage or "").strip() or None
            started_event = "task_continue_prepare_started" if action == TASK_ACTION_CONTINUE else "task_retry_prepare_started"
            finished_event = "task_continue_prepare_finished" if action == TASK_ACTION_CONTINUE else "task_retry_prepare_finished"
            failed_event = "task_continue_prepare_failed" if action == TASK_ACTION_CONTINUE else "task_retry_prepare_failed"
            requeued_event = "task_continue_requested" if action == TASK_ACTION_CONTINUE else "task_retried"

            self._record_event(
                db,
                task,
                started_event,
                "后台准备已开始，正在清理旧阶段结果并重建可继续执行状态",
                stage_name=target_stage,
                payload={"action": action, "target_stage": target_stage},
            )
            db.commit()

            if action == TASK_ACTION_CONTINUE:
                if not target_stage:
                    raise ValidationError("继续任务缺少目标阶段")
                affected_stages = await self._prepare_continue_task(db, task, target_stage)
                task.execution_mode = "task_retry"
                task.target_stage_name = target_stage
                requeued_message = f"任务已完成继续准备，将从阶段 {target_stage} 重新排队"
                retry_semantics = "continue_with_existing_downstream"
            elif action == TASK_ACTION_RETRY:
                stage_sequence = await self._prepare_retry_task(db, task)
                target_stage = stage_sequence[0] if stage_sequence else None
                affected_stages = stage_sequence
                task.execution_mode = None
                task.target_stage_name = None
                requeued_message = f"任务已完成清理，将从第一阶段 {target_stage} 重新排队"
                retry_semantics = "full_restart"
            elif action in {TASK_ACTION_RETRY_FAILED_ITEMS, TASK_ACTION_RETRY_STAGE_FAILED_ITEMS}:
                if not target_stage:
                    raise ValidationError("失败项重试缺少目标阶段")
                affected_stages = await self._prepare_retry_failed_items(db, task, target_stage)
                task.execution_mode = "task_retry_failed_items" if action == TASK_ACTION_RETRY_FAILED_ITEMS else "stage_retry_failed_items"
                task.target_stage_name = target_stage
                requeued_message = f"任务已完成失败项清理，将从阶段 {target_stage} 重新排队"
                retry_semantics = "retry_failed_items"
            elif action == TASK_ACTION_RETRY_STAGE_FULL:
                if not target_stage:
                    raise ValidationError("阶段完全重试缺少目标阶段")
                affected_stages = await self._prepare_retry_stage_full(db, task, target_stage)
                task.execution_mode = "stage_retry_full"
                task.target_stage_name = target_stage
                requeued_message = f"阶段 {target_stage} 已完成全量清理，将重新排队"
                retry_semantics = "stage_retry_full"
            else:
                raise ValidationError(f"未知 preparing action: {action}")

            task.status = "pending"
            task.pending_action = None
            task.current_stage = target_stage
            task.last_error = None
            task.finished_at = None
            self._invalidate_task_execution(task)
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
            self._record_event(
                db,
                task,
                finished_event,
                "后台准备完成，任务已恢复为待调度状态",
                stage_name=target_stage,
                payload={"action": action, "target_stage": target_stage, "cleared_stages": affected_stages},
            )
            self._record_event(
                db,
                task,
                requeued_event,
                requeued_message,
                stage_name=target_stage,
                payload={
                    "target_stage": target_stage,
                    "cleared_stages": affected_stages,
                    "retry_semantics": retry_semantics,
                    "accepted_async": True,
                },
            )
            db.commit()
            self._enqueue_task(task.id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            db.rollback()
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is not None:
                action = str(task.pending_action or "").strip()
                target_stage = str(task.current_stage or "").strip() or None
                task.status = "failed"
                task.pending_action = None
                task.last_error = str(exc)
                task.finished_at = _now()
                self._invalidate_task_execution(task)
                await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="failed")
                self._record_event(
                    db,
                    task,
                    "task_continue_prepare_failed" if action == TASK_ACTION_CONTINUE else "task_retry_prepare_failed",
                    f"后台准备失败: {exc}",
                    level="error",
                    stage_name=target_stage,
                    payload={"action": action or None, "target_stage": target_stage, "error": str(exc)},
                )
                db.commit()
        finally:
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                await asyncio.gather(heartbeat_task, return_exceptions=True)
            if operation_token:
                self._release_task_operation_lease(db, task_id, token=operation_token)
            async with self._action_worker_lock:
                self._action_workers.pop(task_id, None)
            db.close()

    async def _archive_dispatch_loop(self) -> None:
        while self._running:
            try:
                with observe_scheduler_loop("archive_dispatch"):
                    await self._schedule_archive_workers()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(max(1, self.cfg.scheduler.poll_interval_seconds))

    async def _schedule_archive_workers(self) -> None:
        max_workers = max(1, int(getattr(self.cfg.scheduler, "archive_job_concurrency", 0) or 1))
        async with self._archive_worker_lock:
            self._archive_workers = {task for task in self._archive_workers if not task.done()}
            slots = max_workers - len(self._archive_workers)
            if slots <= 0:
                return
            assignments: list[tuple[str, str]] = []
            for _ in range(slots):
                archived_job_id = await asyncio.to_thread(self._next_archived_job)
                if archived_job_id:
                    observe_archive_action("claim", "apply")
                    assignments.append(("apply", archived_job_id))
                    continue
                job_id = await asyncio.to_thread(self._claim_archive_job)
                if job_id:
                    observe_archive_action("claim", "copy")
                    assignments.append(("copy", job_id))
                    continue
                break
            for work_type, job_id in assignments:
                worker = asyncio.create_task(
                    self._archive_worker(work_type, job_id),
                    name=f"binary-security-archive-{work_type}-{job_id}",
                )
                self._archive_workers.add(worker)
            self._observe_worker_counts()

    async def _archive_worker(self, work_type: str, job_id: str) -> None:
        try:
            if work_type == "apply":
                await asyncio.to_thread(
                    self._enqueue_archive_state_event_by_job_id,
                    job_id,
                    event_type="archive_job_copied",
                    payload={"source": "archive_apply_claim"},
                )
            else:
                await self._process_archive_job(job_id)
        finally:
            async with self._archive_worker_lock:
                self._archive_workers.discard(asyncio.current_task())
            self._observe_worker_counts()

    async def _state_reducer_loop(self) -> None:
        interval_seconds = max(1, int(self.cfg.scheduler.poll_interval_seconds or 5))
        while self._running:
            db = get_session_factory()()
            try:
                with observe_scheduler_loop("state_reducer"):
                    await asyncio.to_thread(self._observe_state_runtime_metrics, db)
                    processed = 0
                    for _ in range(max(1, int(self.cfg.scheduler.downstream_action_concurrency or 1))):
                        event_id = self._claim_state_event(db)
                        if not event_id:
                            break
                        processed += 1
                        await self._reduce_state_event(event_id)
                    await self._observe_runtime_metrics(db)
                    if processed:
                        continue
            finally:
                db.close()
            await asyncio.sleep(interval_seconds)

    def _observe_state_runtime_metrics(self, db: Session) -> None:
        rows = (
            db.query(BinarySecurityStateEvent.status, func.count(BinarySecurityStateEvent.id))
            .group_by(BinarySecurityStateEvent.status)
            .all()
        )
        status_counts = {str(status or "unknown"): int(count or 0) for status, count in rows}
        oldest_ages: dict[str, float] = {}
        for status in {"pending", "processing", "retryable", "dead_letter"}:
            oldest = (
                db.query(func.min(BinarySecurityStateEvent.created_at))
                .filter(BinarySecurityStateEvent.status == status)
                .scalar()
            )
            oldest_ages[status] = max(0.0, (_now() - oldest).total_seconds()) if oldest else 0.0
        observe_state_event_queues(status_counts=status_counts, oldest_ages=oldest_ages)
        archive_rows = (
            db.query(BinarySecurityArchiveJob.stage_name, BinarySecurityArchiveJob.archive_status, func.count(BinarySecurityArchiveJob.id))
            .group_by(BinarySecurityArchiveJob.stage_name, BinarySecurityArchiveJob.archive_status)
            .all()
        )
        observe_archive_job_statuses({
            (str(stage or "unknown"), str(status or "unknown")): int(count or 0)
            for stage, status, count in archive_rows
        })

    def _claim_state_event(self, db: Session) -> str | None:
        now_value = _now()
        event = (
            db.query(BinarySecurityStateEvent)
            .filter(
                BinarySecurityStateEvent.status.in_(["pending", "retryable", "processing"]),
                BinarySecurityStateEvent.available_at <= now_value,
                or_(
                    BinarySecurityStateEvent.status != "processing",
                    BinarySecurityStateEvent.lease_expires_at.is_(None),
                    BinarySecurityStateEvent.lease_expires_at < now_value,
                ),
            )
            .order_by(BinarySecurityStateEvent.available_at.asc(), BinarySecurityStateEvent.created_at.asc(), BinarySecurityStateEvent.id.asc())
            .first()
        )
        if event is None:
            return None
        updated = (
            db.query(BinarySecurityStateEvent)
            .filter(
                BinarySecurityStateEvent.id == event.id,
                BinarySecurityStateEvent.status.in_(["pending", "retryable", "processing"]),
                or_(
                    BinarySecurityStateEvent.status != "processing",
                    BinarySecurityStateEvent.lease_expires_at.is_(None),
                    BinarySecurityStateEvent.lease_expires_at < now_value,
                ),
            )
            .update(
                {
                    BinarySecurityStateEvent.status: "processing",
                    BinarySecurityStateEvent.leased_by: self.instance_id,
                    BinarySecurityStateEvent.lease_expires_at: now_value + timedelta(seconds=STATE_EVENT_LEASE_SECONDS),
                    BinarySecurityStateEvent.attempts: int(event.attempts or 0) + 1,
                    BinarySecurityStateEvent.updated_at: now_value,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        return event.id if updated else None

    def _acquire_task_state_lease(self, db: Session, task_id: str, *, operation: str = "state_reduce") -> str | None:
        started = time.perf_counter()
        now_value = _now()
        token = uuid.uuid4().hex
        expires_at = now_value + timedelta(seconds=TASK_STATE_LEASE_SECONDS)
        values = {
            BinarySecurityTaskStateLease.owner_id: self.instance_id,
            BinarySecurityTaskStateLease.lease_token: token,
            BinarySecurityTaskStateLease.lease_expires_at: expires_at,
            BinarySecurityTaskStateLease.heartbeat_at: now_value,
            BinarySecurityTaskStateLease.operation: operation,
            BinarySecurityTaskStateLease.updated_at: now_value,
        }
        updated = (
            db.query(BinarySecurityTaskStateLease)
            .filter(
                BinarySecurityTaskStateLease.task_id == task_id,
                or_(
                    BinarySecurityTaskStateLease.lease_expires_at.is_(None),
                    BinarySecurityTaskStateLease.lease_expires_at <= now_value,
                    BinarySecurityTaskStateLease.owner_id == self.instance_id,
                ),
            )
            .update(values, synchronize_session=False)
        )
        if updated:
            db.flush()
            observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=1)
            return token
        try:
            lease = BinarySecurityTaskStateLease(
                task_id=task_id,
                owner_id=self.instance_id,
                lease_token=token,
                lease_expires_at=expires_at,
                heartbeat_at=now_value,
                operation=operation,
                updated_at=now_value,
            )
            with self._savepoint(db):
                db.add(lease)
                db.flush()
            observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=1)
            return token
        except IntegrityError:
            updated = (
                db.query(BinarySecurityTaskStateLease)
                .filter(
                    BinarySecurityTaskStateLease.task_id == task_id,
                    or_(
                        BinarySecurityTaskStateLease.lease_expires_at.is_(None),
                        BinarySecurityTaskStateLease.lease_expires_at <= now_value,
                        BinarySecurityTaskStateLease.owner_id == self.instance_id,
                    ),
                )
                .update(values, synchronize_session=False)
            )
            if updated:
                db.flush()
                observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=1)
                return token
            observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=0)
            return None

    def _release_task_state_lease(self, db: Session, task_id: str, *, token: str, operation: str = "state_reduce", held_started: float | None = None) -> None:
        lease = db.query(BinarySecurityTaskStateLease).filter(BinarySecurityTaskStateLease.task_id == task_id).first()
        if lease is not None and lease.lease_token == token:
            db.delete(lease)
            db.flush()
        observe_task_state_lock(
            operation=operation,
            held_seconds=(time.perf_counter() - held_started) if held_started is not None else None,
            active=0,
        )

    async def _reduce_state_event(self, event_id: str) -> None:
        started = time.perf_counter()
        db = get_session_factory()()
        event: BinarySecurityStateEvent | None = None
        lease_token: str | None = None
        held_started: float | None = None
        result = "unknown"
        try:
            event = db.query(BinarySecurityStateEvent).filter(BinarySecurityStateEvent.id == event_id).first()
            if event is None or event.status != "processing" or event.leased_by != self.instance_id:
                result = "skipped"
                return
            lease_token = self._acquire_task_state_lease(db, event.task_id)
            if not lease_token:
                event.status = "retryable"
                event.available_at = _now() + timedelta(seconds=5)
                event.leased_by = None
                event.lease_expires_at = None
                event.updated_at = _now()
                db.commit()
                result = "lock_busy"
                return
            held_started = time.perf_counter()
            # Publish the task-state lease before doing potentially slow file
            # and summary work; the apply itself stays in this reducer session.
            db.commit()
            await self._apply_state_event_locked(db, event)
            event = db.query(BinarySecurityStateEvent).filter(BinarySecurityStateEvent.id == event_id).first()
            if event is None:
                result = "missing_after_apply"
                return
            event_type = event.event_type
            task_id = event.task_id
            event_created_at = event.created_at
            if event_type == "manual_delete_requested":
                observe_state_event_lag(event_type, (_now() - event_created_at).total_seconds() if event_created_at else None)
                observe_state_reducer_event(event_type, "processed")
                db.expunge(event)
                db.query(BinarySecurityStateEvent).filter(
                    BinarySecurityStateEvent.task_id == task_id,
                ).delete(synchronize_session=False)
                result = "success"
                db.commit()
                return
            event.status = "processed"
            event.processed_at = _now()
            event.leased_by = None
            event.lease_expires_at = None
            event.error_message = None
            event.updated_at = _now()
            observe_state_event_lag(event_type, (_now() - event.created_at).total_seconds() if event.created_at else None)
            observe_state_reducer_event(event_type, "processed")
            result = "success"
            db.commit()
            if event_type == "manual_blocking_action_requested":
                self._enqueue_action(task_id)
            if event_type == "manual_module_selection_confirmed":
                self._enqueue_task(task_id)
        except Exception as exc:
            db.rollback()
            result = "failed"
            if event is not None:
                try:
                    event = db.query(BinarySecurityStateEvent).filter(BinarySecurityStateEvent.id == event_id).first()
                    if event is not None:
                        event.error_message = str(exc)
                        event.leased_by = None
                        event.lease_expires_at = None
                        event.updated_at = _now()
                        if int(event.attempts or 0) >= STATE_EVENT_MAX_ATTEMPTS:
                            event.status = "dead_letter"
                            event.processed_at = _now()
                            observe_state_dead_letter(event.event_type, "max_attempts")
                        else:
                            event.status = "retryable"
                            event.available_at = _now() + timedelta(seconds=min(300, 2 ** max(1, int(event.attempts or 1))))
                        db.commit()
                except Exception:
                    db.rollback()
            logger.exception("binary-security state reducer failed: event=%s", event_id)
        finally:
            if lease_token and event is not None:
                try:
                    self._release_task_state_lease(db, event.task_id, token=lease_token, held_started=held_started)
                    db.commit()
                except Exception:
                    db.rollback()
            db.close()
            observe_state_reducer_run(result=result, pod=self.instance_id, duration_seconds=time.perf_counter() - started)

    async def _apply_state_event_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        if event.event_type == "archive_job_copied":
            await self._apply_archive_job_status_locked(db, event.archive_job_id or "", payload.get("archive_root"), state_event_id=event.id)
            return
        if event.event_type == "archive_job_copy_failed":
            self._apply_archive_job_copy_failed_locked(db, event)
            return
        if event.event_type in {"downstream_status_observed", "downstream_terminal_observed"}:
            await self._apply_downstream_status_event_locked(db, event)
            return
        if event.event_type == "stage_worker_terminal_observed":
            await self._apply_stage_worker_terminal_event_locked(db, event)
            return
        if event.event_type == "task_execution_failed":
            await self._apply_task_execution_failed_locked(db, event)
            return
        if event.event_type == "stage_worker_start_requested":
            self._apply_stage_worker_start_requested_locked(db, event)
            return
        if event.event_type == "manual_blocking_action_requested":
            self._apply_blocking_action_request_locked(db, event)
            return
        if event.event_type == "manual_archive_retry_requested":
            self._apply_manual_archive_retry_request_locked(db, event)
            return
        if event.event_type == "manual_cancel_requested":
            await self._apply_manual_cancel_request_locked(db, event)
            return
        if event.event_type == "manual_delete_requested":
            await self._apply_manual_delete_request_locked(db, event)
            return
        if event.event_type == "manual_module_selection_confirmed":
            self._apply_manual_module_selection_confirmed_locked(db, event)
            return
        if event.event_type == "manual_policy_update_requested":
            self._apply_manual_policy_update_requested_locked(db, event)
            return
        logger.info("binary-security state reducer ignored event type: %s", event.event_type)

    async def _apply_downstream_status_event_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        item = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.id == event.item_id).first()
        if task is None or item is None:
            return
        payload = dict(event.payload or {})
        if task.status == "cancelled":
            self._record_event(
                db,
                task,
                "downstream_status_event_ignored",
                "下游状态事件晚于取消事件到达，已忽略以避免恢复已取消任务",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "state_event_id": event.id,
                    "downstream_service": item.downstream_service,
                    "downstream_task_id": item.downstream_task_id,
                    "ignored_status": payload.get("mapped_status") or payload.get("downstream_status"),
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        mapped_status = str(payload.get("mapped_status") or "").strip()
        if not mapped_status:
            return
        mapped_status = self._map_downstream_status(mapped_status) or mapped_status
        downstream_payload = dict(payload.get("downstream_payload") or {})
        item.status = mapped_status
        item.error_message = None if mapped_status in {"queued", "running", "success"} else (
            payload.get("error_message")
            or downstream_payload.get("error")
            or downstream_payload.get("error_message")
            or downstream_payload.get("message")
            or item.error_message
        )
        item.started_at = item.started_at or _now()
        item.finished_at = None if mapped_status in {"queued", "running"} else (item.finished_at or _now())
        item.result = {
            **(item.result or {}),
            "downstream": self._lightweight_downstream_payload(downstream_payload),
            "downstream_status_synced_at": _now().isoformat(),
        }
        if item.stage_name == "system_analysis":
            self._refresh_system_analysis_stage_from_synced_items(db, task)
        else:
            self._refresh_stage_run_from_items(db, task, item.stage_name)
        self._refresh_task_status_after_sync(db, task)
        self._record_event(
            db,
            task,
            "downstream_status_event_applied",
            "下游状态事件已由 reducer 串行应用",
            level="warning" if mapped_status in {"failed", "cancelled", "downstream_missing"} else "info",
            stage_name=item.stage_name,
            item=item,
            payload={
                "state_event_id": event.id,
                "before_status": payload.get("before_status"),
                "after_status": mapped_status,
                "downstream_status": payload.get("downstream_status"),
                "downstream_service": item.downstream_service,
                "downstream_task_id": item.downstream_task_id,
            },
        )
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    def _apply_stage_worker_start_requested_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        stage_name = str(event.stage_name or payload.get("stage_name") or "").strip()
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None or not stage_name:
            return
        stage_run = self._ensure_stage_run(db, task, stage_name)
        task.current_stage = stage_name
        stage_run.status = "running"
        stage_run.started_at = stage_run.started_at or _now()
        stage_run.finished_at = None
        stage_run.last_error = None
        existing_stage_items = self._stage_items(db, task.id, stage_name) if bool(payload.get("task_retry_mode")) else []
        target_stage_name = str(payload.get("target_stage_name") or "").strip()
        if bool(payload.get("stage_retry_mode")) and stage_name == target_stage_name:
            self._record_event(db, task, "stage_retry_started", f"阶段开始重试: {stage_name}", stage_name=stage_name, payload={"state_event_id": event.id})
        elif bool(payload.get("task_retry_mode")) and existing_stage_items:
            self._record_event(db, task, "stage_retry_started", f"阶段开始安全续跑: {stage_name}", stage_name=stage_name, payload={"state_event_id": event.id})
        self._record_event(db, task, "stage_started", f"阶段开始: {stage_name}", stage_name=stage_name, payload={"state_event_id": event.id})

    async def _apply_stage_worker_terminal_event_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        stage_name = str(event.stage_name or payload.get("stage_name") or "").strip()
        status = str(payload.get("status") or "").strip()
        summary = dict(payload.get("summary") or {})
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None or not stage_name or not status:
            return
        if task.status == "cancelled":
            self._record_event(
                db,
                task,
                "stage_worker_terminal_ignored",
                "阶段终态事件晚于取消事件到达，已忽略以避免恢复已取消任务",
                level="warning",
                stage_name=stage_name,
                payload={"state_event_id": event.id, "ignored_status": status},
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if stage_run is None:
            stage_run = self._ensure_stage_run(db, task, stage_name)
        stage_run.status = "waiting_confirmation" if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION else status
        stage_run.finished_at = _now()
        observe_stage_duration(
            stage=stage_name,
            result=stage_run.status,
            duration_seconds=_elapsed_seconds_since(stage_run.started_at),
        )
        await self._persist_stage_run_output_summary_async(task, stage_run, summary)
        stage_run.counts = self._stage_counts(db, stage_run)
        if status in {"failed", "partial_success", "downstream_missing"}:
            stage_run.last_error = summary.get("error")
        task.stage_summary = {
            **task.stage_summary,
            stage_name: {
                "status": stage_run.status,
                "counts": stage_run.counts,
                "finished_at": stage_run.finished_at.isoformat() if stage_run.finished_at else None,
                **(
                    {
                        "failure_code": summary.get("failure_code"),
                        "failure_category": summary.get("failure_category"),
                        "failure_message": summary.get("failure_message"),
                    }
                    if summary.get("failure_code")
                    else {}
                ),
            },
        }
        task.current_stage = stage_name
        if stage_name == "firmware_unpack":
            task.metrics = {
                **task.metrics,
                "unpacked_firmware_count": int(summary.get("success_count", 0)),
                "failed_firmware_count": int(summary.get("failed_count", 0)),
            }
        elif stage_name == "system_analysis":
            task.metrics = {
                **task.metrics,
                "high_risk_module_count": int(summary.get("high_risk_module_count", 0)),
                "medium_risk_module_count": int(summary.get("medium_risk_module_count", 0)),
                "low_risk_module_count": int(summary.get("low_risk_module_count", 0)),
                "candidate_module_count": int(summary.get("candidate_module_count", 0)),
                "selected_module_count": int(summary.get("selected_module_count", 0)),
            }
        elif stage_name == "entry_analysis":
            task.metrics = {**task.metrics, "entry_count": int(summary.get("entry_count", 0))}
        elif stage_name == "vuln_scan":
            task.metrics = {**task.metrics, "vuln_result_count": int(summary.get("vuln_result_count", 0))}

        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            self._invalidate_task_execution(task)
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if summary.get("archive_blocked"):
            task.status = "failed"
            task.last_error = summary.get("error") or "总任务产物归档失败"
            self._invalidate_task_execution(task)
            task.finished_at = _now()
            observe_task_error("downstream_error", stage=stage_name, result="archive_blocked")
            observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
            observe_task_duration(
                phase="execution",
                duration_seconds=_elapsed_seconds_since(task.started_at),
                status=task.status,
                task_type=self._task_type(task),
            )
            observe_task_duration(
                phase="total",
                duration_seconds=_elapsed_seconds_since(task.created_at),
                status=task.status,
                task_type=self._task_type(task),
            )
            self._record_event(
                db,
                task,
                "stage_archive_blocked",
                f"阶段业务执行已完成，但总任务产物归档失败，停止后续推进: {stage_name}",
                level="error",
                stage_name=stage_name,
                payload={"stage_status": status, "error": task.last_error, "state_event_id": event.id},
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if bool(payload.get("stage_retry_mode")) and stage_name == str(payload.get("target_stage_name") or ""):
            self._record_event(
                db,
                task,
                "stage_retry_finished",
                f"阶段重试完成: {stage_name}",
                stage_name=stage_name,
                payload={"status": status, "state_event_id": event.id},
            )
        if status == "failed":
            task.status = "failed"
            task.last_error = summary.get("failure_message") or summary.get("error")
            self._invalidate_task_execution(task)
            task.finished_at = _now()
            self._record_event(
                db,
                task,
                "stage_failed",
                f"阶段失败，停止后续推进: {stage_name}",
                level="error",
                stage_name=stage_name,
                payload={
                    "error": task.last_error,
                    "state_event_id": event.id,
                    **(
                        {
                            "failure_code": summary.get("failure_code"),
                            "failure_category": summary.get("failure_category"),
                            "failure_message": summary.get("failure_message"),
                        }
                        if summary.get("failure_code")
                        else {}
                    ),
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if bool(payload.get("stage_retry_mode")) or bool(payload.get("task_retry_mode")):
            task.execution_mode = None
            task.target_stage_name = None
            task_summary = dict(task.summary or {})
            task_summary.pop("stage_retry_context", None)
            task_summary.pop("task_retry_context", None)
            task_summary.pop("retry_plan", None)
            task.summary = task_summary
        next_stage = self._next_incomplete_stage(db, task)
        if task.status in {"running", "dispatching"} and next_stage:
            task.status = "pending"
            task.current_stage = next_stage
            self._invalidate_task_execution(task)
            task.finished_at = None
            task.last_error = None
            self._record_event(
                db,
                task,
                "task_requeued_after_stage_completion",
                f"阶段完成后任务继续进入下一阶段: {next_stage}",
                stage_name=next_stage,
                payload={"state_event_id": event.id, "completed_stage": stage_name},
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            self._enqueue_task(task.id)
            return
        self._finalize_task(db, task)
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    async def _apply_task_execution_failed_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        expected_dispatcher = str(payload.get("dispatcher_instance_id") or "").strip()
        expected_execution_token = str(payload.get("execution_token") or "").strip()
        current_execution_token = task.dispatch_started_at.isoformat() if task.dispatch_started_at else ""
        if expected_dispatcher and task.dispatcher_instance_id not in {None, expected_dispatcher}:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前 dispatcher 已变化",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": event.id, "dispatcher_instance_id": expected_dispatcher},
            )
            return
        if expected_execution_token and current_execution_token and expected_execution_token != current_execution_token:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前执行 token 已变化",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": event.id, "execution_token": expected_execution_token},
            )
            return
        if task.status not in {"dispatching", "running"}:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前任务不在运行态",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": event.id, "status": task.status},
            )
            return
        error_message = str(payload.get("error") or "任务执行失败")
        task.status = "failed"
        task.last_error = error_message
        self._invalidate_task_execution(task)
        task.finished_at = _now()
        observe_task_error("execution_error", stage=str(task.current_stage or "unknown"), result="failed")
        observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
        observe_task_duration(
            phase="execution",
            duration_seconds=_elapsed_seconds_since(task.started_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        observe_task_duration(
            phase="total",
            duration_seconds=_elapsed_seconds_since(task.created_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        self._record_event(
            db,
            task,
            "task_failed",
            f"任务执行失败: {error_message}",
            level="error",
            stage_name=task.current_stage,
            payload={"state_event_id": event.id},
        )
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    async def _apply_manual_cancel_request_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        operation_token = str(payload.get("operation_token") or "").strip()
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        try:
            if operation_token:
                current_operation_token = str(task.operation_lock_token or "").strip()
                if current_operation_token and current_operation_token != operation_token:
                    self._record_event(
                        db,
                        task,
                        "manual_cancel_ignored",
                        "取消事件已过期，当前任务操作锁已变化",
                        level="warning",
                        stage_name=task.current_stage,
                        payload={"state_event_id": event.id},
                    )
                    return
            if task.status == "cancelled":
                running_items = db.query(BinarySecurityStageItem).filter(
                    BinarySecurityStageItem.task_id == task.id,
                    BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
                ).all()
                for item in running_items:
                    item.status = "cancelled"
                    item.finished_at = item.finished_at or _now()
                active_stage_runs = db.query(BinarySecurityStageRun).filter(
                    BinarySecurityStageRun.task_id == task.id,
                    BinarySecurityStageRun.status.in_(["pending", "dispatching", "queued", "running"]),
                ).all()
                for stage_run in active_stage_runs:
                    stage_run.status = "cancelled"
                    stage_run.finished_at = stage_run.finished_at or _now()
                self._record_event(
                    db,
                    task,
                    "manual_cancel_noop",
                    "任务已经是取消状态，已归一化仍活跃的阶段与子任务",
                    stage_name=task.current_stage,
                    payload={
                        "state_event_id": event.id,
                        "cancelled_item_count": len(running_items),
                        "cancelled_stage_run_count": len(active_stage_runs),
                    },
                )
                return
            task.status = "cancelled"
            self._invalidate_task_execution(task)
            task.finished_at = _now()
            running_items = db.query(BinarySecurityStageItem).filter(
                BinarySecurityStageItem.task_id == task.id,
                BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
            ).all()
            for item in running_items:
                item.status = "cancelled"
                item.finished_at = _now()
            active_stage_runs = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.status.in_(["pending", "dispatching", "queued", "running"]),
            ).all()
            for stage_run in active_stage_runs:
                stage_run.status = "cancelled"
                stage_run.finished_at = stage_run.finished_at or _now()
            downstream_items = [item for item in running_items if item.downstream_task_id]
            self._record_event(
                db,
                task,
                "task_cancelled",
                "任务已由 reducer 串行取消",
                stage_name=task.current_stage,
                payload={
                    "state_event_id": event.id,
                    "cancelled_item_count": len(running_items),
                    "cancelled_downstream_count": len(downstream_items),
                },
            )
            observe_task_error("cancel", stage=str(task.current_stage or "none"), result="accepted")
            observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="cancelled")
            await self._cancel_local_worker(task.id)
            token = self._service_token()
            await asyncio.gather(
                *(self._cancel_downstream(item, token) for item in downstream_items),
                return_exceptions=True,
            )
        finally:
            if operation_token:
                self._release_task_operation_lease(db, task.id, token=operation_token)

    async def _apply_manual_delete_request_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        operation_token = str(payload.get("operation_token") or "").strip()
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        try:
            if operation_token:
                current_operation_token = str(task.operation_lock_token or "").strip()
                if current_operation_token and current_operation_token != operation_token:
                    self._record_event(
                        db,
                        task,
                        "manual_delete_ignored",
                        "删除事件已过期，当前任务操作锁已变化",
                        level="warning",
                        stage_name=task.current_stage,
                        payload={"state_event_id": event.id},
                    )
                    return
            task.status = "cancelled"
            self._invalidate_task_execution(task)
            task.finished_at = task.finished_at or _now()
            self._record_event(
                db,
                task,
                "task_delete_requested",
                "任务删除已由 reducer 受理，开始清理下游与工作区",
                stage_name=task.current_stage,
                payload={"state_event_id": event.id},
            )
            items = db.query(BinarySecurityStageItem).options(
                load_only(
                    BinarySecurityStageItem.id,
                    BinarySecurityStageItem.task_id,
                    BinarySecurityStageItem.stage_name,
                    BinarySecurityStageItem.item_key,
                    BinarySecurityStageItem.status,
                    BinarySecurityStageItem.retry_count,
                    BinarySecurityStageItem.downstream_service,
                    BinarySecurityStageItem.downstream_task_id,
                    BinarySecurityStageItem.error_message,
                    BinarySecurityStageItem.started_at,
                    BinarySecurityStageItem.finished_at,
                    BinarySecurityStageItem.created_at,
                )
            ).filter(BinarySecurityStageItem.task_id == task.id).all()
            downstream_refs = self._dedupe_downstream_refs(
                self._collect_downstream_refs(task, items)
                + self._discover_parent_linked_downstream_refs(db, task)
            )
            for item in items:
                if item.status in {"pending", "queued", "running"}:
                    item.status = "cancelled"
                    item.finished_at = _now()
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="cancelled")
            db.flush()

            await self._cancel_local_worker(task.id)
            token = self._service_token()
            await self._cancel_downstream_refs(db, task, downstream_refs, token)
            await self._delete_downstream_refs(db, task, downstream_refs, token)
            await self._cleanup_task_workspace(task, token)

            if operation_token:
                self._release_task_operation_lease(db, task.id, token=operation_token)
                operation_token = ""
            db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).delete(synchronize_session=False)
            db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).delete(synchronize_session=False)
            db.query(BinarySecurityEvent).filter(BinarySecurityEvent.task_id == task.id).delete(synchronize_session=False)
            db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.task_id == task.id).delete(synchronize_session=False)
            db.delete(task)
        finally:
            if operation_token:
                self._release_task_operation_lease(db, event.task_id, token=operation_token)

    def _apply_manual_module_selection_confirmed_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        operation_token = str(payload.get("operation_token") or "").strip()
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        try:
            if operation_token:
                current_operation_token = str(task.operation_lock_token or "").strip()
                if current_operation_token and current_operation_token != operation_token:
                    self._record_event(
                        db,
                        task,
                        "manual_module_selection_ignored",
                        "模块确认事件已过期，当前任务操作锁已变化",
                        level="warning",
                        stage_name="system_analysis",
                        payload={"state_event_id": event.id},
                    )
                    return
            if task.status != TASK_STATUS_PENDING_MODULE_CONFIRMATION:
                self._record_event(
                    db,
                    task,
                    "manual_module_selection_ignored",
                    "任务已不处于等待模块确认状态，忽略模块确认事件",
                    level="warning",
                    stage_name="system_analysis",
                    payload={"state_event_id": event.id, "status": task.status},
                )
                return
            summary = dict(task.summary or {})
            candidate_modules = list(summary.get("candidate_modules") or [])
            candidate_map = {
                str(module.get("module_key") or ""): dict(module)
                for module in candidate_modules
                if str(module.get("module_key") or "").strip()
            }
            requested = [str(key or "").strip() for key in payload.get("selected_module_keys") or [] if str(key or "").strip()]
            if not requested:
                raise ValidationError("至少选择 1 个模块")
            invalid = [key for key in requested if key not in candidate_map]
            if invalid:
                raise ValidationError(f"存在不属于候选集合的模块: {invalid[0]}")
            selected = self._mark_selected_modules([candidate_map[key] for key in requested], selected_by=MODULE_SELECTION_MODE_MANUAL_CONFIRM)
            summary["selected_modules"] = selected
            summary["high_risk_modules"] = selected
            task.summary = summary
            task.metrics = {
                **task.metrics,
                "selected_module_count": len(selected),
            }
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == "system_analysis",
            ).first()
            if stage_run:
                stage_run.status = "success"
                stage_run.started_at = stage_run.started_at or _now()
                stage_run.finished_at = stage_run.finished_at or _now()
                stage_run.last_error = None
                stage_run.counts = self._stage_counts(db, stage_run)
                self._merge_stage_run_output_summary(
                    task,
                    stage_run,
                    {
                        "status": "success",
                        "sync_status": "success",
                        "error": None,
                        "waiting_manual_confirmation": False,
                        "selected_module_count": len(selected),
                        "candidate_module_count": len(candidate_modules),
                        "module_count": len(list(summary.get("system_analysis_modules") or [])),
                        "high_risk_module_count": len(selected),
                        "status_synced": True,
                    },
                )
            current_stage = str(task.current_stage or "").strip()
            task.status = "pending"
            next_stage = self._next_incomplete_stage(db, task)
            if next_stage == current_stage or not next_stage:
                stage_sequence = self._stage_sequence_for_task(task)
                if current_stage in stage_sequence:
                    current_index = stage_sequence.index(current_stage)
                    if current_index + 1 < len(stage_sequence):
                        next_stage = stage_sequence[current_index + 1]
            task.current_stage = next_stage or self._stage_sequence_for_task(task)[0]
            task.last_error = None
            self._invalidate_task_execution(task)
            task.finished_at = None
            self._record_event(
                db,
                task,
                "module_selection_confirmed",
                f"已确认 {len(selected)} 个模块，任务继续执行",
                stage_name="system_analysis",
                payload={"selected_module_keys": requested, "state_event_id": event.id},
            )
            self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
        finally:
            if operation_token:
                self._release_task_operation_lease(db, task.id, token=operation_token)

    def _apply_manual_policy_update_requested_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        payload = dict(event.payload or {})
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        mode = str(payload.get("mode") or "policy").strip()
        before = dict(payload.get("before") or {})
        after = dict(payload.get("after") or {})
        if not after:
            raise ValidationError("策略更新事件缺少目标策略")
        task.policy = after
        if mode == "concurrency":
            self._record_event(
                db,
                task,
                "task_concurrency_updated",
                "任务阶段并发配置已由 reducer 更新",
                payload={
                    "before": payload.get("concurrency_before") or before.get("stage_parallelism") or {},
                    "after": payload.get("concurrency_after") or after.get("stage_parallelism") or {},
                    "state_event_id": event.id,
                },
            )
        else:
            self._record_event(
                db,
                task,
                "task_policy_updated",
                "任务策略已由 reducer 更新",
                payload={
                    "before": before,
                    "after": after,
                    "effective_scope": payload.get("effective_scope") or "future_stages_only",
                    "state_event_id": event.id,
                },
            )

    def _apply_archive_job_copy_failed_locked(self, db: Session, event: BinarySecurityStateEvent) -> None:
        job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == event.archive_job_id).first()
        if job is None:
            return
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == job.task_id).first()
        item = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.id == job.item_id).first()
        if task is None:
            return
        payload = dict(event.payload or {})
        job.archive_status = "failed"
        job.error_message = payload.get("error") or job.error_message or "下游产物归档失败"
        job.completed_at = job.completed_at or _now()
        job.updated_at = _now()
        if task.status not in TASK_TERMINAL_STATUSES:
            task.status = "failed"
            task.current_stage = job.stage_name
            task.last_error = job.error_message
            task.finished_at = _now()
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
        self._record_event(
            db,
            task,
            "downstream_archive_job_copy_failed",
            "下游产物归档复制失败，已由 reducer 记录失败事实",
            level="warning",
            stage_name=job.stage_name,
            item=item,
            payload={
                "state_event_id": event.id,
                "archive_job_id": job.id,
                "archive_status": job.archive_status,
                "error": job.error_message,
            },
        )
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    async def _downstream_reconcile_loop(self) -> None:
        interval_seconds = max(5, int(self.cfg.scheduler.stage_poll_interval_seconds or self.cfg.scheduler.poll_interval_seconds or 5))
        while self._running:
            db = get_session_factory()()
            try:
                with observe_scheduler_loop("downstream_reconcile"):
                    task_refs = await asyncio.to_thread(self._list_tasks_needing_downstream_sync, db)
                    token = self._service_token()
                    results = await self._run_with_limits(
                        task_refs,
                        lambda ref: self._reconcile_downstream_task_ref(ref, token),
                        concurrency=max(1, min(int(self.cfg.scheduler.downstream_sync_concurrency or 1), 8)),
                        timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
                    )
                    for ref, _, exc in results:
                        if exc is None:
                            continue
                        try:
                            task = self._task_or_404(db, ref["project_id"], ref["task_id"])
                            self._record_event(
                                db,
                                task,
                                "downstream_status_reconcile_failed",
                                f"后台同步下游状态失败: {exc}",
                                level="warning",
                                payload={"task_id": ref["task_id"], "project_id": ref["project_id"], "error": str(exc)},
                            )
                            db.commit()
                        except Exception:
                            db.rollback()
                    await self._observe_runtime_metrics(db, reconcile_candidates=len(task_refs))
            finally:
                db.close()
            await asyncio.sleep(interval_seconds)

    async def _reconcile_downstream_task_ref(self, ref: dict[str, str], token: str | None) -> None:
        db = get_session_factory()()
        try:
            await self.sync_downstream_status(
                db,
                project_id=ref["project_id"],
                task_id=ref["task_id"],
                force=False,
                token=token,
                record_request_event=False,
                record_noop_events=False,
            )
        finally:
            db.close()

    def _next_archived_job(self) -> str | None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            job = (
                db.query(BinarySecurityArchiveJob)
                .filter(BinarySecurityArchiveJob.archive_status == "archived")
                .order_by(BinarySecurityArchiveJob.updated_at.asc(), BinarySecurityArchiveJob.id.asc())
                .first()
            )
            if job is None:
                return None
            updated = (
                db.query(BinarySecurityArchiveJob)
                .filter(
                    BinarySecurityArchiveJob.id == job.id,
                    BinarySecurityArchiveJob.archive_status == "archived",
                )
                .update(
                    {
                        BinarySecurityArchiveJob.archive_status: "applying",
                        BinarySecurityArchiveJob.owner_id: self.instance_id,
                        BinarySecurityArchiveJob.updated_at: _now(),
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
            return job.id if updated else None
        finally:
            db.close()

    def _list_tasks_needing_downstream_sync(self, db: Session) -> list[dict[str, str]]:
        local_workers = {
            task_id for task_id, worker in self._workers.items()
            if not worker.done()
        }
        rows = (
            db.query(BinarySecurityTask)
            .join(BinarySecurityStageItem, BinarySecurityStageItem.task_id == BinarySecurityTask.id)
            .filter(
                BinarySecurityTask.status.in_(["pending", "dispatching", "running"]),
                BinarySecurityStageItem.downstream_service.isnot(None),
                BinarySecurityStageItem.downstream_task_id.isnot(None),
                BinarySecurityStageItem.status.in_(["pending", "queued", "running", "dispatching"]),
            )
            .distinct()
            .all()
        )
        refs: list[dict[str, str]] = []
        seen: set[str] = set()
        for task in rows:
            if task.id in seen or task.id in local_workers:
                continue
            if not self._task_needs_downstream_reconcile(task):
                continue
            seen.add(task.id)
            refs.append({"project_id": str(task.project_id), "task_id": str(task.id)})
        return refs

    def _claim_archive_job(self) -> str | None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            while True:
                job = (
                    db.query(BinarySecurityArchiveJob)
                    .filter(BinarySecurityArchiveJob.archive_status == "pending")
                    .order_by(BinarySecurityArchiveJob.created_at.asc(), BinarySecurityArchiveJob.id.asc())
                    .first()
                )
                if job is None:
                    return None
                duplicate_active = (
                    db.query(BinarySecurityArchiveJob)
                    .filter(
                        BinarySecurityArchiveJob.id != job.id,
                        BinarySecurityArchiveJob.item_id == job.item_id,
                        BinarySecurityArchiveJob.downstream_task_id == job.downstream_task_id,
                        BinarySecurityArchiveJob.archive_status.in_(["running", "archived", "applying", "success"]),
                    )
                    .first()
                )
                if duplicate_active is not None:
                    job.archive_status = "skipped"
                    job.error_message = f"duplicate archive job skipped; canonical job={duplicate_active.id}"
                    job.completed_at = _now()
                    job.updated_at = _now()
                    db.commit()
                    continue
                updated = (
                    db.query(BinarySecurityArchiveJob)
                    .filter(
                        BinarySecurityArchiveJob.id == job.id,
                        BinarySecurityArchiveJob.archive_status == "pending",
                    )
                    .update(
                        {
                            BinarySecurityArchiveJob.archive_status: "running",
                            BinarySecurityArchiveJob.owner_id: self.instance_id,
                            BinarySecurityArchiveJob.started_at: _now(),
                            BinarySecurityArchiveJob.updated_at: _now(),
                            BinarySecurityArchiveJob.attempts: int(job.attempts or 0) + 1,
                        },
                        synchronize_session=False,
                    )
                )
                db.commit()
                if updated:
                    return job.id
        finally:
            db.close()

    async def _process_archive_job(self, job_id: str) -> None:
        archived_root, error = await asyncio.to_thread(self._run_archive_copy_job, job_id)
        if error:
            observe_archive_action("copy", "failed")
            await asyncio.to_thread(
                self._enqueue_archive_state_event_by_job_id,
                job_id,
                event_type="archive_job_copy_failed",
                payload={"error": error},
            )
            return
        observe_archive_action("copy", "archived")
        await asyncio.to_thread(
            self._enqueue_archive_state_event_by_job_id,
            job_id,
            event_type="archive_job_copied",
            payload={"archive_root": archived_root},
        )

    async def _wait_archive_job_completion(self, job_id: str, task_id: str) -> BinarySecurityArchiveJob | None:
        session_factory = get_session_factory()
        while True:
            self._touch_task_heartbeat(task_id)
            db = session_factory()
            try:
                job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == job_id).first()
                if job is None:
                    return None
                if job.archive_status in {"success", "failed"}:
                    return job
            finally:
                db.close()
            await asyncio.sleep(max(1, self.cfg.scheduler.stage_poll_interval_seconds))

    def _run_archive_copy_job(self, job_id: str) -> tuple[str | None, str | None]:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == job_id).first()
            if job is None or job.archive_status != "running":
                return None, "archive job is not running"
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == job.task_id).first()
            item = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.id == job.item_id).first()
            if task is None or item is None:
                job.archive_status = "failed"
                job.error_message = "任务或阶段子任务不存在"
                job.completed_at = _now()
                db.commit()
                return None, job.error_message
            if task.status == "cancelled":
                job.archive_status = "failed"
                job.error_message = "任务已取消，跳过归档复制"
                job.completed_at = _now()
                job.updated_at = _now()
                db.commit()
                return None, job.error_message
            payload = dict(job.payload or {})
            archived_dir = self._archive_downstream_output(
                db,
                task,
                item,
                semantic_key=item.item_key,
                payload=payload.get("downstream_payload") or {},
                extra_paths=payload.get("extra_paths") or None,
            )
            if not archived_dir:
                job.archive_status = "failed"
                job.error_message = "下游产物归档未完成"
                job.completed_at = _now()
                job.updated_at = _now()
                db.commit()
                return None, job.error_message
            copy_stats = dict((item.output_ref or {}).get("archive_copy_stats") or {})
            job.payload = {
                **dict(job.payload or {}),
                "archive_copy_stats": copy_stats,
            }
            observe_archive_duration(
                action="copy",
                result="archived",
                duration_seconds=_elapsed_seconds_since(job.started_at),
            )
            job.archive_status = "archived"
            job.archive_root = str(archived_dir)
            job.error_message = None
            job.updated_at = _now()
            db.commit()
            return str(archived_dir), None
        except Exception as exc:
            db.rollback()
            try:
                job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == job_id).first()
                if job is not None:
                    job.archive_status = "failed"
                    job.error_message = str(exc)
                    job.completed_at = _now()
                    job.updated_at = _now()
                    observe_archive_duration(
                        action="copy",
                        result="failed",
                        duration_seconds=_elapsed_seconds_since(job.started_at),
                    )
                    db.commit()
            except Exception:
                db.rollback()
            return None, str(exc)
        finally:
            db.close()

    async def _apply_archive_job_status(self, job_id: str, archived_root: str | None) -> None:
        await asyncio.to_thread(
            self._enqueue_archive_state_event_by_job_id,
            job_id,
            event_type="archive_job_copied",
            payload={"archive_root": archived_root, "source": "compat_apply_request"},
        )

    async def _apply_archive_job_status_locked(
        self,
        db: Session,
        job_id: str,
        archived_root: str | None,
        *,
        state_event_id: str | None = None,
    ) -> None:
        job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == job_id).first()
        if job is None or job.archive_status not in {"archived", "running", "applying", "success"}:
            return
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == job.task_id).first()
        item = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.id == job.item_id).first()
        if task is None or item is None:
            return
        if task.status == "cancelled":
            job.archive_status = "success"
            job.error_message = None
            job.completed_at = job.completed_at or _now()
            job.updated_at = _now()
            self._record_event(
                db,
                task,
                "downstream_archive_job_ignored",
                "归档完成事件晚于取消事件到达，已忽略以避免恢复已取消任务",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "archive_job_id": job.id,
                    "state_event_id": state_event_id,
                    "archive_root": archived_root or job.archive_root,
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        try:
            payload = dict(job.payload or {})
            mapped_status = str(payload.get("mapped_status") or "").strip()
            downstream_payload = dict(payload.get("downstream_payload") or {})
            effective_archive_root = archived_root or job.archive_root
            if not mapped_status:
                job.archive_status = "failed"
                job.error_message = "归档 job 缺少目标状态"
                job.completed_at = _now()
                return
            normalized_mapped_status = self._map_downstream_status(mapped_status) or mapped_status
            downstream_error_text = json.dumps(downstream_payload, ensure_ascii=False) if downstream_payload else ""
            if normalized_mapped_status == "failed" and any(
                marker in downstream_error_text.lower()
                for marker in ("task not found", "not found", "不存在", "downstream_missing")
            ):
                normalized_mapped_status = "downstream_missing"
            if str(item.status or "").strip().lower() == "downstream_missing" and normalized_mapped_status == "failed":
                normalized_mapped_status = "downstream_missing"
            item.status = normalized_mapped_status
            item.error_message = None if normalized_mapped_status in {"queued", "running", "success"} else (
                downstream_payload.get("error") or downstream_payload.get("error_message") or downstream_payload.get("message") or item.error_message
            )
            item.finished_at = None if normalized_mapped_status in {"queued", "running"} else (item.finished_at or _now())
            item.started_at = item.started_at or _now()
            item.result = {
                **(item.result or {}),
                "downstream": self._lightweight_downstream_payload(downstream_payload),
                "downstream_status_synced_at": _now().isoformat(),
                "archive_root": effective_archive_root,
            }
            item.output_ref = {
                **(item.output_ref or {}),
                "archive_root": effective_archive_root,
            }
            if item.stage_name == "firmware_unpack" and normalized_mapped_status == "success":
                self._refresh_firmware_unpack_item_result(
                    task,
                    item,
                    archived_dir=Path(effective_archive_root) if effective_archive_root else None,
                    downstream_payload=downstream_payload,
                )
            if normalized_mapped_status in {"success", "partial_success"}:
                await self._refresh_terminal_item_result_from_downstream(
                    task,
                    item,
                    downstream_payload,
                    mapped_status=normalized_mapped_status,
                    archived_dir=Path(effective_archive_root) if effective_archive_root else None,
                )
            if item.stage_name == "system_analysis":
                self._refresh_system_analysis_stage_from_synced_items(db, task)
            else:
                self._refresh_stage_run_from_items(db, task, item.stage_name)
            self._refresh_task_status_after_sync(db, task)
            job.archive_status = "success"
            job.error_message = None
            job.completed_at = _now()
            job.updated_at = _now()
            self._record_event(
                db,
                task,
                "downstream_archive_job_completed",
                "下游产物归档完成，状态已同步",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "archive_job_id": job.id,
                    "archive_root": effective_archive_root,
                    "mapped_status": mapped_status,
                    "downstream_service": item.downstream_service,
                    "downstream_task_id": item.downstream_task_id,
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            observe_archive_action("apply", "success")
            observe_archive_duration(
                action="apply",
                result="success",
                duration_seconds=_elapsed_seconds_since(job.started_at),
            )
        except Exception as exc:
            if job is not None:
                job.archive_status = "failed"
                job.error_message = str(exc)
                job.completed_at = _now()
                job.updated_at = _now()
            observe_archive_action("apply", "failed")
            observe_archive_duration(
                action="apply",
                result="failed",
                duration_seconds=_elapsed_seconds_since(job.started_at) if job is not None else None,
            )
            raise

    def _dispatch_once(self, db: Session) -> list[str]:
        stale_reclaimed = self._reclaim_stale_dispatching_locked(db)
        stale_running_reclaimed = self._reclaim_stale_running_locked(db)
        service_config = self._load_service_config(db)
        active_count = self._active_dispatch_count(db)
        slots = max(0, service_config.max_concurrent_tasks - active_count)
        claimed_ids = self._claim_pending_tasks(db, slots)
        if stale_reclaimed or stale_running_reclaimed or claimed_ids:
            db.commit()
        return claimed_ids

    def _dispatch_task_by_id(self, db: Session, task_id: str) -> str | None:
        self._reclaim_stale_dispatching_locked(db)
        self._reclaim_stale_running_locked(db)
        service_config = self._load_service_config(db)
        active_count = self._active_dispatch_count(db)
        if active_count >= service_config.max_concurrent_tasks:
            return None
        started_at = _now()
        lease_expires_at = self._next_lease_expiry(db, now_value=started_at)
        updated = (
            db.query(BinarySecurityTask)
            .filter(
                BinarySecurityTask.id == task_id,
                BinarySecurityTask.status == "pending",
                self._lease_filter_available(),
            )
            .update(
                {
                    BinarySecurityTask.status: "dispatching",
                    BinarySecurityTask.dispatcher_instance_id: self.instance_id,
                    BinarySecurityTask.dispatch_started_at: started_at,
                    BinarySecurityTask.lease_expires_at: lease_expires_at,
                    BinarySecurityTask.updated_at: started_at,
                },
                synchronize_session=False,
            )
        )
        if updated:
            db.commit()
            return task_id
        return None

    async def _run_task(self, task_id: str) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        execution_token: str | None = None
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if (
                task is None
                or task.status != "dispatching"
                or task.dispatcher_instance_id != self.instance_id
                or not self._lease_is_active(task)
            ):
                return
            if task.started_at is None:
                task.started_at = _now()
            started_at = task.dispatch_started_at or _now()
            task.dispatch_started_at = started_at
            task.lease_expires_at = self._next_lease_expiry(db, now_value=started_at)
            execution_token = task.dispatch_started_at.isoformat() if task.dispatch_started_at else None
            task.status = "running"
            self._bind_execution_token(task)
            observe_task_lifecycle("started", status=task.status, task_type=self._task_type(task))
            self._record_event(
                db,
                task,
                "task_dispatched",
                f"任务由实例 {self.instance_id} 启动执行",
                payload={"dispatcher_instance_id": self.instance_id},
            )
            db.commit()
            await self._execute_task(task_id)
        except StaleTaskExecution:
            return
        except Exception as exc:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task:
                current_token = task.dispatch_started_at.isoformat() if task.dispatch_started_at else None
                same_execution = (
                    task.dispatcher_instance_id == self.instance_id
                    and execution_token is not None
                    and execution_token == current_token
                    and task.status in {"dispatching", "running"}
                )
                if not same_execution:
                    return
                self._enqueue_state_event(
                    db,
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name=task.current_stage,
                    event_type="task_execution_failed",
                    idempotency_key=(
                        f"task_execution_failed:{task.id}:"
                        f"{execution_token or current_token or ''}:{hashlib.sha1(str(exc).encode('utf-8')).hexdigest()}"
                    ),
                    payload={
                        "error": str(exc),
                        "dispatcher_instance_id": self.instance_id,
                        "execution_token": execution_token or current_token,
                    },
                )
                db.commit()
        finally:
            async with self._worker_lock:
                self._workers.pop(task_id, None)
            db.close()

    async def _execute_task(self, task_id: str) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if not task:
                return
            self._bind_execution_token(task)
            token = self._service_token()
            stage_sequence = self._stage_sequence_for_task(task)
            start_index = stage_sequence.index(task.current_stage) if task.current_stage in stage_sequence else 0
            stage_retry_mode = task.execution_mode in {"stage_retry", "stage_retry_failed_items", "stage_retry_full"} and bool(task.target_stage_name)
            task_retry_mode = task.execution_mode in {"task_retry", "task_retry_failed_items"} and bool(task.target_stage_name)
            target_stage_name = task.target_stage_name if (stage_retry_mode or task_retry_mode) else None
            target_stage_index = stage_sequence.index(target_stage_name) if target_stage_name in stage_sequence else start_index
            if stage_retry_mode:
                start_index = min(start_index, target_stage_index)
            archive_blocked = False
            for stage_name in stage_sequence[start_index:]:
                if stage_retry_mode and stage_sequence.index(stage_name) < target_stage_index:
                    continue
                db.refresh(task)
                if task.status == "cancelled":
                    return
                if not self._stage_enabled(task, stage_name):
                    stage_run = self._ensure_stage_run(db, task, stage_name)
                    stage_run.status = "success"
                    stage_run.started_at = stage_run.started_at or _now()
                    stage_run.finished_at = _now()
                    await self._persist_stage_run_output_summary_async(task, stage_run, {"reason": "disabled_by_stage_options"})
                    stage_run.counts = self._stage_counts(db, stage_run)
                    task.stage_summary = {
                        **task.stage_summary,
                        stage_name: {
                            "status": "success",
                            "counts": stage_run.counts,
                            "finished_at": stage_run.finished_at.isoformat(),
                            "reason": "disabled_by_stage_options",
                        },
                    }
                    self._record_event(db, task, "stage_completed", f"阶段未启用，按配置完成: {stage_name}", stage_name=stage_name)
                    observe_stage_duration(stage=stage_name, result="success", duration_seconds=_elapsed_seconds_since(stage_run.started_at))
                    db.commit()
                    continue
                start_event = self._enqueue_state_event(
                    db,
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name=stage_name,
                    event_type="stage_worker_start_requested",
                    idempotency_key=(
                        f"stage_worker_start_requested:{task.id}:{stage_name}:"
                        f"{task.dispatch_started_at.isoformat() if task.dispatch_started_at else ''}"
                    ),
                    payload={
                        "stage_name": stage_name,
                        "stage_retry_mode": bool(stage_retry_mode),
                        "task_retry_mode": bool(task_retry_mode),
                        "target_stage_name": target_stage_name,
                    },
                )
                if start_event is not None:
                    self._apply_stage_worker_start_requested_locked(db, start_event)
                handler = getattr(self, f"_stage_{stage_name}")
                stage_run = self._ensure_stage_run(db, task, stage_name)
                existing_stage_items = self._stage_items(db, task.id, stage_name) if task_retry_mode else []
                db.commit()
                retry_existing = False
                if task.execution_mode in {"stage_retry_failed_items", "task_retry_failed_items"} and stage_name == target_stage_name:
                    retry_existing = True
                elif task_retry_mode and existing_stage_items:
                    retry_existing = True
                status, summary = await handler(db, task, stage_run, token, retry_existing)
                self._enqueue_state_event(
                    db,
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name=stage_name,
                    event_type="stage_worker_terminal_observed",
                    idempotency_key=(
                        f"stage_worker_terminal_observed:{task.id}:{stage_name}:"
                        f"{task.dispatch_started_at.isoformat() if task.dispatch_started_at else ''}:{status}"
                    ),
                    payload={
                        "stage_name": stage_name,
                        "status": status,
                        "summary": summary,
                        "stage_retry_mode": bool(stage_retry_mode),
                        "task_retry_mode": bool(task_retry_mode),
                        "target_stage_name": target_stage_name,
                    },
                )
                self._record_event(
                    db,
                    task,
                    "stage_worker_terminal_observed",
                    f"阶段 worker 已完成，等待 reducer 串行收口: {stage_name}",
                    stage_name=stage_name,
                    payload={"status": status},
                )
                db.commit()
                return
                stage_run.status = "waiting_confirmation" if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION else status
                stage_run.finished_at = _now()
                observe_stage_duration(
                    stage=stage_name,
                    result=stage_run.status,
                    duration_seconds=_elapsed_seconds_since(stage_run.started_at),
                )
                await self._persist_stage_run_output_summary_async(task, stage_run, summary)
                stage_run.counts = self._stage_counts(db, stage_run)
                if status in {"failed", "partial_success", "downstream_missing"}:
                    stage_run.last_error = summary.get("error")
                task.stage_summary = {
                    **task.stage_summary,
                    stage_name: {
                        "status": stage_run.status,
                        "counts": stage_run.counts,
                        "finished_at": stage_run.finished_at.isoformat() if stage_run.finished_at else None,
                        **(
                            {
                                "failure_code": summary.get("failure_code"),
                                "failure_category": summary.get("failure_category"),
                                "failure_message": summary.get("failure_message"),
                            }
                            if summary.get("failure_code")
                            else {}
                        ),
                    },
                }
                task.current_stage = stage_name
                if stage_name == "firmware_unpack":
                    task.metrics = {
                        **task.metrics,
                        "unpacked_firmware_count": int(summary.get("success_count", 0)),
                        "failed_firmware_count": int(summary.get("failed_count", 0)),
                    }
                elif stage_name == "system_analysis":
                    task.metrics = {
                        **task.metrics,
                        "high_risk_module_count": int(summary.get("high_risk_module_count", 0)),
                        "medium_risk_module_count": int(summary.get("medium_risk_module_count", 0)),
                        "low_risk_module_count": int(summary.get("low_risk_module_count", 0)),
                        "candidate_module_count": int(summary.get("candidate_module_count", 0)),
                        "selected_module_count": int(summary.get("selected_module_count", 0)),
                    }
                elif stage_name == "entry_analysis":
                    task.metrics = {**task.metrics, "entry_count": int(summary.get("entry_count", 0))}
                elif stage_name == "vuln_scan":
                    task.metrics = {**task.metrics, "vuln_result_count": int(summary.get("vuln_result_count", 0))}
                db.commit()
                if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
                    await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
                    db.commit()
                    return
                if summary.get("archive_blocked"):
                    archive_blocked = True
                    task.status = "failed"
                    task.last_error = summary.get("error") or "总任务产物归档失败"
                    task.dispatcher_instance_id = None
                    task.dispatch_started_at = None
                    task.lease_expires_at = None
                    task.finished_at = _now()
                    observe_task_error("downstream_error", stage=stage_name, result="archive_blocked")
                    observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
                    observe_task_duration(
                        phase="execution",
                        duration_seconds=_elapsed_seconds_since(task.started_at),
                        status=task.status,
                        task_type=self._task_type(task),
                    )
                    observe_task_duration(
                        phase="total",
                        duration_seconds=_elapsed_seconds_since(task.created_at),
                        status=task.status,
                        task_type=self._task_type(task),
                    )
                    self._record_event(
                        db,
                        task,
                        "stage_archive_blocked",
                        f"阶段业务执行已完成，但总任务产物归档失败，停止后续推进: {stage_name}",
                        level="error",
                        stage_name=stage_name,
                        payload={"stage_status": status, "error": task.last_error},
                    )
                    db.commit()
                    break
                if stage_retry_mode and stage_name == target_stage_name:
                    self._record_event(
                        db,
                        task,
                        "stage_retry_finished",
                        f"阶段重试完成: {stage_name}",
                        stage_name=stage_name,
                        payload={"status": status},
                    )
                if status == "failed":
                    task.status = "failed"
                    task.last_error = summary.get("failure_message") or summary.get("error")
                    self._record_event(
                        db,
                        task,
                        "stage_failed",
                        f"阶段失败，停止后续推进: {stage_name}",
                        level="error",
                        stage_name=stage_name,
                        payload={
                            "error": task.last_error,
                            **(
                                {
                                    "failure_code": summary.get("failure_code"),
                                    "failure_category": summary.get("failure_category"),
                                    "failure_message": summary.get("failure_message"),
                                }
                                if summary.get("failure_code")
                                else {}
                            ),
                        },
                    )
                    db.commit()
                    break
            if archive_blocked:
                await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
                db.commit()
                return
            if stage_retry_mode or task_retry_mode:
                task.execution_mode = None
                task.target_stage_name = None
                summary = dict(task.summary or {})
                summary.pop("stage_retry_context", None)
                summary.pop("task_retry_context", None)
                summary.pop("retry_plan", None)
                task.summary = summary
            next_stage = self._next_incomplete_stage(db, task)
            if task.status in {"running", "dispatching"} and next_stage:
                task.status = "pending"
                task.current_stage = next_stage
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.finished_at = None
                task.last_error = None
                self._record_event(
                    db,
                    task,
                    "task_requeued_after_stage_completion",
                    f"阶段完成后任务继续进入下一阶段: {next_stage}",
                    stage_name=next_stage,
                )
                db.commit()
                self._enqueue_task(task.id)
                return
            self._finalize_task(db, task)
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            db.commit()
        finally:
            db.close()

    def _load_service_config(self, db: Session) -> BinarySecurityServiceConfigPayload:
        row = db.query(BinarySecurityServiceConfig).filter(BinarySecurityServiceConfig.config_key == "global").first()
        raw = row.config if row else {}
        return BinarySecurityServiceConfigPayload(**raw)

    def _lease_timeout_seconds(self, db: Session | None = None) -> int:
        if db is not None:
            try:
                return max(15, int(self._load_service_config(db).lease_timeout_seconds))
            except Exception:
                pass
        return 90

    def _next_lease_expiry(self, db: Session | None = None, *, now_value: datetime | None = None) -> datetime:
        return (now_value or _now()) + timedelta(seconds=self._lease_timeout_seconds(db))

    def runtime_status(self) -> dict[str, object]:
        loop_task_alive = bool(self._loop_task and not self._loop_task.done())
        action_loop_alive = bool(self._action_loop_task and not self._action_loop_task.done())
        archive_loop_alive = bool(self._archive_loop_task and not self._archive_loop_task.done())
        reconcile_loop_alive = bool(self._downstream_reconcile_task and not self._downstream_reconcile_task.done())
        state_reducer_loop_alive = bool(self._state_reducer_loop_task and not self._state_reducer_loop_task.done())
        return {
            "running": self._running,
            "loops": {
                "task_dispatch": loop_task_alive,
                "action_dispatch": action_loop_alive,
                "archive_dispatch": archive_loop_alive,
                "downstream_reconcile": reconcile_loop_alive,
                "state_reducer": state_reducer_loop_alive,
            },
            "workers": {
                "task_workers": len([task for task in self._workers.values() if not task.done()]),
                "action_workers": len([task for task in self._action_workers.values() if not task.done()]),
                "archive_workers": len([task for task in self._archive_workers if not task.done()]),
            },
        }

    def _lease_is_active(self, task: BinarySecurityTask) -> bool:
        remaining = _seconds_until(task.lease_expires_at)
        return remaining is not None and remaining > 0

    def _lease_filter_available(self):
        return or_(
            BinarySecurityTask.lease_expires_at.is_(None),
            BinarySecurityTask.lease_expires_at < _now(),
        )

    def _task_needs_downstream_reconcile(self, task: BinarySecurityTask) -> bool:
        if task.status == "pending":
            return True
        if not str(task.dispatcher_instance_id or "").strip():
            return True
        if not self._lease_is_active(task):
            return True
        heartbeat_at = task.updated_at or task.dispatch_started_at
        elapsed_seconds = _elapsed_seconds_since(heartbeat_at)
        if elapsed_seconds is None:
            return False
        grace_seconds = max(
            int(getattr(self.cfg.scheduler, "downstream_reconcile_grace_seconds", 0) or 0),
            int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15) * 2,
            30,
        )
        return elapsed_seconds >= grace_seconds

    def _active_dispatch_count(self, db: Session) -> int:
        now_value = _now()
        return int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(BinarySecurityTask.status.in_(["dispatching", "running"]))
            .filter(
                or_(
                    BinarySecurityTask.lease_expires_at.is_(None),
                    BinarySecurityTask.lease_expires_at > now_value,
                )
            )
            .scalar()
            or 0
        )

    def _claim_pending_tasks(self, db: Session, slots: int) -> list[str]:
        if slots <= 0:
            return []
        lease_expires_at = self._next_lease_expiry(db)
        candidates = (
            db.query(BinarySecurityTask.id)
            .filter(
                BinarySecurityTask.status == "pending",
                self._lease_filter_available(),
            )
            .order_by(BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
            .limit(slots)
            .all()
        )
        claimed: list[str] = []
        dispatch_started_at = _now()
        for row in candidates:
            task_id = row[0]
            updated = (
                db.query(BinarySecurityTask)
                .filter(
                    BinarySecurityTask.id == task_id,
                    BinarySecurityTask.status == "pending",
                    self._lease_filter_available(),
                )
                .update(
                    {
                        BinarySecurityTask.status: "dispatching",
                        BinarySecurityTask.dispatcher_instance_id: self.instance_id,
                        BinarySecurityTask.dispatch_started_at: dispatch_started_at,
                        BinarySecurityTask.lease_expires_at: lease_expires_at,
                        BinarySecurityTask.updated_at: dispatch_started_at,
                    },
                    synchronize_session=False,
                )
            )
            if updated:
                claimed.append(task_id)
        if claimed:
            db.flush()
        return claimed

    def _reclaim_stale_dispatching_locked(self, db: Session) -> bool:
        service_config = self._load_service_config(db)
        stale_rows = (
            db.query(BinarySecurityTask)
            .filter(
                BinarySecurityTask.status == "dispatching",
                BinarySecurityTask.dispatch_started_at.isnot(None),
                BinarySecurityTask.lease_expires_at.isnot(None),
            )
            .all()
        )
        if not stale_rows:
            return False
        local_workers = {
            task_id for task_id, worker in self._workers.items()
            if not worker.done()
        }
        reclaimed = False
        for task in stale_rows:
            if task.id in local_workers:
                continue
            lease_remaining = _seconds_until(task.lease_expires_at)
            if lease_remaining is None:
                elapsed_seconds = _elapsed_seconds_since(task.dispatch_started_at)
                if elapsed_seconds is None or elapsed_seconds < service_config.dispatch_timeout_seconds:
                    continue
            elif lease_remaining > 0:
                continue
            task.status = "pending"
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.last_error = None
            self._record_event(
                db,
                task,
                "dispatch_reclaimed",
                "调度超时，任务已回收并重新进入队列",
                level="warning",
            )
            reclaimed = True
        if reclaimed:
            db.flush()
        return reclaimed

    def _reclaim_stale_running_locked(self, db: Session) -> bool:
        service_config = self._load_service_config(db)
        timeout_seconds = max(int(service_config.dispatch_timeout_seconds) * 3, 300)
        stale_rows = (
            db.query(BinarySecurityTask)
            .filter(
                BinarySecurityTask.status == "running",
                BinarySecurityTask.dispatch_started_at.isnot(None),
                BinarySecurityTask.lease_expires_at.isnot(None),
            )
            .all()
        )
        if not stale_rows:
            return False
        local_workers = {
            task_id for task_id, worker in self._workers.items()
            if not worker.done()
        }
        reclaimed = False
        for task in stale_rows:
            if task.id in local_workers:
                continue
            lease_remaining = _seconds_until(task.lease_expires_at)
            if lease_remaining is None:
                heartbeat_at = task.updated_at or task.dispatch_started_at
                elapsed_seconds = _elapsed_seconds_since(heartbeat_at)
                if elapsed_seconds is None or elapsed_seconds < timeout_seconds:
                    continue
            elif lease_remaining > 0:
                continue
            stage_name = task.current_stage or self._stage_sequence_for_task(task)[0]
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            active_items = db.query(BinarySecurityStageItem).filter(
                BinarySecurityStageItem.task_id == task.id,
                BinarySecurityStageItem.stage_name == stage_name,
                BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
            ).all()
            has_downstream_refs = any(str(item.downstream_task_id or "").strip() for item in active_items)
            queued_only = bool(active_items) and all(
                str(item.status or "").strip().lower() in {"pending", "queued"}
                for item in active_items
            )
            if queued_only or has_downstream_refs:
                task.status = "pending" if queued_only else "running"
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.last_error = None
                self._record_event(
                    db,
                    task,
                    "running_execution_released",
                    "运行实例心跳超时，已释放过期执行实例并保留阶段状态等待安全接管",
                    level="warning",
                    stage_name=stage_name,
                    payload={
                        "stage_name": stage_name,
                        "queued_only": queued_only,
                        "has_downstream_refs": has_downstream_refs,
                        "active_item_count": len(active_items),
                    },
                )
                reclaimed = True
                continue
            if stage_run:
                stage_run.status = "failed"
                stage_run.finished_at = _now()
                stage_run.last_error = "任务执行实例心跳超时，运行状态已回收"
                self._merge_stage_run_output_summary(
                    task,
                    stage_run,
                    {
                        "error": stage_run.last_error,
                        "reclaimed": True,
                    },
                )
                running_items = db.query(BinarySecurityStageItem).filter(
                    BinarySecurityStageItem.task_id == task.id,
                    BinarySecurityStageItem.stage_name == stage_name,
                    BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
                ).all()
                for item in running_items:
                    item.status = "failed"
                    item.finished_at = _now()
                    item.error_message = item.error_message or stage_run.last_error
                stage_run.counts = self._stage_counts(db, stage_run)
            task.status = "failed"
            task.last_error = "任务执行实例心跳超时，运行状态已回收"
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.finished_at = _now()
            self._record_event(
                db,
                task,
                "running_reclaimed",
                "运行实例心跳超时，任务已回收并标记失败",
                level="error",
                stage_name=stage_name,
                payload={"stage_name": stage_name},
            )
            reclaimed = True
        if reclaimed:
            db.flush()
        return reclaimed

    def _build_queue_info(self, db: Session, *, project_id: str) -> dict[str, Any]:
        running_count = int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(
                BinarySecurityTask.status.in_(["dispatching", "running", TASK_STATUS_CONTINUE_PREPARING, TASK_STATUS_RETRY_PREPARING]),
            )
            .scalar()
            or 0
        )
        queued_rows = (
            db.query(BinarySecurityTask.id)
            .filter(
                BinarySecurityTask.status == "pending",
            )
            .order_by(BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
            .all()
        )
        pending_positions = {row[0]: index + 1 for index, row in enumerate(queued_rows)}
        return {
            "running_count": running_count,
            "queued_count": len(queued_rows),
            "pending_positions": pending_positions,
        }

    def _observe_worker_counts(self) -> None:
        observe_worker_counts(
            task_workers=len([task for task in self._workers.values() if not task.done()]),
            action_workers=len([task for task in self._action_workers.values() if not task.done()]),
            archive_workers=len([task for task in self._archive_workers if not task.done()]),
        )

    async def _observe_runtime_metrics(self, db: Session, *, reconcile_candidates: int | None = None) -> None:
        queue_snapshot = await get_task_queue().snapshot()
        pending_tasks = int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(BinarySecurityTask.status == "pending")
            .scalar()
            or 0
        )
        running_tasks = int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(BinarySecurityTask.status.in_(["dispatching", "running"]))
            .scalar()
            or 0
        )
        preparing_tasks = int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(BinarySecurityTask.status.in_(list(TASK_PREPARING_STATUSES)))
            .scalar()
            or 0
        )
        archive_pending_jobs = int(
            db.query(func.count(BinarySecurityArchiveJob.id))
            .filter(BinarySecurityArchiveJob.archive_status == "pending")
            .scalar()
            or 0
        )
        archive_running_jobs = int(
            db.query(func.count(BinarySecurityArchiveJob.id))
            .filter(BinarySecurityArchiveJob.archive_status == "running")
            .scalar()
            or 0
        )
        archive_applying_jobs = int(
            db.query(func.count(BinarySecurityArchiveJob.id))
            .filter(BinarySecurityArchiveJob.archive_status.in_(["archived", "applying"]))
            .scalar()
            or 0
        )
        leased_tasks = int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(
                BinarySecurityTask.dispatch_started_at.isnot(None),
                BinarySecurityTask.lease_expires_at.isnot(None),
            )
            .scalar()
            or 0
        )
        service_config = self._load_service_config(db)
        task_workers = len([task for task in self._workers.values() if not task.done()])
        action_workers = len([task for task in self._action_workers.values() if not task.done()])
        observe_queue_depths(
            pending_tasks=pending_tasks,
            running_tasks=running_tasks,
            preparing_tasks=preparing_tasks,
            archive_pending_jobs=archive_pending_jobs,
            archive_running_jobs=archive_running_jobs,
            archive_applying_jobs=archive_applying_jobs,
            reconcile_candidates=max(0, int(reconcile_candidates or 0)),
            redis_task_queue=int((queue_snapshot.get("task_queue") or {}).get("length", 0)),
            redis_action_queue=int((queue_snapshot.get("action_queue") or {}).get("length", 0)),
            leased_tasks=leased_tasks,
            task_queue_oldest_age_seconds=float((queue_snapshot.get("task_queue") or {}).get("oldest_age_seconds", 0.0) or 0.0),
            action_queue_oldest_age_seconds=float((queue_snapshot.get("action_queue") or {}).get("oldest_age_seconds", 0.0) or 0.0),
        )
        observe_slot_usage(
            task_active=task_workers,
            task_capacity=int(service_config.max_concurrent_tasks),
            action_active=action_workers,
            action_capacity=max(1, int(self.cfg.scheduler.downstream_action_concurrency)),
        )
        self._observe_worker_counts()

    def _finalize_task(self, db: Session, task: BinarySecurityTask) -> None:
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._last_task_heartbeat_at.pop(task.id, None)
            return
        pending_action = str(task.pending_action or "").strip()
        if pending_action in TASK_PENDING_ACTIONS:
            task.status = _preparing_status_for_action(pending_action)
            task.finished_at = None
            task.last_error = None
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._last_task_heartbeat_at.pop(task.id, None)
            return
        if task.status == "cancelled":
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.finished_at = _now()
            self._last_task_heartbeat_at.pop(task.id, None)
            return
        next_stage = self._next_incomplete_stage(db, task)
        if next_stage:
            task.status = "partial_success"
            task.current_stage = next_stage
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.finished_at = _now()
            self._last_task_heartbeat_at.pop(task.id, None)
            self._record_event(
                db,
                task,
                "task_finalize_blocked_by_incomplete_stage",
                f"任务仍有未完成阶段，拒绝收口为终态: {next_stage}",
                level="warning",
                stage_name=next_stage,
            )
            return
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        statuses = [run.status for run in stage_runs]
        vuln_run = next((run for run in stage_runs if run.stage_name == "vuln_scan"), None)
        if statuses and all(status == "success" for status in statuses):
            task.status = "success"
        elif vuln_run and vuln_run.status in {"success", "partial_success"}:
            task.status = "partial_success" if any(status in {"failed", "partial_success", "downstream_missing"} for status in statuses) else "success"
        elif any(status in {"failed", "partial_success", "downstream_missing"} for status in statuses):
            task.status = "partial_success" if any(status == "success" for status in statuses) else "failed"
        else:
            task.status = "success"
        stale_stages = list((task.summary or {}).get("stale_stages") or [])
        if stale_stages and task.status == "success":
            task.status = "partial_success"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = _now()
        self._last_task_heartbeat_at.pop(task.id, None)
        observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
        observe_task_duration(
            phase="execution",
            duration_seconds=_elapsed_seconds_since(task.started_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        observe_task_duration(
            phase="total",
            duration_seconds=_elapsed_seconds_since(task.created_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        self._record_event(db, task, "task_finished", f"任务结束: {task.status}")

    def _resolve_output_root(self, workspace_root: Path, custom_output_root: str | None) -> Path:
        if custom_output_root:
            candidate = Path(custom_output_root).resolve()
            return ensure_dir(candidate)
        return ensure_dir(workspace_root / "output")

    def _init_workspace(self, root: Path) -> None:
        for rel in ["input", "output", "run", "logs"]:
            ensure_dir(root / rel)

    async def _init_workspace_async(self, root: Path) -> None:
        await asyncio.to_thread(self._init_workspace, root)

    async def _ensure_task_directories(self, project_id: str, task_id: str, authorization_token: str) -> None:
        client = get_fileserver_client()
        task_root = client.project_files_root(project_id) / "app" / "secflow-app-binary-security" / task_id
        await client.ensure_project_directory(project_id, task_root.parent.parent, authorization_token)
        await client.ensure_project_directory(project_id, task_root.parent, authorization_token)
        await client.ensure_project_directory(project_id, task_root, authorization_token)
        for name in ("input", "output", "run"):
            await client.ensure_project_directory(project_id, task_root / name, authorization_token)
        await client.ensure_project_directory(project_id, task_root / "run" / "upload-tmp", authorization_token)

    def _write_task_metadata(self, task: BinarySecurityTask, metadata_path: Path, *, status: str) -> None:
        _write_json(
            metadata_path,
            {
                "task_id": task.id,
                "project_id": task.project_id,
                "task_type": self._task_type(task),
                "name": task.name,
                "description": task.description,
                "created_by": task.created_by,
                "created_at": task.created_at.isoformat() if task.created_at else None,
                "status": status,
                "input_files": task.summary.get("input_files", []),
                "input_kind": task.summary.get("input_kind"),
                "policy": task.policy,
                "stage_options": task.policy.get("stage_options", {}),
                "paths": {
                    "task_root": task.summary.get("task_root_path"),
                    "input_dir": task.summary.get("input_dir"),
                    "output_dir": task.summary.get("output_dir"),
                    "run_dir": task.summary.get("run_dir"),
                    "temp_upload_dir": task.summary.get("temp_upload_dir"),
                },
            },
        )

    async def _write_task_metadata_async(self, task: BinarySecurityTask, metadata_path: Path, *, status: str) -> None:
        await asyncio.to_thread(self._write_task_metadata, task, metadata_path, status=status)

    def _normalize_input_files(self, files: list[BinarySecurityInputFile | dict[str, Any]], *, task_type: str) -> list[dict[str, Any]]:
        rows = []
        seen_names: set[str] = set()
        seen_paths: set[str] = set()
        seen_keys: set[str] = set()
        for index, raw in enumerate(files):
            item = raw.model_dump(mode="json") if isinstance(raw, BinarySecurityInputFile) else dict(raw)
            filename = str(item.get("filename") or "").strip()
            if not filename:
                raise ValidationError("上传文件名不能为空")
            if "/" in filename or "\\" in filename:
                raise ValidationError(f"文件名不合法: {filename}")
            relative_path_raw = str(item.get("relative_path") or "").strip().replace("\\", "/").strip("/")
            if relative_path_raw:
                path_parts = [part for part in relative_path_raw.split("/") if part]
                if any(part in {".", ".."} for part in path_parts):
                    raise ValidationError(f"相对路径不合法: {relative_path_raw}")
                effective_path = "/".join(path_parts)
                if Path(effective_path).name != filename:
                    effective_path = "/".join([part for part in path_parts[:-1]] + [filename]) if path_parts else filename
            else:
                effective_path = filename
            if task_type == TASK_TYPE_SOURCE:
                effective_path = filename
                if filename in seen_names:
                    raise ValidationError(f"存在重复文件名: {filename}")
                seen_names.add(filename)
                if not self._is_supported_source_archive(filename):
                    raise ValidationError(f"源码扫描仅支持常见压缩文件: {filename}")
            else:
                if filename in seen_names:
                    raise ValidationError(f"存在重复文件名: {filename}")
                seen_names.add(filename)
            firmware_key = _slug(filename)
            if firmware_key in seen_keys:
                firmware_key = _slug(f"{index + 1}-{filename}")
            seen_keys.add(firmware_key)
            rows.append(
                {
                    "filename": filename,
                    "size": int(item.get("size") or 0),
                    "content_type": item.get("content_type"),
                    "relative_path": effective_path,
                    "metadata": item.get("metadata") or {},
                    "firmware_key": firmware_key,
                    "firmware_name": Path(filename).stem or filename,
                }
            )
        if not rows:
            raise ValidationError("至少需要上传一个输入文件")
        return rows

    def _is_supported_source_archive(self, filename: str) -> bool:
        lowered = str(filename or "").strip().lower()
        return any(lowered.endswith(ext) for ext in SOURCE_ARCHIVE_FORMATS)

    def _source_temp_upload_root(self, task: BinarySecurityTask) -> Path:
        return ensure_dir(Path(task.workspace_root) / "run" / "upload-tmp")

    def _check_storage_free_space(self, *, required_bytes: int = 0) -> None:
        root = Path(self.cfg.services.fileserver.data_mount_path)
        usage = shutil.disk_usage(root)
        min_required = max(
            int(getattr(self.cfg.storage, "min_free_disk_bytes", 0) or 0),
            int(required_bytes or 0),
        )
        if usage.free < min_required:
            raise ValidationError(f"存储空间不足，当前剩余 {usage.free} 字节，小于要求 {min_required} 字节")

    def _validate_uploaded_archive_size(self, filename: str, size_bytes: int, *, source_task: bool) -> None:
        max_upload = max(1, int(getattr(self.cfg.storage, "max_upload_file_bytes", 0) or 1))
        if size_bytes > max_upload:
            raise ValidationError(f"上传文件过大: {filename}，大小 {size_bytes} 超过限制 {max_upload} 字节")
        if source_task:
            max_archive = max(1, int(getattr(self.cfg.storage, "max_source_archive_bytes", 0) or 1))
            if size_bytes > max_archive:
                raise ValidationError(f"源码压缩包过大: {filename}，大小 {size_bytes} 超过限制 {max_archive} 字节")

    def _safe_extract_archive(self, archive_path: Path, target_dir: Path) -> int:
        ensure_dir(target_dir)
        extracted = 0
        extracted_bytes = 0
        max_files = max(1, int(getattr(self.cfg.storage, "max_source_extract_files", 0) or 1))
        max_bytes = max(1, int(getattr(self.cfg.storage, "max_source_extract_bytes", 0) or 1))

        def ensure_limits(member_name: str, size_bytes: int) -> None:
            nonlocal extracted, extracted_bytes
            extracted += 1
            extracted_bytes += max(0, int(size_bytes or 0))
            if extracted > max_files:
                raise ValidationError(f"压缩包解压文件数超限: {member_name}")
            if extracted_bytes > max_bytes:
                raise ValidationError(f"压缩包解压总大小超限: {member_name}")

        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive.infolist():
                    member_name = member.filename.replace("\\", "/").strip("/")
                    if not member_name:
                        continue
                    target_path = target_dir / member_name
                    if not _is_within_path(target_dir, target_path):
                        raise ValidationError(f"压缩包包含非法路径: {member.filename}")
                    if member.is_dir():
                        ensure_dir(target_path)
                        continue
                    ensure_limits(member_name, member.file_size)
                    ensure_dir(target_path.parent)
                    with archive.open(member, "r") as source, open(target_path, "wb") as dest:
                        shutil.copyfileobj(source, dest, length=1024 * 1024)
            return extracted
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as archive:
                for member in archive.getmembers():
                    member_name = member.name.replace("\\", "/").strip("/")
                    if not member_name:
                        continue
                    target_path = target_dir / member_name
                    if not _is_within_path(target_dir, target_path):
                        raise ValidationError(f"压缩包包含非法路径: {member.name}")
                    if member.isdir():
                        ensure_dir(target_path)
                        continue
                    if member.issym() or member.islnk() or not member.isfile():
                        raise ValidationError(f"压缩包包含不安全条目: {member.name}")
                    ensure_limits(member_name, member.size)
                    ensure_dir(target_path.parent)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValidationError(f"压缩包成员无法读取: {member.name}")
                    with source, open(target_path, "wb") as dest:
                        shutil.copyfileobj(source, dest, length=1024 * 1024)
            return extracted
        raise ValidationError(f"不支持的源码压缩文件格式: {archive_path.name}")

    async def _wait_for_uploaded_file(self, path: Path, *, timeout_seconds: int = 10, interval_seconds: int = 1) -> bool:
        attempts = max(1, timeout_seconds // max(1, interval_seconds)) + 1
        for attempt in range(attempts):
            if await asyncio.to_thread(path.is_file):
                return True
            if attempt < attempts - 1:
                await asyncio.sleep(interval_seconds)
        return await asyncio.to_thread(path.is_file)

    async def _materialize_source_archives(self, task: BinarySecurityTask, declared: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int]:
        input_dir = ensure_dir(Path(task.workspace_root) / "input")
        temp_dir = self._source_temp_upload_root(task)
        actual_files: list[dict[str, Any]] = []
        total_bytes = 0
        extracted_count = 0
        for file_info in declared:
            filename = str(file_info["filename"])
            temp_path = temp_dir / filename
            if not await self._wait_for_uploaded_file(temp_path, timeout_seconds=10, interval_seconds=1):
                raise ValidationError(f"上传文件缺失: {filename}")
            stat = await asyncio.to_thread(temp_path.stat)
            self._validate_uploaded_archive_size(filename, stat.st_size, source_task=True)
            self._check_storage_free_space(
                required_bytes=min(
                    int(getattr(self.cfg.storage, "max_source_extract_bytes", 0) or 0),
                    stat.st_size * 4 if stat.st_size > 0 else 0,
                )
            )
            total_bytes += stat.st_size
            extracted_count += await asyncio.to_thread(self._safe_extract_archive, temp_path, input_dir)
            await asyncio.to_thread(temp_path.unlink, missing_ok=True)
            actual_files.append(
                {
                    **file_info,
                    "size": stat.st_size,
                    "uploaded": True,
                    "path": str(task.summary.get("input_dir") or self._fileserver_task_path(task.project_id, task.id, "input")),
                    "temp_path": f"{task.summary.get('temp_upload_dir')}/{filename}" if task.summary.get("temp_upload_dir") else None,
                    "extracted": True,
                }
            )
        if extracted_count <= 0:
            raise ValidationError("源码压缩包解压后没有得到任何文件")
        await asyncio.to_thread(shutil.rmtree, temp_dir, True)
        await asyncio.to_thread(ensure_dir, temp_dir)
        return actual_files, total_bytes, extracted_count

    def _merge_policy(self, db: Session, project_id: str, overrides: dict[str, Any], stage_options: dict[str, Any]) -> dict[str, Any]:
        stage_parallelism = {stage: self.cfg.runtime_policy.max_stage_parallelism for stage in STAGE_SEQUENCE}
        base = BinarySecurityProjectConfigPayload(
            max_stage_parallelism=self.cfg.runtime_policy.max_stage_parallelism,
            max_retries_per_item=self.cfg.runtime_policy.max_retries_per_item,
            continue_on_item_failure=self.cfg.runtime_policy.continue_on_item_failure,
            partial_success_stage_advancement=DEFAULT_PARTIAL_SUCCESS_STAGE_ADVANCEMENT,
            stage_parallelism=stage_parallelism,
        ).model_dump(mode="json")
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        if row:
            base.update(row.config)
        base["partial_success_stage_advancement"] = self._normalized_partial_success_stage_advancement_map(
            base.get("partial_success_stage_advancement"),
            allowed_stages=PARTIAL_SUCCESS_ADVANCEMENT_STAGES,
            default_map=DEFAULT_PARTIAL_SUCCESS_STAGE_ADVANCEMENT,
        )
        if stage_options:
            base["stage_options"] = {
                **base.get("stage_options", {}),
                **{key: value.model_dump(mode="json") for key, value in stage_options.items()},
            }
        if overrides.get("max_stage_parallelism") is not None:
            stage_value = int(overrides["max_stage_parallelism"])
            base["max_stage_parallelism"] = stage_value
            base["stage_parallelism"] = {stage: stage_value for stage in STAGE_SEQUENCE}
        if overrides.get("stage_parallelism"):
            merged = {**base.get("stage_parallelism", {})}
            for stage_name, value in (overrides.get("stage_parallelism") or {}).items():
                if stage_name in STAGE_SEQUENCE and value is not None:
                    merged[stage_name] = int(value)
            base["stage_parallelism"] = merged
        if overrides.get("max_retries_per_item") is not None:
            base["max_retries_per_item"] = int(overrides["max_retries_per_item"])
        if overrides.get("continue_on_item_failure") is not None:
            base["continue_on_item_failure"] = bool(overrides["continue_on_item_failure"])
        if overrides.get("partial_success_stage_advancement"):
            base["partial_success_stage_advancement"] = {
                **base.get("partial_success_stage_advancement", {}),
                **self._validate_and_normalize_partial_success_stage_advancement_overrides(
                    overrides.get("partial_success_stage_advancement"),
                    task_type=overrides.get("task_type"),
                ),
            }
        if overrides.get("task_type") is not None:
            base["partial_success_stage_advancement"] = self._normalized_partial_success_stage_advancement_map(
                base.get("partial_success_stage_advancement"),
                allowed_stages=self._partial_success_advancement_stages_for_task(overrides.get("task_type")),
                default_map=self._default_partial_success_stage_advancement_for_task(overrides.get("task_type")),
                strict=False,
            )
        selection_mode = str(overrides.get("module_selection_mode") or base.get("module_selection_mode") or MODULE_SELECTION_MODE_AUTO).strip()
        if selection_mode not in {MODULE_SELECTION_MODE_AUTO, MODULE_SELECTION_MODE_MANUAL_CONFIRM}:
            selection_mode = MODULE_SELECTION_MODE_AUTO
        base["module_selection_mode"] = selection_mode
        base["module_risk_levels"] = _normalize_module_risk_levels(overrides.get("module_risk_levels") or base.get("module_risk_levels"))
        return base

    def _partial_success_advancement_stages_for_task(self, task: BinarySecurityTask | str | None) -> list[str]:
        stage_sequence = set(self._stage_sequence_for_task(task))
        return [stage_name for stage_name in PARTIAL_SUCCESS_ADVANCEMENT_STAGES if stage_name in stage_sequence]

    def _default_partial_success_stage_advancement_for_task(self, task: BinarySecurityTask | str | None) -> dict[str, bool]:
        return {
            stage_name: DEFAULT_PARTIAL_SUCCESS_STAGE_ADVANCEMENT[stage_name]
            for stage_name in self._partial_success_advancement_stages_for_task(task)
        }

    def _normalized_partial_success_stage_advancement_map(
        self,
        raw: Any,
        *,
        allowed_stages: list[str] | tuple[str, ...],
        default_map: dict[str, bool],
        strict: bool = True,
    ) -> dict[str, bool]:
        allowed = list(allowed_stages)
        payload = dict(raw or {}) if isinstance(raw, dict) else {}
        invalid_stage = next((stage for stage in payload if stage not in allowed), None)
        if invalid_stage and strict:
            raise ValidationError(f"阶段不支持配置部分成功推进: {invalid_stage}")
        normalized = {stage_name: bool(default_map.get(stage_name, True)) for stage_name in allowed}
        for stage_name, value in payload.items():
            if stage_name not in allowed:
                continue
            normalized[stage_name] = bool(value)
        return normalized

    def _validate_and_normalize_partial_success_stage_advancement_overrides(
        self,
        raw: Any,
        *,
        task_type: BinarySecurityTask | str | None,
    ) -> dict[str, bool]:
        allowed_stages = self._partial_success_advancement_stages_for_task(task_type)
        if not raw:
            return {}
        payload = dict(raw or {}) if isinstance(raw, dict) else {}
        invalid_stage = next((stage for stage in payload if stage not in allowed_stages), None)
        if invalid_stage:
            raise ValidationError(f"阶段不属于当前任务流程: {invalid_stage}")
        return {stage_name: bool(value) for stage_name, value in payload.items()}

    def _partial_success_advancement_enabled(self, task: BinarySecurityTask, stage_name: str) -> bool:
        if stage_name not in PARTIAL_SUCCESS_ADVANCEMENT_STAGES:
            return True
        stage_map = self._normalized_partial_success_stage_advancement_map(
            (task.policy or {}).get("partial_success_stage_advancement"),
            allowed_stages=self._partial_success_advancement_stages_for_task(task),
            default_map=self._default_partial_success_stage_advancement_for_task(task),
            strict=False,
        )
        return bool(stage_map.get(stage_name, True))

    def _service_token(self) -> str | None:
        return self.cfg.auth_service.service_machine_token

    def _dispatch_token(self, task: BinarySecurityTask) -> str | None:
        return task.dispatch_started_at.isoformat() if task.dispatch_started_at else None

    def _bind_execution_token(self, task: BinarySecurityTask) -> None:
        setattr(task, "_execution_dispatcher_id", task.dispatcher_instance_id)
        setattr(task, "_execution_token", self._dispatch_token(task))

    def _ensure_task_execution_current(self, task: BinarySecurityTask) -> None:
        expected_dispatcher_id = getattr(task, "_execution_dispatcher_id", None)
        expected_token = getattr(task, "_execution_token", None)
        if expected_dispatcher_id is None and expected_token is None and not task.dispatcher_instance_id and not task.dispatch_started_at:
            return
        expected_dispatcher_id = expected_dispatcher_id or task.dispatcher_instance_id
        expected_token = expected_token or self._dispatch_token(task)
        if not expected_dispatcher_id or not expected_token:
            raise StaleTaskExecution(f"任务 {task.id} 缺少当前执行 token")
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task.id).first()
            current_token = row.dispatch_started_at.isoformat() if row and row.dispatch_started_at else None
            if (
                row is None
                or row.status not in {"dispatching", "running"}
                or row.dispatcher_instance_id != expected_dispatcher_id
                or current_token != expected_token
                or not self._lease_is_active(row)
            ):
                raise StaleTaskExecution(f"任务 {task.id} 当前执行 token 已失效")
        finally:
            session.close()

    async def _ensure_task_execution_current_async(self, task: BinarySecurityTask) -> None:
        await asyncio.to_thread(self._ensure_task_execution_current, task)

    def _invalidate_task_execution(self, task: BinarySecurityTask) -> None:
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        self._last_task_heartbeat_at.pop(task.id, None)

    def _task_operation_token(self) -> str:
        return uuid.uuid4().hex

    def _task_operation_lock_expires_at(self, *, now_value: datetime | None = None, ttl_seconds: int = TASK_OPERATION_LOCK_TTL_SECONDS) -> datetime:
        base = now_value or _now()
        return base + timedelta(seconds=max(30, int(ttl_seconds)))

    def _raise_task_operation_locked(self, task_id: str) -> None:
        connection = get_engine().connect()
        try:
            row = connection.execute(
                text(
                    f"SELECT operation_lock_type, operation_lock_owner, operation_lock_expires_at "
                    f"FROM {BinarySecurityTask.__tablename__} WHERE id = :task_id"
                ),
                {"task_id": task_id},
            ).first()
        finally:
            connection.close()
        if row:
            lock_type = str(row[0] or "unknown").strip() or "unknown"
            owner = str(row[1] or "").strip()
            expires_at = row[2]
            owner_suffix = f"，持有实例 {owner}" if owner else ""
            expires_suffix = f"，预计释放时间 {expires_at}" if expires_at else ""
            raise ValidationError(f"当前任务正在执行 {lock_type} 操作{owner_suffix}{expires_suffix}，请稍后重试")
        raise ValidationError("当前任务正被其他操作修改，请稍后重试")

    def _acquire_task_operation_lease(
        self,
        db: Session,
        task_id: str,
        *,
        operation: str,
        ttl_seconds: int = TASK_OPERATION_LOCK_TTL_SECONDS,
    ) -> str:
        if not isinstance(db, Session):
            connection_factory = getattr(db, "connection", None)
            if not callable(connection_factory):
                return "test-operation-token"
            connection = connection_factory()
            lock_name = f"secflow_binary_security_task_lock:{task_id}"
            acquired = bool(
                connection.execute(
                    text("SELECT GET_LOCK(:name, :timeout)"),
                    {"name": lock_name, "timeout": 1},
                ).scalar()
            )
            if not acquired:
                raise ValidationError("当前任务正被其他操作修改，请稍后重试")
            return lock_name

        now_value = _now()
        expires_at = self._task_operation_lock_expires_at(now_value=now_value, ttl_seconds=ttl_seconds)
        token = self._task_operation_token()
        with get_engine().begin() as connection:
            result = connection.execute(
                text(
                    f"""
                    UPDATE {BinarySecurityTask.__tablename__}
                       SET operation_lock_owner = :owner,
                           operation_lock_token = :token,
                           operation_lock_type = :operation,
                           operation_lock_acquired_at = :now_value,
                           operation_lock_heartbeat_at = :now_value,
                           operation_lock_expires_at = :expires_at,
                           updated_at = :now_value
                     WHERE id = :task_id
                       AND (
                            operation_lock_expires_at IS NULL
                            OR operation_lock_expires_at < :now_value
                       )
                    """
                ),
                {
                    "owner": self.instance_id,
                    "token": token,
                    "operation": operation,
                    "now_value": now_value,
                    "expires_at": expires_at,
                    "task_id": task_id,
                },
            )
        if int(getattr(result, "rowcount", 0) or 0) != 1:
            self._raise_task_operation_locked(task_id)
        return token

    def _renew_task_operation_lease(
        self,
        task_id: str,
        *,
        token: str,
        operation: str,
        ttl_seconds: int = TASK_OPERATION_LOCK_TTL_SECONDS,
    ) -> bool:
        now_value = _now()
        expires_at = self._task_operation_lock_expires_at(now_value=now_value, ttl_seconds=ttl_seconds)
        with get_engine().begin() as connection:
            result = connection.execute(
                text(
                    f"""
                    UPDATE {BinarySecurityTask.__tablename__}
                       SET operation_lock_owner = :owner,
                           operation_lock_type = :operation,
                           operation_lock_heartbeat_at = :now_value,
                           operation_lock_expires_at = :expires_at,
                           updated_at = :now_value
                     WHERE id = :task_id
                       AND operation_lock_token = :token
                    """
                ),
                {
                    "owner": self.instance_id,
                    "operation": operation,
                    "now_value": now_value,
                    "expires_at": expires_at,
                    "task_id": task_id,
                    "token": token,
                },
            )
        return int(getattr(result, "rowcount", 0) or 0) == 1

    def _release_task_operation_lease(self, db: Session, task_id: str, *, token: str) -> None:
        if not isinstance(db, Session):
            connection_factory = getattr(db, "connection", None)
            if not callable(connection_factory):
                return
            connection = connection_factory()
            try:
                connection.execute(
                    text("SELECT RELEASE_LOCK(:name)"),
                    {"name": token},
                )
            finally:
                close_fn = getattr(connection, "close", None)
                if callable(close_fn):
                    close_fn()
            return

        now_value = _now()
        with get_engine().begin() as connection:
            connection.execute(
                text(
                    f"""
                    UPDATE {BinarySecurityTask.__tablename__}
                       SET operation_lock_owner = NULL,
                           operation_lock_token = NULL,
                           operation_lock_type = NULL,
                           operation_lock_acquired_at = NULL,
                           operation_lock_heartbeat_at = NULL,
                           operation_lock_expires_at = NULL,
                           updated_at = :now_value
                     WHERE id = :task_id
                       AND operation_lock_token = :token
                    """
                ),
                {
                    "now_value": now_value,
                    "task_id": task_id,
                    "token": token,
                },
            )

    async def _task_operation_lease_heartbeat(self, task_id: str, *, token: str, operation: str) -> None:
        interval = max(5, int(TASK_OPERATION_LOCK_HEARTBEAT_SECONDS))
        while True:
            await asyncio.sleep(interval)
            try:
                renewed = await asyncio.to_thread(
                    self._renew_task_operation_lease,
                    task_id,
                    token=token,
                    operation=operation,
                )
            except Exception:
                logger.exception("binary-security operation lock heartbeat failed: task=%s operation=%s", task_id, operation)
                return
            if not renewed:
                logger.warning("binary-security operation lock lost: task=%s operation=%s", task_id, operation)
                return

    @contextmanager
    def _task_operation_lock(self, db: Session, task_id: str, *, operation: str, ttl_seconds: int = TASK_OPERATION_LOCK_TTL_SECONDS):
        token = self._acquire_task_operation_lease(db, task_id, operation=operation, ttl_seconds=ttl_seconds)
        try:
            yield token
        finally:
            self._release_task_operation_lease(db, task_id, token=token)

    @contextmanager
    def _savepoint(self, db: Session):
        begin_nested = getattr(db, "begin_nested", None)
        if not callable(begin_nested):
            yield None
            return
        nested = begin_nested()
        try:
            yield nested
        except Exception:
            nested.rollback()
            raise

    def _is_retryable_lock_error(self, exc: BaseException) -> bool:
        current: BaseException | None = exc
        while current is not None:
            if isinstance(current, OperationalError):
                args = getattr(getattr(current, "orig", None), "args", ()) or ()
                code = args[0] if args else None
                message = str(current).lower()
                if code in {1205, 1213}:
                    return True
                if "lock wait timeout" in message or "deadlock found" in message:
                    return True
            current = getattr(current, "__cause__", None) or getattr(current, "orig", None)
        return False

    def _delete_stage_items_for_stages(
        self,
        db: Session,
        task_id: str,
        stage_names: list[str],
        *,
        batch_size: int = 100,
        max_retries: int = 3,
    ) -> int:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return 0
        deleted = 0
        while True:
            item_ids = [
                row[0]
                for row in db.query(BinarySecurityStageItem.id)
                .filter(
                    BinarySecurityStageItem.task_id == task_id,
                    BinarySecurityStageItem.stage_name.in_(normalized),
                )
                .order_by(BinarySecurityStageItem.created_at.asc(), BinarySecurityStageItem.id.asc())
                .limit(max(1, int(batch_size)))
                .all()
            ]
            if not item_ids:
                return deleted
            for attempt in range(max(1, int(max_retries))):
                try:
                    with self._savepoint(db):
                        deleted += int(
                            db.query(BinarySecurityStageItem)
                            .filter(BinarySecurityStageItem.id.in_(item_ids))
                            .delete(synchronize_session=False)
                            or 0
                        )
                        db.flush()
                    break
                except OperationalError as exc:
                    if not self._is_retryable_lock_error(exc) or attempt >= max(1, int(max_retries)) - 1:
                        raise
                    time.sleep(0.2 * (attempt + 1))

    def _delete_stage_items_by_ids(self, db: Session, item_ids: list[str]) -> int:
        normalized = [str(item_id or "").strip() for item_id in item_ids if str(item_id or "").strip()]
        if not normalized:
            return 0
        return int(
            db.query(BinarySecurityStageItem)
            .filter(BinarySecurityStageItem.id.in_(normalized))
            .delete(synchronize_session=False)
            or 0
        )

    def _stage_enabled(self, task: BinarySecurityTask, stage_name: str) -> bool:
        policy = task.policy or {}
        stage_options = policy.get("stage_options", {})
        option = stage_options.get(stage_name)
        if option is None:
            return True
        return bool(option.get("enabled", True))

    def _stage_parallelism(self, task: BinarySecurityTask, stage_name: str) -> int:
        policy = task.policy or {}
        stage_parallelism = policy.get("stage_parallelism") or {}
        if stage_name in stage_parallelism:
            return max(1, int(stage_parallelism[stage_name]))
        return max(1, int(policy.get("max_stage_parallelism") or 1))

    def _module_selection_mode(self, task: BinarySecurityTask) -> str:
        mode = str((task.policy or {}).get("module_selection_mode") or MODULE_SELECTION_MODE_AUTO).strip()
        if mode not in {MODULE_SELECTION_MODE_AUTO, MODULE_SELECTION_MODE_MANUAL_CONFIRM}:
            return MODULE_SELECTION_MODE_AUTO
        return mode

    def _module_risk_levels(self, task: BinarySecurityTask) -> list[str]:
        return _normalize_module_risk_levels((task.policy or {}).get("module_risk_levels"))

    def _mark_selected_modules(self, modules: list[dict[str, Any]], *, selected_by: str, selected_at: str | None = None) -> list[dict[str, Any]]:
        timestamp = selected_at or _now().isoformat()
        return [
            {
                **module,
                "selected_by": selected_by,
                "selected_at": timestamp,
            }
            for module in modules
        ]

    def _filter_candidate_modules(self, modules: list[dict[str, Any]], risk_levels: list[str]) -> list[dict[str, Any]]:
        allowed = set(_normalize_module_risk_levels(risk_levels))
        return [dict(module) for module in modules if str(module.get("risk_level") or "").strip() in allowed]

    def _module_metrics(self, modules: list[dict[str, Any]], candidate_modules: list[dict[str, Any]], selected_modules: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "high_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "高"),
            "medium_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "中"),
            "low_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "低"),
            "candidate_module_count": len(candidate_modules),
            "selected_module_count": len(selected_modules),
        }

    def _task_or_404(self, db: Session, project_id: str, task_id: str) -> BinarySecurityTask:
        task = db.query(BinarySecurityTask).filter(
            BinarySecurityTask.project_id == project_id,
            BinarySecurityTask.id == task_id,
        ).first()
        if not task:
            raise NotFoundError("任务不存在")
        return task

    def _ensure_stage_run(self, db: Session, task: BinarySecurityTask, stage_name: str) -> BinarySecurityStageRun:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if stage_run:
            return stage_run
        stage_run = BinarySecurityStageRun(
            id=f"sr_{uuid.uuid4().hex[:20]}",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_name,
            sequence_no=self._stage_sequence_for_task(task).index(stage_name) + 1,
            status="pending",
        )
        try:
            with self._savepoint(db):
                db.add(stage_run)
                db.flush()
            return stage_run
        except IntegrityError:
            existing = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            if existing is None:
                raise
            return existing

    def _record_event(
        self,
        db: Session,
        task: BinarySecurityTask,
        event_type: str,
        message: str,
        *,
        level: str = "info",
        stage_name: str | None = None,
        item: BinarySecurityStageItem | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        event = BinarySecurityEvent(
            id=f"evt_{uuid.uuid4().hex[:24]}",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_name,
            item_id=_stage_item_attr(item, "id"),
            item_key=_stage_item_attr(item, "item_key"),
            level=level,
            event_type=event_type,
            message=message,
        )
        event.payload = payload or {}
        db.add(event)

    def _enqueue_state_event(
        self,
        db: Session,
        *,
        task_id: str,
        project_id: str,
        event_type: str,
        idempotency_key: str,
        stage_name: str | None = None,
        item_id: str | None = None,
        archive_job_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> BinarySecurityStateEvent | None:
        event = BinarySecurityStateEvent(
            id=f"sev_{uuid.uuid4().hex[:24]}",
            task_id=task_id,
            project_id=project_id,
            stage_name=stage_name,
            item_id=item_id,
            archive_job_id=archive_job_id,
            event_type=event_type,
            idempotency_key=idempotency_key,
            status="pending",
            available_at=_now(),
            updated_at=_now(),
        )
        event.payload = payload or {}
        try:
            with self._savepoint(db):
                db.add(event)
                db.flush()
            observe_state_event(event_type, "created")
            return event
        except IntegrityError:
            observe_state_event(event_type, "duplicate")
            return None

    def _enqueue_downstream_status_event(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        mapped_status: str,
        before_status: str | None,
        downstream_status: str,
        payload: dict[str, Any],
        error_message: str | None = None,
        force: bool = False,
        event_type: str = "downstream_status_observed",
    ) -> BinarySecurityStateEvent | None:
        downstream_payload = self._lightweight_downstream_payload(payload or {})
        fingerprint_payload = {
            "item_id": item.id,
            "downstream_task_id": item.downstream_task_id,
            "mapped_status": mapped_status,
            "downstream_status": downstream_status,
            "error_message": error_message,
            "downstream_payload": downstream_payload,
        }
        fingerprint = hashlib.sha1(json.dumps(fingerprint_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        return self._enqueue_state_event(
            db,
            task_id=task.id,
            project_id=task.project_id,
            stage_name=item.stage_name,
            item_id=item.id,
            event_type=event_type,
            idempotency_key=f"{event_type}:{item.id}:{fingerprint}",
            payload={
                "mapped_status": mapped_status,
                "before_status": before_status,
                "downstream_status": downstream_status,
                "downstream_payload": downstream_payload,
                "error_message": error_message,
                "force": bool(force),
            },
        )

    def _enqueue_downstream_terminal_event(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        mapped_status: str,
        before_status: str | None,
        downstream_status: str,
        payload: dict[str, Any],
        error_message: str | None = None,
        force: bool = False,
    ) -> BinarySecurityStateEvent | None:
        return self._enqueue_downstream_status_event(
            db,
            task=task,
            item=item,
            mapped_status=mapped_status,
            before_status=before_status,
            downstream_status=downstream_status,
            payload=payload,
            error_message=error_message,
            force=force,
            event_type="downstream_terminal_observed",
        )

    def _enqueue_archive_state_event_by_job_id(self, job_id: str, *, event_type: str, payload: dict[str, Any] | None = None) -> None:
        db = get_session_factory()()
        try:
            job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == job_id).first()
            if job is None:
                observe_state_event(event_type, "missing_archive_job")
                return
            merged_payload = {**(payload or {})}
            if job.archive_root and "archive_root" not in merged_payload:
                merged_payload["archive_root"] = job.archive_root
            self._enqueue_state_event(
                db,
                task_id=job.task_id,
                project_id=job.project_id,
                stage_name=job.stage_name,
                item_id=job.item_id,
                archive_job_id=job.id,
                event_type=event_type,
                idempotency_key=f"{event_type}:{job.id}:{job.archive_status}:{job.updated_at.isoformat() if job.updated_at else ''}",
                payload=merged_payload,
            )
            db.commit()
        except Exception:
            db.rollback()
            observe_state_event(event_type, "error")
            logger.exception("binary-security failed to enqueue archive state event: job=%s type=%s", job_id, event_type)
        finally:
            db.close()

    def _stage_counts(self, db: Session, stage_run: BinarySecurityStageRun) -> dict[str, int]:
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.stage_run_id == stage_run.id).all()
        counts = {
            "total_items": len(items),
            "success_items": 0,
            "failed_items": 0,
            "downstream_missing_items": 0,
            "skipped_items": 0,
            "running_items": 0,
            "cancelled_items": 0,
        }
        for item in items:
            normalized_status = self._normalize_downstream_status(item.status) or item.status
            key = f"{normalized_status}_items"
            if key in counts:
                counts[key] += 1
            elif normalized_status in {"pending", "queued", "dispatching"}:
                counts["running_items"] += 1
        return counts

    def _normalize_downstream_status(self, status: str | None) -> str | None:
        return self._map_downstream_status(status or "")

    def _business_stage_status(
        self,
        task: BinarySecurityTask,
        stage_name: str,
        stage_run: BinarySecurityStageRun | None,
        items: list[BinarySecurityStageItem],
    ) -> str:
        if stage_name == "system_analysis":
            if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
                return "waiting_confirmation"
            if stage_run and stage_run.status == "waiting_confirmation":
                return "waiting_confirmation"
        statuses = [self._normalize_downstream_status(item.status) or item.status for item in items]
        if statuses:
            return self._aggregate_item_statuses(statuses)
        if task.current_stage == stage_name and task.status in {"running", "dispatching", TASK_STATUS_PENDING_MODULE_CONFIRMATION}:
            return "queued"
        if stage_run and stage_run.status in {"success", "partial_success", "failed", "cancelled", "waiting_confirmation"}:
            return stage_run.status
        return "pending"

    def _status_label(self, status: str) -> str:
        return {
            "pending": "pending",
            "queued": "queued",
            "running": "running",
            "applying": "applying",
            "success": "success",
            "skipped": "skipped",
            "partial_success": "partial_success",
            "failed": "failed",
            "downstream_missing": "downstream_missing",
            "cancelled": "cancelled",
            "waiting_confirmation": "waiting_confirmation",
        }.get(status, status)

    def _build_stage_summaries(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_sequence: list[str],
        stage_runs: list[BinarySecurityStageRun],
        items: list[BinarySecurityStageItem],
    ) -> list[BinarySecurityStageSummary]:
        runs_by_stage = {run.stage_name: run for run in stage_runs if run.stage_name in stage_sequence}
        items_by_stage: dict[str, list[BinarySecurityStageItem]] = {stage_name: [] for stage_name in stage_sequence}
        for item in items:
            if item.stage_name in items_by_stage:
                items_by_stage[item.stage_name].append(item)
        stage_retry_support = {
            stage_name: self._stage_retry_support(db, task, stage_name)
            for stage_name in stage_sequence
            if stage_name in runs_by_stage
        }
        stage_retry_failed_support = {
            stage_name: self._stage_retry_failed_items_support(db, task, stage_name)
            for stage_name in stage_sequence
            if stage_name in runs_by_stage
        }
        summaries: list[BinarySecurityStageSummary] = []
        for index, stage_name in enumerate(stage_sequence, start=1):
            run = runs_by_stage.get(stage_name)
            stage_items = items_by_stage.get(stage_name, [])
            counts = {
                "total_items": len(stage_items),
                "success_items": len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) == "success"]),
                "failed_items": len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) == "failed"]),
                "downstream_missing_items": len([item for item in stage_items if (self._normalize_downstream_status(item.status) or item.status) == "downstream_missing"]),
                "skipped_items": 0,
                "running_items": len(
                    [
                        item for item in stage_items
                        if (self._normalize_downstream_status(item.status) or item.status) in {"pending", "queued", "running", "dispatching"}
                    ]
                ),
            }
            summaries.append(
                BinarySecurityStageSummary(
                    stage_name=stage_name,
                    sequence_no=run.sequence_no if run else index,
                    status=self._business_stage_status(task, stage_name, run, stage_items),
                    retry_count=int(run.retry_count or 0) if run else 0,
                    retry_supported=stage_retry_support.get(stage_name, (False, None))[0],
                    retry_reason=stage_retry_support.get(stage_name, (False, None))[1],
                    retry_failed_supported=stage_retry_failed_support.get(stage_name, (False, None, []))[0],
                    retry_failed_reason=stage_retry_failed_support.get(stage_name, (False, None, []))[1],
                    retry_full_supported=stage_retry_support.get(stage_name, (False, None))[0],
                    retry_full_reason=stage_retry_support.get(stage_name, (False, None))[1],
                    total_items=counts["total_items"],
                    success_items=counts["success_items"],
                    failed_items=counts["failed_items"],
                    skipped_items=counts["skipped_items"],
                    running_items=counts["running_items"],
                    started_at=run.started_at if run else None,
                    finished_at=run.finished_at if run else None,
                    last_error=(run.last_error if run and run.last_error else next((item.error_message for item in stage_items if item.error_message), None)),
                )
            )
        return summaries

    def _aggregate_archive_stage_status(self, statuses: list[str]) -> str:
        if not statuses:
            return "pending"
        normalized = [str(status or "").strip().lower() for status in statuses]
        if any(status == "running" for status in normalized):
            return "running"
        if any(status in {"archived", "applying"} for status in normalized):
            return "applying"
        if any(status == "failed" for status in normalized):
            return "failed"
        terminal = [status for status in normalized if status != "skipped"]
        if terminal and all(status == "success" for status in terminal):
            return "success"
        return "pending"

    def _build_stage_overview_nodes(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_summaries: list[BinarySecurityStageSummary],
        archive_jobs: list[BinarySecurityArchiveJobResponse],
        stage_items: list[BinarySecurityStageItem],
    ) -> list[BinarySecurityOverviewNode]:
        stage_sequence = self._stage_sequence_for_task(task)
        summaries_by_stage = {summary.stage_name: summary for summary in stage_summaries}
        jobs_by_stage: dict[str, list[BinarySecurityArchiveJobResponse]] = {}
        items_by_stage: dict[str, list[BinarySecurityStageItem]] = {}
        for job in archive_jobs:
            jobs_by_stage.setdefault(job.stage_name, []).append(job)
        for item in stage_items:
            items_by_stage.setdefault(item.stage_name, []).append(item)
        nodes: list[BinarySecurityOverviewNode] = []
        for index, stage_name in enumerate(stage_sequence, start=1):
            summary = summaries_by_stage.get(stage_name) or BinarySecurityStageSummary(stage_name=stage_name, sequence_no=index, status="pending")
            stage_jobs = jobs_by_stage.get(stage_name, [])
            current_stage_items = items_by_stage.get(stage_name, [])
            downstream_status_counts: dict[str, int] = {}
            for item in current_stage_items:
                normalized_status = self._normalize_downstream_status(item.status) or item.status or "pending"
                downstream_status_counts[normalized_status] = downstream_status_counts.get(normalized_status, 0) + 1
            business_detail = BinarySecurityOverviewBusinessDetail(
                total_items=summary.total_items,
                success_items=summary.success_items,
                failed_items=summary.failed_items,
                downstream_missing_items=summary.downstream_missing_items,
                skipped_items=summary.skipped_items,
                running_items=summary.running_items,
                cancelled_items=downstream_status_counts.get("cancelled", 0),
                downstream_status_counts=downstream_status_counts,
                downstream_services=sorted({str(item.downstream_service) for item in current_stage_items if item.downstream_service}),
                representative_item_key=next((item.item_key for item in current_stage_items if item.item_key), None),
                representative_downstream_task_id=next((item.downstream_task_id for item in current_stage_items if item.downstream_task_id), None),
            )
            nodes.append(
                BinarySecurityOverviewNode(
                    node_id=f"business:{stage_name}",
                    node_type="business",
                    stage_name=stage_name,
                    sequence_no=summary.sequence_no or index,
                    title=STAGE_TITLES.get(stage_name, stage_name),
                    status=summary.status,
                    status_label=self._status_label(summary.status),
                    started_at=summary.started_at,
                    finished_at=summary.finished_at,
                    updated_at=summary.finished_at or summary.started_at,
                    last_error=summary.last_error,
                    retry_supported=summary.retry_supported,
                    retry_reason=summary.retry_reason,
                    retry_failed_supported=summary.retry_failed_supported,
                    retry_failed_reason=summary.retry_failed_reason,
                    retry_full_supported=summary.retry_full_supported,
                    retry_full_reason=summary.retry_full_reason,
                    detail=business_detail,
                )
            )
            first_created_at = min((job.created_at for job in stage_jobs if job.created_at), default=None)
            last_updated_at = max(
                (job.completed_at or job.updated_at or job.started_at or job.created_at for job in stage_jobs if (job.completed_at or job.updated_at or job.started_at or job.created_at)),
                default=None,
            )
            duration_seconds = None
            if first_created_at and last_updated_at:
                duration_seconds = max(0.0, (last_updated_at - first_created_at).total_seconds())
            archive_detail = BinarySecurityOverviewArchiveDetail(
                job_count=len(stage_jobs),
                success_count=len([job for job in stage_jobs if job.archive_status == "success"]),
                failed_count=len([job for job in stage_jobs if job.archive_status == "failed"]),
                running_count=len([job for job in stage_jobs if job.archive_status == "running"]),
                applying_count=len([job for job in stage_jobs if job.archive_status in {"archived", "applying"}]),
                pending_count=len([job for job in stage_jobs if job.archive_status == "pending"]),
                first_created_at=first_created_at,
                last_updated_at=last_updated_at,
                duration_seconds=duration_seconds,
                latest_error=next((job.error_message for job in reversed(stage_jobs) if job.archive_status == "failed" and job.error_message), None),
                jobs=stage_jobs,
            )
            archive_status = self._aggregate_archive_stage_status([job.archive_status for job in stage_jobs])
            terminal_item_count = sum(
                1
                for item in current_stage_items
                if (self._normalize_downstream_status(item.status) or item.status) in {"success", "failed", "partial_success", "cancelled"}
            )
            has_non_terminal_items = any(
                (self._normalize_downstream_status(item.status) or item.status) not in {"success", "failed", "partial_success", "cancelled"}
                for item in current_stage_items
            )
            # A stage may still be running while some completed items have already
            # been archived successfully. In that case the archive lane should stay
            # idle/pending until new terminal items produce new archive jobs,
            # instead of looking like an actively running archive worker.
            if archive_status == "success" and (has_non_terminal_items or len(stage_jobs) < terminal_item_count):
                archive_status = "pending"
            if stage_name == "system_analysis" and summary.status == "waiting_confirmation":
                archive_status = "pending"
            archive_retry_supported, archive_retry_reason, _ = self._archive_retry_support(db, task, stage_name)
            archive_retry_full_supported, archive_retry_full_reason, _, _ = self._archive_full_retry_support(db, task, stage_name)
            nodes.append(
                BinarySecurityOverviewNode(
                    node_id=f"archive:{stage_name}",
                    node_type="archive",
                    stage_name=stage_name,
                    sequence_no=summary.sequence_no or index,
                    title="产物归档",
                    status=archive_status,
                    status_label=self._status_label(archive_status),
                    started_at=first_created_at,
                    finished_at=last_updated_at if archive_status == "success" else None,
                    updated_at=last_updated_at,
                    last_error=archive_detail.latest_error,
                    retry_supported=archive_retry_supported,
                    retry_reason=archive_retry_reason,
                    retry_failed_supported=archive_retry_supported,
                    retry_failed_reason=archive_retry_reason,
                    retry_full_supported=archive_retry_full_supported,
                    retry_full_reason=archive_retry_full_reason,
                    detail=archive_detail,
                )
            )
        return nodes

    def _build_project_stats(self, tasks: list[BinarySecurityTask]) -> BinarySecurityProjectStats:
        active_statuses = {
            "pending",
            "dispatching",
            "running",
            TASK_STATUS_CONTINUE_PREPARING,
            TASK_STATUS_RETRY_PREPARING,
            "pending_upload",
            "uploading",
            "ready_to_start",
            TASK_STATUS_PENDING_MODULE_CONFIRMATION,
        }
        stats = BinarySecurityProjectStats(total=len(tasks))
        for task in tasks:
            status = task.status or ""
            metrics = task.metrics or {}
            if status in active_statuses:
                stats.running += 1
            elif status == "success":
                stats.success += 1
            elif status == "partial_success":
                stats.partial_success += 1
            elif status == "failed":
                stats.failed += 1
            elif status == "cancelled":
                stats.cancelled += 1
            stats.selected_module_count += int(metrics.get("selected_module_count") or 0)
            stats.candidate_module_count += int(metrics.get("candidate_module_count") or 0)
            stats.high_risk_module_count += int(metrics.get("high_risk_module_count") or 0)
            stats.entry_count += int(metrics.get("entry_count") or 0)
            stats.vuln_result_count += int(metrics.get("vuln_result_count") or 0)
            stats.input_count += int(metrics.get("firmware_item_count") or 0)
            stats.unpacked_firmware_count += int(metrics.get("unpacked_firmware_count") or 0)
            stats.failed_firmware_count += int(metrics.get("failed_firmware_count") or 0)
        return stats

    def _build_project_stage_aggregates(
        self,
        db: Session,
        tasks: list[BinarySecurityTask],
        task_type: str | None = None,
    ) -> list[BinarySecurityProjectStageAggregate]:
        if task_type:
            stage_sequence = list(TASK_STAGE_SEQUENCES.get(task_type, STAGE_SEQUENCE))
        elif tasks and all(self._task_type(task) == TASK_TYPE_SOURCE for task in tasks):
            stage_sequence = list(TASK_STAGE_SEQUENCES[TASK_TYPE_SOURCE])
        else:
            stage_sequence = list(TASK_STAGE_SEQUENCES[TASK_TYPE_BINARY])

        aggregates = {
            stage_name: BinarySecurityProjectStageAggregate(stage_name=stage_name, sequence_no=index)
            for index, stage_name in enumerate(stage_sequence, start=1)
        }
        task_ids = [task.id for task in tasks if task.id]
        if not task_ids:
            return list(aggregates.values())

        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id.in_(task_ids)).all()
        stage_items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id.in_(task_ids)).all()
        archive_jobs = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.task_id.in_(task_ids)).all()

        entered_task_ids: dict[str, set[str]] = {stage_name: set() for stage_name in stage_sequence}
        for run in stage_runs:
            if run.stage_name in entered_task_ids:
                entered_task_ids[run.stage_name].add(run.task_id)

        for item in stage_items:
            aggregate = aggregates.get(item.stage_name)
            if not aggregate:
                continue
            entered_task_ids[item.stage_name].add(item.task_id)
            status = self._normalize_downstream_status(item.status) or item.status or "unknown"
            business = aggregate.business
            business.total_items += 1
            business.status_counts[status] = business.status_counts.get(status, 0) + 1
            if status == "success":
                business.success_items += 1
            elif status == "failed":
                business.failed_items += 1
            elif status == "cancelled":
                business.cancelled_items += 1
            if status in {"pending", "queued", "running", "dispatching"}:
                business.running_items += 1

        for stage_name, task_id_set in entered_task_ids.items():
            aggregates[stage_name].business.task_count = len(task_id_set)

        for job in archive_jobs:
            aggregate = aggregates.get(job.stage_name)
            if not aggregate:
                continue
            status = str(job.archive_status or "unknown").strip().lower() or "unknown"
            archive = aggregate.archive
            archive.job_count += 1
            archive.status_counts[status] = archive.status_counts.get(status, 0) + 1
            if status == "success":
                archive.success_count += 1
            elif status == "failed":
                archive.failed_count += 1
            elif status == "running":
                archive.running_count += 1
            elif status in {"archived", "applying"}:
                archive.applying_count += 1
            elif status == "pending":
                archive.pending_count += 1

        return list(aggregates.values())

    def _task_response(self, db: Session, task: BinarySecurityTask, queue_info: dict[str, Any] | None = None) -> BinarySecurityTaskResponse:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).order_by(BinarySecurityStageRun.sequence_no.asc()).all()
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all()
        metrics = task.metrics or {}
        queue_info = queue_info or {"pending_positions": {}}
        queue_position = queue_info.get("pending_positions", {}).get(task.id)
        stage_sequence = self._stage_sequence_for_task(task)
        task_retry_supported, task_retry_reason, _ = self._task_retry_support(db, task)
        task_continue_supported, task_continue_reason, _ = self._task_continue_support(db, task)
        task_retry_failed_supported, task_retry_failed_reason, _, _ = self._task_retry_failed_items_support(db, task)
        stage_summaries = self._build_stage_summaries(db, task, stage_sequence, stage_runs, items)
        manual_operation_state = self._build_manual_operation_state(
            db,
            task,
            task_retry_supported=task_retry_supported,
            task_retry_reason=task_retry_reason,
            task_continue_supported=task_continue_supported,
            task_continue_reason=task_continue_reason,
            task_retry_failed_supported=task_retry_failed_supported,
            task_retry_failed_reason=task_retry_failed_reason,
            stage_summaries=stage_summaries,
        )
        return BinarySecurityTaskResponse(
            id=task.id,
            project_id=task.project_id,
            task_type=self._task_type(task),
            name=task.name,
            status=task.status,
            current_stage=task.current_stage,
            pending_action=task.pending_action,
            firmware_path=task.firmware_path,
            stage_sequence=stage_sequence,
            is_queued=task.status == "pending",
            queue_position=queue_position,
            dispatcher_instance_id=task.dispatcher_instance_id,
            created_by=task.created_by,
            created_at=task.created_at,
            updated_at=task.updated_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            high_risk_module_count=int(metrics.get("high_risk_module_count", 0)),
            medium_risk_module_count=int(metrics.get("medium_risk_module_count", 0)),
            low_risk_module_count=int(metrics.get("low_risk_module_count", 0)),
            candidate_module_count=int(metrics.get("candidate_module_count", 0)),
            selected_module_count=int(metrics.get("selected_module_count", 0)),
            selected_risk_levels=_normalize_module_risk_levels((task.policy or {}).get("module_risk_levels")),
            module_selection_mode=self._module_selection_mode(task),
            entry_count=int(metrics.get("entry_count", 0)),
            vuln_result_count=int(metrics.get("vuln_result_count", 0)),
            firmware_item_count=int(metrics.get("firmware_item_count", 0)),
            unpacked_firmware_count=int(metrics.get("unpacked_firmware_count", 0)),
            failed_firmware_count=int(metrics.get("failed_firmware_count", 0)),
            task_retry_supported=task_retry_supported,
            task_retry_reason=task_retry_reason,
            task_continue_supported=task_continue_supported,
            task_continue_reason=task_continue_reason,
            task_retry_failed_items_supported=task_retry_failed_supported,
            task_retry_failed_items_reason=task_retry_failed_reason,
            stage_summaries=stage_summaries,
            manual_operation_state=manual_operation_state,
        )

    def _build_manual_operation_state(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        task_retry_supported: bool,
        task_retry_reason: str | None,
        task_continue_supported: bool,
        task_continue_reason: str | None,
        task_retry_failed_supported: bool,
        task_retry_failed_reason: str | None,
        stage_summaries: list[BinarySecurityStageSummary],
    ) -> dict[str, Any]:
        now_value = _now()
        lock_active = bool(task.operation_lock_expires_at and task.operation_lock_expires_at > now_value)
        operation_type = str(task.operation_lock_type or task.pending_action or "").strip() or None
        operation_owner = str(task.operation_lock_owner or "").strip() or None
        has_stage_retry = any(bool(summary.retry_full_supported) for summary in stage_summaries)
        has_stage_retry_failed = any(bool(summary.retry_failed_supported) for summary in stage_summaries)
        preparing = task.status in TASK_PREPARING_STATUSES
        running = task.status in {"dispatching", "running"}
        waiting_modules = task.status in {TASK_STATUS_PENDING_MODULE_CONFIRMATION, "waiting_confirmation"}
        can_retry_archive = not preparing and not running and not lock_active and any(
            self._archive_retry_support(db, task, summary.stage_name)[0] or self._archive_full_retry_support(db, task, summary.stage_name)[0]
            for summary in stage_summaries
        )

        can_cancel = task.status not in TASK_TERMINAL_STATUSES and not preparing and not lock_active
        can_continue = bool(task_continue_supported) and not lock_active
        can_retry = bool(task_retry_supported) and not lock_active
        can_retry_failed_items = bool(task_retry_failed_supported) and not lock_active
        can_retry_stage = (has_stage_retry or has_stage_retry_failed) and not lock_active and not running and not preparing
        can_delete = not lock_active
        can_edit_policy = task.status not in {"dispatching", "running"} | TASK_PREPARING_STATUSES and not lock_active
        can_confirm_modules = waiting_modules and not lock_active

        blocking_code: str | None = None
        blocking_reason: str | None = None
        overall = "ready"
        summary = "当前任务允许手工操作"
        if lock_active:
            blocking_code = "task_operation_in_progress"
            blocking_reason = f"当前任务正在执行 {operation_type or '未知'} 操作，请稍后重试"
            overall = "in_progress"
            summary = blocking_reason
        elif preparing:
            blocking_code = "task_preparing"
            blocking_reason = f"当前任务正在执行 {task.pending_action or operation_type or '后台准备'}，暂不可手工操作"
            overall = "in_progress"
            summary = blocking_reason
        elif waiting_modules:
            blocking_code = "pending_module_confirmation"
            blocking_reason = "当前任务等待模块确认，请先确认模块后再执行其他操作"
            overall = "blocked"
            summary = blocking_reason
        elif running:
            blocking_code = "task_running"
            blocking_reason = f"当前任务正在执行中，当前状态 {task.status} 下仅支持取消或同步状态"
            overall = "blocked"
            summary = blocking_reason
        elif not any([can_cancel, can_continue, can_retry, can_retry_failed_items, can_retry_stage, can_retry_archive, can_delete, can_edit_policy, can_confirm_modules]):
            blocking_code = "no_manual_operation"
            blocking_reason = task_retry_failed_reason or task_continue_reason or task_retry_reason or "当前任务暂无可执行的手工操作"
            overall = "blocked"
            summary = blocking_reason

        return {
            "overall": overall,
            "summary": summary,
            "blocking_code": blocking_code,
            "blocking_reason": blocking_reason,
            "operation_in_progress": lock_active or preparing,
            "operation_type": operation_type,
            "operation_owner": operation_owner,
            "operation_expires_at": _isoformat_or_none(task.operation_lock_expires_at),
            "operation_heartbeat_at": _isoformat_or_none(task.operation_lock_heartbeat_at),
            "can_cancel": can_cancel,
            "can_continue": can_continue,
            "can_retry": can_retry,
            "can_retry_failed_items": can_retry_failed_items,
            "can_retry_stage": can_retry_stage,
            "can_retry_stage_failed_items": has_stage_retry_failed and not lock_active and not running and not preparing,
            "can_retry_stage_full": has_stage_retry and not lock_active and not running and not preparing,
            "can_retry_archive": can_retry_archive,
            "can_retry_archive_failed_items": can_retry_archive,
            "can_retry_archive_full": can_retry_archive,
            "can_delete": can_delete,
            "can_edit_policy": can_edit_policy,
            "can_confirm_modules": can_confirm_modules,
        }

    def _stage_item_response(self, item: BinarySecurityStageItem) -> BinarySecurityStageItemResponse:
        return BinarySecurityStageItemResponse(
            id=item.id,
            stage_name=item.stage_name,
            item_key=item.item_key,
            item_name=item.item_name,
            parent_key=item.parent_key,
            status=item.status,
            retry_count=item.retry_count,
            downstream_service=item.downstream_service,
            downstream_task_id=item.downstream_task_id,
            input_ref=item.input_ref,
            output_ref=item.output_ref,
            result=item.result,
            error_message=item.error_message,
            started_at=item.started_at,
            finished_at=item.finished_at,
        )

    def _stage_run_summary_path(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun) -> Path:
        return Path(task.workspace_root) / "run" / "stage-summaries" / f"{int(stage_run.sequence_no or 0):02d}_{stage_run.stage_name}.json"

    def _load_stage_run_output_summary_full(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun) -> dict[str, Any]:
        db_summary = dict(stage_run.output_summary or {})
        summary_file = db_summary.get("summary_file")
        candidate = Path(str(summary_file)) if summary_file else self._stage_run_summary_path(task, stage_run)
        if candidate.is_file():
            try:
                payload = json.loads(_read_text(candidate) or "{}")
                if isinstance(payload, dict):
                    return payload
            except Exception:
                pass
        return {}

    def _compact_stage_output_item_preview(self, stage_name: str, item: dict[str, Any]) -> dict[str, Any]:
        row = dict(item)
        if stage_name == "system_analysis":
            modules = [dict(module) for module in row.get("modules") or [] if isinstance(module, dict)]
            row["modules"] = self._lightweight_modules_for_storage(modules, limit=5)
            if "system_analysis_result" in row:
                result = dict(row.get("system_analysis_result") or {})
                result["modules"] = self._lightweight_modules_for_storage(list(result.get("modules") or []), limit=5)
                warnings = result.get("warnings") or []
                if isinstance(warnings, list):
                    result["warnings"] = warnings[:10]
                    result["warning_count"] = len(warnings)
                row["system_analysis_result"] = result
            return row
        if stage_name == "entry_analysis":
            entries = [dict(entry) for entry in row.get("entries") or row.get("entries_preview") or [] if isinstance(entry, dict)]
            return {
                "firmware_key": row.get("firmware_key"),
                "firmware_name": row.get("firmware_name"),
                "module_key": row.get("module_key"),
                "module_name": row.get("module_name"),
                "module_dir": row.get("module_dir"),
                "source_dir": row.get("source_dir"),
                "artifact_root": row.get("artifact_root"),
                "entry_count": row.get("entry_count") if row.get("entry_count") is not None else len(entries),
                "entries_preview": self._compact_entry_rows(entries[:5]),
            }
        if stage_name == "vuln_scan":
            artifact_files = row.get("artifact_files_preview") or row.get("artifact_files") or []
            return {
                "entry_key": row.get("entry_key"),
                "module_key": row.get("module_key"),
                "module_name": row.get("module_name"),
                "function_name": row.get("function_name"),
                "file_name": row.get("file_name"),
                "line_no": row.get("line_no"),
                "source_dir": row.get("source_dir"),
                "data_flow_file": row.get("data_flow_file"),
                "workspace_root": row.get("workspace_root"),
                "archive_root": row.get("archive_root"),
                "artifact_file_count": row.get("artifact_file_count") if row.get("artifact_file_count") is not None else len(artifact_files),
                "artifact_files_preview": list(artifact_files[:5]) if isinstance(artifact_files, list) else [],
            }
        if stage_name == "dataflow_analysis":
            return self._compact_dataflow_summary_item(row)
        if stage_name == "binary_to_source":
            return self._compact_b2s_summary_item(row)
        if stage_name == "firmware_unpack":
            return self._compact_firmware_unpack_summary_item(row)
        return row

    def _compact_stage_output_summary_for_db(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        full_summary: dict[str, Any] | None,
        *,
        summary_file: str | None = None,
    ) -> dict[str, Any]:
        summary = dict(full_summary or {})
        compact: dict[str, Any] = {
            "summary_externalized": bool(summary_file),
        }
        if summary_file:
            compact["summary_file"] = summary_file
        scalar_keys = [
            "status",
            "sync_status",
            "error",
            "reason",
            "failure_code",
            "failure_category",
            "failure_message",
            "reclaimed",
            "archive_blocked",
            "waiting_manual_confirmation",
            "success_count",
            "failed_count",
            "cancelled_count",
            "entry_count",
            "vuln_result_count",
            "module_count",
            "high_risk_module_count",
            "medium_risk_module_count",
            "low_risk_module_count",
            "candidate_module_count",
            "selected_module_count",
            "total_items",
            "success_items",
            "failed_items_count",
            "running_items",
            "cancelled_items_count",
            "skipped_items",
            "items_truncated",
            "failed_items_truncated",
            "cancelled_items_truncated",
            "status_synced",
        ]
        for key in scalar_keys:
            value = summary.get(key)
            if value is not None:
                compact[key] = value
        for count_key, alias in (("failed_items", "failed_items_count"), ("cancelled_items", "cancelled_items_count")):
            rows = summary.get(count_key)
            if isinstance(rows, list):
                compact[alias] = len(rows)
        items = summary.get("items")
        if isinstance(items, list):
            compact["item_count"] = len(items)
            compact["items_preview"] = [
                self._compact_stage_output_item_preview(stage_run.stage_name, item)
                for item in items[:10]
                if isinstance(item, dict)
            ]
        failed_items = summary.get("failed_items")
        if isinstance(failed_items, list):
            compact["failed_items_preview"] = [
                self._lightweight_stage_failure(item if isinstance(item, dict) else {"item": {}, "error": str(item)})
                for item in failed_items[:10]
            ]
        cancelled_items = summary.get("cancelled_items")
        if isinstance(cancelled_items, list):
            compact["cancelled_items_preview"] = [
                self._lightweight_stage_failure(item if isinstance(item, dict) else {"item": {}, "error": str(item)})
                for item in cancelled_items[:10]
            ]
        return self._fit_stage_output_summary_for_db(compact)

    def _fit_stage_output_summary_for_db(self, compact: dict[str, Any], *, max_bytes: int = 32768) -> dict[str, Any]:
        payload = dict(compact or {})

        def encoded_size(value: dict[str, Any]) -> int:
            return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))

        if encoded_size(payload) <= max_bytes:
            return payload

        items_preview = payload.get("items_preview")
        if isinstance(items_preview, list):
            shrunk_items: list[dict[str, Any]] = []
            for item in items_preview:
                if not isinstance(item, dict):
                    continue
                row = dict(item)
                entries_preview = row.get("entries_preview")
                if isinstance(entries_preview, list):
                    row["entries_preview_count"] = len(entries_preview)
                    row["entries_preview"] = entries_preview[:1]
                shrunk_items.append(row)
            payload["items_preview"] = shrunk_items[:5]
            payload["items_preview_truncated_for_db"] = True
        if encoded_size(payload) <= max_bytes:
            return payload

        for preview_key in ("failed_items_preview", "cancelled_items_preview"):
            rows = payload.get(preview_key)
            if isinstance(rows, list):
                payload[f"{preview_key}_count"] = len(rows)
                payload[preview_key] = rows[:3]
        if encoded_size(payload) <= max_bytes:
            return payload

        scalar_allowlist = {
            "summary_externalized",
            "summary_file",
            "status",
            "sync_status",
            "error",
            "reason",
            "failure_code",
            "failure_category",
            "failure_message",
            "reclaimed",
            "archive_blocked",
            "waiting_manual_confirmation",
            "success_count",
            "failed_count",
            "cancelled_count",
            "entry_count",
            "vuln_result_count",
            "module_count",
            "high_risk_module_count",
            "medium_risk_module_count",
            "low_risk_module_count",
            "candidate_module_count",
            "selected_module_count",
            "total_items",
            "success_items",
            "failed_items_count",
            "running_items",
            "cancelled_items_count",
            "skipped_items",
            "item_count",
            "items_truncated",
            "failed_items_truncated",
            "cancelled_items_truncated",
            "status_synced",
        }
        fitted = {key: value for key, value in payload.items() if key in scalar_allowlist}
        fitted["db_summary_truncated"] = True
        if encoded_size(fitted) <= max_bytes:
            return fitted

        for verbose_key in ("error", "failure_message", "reason"):
            if isinstance(fitted.get(verbose_key), str):
                fitted[verbose_key] = str(fitted[verbose_key])[:1000]
        return fitted

    def _persist_stage_run_output_summary(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        full_summary: dict[str, Any] | None,
    ) -> dict[str, Any]:
        summary_payload = dict(full_summary or {})
        summary_file: str | None = None
        try:
            path = self._stage_run_summary_path(task, stage_run)
            _write_json(path, summary_payload)
            summary_file = str(path)
        except Exception:
            summary_file = None
        compact = self._compact_stage_output_summary_for_db(task, stage_run, summary_payload, summary_file=summary_file)
        stage_run.output_summary = compact
        return compact

    async def _persist_stage_run_output_summary_async(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        full_summary: dict[str, Any] | None,
    ) -> dict[str, Any]:
        summary_payload = dict(full_summary or {})
        summary_file: str | None = None
        try:
            path = self._stage_run_summary_path(task, stage_run)
            await asyncio.to_thread(_write_json, path, summary_payload)
            summary_file = str(path)
        except Exception:
            summary_file = None
        compact = self._compact_stage_output_summary_for_db(task, stage_run, summary_payload, summary_file=summary_file)
        stage_run.output_summary = compact
        return compact

    def _merge_stage_run_output_summary(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        patch: dict[str, Any] | None,
    ) -> dict[str, Any]:
        merged = {**self._load_stage_run_output_summary_full(task, stage_run), **(patch or {})}
        return self._persist_stage_run_output_summary(task, stage_run, merged)

    async def _merge_stage_run_output_summary_async(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        patch: dict[str, Any] | None,
    ) -> dict[str, Any]:
        merged = {**self._load_stage_run_output_summary_full(task, stage_run), **(patch or {})}
        return await self._persist_stage_run_output_summary_async(task, stage_run, merged)

    def _item_stats(self, items: list[BinarySecurityStageItem]) -> dict[str, dict[str, int]]:
        stats: dict[str, dict[str, int]] = {}
        for item in items:
            entry = stats.setdefault(item.stage_name, {"total": 0, "success": 0, "failed": 0, "skipped": 0, "running": 0, "cancelled": 0})
            entry["total"] += 1
            normalized_status = self._normalize_downstream_status(item.status) or item.status
            if normalized_status in entry:
                entry[normalized_status] += 1
        return stats

    def _next_incomplete_stage(self, db: Session, task: BinarySecurityTask) -> str | None:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        runs_by_stage = {run.stage_name: run for run in stage_runs}
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            run = runs_by_stage.get(stage_name)
            if run is None:
                return stage_name
            if run.status == "partial_success":
                if not self._partial_success_advancement_enabled(task, stage_name):
                    return stage_name
                continue
            if run.status != "success":
                return stage_name
        return None

    def _retry_plan(self, task: BinarySecurityTask) -> dict[str, Any]:
        summary = dict(task.summary or {})
        plan = summary.get("retry_plan") or {}
        return dict(plan) if isinstance(plan, dict) else {}

    def _set_retry_plan(self, task: BinarySecurityTask, plan: dict[str, Any] | None) -> None:
        summary = dict(task.summary or {})
        if plan:
            summary["retry_plan"] = dict(plan)
        else:
            summary.pop("retry_plan", None)
        task.summary = summary

    def _normalize_item_status(self, status: str | None) -> str:
        return (self._normalize_downstream_status(status) or str(status or "").strip().lower() or "unknown")

    def _is_failed_retry_candidate_status(self, status: str | None) -> bool:
        return self._normalize_item_status(status) in FAILED_ITEM_RETRYABLE_STATUSES

    def _stage_retry_candidate_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> list[BinarySecurityStageItem]:
        return [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if self._is_failed_retry_candidate_status(item.status)
        ]

    @staticmethod
    def _comparable_datetime(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is not None:
            return value.astimezone().replace(tzinfo=None)
        return value

    def _upstream_stage_retried(self, db: Session, task: BinarySecurityTask, stage_name: str) -> tuple[bool, str | None]:
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            return False, None
        target_index = stage_sequence.index(stage_name)
        upstream_stages = stage_sequence[:target_index]
        summary = dict(task.summary or {})
        stale_stages = set(summary.get("stale_stages") or [])
        stale_from_stage = str(summary.get("stale_from_stage") or "").strip()
        if stage_name in stale_stages and stale_from_stage in upstream_stages:
            return True, stale_from_stage

        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        runs_by_stage = {run.stage_name: run for run in stage_runs}
        target_items = [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if item.stage_name == stage_name
        ]
        target_created_at = [
            comparable
            for comparable in (self._comparable_datetime(item.created_at) for item in target_items)
            if comparable is not None
        ]
        earliest_target_created_at = min(target_created_at) if target_created_at else None

        for upstream_stage in upstream_stages:
            run = runs_by_stage.get(upstream_stage)
            if not run or int(run.retry_count or 0) <= 0:
                continue
            upstream_completed_at = self._comparable_datetime(run.finished_at or run.started_at)
            if earliest_target_created_at and upstream_completed_at and earliest_target_created_at > upstream_completed_at:
                continue
            if run and int(run.retry_count or 0) > 0:
                return True, upstream_stage
        return False, None

    def _first_failed_retry_stage(self, db: Session, task: BinarySecurityTask) -> tuple[str | None, list[BinarySecurityStageItem]]:
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            items = self._stage_retry_candidate_items(db, task, stage_name)
            if items:
                return stage_name, items
        return None, []

    @staticmethod
    def _clear_failure_fields_from_summary(summary: dict[str, Any]) -> dict[str, Any]:
        cleaned = dict(summary or {})
        for key in ("failure_code", "failure_category", "failure_message", "error"):
            cleaned.pop(key, None)
        return cleaned

    def _retry_snapshot_for_item(self, task: BinarySecurityTask, stage_name: str, item_key: str) -> dict[str, Any] | None:
        summary = task.summary or {}
        stage_context = (summary.get("stage_retry_context") or {}).get(stage_name) or {}
        snapshot = stage_context.get(item_key)
        return dict(snapshot) if isinstance(snapshot, dict) else None

    def _stage_result_keys(self, stage_name: str) -> list[str]:
        return list(STAGE_SUMMARY_RESULT_KEYS.get(stage_name, []))

    def _stage_expected_service(self, stage_name: str) -> str | None:
        mapping = STAGE_RETRY_ENDPOINTS.get(stage_name)
        return mapping[0] if mapping else None

    async def _fetch_downstream_task_payload(self, task: BinarySecurityTask, item: BinarySecurityStageItem, token: str) -> dict[str, Any]:
        task_id = str(item.downstream_task_id or "").strip()
        if not task_id:
            raise ValidationError("缺少下游任务ID")
        if item.downstream_service == "firmware_unpacker":
            return await get_firmware_unpacker_client().get_task(task.project_id, task_id, token or "")
        if item.downstream_service == "system_analyse":
            return await get_system_analyse_client().get_task(task_id)
        if item.downstream_service == "binary_to_source":
            project_id = (item.result or {}).get("project_id") or task.project_id
            return await get_binary_to_source_client().get_task(project_id, task_id, token or "")
        if item.downstream_service == "entry_analyse":
            return await get_entry_analyse_client().get_task(task_id, token or "")
        if item.downstream_service == "dataflow_analyse":
            return await get_dataflow_analyse_client().get_task(task_id)
        if item.downstream_service == "dataflow_vuln_scanner":
            return await get_dataflow_vuln_scanner_client().get_task(task_id, token or "")
        raise ValidationError(f"未知下游服务: {item.downstream_service}")

    async def _refresh_terminal_item_result_from_downstream(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        payload: dict[str, Any],
        *,
        mapped_status: str,
        archived_dir: Path | None,
    ) -> None:
        if item.stage_name != "system_analysis" or item.downstream_service != "system_analyse":
            return
        if mapped_status != "success":
            return
        result_payload: dict[str, Any] = {}
        try:
            result_payload = await get_system_analyse_client().get_task_result(str(item.downstream_task_id))
        except Exception:
            result_payload = {}
        firmware = self._system_analysis_input_for_item(task, item)
        artifact_root = archived_dir or self._service_output_dir(
            task,
            item.downstream_service or item.stage_name,
            item.item_key,
            item.downstream_task_id,
        )
        modules = self._parse_system_analysis_modules(artifact_root, firmware, result_payload)
        item.result = {
            **self._lightweight_system_analysis_input(firmware),
            "artifact_root": str(artifact_root),
            "archive_root": str(artifact_root),
            "modules": self._lightweight_modules_for_storage(modules),
            "module_count": len(modules),
            "downstream": self._lightweight_downstream_payload(payload),
            "system_analysis_result": self._lightweight_system_analysis_result(result_payload),
            "downstream_status_synced_at": _now().isoformat(),
        }
        item.output_ref = {
            **(item.output_ref or {}),
            "artifact_root": str(artifact_root),
            "archive_root": str(artifact_root),
        }

    def _refresh_firmware_unpack_item_result(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        archived_dir: Path | None,
        downstream_payload: dict[str, Any] | None = None,
    ) -> None:
        input_ref = dict(item.input_ref or {})
        result = dict(item.result or {})
        firmware_key = str(item.item_key or input_ref.get("firmware_key") or result.get("firmware_key") or "")
        filename = str(input_ref.get("filename") or item.item_name or result.get("filename") or firmware_key)
        metadata_sources = self._resolve_downstream_output_sources(
            downstream_payload or result.get("downstream") or {},
            downstream_task_id=item.downstream_task_id,
            task=task,
            downstream_service=item.downstream_service,
        )
        runtime_output_path = str(metadata_sources[0]) if metadata_sources else ""
        unpacked_root = str(archived_dir) if archived_dir else str(
            (item.output_ref or {}).get("archive_root")
            or result.get("archive_root")
            or result.get("unpacked_root")
            or runtime_output_path
        )
        item.result = {
            **result,
            "firmware_key": firmware_key,
            "firmware_name": str(result.get("firmware_name") or Path(filename).stem or firmware_key),
            "filename": filename,
            "input_path": str(input_ref.get("path") or result.get("input_path") or ""),
            "unpacked_root": unpacked_root,
            "source_root": str(result.get("source_root") or unpacked_root),
            "task_type": result.get("task_type", TASK_TYPE_BINARY),
            "downstream": self._lightweight_downstream_payload(downstream_payload or result.get("downstream") or {}),
            "downstream_status_synced_at": _now().isoformat(),
        }
        item.output_ref = {
            **(item.output_ref or {}),
            "runtime_output_path": runtime_output_path,
            "unpacked_root": unpacked_root,
            **({"archive_root": str(archived_dir)} if archived_dir else {}),
        }

    def _system_analysis_input_for_item(self, task: BinarySecurityTask, item: BinarySecurityStageItem) -> dict[str, Any]:
        for candidate in self._system_analysis_inputs(task):
            if str(candidate.get("firmware_key") or "") == str(item.item_key or ""):
                return dict(candidate)
        input_ref = dict(item.input_ref or {})
        return {
            "firmware_key": str(item.item_key or input_ref.get("firmware_key") or SOURCE_TASK_INPUT_KEY),
            "firmware_name": str(item.item_name or task.name),
            "filename": str(item.item_name or input_ref.get("filename") or item.item_key or "source-project"),
            "unpacked_root": str(input_ref.get("input_path") or input_ref.get("unpacked_root") or Path(task.workspace_root) / "input"),
            "source_root": str(input_ref.get("source_root") or input_ref.get("input_path") or Path(task.workspace_root) / "input"),
            "task_type": self._task_type(task),
        }

    def _map_downstream_status(self, status: str) -> str | None:
        normalized = (status or "").lower()
        if normalized in {"downstream_missing", "not_found", "missing", "task_not_found"}:
            return "downstream_missing"
        if normalized in {"pending", "queued", "created", "dispatching", "ready", "ready_to_start"}:
            return "queued"
        if normalized in {"running", "processing", "in_progress", "cancelling", "started"}:
            return "running"
        if normalized in {"success", "passed", "completed", "complete", "done"}:
            return "success"
        if normalized == "partial_success":
            return "partial_success"
        if normalized == "skipped":
            return "failed"
        if normalized in {"invalid_input", "completed_limited"}:
            return "failed"
        if normalized in {"failed", "error", "failure"}:
            return "failed"
        if normalized in {"cancelled", "canceled"}:
            return "cancelled"
        return None

    def _aggregate_item_statuses(self, statuses: list[str]) -> str:
        if not statuses:
            return "pending"
        active = {"pending", "queued", "running", "dispatching"}
        if any(status in active for status in statuses):
            return "running"
        if all(status == "success" for status in statuses):
            return "success"
        if any(status == "success" for status in statuses) and any(status in {"failed", "cancelled", "partial_success", "downstream_missing"} for status in statuses):
            return "partial_success"
        if all(status == "cancelled" for status in statuses):
            return "cancelled"
        if all(status == "downstream_missing" for status in statuses):
            return "downstream_missing"
        if any(status in {"failed", "partial_success"} for status in statuses):
            return "failed"
        if any(status == "downstream_missing" for status in statuses):
            return "downstream_missing"
        return statuses[0]

    def _refresh_stage_run_from_items(self, db: Session, task: BinarySecurityTask, stage_name: str) -> None:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if not stage_run:
            return
        items = self._stage_items(db, task.id, stage_name)
        status = self._aggregate_item_statuses([item.status for item in items])
        stage_run.status = status
        stage_run.counts = self._stage_counts(db, stage_run)
        stage_run.last_error = next(
            (
                item.error_message
                for item in items
                if item.status in {"failed", "downstream_missing"} and item.error_message
            ),
            None,
        )
        self._merge_stage_run_output_summary(
            task,
            stage_run,
            {
                "status_synced": True,
                "sync_status": status,
                **stage_run.counts,
            },
        )
        if status in {"running", "pending", "queued"}:
            stage_run.finished_at = None
            stage_run.started_at = stage_run.started_at or _now()
        else:
            stage_run.finished_at = stage_run.finished_at or _now()
        if stage_name == "firmware_unpack":
            success_items = [dict(item.result or {}) for item in items if item.status == "success"]
            compact_success = self._compact_stage_success_items("firmware_unpack_results", success_items)
            task.summary = {**(task.summary or {}), "firmware_unpack_results": compact_success}
            task.metrics = {
                **(task.metrics or {}),
                "unpacked_firmware_count": int(stage_run.counts.get("success_items", 0)),
                "failed_firmware_count": int(stage_run.counts.get("failed_items", 0)),
            }
        elif stage_name == "entry_analysis":
            self._rebuild_entry_results_from_stage_items(db, task, stage_run)

    def _rebuild_entry_results_from_stage_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> list[dict[str, Any]]:
        """Rebuild full entry_results after downstream sync only updated stage items.

        Stage item result_json intentionally stores only entries_preview to keep DB rows
        small, so the authoritative source for full entries is the archived artifact.
        """
        items = [
            item
            for item in self._stage_items(db, task.id, "entry_analysis")
            if item.status == "success"
        ]
        rebuilt: list[dict[str, Any]] = []
        for item in items:
            result = dict(item.result or {})
            input_ref = dict(item.input_ref or {})
            output_ref = dict(item.output_ref or {})
            module = {
                **input_ref,
                **result,
                "module_key": str(result.get("module_key") or input_ref.get("module_key") or item.item_key or ""),
                "module_name": str(result.get("module_name") or input_ref.get("module_name") or item.item_name or ""),
                "source_dir": str(result.get("source_dir") or input_ref.get("source_dir") or task.firmware_path or ""),
            }
            if not module["module_key"] or not module["module_name"]:
                continue
            artifact_root_value = (
                output_ref.get("artifact_root")
                or output_ref.get("archive_root")
                or result.get("artifact_root")
                or result.get("archive_root")
            )
            entries = [dict(entry) for entry in result.get("entries") or [] if isinstance(entry, dict)]
            if artifact_root_value:
                artifact_root = Path(str(artifact_root_value))
                parsed_entries = self._parse_entries(artifact_root, module)
                if parsed_entries:
                    entries = parsed_entries
                    module["artifact_root"] = str(artifact_root)
            if not entries:
                entries = [dict(entry) for entry in result.get("entries_preview") or [] if isinstance(entry, dict)]
            if not entries:
                continue
            rebuilt.append(self._compact_entry_summary_item({**module, "entries": entries}))

        if not rebuilt:
            return []

        summary = {**(task.summary or {}), "entry_results": rebuilt}
        task.summary = summary
        entry_count = self._entry_count_for_summary("entry_results", rebuilt)
        task.metrics = {**(task.metrics or {}), "entry_count": entry_count}
        if stage_run is not None:
            stage_summary = {
                "items": self._compact_stage_success_items_for_db("entry_results", rebuilt),
                "failed_items": [
                    self._lightweight_stage_failure({"item": dict(item.input_ref or item.result or {}), "error": item.error_message})
                    for item in self._stage_items(db, task.id, "entry_analysis")
                    if item.status in {"failed", "cancelled", "downstream_missing"}
                ],
                "success_count": len(rebuilt),
                "failed_count": int((stage_run.counts or {}).get("failed_items") or 0),
                "cancelled_count": int((stage_run.counts or {}).get("cancelled_items") or 0),
                "entry_count": entry_count,
                "status_synced": True,
                "sync_status": stage_run.status,
                **(stage_run.counts or {}),
            }
            self._persist_stage_run_output_summary(task, stage_run, stage_summary)
        return rebuilt

    def _refresh_system_analysis_stage_from_synced_items(self, db: Session, task: BinarySecurityTask) -> None:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == "system_analysis",
        ).first()
        if not stage_run:
            return
        items = self._stage_items(db, task.id, "system_analysis")
        success = []
        failed = [
            {"status": item.status, "error": item.error_message, "item_key": item.item_key}
            for item in items
            if item.status in {"failed", "cancelled", "downstream_missing"}
        ]
        all_modules: list[dict[str, Any]] = []
        for item in items:
            if item.status != "success":
                continue
            result = dict(item.result or {})
            item_modules = self._system_analysis_modules_from_item(task, item)
            all_modules.extend(item_modules)
            success.append({**result, "modules": self._lightweight_modules_for_storage(item_modules), "module_count": len(item_modules)})
        status = self._aggregate_item_statuses([item.status for item in items])
        candidate_modules = self._filter_candidate_modules(all_modules, self._module_risk_levels(task))
        selected_modules: list[dict[str, Any]] = []
        if status in {"success", "partial_success"} and candidate_modules:
            if self._module_selection_mode(task) == MODULE_SELECTION_MODE_AUTO:
                selected_modules = self._mark_selected_modules(candidate_modules, selected_by=MODULE_SELECTION_MODE_AUTO)
            else:
                task.status = TASK_STATUS_PENDING_MODULE_CONFIRMATION
                self._record_event(
                    db,
                    task,
                    "module_selection_required",
                    "系统分析已同步完成，等待人工确认模块",
                    stage_name="system_analysis",
                    payload={"candidate_module_count": len(candidate_modules)},
                )
        no_candidate_modules_failure = status == "success" and not failed and not candidate_modules
        if no_candidate_modules_failure:
            failure = _no_candidate_modules_failure()
            status = "failed"
            failed = failed or [{"status": "failed", **failure}]
        summary = dict(task.summary or {})
        summary.update(
            {
                "system_analysis_results": self._lightweight_system_analysis_items(success),
                "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
                "system_analysis_module_count": len(all_modules),
                "candidate_modules": candidate_modules,
                "selected_modules": selected_modules,
                "high_risk_modules": selected_modules,
                **(_no_candidate_modules_failure() if no_candidate_modules_failure else {}),
            }
        )
        task.summary = summary
        task.metrics = {
            **(task.metrics or {}),
            **self._module_metrics(all_modules, candidate_modules, selected_modules),
        }
        stage_run.status = "waiting_confirmation" if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION else status
        stage_run.finished_at = None if stage_run.status in {"running", "pending", "queued"} else (stage_run.finished_at or _now())
        stage_run.started_at = stage_run.started_at or _now()
        stage_run.counts = self._stage_counts(db, stage_run)
        stage_run.last_error = failed[0].get("error") if failed and status == "failed" else None
        if no_candidate_modules_failure and stage_run.last_error == NO_CANDIDATE_MODULES_FAILURE_MESSAGE:
            task.last_error = stage_run.last_error
            self._record_event(
                db,
                task,
                "system_analysis_no_candidate_modules",
                NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
                level="error",
                stage_name="system_analysis",
                payload=_no_candidate_modules_failure(),
            )
        self._persist_stage_run_output_summary(
            task,
            stage_run,
            {
                "items": self._lightweight_system_analysis_items(success),
                "failed_items": failed,
                "success_count": len(success),
                "failed_count": len(failed),
                "module_count": len(all_modules),
                "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
                "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
                "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
                "candidate_module_count": len(candidate_modules),
                "selected_module_count": len(selected_modules),
                "status_synced": True,
                "sync_status": stage_run.status,
                "error": stage_run.last_error,
                **(_no_candidate_modules_failure() if no_candidate_modules_failure else {}),
                **stage_run.counts,
            },
        )

    def _refresh_task_status_after_sync(self, db: Session, task: BinarySecurityTask) -> None:
        if task.status == "cancelled":
            self._invalidate_task_execution(task)
            task.finished_at = task.finished_at or _now()
            return
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.finished_at = None
            return
        pending_action = str(task.pending_action or "").strip()
        if pending_action in TASK_PENDING_ACTIONS:
            task.status = _preparing_status_for_action(pending_action)
            task.finished_at = None
            task.last_error = None
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._enqueue_action(task.id)
            return
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        statuses = [run.status for run in stage_runs]
        if any(status in {"running", "dispatching"} for status in statuses):
            task.status = "running"
            task.finished_at = None
            task.last_error = None
            return
        stage_retry_mode = task.execution_mode in {"stage_retry", "stage_retry_failed_items", "stage_retry_full"} and bool(task.target_stage_name)
        task_retry_mode = task.execution_mode in {"task_retry", "task_retry_failed_items"} and bool(task.target_stage_name)
        if stage_retry_mode:
            task.execution_mode = None
            task.target_stage_name = None
            summary = dict(task.summary or {})
            summary.pop("stage_retry_context", None)
            summary.pop("retry_plan", None)
            task.summary = summary
        if task_retry_mode:
            task.execution_mode = None
            task.target_stage_name = None
            summary = dict(task.summary or {})
            summary.pop("task_retry_context", None)
            summary.pop("retry_plan", None)
            task.summary = summary
        next_stage = self._next_incomplete_stage(db, task)
        next_stage_run = next((run for run in stage_runs if run.stage_name == next_stage), None)
        next_stage_status = next_stage_run.status if next_stage_run else "pending"
        if next_stage and next_stage_status in {"pending", "queued"}:
            task.status = "pending"
            task.current_stage = next_stage
            task.finished_at = None
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.last_error = None
            summary = dict(task.summary or {})
            if summary.get("stale_from_stage") and next_stage in set(summary.get("stale_stages") or []):
                summary["stale_stages"] = []
                summary["stale_reason"] = None
                summary["stale_from_stage"] = None
                task.summary = summary
            self._record_event(
                db,
                task,
                "task_requeued_after_downstream_sync",
                f"下游状态同步完成，任务继续进入阶段: {next_stage}",
                stage_name=next_stage,
            )
            self._enqueue_task(task.id)
            return
        self._finalize_task(db, task)

    def _stage_items(self, db: Session, task_id: str, stage_name: str) -> list[BinarySecurityStageItem]:
        return db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task_id,
            BinarySecurityStageItem.stage_name == stage_name,
        ).order_by(BinarySecurityStageItem.created_at.asc()).all()

    def _stage_item_identity(self, item_key: str, parent_key: str | None) -> str:
        return build_stage_item_identity_key(item_key, parent_key)

    def _find_stage_item(
        self,
        db: Session,
        *,
        task_id: str,
        stage_name: str,
        item_key: str,
        parent_key: str | None,
    ) -> BinarySecurityStageItem | None:
        identity_key = build_stage_item_identity_key(item_key, parent_key)
        items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task_id,
            BinarySecurityStageItem.stage_name == stage_name,
            BinarySecurityStageItem.item_identity_key == identity_key,
        ).order_by(BinarySecurityStageItem.created_at.asc()).all()
        if not items:
            items = db.query(BinarySecurityStageItem).filter(
                BinarySecurityStageItem.task_id == task_id,
                BinarySecurityStageItem.stage_name == stage_name,
                BinarySecurityStageItem.item_key == item_key,
            ).order_by(BinarySecurityStageItem.created_at.asc()).all()
        matches = [item for item in items if (item.parent_key or None) == (parent_key or None)]
        if len(matches) > 1:
            raise ValidationError(f"阶段 {stage_name} 存在重复历史 item，无法安全重试: {item_key}")
        return matches[0] if matches else None

    def _upsert_stage_item(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        stage_name: str,
        item_key: str,
        item_name: str | None,
        parent_key: str | None,
        downstream_service: str,
        input_ref: dict[str, Any],
        output_ref: dict[str, Any] | None = None,
        retrying: bool,
        running_status: str = "running",
    ) -> BinarySecurityStageItem:
        identity_key = build_stage_item_identity_key(item_key, parent_key)
        item = self._find_stage_item(
            db,
            task_id=task.id,
            stage_name=stage_name,
            item_key=item_key,
            parent_key=parent_key,
        )
        if item is None:
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_name,
                item_key=item_key,
                item_name=item_name,
                parent_key=parent_key,
                item_identity_key=identity_key,
                status=running_status,
                downstream_service=downstream_service,
                started_at=_now(),
            )
            if retrying:
                item.retry_count = 1
        else:
            item.stage_run_id = stage_run.id
            item.item_name = item_name
            item.parent_key = parent_key
            item.item_identity_key = identity_key
            item.status = running_status
            item.downstream_service = downstream_service
            item.error_message = None
            item.finished_at = None
            item.started_at = _now()
            item.payload = {}
            item.result = {}
            if retrying:
                item.retry_count = int(item.retry_count or 0) + 1
        item.input_ref = input_ref
        if output_ref is not None:
            item.output_ref = output_ref
        try:
            with self._savepoint(db):
                db.add(item)
                db.flush()
        except IntegrityError:
            existing = self._find_stage_item(
                db,
                task_id=task.id,
                stage_name=stage_name,
                item_key=item_key,
                parent_key=parent_key,
            )
            if existing is None:
                raise
            existing.stage_run_id = stage_run.id
            existing.item_name = item_name
            existing.parent_key = parent_key
            existing.item_identity_key = identity_key
            existing.status = running_status
            existing.downstream_service = downstream_service
            existing.error_message = None
            existing.finished_at = None
            existing.started_at = _now()
            existing.payload = {}
            existing.result = {}
            if retrying:
                existing.retry_count = int(existing.retry_count or 0) + 1
            existing.input_ref = input_ref
            if output_ref is not None:
                existing.output_ref = output_ref
            item = existing
        return item

    def _prepare_stage_items_for_execution(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        inputs: list[dict[str, Any]],
        downstream_service: str,
        identity,
        output_ref,
    ) -> list[dict[str, Any]]:
        """Persist every intended stage item as queued before fan-out execution starts."""
        retry_plan = self._retry_plan(task)
        retry_item_keys = set(retry_plan.get("retry_item_keys") or [])
        target_stage = str(retry_plan.get("target_stage") or "").strip()
        retry_failed_only = (
            stage_run.stage_name == target_stage
            and str(retry_plan.get("mode") or "").strip() in {TASK_ACTION_RETRY_FAILED_ITEMS, TASK_ACTION_RETRY_STAGE_FAILED_ITEMS}
            and bool(retry_item_keys)
        )
        executable_inputs: list[dict[str, Any]] = []
        last_error: Exception | None = None
        for _ in range(2):
            try:
                for input_item in inputs:
                    item_key, item_name, parent_key, input_ref = identity(input_item)
                    identity_key = build_stage_item_identity_key(item_key, parent_key)
                    if retry_failed_only and identity_key not in retry_item_keys:
                        continue
                    executable_inputs.append(input_item)
                    item = self._find_stage_item(
                        db,
                        task_id=task.id,
                        stage_name=stage_run.stage_name,
                        item_key=item_key,
                        parent_key=parent_key,
                    )
                    if item is None:
                        item = BinarySecurityStageItem(
                            id=f"si_{uuid.uuid4().hex[:20]}",
                            task_id=task.id,
                            project_id=task.project_id,
                            stage_run_id=stage_run.id,
                            stage_name=stage_run.stage_name,
                            item_key=item_key,
                            item_name=item_name,
                            parent_key=parent_key,
                            item_identity_key=identity_key,
                            status="queued",
                            downstream_service=downstream_service,
                        )
                        db.add(item)
                    else:
                        item.stage_run_id = stage_run.id
                        item.item_name = item_name
                        item.parent_key = parent_key
                        item.item_identity_key = identity_key
                        item.status = "queued"
                        item.downstream_service = downstream_service
                        item.error_message = None
                        item.started_at = None
                        item.finished_at = None
                        item.payload = {}
                        item.result = {}
                    item.input_ref = input_ref
                    item.output_ref = output_ref(input_item)
                db.commit()
                return executable_inputs
            except IntegrityError as exc:
                db.rollback()
                executable_inputs = []
                last_error = exc
                continue
        raise last_error or ValidationError(f"阶段 {stage_run.stage_name} 初始化阶段子任务失败")

    def _invoke_existing_downstream_retry(
        self,
        stage_name: str,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
    ):
        downstream_task_id = str(item.downstream_task_id or "").strip()
        if not downstream_task_id:
            raise ValidationError("缺少下游任务ID，无法安全重试")
        expected_service = self._stage_expected_service(stage_name)
        if expected_service and item.downstream_service != expected_service:
            raise ValidationError(
                f"下游服务不匹配，无法安全重试: 期望 {expected_service}，实际 {item.downstream_service or '-'}"
            )
        if stage_name == "firmware_unpack":
            return get_firmware_unpacker_client().retry_task(downstream_task_id, token or "")
        if stage_name == "system_analysis":
            return get_system_analyse_client().restart_task(downstream_task_id)
        if stage_name == "binary_to_source":
            return get_binary_to_source_client().rerun_task(
                task.project_id,
                downstream_task_id,
                token or "",
                clean_output=True,
                cancel_running=True,
            )
        if stage_name == "entry_analysis":
            return get_entry_analyse_client().restart_task(downstream_task_id, token or "")
        if stage_name == "dataflow_analysis":
            return get_dataflow_analyse_client().restart_task(downstream_task_id)
        if stage_name == "vuln_scan":
            return get_dataflow_vuln_scanner_client().retry_task(downstream_task_id, token or "")
        raise ValidationError(f"阶段 {stage_name} 未配置安全重试接口")

    def _has_retryable_downstream_task(self, item: BinarySecurityStageItem) -> bool:
        if not str(item.downstream_task_id or "").strip():
            return False
        return str(item.status or "").strip().lower() != "downstream_missing"

    async def _active_downstream_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None = None,
    ) -> dict[str, Any] | None:
        if not self._has_retryable_downstream_task(item):
            return None
        try:
            payload = await self._fetch_downstream_task_payload(task, item, token or "")
        except Exception:
            return None
        mapped_status = self._map_downstream_status(str(payload.get("status") or ""))
        if mapped_status in {"queued", "running"}:
            return payload
        return None

    def _stage_retry_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        require_stage_run: bool = True,
    ) -> tuple[bool, str | None]:
        if stage_name not in self._stage_sequence_for_task(task):
            return False, f"无效阶段: {stage_name}"
        mapping = STAGE_RETRY_ENDPOINTS.get(stage_name)
        if not mapping:
            return False, f"阶段 {stage_name} 未配置安全重试接口"
        self._normalize_cancelled_task_active_children(db, task)
        if task.status in STAGE_RETRY_BLOCKED_TASK_STATUSES:
            return False, f"当前任务状态不允许重试: {task.status}"
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if require_stage_run and not stage_run:
            return False, "目标阶段尚未执行，不能重试"
        if stage_run and stage_run.status not in STAGE_RETRY_ALLOWED_STATUSES:
            return False, f"当前阶段状态不允许重试: {stage_run.status}"
        items = self._stage_items(db, task.id, stage_name)
        if not items:
            reason = self._continue_stage_input_error(db, task, stage_name)
            if reason:
                return False, reason
            return True, None
        seen: set[str] = set()
        expected_service = mapping[0]
        for item in items:
            logical_key = self._stage_item_identity(item.item_key, item.parent_key)
            if logical_key in seen:
                return False, f"阶段 {stage_name} 存在重复历史 item，无法安全重试: {item.item_key}"
            seen.add(logical_key)
            if item.downstream_service and item.downstream_service != expected_service:
                return False, (
                    f"阶段 {stage_name} 下游服务不匹配，期望 {expected_service}，实际 {item.downstream_service or '-'}"
                )
        return True, None

    def _normalize_cancelled_task_active_children(self, db: Session, task: BinarySecurityTask) -> None:
        """Cancelled tasks must not keep stale active stage/item state that blocks retry."""
        if task.status != "cancelled":
            return
        now_value = _now()
        active_items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.status.in_(["pending", "queued", "dispatching", "running"]),
        ).all()
        active_stage_runs = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.status.in_(["pending", "queued", "dispatching", "running"]),
        ).all()
        if not active_items and not active_stage_runs:
            return
        for item in active_items:
            item.status = "cancelled"
            item.finished_at = item.finished_at or now_value
        for stage_run in active_stage_runs:
            stage_run.status = "cancelled"
            stage_run.finished_at = stage_run.finished_at or now_value
        self._record_event(
            db,
            task,
            "cancelled_task_children_normalized",
            "已归一化取消任务中残留的活跃阶段与子任务",
            level="warning",
            stage_name=task.current_stage,
            payload={
                "cancelled_item_count": len(active_items),
                "cancelled_stage_run_count": len(active_stage_runs),
            },
        )

    def _first_retry_stage_name(self, db: Session, task: BinarySecurityTask) -> str | None:
        stage_runs = {
            row.stage_name: row
            for row in db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
            ).all()
        }
        for stage_name in self._stage_sequence_for_task(task):
            run = stage_runs.get(stage_name)
            if not run:
                return None
            if run.status != "success":
                return stage_name
        return None

    def _task_retry_support(self, db: Session, task: BinarySecurityTask) -> tuple[bool, str | None, str | None]:
        if task.status in {"pending_upload", "uploading", "ready_to_start"}:
            return False, "当前任务尚未完成输入准备，不能重试", None
        if task.status in {"pending", "dispatching", "running"} | TASK_PREPARING_STATUSES:
            return False, f"当前任务正在执行或排队中，不能重试: {task.status}", None
        if str(task.pending_action or "").strip():
            return False, f"当前任务已有待处理操作: {task.pending_action}", None
        stage_sequence = self._stage_sequence_for_task(task)
        if not stage_sequence:
            return False, "当前任务没有可执行阶段", None
        return True, None, stage_sequence[0]

    def _task_retry_failed_items_support(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[bool, str | None, str | None, list[BinarySecurityStageItem]]:
        if task.status in {"pending_upload", "uploading", "ready_to_start"}:
            return False, "当前任务尚未完成输入准备，不能重试失败项", None, []
        if task.status in {"pending", "dispatching", "running"} | TASK_PREPARING_STATUSES:
            return False, f"当前任务正在执行或排队中，不能重试失败项: {task.status}", None, []
        if str(task.pending_action or "").strip():
            return False, f"当前任务已有待处理操作: {task.pending_action}", None, []
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            return False, "当前任务等待模块确认，请先确认模块后再重试失败项", None, []
        stage_name, items = self._first_failed_retry_stage(db, task)
        if not stage_name or not items:
            return False, "当前任务没有可重试的失败项", None, []
        upstream_retried, upstream_stage = self._upstream_stage_retried(db, task, stage_name)
        if upstream_retried:
            return False, f"阶段 {STAGE_TITLES.get(stage_name, stage_name)} 的上游阶段 {STAGE_TITLES.get(upstream_stage or '', upstream_stage or '')} 已发生重试，不能只重试失败项", None, []
        reason = self._continue_stage_input_error(db, task, stage_name)
        if reason:
            return False, reason, stage_name, []
        return True, None, stage_name, items

    def _stage_retry_failed_items_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> tuple[bool, str | None, list[BinarySecurityStageItem]]:
        supported, reason = self._stage_retry_support(db, task, stage_name)
        if not supported:
            return False, reason, []
        items = self._stage_retry_candidate_items(db, task, stage_name)
        if not items:
            return False, "当前阶段没有可重试的失败项", []
        upstream_retried, upstream_stage = self._upstream_stage_retried(db, task, stage_name)
        if upstream_retried:
            return False, f"上游阶段 {STAGE_TITLES.get(upstream_stage or '', upstream_stage or '')} 已发生重试，当前阶段不能只重试失败项", []
        reason = self._continue_stage_input_error(db, task, stage_name)
        if reason:
            return False, reason, []
        return True, None, items

    def _task_continue_support(self, db: Session, task: BinarySecurityTask) -> tuple[bool, str | None, str | None]:
        if task.status in {"pending_upload", "uploading", "ready_to_start"}:
            return False, f"当前任务状态不允许继续: {task.status}", None
        if task.status in {"pending", "dispatching", "running"} | TASK_PREPARING_STATUSES:
            return False, f"当前任务正在执行或排队中，不能手动继续: {task.status}", None
        if str(task.pending_action or "").strip():
            return False, f"当前任务已有待处理操作: {task.pending_action}", None
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            return False, "当前任务等待模块确认，请先确认模块后继续", None

        stage_sequence = self._stage_sequence_for_task(task)
        if not stage_sequence:
            return False, "当前任务没有可执行阶段", None

        target_stage = self._next_incomplete_stage(db, task)
        if target_stage is None:
            return False, "当前任务所有阶段都已成功，没有可继续的后续阶段", None

        reason = self._continue_stage_input_error(db, task, target_stage)
        if reason:
            return False, reason, target_stage
        return True, None, target_stage

    def _ensure_stage_inputs_available(self, db: Session, task: BinarySecurityTask, stage_name: str) -> None:
        """Rebuild target-stage inputs from the previous successful stage when possible."""
        summary = dict(task.summary or {})
        if stage_name in {"binary_to_source", "entry_analysis"} and not summary.get("selected_modules"):
            self._refresh_system_analysis_stage_from_synced_items(db, task)
            summary = dict(task.summary or {})
        if stage_name == "entry_analysis" and self._task_type(task) != TASK_TYPE_SOURCE and not summary.get("b2s_results"):
            self._rebuild_summary_results_from_stage_items(db, task, "binary_to_source", "b2s_results")
        if stage_name == "dataflow_analysis" and not summary.get("entry_results"):
            self._rebuild_entry_results_from_stage_items(db, task)
        if stage_name == "vuln_scan" and not summary.get("dataflow_results"):
            self._rebuild_summary_results_from_stage_items(db, task, "dataflow_analysis", "dataflow_results")

    def _rebuild_summary_results_from_stage_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        summary_key: str,
    ) -> list[dict[str, Any]]:
        items = [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if item.status == "success"
        ]
        rebuilt = self._compact_stage_success_items(
            summary_key,
            [
                {
                    **dict(item.input_ref or {}),
                    **dict(item.output_ref or {}),
                    **dict(item.result or {}),
                }
                for item in items
            ],
        )
        if rebuilt:
            task.summary = {**(task.summary or {}), summary_key: rebuilt}
        return rebuilt

    def _continue_stage_input_error(self, db: Session, task: BinarySecurityTask, stage_name: str) -> str | None:
        self._ensure_stage_inputs_available(db, task, stage_name)
        summary = dict(task.summary or {})
        if stage_name == "system_analysis":
            inputs = self._system_analysis_inputs(task)
            if not inputs:
                return "系统分析缺少可执行输入，不能继续"
            return None
        if stage_name == "binary_to_source":
            inputs = list(summary.get("selected_modules") or [])
            if not inputs:
                return "系统分析尚未产出可用模块，不能继续二进制逆向阶段"
            return None
        if stage_name == "entry_analysis":
            inputs = list(summary.get("selected_modules") or [])
            if not inputs:
                return "系统分析尚未产出可用模块，不能继续入口分析阶段"
            return None
        if stage_name == "dataflow_analysis":
            inputs = list(summary.get("entry_results") or [])
            if not inputs:
                return "入口分析尚未产出可用入口结果，不能继续数据流分析阶段"
            return None
        if stage_name == "vuln_scan":
            inputs = list(summary.get("dataflow_results") or [])
            if not inputs:
                return "数据流分析尚未产出可用结果，不能继续漏洞扫描阶段"
            return None
        return None

    def _clear_stage_outputs_from(self, task: BinarySecurityTask, stage_name: str, *, mark_stale: bool = True) -> None:
        summary = dict(task.summary or {})
        metrics = dict(task.metrics or {})
        stage_summary = dict(task.stage_summary or {})
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            return
        affected = stage_sequence[stage_sequence.index(stage_name):]
        for current_stage in affected:
            for summary_key in self._stage_result_keys(current_stage):
                summary.pop(summary_key, None)
            stage_summary.pop(current_stage, None)
            metrics.update(STAGE_METRIC_RESETTERS.get(current_stage, {}))
        if mark_stale:
            summary["stale_reason"] = "upstream_stage_retried"
            summary["stale_from_stage"] = stage_name
            summary["stale_stages"] = stage_sequence[stage_sequence.index(stage_name) + 1:]
        else:
            summary.pop("stale_reason", None)
            summary.pop("stale_from_stage", None)
            summary.pop("stale_stages", None)
        task.summary = summary
        task.metrics = metrics
        task.stage_summary = stage_summary

    def _clear_stage_output_artifacts(self, task: BinarySecurityTask, stage_names: list[str]) -> None:
        output_root = Path(str(task.output_root or "")).resolve()
        if not output_root.exists():
            return
        services: set[str] = set()
        for stage_name in stage_names:
            for downstream_service in STAGE_OUTPUT_SERVICES.get(stage_name, []):
                services.add(downstream_service)
        for downstream_service in services:
            folder = SERVICE_OUTPUT_FOLDERS.get(downstream_service, downstream_service.replace("_", "-"))
            target = output_root / folder
            if target.exists():
                try:
                    shutil.rmtree(target, ignore_errors=True)
                except OSError as exc:
                    if exc.errno != errno.ESTALE:
                        raise

    def _clear_single_stage_outputs(self, task: BinarySecurityTask, stage_name: str) -> None:
        summary = dict(task.summary or {})
        metrics = dict(task.metrics or {})
        stage_summary = dict(task.stage_summary or {})
        for summary_key in self._stage_result_keys(stage_name):
            summary.pop(summary_key, None)
        stage_summary.pop(stage_name, None)
        metrics.update(STAGE_METRIC_RESETTERS.get(stage_name, {}))
        task.summary = summary
        task.metrics = metrics
        task.stage_summary = stage_summary
        self._clear_stage_output_artifacts(task, [stage_name])

    def _clear_single_stage_runtime_state(self, task: BinarySecurityTask, stage_name: str) -> None:
        summary = dict(task.summary or {})
        metrics = dict(task.metrics or {})
        stage_summary = dict(task.stage_summary or {})
        for summary_key in self._stage_result_keys(stage_name):
            summary.pop(summary_key, None)
        stage_summary.pop(stage_name, None)
        metrics.update(STAGE_METRIC_RESETTERS.get(stage_name, {}))
        task.summary = summary
        task.metrics = metrics
        task.stage_summary = stage_summary

    def _list_artifact_page(self, root: Path, *, limit: int, offset: int) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        total = 0
        if root.exists():
            for current_root, dirnames, filenames in os.walk(root):
                dirnames.sort()
                filenames.sort()
                current_path = Path(current_root)
                for filename in filenames:
                    path = current_path / filename
                    if total >= offset and len(files) < limit:
                        files.append({"path": str(path.relative_to(root)), "size": path.stat().st_size})
                    total += 1
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(files) < total,
            "files": files,
        }

    def _reset_stage_run_for_retry(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, *, increment_retry: bool) -> None:
        stage_run.status = "pending"
        if increment_retry:
            stage_run.retry_count = int(stage_run.retry_count or 0) + 1
        stage_run.started_at = None
        stage_run.finished_at = None
        stage_run.last_error = None
        stage_run.input_snapshot = {}
        stage_run.output_summary = {}
        stage_run.counts = {}
        stage_run.downstream_refs = {}
        summary_file = self._stage_run_summary_path(task, stage_run)
        try:
            if summary_file.exists():
                summary_file.unlink()
        except Exception:
            pass

    async def _run_with_limits(
        self,
        rows: list[Any],
        worker,
        *,
        concurrency: int,
        timeout_seconds: int | float | None,
    ) -> list[tuple[Any, Any, Exception | None]]:
        if not rows:
            return []
        semaphore = asyncio.Semaphore(max(1, int(concurrency or 1)))

        async def _guarded(row: Any) -> tuple[Any, Any, Exception | None]:
            async with semaphore:
                try:
                    if timeout_seconds and timeout_seconds > 0:
                        result = await asyncio.wait_for(worker(row), timeout=float(timeout_seconds))
                    else:
                        result = await worker(row)
                    return row, result, None
                except Exception as exc:
                    return row, None, exc

        return await asyncio.gather(*(_guarded(row) for row in rows))

    async def _cancel_downstream(self, item: BinarySecurityStageItem, token: str | None) -> None:
        try:
            if item.downstream_service == "firmware_unpacker":
                await get_firmware_unpacker_client().cancel_task(item.downstream_task_id, token or "")
            elif item.downstream_service == "binary_to_source":
                result = item.result
                await get_binary_to_source_client().cancel_task(result.get("project_id") or item.project_id, item.downstream_task_id, token or "")
            elif item.downstream_service == "entry_analyse":
                await get_entry_analyse_client().cancel_task(item.downstream_task_id, token or "")
            elif item.downstream_service == "dataflow_analyse":
                await get_dataflow_analyse_client().cancel_task(item.downstream_task_id)
            elif item.downstream_service == "dataflow_vuln_scanner":
                await get_dataflow_vuln_scanner_client().cancel_task(item.downstream_task_id, token or "")
            elif item.downstream_service == "system_analyse":
                await get_system_analyse_client().cancel_task(item.downstream_task_id)
        except Exception:
            pass

    def _collect_downstream_refs(self, task: BinarySecurityTask, items: list[BinarySecurityStageItem]) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in items:
            downstream_service = str(_stage_item_attr(item, "downstream_service") or "").strip()
            downstream_task_id = str(_stage_item_attr(item, "downstream_task_id") or "").strip()
            if not downstream_service or not downstream_task_id:
                continue
            key = (downstream_service, downstream_task_id)
            if key in seen:
                continue
            seen.add(key)
            refs.append(
                {
                    "service": downstream_service,
                    "task_id": downstream_task_id,
                    "project_id": task.project_id,
                    "stage_name": _stage_item_attr(item, "stage_name"),
                }
            )
        return refs

    def _dedupe_downstream_refs(self, refs: list[dict[str, str]]) -> list[dict[str, str]]:
        unique: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for ref in refs:
            service = str(ref.get("service") or "").strip()
            task_id = str(ref.get("task_id") or "").strip()
            if not service or not task_id:
                continue
            key = (service, task_id)
            if key in seen:
                continue
            seen.add(key)
            unique.append({**ref, "service": service, "task_id": task_id})
        return unique

    def _discover_parent_linked_downstream_refs(self, db: Session, task: BinarySecurityTask) -> list[dict[str, str]]:
        """Find old child tasks that are no longer referenced by current stage items."""
        candidates = [
            ("firmware_unpacker", "secflow_app_firmware_unpacker_unpack_tasks", "id", "parent_task_id", "parent_stage_name"),
            ("binary_to_source", "secflow_b2s_task", "id", "parent_task_id", "parent_stage_name"),
            ("system_analyse", "secflow_app_sa_tasks", "task_id", "parent_task_id", "parent_stage_name"),
            ("entry_analyse", "secflow_app_ea_tasks", "task_id", "parent_task_id", "parent_stage_name"),
            ("dataflow_analyse", "secflow_app_dfa_tasks", "task_id", "parent_task_id", "parent_stage_name"),
            ("dataflow_vuln_scanner", "secflow_dataflow_vuln_scanner_run_index", "id", "linked_task_id", None),
        ]
        refs: list[dict[str, str]] = []
        for service, table_name, task_id_column, parent_column, stage_column in candidates:
            try:
                column_rows = db.execute(
                    text(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema = DATABASE()
                          AND table_name = :table_name
                          AND (
                            column_name = :task_id_column
                            OR column_name = :parent_column
                            OR column_name = :stage_column
                          )
                        """
                    ),
                    {
                        "table_name": table_name,
                        "task_id_column": task_id_column,
                        "parent_column": parent_column,
                        "stage_column": stage_column or "",
                    },
                ).fetchall()
                available_columns = {str(row[0]) for row in column_rows}
                if task_id_column not in available_columns or parent_column not in available_columns:
                    continue
                select_stage = f"`{stage_column}`" if stage_column and stage_column in available_columns else "NULL"
                rows = db.execute(
                    text(
                        f"""
                        SELECT `{task_id_column}` AS task_id, {select_stage} AS stage_name
                        FROM `{table_name}`
                        WHERE `{parent_column}` = :parent_task_id
                        """
                    ),
                    {"parent_task_id": task.id},
                ).fetchall()
            except Exception:
                logger.debug(
                    "failed to discover parent-linked downstream refs: service=%s table=%s task_id=%s",
                    service,
                    table_name,
                    task.id,
                    exc_info=True,
                )
                continue
            for row in rows:
                downstream_task_id = str(row[0] or "").strip()
                if not downstream_task_id:
                    continue
                refs.append(
                    {
                        "service": service,
                        "task_id": downstream_task_id,
                        "project_id": task.project_id,
                        "stage_name": str(row[1] or "") or None,
                    }
                )
        return refs

    def _downstream_refs_for_stages(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_names: list[str],
    ) -> list[dict[str, str]]:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return []
        rows = db.query(
            BinarySecurityStageItem.stage_name,
            BinarySecurityStageItem.downstream_service,
            BinarySecurityStageItem.downstream_task_id,
        ).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.stage_name.in_(normalized),
        ).all()
        snapshot_items = [
            {
                "stage_name": row[0],
                "downstream_service": row[1],
                "downstream_task_id": row[2],
            }
            for row in rows
        ]
        return self._collect_downstream_refs(task, snapshot_items)

    async def _cancel_local_worker(self, task_id: str) -> None:
        async with self._worker_lock:
            worker = self._workers.get(task_id)
        if worker and not worker.done():
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

    async def _cancel_downstream_refs(self, db: Session, task: BinarySecurityTask, refs: list[dict[str, str]], token: str | None) -> int:
        for ref in refs:
            self._record_event(
                db,
                task,
                "downstream_cancel_requested",
                f"请求取消下游任务: {ref['service']}:{ref['task_id']}",
                stage_name=ref.get("stage_name"),
                payload=ref,
            )

        async def do_cancel(ref: dict[str, str]) -> bool:
            try:
                if ref["service"] == "firmware_unpacker":
                    await get_firmware_unpacker_client().cancel_task(ref["task_id"], token or "")
                elif ref["service"] == "system_analyse":
                    await get_system_analyse_client().cancel_task(ref["task_id"])
                elif ref["service"] == "binary_to_source":
                    await get_binary_to_source_client().cancel_task(ref["project_id"], ref["task_id"], token or "")
                elif ref["service"] == "entry_analyse":
                    await get_entry_analyse_client().cancel_task(ref["task_id"], token or "")
                elif ref["service"] == "dataflow_analyse":
                    await get_dataflow_analyse_client().cancel_task(ref["task_id"])
                elif ref["service"] == "dataflow_vuln_scanner":
                    await get_dataflow_vuln_scanner_client().cancel_task(ref["task_id"], token or "")
                return True
            except Exception:
                raise
        db.commit()
        results = await self._run_with_limits(
            refs,
            do_cancel,
            concurrency=self.cfg.scheduler.downstream_action_concurrency,
            timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
        )
        success_count = 0
        for ref, ok, exc in results:
            if exc is None and ok:
                success_count += 1
                continue
            self._record_event(
                db,
                task,
                "downstream_cancel_failed",
                f"下游取消失败: {ref['service']}:{ref['task_id']} - {exc}",
                stage_name=ref.get("stage_name"),
                level="warning",
                payload={**ref, "error": str(exc)},
            )
        db.commit()
        return success_count

    async def _fetch_downstream_ref_payload(self, ref: dict[str, str], token: str | None) -> dict[str, Any]:
        service = str(ref.get("service") or "").strip()
        task_id = str(ref.get("task_id") or "").strip()
        project_id = str(ref.get("project_id") or "").strip()
        if not service or not task_id:
            raise ValidationError("下游引用缺少 service/task_id")
        if service == "firmware_unpacker":
            return await get_firmware_unpacker_client().get_task(project_id, task_id, token or "")
        if service == "system_analyse":
            return await get_system_analyse_client().get_task(task_id)
        if service == "binary_to_source":
            return await get_binary_to_source_client().get_task(project_id, task_id, token or "")
        if service == "entry_analyse":
            return await get_entry_analyse_client().get_task(task_id, token or "")
        if service == "dataflow_analyse":
            return await get_dataflow_analyse_client().get_task(task_id)
        if service == "dataflow_vuln_scanner":
            return await get_dataflow_vuln_scanner_client().get_task(task_id, token or "")
        raise ValidationError(f"未知下游服务: {service}")

    async def _wait_downstream_ref_inactive(
        self,
        db: Session,
        task: BinarySecurityTask,
        ref: dict[str, str],
        token: str | None,
    ) -> None:
        del db, task
        # Downstream services commonly reject deletion for active work. After a
        # retry/cancel request, always wait until the old child is inactive
        # before deleting local references and creating a replacement. Otherwise
        # stale children can keep consuming downstream concurrency while the
        # parent stage has already moved to a new retry attempt.
        service = str(ref.get("service") or "").strip()
        if not service:
            return
        timeout_seconds = max(
            int(self.cfg.scheduler.downstream_request_timeout_seconds or 120),
            int(self.cfg.scheduler.stage_poll_interval_seconds or 5) * 2,
        )
        deadline = _now() + timedelta(seconds=timeout_seconds)
        while _now() <= deadline:
            try:
                payload = await self._fetch_downstream_ref_payload(ref, token)
            except NotFoundError:
                return
            mapped_status = self._map_downstream_status(str(payload.get("status") or "")) or str(payload.get("status") or "").lower()
            if mapped_status not in {"queued", "running", "dispatching", "pending"}:
                return
            await asyncio.sleep(max(1, int(self.cfg.scheduler.stage_poll_interval_seconds or 5)))
        raise ValidationError(f"旧下游任务仍在运行，不能安全继续: {ref.get('service')}:{ref.get('task_id')}")

    async def _ensure_downstream_refs_inactive(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
    ) -> None:
        for ref in refs:
            await self._wait_downstream_ref_inactive(db, task, ref, token)

    async def _delete_downstream_refs(self, db: Session, task: BinarySecurityTask, refs: list[dict[str, str]], token: str | None) -> int:
        for ref in refs:
            self._record_event(
                db,
                task,
                "downstream_delete_requested",
                f"请求删除下游任务: {ref['service']}:{ref['task_id']}",
                stage_name=ref.get("stage_name"),
                payload=ref,
            )

        async def do_delete(ref: dict[str, str]) -> bool:
            try:
                if ref["service"] == "firmware_unpacker":
                    await get_firmware_unpacker_client().delete_task(ref["task_id"], token or "")
                elif ref["service"] == "system_analyse":
                    await get_system_analyse_client().delete_task(ref["task_id"])
                elif ref["service"] == "binary_to_source":
                    await get_binary_to_source_client().delete_task(ref["project_id"], ref["task_id"], token or "")
                elif ref["service"] == "entry_analyse":
                    await get_entry_analyse_client().delete_task(ref["task_id"], token or "")
                elif ref["service"] == "dataflow_analyse":
                    await get_dataflow_analyse_client().delete_task(ref["task_id"])
                elif ref["service"] == "dataflow_vuln_scanner":
                    await get_dataflow_vuln_scanner_client().delete_task(ref["task_id"], token or "")
                return True
            except Exception:
                raise
        db.commit()
        results = await self._run_with_limits(
            refs,
            do_delete,
            concurrency=self.cfg.scheduler.downstream_action_concurrency,
            timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
        )
        success_count = 0
        for ref, ok, exc in results:
            if exc is None and ok:
                success_count += 1
                continue
            if isinstance(exc, ConflictError):
                raise ValidationError(f"旧下游任务仍在运行，不能安全删除: {ref['service']}:{ref['task_id']}") from exc
            self._record_event(
                db,
                task,
                "downstream_delete_failed",
                f"下游删除失败: {ref['service']}:{ref['task_id']} - {exc}",
                stage_name=ref.get("stage_name"),
                level="warning",
                payload={**ref, "error": str(exc)},
            )
        db.commit()
        return success_count

    async def _cleanup_task_workspace(self, task: BinarySecurityTask, token: str | None) -> str:
        workspace_root = Path(task.workspace_root)
        client = get_fileserver_client()
        cleanup_status = "deleted"
        try:
            await client.delete_project_path(task.project_id, str(workspace_root), token, recursive=True)
        except Exception:
            cleanup_status = "fallback"
        try:
            await asyncio.to_thread(shutil.rmtree, workspace_root, True)
        except Exception:
            cleanup_status = "partial_failed"
        return cleanup_status

    async def _poll_until_terminal(self, fetcher, *, success_statuses: set[str], failure_statuses: set[str], task: BinarySecurityTask, item: BinarySecurityStageItem | None = None):
        while True:
            await self._ensure_task_execution_current_async(task)
            await self._touch_task_heartbeat_async(task.id)
            try:
                payload = await fetcher()
            except NotFoundError:
                return "downstream_missing", {"status": "downstream_missing", "error": "下游子任务不存在"}
            await self._ensure_task_execution_current_async(task)
            status = str(payload.get("status") or "").lower()
            if status in success_statuses:
                return "success", payload
            if status in failure_statuses:
                return "failed", payload
            if await self._is_task_cancelled_async(task.id):
                if item and item.downstream_task_id:
                    await self._cancel_downstream(item, self._service_token())
                return "cancelled", payload
            await asyncio.sleep(self.cfg.scheduler.stage_poll_interval_seconds)

    def _touch_task_heartbeat(self, task_id: str) -> None:
        now = _now()
        last_heartbeat_at = self._last_task_heartbeat_at.get(task_id)
        interval_seconds = max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15))
        if last_heartbeat_at and (now - last_heartbeat_at).total_seconds() < interval_seconds:
            observe_heartbeat_update("skipped")
            return
        session = get_session_factory()()
        try:
            lease_expires_at = self._next_lease_expiry(session, now_value=now)
            session.query(BinarySecurityTask).filter(
                BinarySecurityTask.id == task_id,
                BinarySecurityTask.status == "running",
                BinarySecurityTask.dispatcher_instance_id == self.instance_id,
            ).update(
                {
                    BinarySecurityTask.updated_at: now,
                    BinarySecurityTask.lease_expires_at: lease_expires_at,
                },
                synchronize_session=False,
            )
            session.commit()
            self._last_task_heartbeat_at[task_id] = now
            observe_heartbeat_update("written")
        finally:
            session.close()

    async def _touch_task_heartbeat_async(self, task_id: str) -> None:
        await asyncio.to_thread(self._touch_task_heartbeat, task_id)

    def _is_task_cancelled(self, task_id: str) -> bool:
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask.status).filter(BinarySecurityTask.id == task_id).first()
            return row is None or bool(row and row[0] == "cancelled")
        finally:
            session.close()

    async def _is_task_cancelled_async(self, task_id: str) -> bool:
        return await asyncio.to_thread(self._is_task_cancelled, task_id)

    async def _stage_firmware_unpack(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        input_files = list(task.summary.get("input_files") or [])
        if not input_files:
            return "failed", {"error": "缺少输入文件"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=input_files,
            downstream_service="firmware_unpacker",
            identity=lambda input_file: (
                input_file["firmware_key"],
                input_file["filename"],
                input_file["firmware_key"],
                {"filename": input_file["filename"], "path": str(Path(task.workspace_root) / "input" / input_file["filename"])},
            ),
            output_ref=lambda input_file: {
                "downstream_service": "firmware_unpacker",
            },
        )
        if executable_inputs is None:
            executable_inputs = input_files
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda input_file, retrying=False: self._run_firmware_item(task, stage_run, input_file, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        status, summary = self._aggregate_stage_items(db, task, results, "firmware_unpack_results")
        return status, summary

    async def _run_firmware_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        input_file: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            firmware_key = input_file["firmware_key"]
            input_path = Path(task.workspace_root) / "input" / input_file["filename"]
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=firmware_key,
                item_name=input_file["filename"],
                parent_key=firmware_key,
                downstream_service="firmware_unpacker",
                input_ref={"filename": input_file["filename"], "path": str(input_path)},
                output_ref={"downstream_service": "firmware_unpacker"},
                retrying=retrying,
                running_status="queued",
            )
            session.commit()
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=token)
            else:
                created = await get_firmware_unpacker_client().create_task(
                    task.project_id,
                    str(input_path),
                    token or "",
                    _downstream_origin_payload(task, item),
                )
            item.status = "running"
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            item.started_at = _now()
            item.result = {"project_id": task.project_id}
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_firmware_unpacker_client().get_task(task.project_id, item.downstream_task_id, token or ""),
                success_statuses={"success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )
            mapped_status = "success" if status == "success" else "cancelled" if status == "cancelled" else "downstream_missing" if status == "downstream_missing" else "failed"
            item.status = mapped_status
            item.error_message = None if mapped_status in {"success", "partial_success"} else (
                payload.get("error") or payload.get("error_message") or payload.get("message")
            )
            item.finished_at = _now()
            item.started_at = item.started_at or _now()
            archive_root, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": input_file}
            if archive_root is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": input_file, "archive_blocked": True}
            result = {
                **input_file,
                "input_path": str(input_path),
                "unpacked_root": str(archive_root),
                "downstream": self._lightweight_downstream_payload(payload),
            }
            item.result = {**(item.result or {}), **result}
            item.output_ref = {
                **(item.output_ref or {}),
                "archive_root": str(archive_root),
                "unpacked_root": result["unpacked_root"],
            }
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": input_file}
        finally:
            session.close()

    async def _stage_system_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        del token
        system_inputs = self._system_analysis_inputs(task)
        if not system_inputs:
            return "failed", {"error": "缺少可用于系统分析的输入"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=system_inputs,
            downstream_service="system_analyse",
            identity=lambda analysis_input: (
                analysis_input["firmware_key"],
                analysis_input.get("firmware_name") or analysis_input["firmware_key"],
                analysis_input["firmware_key"],
                analysis_input,
            ),
            output_ref=lambda _analysis_input: {},
        )
        if executable_inputs is None:
            executable_inputs = system_inputs
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda analysis_input, retrying=False: self._run_system_analysis_item(task, stage_run, analysis_input, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        success = [result["item"] for result in results if result.get("status") == "success"]
        archive_blocked = [result for result in results if result.get("status") == "archive_blocked" or result.get("archive_blocked")]
        if archive_blocked:
            return "success", {
                "archive_blocked": True,
                "success_count": len(success),
                "failed_count": 0,
                "error": archive_blocked[0].get("error") or "总任务产物归档失败",
            }
        failed = [result for result in results if result.get("status") == "failed"]
        all_modules: list[dict[str, Any]] = []
        for result in success:
            all_modules.extend(result.get("modules", []))
        candidate_modules = self._filter_candidate_modules(all_modules, self._module_risk_levels(task))
        if success and not failed and not candidate_modules:
            failure = _no_candidate_modules_failure()
            task.summary = {
                **task.summary,
                "system_analysis_results": self._lightweight_system_analysis_items(success),
                "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
                "system_analysis_module_count": len(all_modules),
                "candidate_modules": [],
                "selected_modules": [],
                "high_risk_modules": [],
                **failure,
            }
            task.metrics = {
                **task.metrics,
                **self._module_metrics(all_modules, [], []),
            }
            task.last_error = failure["failure_message"]
            self._record_event(
                db,
                task,
                "system_analysis_no_candidate_modules",
                failure["failure_message"],
                level="error",
                stage_name=stage_run.stage_name,
                payload=failure,
            )
            db.commit()
            return "failed", {
                "items": self._lightweight_system_analysis_items(success),
                "failed_items": failed,
                "success_count": len(success),
                "failed_count": len(failed),
                "module_count": len(all_modules),
                "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
                "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
                "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
                "candidate_module_count": 0,
                "selected_module_count": 0,
                **failure,
            }
        selection_mode = self._module_selection_mode(task)
        selected_modules = self._mark_selected_modules(candidate_modules, selected_by=MODULE_SELECTION_MODE_AUTO) if selection_mode == MODULE_SELECTION_MODE_AUTO else []
        task.summary = {
            **self._clear_failure_fields_from_summary(task.summary),
            "system_analysis_results": self._lightweight_system_analysis_items(success),
            "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
            "system_analysis_module_count": len(all_modules),
            "candidate_modules": candidate_modules,
            "selected_modules": selected_modules,
            "high_risk_modules": selected_modules,
        }
        task.metrics = {
            **task.metrics,
            **self._module_metrics(all_modules, candidate_modules, selected_modules),
        }
        task.last_error = None
        db.commit()
        status = "success"
        if failed and success:
            status = "partial_success"
        elif failed:
            status = "failed"
        if status in {"success", "partial_success"} and selection_mode == MODULE_SELECTION_MODE_MANUAL_CONFIRM:
            task.status = TASK_STATUS_PENDING_MODULE_CONFIRMATION
            self._record_event(
                db,
                task,
                "module_selection_required",
                "系统分析已完成，等待人工确认模块",
                stage_name=stage_run.stage_name,
                payload={"candidate_module_count": len(candidate_modules)},
            )
            db.commit()
        return status, {
            "items": self._lightweight_system_analysis_items(success),
            "failed_items": failed,
            "success_count": len(success),
            "failed_count": len(failed),
            "module_count": len(all_modules),
            "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
            "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
            "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
            "candidate_module_count": len(candidate_modules),
            "selected_module_count": len(selected_modules),
            "requires_confirmation": selection_mode == MODULE_SELECTION_MODE_MANUAL_CONFIRM,
            "error": failed[0].get("error") if failed else None,
        }

    def _system_analysis_inputs(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        if self._task_type(task) == TASK_TYPE_SOURCE:
            input_dir = Path(task.workspace_root) / "input"
            if not input_dir.exists():
                return []
            return [
                {
                    "firmware_key": SOURCE_TASK_INPUT_KEY,
                    "firmware_name": task.name,
                    "filename": "source-project",
                    "unpacked_root": str(input_dir),
                    "source_root": str(input_dir),
                    "task_type": TASK_TYPE_SOURCE,
                }
            ]
        return list(task.summary.get("firmware_unpack_results") or [])

    async def _run_system_analysis_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        firmware: dict[str, Any],
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=firmware["firmware_key"],
                item_name=firmware["filename"],
                parent_key=firmware["firmware_key"],
                downstream_service="system_analyse",
                input_ref={
                    "input_path": firmware["unpacked_root"],
                    "firmware_key": firmware["firmware_key"],
                    "task_type": self._task_type(task),
                    "analysis_mode": self._task_type(task),
                },
                retrying=retrying,
            )
            session.commit()
            active_payload = await self._active_downstream_payload(task, item)
            if active_payload is not None:
                status, payload = await self._poll_until_terminal(
                    lambda: get_system_analyse_client().get_task(item.downstream_task_id),
                    success_statuses={"passed", "success"},
                    failure_statuses={"failed", "error", "cancelled"},
                    task=task,
                    item=item,
                )
            else:
                if retrying and self._has_retryable_downstream_task(item):
                    created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=None)
                else:
                    created = await get_system_analyse_client().create_task(
                        task.project_id,
                        f"{task.name}-{firmware['firmware_name']}-system-analysis",
                        firmware["unpacked_root"],
                        _downstream_origin_payload(task, item),
                        analysis_mode=self._task_type(task),
                    )
                item.downstream_task_id = created.get("task_id") or item.downstream_task_id
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: get_system_analyse_client().get_task(item.downstream_task_id),
                    success_statuses={"passed", "success"},
                    failure_statuses={"failed", "error", "cancelled"},
                    task=task,
                    item=item,
                )
            result_payload = {}
            if status == "success":
                try:
                    result_payload = await get_system_analyse_client().get_task_result(item.downstream_task_id)
                except Exception:
                    result_payload = {}
            archive_payload = {**payload, **({"result": result_payload} if result_payload else {})}
            mapped_status = "success" if status == "success" else "cancelled" if status == "cancelled" else "downstream_missing" if status == "downstream_missing" else "failed"
            item.status = mapped_status
            item.finished_at = _now()
            archive_root, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=archive_payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {"status": mapped_status, "item": self._lightweight_system_analysis_input(firmware), "error": item.error_message}
            if archive_root is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {
                    "status": "archive_blocked",
                    "error": error,
                    "item": self._lightweight_system_analysis_input(firmware),
                    "archive_blocked": True,
                }
            modules = self._parse_system_analysis_modules(archive_root, firmware, result_payload)
            result = {
                **self._lightweight_system_analysis_input(firmware),
                "artifact_root": str(archive_root),
                "archive_root": str(archive_root),
                "module_count": len(modules),
                "modules_file": str(archive_root / "system_analysis_modules.json"),
                "modules_preview": self._lightweight_modules_for_storage(modules),
                "downstream": self._lightweight_downstream_payload(payload),
                "system_analysis_result": self._lightweight_system_analysis_result(result_payload),
            }
            item.result = self._compact_result_for_storage(stage_run.stage_name, result)
            item.output_ref = {**(item.output_ref or {}), "artifact_root": str(archive_root), "archive_root": str(archive_root)}
            session.commit()
            return {"status": item.status, "item": {**result, "modules": modules}, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except Exception as exc:
            if "item" in locals():
                session.rollback()
                item = session.merge(item)
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                item.result = {
                    **self._lightweight_system_analysis_input(firmware),
                    "error": str(exc),
                    "downstream_task_id": item.downstream_task_id,
                }
                session.commit()
            return {"status": "failed", "error": str(exc), "item": firmware}
        finally:
            session.close()

    def _lightweight_system_analysis_input(self, firmware: dict[str, Any]) -> dict[str, Any]:
        return {
            "firmware_key": firmware.get("firmware_key"),
            "firmware_name": firmware.get("firmware_name"),
            "filename": firmware.get("filename"),
            "unpacked_root": firmware.get("unpacked_root"),
            "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
            "task_type": firmware.get("task_type", TASK_TYPE_BINARY),
        }

    def _lightweight_downstream_payload(self, payload: dict[str, Any] | None) -> dict[str, Any]:
        payload = payload or {}
        keys = [
            "task_id",
            "id",
            "project_id",
            "status",
            "error",
            "error_message",
            "message",
            "output_path",
            "workspace_root",
            "created_at",
            "updated_at",
            "started_at",
            "finished_at",
        ]
        return {key: payload.get(key) for key in keys if payload.get(key) is not None}

    def _archive_job_downstream_payload(self, payload: dict[str, Any] | None) -> dict[str, Any]:
        compact = self._lightweight_downstream_payload(payload)
        payload = payload or {}
        for key in ("output_root", "work_dir", "task_root"):
            value = payload.get(key)
            if value is not None:
                compact[key] = value
        for key in ("result", "artifacts", "artifact", "data"):
            nested = payload.get(key)
            if not isinstance(nested, dict):
                continue
            nested_compact = self._lightweight_downstream_payload(nested)
            for nested_key in ("output_root", "work_dir", "task_root"):
                value = nested.get(nested_key)
                if value is not None:
                    nested_compact[nested_key] = value
            if nested_compact:
                compact[key] = nested_compact
        return compact

    def _build_archive_job_payload(
        self,
        *,
        mapped_status: str,
        before_status: str | None,
        force: bool,
        payload: dict[str, Any] | None,
        extra_paths: list[str | Path] | None = None,
        previous_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        preserved = dict(previous_payload or {})
        preserved.pop("archive_copy_stats", None)
        return {
            **preserved,
            "mapped_status": mapped_status,
            "before_status": before_status,
            "force": force,
            "downstream_payload": self._archive_job_downstream_payload(payload),
            "extra_paths": [str(path) for path in (extra_paths or [])],
        }

    def _archive_job_payload_requires_refresh(
        self,
        job: BinarySecurityArchiveJob,
        *,
        next_payload: dict[str, Any],
    ) -> bool:
        current_payload = dict(job.payload or {})
        current_downstream = dict(current_payload.get("downstream_payload") or {})
        next_downstream = dict(next_payload.get("downstream_payload") or {})
        current_extra_paths = [str(path) for path in (current_payload.get("extra_paths") or [])]
        next_extra_paths = [str(path) for path in (next_payload.get("extra_paths") or [])]
        return (
            str(current_payload.get("mapped_status") or "").strip() != str(next_payload.get("mapped_status") or "").strip()
            or current_downstream != next_downstream
            or current_extra_paths != next_extra_paths
        )

    def _lightweight_artifacts_payload(self, payload: dict[str, Any] | None) -> dict[str, Any]:
        payload = payload or {}
        files = payload.get("files") or []
        return {
            key: value
            for key, value in {
                "workspace_root": payload.get("workspace_root"),
                "output_root": payload.get("output_root"),
                "task_root": payload.get("task_root"),
                "status": payload.get("status"),
                "file_count": len(files) if isinstance(files, list) else 0,
                "files_preview": files[:DB_ARTIFACT_PREVIEW_LIMIT] if isinstance(files, list) else [],
            }.items()
            if value not in (None, "")
        }

    def _compact_result_for_storage(self, stage_name: str, item: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(item, dict):
            return {}
        result = dict(item)
        if "downstream" in result:
            result["downstream"] = self._lightweight_downstream_payload(result.get("downstream") or {})
        if "artifacts" in result:
            result["artifacts"] = self._lightweight_artifacts_payload(result.get("artifacts") or {})
        if stage_name == "entry_analysis":
            entries = [dict(row) for row in result.get("entries") or [] if isinstance(row, dict)]
            result["entry_count"] = len(entries)
            result["entries_preview"] = self._compact_entry_rows(entries[:DB_ENTRY_PREVIEW_LIMIT])
            result.pop("entries", None)
        elif stage_name == "vuln_scan":
            artifact_files = result.get("artifact_files") or []
            if isinstance(artifact_files, list):
                result["artifact_file_count"] = len(artifact_files)
                result["artifact_files_preview"] = artifact_files[:DB_ARTIFACT_PREVIEW_LIMIT]
            result.pop("artifact_files", None)
        return result

    def _lightweight_system_analysis_result(self, result_payload: dict[str, Any] | None) -> dict[str, Any]:
        payload = result_payload or {}
        raw_summary = dict(payload.get("summary") or {})
        summary = {
            key: value
            for key, value in raw_summary.items()
            if isinstance(value, (int, float, bool)) or (isinstance(value, str) and len(value) <= 500)
        }
        modules = self._lightweight_modules_for_storage(list(payload.get("modules") or []))
        return {
            "available": payload.get("available"),
            "status": payload.get("status"),
            "output_root": payload.get("output_root"),
            "final_report_path": payload.get("final_report_path"),
            "modules_list_path": payload.get("modules_list_path"),
            "summary": summary,
            "module_count": len(modules),
            "modules": modules,
            "warnings": payload.get("warnings") or [],
        }

    def _lightweight_system_analysis_items(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for item in items:
            row = dict(item)
            row["modules"] = self._lightweight_modules_for_storage(list(row.get("modules") or []))
            if "system_analysis_result" in row:
                row["system_analysis_result"] = self._lightweight_system_analysis_result(row.get("system_analysis_result") or {})
            rows.append(row)
        return rows

    def _lightweight_modules_for_storage(self, modules: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
        rows = []
        for module in modules[:limit]:
            rows.append(
                {
                    "module_key": module.get("module_key"),
                    "module_name": module.get("module_name"),
                    "rank": module.get("rank"),
                    "risk_level": module.get("risk_level"),
                    "risk_score": module.get("risk_score"),
                    "file_count": module.get("file_count"),
                }
            )
        return rows

    def _system_analysis_modules_from_item(self, task: BinarySecurityTask, item: BinarySecurityStageItem) -> list[dict[str, Any]]:
        result = dict(item.result or {})
        artifact_root = Path(str((item.output_ref or {}).get("archive_root") or result.get("archive_root") or result.get("artifact_root") or ""))
        modules_file = artifact_root / "system_analysis_modules.json"
        if modules_file.is_file():
            try:
                payload = json.loads(_read_text(modules_file) or "{}")
                rows = payload.get("items") or []
                if isinstance(rows, list):
                    return [dict(row) for row in rows if isinstance(row, dict)]
            except Exception:
                pass
        modules = result.get("modules") or []
        return [dict(row) for row in modules if isinstance(row, dict)]

    def _parse_system_analysis_modules(self, root: Path, firmware: dict[str, Any], result_payload: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        result_payload = result_payload or {}
        modules_list = root / "modules.list"
        modules_dir = root / "modules"
        items: list[dict[str, Any]] = []
        result_modules = list(result_payload.get("modules") or [])
        if result_modules:
            for module in sorted(result_modules, key=lambda item: int(item.get("rank") or 0)):
                name = str(module.get("module_name") or "").strip()
                if not name:
                    continue
                archived_module_dir = modules_dir / name
                reported_module_dir = Path(str(module.get("module_dir_path") or archived_module_dir))
                module_dir = archived_module_dir if archived_module_dir.is_dir() else reported_module_dir
                archived_files_list = module_dir / "files.list"
                reported_files_list = Path(str(module.get("files_list_path") or archived_files_list))
                files_list = archived_files_list if archived_files_list.is_file() else reported_files_list
                archived_module_report = module_dir / "module_report.md"
                reported_module_report = Path(str(module.get("module_report_path") or archived_module_report))
                module_report = archived_module_report if archived_module_report.is_file() else reported_module_report
                source_dir = module_dir if module_dir.is_dir() else Path(str(firmware.get("source_root") or firmware.get("unpacked_root") or root))
                module_key = _slug(f"{firmware['firmware_key']}-{name}")
                items.append(
                    {
                        "firmware_key": firmware["firmware_key"],
                        "firmware_name": firmware["firmware_name"],
                        "filename": firmware["filename"],
                        "unpacked_root": firmware["unpacked_root"],
                        "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
                        "task_type": firmware.get("task_type", TASK_TYPE_BINARY),
                        "module_key": module_key,
                        "module_name": name,
                        "module_dir": str(module_dir),
                        "source_dir": str(source_dir),
                        "module_report": str(module_report),
                        "files_list": str(files_list),
                        "risk_level": str(module.get("risk_level") or "").strip(),
                        "risk_score": int(module.get("risk_score") or 0),
                        "rank": int(module.get("rank") or 0),
                        "selected_by": None,
                        "selected_at": None,
                    }
                )
            _write_json(root / "system_analysis_modules.json", {"items": items})
            _write_json(root / "high_risk_modules.json", {"items": items})
            return items
        names = [line.strip() for line in _read_text(modules_list).splitlines() if line.strip()]
        if not names and modules_dir.is_dir():
            names = [path.name for path in sorted(p for p in modules_dir.iterdir() if p.is_dir())]
        if not names and self._task_type(firmware.get("task_type")) == TASK_TYPE_SOURCE:
            names = ["source-project"]
        for name in names:
            module_dir = modules_dir / name
            source_dir = module_dir if module_dir.is_dir() else Path(str(firmware.get("source_root") or firmware.get("unpacked_root") or root))
            module_key = _slug(f"{firmware['firmware_key']}-{name}")
            items.append(
                {
                    "firmware_key": firmware["firmware_key"],
                    "firmware_name": firmware["firmware_name"],
                    "filename": firmware["filename"],
                    "unpacked_root": firmware["unpacked_root"],
                    "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
                    "task_type": firmware.get("task_type", TASK_TYPE_BINARY),
                    "module_key": module_key,
                    "module_name": name,
                    "module_dir": str(module_dir),
                    "source_dir": str(source_dir),
                    "module_report": str(module_dir / "module_report.md"),
                    "files_list": str(module_dir / "files.list"),
                    "risk_level": "",
                    "risk_score": 0,
                    "rank": len(items) + 1,
                    "selected_by": None,
                    "selected_at": None,
                }
            )
        _write_json(root / "system_analysis_modules.json", {"items": items})
        _write_json(root / "high_risk_modules.json", {"items": items})
        return items

    def _service_output_dir(
        self,
        task: BinarySecurityTask,
        downstream_service: str,
        semantic_key: str,
        downstream_task_id: str | None,
    ) -> Path:
        return ensure_dir(self._service_output_path(task, downstream_service, semantic_key, downstream_task_id))

    def _service_output_path(
        self,
        task: BinarySecurityTask,
        downstream_service: str,
        semantic_key: str,
        downstream_task_id: str | None,
    ) -> Path:
        service_folder = SERVICE_OUTPUT_FOLDERS.get(downstream_service, downstream_service.replace("_", "-"))
        suffix = downstream_task_id or "unknown-task"
        dirname = f"{semantic_key}__{suffix}"
        return Path(task.output_root) / service_folder / dirname

    def _downstream_standard_output_sources(
        self,
        task: BinarySecurityTask,
        downstream_service: str | None,
        downstream_task_id: str | None,
    ) -> list[Path]:
        if not downstream_service or not downstream_task_id:
            return []
        app_root = DOWNSTREAM_APP_ROOTS.get(downstream_service)
        if not app_root:
            return []
        project_app_root = Path(task.workspace_root).parent.parent
        task_root = project_app_root / app_root / downstream_task_id
        return [task_root / "output", task_root]

    def _payload_output_candidates(
        self,
        payload: dict[str, Any] | None,
        *,
        downstream_task_id: str | None = None,
    ) -> list[Path]:
        candidates: list[Path] = []
        if not isinstance(payload, dict):
            return candidates
        for key in (
            "output_path",
            "output_root",
            "artifact_root",
            "artifacts_root",
            "result_root",
            "workspace_root",
            "work_dir",
            "task_root",
            "final_report_path",
            "modules_list_path",
            "result_file",
            "result_file_path",
            "run_result_path",
            "run_report_path",
            "functions_list_path",
            "index_path",
            "sessions_root",
        ):
            value = payload.get(key)
            if not value:
                continue
            raw = Path(str(value))
            if raw.suffix:
                candidates.extend([raw.parent, raw.parent / "output"])
            if key in {"output_path", "output_root"} and downstream_task_id:
                candidates.extend([raw / downstream_task_id / "output", raw / downstream_task_id])
            if key in {"workspace_root", "work_dir", "task_root"}:
                candidates.append(raw / "output")
            candidates.append(raw)
        for key in ("result", "artifacts", "artifact", "data"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                candidates.extend(self._payload_output_candidates(nested, downstream_task_id=downstream_task_id))
        return candidates

    def _resolve_downstream_output_sources(
        self,
        payload: dict[str, Any] | None,
        *,
        downstream_task_id: str | None = None,
        extra_paths: list[str | Path] | None = None,
        task: BinarySecurityTask | None = None,
        downstream_service: str | None = None,
    ) -> list[Path]:
        candidates: list[Path] = []
        candidates.extend(self._payload_output_candidates(payload, downstream_task_id=downstream_task_id))
        if task is not None:
            candidates.extend(self._downstream_standard_output_sources(task, downstream_service, downstream_task_id))
        for value in extra_paths or []:
            if not value:
                continue
            raw = Path(str(value))
            if raw.is_file():
                candidates.append(raw.parent)
            else:
                candidates.append(raw)
        normalized: list[Path] = []
        for candidate in candidates:
            if candidate.name == "output":
                normalized.append(candidate)
                continue
            if candidate.is_dir() and (candidate / "output").exists():
                normalized.append(candidate / "output")
                continue
            normalized.append(candidate)
        return _dedupe_paths(normalized)

    def _archive_downstream_output(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        semantic_key: str,
        payload: dict[str, Any] | None = None,
        extra_paths: list[str | Path] | None = None,
    ) -> Path | None:
        target_dir = self._service_output_path(task, item.downstream_service or item.stage_name, semantic_key, item.downstream_task_id)
        sources = self._resolve_downstream_output_sources(
            payload,
            downstream_task_id=item.downstream_task_id,
            extra_paths=extra_paths,
            task=task,
            downstream_service=item.downstream_service,
        )
        existing_sources = [
            source
            for source in sources
            if source.exists()
            and _path_has_content(source)
            and source.resolve() != target_dir.resolve()
            and not _is_within_path(target_dir, source)
        ]
        if not existing_sources:
            self._record_event(
                db,
                task,
                "downstream_output_copy_skipped",
                f"下游阶段产物不存在，跳过归档: {item.downstream_service or item.stage_name}",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "target_dir": str(target_dir),
                    "sources": [str(path) for path in sources],
                },
            )
            return None
        ensure_dir(target_dir)
        copy_stats = {
            "copied_files": 0,
            "copied_dirs": 0,
            "copied_symlinks": 0,
            "skipped_errors": 0,
            "errors": [],
            "error_truncated": False,
        }
        for source in existing_sources:
            current_stats = _copytree_best_effort(source, target_dir)
            copy_stats["copied_files"] += int(current_stats.get("copied_files") or 0)
            copy_stats["copied_dirs"] += int(current_stats.get("copied_dirs") or 0)
            copy_stats["copied_symlinks"] += int(current_stats.get("copied_symlinks") or 0)
            copy_stats["skipped_errors"] += int(current_stats.get("skipped_errors") or 0)
            remaining = max(0, 200 - len(copy_stats["errors"]))
            copy_stats["errors"].extend(list(current_stats.get("errors") or [])[:remaining])
            if int(current_stats.get("skipped_errors") or 0) > len(current_stats.get("errors") or []):
                copy_stats["error_truncated"] = True
        if copy_stats["skipped_errors"]:
            self._record_event(
                db,
                task,
                "downstream_output_copy_partial",
                f"下游阶段产物已尽力归档，跳过 {copy_stats['skipped_errors']} 个错误文件",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "target_dir": str(target_dir),
                    "sources": [str(path) for path in existing_sources],
                    "copy_stats": copy_stats,
                },
            )
        self._record_event(
            db,
            task,
            "downstream_output_copied",
            f"下游阶段产物已归档: {item.downstream_service or item.stage_name}",
            stage_name=item.stage_name,
            item=item,
            payload={
                "target_dir": str(target_dir),
                "sources": [str(path) for path in existing_sources],
                "copied_file_count": _count_files(target_dir),
                "copy_stats": copy_stats,
            },
        )
        item.output_ref = {
            **(getattr(item, "output_ref", None) or {}),
            "archive_copy_stats": copy_stats,
        }
        item.result = {
            **(getattr(item, "result", None) or {}),
            "archive_copy_stats": copy_stats,
        }
        return target_dir

    def _materialize_stage_artifact(
        self,
        artifact_root: Path,
        downstream_task_id: str | None,
        payload: dict[str, Any],
        *,
        db: Session | None = None,
        task: BinarySecurityTask | None = None,
        item: BinarySecurityStageItem | None = None,
    ) -> Path:
        del db
        candidates = [
            candidate
            for candidate in self._resolve_downstream_output_sources(
                payload,
                downstream_task_id=downstream_task_id,
                task=task,
                downstream_service=item.downstream_service if item else None,
            )
            if candidate.exists()
            and _path_has_content(candidate)
            and candidate.resolve() != artifact_root.resolve()
            and not _is_within_path(artifact_root, candidate)
        ]
        return candidates[0] if candidates else artifact_root

    async def _stage_binary_to_source(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        modules = list(task.summary.get("selected_modules") or [])
        if not modules:
            return "failed", {"error": "缺少已选模块列表"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=modules,
            downstream_service="binary_to_source",
            identity=lambda module: (
                module["module_key"],
                module["module_name"],
                module.get("firmware_key"),
                module,
            ),
            output_ref=lambda _module: {},
        )
        if executable_inputs is None:
            executable_inputs = modules
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module, retrying=False: self._run_b2s_item(task, stage_run, module, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "b2s_results")

    async def _stage_entry_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        b2s_success = self._entry_analysis_inputs(task)
        if not b2s_success:
            return "failed", {"error": "没有可用于入口分析的源码模块"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=b2s_success,
            downstream_service="entry_analyse",
            identity=lambda module: (
                module["module_key"],
                module["module_name"],
                module.get("firmware_key"),
                module,
            ),
            output_ref=lambda _module: {},
        )
        if executable_inputs is None:
            executable_inputs = b2s_success
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module, retrying=False: self._run_entry_item(task, stage_run, module, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "entry_results")

    def _entry_analysis_inputs(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        if self._task_type(task) == TASK_TYPE_SOURCE:
            return list(task.summary.get("selected_modules") or [])
        return list(task.summary.get("b2s_results") or [])

    async def _stage_dataflow_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        entry_results = list(task.summary.get("entry_results") or [])
        if not entry_results:
            self._rebuild_entry_results_from_stage_items(db, task)
            entry_results = list(task.summary.get("entry_results") or [])
        entries: list[dict[str, Any]] = []
        for result in entry_results:
            entries.extend(result.get("entries", []))
        entries = _deduplicate_entry_keys(entries)
        if not entries:
            return "failed", {"error": "没有可用于数据流分析的入口"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=entries,
            downstream_service="dataflow_analyse",
            identity=lambda entry: (
                entry["entry_key"],
                entry["function_name"],
                entry.get("module_key"),
                entry,
            ),
            output_ref=lambda _entry: {},
        )
        if executable_inputs is None:
            executable_inputs = entries
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda entry, retrying=False: self._run_dataflow_item(task, stage_run, entry, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "dataflow_results")

    async def _stage_vuln_scan(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        dataflow_results = list(task.summary.get("dataflow_results") or [])
        if not dataflow_results:
            return "failed", {"error": "没有可用于漏洞扫描的数据流结果"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=dataflow_results,
            downstream_service="dataflow_vuln_scanner",
            identity=lambda result: (
                result["entry_key"],
                result["function_name"],
                result.get("module_key"),
                result,
            ),
            output_ref=lambda _result: {},
        )
        if executable_inputs is None:
            executable_inputs = dataflow_results
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda result, retrying=False: self._run_vuln_item(task, stage_run, result, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "vuln_results")

    async def _run_stage_pool(
        self,
        task: BinarySecurityTask,
        items: list[dict[str, Any]],
        concurrency: int,
        runner,
        retries: int = 0,
        initial_retry: bool = False,
    ):
        effective_concurrency = concurrency
        semaphore = asyncio.Semaphore(max(1, effective_concurrency))

        async def wrapped(item: dict[str, Any]):
            async with semaphore:
                await self._ensure_task_execution_current_async(task)
                if await self._is_task_cancelled_async(task.id):
                    return {"status": "cancelled", "error": "task cancelled", "item": item}
                attempts = 0
                result = await runner(item, initial_retry)
                await self._ensure_task_execution_current_async(task)
                while result.get("status") == "failed" and attempts < max(0, retries):
                    attempts += 1
                    await self._ensure_task_execution_current_async(task)
                    result = await runner(item, True)
                    await self._ensure_task_execution_current_async(task)
                    result["attempts"] = attempts + 1
                return result

        return await asyncio.gather(*(wrapped(item) for item in items))

    async def _run_b2s_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        module: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                downstream_service="binary_to_source",
                input_ref=module,
                retrying=retrying,
            )
            session.commit()
            elf_path = self._choose_module_binary(module)
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=token)
            else:
                created = await get_binary_to_source_client().create_task(
                    task.project_id,
                    f"{task.name}-{module['module_name']}",
                    elf_path,
                    token or "",
                    module,
                    _downstream_origin_payload(task, item),
                )
            item.downstream_task_id = created.get("id") or item.downstream_task_id
            item.result = {"project_id": task.project_id}
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_binary_to_source_client().get_task(task.project_id, item.downstream_task_id, token or ""),
                success_statuses={"success", "partial_success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )
            extra_paths: list[str] = []
            for child in payload.get("items", []):
                if child.get("output_dir"):
                    extra_paths.append(child["output_dir"])
                for file_path in child.get("generated_files") or []:
                    src = Path(file_path)
                    if src.exists():
                        extra_paths.append(str(src.parent))
            mapped_status = "success" if status == "success" else "cancelled" if status == "cancelled" else "downstream_missing" if status == "downstream_missing" else "failed"
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
                extra_paths=extra_paths,
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": module}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": module, "archive_blocked": True}
            result = {
                **module,
                "source_dir": str(archived_dir),
                "generated_files": [],
                "downstream": self._lightweight_downstream_payload(payload),
            }
            item.result = self._compact_result_for_storage(stage_run.stage_name, result)
            item.output_ref = {
                **(item.output_ref or {}),
                "archive_root": str(archived_dir),
                "source_dir": str(archived_dir),
            }
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": module}
        finally:
            session.close()

    def _choose_module_binary(self, module: dict[str, Any]) -> str:
        files = [line.strip() for line in _read_text(Path(module["files_list"])).splitlines() if line.strip()]
        module_dir = Path(module["module_dir"])
        unpacked_root = Path(str(module["unpacked_root"]))
        for rel in files:
            candidate = Path(rel)
            candidates = []
            if candidate.is_absolute():
                candidates.append(candidate)
            else:
                candidates.append(module_dir / rel)
                candidates.append(unpacked_root / rel)
                candidates.append(module_dir.parent / rel)
            for resolved in candidates:
                if resolved.exists() and resolved.is_file():
                    return str(resolved.resolve())
                if resolved.parent.exists():
                    matches = sorted(p for p in resolved.parent.rglob(candidate.name) if p.is_file())
                    if matches:
                        return str(matches[0].resolve())
        raise ValidationError(f"模块 {module['module_name']} 未找到可反编译文件")

    async def _run_entry_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        module: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                downstream_service="entry_analyse",
                input_ref=module,
                retrying=retrying,
            )
            session.commit()
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=token)
            else:
                created = await get_entry_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{module['module_name']}-entry",
                    module["source_dir"],
                    module["module_name"],
                    token or "",
                    module.get("source_root") or module.get("unpacked_root") or module["source_dir"],
                    _downstream_origin_payload(task, item),
                )
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_entry_analyse_client().get_task(item.downstream_task_id, token or ""),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                item=item,
            )
            service_output = self._materialize_stage_artifact(
                self._service_output_path(task, item.downstream_service or stage_run.stage_name, module["module_key"], item.downstream_task_id),
                item.downstream_task_id,
                payload,
                db=session,
                task=task,
                item=item,
            )
            entries = self._parse_entries(service_output, module)
            mapped_status = "success" if status == "success" else "cancelled" if status == "cancelled" else "downstream_missing" if status == "downstream_missing" else "failed"
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": module}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": module, "archive_blocked": True}
            archived_entries = self._parse_entries(archived_dir, module)
            if archived_entries:
                entries = archived_entries
            result = {
                **module,
                "artifact_root": str(archived_dir),
                "entries": entries,
                "source_dir": module["source_dir"],
                "downstream": payload,
            }
            item.result = self._compact_result_for_storage(stage_run.stage_name, result)
            item.output_ref = {**(item.output_ref or {}), "artifact_root": str(archived_dir), "archive_root": str(archived_dir)}
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": module}
        finally:
            session.close()

    def _parse_entries(self, artifact_root: Path, module: dict[str, Any]) -> list[dict[str, Any]]:
        def _rows_from_payload(payload: Any, source: Path) -> list[dict[str, Any]]:
            if isinstance(payload, dict):
                raw_entries = payload.get("entries") or payload.get("items") or []
            elif isinstance(payload, list):
                raw_entries = payload
            else:
                raw_entries = []
            rows = []
            for index, entry in enumerate(raw_entries):
                if not isinstance(entry, dict):
                    continue
                raw_function_name = entry.get("function_name") or entry.get("function") or entry.get("name") or ""
                function_name = _normalize_entry_function_name(raw_function_name)
                if not function_name:
                    continue
                file_name = str(entry.get("file_name") or entry.get("file") or "").strip()
                line_no = str(entry.get("line_no") or entry.get("line") or index + 1)
                taint_params = [
                    str(value).strip()
                    for value in (entry.get("taints") or entry.get("taint_params") or [])
                    if str(value).strip()
                ]
                tag = str(entry.get("tag") or "").strip().upper()
                raw_function_description = str(entry.get("function_description") or "").strip()
                raw_entry_reason = str(entry.get("entry_reason") or "").strip()
                rows.append(
                    {
                        "entry_key": _slug(f"{module['module_key']}-{function_name}-{line_no}"),
                        "firmware_key": module.get("firmware_key") or "",
                        "firmware_name": module.get("firmware_name") or "",
                        "module_key": module["module_key"],
                        "module_name": module["module_name"],
                        "file_name": file_name,
                        "function_name": function_name,
                        "raw_function_name": str(raw_function_name or ""),
                        "line_no": line_no,
                        "definition_file": str(entry.get("definition_file") or entry.get("file_name") or entry.get("file") or file_name or "").strip(),
                        "definition_line": str(entry.get("definition_line") or entry.get("line_no") or entry.get("line") or line_no),
                        "is_definition_found": bool(entry.get("is_definition_found", True)),
                        "tag": tag or "P",
                        "taint_params": taint_params,
                        "function_description": raw_function_description or _default_entry_function_description(function_name),
                        "function_description_source": _entry_description_source(raw_function_description),
                        "entry_reason": raw_entry_reason or _default_entry_reason(tag, function_name),
                        "entry_reason_source": _entry_description_source(raw_entry_reason),
                        "taint_details": _normalize_entry_taint_details(entry, taint_params),
                        "signature_params": _entry_signature_params({**entry, "raw_function_name": raw_function_name}),
                        "entry_file": str(source),
                        "source_dir": (module.get("source_root") if module.get("task_type") == TASK_TYPE_SOURCE else None) or module["source_dir"],
                    }
                )
            return _deduplicate_entry_keys(rows)

        function_list_candidates = [
            artifact_root / "entry-details.json",
            artifact_root / "functions.list",
            artifact_root / "output" / "entry-details.json",
            artifact_root / "output" / "functions.list",
        ]
        if artifact_root.is_dir() and not any(candidate.is_file() for candidate in function_list_candidates):
            recursive_matches = sorted(artifact_root.rglob("functions.list"))
            if len(recursive_matches) == 1:
                function_list_candidates.append(recursive_matches[0])
        for candidate in function_list_candidates:
            if candidate.is_file():
                try:
                    rows = _rows_from_payload(json.loads(_read_text(candidate) or "[]"), candidate)
                    if rows:
                        return rows
                except Exception:
                    pass

        json_candidates = [
            artifact_root / "result.json",
            artifact_root / "result_json",
            artifact_root / "entry-list.json",
        ]
        for candidate in json_candidates:
            if candidate.is_file():
                payload = json.loads(_read_text(candidate) or "{}")
                rows = _rows_from_payload(payload, candidate)
                if rows:
                    return rows
        entry_file = artifact_root / "entry-list.md"
        content = _read_text(entry_file)
        rows = []
        for line in content.splitlines():
            parts = [part.strip() for part in line.split("|")]
            if parts and not parts[0]:
                parts = parts[1:]
            if parts and not parts[-1]:
                parts = parts[:-1]
            if len(parts) >= 7 and parts[1].isdigit():
                file_name = parts[2]
                function_name = _normalize_entry_function_name(parts[3])
                line_no = parts[4]
                if file_name and function_name:
                    taint_params = [part.strip() for part in parts[5].split(",") if part.strip()] if len(parts) > 5 else []
                    rows.append(
                        {
                            "entry_key": _slug(f"{module['module_key']}-{function_name}-{line_no}"),
                            "firmware_key": module.get("firmware_key") or "",
                            "firmware_name": module.get("firmware_name") or "",
                            "module_key": module["module_key"],
                            "module_name": module["module_name"],
                            "file_name": file_name,
                            "function_name": function_name,
                            "raw_function_name": parts[3],
                            "line_no": line_no,
                            "tag": "P",
                            "taint_params": taint_params,
                            "function_description": _default_entry_function_description(function_name),
                            "function_description_source": "default",
                            "entry_reason": _default_entry_reason("P", function_name),
                            "entry_reason_source": "default",
                            "taint_details": _normalize_entry_taint_details({"taint_details": []}, taint_params),
                            "entry_file": str(entry_file),
                            "source_dir": (module.get("source_root") if module.get("task_type") == TASK_TYPE_SOURCE else None) or module["source_dir"],
                        }
                    )
        return _deduplicate_entry_keys(rows)

    async def _run_dataflow_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        entry: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        del token
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=entry["entry_key"],
                item_name=entry["function_name"],
                parent_key=entry["module_key"],
                downstream_service="dataflow_analyse",
                input_ref=entry,
                retrying=retrying,
            )
            session.commit()
            taint_params = [
                str(value).strip()
                for value in (entry.get("taint_params") or [])
                if str(value).strip()
            ]
            if not taint_params:
                taint_params = _entry_signature_params(entry)
            definition_found = bool(entry.get("is_definition_found", True))
            definition_file = str(entry.get("definition_file") or entry.get("file_name") or "").strip()
            definition_line = str(entry.get("definition_line") or entry.get("line_no") or "").strip()
            if not definition_found:
                item.status = "failed"
                item.finished_at = _now()
                item.error_message = "未找到函数定义，无法执行数据流分析"
                item.result = self._compact_result_for_storage(
                    stage_run.stage_name,
                    {
                        **entry,
                        "failed": True,
                        "failure_reason": item.error_message,
                    },
                )
                session.commit()
                return {"status": "failed", "error": item.error_message, "item": entry}
            if not taint_params:
                item.status = "failed"
                item.finished_at = _now()
                item.error_message = "未识别到明确污点参数，无法执行数据流分析"
                item.result = self._compact_result_for_storage(
                    stage_run.stage_name,
                    {
                        **entry,
                        "failed": True,
                        "failure_reason": item.error_message,
                    },
                )
                session.commit()
                return {"status": "failed", "error": item.error_message, "item": entry}
            prompt = f"分析文件 {definition_file or entry['file_name']} 中函数 {entry['function_name']} 的外部输入数据流"
            line_hint = ""
            if definition_line:
                line_hint = definition_line if definition_line.upper().startswith("L") else f"L{definition_line}"
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=None)
            else:
                created = await get_dataflow_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{entry['function_name']}-dfa",
                    entry["source_dir"],
                    prompt,
                    _downstream_origin_payload(task, item),
                    source_file=definition_file or entry["file_name"],
                    function_name=entry["function_name"],
                    line_hint=line_hint,
                    taint_params=taint_params,
                    function_description=str(entry.get("function_description") or ""),
                    function_description_source=str(entry.get("function_description_source") or ""),
                    entry_reason=str(entry.get("entry_reason") or ""),
                    entry_reason_source=str(entry.get("entry_reason_source") or ""),
                    taint_details=[dict(detail) for detail in (entry.get("taint_details") or []) if isinstance(detail, dict)],
                )
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled", "invalid_input", "completed_limited"},
                task=task,
                item=item,
            )
            artifact_root = self._service_output_dir(task, item.downstream_service or stage_run.stage_name, entry["entry_key"], item.downstream_task_id)
            materialized = self._materialize_stage_artifact(
                artifact_root,
                item.downstream_task_id,
                payload,
                db=session,
                task=task,
                item=item,
            )
            data_flow_file = self._find_first(materialized, [r"dataflow-.*\.md", r".*result.*\.md", r"report\.md"])
            downstream_status = str(payload.get("status") or "").lower()
            mapped_status = self._map_downstream_status(downstream_status) or (
                "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            )
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message") or payload.get("analysis_status") or payload.get("completion_reason")
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": entry}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": entry, "archive_blocked": True}
            archived_data_flow_file = self._find_first(archived_dir, [r"dataflow-.*\.md", r".*result.*\.md", r"report\.md"])
            result = {
                **entry,
                "artifact_root": str(archived_dir),
                "data_flow_file": str(archived_data_flow_file or data_flow_file) if (archived_data_flow_file or data_flow_file) else "",
                "downstream": self._lightweight_downstream_payload(payload),
            }
            item.result = self._compact_result_for_storage(stage_run.stage_name, result)
            item.output_ref = {
                **(item.output_ref or {}),
                "artifact_root": str(archived_dir),
                "archive_root": str(archived_dir),
                "data_flow_file": result["data_flow_file"],
            }
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": entry}
        finally:
            session.close()

    async def _run_vuln_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        dataflow_result: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=dataflow_result["entry_key"],
                item_name=dataflow_result["function_name"],
                parent_key=dataflow_result["module_key"],
                downstream_service="dataflow_vuln_scanner",
                input_ref=dataflow_result,
                retrying=retrying,
            )
            session.commit()
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=token)
            else:
                created = await get_dataflow_vuln_scanner_client().create_task(
                    task.project_id,
                    f"{task.name}-{dataflow_result['function_name']}-scan",
                    token or "",
                    dataflow_result["data_flow_file"],
                    dataflow_result["source_dir"],
                    _downstream_origin_payload(task, item),
                )
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_vuln_scanner_client().get_task(item.downstream_task_id, token or ""),
                success_statuses={"success", "succeeded", "completed"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )
            artifacts = await get_dataflow_vuln_scanner_client().get_artifacts(item.downstream_task_id, token or "")
            archive_payload = {
                **payload,
                "artifacts": artifacts,
                "workspace_root": artifacts.get("workspace_root"),
            }
            mapped_status = "success" if status == "success" else "cancelled" if status == "cancelled" else "downstream_missing" if status == "downstream_missing" else "failed"
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=archive_payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": dataflow_result}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": dataflow_result, "archive_blocked": True}
            result = {
                **dataflow_result,
                "workspace_root": artifacts.get("workspace_root"),
                "artifact_files": artifacts.get("files", []),
                "archive_root": str(archived_dir),
                "downstream": self._lightweight_downstream_payload(payload),
                "artifacts": artifacts,
            }
            item.result = self._compact_result_for_storage(stage_run.stage_name, result)
            item.output_ref = {
                **(item.output_ref or {}),
                "workspace_root": artifacts.get("workspace_root"),
                "archive_root": str(archived_dir),
            }
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": dataflow_result}
        finally:
            session.close()

    def _find_first(self, root: Path, patterns: list[str]) -> Path | None:
        if not root.exists():
            return None
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            for pattern in patterns:
                if re.fullmatch(pattern, path.name):
                    return path
        return None

    def _aggregate_stage_items(self, db: Session, task: BinarySecurityTask, results: list[dict[str, Any]], summary_key: str) -> tuple[str, dict[str, Any]]:
        success = [result["item"] for result in results if result.get("status") == "success"]
        compact_success = self._compact_stage_success_items(summary_key, success)
        db_success = self._compact_stage_success_items_for_db(summary_key, compact_success)
        archive_blocked = [result for result in results if result.get("status") == "archive_blocked" or result.get("archive_blocked")]
        if archive_blocked:
            summary = {
                "items": db_success,
                "failed_items": [],
                "cancelled_items": [],
                "success_count": len(compact_success),
                "failed_count": 0,
                "entry_count": self._entry_count_for_summary(summary_key, compact_success),
                "vuln_result_count": len(compact_success) if summary_key == "vuln_results" else 0,
                "items_truncated": len(db_success) < len(compact_success),
                "archive_blocked": True,
                "error": archive_blocked[0].get("error") or "总任务产物归档失败",
            }
            task.summary = {**task.summary, summary_key: compact_success}
            db.commit()
            return "success", summary
        failed_all = [self._lightweight_stage_failure(result) for result in results if result.get("status") == "failed"]
        cancelled_all = [self._lightweight_stage_failure(result) for result in results if result.get("status") == "cancelled"]
        failed = failed_all[:DB_FAILURE_ITEM_LIMIT]
        cancelled = cancelled_all[:DB_FAILURE_ITEM_LIMIT]
        if failed and success:
            status = "partial_success"
        elif failed:
            status = "failed"
        elif cancelled and not success:
            status = "cancelled"
        else:
            status = "success"
        summary = {
            "items": db_success,
            "failed_items": failed,
            "cancelled_items": cancelled,
            "success_count": len(compact_success),
            "failed_count": len(failed_all),
            "cancelled_count": len(cancelled_all),
            "entry_count": self._entry_count_for_summary(summary_key, compact_success),
            "vuln_result_count": len(compact_success) if summary_key == "vuln_results" else 0,
            "items_truncated": len(db_success) < len(compact_success),
            "failed_items_truncated": len(failed) < len(failed_all),
            "cancelled_items_truncated": len(cancelled) < len(cancelled_all),
            "error": failed[0].get("error") if failed else cancelled[0].get("error") if cancelled else None,
        }
        task.summary = {**task.summary, summary_key: compact_success}
        db.commit()
        return status, summary

    def _compact_stage_success_items(self, summary_key: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        compactors = {
            "firmware_unpack_results": self._compact_firmware_unpack_summary_item,
            "b2s_results": self._compact_b2s_summary_item,
            "entry_results": self._compact_entry_summary_item,
            "dataflow_results": self._compact_dataflow_summary_item,
            "vuln_results": self._compact_vuln_summary_item,
        }
        compactor = compactors.get(summary_key)
        if compactor is None:
            return [dict(item) for item in items if isinstance(item, dict)]
        return [compactor(item) for item in items if isinstance(item, dict)]

    def _compact_stage_success_items_for_db(self, summary_key: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if summary_key == "entry_results":
            return [self._compact_entry_summary_item_for_db(item) for item in items[:DB_SUMMARY_ITEM_LIMIT] if isinstance(item, dict)]
        return [dict(item) for item in items[:DB_SUMMARY_ITEM_LIMIT] if isinstance(item, dict)]

    def _entry_count_for_summary(self, summary_key: str, items: list[dict[str, Any]]) -> int:
        if summary_key != "entry_results":
            return 0
        return sum(len(item.get("entries") or []) for item in items if isinstance(item, dict))

    def _compact_firmware_unpack_summary_item(self, item: dict[str, Any]) -> dict[str, Any]:
        unpacked_root = item.get("unpacked_root")
        return {
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "filename": item.get("filename"),
            "input_path": item.get("input_path"),
            "unpacked_root": unpacked_root,
            "source_root": item.get("source_root") or unpacked_root,
            "task_type": item.get("task_type", TASK_TYPE_BINARY),
        }

    def _compact_b2s_summary_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "filename": item.get("filename"),
            "unpacked_root": item.get("unpacked_root"),
            "source_root": item.get("source_root"),
            "task_type": item.get("task_type"),
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "module_dir": item.get("module_dir"),
            "source_dir": item.get("source_dir"),
            "module_report": item.get("module_report"),
            "files_list": item.get("files_list"),
        }

    def _compact_entry_summary_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "filename": item.get("filename"),
            "unpacked_root": item.get("unpacked_root"),
            "source_root": item.get("source_root"),
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "module_dir": item.get("module_dir"),
            "source_dir": item.get("source_dir"),
            "artifact_root": item.get("artifact_root"),
            "entries": self._compact_entry_rows(item.get("entries") or []),
        }

    def _compact_entry_rows(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            signature_params = _entry_signature_params(entry)
            taint_params = [
                str(value).strip()
                for value in (entry.get("taint_params") or [])
                if str(value).strip()
            ] or signature_params
            rows.append(
                {
                    "entry_key": entry.get("entry_key"),
                    "firmware_key": entry.get("firmware_key"),
                    "firmware_name": entry.get("firmware_name"),
                    "module_key": entry.get("module_key"),
                    "module_name": entry.get("module_name"),
                    "file_name": entry.get("file_name"),
                    "function_name": entry.get("function_name"),
                    "raw_function_name": entry.get("raw_function_name"),
                    "line_no": entry.get("line_no"),
                    "definition_file": entry.get("definition_file") or entry.get("file_name"),
                    "definition_line": entry.get("definition_line") or entry.get("line_no"),
                    "is_definition_found": entry.get("is_definition_found", True),
                    "tag": entry.get("tag") or "P",
                    "taint_params": taint_params,
                    "function_description": entry.get("function_description") or _default_entry_function_description(str(entry.get("function_name") or "")),
                    "function_description_source": entry.get("function_description_source") or _entry_description_source(entry.get("function_description")),
                    "entry_reason": entry.get("entry_reason") or _default_entry_reason(entry.get("tag"), str(entry.get("function_name") or "")),
                    "entry_reason_source": entry.get("entry_reason_source") or _entry_description_source(entry.get("entry_reason")),
                    "taint_details": _normalize_entry_taint_details(entry, taint_params),
                    "signature_params": signature_params,
                    "entry_file": entry.get("entry_file"),
                    "source_dir": entry.get("source_dir"),
                }
            )
        return rows

    def _compact_entry_summary_item_for_db(self, item: dict[str, Any]) -> dict[str, Any]:
        row = dict(item)
        entries = [dict(entry) for entry in row.get("entries") or [] if isinstance(entry, dict)]
        row["entry_count"] = len(entries)
        row["entries_preview"] = self._compact_entry_rows(entries[:DB_ENTRY_PREVIEW_LIMIT])
        row.pop("entries", None)
        return row

    def _compact_dataflow_summary_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "entry_key": item.get("entry_key"),
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "file_name": item.get("file_name"),
            "function_name": item.get("function_name"),
            "line_no": item.get("line_no"),
            "entry_file": item.get("entry_file"),
            "source_dir": item.get("source_dir"),
            "artifact_root": item.get("artifact_root"),
            "data_flow_file": item.get("data_flow_file"),
        }

    def _compact_vuln_summary_item(self, item: dict[str, Any]) -> dict[str, Any]:
        artifact_files = item.get("artifact_files") or []
        return {
            "entry_key": item.get("entry_key"),
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "file_name": item.get("file_name"),
            "function_name": item.get("function_name"),
            "line_no": item.get("line_no"),
            "source_dir": item.get("source_dir"),
            "data_flow_file": item.get("data_flow_file"),
            "workspace_root": item.get("workspace_root"),
            "archive_root": item.get("archive_root"),
            "artifact_file_count": len(artifact_files) if isinstance(artifact_files, list) else 0,
        }

    def _lightweight_stage_failure(self, result: dict[str, Any]) -> dict[str, Any]:
        item = result.get("item") or {}
        if not isinstance(item, dict):
            item = {}
        error = str(result.get("error") or "")[:1000]
        return {
            "status": result.get("status"),
            "error": error,
            "item": {
                "firmware_key": item.get("firmware_key"),
                "firmware_name": item.get("firmware_name"),
                "module_key": item.get("module_key"),
                "module_name": item.get("module_name"),
                "entry_key": item.get("entry_key"),
                "function_name": item.get("function_name"),
                "file_name": item.get("file_name"),
                "line_no": item.get("line_no"),
                "source_dir": item.get("source_dir"),
            },
        }

    def _fileserver_task_path(self, project_id: str, task_id: str, suffix: str | None = None) -> str:
        base = Path(self.cfg.storage.project_root_template.format(project_id=project_id)) / "app" / "secflow-app-binary-security" / task_id
        if suffix:
            return str(base / suffix.strip("/"))
        return str(base)


_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
