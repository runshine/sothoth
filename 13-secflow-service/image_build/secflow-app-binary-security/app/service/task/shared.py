from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from app.copy_utils import safe_copy2
from app.model import BinarySecurityStageItem, BinarySecurityTask, TASK_TYPE_BINARY_MODULE, TASK_TYPE_SOURCE
from app.observability import observe_state_file_write
from app.service.security import ensure_dir
from app.time_utils import now_local

NO_CANDIDATE_MODULES_FAILURE_CODE = "no_candidate_modules"
NO_CANDIDATE_MODULES_FAILURE_CATEGORY = "business"
NO_CANDIDATE_MODULES_FAILURE_MESSAGE = "系统分析已完成，但未发现匹配所选风险等级的风险模块"

ENTRY_SELECTION_MODE_AUTO = "auto"
ENTRY_SELECTION_MODE_MANUAL_CONFIRM = "manual_confirm"
ALLOWED_MODULE_RISK_LEVELS = ("高", "中", "低")
PIPELINE_MODE_BARRIER = "barrier"
PIPELINE_MODE_MIXED_STREAMING = "mixed_streaming"


@dataclass
class ArchiveOutputResult:
    status: str
    target_dir: Path | None = None
    source_candidates: list[str] = field(default_factory=list)


def _now() -> datetime:
    return now_local()


def _isoformat_or_none(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _elapsed_seconds_since(value: datetime | None) -> float | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone().replace(tzinfo=None)
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
    if value.tzinfo is not None:
        value = value.astimezone().replace(tzinfo=None)
    candidates = [
        (value - _now()).total_seconds(),
        (value - datetime.utcnow()).total_seconds(),
    ]
    return min(candidates, key=lambda remaining: abs(remaining))


def _parse_iso_datetime(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _runtime_health_status_rank(status: str) -> int:
    normalized = str(status or "").strip().lower()
    if normalized == "unhealthy":
        return 4
    if normalized == "degraded":
        return 3
    if normalized == "unknown":
        return 2
    if normalized == "idle":
        return 1
    return 0


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value or "").strip("-")
    return cleaned[:120] or uuid.uuid4().hex[:12]


def _display_task_type(task_type: str) -> str:
    if task_type == TASK_TYPE_SOURCE:
        return "源码扫描"
    if task_type == TASK_TYPE_BINARY_MODULE:
        return "二进制模块扫描"
    return "二进制安全"


def _normalize_pipeline_mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == PIPELINE_MODE_MIXED_STREAMING:
        return PIPELINE_MODE_MIXED_STREAMING
    return PIPELINE_MODE_BARRIER


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
            candidate = _entry_key_with_suffix(base_key or _slug(str(suffix_source)), f"{index + 1}-{attempt}", index + 1)
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
        safe_copy2(src, dst, follow_symlinks=False)
        return
    shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=True, ignore_dangling_symlinks=True)


def _copytree_best_effort(
    src: Path,
    dst: Path,
    *,
    error_limit: int = 200,
    skip_path: Callable[[Path, Path], bool] | None = None,
) -> dict[str, Any]:
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
            stats["errors"].append({"source": str(source), "target": str(target), "error": str(exc)})

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
                safe_copy2(source, target, follow_symlinks=False)
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
        if skip_path and skip_path(src, src):
            return stats
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
            if skip_path and skip_path(source_dir, src):
                dirnames.remove(dirname)
                continue
            copy_one(source_dir, target_dir)
            if source_dir.is_symlink():
                dirnames.remove(dirname)
        for filename in filenames:
            source_file = current_path / filename
            target_file = target_root / filename
            if skip_path and skip_path(source_file, src):
                continue
            copy_one(source_file, target_file)
    return stats


def _is_b2s_runtime_temp_dir(path: str | Path | None) -> bool:
    if not path:
        return False
    try:
        candidate = Path(str(path))
    except Exception:
        return False
    name = candidate.name.lower()
    return name == "run" or name.startswith(".re_work_")


def _should_skip_b2s_archive_path(path: Path, *, source_root: Path) -> bool:
    try:
        relative = path.relative_to(source_root)
    except ValueError:
        relative = path
    return any(_is_b2s_runtime_temp_dir(part) for part in relative.parts)


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


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def _path_matches_task_id(path: Path, task_id: str | None) -> bool:
    if not task_id:
        return False
    return any(part == task_id for part in path.parts)


def _prefer_specific_paths(paths: list[Path], *, downstream_task_id: str | None = None) -> list[Path]:
    if not paths:
        return []
    preferred = list(paths)
    task_scoped = [path for path in preferred if _path_matches_task_id(path, downstream_task_id)]
    if task_scoped:
        preferred = task_scoped
    pruned: list[Path] = []
    for candidate in preferred:
        if any(candidate != other and _is_within_path(candidate, other) for other in preferred):
            continue
        pruned.append(candidate)
    return _dedupe_paths(pruned or preferred)


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
        "create_dedupe_key": f"{_stage_item_attr(item, 'stage_name') or 'stage'}:{_stage_item_attr(item, 'id') or _stage_item_attr(item, 'item_key') or ''}",
    }


def _normalize_module_risk_levels(values: list[str] | None) -> list[str]:
    ordered: list[str] = []
    for value in values or []:
        normalized = str(value or "").strip()
        if normalized in ALLOWED_MODULE_RISK_LEVELS and normalized not in ordered:
            ordered.append(normalized)
    return ordered or ["高"]


def _no_candidate_modules_failure() -> dict[str, str]:
    return {
        "failure_code": NO_CANDIDATE_MODULES_FAILURE_CODE,
        "failure_category": NO_CANDIDATE_MODULES_FAILURE_CATEGORY,
        "failure_message": NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
        "error": NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
    }


def _failure_shape(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    return {}
