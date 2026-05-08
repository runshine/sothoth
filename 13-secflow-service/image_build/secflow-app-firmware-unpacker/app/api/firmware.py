"""Firmware unpacker API routes."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import or_

from app.api.dependencies import ensure_project_access, get_current_subject
from app.exception import ForbiddenError, InternalError, NotFoundError, ValidationError
from app.model import ServiceConfig, TaskStatus, UnpackTask, get_db_session
from app.schemas import (
    ActionResponse,
    BatchDeleteRequest,
    ClusterInfoResponse,
    ConfigBatchUpdateItem,
    ConfigEntryResponse,
    ConfigListResponse,
    ConfigUpdateRequest,
    HealthResponse,
    LlmConfigFileSummaryListResponse,
    LlmProviderSummaryListResponse,
    ReadyResponse,
    TaskEventListResponse,
    TaskListResponse,
    TaskLogResponse,
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
from app.services.task_events import list_task_events
from app.services.task_manager import cancel_task, delete_tasks, retry_task, submit_unpack_task
from app.services.worker import get_cluster_snapshot, get_worker_id
from app.skill_store import list_skills
from app.unpacker_engine_config import get_max_retries
from app.unpacker_engine import TOOLS_DIR


router = APIRouter(tags=["Firmware Unpacker"])
logger = logging.getLogger(__name__)


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


def _get_task_or_404(task_id: str) -> dict:
    db = get_db_session()
    try:
        task = db.query(UnpackTask).filter(UnpackTask.id == task_id).first()
        if not task:
            raise NotFoundError("任务", task_id)
        return task.to_dict()
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
) -> dict:
    return {
        "key": key,
        "label": label,
        "status": status,
        "detail": detail,
        "updated_at": updated_at,
        "current_round": current_round,
        "total_rounds": total_rounds,
    }


def _read_json_file(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


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


def _derive_run_path(task: dict) -> Path:
    output_path = str(task.get("output_path") or "").strip()
    if not output_path:
        return Path("/tmp")
    output_dir = Path(output_path)
    return output_dir.parent / "run" if output_dir.name == "output" else output_dir.parent / "run"


def _get_task_progress(task_id: str) -> dict:
    task = _get_task_or_404(task_id)
    run_dir = _derive_run_path(task)
    stage1_path = run_dir / "stage1_preprocess.json"
    stage2_path = run_dir / "stage2_skill_match.json"
    stage3_path = run_dir / "stage3_skill_exec.json"
    stage3_llm_unpack_log = run_dir / "stage3_llm_unpack.log"
    stage4_llm_review_log = run_dir / "stage4_llm_review.log"
    stage4_path = run_dir / "stage4_llm_fallback.json"
    stage5_path = run_dir / "stage5_skill_generate.json"
    cleaner_path = run_dir / "cleaner_messages.json"
    executor_logs = sorted(run_dir.glob("executor_round_*_messages.json"))
    verifier_logs = sorted(run_dir.glob("verifier_round_*_messages.json"))

    task_status = str(task.get("status") or "").lower()
    task_result = str(task.get("result_status") or "").lower()
    task_current_stage = str(task.get("current_stage") or "").strip().lower()
    result_message = str(task.get("result_message") or "")
    quick_preprocess_success = "quick pre-process" in result_message.lower()
    matched_skill = str(task.get("matched_skill") or "").strip()
    fallback_to_llm = bool(task.get("fallback_to_llm"))
    generated_skill_path = str(task.get("generated_skill_path") or "").strip()
    final_round = int(task.get("rounds") or 0)
    total_llm_rounds = max(1, int(get_max_retries() or 1))

    def _clamp_round(value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        return max(1, min(int(value), total_llm_rounds))

    def _running_unpack_round() -> Optional[int]:
        if task_current_stage != "llm_unpack":
            return None
        if executor_logs:
            return _clamp_round(len(executor_logs))
        return 1

    def _running_review_round() -> Optional[int]:
        if task_current_stage != "review":
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

    phases = [
        _phase_payload("preprocess", "预处理", "pending"),
        _phase_payload("tool_match", "工具匹配执行", "pending"),
        _phase_payload("llm_unpack", "LLM 解包", "pending"),
        _phase_payload("llm_review", "LLM 评审", "pending"),
        _phase_payload("llm_cleanup", "LLM 清理", "pending"),
    ]

    if task_status in {"running", "cancelling", "success", "failed", "cancelled"}:
        phases[0]["status"] = "running"
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
        phases[3]["status"] = "skipped"
        phases[3]["detail"] = "预处理已直接完成解包，跳过"
        phases[4]["status"] = "success" if cleaner_path.exists() else ("running" if task_status == "running" else "pending")
        phases[4]["detail"] = "正在收尾清理输出目录" if phases[4]["status"] == "running" else "清理已完成"
        phases[4]["updated_at"] = _mtime_iso_text(cleaner_path)
    else:
        if stage2_path.exists():
            stage2_data = _read_json_file(stage2_path)
            matched_path = matched_skill
            matched_score = task.get("matched_skill_score")
            if isinstance(stage2_data, dict):
                matched_path = str(stage2_data.get("matched_skill") or matched_path or "")
                matched_score = stage2_data.get("matched_skill_score", matched_score)
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
            elif executor_logs or task_status in {"running", "success", "failed", "cancelled"}:
                phases[1] = _phase_payload(
                    "tool_match",
                    "工具匹配执行",
                    "skipped",
                    "未命中可复用工具，转入 LLM 解包",
                    _mtime_iso_text(stage2_path),
                )

        if executor_logs or fallback_to_llm or (task_status == "running" and stage2_path.exists()):
            unpack_status = "running"
            unpack_detail = "LLM 正在执行解包"
            unpack_round = _running_unpack_round()
            if executor_logs:
                unpack_round = _clamp_round(max(len(executor_logs), final_round or 0, 1))
                unpack_detail = f"已执行 {len(executor_logs)} 轮解包"
                if verifier_logs or task_result in {"success", "max_retries_reached", "failed"}:
                    unpack_status = "success"
            if matched_skill and not fallback_to_llm and not executor_logs and task_status != "running":
                unpack_status = "skipped"
                unpack_detail = "工具执行成功，未进入 LLM 解包"
            if task_status == "failed" and not verifier_logs and executor_logs:
                unpack_status = "failed"
                unpack_detail = "LLM 解包阶段执行失败"
            phases[2] = _phase_payload(
                "llm_unpack",
                "LLM 解包",
                unpack_status,
                unpack_detail,
                _mtime_iso_text(executor_logs[-1]) if executor_logs else (_mtime_iso_text(stage3_llm_unpack_log) or _mtime_iso_text(stage4_path)),
                current_round=unpack_round if unpack_status != "skipped" else None,
                total_rounds=total_llm_rounds if unpack_status != "skipped" else None,
            )
        elif matched_skill and not fallback_to_llm:
            phases[2] = _phase_payload("llm_unpack", "LLM 解包", "skipped", "工具执行成功，未进入 LLM 解包")

        if verifier_logs or task_result in {"success", "max_retries_reached", "failed"}:
            review_status = "running"
            review_detail = "LLM 正在评审当前解包结果"
            review_round = _running_review_round()
            if verifier_logs:
                review_status = "success" if task_status == "success" else ("failed" if task_status == "failed" else "running")
                review_detail = f"已完成 {len(verifier_logs)} 轮评审"
                if review_status != "running":
                    review_round = _completed_round()
                else:
                    review_round = _clamp_round(max(len(verifier_logs), len(executor_logs), 1))
                if task_status == "failed":
                    review_detail = "评审未通过，任务失败"
            phases[3] = _phase_payload(
                "llm_review",
                "LLM 评审",
                review_status,
                review_detail,
                _mtime_iso_text(verifier_logs[-1]) if verifier_logs else _mtime_iso_text(stage4_llm_review_log),
                current_round=review_round,
                total_rounds=total_llm_rounds if review_round is not None else None,
            )
        elif matched_skill and not fallback_to_llm:
            phases[3] = _phase_payload("llm_review", "LLM 评审", "skipped", "工具执行成功后未进入 LLM 评审链路")

        cleanup_status = "pending"
        cleanup_detail = None
        if cleaner_path.exists():
            cleanup_status = "success"
            cleanup_detail = "清理已完成"
        elif task_status == "running" and (verifier_logs or (matched_skill and not fallback_to_llm and stage3_path.exists())):
            cleanup_status = "running"
            cleanup_detail = "正在清理中间产物和重复文件"
        elif task_status in {"failed", "cancelled"}:
            cleanup_status = "skipped"
            cleanup_detail = "任务未正常完成，未进入清理阶段"
        phases[4] = _phase_payload(
            "llm_cleanup",
            "LLM 清理",
            cleanup_status,
            cleanup_detail,
            _mtime_iso_text(cleaner_path),
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
    if matched_skill:
        summary_parts.append(f"命中工具：{Path(matched_skill).name}")
    if fallback_to_llm:
        summary_parts.append("已回退到 LLM 解包")
    if generated_skill_path:
        summary_parts.append(f"生成候选工具：{Path(generated_skill_path).name}")
    summary = "；".join(summary_parts) if summary_parts else "根据运行目录推导当前阶段进展"

    overall_current_round = None
    overall_total_rounds = None
    for phase in phases:
        if phase["key"] in {"llm_unpack", "llm_review"} and phase.get("current_round") is not None:
            overall_current_round = phase.get("current_round")
            overall_total_rounds = phase.get("total_rounds")
            if phase["status"] == "running":
                break
    if overall_current_round is None:
        completed_round = _completed_round()
        if completed_round is not None:
            overall_current_round = completed_round
            overall_total_rounds = total_llm_rounds

    return {
        "task_id": task_id,
        "current_phase": current_phase,
        "summary": summary,
        "current_round": overall_current_round,
        "total_rounds": overall_total_rounds,
        "phases": phases,
    }


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _format_log_file(path: Path) -> str:
    if path.suffix.lower() == ".json":
        payload = _read_json_file(path)
        if payload is not None:
            try:
                return json.dumps(payload, ensure_ascii=False, indent=2)
            except Exception:
                pass
    return _read_text_file(path)


def _phase_log_files(run_dir: Path, phase: Optional[str]) -> list[Path]:
    phase_key = str(phase or "").strip()
    if not phase_key:
        files: list[Path] = [
            run_dir / "stage1_preprocess.json",
            run_dir / "stage2_skill_match.json",
            run_dir / "stage3_skill_exec.json",
            run_dir / "stage4_llm_fallback.json",
            run_dir / "stage5_skill_generate.json",
            run_dir / "cleaner_messages.json",
            run_dir / "summary.txt",
            run_dir / "reason.txt",
        ]
        files.extend(sorted(run_dir.glob("executor_round_*_messages.json")))
        files.extend(sorted(run_dir.glob("verifier_round_*_messages.json")))
        files.extend(sorted(run_dir.glob("*.log")))
        return files

    mapping: dict[str, list[Path]] = {
        "preprocess": [run_dir / "stage1_preprocess.log", run_dir / "stage1_preprocess.json"],
        "tool_match": [run_dir / "stage2_skill_match.log", run_dir / "stage2_skill_match.json", run_dir / "stage3_skill_exec.log", run_dir / "stage3_skill_exec.json"],
        "llm_unpack": [
            run_dir / "stage3_llm_unpack.log",
            run_dir / "stage4_llm_fallback.json",
            *sorted(run_dir.glob("executor_round_*_transcript.log")),
            *sorted(run_dir.glob("executor_round_*_messages.json")),
        ],
        "llm_review": [
            run_dir / "stage4_llm_review.log",
            *sorted(run_dir.glob("verifier_round_*_transcript.log")),
            *sorted(run_dir.glob("verifier_round_*_messages.json")),
            run_dir / "reason.txt",
            run_dir / "summary.txt",
        ],
        "llm_cleanup": [
            run_dir / "cleaner.log",
            run_dir / "cleaner_transcript.log",
            run_dir / "cleaner_messages.json",
            run_dir / "stage5_skill_generate.log",
            run_dir / "stage5_skill_generate.json",
            run_dir / "skill_author_transcript.log",
            run_dir / "skill_author_messages.json",
        ],
    }
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


def _read_json_index_items(path: Path) -> list[dict]:
    payload = _read_json_file(path)
    if not isinstance(payload, dict):
        return []
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return []
    return [item for item in raw_items if isinstance(item, dict)]


def _scan_output_tree(output_root: Path) -> tuple[int, int, int, Optional[str], int, int]:
    file_count = 0
    dir_count = 0
    total_size = 0
    largest_file_path: Optional[str] = None
    largest_file_size = 0
    top_level_entry_count = 0

    if not output_root.exists() or not output_root.is_dir():
        return file_count, dir_count, total_size, largest_file_path, largest_file_size, top_level_entry_count

    try:
        top_level_entry_count = sum(1 for _ in output_root.iterdir())
    except Exception:
        top_level_entry_count = 0

    for root, dirs, files in os.walk(output_root, followlinks=False):
        root_path = Path(root)
        real_dirs: list[str] = []
        for directory in dirs:
            path = root_path / directory
            if path.is_symlink():
                continue
            dir_count += 1
            real_dirs.append(directory)
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

    return file_count, dir_count, total_size, largest_file_path, largest_file_size, top_level_entry_count


def _get_task_result(task_id: str) -> dict:
    task = _get_task_or_404(task_id)
    output_root = Path(str(task.get("output_path") or "").strip())
    run_root = _derive_run_path(task)
    summary_path = run_root / "summary.txt"
    reason_path = run_root / "reason.txt"
    tokens_summary_path = run_root / "tokens_summary.json"
    sessions_index_path = run_root / "sessions" / "index.json"

    warnings: list[str] = []
    task_status = str(task.get("status") or "").strip() or "unknown"
    session_count = len(_read_json_index_items(sessions_index_path))
    event_count = _count_task_events(task_id)

    available = task_status in {"success", "failed", "cancelled"}
    if not output_root.exists() or not output_root.is_dir():
        warnings.append("输出目录不存在")
        available = False

    output_file_count = 0
    output_dir_count = 0
    output_total_size_bytes = 0
    largest_file_path: Optional[str] = None
    largest_file_size_bytes = 0
    top_level_entry_count = 0
    if output_root.exists() and output_root.is_dir():
        (
            output_file_count,
            output_dir_count,
            output_total_size_bytes,
            largest_file_path,
            largest_file_size_bytes,
            top_level_entry_count,
        ) = _scan_output_tree(output_root)

    summary_text = _read_text_file(summary_path).strip() or None
    reason_text = _read_text_file(reason_path).strip() or None
    if summary_path.exists() and not summary_text:
        warnings.append("summary.txt 存在但为空")
    if reason_path.exists() and not reason_text:
        warnings.append("reason.txt 存在但为空")
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
            "output_file_count": output_file_count,
            "output_dir_count": output_dir_count,
            "output_total_size_bytes": output_total_size_bytes,
            "largest_file_path": largest_file_path,
            "largest_file_size_bytes": largest_file_size_bytes,
            "top_level_entry_count": top_level_entry_count,
            "matched_skill": str(task.get("matched_skill") or "").strip() or None,
            "fallback_to_llm": bool(task.get("fallback_to_llm")),
            "generated_skill_path": str(task.get("generated_skill_path") or "").strip() or None,
            "promotion_success_count": int(task.get("promotion_success_count") or 0),
            "executor_rounds": int(task.get("rounds") or 0),
            "session_count": session_count,
            "event_count": event_count,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_seconds": duration_seconds,
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
            query.order_by(UnpackTask.created_at.desc())
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
    db = get_db_session()
    try:
        row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
        if row is None:
            row = ServiceConfig(
                key=key,
                value=payload.value,
                value_type=_infer_value_type(payload.value),
                description=payload.description,
            )
            db.add(row)
        else:
            row.value = payload.value
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
    for meta in list_skills(TOOLS_DIR):
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
                "skill_status": str(meta.get("skill_status") or ""),
                "skill_version": int(meta.get("skill_version") or 1),
                "family_id": str(meta.get("family_id") or ""),
                "promotion_success_count": int(meta.get("promotion_success_count") or 0),
                "promotion_threshold": int(meta.get("promotion_threshold") or 5),
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
    return {"status": "ok", "owner_id": get_worker_id()}


@router.get("/ready", response_model=ReadyResponse)
@router.get("/api/app/firmware-unpacker/ready", response_model=ReadyResponse)
async def ready_check():
    return {"status": "ready", "owner_id": get_worker_id()}


@router.get("/api/app/firmware-unpacker/cluster", response_model=ClusterInfoResponse)
async def get_cluster_info(
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    return get_cluster_snapshot()


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
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    return _list_tasks(project_id, status_filter, owner_id, search, limit, offset)


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
    return task


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
        "message": "任务删除成功",
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


@router.get("/api/app/firmware-unpacker/tasks", response_model=TaskListResponse)
async def list_tasks_legacy(
    project_id: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    owner_id: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=200),
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
        "message": "批量删除完成",
        "deleted_count": deleted_count,
        "skipped_ids": skipped_ids,
    }
