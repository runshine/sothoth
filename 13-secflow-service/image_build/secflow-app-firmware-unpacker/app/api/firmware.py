"""Firmware unpacker API routes."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import or_

from app.api.dependencies import ensure_project_access, get_current_subject
from app.exception import ForbiddenError, NotFoundError, ValidationError
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
    ReadyResponse,
    TaskListResponse,
    TaskProgressResponse,
    TaskResourceUsageResponse,
    TaskResponse,
    TaskSubmitResponse,
    ToolListResponse,
    UnpackRequest,
)
from app.services.pod_metrics import get_pod_resource_usage
from app.services.task_manager import cancel_task, delete_tasks, retry_task, submit_unpack_task
from app.services.worker import get_cluster_snapshot, get_worker_id
from app.skill_store import list_skills
from app.unpacker_engine import TOOLS_DIR


router = APIRouter(tags=["Firmware Unpacker"])


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
        return _with_agentflow_run_dir(task.to_dict())
    finally:
        db.close()


def _with_agentflow_run_dir(task: dict) -> dict:
    run_id = str(task.get("agentflow_run_id") or "").strip()
    if not run_id:
        task["agentflow_run_dir"] = None
        return task

    from app.config import get_config

    task["agentflow_run_dir"] = str(Path(get_config().agentflow.runs_dir) / run_id)
    return task


def _get_task_resource_usage(task_id: str) -> dict:
    task = _get_task_or_404(task_id)
    worker_id = str(task.get("worker_id") or "").strip() or None
    if not worker_id:
        return {
            "task_id": task_id,
            "worker_id": None,
            "available": False,
            "message": "任务当前未绑定运行中的 Worker，无法获取资源使用情况",
            "containers": [],
        }

    metrics = get_pod_resource_usage(worker_id)
    if not metrics:
        return {
            "task_id": task_id,
            "worker_id": worker_id,
            "available": False,
            "pod_name": worker_id,
            "message": "未获取到任务所在 Worker Pod 的资源指标",
            "containers": [],
        }

    return {
        "task_id": task_id,
        "worker_id": worker_id,
        "available": True,
        **metrics,
    }


def _get_task_agentflow_status(task_id: str) -> dict:
    from app.config import get_config

    task = _get_task_or_404(task_id)
    run_id = str(task.get("agentflow_run_id") or "").strip() or None
    run_path = str(task.get("run_path") or "").strip()
    run_json = None
    agentflow_run_dir = None
    if run_id:
        candidate_dirs = [Path(get_config().agentflow.runs_dir) / run_id]
        if run_path:
            candidate_dirs.append(Path(run_path) / "agentflow" / "runs" / run_id)
        for candidate_dir in candidate_dirs:
            candidate = candidate_dir / "run.json"
            if candidate.is_file():
                try:
                    run_json = json.loads(candidate.read_text(encoding="utf-8"))
                    agentflow_run_dir = str(candidate_dir)
                    break
                except Exception:
                    run_json = None
    run_dir = Path(run_path) if run_path else None
    final_result = _read_json_file(run_dir / "final_result.json") if run_dir else None
    tokens_summary = _read_json_file(run_dir / "tokens_summary.json") if run_dir else None
    return {
        "task_id": task_id,
        "agentflow_run_id": run_id,
        "agentflow_run_dir": agentflow_run_dir,
        "run_path": run_path or None,
        "status": run_json.get("status") if isinstance(run_json, dict) else None,
        "nodes": run_json.get("nodes") if isinstance(run_json, dict) else None,
        "final_result": final_result,
        "tokens_summary": tokens_summary,
        "node_attempts": task.get("node_attempts"),
        "failure_summary": task.get("failure_summary"),
        "run": run_json,
    }


def _phase_payload(key: str, label: str, status: str, detail: Optional[str] = None, updated_at: Optional[str] = None) -> dict:
    return {
        "key": key,
        "label": label,
        "status": status,
        "detail": detail,
        "updated_at": updated_at,
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
    stage4_path = run_dir / "stage4_llm_fallback.json"
    stage5_path = run_dir / "stage5_skill_generate.json"
    cleaner_path = run_dir / "cleaner_messages.json"
    executor_logs = sorted(run_dir.glob("executor_round_*_messages.json"))
    verifier_logs = sorted(run_dir.glob("verifier_round_*_messages.json"))

    task_status = str(task.get("status") or "").lower()
    task_result = str(task.get("result_status") or "").lower()
    result_message = str(task.get("result_message") or "")
    quick_preprocess_success = "quick pre-process" in result_message.lower()
    matched_skill = str(task.get("matched_skill") or "").strip()
    fallback_to_llm = bool(task.get("fallback_to_llm"))
    generated_skill_path = str(task.get("generated_skill_path") or "").strip()

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
            if executor_logs:
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
                _mtime_iso_text(executor_logs[-1]) if executor_logs else _mtime_iso_text(stage4_path),
            )
        elif matched_skill and not fallback_to_llm:
            phases[2] = _phase_payload("llm_unpack", "LLM 解包", "skipped", "工具执行成功，未进入 LLM 解包")

        if verifier_logs or task_result in {"success", "max_retries_reached", "failed"}:
            review_status = "running"
            review_detail = "LLM 正在评审当前解包结果"
            if verifier_logs:
                review_status = "success" if task_status == "success" else ("failed" if task_status == "failed" else "running")
                review_detail = f"已完成 {len(verifier_logs)} 轮评审"
                if task_status == "failed":
                    review_detail = "评审未通过，任务失败"
            phases[3] = _phase_payload(
                "llm_review",
                "LLM 评审",
                review_status,
                review_detail,
                _mtime_iso_text(verifier_logs[-1]) if verifier_logs else None,
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

    return {
        "task_id": task_id,
        "current_phase": current_phase,
        "summary": summary,
        "phases": phases,
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
    result = submit_unpack_task(
        firmware_path=request.firmware_path,
        project_id=project_id,
    )
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
    worker_id: Optional[str],
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
        if worker_id:
            query = query.filter(UnpackTask.worker_id == worker_id)
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
            "items": [_with_agentflow_run_dir(task.to_dict()) for task in tasks],
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


@router.get("/health", response_model=HealthResponse)
@router.get("/api/app/firmware-unpacker/health", response_model=HealthResponse)
async def health_check():
    return {"status": "ok", "worker_id": get_worker_id()}


@router.get("/ready", response_model=ReadyResponse)
@router.get("/api/app/firmware-unpacker/ready", response_model=ReadyResponse)
async def ready_check():
    return {"status": "ready", "worker_id": get_worker_id()}


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
    worker_id: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    return _list_tasks(project_id, status_filter, worker_id, search, limit, offset)


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


@router.get("/api/app/firmware-unpacker/projects/{project_id}/tasks/{task_id}/agentflow")
async def get_project_task_agentflow(
    project_id: str,
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await ensure_project_access(project_id, token)
    task = _get_task_or_404(task_id)
    if _normalize_project_id(task.get("project_id")) != project_id:
        raise NotFoundError("任务", task_id)
    return _get_task_agentflow_status(task_id)


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
    worker_id: Optional[str] = Query(default=None),
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
        worker_id,
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


@router.get("/api/app/firmware-unpacker/tasks/{task_id}/agentflow")
async def get_task_agentflow_legacy(
    task_id: str,
    subject_and_token: tuple[dict, str] = Depends(get_current_subject),
):
    _, token = subject_and_token
    await _get_task_with_access(task_id, token)
    return _get_task_agentflow_status(task_id)


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
    ok, new_task_id, message = retry_task(task_id)
    if not ok or not new_task_id:
        raise ValidationError(message)
    return {
        "message": message,
        "task_id": task_id,
        "new_task_id": new_task_id,
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
