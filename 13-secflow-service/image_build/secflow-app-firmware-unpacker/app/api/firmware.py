"""Firmware unpacker API routes."""

from __future__ import annotations

import os
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
    TaskResponse,
    TaskSubmitResponse,
    UnpackRequest,
)
from app.services.task_manager import cancel_task, delete_tasks, retry_task, submit_unpack_task
from app.services.worker import get_cluster_snapshot, get_worker_id


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
        return task.to_dict()
    finally:
        db.close()


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
