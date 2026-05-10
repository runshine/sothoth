"""Binary Security API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from app.exception import UnauthorizedError
from app.model import get_db
from app.schemas import (
    BinarySecurityActionResponse,
    BinarySecurityArtifactsResponse,
    BinarySecurityDownstreamStatusSyncPayload,
    BinarySecurityModuleSelectionConfirmPayload,
    BinarySecurityModuleSelectionResponse,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityServiceConfigPayload,
    BinarySecurityServiceConfigResponse,
    BinarySecurityTaskCreate,
    BinarySecurityUploadCompletePayload,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskPrepareResponse,
    BinarySecurityTimelineResponse,
    TokenUser,
)
from app.service.auth import get_auth_service
from app.service.project import get_project_service
from app.service.security import validate_project_id
from app.service.task_manager import get_task_manager

from . import router


async def get_current_context(project_id: str, authorization: Optional[str] = Header(None)) -> TokenUser:
    validate_project_id(project_id)
    if not authorization:
        raise UnauthorizedError("缺少 Authorization 头")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization 格式错误，应为 Bearer <token>")
    token = parts[1]
    user = await get_auth_service().validate_token(token)
    await get_project_service().require_access(token, project_id)
    return TokenUser(**user)


async def get_current_user(authorization: Optional[str] = Header(None)) -> TokenUser:
    if not authorization:
        raise UnauthorizedError("缺少 Authorization 头")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization 格式错误，应为 Bearer <token>")
    token = parts[1]
    user = await get_auth_service().validate_token(token)
    return TokenUser(**user)


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "secflow-app-binary-security"}


@router.get("/ready")
async def ready_check():
    return {"status": "ready"}


@router.get("/projects/{project_id}/tasks", response_model=BinarySecurityTaskListResponse)
def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().list_tasks(db, project_id=project_id, status=status, task_type=task_type)


@router.post("/projects/{project_id}/tasks/prepare", response_model=BinarySecurityTaskPrepareResponse)
def prepare_task(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task_id = get_task_manager().prepare_task_id(db, project_id)
    return BinarySecurityTaskPrepareResponse(task_id=task_id)


@router.post("/projects/{project_id}/tasks", response_model=BinarySecurityTaskDetailResponse)
async def create_task(
    project_id: str,
    payload: BinarySecurityTaskCreate,
    user: TokenUser = Depends(get_current_context),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    token = authorization.split()[1] if authorization else ""
    created_by = user.username or user.user_id or "unknown"
    return await get_task_manager().create_task(
        db,
        project_id=project_id,
        payload=payload,
        created_by=created_by,
        authorization_token=token,
    )


@router.post("/projects/{project_id}/tasks/{task_id}/uploads/complete", response_model=BinarySecurityTaskDetailResponse)
async def complete_uploads(
    project_id: str,
    task_id: str,
    payload: BinarySecurityUploadCompletePayload,
    user: TokenUser = Depends(get_current_context),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    token = authorization.split()[1] if authorization else ""
    updated_by = user.username or user.user_id or "unknown"
    return await get_task_manager().complete_uploads(
        db,
        project_id=project_id,
        task_id=task_id,
        payload=payload,
        updated_by=updated_by,
        authorization_token=token,
    )


@router.post("/projects/{project_id}/tasks/{task_id}/start", response_model=BinarySecurityTaskDetailResponse)
def start_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().start_task(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=BinarySecurityTaskDetailResponse)
def get_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_detail(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}/timeline", response_model=BinarySecurityTimelineResponse)
def get_timeline(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_timeline(db, project_id=project_id, task_id=task_id)


@router.delete("/projects/{project_id}/tasks/{task_id}/timeline", response_model=BinarySecurityActionResponse)
def clear_timeline(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().clear_timeline(db, project_id=project_id, task_id=task_id)


@router.delete("/projects/{project_id}/tasks/{task_id}/timeline/{event_id}", response_model=BinarySecurityActionResponse)
def delete_timeline_event(
    project_id: str,
    task_id: str,
    event_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().delete_timeline_event(db, project_id=project_id, task_id=task_id, event_id=event_id)


@router.get("/projects/{project_id}/tasks/{task_id}/artifacts", response_model=BinarySecurityArtifactsResponse)
def get_artifacts(
    project_id: str,
    task_id: str,
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_artifacts(db, project_id=project_id, task_id=task_id, limit=limit, offset=offset)


@router.post("/projects/{project_id}/tasks/{task_id}/cancel", response_model=BinarySecurityActionResponse)
async def cancel_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return await get_task_manager().cancel_task(db, project_id=project_id, task_id=task_id)


@router.delete("/projects/{project_id}/tasks/{task_id}", response_model=BinarySecurityActionResponse)
async def delete_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return await get_task_manager().delete_task(db, project_id=project_id, task_id=task_id)


@router.post("/projects/{project_id}/tasks/{task_id}/retry", response_model=BinarySecurityActionResponse)
def retry_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    get_task_manager().retry_task(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(task_id=task_id, message="任务已从第一阶段重新排队")


@router.post("/projects/{project_id}/tasks/{task_id}/continue", response_model=BinarySecurityActionResponse)
async def continue_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    target_stage = await get_task_manager().continue_task(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(task_id=task_id, message=f"任务已重新排队，将从阶段 {target_stage} 继续")


@router.post("/projects/{project_id}/tasks/{task_id}/stages/{stage_name}/retry", response_model=BinarySecurityActionResponse)
def retry_stage(
    project_id: str,
    task_id: str,
    stage_name: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    get_task_manager().retry_stage(db, project_id=project_id, task_id=task_id, stage_name=stage_name)
    return BinarySecurityActionResponse(task_id=task_id, message=f"阶段 {stage_name} 的全部子任务已重新排队")


@router.post("/projects/{project_id}/tasks/{task_id}/sync-downstream-status", response_model=BinarySecurityActionResponse)
async def sync_downstream_status(
    project_id: str,
    task_id: str,
    payload: Optional[BinarySecurityDownstreamStatusSyncPayload] = None,
    _: TokenUser = Depends(get_current_context),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    token = authorization.split()[1] if authorization else ""
    return await get_task_manager().sync_downstream_status(
        db,
        project_id=project_id,
        task_id=task_id,
        stage_name=payload.stage_name if payload else None,
        item_id=payload.item_id if payload else None,
        force=payload.force if payload else False,
        token=token,
    )


@router.get("/projects/{project_id}/tasks/{task_id}/module-selection", response_model=BinarySecurityModuleSelectionResponse)
def get_module_selection(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_module_selection(db, project_id=project_id, task_id=task_id)


@router.post("/projects/{project_id}/tasks/{task_id}/module-selection/confirm", response_model=BinarySecurityTaskDetailResponse)
def confirm_module_selection(
    project_id: str,
    task_id: str,
    payload: BinarySecurityModuleSelectionConfirmPayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().confirm_module_selection(
        db,
        project_id=project_id,
        task_id=task_id,
        selected_module_keys=payload.selected_module_keys,
    )


@router.get("/projects/{project_id}/config", response_model=BinarySecurityProjectConfigResponse)
def get_project_config(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_project_config(db, project_id)


@router.put("/projects/{project_id}/config", response_model=BinarySecurityProjectConfigResponse)
def put_project_config(
    project_id: str,
    payload: BinarySecurityProjectConfigPayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().save_project_config(db, project_id, payload)


@router.get("/service/config", response_model=BinarySecurityServiceConfigResponse)
def get_service_config(
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_service_config(db)


@router.put("/service/config", response_model=BinarySecurityServiceConfigResponse)
def put_service_config(
    payload: BinarySecurityServiceConfigPayload,
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().save_service_config(db, payload)
