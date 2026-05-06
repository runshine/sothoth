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
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
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


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "secflow-app-binary-security"}


@router.get("/ready")
async def ready_check():
    return {"status": "ready"}


@router.get("/projects/{project_id}/tasks", response_model=BinarySecurityTaskListResponse)
async def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().list_tasks(db, project_id=project_id, status=status)


@router.post("/projects/{project_id}/tasks/prepare", response_model=BinarySecurityTaskPrepareResponse)
async def prepare_task(
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
async def start_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().start_task(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=BinarySecurityTaskDetailResponse)
async def get_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_detail(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}/timeline", response_model=BinarySecurityTimelineResponse)
async def get_timeline(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_timeline(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}/artifacts", response_model=BinarySecurityArtifactsResponse)
async def get_artifacts(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_artifacts(db, project_id=project_id, task_id=task_id)


@router.post("/projects/{project_id}/tasks/{task_id}/cancel", response_model=BinarySecurityActionResponse)
async def cancel_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    await get_task_manager().cancel_task(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(task_id=task_id, message="任务已取消")


@router.post("/projects/{project_id}/tasks/{task_id}/retry", response_model=BinarySecurityActionResponse)
async def retry_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    get_task_manager().retry_task(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(task_id=task_id, message="任务已重新排队")


@router.post("/projects/{project_id}/tasks/{task_id}/resume", response_model=BinarySecurityActionResponse)
async def resume_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    get_task_manager().resume_task(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(task_id=task_id, message="任务已继续执行")


@router.get("/projects/{project_id}/config", response_model=BinarySecurityProjectConfigResponse)
async def get_project_config(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_project_config(db, project_id)


@router.put("/projects/{project_id}/config", response_model=BinarySecurityProjectConfigResponse)
async def put_project_config(
    project_id: str,
    payload: BinarySecurityProjectConfigPayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().save_project_config(db, project_id, payload)
