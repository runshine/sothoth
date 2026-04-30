"""B2S frontend-compatible API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Query
from sqlalchemy.orm import Session

from app.exception import UnauthorizedError
from app.model import B2STask, get_db
from app.schemas import ActionResponse, RetryRequest, TaskCreate, TaskDetailResponse, TaskListResponse, TaskResponse, TokenUser
from app.service.auth import get_auth_service
from app.service.project import get_project_service
from app.service.security import validate_project_id
from app.service.task_service import (
    build_task_detail,
    build_task_response,
    create_task,
    get_task_or_404,
    retry_task,
    sync_task,
    terminate_task,
)

router = APIRouter(prefix="/api/app/binary-to-source", tags=["binary-to-source"])


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "secflow-app-binary-to-source"}


@router.get("/ready")
async def ready_check():
    return {"status": "ready"}


async def get_current_context(project_id: str, authorization: Optional[str] = Header(None)) -> TokenUser:
    validate_project_id(project_id)
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization格式错误，应为 Bearer <token>")
    token = parts[1]
    user = await get_auth_service().validate_token(token)
    await get_project_service().require_access(token, project_id)
    return TokenUser(**user)


@router.get("/projects/{project_id}/tasks", response_model=TaskListResponse)
async def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    query = db.query(B2STask).filter(B2STask.project_id == project_id).order_by(B2STask.created_at.desc())
    tasks = query.all()
    for task in tasks:
        await sync_task(db, task)
    if status:
        tasks = [task for task in tasks if task.status == status]
    items = [build_task_response(db, task) for task in tasks]
    return TaskListResponse(total=len(items), items=items)


@router.post("/projects/{project_id}/tasks", response_model=TaskResponse)
async def create_b2s_task(
    project_id: str,
    payload: TaskCreate,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    created_by = user.username or user.user_id
    return await create_task(db, project_id, payload, created_by)


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=TaskDetailResponse)
async def get_b2s_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    return build_task_detail(db, task)


@router.post("/projects/{project_id}/tasks/{task_id}/terminate", response_model=ActionResponse)
async def terminate_b2s_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await terminate_task(db, task)
    return ActionResponse(status="ok", task_id=task_id, message="任务已取消")


@router.post("/projects/{project_id}/tasks/{task_id}/retry", response_model=ActionResponse)
async def retry_b2s_task(
    project_id: str,
    task_id: str,
    payload: RetryRequest,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await retry_task(db, task, payload.item_ids)
    return ActionResponse(status="ok", task_id=task_id, message="任务已重新提交")
