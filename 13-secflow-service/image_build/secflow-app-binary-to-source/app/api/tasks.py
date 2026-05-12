"""B2S frontend-compatible API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.exception import UnauthorizedError
from app.model import B2STask, get_db
from app.schemas import ActionResponse, B2SArtifactContentResponse, B2SServiceConfig, LlmProviderListResponse, LlmProviderSummary, RerunRequest, RetryRequest, ReviewAnalyticsResponse, TaskCreate, TaskDetailResponse, TaskItemAdvancedResponse, TaskItemArtifactsResponse, TaskListResponse, TaskPrepareResponse, TaskResponse, TokenUser
from app.service.auth import get_auth_service
from app.service.configcenter import get_configcenter_client
from app.service.config_service import get_config_service
from app.service.project import get_project_service
from app.service.security import validate_project_id
from app.service.task_service import (
    build_task_detail,
    build_task_item_advanced,
    build_task_item_artifact_content,
    build_task_item_artifacts,
    build_task_item_review_analytics,
    build_task_response,
    create_task,
    delete_task,
    get_task_item_or_404,
    get_task_or_404,
    retry_task,
    rerun_task,
    sync_task,
    generate_task_id,
    terminate_task,
)

router = APIRouter(prefix="/api/app/binary-to-source", tags=["binary-to-source"])


class ConfigSaveRequest(BaseModel):
    config: dict


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


@router.get("/projects/{project_id}/llm-providers", response_model=LlmProviderListResponse)
async def list_llm_providers(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
):
    payload = await get_configcenter_client().list_llm_providers()
    raw_items = payload.get("items") if isinstance(payload.get("items"), list) else []
    items = [LlmProviderSummary(**item) for item in raw_items if isinstance(item, dict) and item.get("enabled", True)]
    return LlmProviderListResponse(
        items=items,
        total=len(items),
        default_provider_key=payload.get("default_provider_key"),
    )


@router.get("/projects/{project_id}/config", response_model=B2SServiceConfig)
async def get_b2s_config(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return B2SServiceConfig(**get_config_service().get_config(db, project_id))


@router.put("/projects/{project_id}/config", response_model=B2SServiceConfig)
async def save_b2s_config(
    project_id: str,
    payload: ConfigSaveRequest,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return B2SServiceConfig(**get_config_service().save_config(db, project_id, payload.config))


@router.get("/projects/{project_id}/tasks", response_model=TaskListResponse)
async def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    query = db.query(B2STask).filter(B2STask.project_id == project_id)
    if status:
        query = query.filter(B2STask.status == status)
    total = query.count()
    tasks = query.order_by(B2STask.created_at.desc()).offset(offset).limit(limit).all()
    for task in tasks:
        await sync_task(db, task)
    items = [build_task_response(db, task) for task in tasks]
    return TaskListResponse(total=total, items=items)


@router.post("/projects/{project_id}/tasks/prepare", response_model=TaskPrepareResponse)
async def prepare_b2s_task(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return TaskPrepareResponse(task_id=generate_task_id(db, project_id))


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


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/advanced", response_model=TaskItemAdvancedResponse)
async def get_b2s_task_item_advanced(
    project_id: str,
    task_id: str,
    item_id: str,
    include_content: bool = Query(True),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_advanced(item, include_content=include_content)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/artifacts", response_model=TaskItemArtifactsResponse)
async def get_b2s_task_item_artifacts(
    project_id: str,
    task_id: str,
    item_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_artifacts(item)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/artifacts/{artifact_id}/content", response_model=B2SArtifactContentResponse)
async def get_b2s_task_item_artifact_content(
    project_id: str,
    task_id: str,
    item_id: str,
    artifact_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(512 * 1024, ge=1, le=512 * 1024),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_artifact_content(item, artifact_id, offset=offset, limit=limit)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/review-analytics", response_model=ReviewAnalyticsResponse)
async def get_b2s_task_item_review_analytics(
    project_id: str,
    task_id: str,
    item_id: str,
    mock: bool = Query(False),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_review_analytics(item, mock=mock)


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


@router.delete("/projects/{project_id}/tasks/{task_id}", response_model=ActionResponse)
async def delete_b2s_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await delete_task(db, task)
    return ActionResponse(status="ok", task_id=task_id, message="任务及文件已删除")


@router.post("/projects/{project_id}/tasks/{task_id}/rerun", response_model=ActionResponse)
async def rerun_b2s_task(
    project_id: str,
    task_id: str,
    payload: RerunRequest | None = None,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    req = payload or RerunRequest()
    await rerun_task(db, task, clean_output=req.clean_output, cancel_running=req.cancel_running)
    return ActionResponse(status="ok", task_id=task_id, message="任务已完整重新提交")


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
