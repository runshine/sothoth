"""B2S frontend-compatible API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.exception import UnauthorizedError
from app.model import B2STask, get_db
from app.schemas import ActionResponse, B2SArtifactContentResponse, B2SServiceConfig, LlmProviderListResponse, LlmProviderSummary, RerunRequest, RetryRequest, ReviewAnalyticsResponse, SessionFileResponse, SessionIndexResponse, TaskCreate, TaskDetailResponse, TaskItemAdvancedResponse, TaskItemArtifactsResponse, TaskListResponse, TaskObservabilitySummary, TaskPrepareResponse, TaskRelationshipResponse, TaskResponse, TaskResultSummary, TokenUser
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
    build_task_observability_summary,
    build_task_relationship,
    build_task_result_summary,
    build_task_session_file,
    build_task_session_index,
    build_task_response,
    create_task,
    delete_task,
    get_task_item_or_404,
    get_task_or_404,
    query_items,
    retry_task,
    rerun_task,
    refresh_task_function_stats,
    sync_task,
    generate_task_id,
    terminate_task,
)

router = APIRouter(prefix="/api/app/binary-to-source", tags=["binary-to-source"])


class ConfigSaveRequest(BaseModel):
    config: dict


def _provider_summary(payload: dict) -> dict:
    return {
        "provider_key": str(payload.get("provider_key") or "").strip(),
        "display_name": str(payload.get("display_name") or "").strip() or None,
        "provider_type": str(payload.get("provider_type") or "").strip() or None,
        "enabled": bool(payload.get("enabled", False)),
        "is_default": bool(payload.get("is_default", False)),
        "model": str(payload.get("model") or "").strip() or None,
    }


async def _effective_llm_provider_summary(provider_key: str | None) -> dict | None:
    try:
        payload = await get_configcenter_client().list_llm_providers()
    except Exception:
        return None
    items = [item for item in (payload.get("items") if isinstance(payload.get("items"), list) else []) if isinstance(item, dict) and item.get("enabled", True)]
    if not items:
        return None
    normalized = str(provider_key or "").strip()
    if normalized:
        matched = next((item for item in items if str(item.get("provider_key") or "").strip() == normalized), None)
        return _provider_summary(matched) if matched else None
    default_key = str(payload.get("default_provider_key") or "").strip()
    matched = next((item for item in items if str(item.get("provider_key") or "").strip() == default_key), None) if default_key else None
    return _provider_summary(matched or items[0])


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
    payload = get_config_service().get_config(db, project_id)
    payload["effective_llm_provider"] = await _effective_llm_provider_summary(payload.get("llm_provider_key"))
    return B2SServiceConfig(**payload)


@router.put("/projects/{project_id}/config", response_model=B2SServiceConfig)
async def save_b2s_config(
    project_id: str,
    payload: ConfigSaveRequest,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    provider_key = str(payload.config.get("llm_provider_key") or "").strip()
    if provider_key:
        await get_configcenter_client().get_llm_provider(provider_key)
    saved = get_config_service().save_config(db, project_id, payload.config)
    saved["effective_llm_provider"] = await _effective_llm_provider_summary(saved.get("llm_provider_key"))
    return B2SServiceConfig(**saved)


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
    stats_changed = False
    for task in tasks:
        await sync_task(db, task)
        if refresh_task_function_stats(db, task, inspect_files=True, only_missing=True, commit=False):
            stats_changed = True
    if stats_changed:
        db.commit()
        for task in tasks:
            db.refresh(task)
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
    refresh_task_function_stats(db, task, inspect_files=True, only_missing=True)
    return build_task_detail(db, task)


@router.get("/projects/{project_id}/tasks/{task_id}/sessions", response_model=SessionIndexResponse)
async def get_b2s_task_sessions(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    return build_task_session_index(query_items(db, task.id))


@router.get("/projects/{project_id}/tasks/{task_id}/sessions/file", response_model=SessionFileResponse)
async def get_b2s_task_session_file(
    project_id: str,
    task_id: str,
    path: str = Query(...),
    offset: int = Query(0, ge=0),
    limit: int = Query(512 * 1024, ge=1, le=512 * 1024),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    items = query_items(db, task.id)
    return build_task_session_file(items, path, offset=offset, limit=limit)


@router.get("/projects/{project_id}/tasks/{task_id}/relationships", response_model=TaskRelationshipResponse)
async def get_b2s_task_relationships(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    items = query_items(db, task.id)
    return build_task_relationship(items)


@router.get("/projects/{project_id}/tasks/{task_id}/result", response_model=TaskResultSummary)
async def get_b2s_task_result(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    items = query_items(db, task.id)
    return build_task_result_summary(items)


@router.get("/projects/{project_id}/tasks/{task_id}/observability", response_model=TaskObservabilitySummary)
async def get_b2s_task_observability(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    items = query_items(db, task.id)
    return build_task_observability_summary(items)


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
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await sync_task(db, task)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_review_analytics(item)


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
    if payload and (payload.clean_output is not None or payload.cancel_running is not None):
        # Keep the request body backward-compatible for older clients, but the
        # backend no longer allows changing rerun semantics.
        pass
    await rerun_task(db, task, clean_output=True, cancel_running=True)
    return ActionResponse(status="ok", task_id=task_id, message="任务已清空output并从头重跑")


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
