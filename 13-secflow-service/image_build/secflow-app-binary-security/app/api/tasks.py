"""Binary Security API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.build_info import build_service_meta
from app.exception import UnauthorizedError
from app.model import get_db
from app.runtime_health import collect_liveness, collect_readiness
from app.schemas import (
    BinarySecurityAbnormalReasonHistoryResponse,
    BinarySecurityActionResponse,
    BinarySecurityArchiveJobPageResponse,
    BinarySecurityArtifactsResponse,
    BinarySecurityDeleteQueueResponse,
    BinarySecurityDownstreamStatusSyncPayload,
    BinarySecurityEntrySelectionConfirmPayload,
    BinarySecurityEntrySelectionResponse,
    BinarySecurityModuleReportDetailResponse,
    BinarySecurityModuleSelectionConfirmPayload,
    BinarySecurityModuleSelectionResponse,
    BinarySecurityOverviewResponse,
    BinarySecurityGlobalConfigPayload,
    BinarySecurityGlobalConfigResponse,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityTaskPolicyConfigPayload,
    BinarySecurityTaskPolicyConfigResponse,
    BinarySecurityServiceConfigResponse,
    BinarySecurityStageItemDetailResponse,
    BinarySecurityStateEventInboxPageResponse,
    BinarySecurityStageItemPageResponse,
    BinarySecuritySyncEventPageResponse,
    BinarySecurityTaskConcurrencyUpdatePayload,
    BinarySecurityTaskCreate,
    BinarySecurityTaskPolicyUpdatePayload,
    BinarySecurityTaskRuntimePolicyUpdatePayload,
    BinarySecurityUploadCompletePayload,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskOperationPageResponse,
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
    meta = dict(build_service_meta() or {})
    payload = {
        **meta,
        **collect_liveness(),
    }
    if meta.get("service_id") and "service" not in payload:
        payload["service"] = meta.get("service_id")
    return payload


@router.get("/ready")
async def ready_check():
    payload = await collect_readiness()
    status_code = 200 if payload.get("status") == "ready" else 503
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/projects/{project_id}/tasks", response_model=BinarySecurityTaskListResponse)
def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    pipeline_profile: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=1000),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().list_tasks(
        db,
        project_id=project_id,
        status=status,
        task_type=task_type,
        pipeline_profile=pipeline_profile,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )


@router.get("/tasks", response_model=BinarySecurityTaskListResponse)
def list_tasks_global(
    project_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    pipeline_profile: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=1000),
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().list_tasks(
        db,
        project_id=project_id,
        status=status,
        task_type=task_type,
        pipeline_profile=pipeline_profile,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )


@router.get("/delete-queue", response_model=BinarySecurityDeleteQueueResponse)
def list_delete_queue(
    project_id: Optional[str] = Query(None),
    task_type: Optional[str] = Query(None),
    delete_status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("delete_requested_at"),
    sort_direction: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=1000),
    authorization: Optional[str] = Header(None),
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    return get_task_manager().list_delete_queue(
        db,
        token=token,
        project_id=project_id,
        task_type=task_type,
        delete_status=delete_status,
        search=search,
        sort_by=sort_by,
        sort_direction=sort_direction,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/state-events",
    response_model=BinarySecurityStateEventInboxPageResponse,
    summary="List Historical Compatibility State Events",
)
def list_state_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=1000),
    sort_by: str = Query("processed_at"),
    sort_order: str = Query("desc"),
    status: Optional[list[str]] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    handler_pod: Optional[str] = Query(default=None),
    task_id: Optional[str] = Query(default=None),
    failed_only: bool = Query(default=False),
    slow_only: bool = Query(default=False),
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().list_state_event_inbox_records(
        db,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
        statuses=status or [],
        event_type=event_type,
        handler_pod=handler_pod,
        task_id=task_id,
        failed_only=failed_only,
        slow_only=slow_only,
    )


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


# Preferred endpoint for the global task policy config used during task creation.
@router.get("/task-policy-config", response_model=BinarySecurityTaskPolicyConfigResponse)
def get_task_policy_config(
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_policy_config(db)


# Preferred endpoint for the global task policy config used during task creation.
@router.put("/task-policy-config", response_model=BinarySecurityTaskPolicyConfigResponse)
def save_task_policy_config(
    payload: BinarySecurityTaskPolicyConfigPayload,
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().save_task_policy_config(db, payload=payload)


# Backward-compatible alias for the global task policy config endpoint.
@router.get("/projects/{project_id}/config", response_model=BinarySecurityProjectConfigResponse)
def get_project_config(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_project_config(db, project_id=project_id)


# Backward-compatible alias for the global task policy config endpoint.
@router.put("/projects/{project_id}/config", response_model=BinarySecurityProjectConfigResponse)
def save_project_config(
    project_id: str,
    payload: BinarySecurityProjectConfigPayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().save_project_config(db, project_id=project_id, payload=payload)


@router.get("/service/config", response_model=BinarySecurityServiceConfigResponse)
def get_service_config(
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_service_config(db)


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


@router.get("/projects/{project_id}/tasks/{task_id}/stage-items", response_model=BinarySecurityStageItemPageResponse)
def get_task_stage_items(
    project_id: str,
    task_id: str,
    stage_name: str = Query(..., min_length=1),
    status: Optional[str] = Query(None),
    downstream_status: Optional[str] = Query(None),
    sync_status: Optional[str] = Query(None),
    sort_by: Optional[str] = Query(None),
    sort_direction: str = Query("desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=2000),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_stage_items_page(
        db,
        project_id=project_id,
        task_id=task_id,
        stage_name=stage_name,
        status=status,
        downstream_status=downstream_status,
        sync_status=sync_status,
        sort_by=sort_by,
        sort_direction=sort_direction,
        page=page,
        per_page=per_page,
    )


@router.get("/projects/{project_id}/tasks/{task_id}/stage-items/{item_id}", response_model=BinarySecurityStageItemDetailResponse)
def get_task_stage_item_detail(
    project_id: str,
    task_id: str,
    item_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_stage_item_detail(
        db,
        project_id=project_id,
        task_id=task_id,
        item_id=item_id,
    )


@router.get("/projects/{project_id}/tasks/{task_id}/orchestration-observability")
def get_task_orchestration_observability(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_orchestration_observability(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}/overview", response_model=BinarySecurityOverviewResponse)
def get_task_overview(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_overview(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}/archive-jobs", response_model=BinarySecurityArchiveJobPageResponse)
def get_task_archive_jobs(
    project_id: str,
    task_id: str,
    stage_name: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=1000),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_archive_jobs_page(
        db,
        project_id=project_id,
        task_id=task_id,
        stage_name=stage_name,
        page=page,
        per_page=per_page,
    )


@router.get(
    "/projects/{project_id}/tasks/{task_id}/abnormal-reason-history",
    response_model=BinarySecurityAbnormalReasonHistoryResponse,
)
def get_task_abnormal_reason_history(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_task_abnormal_reason_history(db, project_id=project_id, task_id=task_id)


@router.put("/projects/{project_id}/tasks/{task_id}/concurrency", response_model=BinarySecurityTaskDetailResponse)
def update_task_concurrency(
    project_id: str,
    task_id: str,
    payload: BinarySecurityTaskConcurrencyUpdatePayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().update_task_concurrency(db, project_id=project_id, task_id=task_id, payload=payload)


@router.put("/projects/{project_id}/tasks/{task_id}/policy", response_model=BinarySecurityTaskDetailResponse)
def update_task_policy(
    project_id: str,
    task_id: str,
    payload: BinarySecurityTaskPolicyUpdatePayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().update_task_policy(db, project_id=project_id, task_id=task_id, payload=payload)


@router.put("/projects/{project_id}/tasks/{task_id}/runtime-policy", response_model=BinarySecurityTaskDetailResponse)
def update_task_runtime_policy(
    project_id: str,
    task_id: str,
    payload: BinarySecurityTaskRuntimePolicyUpdatePayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().update_task_runtime_policy(db, project_id=project_id, task_id=task_id, payload=payload)


@router.get("/projects/{project_id}/tasks/{task_id}/timeline", response_model=BinarySecurityTimelineResponse)
def get_timeline(
    project_id: str,
    task_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=10, le=1000),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_timeline(
        db,
        project_id=project_id,
        task_id=task_id,
        page=page,
        page_size=page_size,
    )


@router.get("/projects/{project_id}/tasks/{task_id}/sync-events", response_model=BinarySecuritySyncEventPageResponse)
def get_sync_events(
    project_id: str,
    task_id: str,
    stage_name: Optional[str] = Query(None),
    downstream_service: Optional[str] = Query(None),
    operation: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    sync_status: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    has_error: Optional[bool] = Query(None),
    state_applied: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=10, le=1000),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_sync_events(
        db,
        project_id=project_id,
        task_id=task_id,
        stage_name=stage_name,
        downstream_service=downstream_service,
        operation=operation,
        event_type=event_type,
        sync_status=sync_status,
        outcome=outcome,
        has_error=has_error,
        state_applied=state_applied,
        search=search,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/projects/{project_id}/tasks/{task_id}/operations", response_model=BinarySecurityTaskOperationPageResponse)
def get_operations(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_operations(db, project_id=project_id, task_id=task_id)


@router.delete("/projects/{project_id}/tasks/{task_id}/timeline", response_model=BinarySecurityActionResponse)
def clear_timeline(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().clear_timeline(db, project_id=project_id, task_id=task_id)


@router.delete("/projects/{project_id}/tasks/{task_id}/sync-events", response_model=BinarySecurityActionResponse)
def clear_sync_events(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().clear_sync_events(db, project_id=project_id, task_id=task_id)


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


@router.post("/projects/{project_id}/tasks/{task_id}/finish-success", response_model=BinarySecurityActionResponse)
async def finish_task_as_success(
    project_id: str,
    task_id: str,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    requested_by = user.username or user.user_id or "unknown"
    return await get_task_manager().finish_task_as_success(
        db,
        project_id=project_id,
        task_id=task_id,
        requested_by=requested_by,
    )


@router.delete("/projects/{project_id}/tasks/{task_id}", response_model=BinarySecurityActionResponse)
async def delete_task(
    project_id: str,
    task_id: str,
    force: bool = Query(default=False),
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    requested_by = user.username or user.user_id or "unknown"
    return await get_task_manager().delete_task(
        db,
        project_id=project_id,
        task_id=task_id,
        force=force,
        requested_by=requested_by,
        request_source="api",
        request_token_type=user.token_type,
        request_machine_code=user.machine_code,
    )


@router.post("/projects/{project_id}/tasks/{task_id}/force-reset", response_model=BinarySecurityActionResponse)
async def force_reset_task(
    project_id: str,
    task_id: str,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    requested_by = user.username or user.user_id or "unknown"
    return await get_task_manager().force_reset_task_to_pending(
        db,
        project_id=project_id,
        task_id=task_id,
        requested_by=requested_by,
    )


@router.post("/projects/{project_id}/tasks/{task_id}/retry", response_model=BinarySecurityActionResponse)
def retry_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_task(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(
        task_id=task_id,
        operation_id=operation.id if operation else None,
        status="accepted",
        accepted=True,
        action="retry",
        message="任务已受理，后台正在清空并准备从第一阶段重新排队",
    )


@router.post("/projects/{project_id}/tasks/{task_id}/continue", response_model=BinarySecurityActionResponse)
async def continue_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = await get_task_manager().continue_task(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(
        task_id=task_id,
        operation_id=operation.id if operation else None,
        status="accepted",
        accepted=True,
        action="continue",
        message=f"任务已受理，后台正在准备从阶段 {operation.target_stage} 继续",
    )


@router.post("/projects/{project_id}/tasks/{task_id}/retry-failed-items", response_model=BinarySecurityActionResponse)
def retry_failed_items(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_failed_items(db, project_id=project_id, task_id=task_id)
    return BinarySecurityActionResponse(
        task_id=task_id,
        operation_id=operation.id if operation else None,
        status="accepted",
        accepted=True,
        action="retry_failed_items",
        message=f"任务已受理，后台正在准备从阶段 {operation.target_stage} 重试失败项",
    )


@router.post("/projects/{project_id}/tasks/{task_id}/stages/{stage_name}/retry", response_model=BinarySecurityActionResponse)
def retry_stage(
    project_id: str,
    task_id: str,
    stage_name: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_stage_full(db, project_id=project_id, task_id=task_id, stage_name=stage_name)
    return BinarySecurityActionResponse(task_id=task_id, operation_id=operation.id if operation else None, accepted=True, action="retry_stage_full", status="accepted", message=f"阶段 {stage_name} 的完全重试已受理")


@router.post("/projects/{project_id}/tasks/{task_id}/stages/{stage_name}/retry-failed-items", response_model=BinarySecurityActionResponse)
def retry_stage_failed_items(
    project_id: str,
    task_id: str,
    stage_name: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_stage_failed_items(db, project_id=project_id, task_id=task_id, stage_name=stage_name)
    return BinarySecurityActionResponse(task_id=task_id, operation_id=operation.id if operation else None, accepted=True, action="retry_stage_failed_items", status="accepted", message=f"阶段 {stage_name} 的失败项重试已受理")


@router.post("/projects/{project_id}/tasks/{task_id}/stages/{stage_name}/retry-full", response_model=BinarySecurityActionResponse)
def retry_stage_full(
    project_id: str,
    task_id: str,
    stage_name: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_stage_full(db, project_id=project_id, task_id=task_id, stage_name=stage_name)
    return BinarySecurityActionResponse(task_id=task_id, operation_id=operation.id if operation else None, accepted=True, action="retry_stage_full", status="accepted", message=f"阶段 {stage_name} 的完全重试已受理")


@router.post("/projects/{project_id}/tasks/{task_id}/stages/{stage_name}/archive/retry", response_model=BinarySecurityActionResponse)
def retry_stage_archive(
    project_id: str,
    task_id: str,
    stage_name: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_stage_archive_failed_items(db, project_id=project_id, task_id=task_id, stage_name=stage_name)
    return BinarySecurityActionResponse(
        task_id=task_id,
        operation_id=operation.id if operation else None,
        accepted=True,
        action="retry_archive_failed_items",
        status="accepted",
        message=f"阶段 {stage_name} 的归档失败项重试已受理",
    )


@router.post("/projects/{project_id}/tasks/{task_id}/stages/{stage_name}/archive/retry-failed-items", response_model=BinarySecurityActionResponse)
def retry_stage_archive_failed_items(
    project_id: str,
    task_id: str,
    stage_name: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_stage_archive_failed_items(db, project_id=project_id, task_id=task_id, stage_name=stage_name)
    return BinarySecurityActionResponse(
        task_id=task_id,
        operation_id=operation.id if operation else None,
        accepted=True,
        action="retry_archive_failed_items",
        status="accepted",
        message=f"阶段 {stage_name} 的归档失败项重试已受理",
    )


@router.post("/projects/{project_id}/tasks/{task_id}/stages/{stage_name}/archive/retry-full", response_model=BinarySecurityActionResponse)
def retry_stage_archive_full(
    project_id: str,
    task_id: str,
    stage_name: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    operation = get_task_manager().retry_stage_archive_full(db, project_id=project_id, task_id=task_id, stage_name=stage_name)
    return BinarySecurityActionResponse(
        task_id=task_id,
        operation_id=operation.id if operation else None,
        accepted=True,
        action="retry_archive_full",
        status="accepted",
        message=f"阶段 {stage_name} 的归档全量重试已受理",
    )


@router.post("/projects/{project_id}/tasks/{task_id}/archive-jobs/{archive_job_id}/retry", response_model=BinarySecurityActionResponse)
def retry_archive_job(
    project_id: str,
    task_id: str,
    archive_job_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    stage_name = get_task_manager().retry_archive_job(db, project_id=project_id, task_id=task_id, archive_job_id=archive_job_id)
    return BinarySecurityActionResponse(
        task_id=task_id,
        accepted=True,
        action="retry_archive_job",
        status="running",
        message=f"归档任务已重新排队，将在阶段 {stage_name} 完成后回写状态",
    )


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
        apply_state=True,
    )


@router.get("/projects/{project_id}/tasks/{task_id}/module-selection", response_model=BinarySecurityModuleSelectionResponse)
def get_module_selection(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_module_selection(db, project_id=project_id, task_id=task_id)


@router.get("/projects/{project_id}/tasks/{task_id}/module-report", response_model=BinarySecurityModuleReportDetailResponse)
def get_module_report(
    project_id: str,
    task_id: str,
    module_key: str = Query(..., min_length=1),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_module_report(db, project_id=project_id, task_id=task_id, module_key=module_key)


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


@router.get("/projects/{project_id}/tasks/{task_id}/entry-selection", response_model=BinarySecurityEntrySelectionResponse)
def get_entry_selection(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_entry_selection(db, project_id=project_id, task_id=task_id)


@router.post("/projects/{project_id}/tasks/{task_id}/entry-selection/confirm", response_model=BinarySecurityTaskDetailResponse)
def confirm_entry_selection(
    project_id: str,
    task_id: str,
    payload: BinarySecurityEntrySelectionConfirmPayload,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return get_task_manager().confirm_entry_selection(
        db,
        project_id=project_id,
        task_id=task_id,
        selected_entry_keys=payload.selected_entry_keys,
    )


@router.get("/config", response_model=BinarySecurityGlobalConfigResponse)
def get_config(
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().get_config(db)


@router.put("/config", response_model=BinarySecurityGlobalConfigResponse)
def put_config(
    payload: BinarySecurityGlobalConfigPayload,
    _: TokenUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return get_task_manager().save_config(db, payload)
