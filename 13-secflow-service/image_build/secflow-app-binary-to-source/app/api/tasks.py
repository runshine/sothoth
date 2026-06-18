"""B2S frontend-compatible API routes."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.build_info import build_service_meta
from app.exception import NotFoundError, UnauthorizedError, ValidationError
from app.observability import get_observability
from app.model import B2STask, B2STaskItem, get_db
from app.runtime_role import get_service_role
from app.schemas import ActionResponse, B2SAgentSessionRuntimeResponse, B2SArtifactContentResponse, B2SCacheBatchDeleteRequest, B2SCacheBatchDeleteResponse, B2SCacheDeleteResponse, B2SCacheDetailResponse, B2SCacheListResponse, B2SServiceConfig, B2STaskListStatsResponse, B2STaskTimelineResponse, LlmProviderListResponse, LlmProviderSummary, RerunRequest, RetryRequest, ReviewAnalyticsResponse, SessionFileResponse, SessionIndexResponse, TaskBatchDeleteItemResult, TaskBatchDeleteRequest, TaskBatchDeleteResponse, TaskCreate, TaskDetailResponse, TaskItemAdvancedResponse, TaskItemArtifactsResponse, TaskListResponse, TaskObservabilitySummary, TaskPrepareResponse, TaskRelationshipResponse, TaskResponse, TaskResultSummary, TokenUser
from app.service.auth import get_auth_service
from app.service.cache_service import get_cache_service
from app.service.configcenter import get_configcenter_client
from app.service.config_service import get_config_service
from app.service.project import get_project_service
from app.service.pi_cluster import PiClusterCacheState, PiWorkerActiveJobSnapshot, PiWorkerSnapshot, get_pi_cluster_monitor
from app.service.security import validate_project_id
from app.service.task_service import (
    build_task_detail,
    build_task_item_advanced,
    build_task_item_artifact_content,
    build_task_item_artifacts,
    build_task_item_review_analytics,
    build_task_item_observability_summary,
    build_task_observability_summary,
    build_task_list_stats,
    build_task_agent_session_runtime,
    build_task_relationship,
    build_task_result_summary,
    build_task_session_file,
    build_task_session_index,
    build_task_response,
    create_task,
    delete_task,
    delete_task_timeline_event,
    get_task_item_or_404,
    get_task_or_404,
    get_task_timeline,
    query_items,
    retry_task,
    rerun_task,
    sync_task,
    generate_task_id,
    terminate_task,
    clear_task_timeline,
)
from app.service.llm_provider import is_materialized_provider_ready

router = APIRouter(prefix="/api/app/binary-to-source", tags=["binary-to-source"])


class ConfigSaveRequest(BaseModel):
    config: dict


class PiWorkerCapacityResponse(BaseModel):
    worker_id: str
    url: str
    pod_name: str | None = None
    pod_ip: str | None = None
    healthy: bool
    max_concurrent_jobs: int
    running_jobs: int = 0
    queued_jobs: int = 0
    available_slots: int = 0
    pod_created_at: str | None = None
    pod_started_at: str | None = None
    pod_metrics_at: str | None = None
    pod_cpu_usage_millicores: int | None = None
    pod_memory_usage_bytes: int | None = None
    pod_cpu_request_millicores: int | None = None
    pod_memory_request_bytes: int | None = None
    pod_cpu_limit_millicores: int | None = None
    pod_memory_limit_bytes: int | None = None
    source: str = "capacity"
    error: str | None = None
    active_jobs: list["PiWorkerActiveJobResponse"] = Field(default_factory=list)


class PiWorkerActiveJobResponse(BaseModel):
    pi_job_id: str
    status: str
    phase: str | None = None
    worker_id: str | None = None
    elf_path: str | None = None
    elf_name: str | None = None
    task_id: str | None = None
    task_name: str | None = None
    task_origin_type: str | None = None
    parent_task_id: str | None = None
    sequence_no: int | None = None
    item_id: str | None = None
    current_batch: int | None = None
    current_attempt: int | None = None
    current_function: str | None = None
    started_at: str | None = None
    updated_at: str | None = None
    mapped: bool = False
    mapping_reason: str = "orphan_pi_job"


class PiClusterCapacityResponse(BaseModel):
    worker_count: int = 0
    total_capacity: int = 0
    running_jobs: int = 0
    queued_jobs: int = 0
    available_slots: int = 0
    updated_at: str | None = None
    snapshot_refreshed_at: str | None = None
    snapshot_expires_at: str | None = None
    snapshot_stale: bool = True
    snapshot_last_error: str | None = None
    workers: list[PiWorkerCapacityResponse]


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
    return {
        "status": "ok",
        "service": "secflow-app-binary-to-source",
        "role": get_service_role(),
        **build_service_meta(),
    }


@router.get("/ready")
async def ready_check():
    if not is_materialized_provider_ready():
        raise HTTPException(status_code=503, detail={"status": "not_ready", "reason": "llm_provider_not_materialized"})
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


async def get_current_user_context(authorization: Optional[str] = Header(None)) -> TokenUser:
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization格式错误，应为 Bearer <token>")
    token = parts[1]
    user = await get_auth_service().validate_token(token)
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


@router.get("/config", response_model=B2SServiceConfig)
async def get_b2s_config(
    _: TokenUser = Depends(get_current_user_context),
    db: Session = Depends(get_db),
):
    payload = get_config_service().get_config(db)
    payload["effective_llm_provider"] = await _effective_llm_provider_summary(payload.get("llm_provider_key"))
    return B2SServiceConfig(**payload)


@router.put("/config", response_model=B2SServiceConfig)
async def save_b2s_config(
    payload: ConfigSaveRequest,
    _: TokenUser = Depends(get_current_user_context),
    db: Session = Depends(get_db),
):
    provider_key = str(payload.config.get("llm_provider_key") or "").strip()
    if provider_key:
        await get_configcenter_client().get_llm_provider(provider_key)
    saved = get_config_service().save_config(db, payload.config)
    saved["effective_llm_provider"] = await _effective_llm_provider_summary(saved.get("llm_provider_key"))
    return B2SServiceConfig(**saved)


@router.get("/projects/{project_id}/cache", response_model=B2SCacheListResponse)
def list_b2s_cache(
    project_id: str,
    limit: int = Query(50, ge=10, le=1000),
    offset: int = Query(0, ge=0),
    include_all_projects: bool = Query(False),
    mode: Optional[str] = Query(None),
    status: Optional[str] = Query("ready"),
    cache_key: Optional[str] = Query(None),
    elf_basename: Optional[str] = Query(None),
    source_task_id: Optional[str] = Query(None),
    source_item_id: Optional[str] = Query(None),
    has_hits: Optional[str] = Query(None),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    payload = get_cache_service().list_cache_entries(
        db,
        project_id=project_id,
        limit=limit,
        offset=offset,
        include_all_projects=include_all_projects,
        mode=mode,
        status=status,
        cache_key=cache_key,
        elf_basename=elf_basename,
        source_task_id=source_task_id,
        source_item_id=source_item_id,
        has_hits=has_hits,
    )
    return B2SCacheListResponse(**payload)


@router.get("/projects/{project_id}/cache/{cache_key}", response_model=B2SCacheDetailResponse)
def get_b2s_cache_detail(
    project_id: str,
    cache_key: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    del project_id
    try:
        payload = get_cache_service().get_cache_entry_detail(db, cache_key)
    except ValueError as exc:
        raise ValidationError(str(exc))
    if not payload:
        raise NotFoundError("缓存条目不存在")
    return B2SCacheDetailResponse(**payload)


@router.delete("/projects/{project_id}/cache/{cache_key}", response_model=B2SCacheDeleteResponse)
def delete_b2s_cache_entry(
    project_id: str,
    cache_key: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    del project_id
    try:
        result = get_cache_service().delete_cache_entry(db, cache_key)
    except ValueError as exc:
        raise ValidationError(str(exc))
    return B2SCacheDeleteResponse(
        status=result.status,
        cache_key=result.cache_key,
        deleted=result.deleted,
        message=result.message,
    )


@router.post("/projects/{project_id}/cache/batch-delete", response_model=B2SCacheBatchDeleteResponse)
def batch_delete_b2s_cache_entries(
    project_id: str,
    payload: B2SCacheBatchDeleteRequest,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    del project_id
    try:
        result = get_cache_service().batch_delete_cache_entries(db, payload.cache_keys)
    except ValueError as exc:
        raise ValidationError(str(exc))
    return B2SCacheBatchDeleteResponse(**result)


@router.get("/projects/{project_id}/tasks", response_model=TaskListResponse)
def list_tasks(
    project_id: str,
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    parent_task_id: Optional[str] = Query(None),
    parent_stage_item_id: Optional[str] = Query(None),
    task_origin_type: Optional[str] = Query(None),
    input_filename: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    limit: int = Query(50, ge=10, le=1000),
    offset: int = Query(0, ge=0),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    query = db.query(B2STask).filter(B2STask.project_id == project_id)
    if status:
        query = query.filter(B2STask.status == status)
    if parent_task_id:
        query = query.filter(B2STask.parent_task_id == parent_task_id)
    if parent_stage_item_id:
        query = query.filter(B2STask.parent_stage_item_id == parent_stage_item_id)
    if task_origin_type:
        query = query.filter(B2STask.task_origin_type == task_origin_type)
    search_text = str(search or "").strip()
    if search_text:
        escaped = search_text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.filter(or_(
            B2STask.id.ilike(pattern, escape="\\"),
            B2STask.name.ilike(pattern, escape="\\"),
            B2STask.parent_task_id.ilike(pattern, escape="\\"),
            B2STask.parent_task_type.ilike(pattern, escape="\\"),
            B2STask.parent_stage_name.ilike(pattern, escape="\\"),
            B2STask.parent_stage_item_id.ilike(pattern, escape="\\"),
            B2STask.origin_label.ilike(pattern, escape="\\"),
            B2STask.parent_task_display.ilike(pattern, escape="\\"),
        ))
    filename_text = str(input_filename or "").strip()
    if filename_text:
        escaped = filename_text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.filter(
            B2STask.id.in_(
                db.query(B2STaskItem.task_id)
                .filter(B2STaskItem.task_id == B2STask.id)
                .filter(B2STaskItem.elf_path.ilike(pattern, escape="\\"))
            )
        )
    total = query.count()
    sort_column = {
        "created_at": B2STask.created_at,
        "updated_at": B2STask.updated_at,
        "status": B2STask.status,
        "name": B2STask.name,
    }.get(sort_by, B2STask.created_at)
    order_expr = sort_column.asc() if str(sort_order or "").lower() == "asc" else sort_column.desc()
    tasks = query.order_by(order_expr, B2STask.created_at.desc()).offset(offset).limit(limit).all()
    items = [build_task_response(db, task) for task in tasks]
    return TaskListResponse(total=total, items=items)


@router.get("/projects/{project_id}/tasks/stats", response_model=B2STaskListStatsResponse)
def get_task_stats(
    project_id: str,
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    parent_task_id: Optional[str] = Query(None),
    parent_stage_item_id: Optional[str] = Query(None),
    task_origin_type: Optional[str] = Query(None),
    input_filename: Optional[str] = Query(None),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    query = db.query(B2STask).filter(B2STask.project_id == project_id)
    if status:
        query = query.filter(B2STask.status == status)
    if parent_task_id:
        query = query.filter(B2STask.parent_task_id == parent_task_id)
    if parent_stage_item_id:
        query = query.filter(B2STask.parent_stage_item_id == parent_stage_item_id)
    if task_origin_type:
        query = query.filter(B2STask.task_origin_type == task_origin_type)
    search_text = str(search or "").strip()
    if search_text:
        escaped = search_text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.filter(or_(
            B2STask.id.ilike(pattern, escape="\\"),
            B2STask.name.ilike(pattern, escape="\\"),
            B2STask.parent_task_id.ilike(pattern, escape="\\"),
            B2STask.parent_task_type.ilike(pattern, escape="\\"),
            B2STask.parent_stage_name.ilike(pattern, escape="\\"),
            B2STask.parent_stage_item_id.ilike(pattern, escape="\\"),
            B2STask.origin_label.ilike(pattern, escape="\\"),
            B2STask.parent_task_display.ilike(pattern, escape="\\"),
        ))
    filename_text = str(input_filename or "").strip()
    if filename_text:
        escaped = filename_text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.filter(
            B2STask.id.in_(
                db.query(B2STaskItem.task_id)
                .filter(B2STaskItem.task_id == B2STask.id)
                .filter(B2STaskItem.elf_path.ilike(pattern, escape="\\"))
            )
        )
    tasks = query.all()
    return build_task_list_stats(db, tasks)


@router.get("/projects/{project_id}/pi-cluster", response_model=PiClusterCapacityResponse)
async def get_pi_cluster_capacity(
    project_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    return _build_pi_cluster_capacity_response(await get_pi_cluster_monitor().get_cached_state(), db=db, project_id=project_id)


@router.get("/pi-cluster", response_model=PiClusterCapacityResponse)
async def get_global_pi_cluster_capacity(
    _: TokenUser = Depends(get_current_user_context),
    db: Session = Depends(get_db),
):
    return _build_pi_cluster_capacity_response(await get_pi_cluster_monitor().get_cached_state(), db=db, project_id=None)


def _build_pi_cluster_capacity_response(cache_state: PiClusterCacheState, *, db: Session, project_id: str | None) -> PiClusterCapacityResponse:
    get_observability().prom.inc("pi_cluster_cache_request", stale=str(cache_state.stale).lower())
    snapshot = cache_state.snapshot
    active_jobs_by_worker, worker_job_errors = _load_cached_worker_active_jobs(snapshot.workers)
    item_by_job_id, task_by_id = _load_pi_job_item_mapping(
        db,
        project_id=project_id,
        pi_job_ids=[
            job.pi_job_id
            for jobs in active_jobs_by_worker.values()
            for job in jobs
            if job.pi_job_id
        ],
    )
    workers = []
    for worker in snapshot.workers:
        detail_error = worker_job_errors.get(worker.worker_id)
        active_jobs = [
            _build_active_job_response(job, item_by_job_id=item_by_job_id, task_by_id=task_by_id)
            for job in active_jobs_by_worker.get(worker.worker_id, [])
        ] if worker.healthy and not detail_error else []
        workers.append(PiWorkerCapacityResponse(
            worker_id=worker.worker_id,
            url=worker.url,
            pod_name=worker.pod_name,
            pod_ip=worker.pod_ip,
            healthy=worker.healthy,
            max_concurrent_jobs=worker.max_concurrent_jobs,
            running_jobs=worker.running_jobs,
            queued_jobs=worker.queued_jobs,
            available_slots=max(0, worker.max_concurrent_jobs - worker.running_jobs) if worker.healthy else 0,
            pod_created_at=worker.pod_created_at,
            pod_started_at=worker.pod_started_at,
            pod_metrics_at=worker.pod_metrics_at,
            pod_cpu_usage_millicores=worker.pod_cpu_usage_millicores,
            pod_memory_usage_bytes=worker.pod_memory_usage_bytes,
            pod_cpu_request_millicores=worker.pod_cpu_request_millicores,
            pod_memory_request_bytes=worker.pod_memory_request_bytes,
            pod_cpu_limit_millicores=worker.pod_cpu_limit_millicores,
            pod_memory_limit_bytes=worker.pod_memory_limit_bytes,
            source=worker.source,
            error=_merge_worker_error(worker.error, detail_error),
            active_jobs=active_jobs,
        ))
    return PiClusterCapacityResponse(
        worker_count=snapshot.worker_count,
        total_capacity=snapshot.total_capacity,
        running_jobs=snapshot.running_jobs,
        queued_jobs=snapshot.queued_jobs,
        available_slots=snapshot.available_slots,
        updated_at=cache_state.refreshed_at or snapshot.updated_at,
        snapshot_refreshed_at=cache_state.refreshed_at or snapshot.updated_at,
        snapshot_expires_at=cache_state.expires_at,
        snapshot_stale=cache_state.stale,
        snapshot_last_error=cache_state.last_error,
        workers=workers,
    )


def _load_cached_worker_active_jobs(workers: list[PiWorkerSnapshot]) -> tuple[dict[str, list[PiWorkerActiveJobSnapshot]], dict[str, str]]:
    active_jobs_by_worker: dict[str, list[PiWorkerActiveJobSnapshot]] = {}
    worker_errors: dict[str, str] = {}
    for worker in workers:
        cached_jobs = getattr(worker, "active_jobs", None)
        if isinstance(cached_jobs, list):
            active_jobs_by_worker[worker.worker_id] = [
                job for job in cached_jobs if isinstance(job, PiWorkerActiveJobSnapshot)
            ]
        else:
            active_jobs_by_worker[worker.worker_id] = []
        if worker.error and "active_jobs=" in worker.error:
            worker_errors[worker.worker_id] = worker.error.split("active_jobs=", 1)[-1].strip()
    return active_jobs_by_worker, worker_errors


def _load_pi_job_item_mapping(db: Session, *, project_id: str | None, pi_job_ids: list[str]) -> tuple[dict[str, B2STaskItem], dict[str, B2STask]]:
    normalized_job_ids = sorted({str(job_id or "").strip() for job_id in pi_job_ids if str(job_id or "").strip()})
    if not normalized_job_ids:
        return {}, {}
    query = db.query(B2STaskItem).filter(B2STaskItem.pi_job_id.in_(normalized_job_ids))
    if str(project_id or "").strip():
        query = query.filter(B2STaskItem.project_id == project_id)
    items = query.all()
    item_by_job_id = {
        str(item.pi_job_id or "").strip(): item
        for item in items
        if str(item.pi_job_id or "").strip()
    }
    task_ids = sorted({str(item.task_id or "").strip() for item in items if str(item.task_id or "").strip()})
    tasks = db.query(B2STask).filter(B2STask.id.in_(task_ids)).all() if task_ids else []
    task_by_id = {task.id: task for task in tasks}
    return item_by_job_id, task_by_id


def _build_active_job_response(
    job: PiWorkerActiveJobSnapshot,
    *,
    item_by_job_id: dict[str, B2STaskItem],
    task_by_id: dict[str, B2STask],
) -> PiWorkerActiveJobResponse:
    item = item_by_job_id.get(job.pi_job_id)
    task = task_by_id.get(item.task_id) if item is not None and str(item.task_id or "").strip() else None
    elf_path = item.elf_path if item is not None else job.elf_path
    elf_name = Path(str(elf_path or job.elf_name or "")).name or job.elf_name
    return PiWorkerActiveJobResponse(
        pi_job_id=job.pi_job_id,
        status=job.status,
        phase=job.phase,
        worker_id=job.worker_id,
        elf_path=elf_path,
        elf_name=elf_name or None,
        task_id=task.id if task is not None else None,
        task_name=(str(task.name or "").strip() or task.id) if task is not None else None,
        task_origin_type=task.task_origin_type if task is not None else None,
        parent_task_id=task.parent_task_id if task is not None else None,
        sequence_no=item.sequence_no if item is not None else None,
        item_id=item.id if item is not None else None,
        current_batch=job.current_batch,
        current_attempt=job.current_attempt,
        current_function=job.current_function,
        started_at=job.started_at,
        updated_at=job.updated_at,
        mapped=item is not None and task is not None,
        mapping_reason="matched_item" if item is not None and task is not None else "orphan_pi_job",
    )


def _merge_worker_error(worker_error: str | None, detail_error: str | None) -> str | None:
    left = str(worker_error or "").strip()
    right = str(detail_error or "").strip()
    if left and right:
        return f"{left}; active_jobs={right}"
    return left or right or None


@router.post("/projects/{project_id}/tasks/prepare", response_model=TaskPrepareResponse)
def prepare_b2s_task(
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
    return await create_task(db, project_id, payload, user)


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=TaskDetailResponse)
def get_b2s_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    return build_task_detail(db, task)


@router.get("/projects/{project_id}/tasks/{task_id}/timeline", response_model=B2STaskTimelineResponse)
def get_b2s_task_timeline(
    project_id: str,
    task_id: str,
    include_internal: bool = Query(False),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    return get_task_timeline(db, task, include_internal=include_internal)


@router.delete("/projects/{project_id}/tasks/{task_id}/timeline", response_model=ActionResponse)
def clear_b2s_task_timeline(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    deleted_event_count = clear_task_timeline(db, task)
    db.commit()
    return ActionResponse(status="ok", task_id=task_id, message="任务时间线已清空", deleted_event_count=deleted_event_count)


@router.delete("/projects/{project_id}/tasks/{task_id}/timeline/{event_id}", response_model=ActionResponse)
def delete_b2s_task_timeline_event(
    project_id: str,
    task_id: str,
    event_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    deleted_event_count = delete_task_timeline_event(db, task, event_id)
    db.commit()
    return ActionResponse(status="ok", task_id=task_id, message="事件已删除", deleted_event_count=deleted_event_count)


@router.get("/projects/{project_id}/tasks/{task_id}/sessions", response_model=SessionIndexResponse)
def get_b2s_task_sessions(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    return build_task_session_index(query_items(db, task.id))


@router.get("/projects/{project_id}/tasks/{task_id}/sessions/file", response_model=SessionFileResponse)
def get_b2s_task_session_file(
    project_id: str,
    task_id: str,
    path: str = Query(...),
    item_id: str | None = Query(None),
    node_id: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(512 * 1024, ge=1, le=512 * 1024),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    items = query_items(db, task.id)
    return build_task_session_file(items, path, offset=offset, limit=limit, item_id=item_id, node_id=node_id)


@router.get("/projects/{project_id}/tasks/{task_id}/agent-sessions/runtime", response_model=B2SAgentSessionRuntimeResponse)
def get_b2s_task_agent_sessions_runtime(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    items = query_items(db, task.id)
    return build_task_agent_session_runtime(items)


@router.get("/projects/{project_id}/tasks/{task_id}/relationships", response_model=TaskRelationshipResponse)
def get_b2s_task_relationships(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    items = query_items(db, task.id)
    return build_task_relationship(items)


@router.get("/projects/{project_id}/tasks/{task_id}/result", response_model=TaskResultSummary)
def get_b2s_task_result(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    items = query_items(db, task.id)
    return build_task_result_summary(items)


@router.get("/projects/{project_id}/tasks/{task_id}/observability", response_model=TaskObservabilitySummary)
def get_b2s_task_observability(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    items = query_items(db, task.id)
    return build_task_observability_summary(items)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/observability", response_model=TaskObservabilitySummary)
def get_b2s_task_item_observability(
    project_id: str,
    task_id: str,
    item_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_observability_summary(item)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/advanced", response_model=TaskItemAdvancedResponse)
def get_b2s_task_item_advanced(
    project_id: str,
    task_id: str,
    item_id: str,
    include_content: bool = Query(True),
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_advanced(item, include_content=include_content)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/artifacts", response_model=TaskItemArtifactsResponse)
def get_b2s_task_item_artifacts(
    project_id: str,
    task_id: str,
    item_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_artifacts(item)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/artifacts/{artifact_id}/content", response_model=B2SArtifactContentResponse)
def get_b2s_task_item_artifact_content(
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
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_artifact_content(item, artifact_id, offset=offset, limit=limit)


@router.get("/projects/{project_id}/tasks/{task_id}/items/{item_id}/review-analytics", response_model=ReviewAnalyticsResponse)
def get_b2s_task_item_review_analytics(
    project_id: str,
    task_id: str,
    item_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    item = get_task_item_or_404(db, task, item_id)
    return build_task_item_review_analytics(item)


@router.post("/projects/{project_id}/tasks/{task_id}/terminate", response_model=ActionResponse)
async def terminate_b2s_task(
    project_id: str,
    task_id: str,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await terminate_task(db, task, user)
    return ActionResponse(status="ok", task_id=task_id, message="任务已取消")


@router.delete("/projects/{project_id}/tasks/{task_id}", response_model=ActionResponse)
async def delete_b2s_task(
    project_id: str,
    task_id: str,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    deleted_event_count = int((await delete_task(db, task)) or 0)
    return ActionResponse(status="ok", task_id=task_id, message="任务及文件已删除", deleted_event_count=deleted_event_count)


@router.post("/projects/{project_id}/tasks/batch-delete", response_model=TaskBatchDeleteResponse)
async def batch_delete_b2s_tasks(
    project_id: str,
    payload: TaskBatchDeleteRequest,
    _: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    results: list[TaskBatchDeleteItemResult] = []
    seen: set[str] = set()
    task_ids: list[str] = []
    for task_id in payload.task_ids:
        if task_id in seen:
            continue
        seen.add(task_id)
        task_ids.append(task_id)
    for task_id in task_ids:
        task = db.query(B2STask).filter(B2STask.project_id == project_id, B2STask.id == task_id).first()
        if not task:
            results.append(TaskBatchDeleteItemResult(task_id=task_id, status="failed", message="任务不存在"))
            continue
        try:
            deleted_event_count = int((await delete_task(db, task)) or 0)
            results.append(TaskBatchDeleteItemResult(task_id=task_id, status="ok", message="任务及文件已删除", deleted_event_count=deleted_event_count))
        except Exception as exc:
            db.rollback()
            results.append(TaskBatchDeleteItemResult(task_id=task_id, status="failed", message=str(exc)))
    deleted_count = sum(1 for item in results if item.status == "ok")
    failed_count = len(results) - deleted_count
    deleted_event_count = sum(int(item.deleted_event_count or 0) for item in results)
    return TaskBatchDeleteResponse(
        status="ok" if failed_count == 0 else "partial",
        deleted_count=deleted_count,
        failed_count=failed_count,
        deleted_event_count=deleted_event_count,
        results=results,
    )


@router.post("/projects/{project_id}/tasks/{task_id}/rerun", response_model=ActionResponse)
async def rerun_b2s_task(
    project_id: str,
    task_id: str,
    payload: RerunRequest | None = None,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    if payload and (payload.clean_output is not None or payload.cancel_running is not None):
        # Keep the request body backward-compatible for older clients, but the
        # backend no longer allows changing rerun semantics.
        pass
    await rerun_task(db, task, user, clean_output=True, cancel_running=True)
    return ActionResponse(status="ok", task_id=task_id, message="任务已清空output并从头重跑")


@router.post("/projects/{project_id}/tasks/{task_id}/retry", response_model=ActionResponse)
async def retry_b2s_task(
    project_id: str,
    task_id: str,
    payload: RetryRequest,
    user: TokenUser = Depends(get_current_context),
    db: Session = Depends(get_db),
):
    task = get_task_or_404(db, project_id, task_id)
    await retry_task(db, task, user, payload.item_ids)
    return ActionResponse(status="ok", task_id=task_id, message="任务已重新提交")
