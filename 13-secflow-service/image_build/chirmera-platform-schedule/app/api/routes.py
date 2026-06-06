"""API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.build_info import build_service_meta
from app.exception import UnauthorizedError
from app.model import get_db
from app.schemas import (
    ManualTriggerPayload,
    MessageResponse,
    JobRuntimeResponse,
    RuntimeOverviewResponse,
    ScheduleExecutionListResponse,
    ScheduleExecutionResponse,
    ScheduleJobCreate,
    ScheduleJobListResponse,
    ScheduleJobResponse,
    ScheduleJobUpdate,
    TokenUser,
    VirtualKeyCreate,
    VirtualKeyCreateResponse,
    VirtualKeyListResponse,
    VirtualKeyResponse,
)
from app.service.auth import get_auth_service
from app.service.litellm import get_virtual_key_manager
from app.service.project import get_project_service
from app.service.runtime_state import collect_liveness, collect_readiness
from app.service.schedule_manager import get_schedule_manager
from app.service.security import validate_project_id


router = APIRouter(prefix="/api/chirmera-platform-schedule", tags=["chirmera-platform-schedule"])


def _token_from_header(authorization: Optional[str]) -> str:
    if not authorization:
        raise UnauthorizedError("缺少 Authorization 头")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization 格式错误，应为 Bearer <token>")
    return parts[1]


async def get_current_context(project_id: str, authorization: Optional[str] = Header(None)) -> TokenUser:
    validate_project_id(project_id)
    token = _token_from_header(authorization)
    user = await get_auth_service().validate_token(token)
    await get_project_service().require_access(token, project_id)
    return TokenUser(
        user_id=str(user.get("user_id") or user.get("id") or ""),
        username=user.get("username") or user.get("name"),
        token_type=user.get("token_type"),
    )


@router.get("/health")
async def health_check():
    return {**build_service_meta(), **collect_liveness()}


@router.get("/ready")
async def ready_check():
    payload = await collect_readiness()
    return JSONResponse(status_code=200 if payload["status"] == "ready" else 503, content=payload)


@router.get("/projects/{project_id}/jobs", response_model=ScheduleJobListResponse)
def list_jobs(project_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    total, items = get_schedule_manager().list_jobs(db, project_id)
    return ScheduleJobListResponse(total=total, items=[ScheduleJobResponse.model_validate(item, from_attributes=True) for item in items])


@router.post("/projects/{project_id}/jobs", response_model=ScheduleJobResponse)
def create_job(project_id: str, payload: ScheduleJobCreate, user: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    actor = user.username or user.user_id or "unknown"
    job = get_schedule_manager().create_job(db, project_id, payload, actor)
    return ScheduleJobResponse.model_validate(job, from_attributes=True)


@router.get("/projects/{project_id}/jobs/{job_id}", response_model=ScheduleJobResponse)
def get_job(project_id: str, job_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    job = get_schedule_manager().get_job_or_404(db, project_id, job_id)
    return ScheduleJobResponse.model_validate(job, from_attributes=True)


@router.put("/projects/{project_id}/jobs/{job_id}", response_model=ScheduleJobResponse)
def update_job(project_id: str, job_id: str, payload: ScheduleJobUpdate, user: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    actor = user.username or user.user_id or "unknown"
    job = get_schedule_manager().update_job(db, project_id, job_id, payload, actor)
    return ScheduleJobResponse.model_validate(job, from_attributes=True)


@router.post("/projects/{project_id}/jobs/{job_id}/enable", response_model=ScheduleJobResponse)
def enable_job(project_id: str, job_id: str, user: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    actor = user.username or user.user_id or "unknown"
    job = get_schedule_manager().set_enabled(db, project_id, job_id, True, actor)
    return ScheduleJobResponse.model_validate(job, from_attributes=True)


@router.post("/projects/{project_id}/jobs/{job_id}/disable", response_model=ScheduleJobResponse)
def disable_job(project_id: str, job_id: str, user: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    actor = user.username or user.user_id or "unknown"
    job = get_schedule_manager().set_enabled(db, project_id, job_id, False, actor)
    return ScheduleJobResponse.model_validate(job, from_attributes=True)


@router.post("/projects/{project_id}/jobs/{job_id}/trigger", response_model=ScheduleExecutionResponse)
async def trigger_job(
    project_id: str,
    job_id: str,
    payload: ManualTriggerPayload,
    _: TokenUser = Depends(get_current_context),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    token = _token_from_header(authorization)
    execution = await get_schedule_manager().trigger_job(db, project_id, job_id, token, payload.trigger_source)
    return ScheduleExecutionResponse.model_validate(execution, from_attributes=True)


@router.get("/projects/{project_id}/jobs/{job_id}/executions", response_model=ScheduleExecutionListResponse)
def list_job_executions(project_id: str, job_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    total, items = get_schedule_manager().list_executions(db, project_id, job_id)
    return ScheduleExecutionListResponse(total=total, items=[ScheduleExecutionResponse.model_validate(item, from_attributes=True) for item in items])


@router.get("/projects/{project_id}/executions/{execution_id}", response_model=ScheduleExecutionResponse)
def get_execution(project_id: str, execution_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    execution = get_schedule_manager().get_execution_or_404(db, project_id, execution_id)
    return ScheduleExecutionResponse.model_validate(execution, from_attributes=True)


@router.get("/runtime/overview", response_model=RuntimeOverviewResponse)
async def runtime_overview():
    return RuntimeOverviewResponse.model_validate(await get_schedule_manager().runtime_overview())


@router.get("/metrics")
async def metrics():
    return PlainTextResponse(await get_schedule_manager().metrics_text())


@router.get("/projects/{project_id}/jobs/{job_id}/runtime", response_model=JobRuntimeResponse)
def job_runtime(project_id: str, job_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    return JobRuntimeResponse.model_validate(get_schedule_manager().job_runtime(db, project_id, job_id))


@router.get("/projects/{project_id}/keys", response_model=VirtualKeyListResponse)
def list_keys(project_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    items = get_virtual_key_manager().list_keys(db, project_id)
    return VirtualKeyListResponse(total=len(items), items=[VirtualKeyResponse.model_validate(item, from_attributes=True) for item in items])


@router.post("/projects/{project_id}/keys", response_model=VirtualKeyCreateResponse)
async def create_key(project_id: str, payload: VirtualKeyCreate, user: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    actor = user.username or user.user_id or "unknown"
    record, plain_text_key = await get_virtual_key_manager().create_key(db, project_id, payload, actor)
    response = VirtualKeyCreateResponse.model_validate(record, from_attributes=True)
    response.plain_text_key = plain_text_key
    return response


@router.get("/projects/{project_id}/keys/{key_id}", response_model=VirtualKeyResponse)
def get_key(project_id: str, key_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    record = get_virtual_key_manager().get_key_or_404(db, project_id, key_id)
    return VirtualKeyResponse.model_validate(record, from_attributes=True)


@router.post("/projects/{project_id}/keys/{key_id}/disable", response_model=VirtualKeyResponse)
async def disable_key(project_id: str, key_id: str, user: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    actor = user.username or user.user_id or "unknown"
    record = await get_virtual_key_manager().disable_key(db, project_id, key_id, actor)
    return VirtualKeyResponse.model_validate(record, from_attributes=True)


@router.post("/projects/{project_id}/keys/{key_id}/sync", response_model=VirtualKeyResponse)
async def sync_key(project_id: str, key_id: str, user: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    actor = user.username or user.user_id or "unknown"
    record = await get_virtual_key_manager().sync_key(db, project_id, key_id, actor)
    return VirtualKeyResponse.model_validate(record, from_attributes=True)


@router.get("/projects/{project_id}/keys/{key_id}/events")
def list_key_events(project_id: str, key_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    items = get_virtual_key_manager().list_events(db, project_id, key_id)
    return {"total": len(items), "items": [item.payload | {"id": item.id, "event_type": item.event_type, "created_at": item.created_at.isoformat()} for item in items]}


@router.get("/projects/{project_id}/executions/{execution_id}/events")
def list_execution_events(project_id: str, execution_id: str, _: TokenUser = Depends(get_current_context), db: Session = Depends(get_db)):
    get_schedule_manager().get_execution_or_404(db, project_id, execution_id)
    items = get_schedule_manager().list_execution_events(db, execution_id)
    return {"total": len(items), "items": [{"id": item.id, "event_type": item.event_type, "message": item.message, "payload": item.payload, "created_at": item.created_at.isoformat()} for item in items]}


@router.get("/", response_model=MessageResponse)
def root():
    return MessageResponse(message="chirmera-platform-schedule")
