from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from app.model import get_db
from app.schemas import (
    EvolutionApplyResponse,
    EvolutionExperimentCreateRequest,
    EvolutionMemoryModePatchRequest,
    EvolutionMemoryModeResponse,
    EvolutionPreviewRequest,
    EvolutionPreviewResponse,
    EvolutionTaskCreateRequest,
    EvolutionTaskDetail,
    EvolutionTaskRoundResponse,
    EvolutionTaskSummary,
    SuccessResponse,
)
from app.service.auth import get_auth_service
from app.service.project import get_project_service
from app.service.scheduler import get_scheduler_service
from app.service.task_service import get_task_service

router = APIRouter(prefix="/api/app/binary-evolution", tags=["binary-evolution"])


async def get_subject(authorization: str | None = Header(default=None)) -> tuple[dict[str, Any], str]:
    return await get_auth_service().validate_human_authorization(authorization)


@router.get("/health")
async def health():
    return get_scheduler_service().health_payload()


@router.get("/ready")
async def ready():
    return {"status": "ready", "service": "secflow-app-binary-evolution-center"}


@router.post("/projects/{project_id}/tasks/preview", response_model=EvolutionPreviewResponse)
async def preview_task(
    project_id: str,
    payload: EvolutionPreviewRequest,
    subject=Depends(get_subject),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return await get_task_service().preview(project_id=project_id, payload=payload, token=token)


@router.post("/projects/{project_id}/tasks", response_model=EvolutionTaskSummary)
async def create_task(
    project_id: str,
    payload: EvolutionTaskCreateRequest,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return await get_task_service().create_task(db, project_id=project_id, payload=payload, principal=principal, token=token)


@router.post("/evolution/experiments", response_model=EvolutionTaskSummary)
async def create_experiment(
    payload: EvolutionExperimentCreateRequest,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await get_project_service().ensure_project_access(payload.project_id, token)
    return await get_task_service().create_experiment(db, payload=payload, principal=principal, token=token)


@router.post("/evolution/experiments/{task_id}/start", response_model=EvolutionTaskSummary)
async def start_experiment(
    task_id: str,
    project_id: str | None = None,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    project_id = project_id or get_task_service().task_project_id_or_404(db, task_id)
    await get_project_service().ensure_project_access(project_id, token)
    return get_task_service().start_task(db, project_id=project_id, task_id=task_id)


@router.get("/evolution/experiments/{task_id}", response_model=EvolutionTaskDetail)
async def get_experiment(
    task_id: str,
    project_id: str | None = None,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    project_id = project_id or get_task_service().task_project_id_or_404(db, task_id)
    await get_project_service().ensure_project_access(project_id, token)
    return get_task_service().get_task(db, project_id, task_id)


@router.post("/evolution/experiments/{task_id}/promote", response_model=EvolutionApplyResponse)
async def promote_experiment(
    task_id: str,
    project_id: str | None = None,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    project_id = project_id or get_task_service().task_project_id_or_404(db, task_id)
    await get_project_service().ensure_project_access(project_id, token)
    return await get_task_service().promote_task(db, project_id=project_id, task_id=task_id, token=token)


@router.get("/evolution/projects/{project_id}/memory-mode", response_model=EvolutionMemoryModeResponse)
async def get_project_memory_mode(
    project_id: str,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return get_task_service().get_memory_mode(db, project_id)


@router.patch("/evolution/projects/{project_id}/memory-mode", response_model=EvolutionMemoryModeResponse)
async def patch_project_memory_mode(
    project_id: str,
    payload: EvolutionMemoryModePatchRequest,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return get_task_service().save_memory_mode(db, project_id=project_id, payload=payload)


@router.get("/projects/{project_id}/tasks", response_model=list[EvolutionTaskSummary])
async def list_tasks(
    project_id: str,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return get_task_service().list_tasks(db, project_id)


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=EvolutionTaskDetail)
async def get_task(
    project_id: str,
    task_id: str,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return get_task_service().get_task(db, project_id, task_id)


@router.get("/projects/{project_id}/tasks/{task_id}/rounds", response_model=list[EvolutionTaskRoundResponse])
async def get_rounds(
    project_id: str,
    task_id: str,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return get_task_service().list_rounds(db, project_id, task_id)


@router.post("/projects/{project_id}/tasks/{task_id}/apply", response_model=EvolutionApplyResponse)
async def apply_task(
    project_id: str,
    task_id: str,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    return await get_task_service().apply_task(db, project_id=project_id, task_id=task_id, token=token)


@router.delete("/projects/{project_id}/tasks/{task_id}", response_model=SuccessResponse)
async def delete_task(
    project_id: str,
    task_id: str,
    subject=Depends(get_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await get_project_service().ensure_project_access(project_id, token)
    await get_task_service().delete_task(db, project_id=project_id, task_id=task_id, token=token)
    return SuccessResponse(message="task deleted")
