"""Task endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import ensure_project_access, get_current_user
from app.model import get_db
from app.schemas import (
    AnalysisTaskCreateRequest,
    AnalysisTaskDetailResponse,
    AnalysisTaskListResponse,
    AnalysisTaskNodeDetailResponse,
    AnalysisTaskNodeListResponse,
    AnalysisTaskResponse,
    RetryNodeRequest,
)
from app.service.task_service import get_task_service

router = APIRouter(prefix="/tasks")


@router.post("", response_model=AnalysisTaskResponse)
async def create_task(
    payload: AnalysisTaskCreateRequest,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    await ensure_project_access(payload.project_id, token)
    username = str(user.get("username") or user.get("user", {}).get("username") or "system")
    return await get_task_service().create_task(db, payload, username, token)


@router.get("", response_model=AnalysisTaskListResponse)
async def list_tasks(
    project_id: str = Query(...),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=200),
    status: Optional[str] = Query(None),
    analysis_type: Optional[str] = Query(None),
    created_by: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    await ensure_project_access(project_id, token)
    return get_task_service().list_tasks(
        db,
        project_id=project_id,
        page=page,
        per_page=per_page,
        status=status,
        analysis_type=analysis_type,
        created_by=created_by,
        risk_level=risk_level,
    )


@router.get("/{task_id}", response_model=AnalysisTaskDetailResponse)
async def get_task(
    task_id: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    detail = get_task_service().get_task(db, task_id)
    await ensure_project_access(detail.project_id, token)
    return detail


@router.get("/{task_id}/nodes", response_model=AnalysisTaskNodeListResponse)
async def list_task_nodes(
    task_id: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    detail = get_task_service().get_task(db, task_id)
    await ensure_project_access(detail.project_id, token)
    return get_task_service().list_task_nodes(db, task_id)


@router.get("/{task_id}/nodes/{agent_key}", response_model=AnalysisTaskNodeDetailResponse)
async def get_task_node(
    task_id: str,
    agent_key: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    detail = get_task_service().get_task(db, task_id)
    await ensure_project_access(detail.project_id, token)
    return get_task_service().get_task_node(db, task_id, agent_key)


@router.post("/{task_id}/rerun", response_model=AnalysisTaskResponse)
async def rerun_task(
    task_id: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    detail = get_task_service().get_task(db, task_id)
    await ensure_project_access(detail.project_id, token)
    username = str(user.get("username") or user.get("user", {}).get("username") or "system")
    return await get_task_service().rerun_task(db, task_id, username, token)


@router.post("/{task_id}/cancel", response_model=AnalysisTaskResponse)
async def cancel_task(
    task_id: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    detail = get_task_service().get_task(db, task_id)
    await ensure_project_access(detail.project_id, token)
    username = str(user.get("username") or user.get("user", {}).get("username") or "system")
    return get_task_service().cancel_task(db, task_id, username)


@router.post("/{task_id}/retry-node", response_model=AnalysisTaskResponse)
async def retry_node(
    task_id: str,
    payload: RetryNodeRequest,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    detail = get_task_service().get_task(db, task_id)
    await ensure_project_access(detail.project_id, token)
    username = str(user.get("username") or user.get("user", {}).get("username") or "system")
    return get_task_service().retry_node(db, task_id, payload.agent_key, username)
