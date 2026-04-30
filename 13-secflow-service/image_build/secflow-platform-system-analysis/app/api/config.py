"""Config API routes for per-project analysis configuration."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import ensure_project_access, get_current_user
from app.model import get_db
from app.schemas import AnalysisServiceConfigRequest, AnalysisServiceConfigResponse
from app.service.config_service import get_config_service

router = APIRouter(tags=["config"])


@router.get("/config", response_model=AnalysisServiceConfigResponse)
async def get_project_config(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    ensure_project_access(current_user, project_id)
    return get_config_service().get_config(db, project_id)


@router.put("/config", response_model=AnalysisServiceConfigResponse)
async def save_project_config(
    payload: AnalysisServiceConfigRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    ensure_project_access(current_user, payload.project_id)
    return get_config_service().save_config(db, payload)
