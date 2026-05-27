"""Overview and capability endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.build_info import build_service_meta
from app.api.deps import ensure_project_access, get_current_user
from app.model import get_db
from app.schemas import AnalysisOverviewResponse, MessageResponse, ProjectAnalysisCapabilitiesResponse
from app.service.capability_service import get_capability_service
from app.service.overview_service import get_overview_service

router = APIRouter()


@router.get("/health", response_model=MessageResponse)
async def health() -> MessageResponse:
    return MessageResponse(message="ok", **build_service_meta())


@router.get("/capabilities/nodes", response_model=ProjectAnalysisCapabilitiesResponse)
async def list_capability_nodes(
    project_id: str = Query(..., description="project id"),
    user_and_token=Depends(get_current_user),
):
    _, token = user_and_token
    await ensure_project_access(project_id, token)
    return await get_capability_service().list_capabilities(project_id, token=token)


@router.get("/overview", response_model=AnalysisOverviewResponse)
async def get_overview(
    project_id: str = Query(..., description="project id"),
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    await ensure_project_access(project_id, token)
    return await get_overview_service().get_overview(db, project_id, token=token)
