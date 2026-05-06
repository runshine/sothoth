from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject, get_db
from app.schemas import ProjectEffectiveConfigResponse, ServiceEffectiveConfigResponse
from app.services.config_view import build_sanitized_service_config
from app.services.workflow_service import get_workflow_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])


@router.get("/projects/{project_id}/config/effective", response_model=ProjectEffectiveConfigResponse)
async def get_project_effective_config(project_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    await ensure_project_access(project_id, token)
    return ProjectEffectiveConfigResponse.model_validate(
        get_workflow_service().get_effective_project_config(db, project_id, principal)
    )


@router.get("/service/config/effective", response_model=ServiceEffectiveConfigResponse)
async def get_service_effective_config(subject=Depends(get_current_subject)):
    return ServiceEffectiveConfigResponse.model_validate(build_sanitized_service_config())
