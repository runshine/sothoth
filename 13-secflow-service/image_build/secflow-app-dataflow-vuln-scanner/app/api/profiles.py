from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject, get_db
from app.schemas import (
    ScanProfileCreateRequest,
    ScanProfileResponse,
    ScanProfileUpdateRequest,
    ScanProfileVersionResponse,
)
from app.services.workflow_service import get_workflow_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])


@router.post("/profiles", response_model=ScanProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_profile(
    payload: ScanProfileCreateRequest,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(payload.project_id, token)
    return get_workflow_service().create_profile(db, payload, principal)


@router.get("/profiles", response_model=List[ScanProfileResponse])
async def list_profiles(
    project_id: Optional[str] = Query(None),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    if project_id:
        await ensure_project_access(project_id, token)
    return get_workflow_service().list_profiles(db, principal, project_id=project_id)


@router.get("/profiles/{profile_id}", response_model=ScanProfileResponse)
async def get_profile(profile_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_workflow_service().get_profile(db, profile_id, principal)


@router.put("/profiles/{profile_id}", response_model=ScanProfileResponse)
async def update_profile(
    profile_id: str,
    payload: ScanProfileUpdateRequest,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, _ = subject
    return get_workflow_service().update_profile(db, profile_id, payload, principal)


@router.post("/profiles/{profile_id}/enable", response_model=ScanProfileResponse)
async def enable_profile(profile_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_workflow_service().set_profile_enabled(db, profile_id, principal, True)


@router.post("/profiles/{profile_id}/disable", response_model=ScanProfileResponse)
async def disable_profile(profile_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_workflow_service().set_profile_enabled(db, profile_id, principal, False)


@router.post("/profiles/{profile_id}/set-default", response_model=ScanProfileResponse)
async def set_default_profile(profile_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_workflow_service().set_profile_default(db, profile_id, principal)


@router.get("/profiles/{profile_id}/versions", response_model=List[ScanProfileVersionResponse])
async def list_profile_versions(profile_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, _ = subject
    return get_workflow_service().list_profile_versions(db, profile_id, principal)
