from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core.auth import Subject, get_current_subject
from app.schemas import CatalogRefreshJobResponse, PagedPresetProjectsResponse, RefreshCatalogRequest
from app.services.catalog_service import get_catalog_service

router = APIRouter()


@router.get("/workspaces/{workspace_id}/preset-projects", response_model=PagedPresetProjectsResponse)
def list_preset_projects(
    workspace_id: str,
    keyword: str | None = Query(default=None),
    source: str | None = Query(default=None),
    has_idl: bool | None = Query(default=None),
    has_on_remote_request_cpp: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
) -> PagedPresetProjectsResponse:
    return get_catalog_service().list_projects(
        workspace_id=workspace_id,
        keyword=keyword,
        source=source,
        has_idl=has_idl,
        has_on_remote_request_cpp=has_on_remote_request_cpp,
        page=page,
        per_page=per_page,
    )


@router.post("/workspaces/{workspace_id}/preset-projects:refresh", response_model=CatalogRefreshJobResponse)
def refresh_preset_projects(
    workspace_id: str,
    payload: RefreshCatalogRequest,
    subject: Subject = Depends(get_current_subject),
) -> CatalogRefreshJobResponse:
    return get_catalog_service().refresh_projects(
        workspace_id=workspace_id,
        source=payload.source,
        write_entries_file=payload.write_entries_file,
        requested_by=subject.username,
    )


@router.get("/catalog-refresh-jobs/{refresh_job_id}", response_model=CatalogRefreshJobResponse)
def get_catalog_refresh_job(refresh_job_id: str) -> CatalogRefreshJobResponse:
    return get_catalog_service().get_refresh_job(refresh_job_id)

