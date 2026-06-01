from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from app.build_info import build_service_meta
from app.runtime_state import build_runtime_status
from app.schemas import HealthResponse, SuccessResponse
from app.services.auth import get_auth_service
from app.services.project import ProjectServiceError, get_project_service
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])
logger = logging.getLogger(__name__)


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse.model_validate(
        {
            **get_scheduler_service().health_payload(),
            **build_runtime_status(),
            **build_service_meta(),
        }
    )


@router.get("/ready", response_model=SuccessResponse)
async def ready() -> SuccessResponse:
    runtime_status = build_runtime_status()
    if not bool(runtime_status.get("ready")):
        raise HTTPException(
            status_code=503,
            detail=f"runtime bootstrap incomplete: {runtime_status.get('last_error') or 'waiting for db init'}",
        )
    await get_auth_service().startup_validate()
    try:
        get_project_service().startup_validate()
    except ProjectServiceError as exc:
        # Readiness should reflect this service's ability to serve. A brief
        # upstream project-service restart should not flap all scanner pods.
        logger.warning("project service readiness check degraded: %s", exc)
    return SuccessResponse(message="ready")
