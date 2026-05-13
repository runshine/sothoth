from __future__ import annotations

import logging

from fastapi import APIRouter

from app.models.database import get_engine
from app.schemas import HealthResponse, SuccessResponse
from app.services.auth import get_auth_service
from app.services.project import ProjectServiceError, get_project_service
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])
logger = logging.getLogger(__name__)


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse.model_validate(get_scheduler_service().health_payload())


@router.get("/ready", response_model=SuccessResponse)
async def ready() -> SuccessResponse:
    with get_engine().connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    await get_auth_service().startup_validate()
    try:
        get_project_service().startup_validate()
    except ProjectServiceError as exc:
        # Readiness should reflect this service's ability to serve. A brief
        # upstream project-service restart should not flap all scanner pods.
        logger.warning("project service readiness check degraded: %s", exc)
    return SuccessResponse(message="ready")
