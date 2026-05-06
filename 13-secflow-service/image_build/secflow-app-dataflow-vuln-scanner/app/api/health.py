from __future__ import annotations

from fastapi import APIRouter

from app.models.database import get_engine
from app.schemas import HealthResponse, SuccessResponse
from app.services.auth import get_auth_service
from app.services.project import get_project_service
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse.model_validate(get_scheduler_service().health_payload())


@router.get("/ready", response_model=SuccessResponse)
async def ready() -> SuccessResponse:
    with get_engine().connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    await get_auth_service().startup_validate()
    get_project_service().startup_validate()
    return SuccessResponse(message="ready")
