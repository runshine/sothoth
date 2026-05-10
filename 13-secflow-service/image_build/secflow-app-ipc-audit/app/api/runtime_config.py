from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import Subject, get_current_subject
from app.schemas import RuntimeConfigResponse, RuntimeConfigUpdateRequest
from app.services.runtime_config_service import get_runtime_config_service

router = APIRouter()


@router.get("/runtime-config", response_model=RuntimeConfigResponse)
def get_runtime_config() -> RuntimeConfigResponse:
    return get_runtime_config_service().get_config()


@router.patch("/runtime-config", response_model=RuntimeConfigResponse)
def update_runtime_config(
    payload: RuntimeConfigUpdateRequest,
    subject: Subject = Depends(get_current_subject),
) -> RuntimeConfigResponse:
    return get_runtime_config_service().update_max_parallel_tasks(
        payload.max_parallel_tasks,
        updated_by=subject.username,
    )
