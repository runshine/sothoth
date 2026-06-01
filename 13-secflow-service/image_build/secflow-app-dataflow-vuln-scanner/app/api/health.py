from __future__ import annotations

import asyncio
import logging
import threading
import time

from fastapi import APIRouter, HTTPException

from app.build_info import build_service_meta
from app.config import get_config
from app.runtime_state import build_runtime_status
from app.schemas import HealthResponse, SuccessResponse
from app.services.auth import get_auth_service
from app.services.project import ProjectServiceError, get_project_service
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner", tags=["Dataflow Vuln Scanner"])
logger = logging.getLogger(__name__)
_ready_cache_lock = threading.Lock()
_ready_cache: dict[str, tuple[float, object]] = {}


async def _cached_auth_startup_validate() -> None:
    ttl_seconds = max(1, int(get_config().run_index_refresh.ready_validation_ttl_seconds or 10))
    now_monotonic = time.monotonic()
    with _ready_cache_lock:
        cached = _ready_cache.get("auth_validate")
        if cached is not None and now_monotonic - cached[0] < ttl_seconds:
            cached_value = cached[1]
            if isinstance(cached_value, Exception):
                raise cached_value
            return None
    try:
        await get_auth_service().startup_validate()
    except Exception as exc:
        with _ready_cache_lock:
            _ready_cache["auth_validate"] = (now_monotonic, exc)
        raise
    with _ready_cache_lock:
        _ready_cache["auth_validate"] = (now_monotonic, None)


def _cached_project_startup_validate() -> None:
    ttl_seconds = max(1, int(get_config().run_index_refresh.ready_validation_ttl_seconds or 10))
    now_monotonic = time.monotonic()
    with _ready_cache_lock:
        cached = _ready_cache.get("project_validate")
        if cached is not None and now_monotonic - cached[0] < ttl_seconds:
            cached_value = cached[1]
            if isinstance(cached_value, Exception):
                raise cached_value
            return None
    try:
        get_project_service().startup_validate()
    except Exception as exc:
        with _ready_cache_lock:
            _ready_cache["project_validate"] = (now_monotonic, exc)
        raise
    with _ready_cache_lock:
        _ready_cache["project_validate"] = (now_monotonic, None)


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
    try:
        await _cached_auth_startup_validate()
    except HTTPException as exc:
        if exc.status_code in {502, 503}:
            raise HTTPException(status_code=503, detail=exc.detail) from exc
        raise
    try:
        await asyncio.to_thread(_cached_project_startup_validate)
    except ProjectServiceError as exc:
        # Readiness should reflect this service's ability to serve. A brief
        # upstream project-service restart should not flap all scanner pods.
        logger.warning("project service readiness check degraded: %s", exc)
    return SuccessResponse(message="ready")
