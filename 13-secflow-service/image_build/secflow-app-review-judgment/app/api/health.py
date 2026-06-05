from __future__ import annotations

import threading
import time
from typing import Any

from fastapi import APIRouter, HTTPException

from app.build_info import build_service_meta
from app.runtime_state import build_runtime_status
from app.schemas import HealthResponse, SuccessResponse
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/review-judgment", tags=["Review Judgment"])

_probe_state_lock = threading.Lock()
_probe_state: dict[str, Any] = {
    "started_at": 0.0,
    "auth_ready": False,
    "project_ready": False,
    "services_ready": False,
    "startup_error": None,
    "shutting_down": False,
}


def mark_probe_state(**kwargs: Any) -> None:
    with _probe_state_lock:
        if not _probe_state["started_at"]:
            _probe_state["started_at"] = time.time()
        for key, value in kwargs.items():
            if key in _probe_state:
                _probe_state[key] = value


def collect_probe_snapshot() -> dict[str, Any]:
    runtime_status = build_runtime_status()
    scheduler = get_scheduler_service()
    scheduler_payload = scheduler.health_payload()
    with _probe_state_lock:
        state = dict(_probe_state)
    ready = bool(runtime_status.get("ready")) and bool(state.get("services_ready")) and not bool(state.get("shutting_down"))
    reason = state.get("startup_error")
    if not reason and not runtime_status.get("ready"):
        reason = runtime_status.get("last_error") or "runtime bootstrap incomplete"
    if not reason and not state.get("services_ready"):
        reason = "service dependencies not ready"
    return {
        **scheduler_payload,
        **runtime_status,
        **build_service_meta(),
        "service": "secflow-app-review-judgment",
        "started_at": state.get("started_at") or None,
        "updated_at": time.time(),
        "shutting_down": bool(state.get("shutting_down")),
        "startup_phase": "ready" if ready else ("stopping" if state.get("shutting_down") else "booting"),
        "last_error": reason,
        "reason": None if ready else reason,
        "liveness_ok": not bool(state.get("shutting_down")),
        "readiness_ok": ready,
        "checks": {
            "bootstrap": {
                "db_ready": bool(runtime_status.get("db_ready")),
                "services_ready": bool(runtime_status.get("services_ready")),
                "ready": bool(runtime_status.get("ready")),
            },
            "auth": {"ok": bool(state.get("auth_ready"))},
            "project": {"ok": bool(state.get("project_ready"))},
        },
    }


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse.model_validate(collect_probe_snapshot())


@router.get("/ready", response_model=SuccessResponse)
async def ready() -> SuccessResponse:
    snapshot = collect_probe_snapshot()
    if not bool(snapshot.get("readiness_ok")):
        raise HTTPException(status_code=503, detail=str(snapshot.get("reason") or "not ready"))
    return SuccessResponse(message="ready")