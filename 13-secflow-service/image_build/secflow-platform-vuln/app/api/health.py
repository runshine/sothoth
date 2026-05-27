"""Health endpoints."""

from fastapi import APIRouter

from app.build_info import build_service_meta

router = APIRouter(prefix="/api/vuln", tags=["health"])


@router.get("/health")
async def health():
    return {"status": "ok", "service": "secflow-platform-vuln", **build_service_meta()}


@router.get("/ready")
async def ready():
    return {"status": "ready", **build_service_meta()}
