"""Health endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/vuln", tags=["health"])


@router.get("/health")
async def health():
    return {"status": "ok", "service": "secflow-platform-vuln"}


@router.get("/ready")
async def ready():
    return {"status": "ready"}
