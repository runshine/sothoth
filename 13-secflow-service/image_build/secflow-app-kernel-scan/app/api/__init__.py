from __future__ import annotations

from fastapi import APIRouter

from app.api.devices import router as devices_router
from app.api.health import router as health_router
from app.api.tasks import router as tasks_router
from app.api.workspace import router as workspace_router

router = APIRouter(prefix="/api/app/kernel-scan", tags=["Kernel Scan"])
router.include_router(health_router)
router.include_router(devices_router)
router.include_router(tasks_router)
router.include_router(workspace_router)
