from __future__ import annotations

from fastapi import APIRouter

from app.api.artifacts import router as artifacts_router
from app.api.capabilities import router as capabilities_router
from app.api.catalog import router as catalog_router
from app.api.health import router as health_router
from app.api.providers import router as providers_router
from app.api.runtime_config import router as runtime_config_router
from app.api.tasks import router as tasks_router
from app.api.workspaces import router as workspaces_router

router = APIRouter(prefix="/api/app/ipc-audit", tags=["IPC Audit"])
router.include_router(health_router)
router.include_router(capabilities_router)
router.include_router(workspaces_router)
router.include_router(catalog_router)
router.include_router(providers_router)
router.include_router(runtime_config_router)
router.include_router(tasks_router)
router.include_router(artifacts_router)
