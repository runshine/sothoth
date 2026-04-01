"""API router collection."""

from fastapi import APIRouter

from app.api.overview import router as overview_router
from app.api.prompts import router as prompts_router
from app.api.reports import router as reports_router
from app.api.tasks import router as tasks_router

router = APIRouter(prefix="/api/system-analysis", tags=["system-analysis"])
router.include_router(overview_router)
router.include_router(prompts_router)
router.include_router(tasks_router)
router.include_router(reports_router)

