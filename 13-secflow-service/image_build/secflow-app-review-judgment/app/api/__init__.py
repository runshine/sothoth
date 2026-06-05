from fastapi import APIRouter

from app.api.health import router as health_router
from app.api.tasks import router as tasks_router

router = APIRouter()
router.include_router(health_router)
router.include_router(tasks_router)

__all__ = ["router"]