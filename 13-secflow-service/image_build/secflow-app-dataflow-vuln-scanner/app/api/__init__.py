from fastapi import APIRouter

from app.api.admin import router as admin_router
from app.api.config_routes import router as config_router
from app.api.health import router as health_router
from app.api.profiles import router as profiles_router
from app.api.tasks import router as tasks_router

router = APIRouter()
router.include_router(health_router)
router.include_router(tasks_router)
router.include_router(profiles_router)
router.include_router(config_router)
router.include_router(admin_router)

__all__ = ["router"]
