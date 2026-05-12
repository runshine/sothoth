from fastapi import APIRouter

from .config_routes import router as config_router
from .tasks import router as task_router

router = APIRouter()
router.include_router(task_router)
router.include_router(config_router)
