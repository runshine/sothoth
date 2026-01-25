"""
API路由模块
"""
from api.routes.auth import router as auth_router
from api.routes.projects import router as projects_router
from api.routes.pvc import router as pvc_router
from api.routes.code_servers import router as code_servers_router
from api.routes.codewiki import router as codewiki_router
from api.routes.tasks import router as tasks_router
from api.routes.files import router as files_router
from api.routes.health import router as health_router

__all__ = [
    "auth_router",
    "projects_router",
    "pvc_router",
    "code_servers_router",
    "codewiki_router",
    "tasks_router",
    "files_router",
    "health_router"
]