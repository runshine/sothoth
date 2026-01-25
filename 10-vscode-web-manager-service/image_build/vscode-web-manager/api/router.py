"""
API路由配置 - 完整版本
"""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timezone

from utils.errors import CodeServerError, ProjectError
from config import Config

# 导入各个路由模块
from api.routes import (
    auth_router,
    projects_router,
    pvc_router,
    code_servers_router,
    codewiki_router,
    tasks_router,
    files_router,
    health_router
)

# 创建主路由器
api_router = APIRouter()

# 注册子路由
api_router.include_router(auth_router, tags=["认证"])
api_router.include_router(projects_router, tags=["项目管理"])
api_router.include_router(pvc_router, tags=["PVC管理"])
api_router.include_router(code_servers_router, tags=["Code-Server管理"])
api_router.include_router(codewiki_router, tags=["CodeWiki管理"])
api_router.include_router(tasks_router, tags=["任务管理"])
api_router.include_router(files_router, tags=["文件下载"])
api_router.include_router(health_router, tags=["健康检查"])


def register_error_handlers(app):
    """注册错误处理器"""

    @app.exception_handler(CodeServerError)
    async def codeserver_error_handler(request: Request, exc: CodeServerError):
        """处理Code-Server相关错误"""
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Code-Server错误: {exc.message}, 详情: {exc.details}")

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "message": exc.message,
                    "details": exc.details,
                    "status_code": exc.status_code,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
        )

    @app.exception_handler(ProjectError)
    async def project_error_handler(request: Request, exc: ProjectError):
        """处理项目相关错误"""
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"项目错误: {exc.message}, 详情: {exc.details}")

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "message": exc.message,
                    "details": exc.details,
                    "status_code": exc.status_code,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
        )