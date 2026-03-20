"""
SecFlow 工作流状态管理服务主入口
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_config
from app.exception import setup_exception_handlers
from app.models.database import init_database
from app.services.auth import get_auth_service
from app.services.k8s_client import get_k8s_client
from app.services.status_sync_service import get_status_sync_service
from app.services.workflow_monitor_engine import get_workflow_monitor_engine
from app.api.workflow_status import router
from app.api.workflow_monitor import router as monitor_router
from app.api.workflow_lifecycle import router as lifecycle_router


# 配置日志
config = get_config()
logging.basicConfig(
    level=getattr(logging, config.logging.level),
    format=config.logging.format,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时初始化
    logger.info("启动工作流状态管理服务...")

    # 初始化数据库
    try:
        init_database()
        logger.info("数据库初始化成功")
    except Exception as e:
        logger.warning(f"数据库初始化警告: {e}")

    # 初始化认证服务
    try:
        auth_service = get_auth_service()
        logger.info("认证服务初始化成功")
    except Exception as e:
        logger.warning(f"认证服务初始化警告: {e}")

    # 初始化K8S客户端
    try:
        k8s_client = get_k8s_client()
        logger.info("K8S客户端初始化成功")
    except Exception as e:
        logger.warning(f"K8S客户端初始化警告: {e}")

    # 初始化状态同步服务
    try:
        status_sync_service = get_status_sync_service()
        logger.info("状态同步服务初始化成功")
    except Exception as e:
        logger.warning(f"状态同步服务初始化警告: {e}")

    # 初始化监控引擎
    try:
        monitor_engine = get_workflow_monitor_engine()
        await monitor_engine.start()
        logger.info("监控引擎初始化成功")
    except Exception as e:
        logger.warning(f"监控引擎初始化警告: {e}")

    logger.info("工作流状态管理服务启动完成")

    yield

    # 关闭时清理
    logger.info("关闭工作流状态管理服务...")

    # 停止监控引擎
    try:
        monitor_engine = get_workflow_monitor_engine()
        await monitor_engine.stop()
        logger.info("监控引擎已停止")
    except Exception as e:
        logger.warning(f"监控引擎停止警告: {e}")


# 创建FastAPI应用
app = FastAPI(
    title="SecFlow 工作流状态管理服务",
    description="提供节点状态查询、同步、历史记录等功能",
    version="2.0.0",
    lifespan=lifespan,
)

# 设置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 设置异常处理器
setup_exception_handlers(app)

# 注册路由
app.include_router(router)
app.include_router(monitor_router)
app.include_router(lifecycle_router)


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
