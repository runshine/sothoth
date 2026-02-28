"""
SecFlow K8S资源管理服务主入口
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.models.database import init_database
from app.services.auth import get_auth_service
from app.services.k8s import get_k8s_service
from app.api.k8s_resources import router


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
    logger.info("启动K8S资源管理服务...")

    # 初始化数据库
    try:
        init_database()
        logger.info("数据库初始化成功")
    except Exception as e:
        logger.warning(f"数据库初始化警告: {e}")

    # 初始化K8S客户端
    try:
        k8s_service = get_k8s_service()
        # 触发客户端初始化
        _ = k8s_service.core_v1
        logger.info("K8S客户端初始化成功")
    except Exception as e:
        logger.warning(f"K8S客户端初始化警告: {e}")

    # 初始化认证服务
    try:
        auth_service = get_auth_service()
        logger.info("认证服务初始化成功")
    except Exception as e:
        logger.warning(f"认证服务初始化警告: {e}")

    logger.info("K8S资源管理服务启动完成")

    yield

    # 关闭时清理
    logger.info("关闭K8S资源管理服务...")


# 创建FastAPI应用
app = FastAPI(
    title="SecFlow K8S资源管理服务",
    description="提供对Kubernetes资源的增删查改操作",
    version="1.0.0",
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


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )