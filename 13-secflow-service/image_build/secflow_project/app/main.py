"""
SecFlow项目管理服务主入口
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.projects import router
from app.config import load_config, get_config
from app.exception import AppException, setup_exception_handlers
from app.model import init_database
from app.service.k8s import get_k8s_client
from app.service.registry import get_registry_service

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时执行
    logger.info("正在启动SecFlow项目管理服务...")

    # 加载配置
    try:
        config = load_config()
        logger.info("配置加载成功")
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        sys.exit(1)

    # 初始化数据库
    try:
        init_database()
        logger.info("数据库初始化成功")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        sys.exit(1)

    # 验证K8S连接
    try:
        k8s_client = get_k8s_client()
        if not k8s_client.connect():
            logger.error("K8S连接验证失败")
            sys.exit(1)
        logger.info("K8S连接验证成功")
    except Exception as e:
        logger.error(f"K8S连接验证失败: {e}")
        sys.exit(1)

    # 向Menu注册中心注册服务
    try:
        registry_service = get_registry_service()
        await registry_service.start()
    except Exception as e:
        logger.warning(f"Menu注册中心注册失败: {e}，服务将继续运行")

    logger.info("SecFlow项目管理服务启动成功")

    yield

    # 关闭时执行
    logger.info("正在关闭SecFlow项目管理服务...")

    # 注销Menu注册中心
    try:
        registry_service = get_registry_service()
        await registry_service.stop()
    except Exception as e:
        logger.warning(f"注销Menu注册中心失败: {e}")


# 创建FastAPI应用
app = FastAPI(
    title="SecFlow项目管理服务",
    description="提供项目CRUD、K8S Namespace管理等功能",
    version="1.0.0",
    lifespan=lifespan,
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册异常处理器
setup_exception_handlers(app)

# 注册路由
app.include_router(router)


# 健康检查
@app.get("/health")
async def health_check():
    """健康检查接口"""
    return {"status": "ok", "service": "secflow-project-service"}


# 就绪检查
@app.get("/ready")
async def ready_check():
    """就绪检查接口"""
    return {"status": "ready"}


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )