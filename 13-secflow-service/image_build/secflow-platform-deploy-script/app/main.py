"""
SecFlow部署脚本管理服务主入口
"""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.files import router
from app.config import load_config, get_config
from app.exception import setup_exception_handlers
from app.services.registry import get_registry_service

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
    logger.info("正在启动SecFlow部署脚本管理服务...")

    # 加载配置
    try:
        config = load_config()
        logger.info("配置加载成功")
        logger.info(f"文件根目录: {config.file_root}")
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        sys.exit(1)

    # 验证文件根目录
    file_root = Path(config.file_root)
    if not file_root.exists():
        logger.warning(f"文件根目录不存在，将自动创建: {file_root}")
        file_root.mkdir(parents=True, exist_ok=True)
    else:
        logger.info(f"文件根目录已存在: {file_root}")

    # 向Menu注册中心注册服务
    try:
        registry_service = get_registry_service()
        await registry_service.start()
    except Exception as e:
        logger.warning(f"Menu注册中心注册失败: {e}，服务将继续运行")

    logger.info("SecFlow部署脚本管理服务启动成功")

    yield

    # 关闭时执行
    logger.info("正在关闭SecFlow部署脚本管理服务...")

    # 注销Menu注册中心
    try:
        registry_service = get_registry_service()
        await registry_service.stop()
    except Exception as e:
        logger.warning(f"注销Menu注册中心失败: {e}")


# 创建FastAPI应用
app = FastAPI(
    title="SecFlow部署脚本管理服务",
    description="提供部署脚本的文件管理功能，包括上传、下载、查看、编辑、重命名、创建目录等",
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

# 注册静态资源服务 - /script 路径对应 resource/script 目录
script_dir = Path(__file__).parent.parent / "resource" / "script"
if script_dir.exists():
    app.mount("/script", StaticFiles(directory=str(script_dir)), name="script")


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )