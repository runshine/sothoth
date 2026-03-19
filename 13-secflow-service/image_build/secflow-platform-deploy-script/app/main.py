"""
SecFlow部署脚本管理服务主入口
"""

import logging
import sys
import json
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

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


def verify_auth_service_or_exit():
    """启动时校验Auth服务连通性与机机Token有效性。"""
    cfg = get_config().auth_service
    machine_token = getattr(cfg, "service_machine_token", None)
    if not machine_token:
        logger.error("未配置auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    base_url = f"http://{cfg.host}:{cfg.port}"
    health_url = f"{base_url}/api/auth/health"
    validate_url = cfg.validate_url

    try:
        with urlopen(health_url, timeout=cfg.timeout) as resp:
            if resp.status != 200:
                logger.error(f"Auth服务健康检查失败: status={resp.status}")
                sys.exit(1)
    except Exception as e:
        logger.error(f"Auth服务不可达: {e}")
        sys.exit(1)

    try:
        req = Request(validate_url, method="POST")
        req.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(req, timeout=cfg.timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if resp.status != 200:
                logger.error(f"机机Token校验失败: status={resp.status}, body={body}")
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error(f"机机Token类型异常: token_type={payload.get('token_type')}")
                sys.exit(1)
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        logger.error(f"机机Token校验失败: status={e.code}, body={body}")
        sys.exit(1)
    except URLError as e:
        logger.error(f"机机Token校验失败，Auth服务不可达: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"机机Token校验失败: {e}")
        sys.exit(1)


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

    verify_auth_service_or_exit()
    logger.info("Auth服务连通性与机机Token校验通过")

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

# 注册静态资源服务 - /script 路径对应 resource 根目录
resource_dir = Path(__file__).parent.parent / "resource"
if resource_dir.exists():
    app.mount("/script", StaticFiles(directory=str(resource_dir)), name="script")


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
