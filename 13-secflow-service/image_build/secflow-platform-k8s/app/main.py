"""
SecFlow K8S资源管理服务主入口
"""

import logging
import sys
import json
from contextlib import asynccontextmanager
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

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

    verify_auth_service_or_exit()
    logger.info("Auth服务连通性与机机Token校验通过")

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
