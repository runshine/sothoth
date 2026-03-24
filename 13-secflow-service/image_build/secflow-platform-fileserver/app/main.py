"""SecFlow fileserver main entry."""

import json
import logging
import sys
from contextlib import asynccontextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.files import router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.model import ensure_storage_dirs, get_engine, init_database
from app.service.registry import get_registry_service


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def verify_auth_service_or_exit():
    cfg = get_config().auth_service
    machine_token = getattr(cfg, "service_machine_token", None)
    if not machine_token:
        logger.error("未配置auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    base_url = f"http://{cfg.host}:{cfg.port}"
    health_url = f"{base_url}/api/auth/health"
    validate_url = cfg.validate_url

    try:
        with urlopen(health_url, timeout=cfg.timeout) as response:
            if response.status != 200:
                logger.error("Auth服务健康检查失败: status=%s", response.status)
                sys.exit(1)
    except Exception as exc:
        logger.error("Auth服务不可达: %s", exc)
        sys.exit(1)

    try:
        request = Request(validate_url, method="POST")
        request.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(request, timeout=cfg.timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            if response.status != 200:
                logger.error("机机Token校验失败: status=%s, body=%s", response.status, body)
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error("机机Token类型异常: token_type=%s", payload.get("token_type"))
                sys.exit(1)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        logger.error("机机Token校验失败: status=%s, body=%s", exc.code, body)
        sys.exit(1)
    except URLError as exc:
        logger.error("机机Token校验失败，Auth服务不可达: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("机机Token校验失败: %s", exc)
        sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("正在启动SecFlow文件管理服务...")
    try:
        load_config()
        ensure_storage_dirs()
        init_database()
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        verify_auth_service_or_exit()
        await get_registry_service().start()
    except Exception as exc:
        logger.error("服务启动失败: %s", exc)
        sys.exit(1)

    logger.info("SecFlow文件管理服务启动成功")
    yield
    logger.info("正在关闭SecFlow文件管理服务...")
    try:
        await get_registry_service().stop()
    except Exception as exc:
        logger.warning("注销Menu注册中心失败: %s", exc)


app = FastAPI(
    title="SecFlow文件管理服务",
    description="按项目和子项目管理文件上传、查询、下载与整理",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_exception_handlers(app)
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
