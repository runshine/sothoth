"""SecFlow Binary-to-Source adapter service."""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.tasks import router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.model import get_engine, init_database
from app.service.llm_provider import materialize_llm_provider
from app.service.registry import get_registry_service


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def verify_auth_service_or_exit() -> None:
    """Verify inter-service machine token before accepting traffic."""
    cfg = get_config().auth_service
    machine_token = os.environ.get("SECFLOW_SERVICE_MACHINE_TOKEN") or cfg.service_machine_token
    if not machine_token:
        logger.error("未配置auth_service.service_machine_token或SECFLOW_SERVICE_MACHINE_TOKEN，拒绝启动")
        sys.exit(1)

    health_url = f"http://{cfg.host}:{cfg.port}/api/auth/health"
    try:
        with urlopen(health_url, timeout=cfg.timeout) as response:
            if response.status != 200:
                logger.error("Auth服务健康检查失败: status=%s", response.status)
                sys.exit(1)
    except Exception as exc:
        logger.error("Auth服务不可达: %s", exc)
        sys.exit(1)

    try:
        request = Request(cfg.validate_url, method="POST")
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
async def lifespan(_: FastAPI):
    logger.info("正在启动SecFlow B2S后端适配服务...")
    try:
        load_config()
        init_database()
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        verify_auth_service_or_exit()
        await materialize_llm_provider()
        await get_registry_service().start()
    except Exception as exc:
        logger.exception("B2S服务启动失败: %s", exc)
        sys.exit(1)
    logger.info("SecFlow B2S后端适配服务启动成功")
    yield
    try:
        await get_registry_service().stop()
    except Exception as exc:
        logger.warning("注销Menu注册中心失败: %s", exc)
    logger.info("SecFlow B2S后端适配服务已关闭")


app = FastAPI(
    title="SecFlow Binary-to-Source Adapter",
    description="项目隔离的B2S后端，适配SecFlow前端与pi-re-agent REST API",
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
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
