"""SecFlow vuln-verify app."""

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
from app.service.registry import get_registry_service
from app.service.worker import get_worker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def _role() -> str:
    return os.environ.get("SECFLOW_VULN_VERIFY_ROLE") or os.environ.get("SECFLOW_APP_ROLE") or "all"


def _api_enabled() -> bool:
    return _role() in {"all", "api"}


def _worker_enabled() -> bool:
    return _role() in {"all", "worker"}


def verify_auth_service_or_exit() -> None:
    cfg = get_config().auth_service
    machine_token = os.environ.get("SECFLOW_SERVICE_MACHINE_TOKEN") or cfg.service_machine_token
    if not machine_token:
        logger.error("未配置auth_service.service_machine_token或SECFLOW_SERVICE_MACHINE_TOKEN，拒绝启动")
        sys.exit(1)
    try:
        with urlopen(f"http://{cfg.host}:{cfg.port}/api/auth/health", timeout=cfg.timeout) as response:
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
    logger.info("正在启动SecFlow漏洞验证服务 role=%s...", _role())
    try:
        load_config()
        init_database()
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        verify_auth_service_or_exit()
        if _api_enabled():
            await get_registry_service().start()
        if _worker_enabled():
            get_worker().start()
    except Exception as exc:
        logger.exception("漏洞验证服务启动失败: %s", exc)
        sys.exit(1)
    logger.info("SecFlow漏洞验证服务启动成功")
    yield
    try:
        if _worker_enabled():
            await get_worker().stop()
        if _api_enabled():
            await get_registry_service().stop()
    finally:
        logger.info("SecFlow漏洞验证服务已关闭")


app = FastAPI(
    title="SecFlow Vuln Verify",
    description="项目隔离的漏洞验证任务服务，封装 vuln-verify CLI",
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


@app.middleware("http")
async def worker_role_route_guard(request, call_next):
    if _role() == "worker":
        path = request.url.path
        allowed = path in {
            "/api/app/vuln-verify/health",
            "/api/app/vuln-verify/ready",
            "/openapi.json",
        } or path.startswith("/docs") or path.startswith("/redoc")
        if not allowed:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=404, content={"detail": "not found"})
    return await call_next(request)


setup_exception_handlers(app)
app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    cfg = get_config()
    uvicorn.run("app.main:app", host=cfg.app.host, port=cfg.app.port, reload=cfg.app.debug)
