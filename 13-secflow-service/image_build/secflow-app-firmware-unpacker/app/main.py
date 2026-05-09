"""Firmware unpacker FastAPI main entry point."""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_app_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_app_dir)
for candidate in (_project_root, _app_dir):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.agentflow_runs import router as agentflow_runs_router
from app.api.firmware import router as firmware_router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.logging_utils import configure_container_logging
from app.metrics import router as metrics_router
from app.model import init_database
from app.services.registry import get_registry_service
from app.services.task_manager import start as start_task_dispatcher
from app.services.task_manager import stop as stop_task_dispatcher
from app.services.worker import (
    deregister_worker,
    register_worker,
    start_heartbeat,
    stop_heartbeat,
)


configure_container_logging("secflow-app-firmware-unpacker")
logger = logging.getLogger(__name__)


def verify_auth_service_or_exit() -> None:
    """Validate auth service health and the configured machine token."""
    config = get_config().auth_service

    if not config.enabled:
        return

    machine_token = getattr(config, "service_machine_token", None)
    if not machine_token:
        logger.error("未配置 auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    try:
        with urlopen(config.health_url, timeout=config.timeout) as response:
            if response.status != 200:
                logger.error("认证服务健康检查失败: status=%s", response.status)
                sys.exit(1)
    except Exception as exc:
        logger.error("认证服务不可达: %s", exc)
        sys.exit(1)

    try:
        request = Request(config.validate_url, method="POST")
        request.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(request, timeout=config.timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            if response.status != 200:
                logger.error("机机 Token 校验失败: status=%s body=%s", response.status, body)
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error("机机 Token 类型异常: token_type=%s", payload.get("token_type"))
                sys.exit(1)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        logger.error("机机 Token 校验失败: status=%s body=%s", exc.code, body)
        sys.exit(1)
    except URLError as exc:
        logger.error("认证服务不可达，机机 Token 校验失败: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("机机 Token 校验失败: %s", exc)
        sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        config = load_config()
        logging.getLogger().setLevel(
            getattr(logging, config.logging.level.upper(), logging.INFO)
        )

        verify_auth_service_or_exit()
        init_database()
        register_worker()
        start_heartbeat()
        start_task_dispatcher()
        await get_registry_service().start()
        logger.info(
            "secflow-app-firmware-unpacker started agentflow_enabled=%s",
            config.agentflow.enabled,
        )
    except Exception as exc:
        logger.exception("service startup failed: %s", exc)
        sys.exit(1)

    yield

    try:
        stop_task_dispatcher()
        stop_heartbeat()
        deregister_worker()
        await get_registry_service().stop()
    except Exception as exc:
        logger.warning("service shutdown warning: %s", exc)


app = FastAPI(
    title="SecFlow Firmware Unpacker",
    description="固件解包任务管理服务",
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
app.include_router(agentflow_runs_router)
app.include_router(firmware_router)
app.include_router(metrics_router)


if __name__ == "__main__":
    from app.start import _default_workers, _env_int
    import gunicorn.app.wsgiapp

    config = get_config()
    workers = _env_int("GUNICORN_WORKERS", _default_workers())
    threads = _env_int("GUNICORN_THREADS", 8)
    timeout = _env_int("GUNICORN_TIMEOUT", 600)
    keepalive = _env_int("GUNICORN_KEEPALIVE", 10)

    sys.argv = [
        "gunicorn",
        "--bind",
        f"{config.app.host}:{config.app.port}",
        "--workers",
        str(workers),
        "--threads",
        str(threads),
        "--worker-class",
        "gthread",
        "--timeout",
        str(timeout),
        "--keep-alive",
        str(keepalive),
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "--capture-output",
        "app.wsgi:app",
    ]
    gunicorn.app.wsgiapp.run()
