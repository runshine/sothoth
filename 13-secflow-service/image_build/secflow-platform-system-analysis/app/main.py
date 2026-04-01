"""SecFlow system analysis service entry."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.model import get_engine, init_database
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
        logger.error("missing auth_service.service_machine_token")
        sys.exit(1)

    base_url = f"http://{cfg.host}:{cfg.port}"
    health_url = f"{base_url}/api/auth/health"
    validate_url = cfg.validate_url

    try:
        with urlopen(health_url, timeout=cfg.timeout) as response:
            if response.status != 200:
                logger.error("auth health check failed, status=%s", response.status)
                sys.exit(1)
    except Exception as exc:
        logger.error("auth service unavailable: %s", exc)
        sys.exit(1)

    try:
        request = Request(validate_url, method="POST")
        request.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(request, timeout=cfg.timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            if response.status != 200:
                logger.error("machine token invalid, status=%s body=%s", response.status, body)
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error("machine token type invalid: %s", payload.get("token_type"))
                sys.exit(1)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        logger.error("machine token validate failed: status=%s body=%s", exc.code, body)
        sys.exit(1)
    except URLError as exc:
        logger.error("machine token validate failed, auth service unreachable: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("machine token validate failed: %s", exc)
        sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting secflow system analysis service...")
    try:
        load_config()
        init_database()
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        verify_auth_service_or_exit()
        await get_registry_service().start()
    except Exception as exc:
        logger.error("startup failed: %s", exc)
        sys.exit(1)

    logger.info("secflow system analysis service started")
    yield

    logger.info("stopping secflow system analysis service...")
    try:
        await get_registry_service().stop()
    except Exception as exc:
        logger.warning("stop registry failed: %s", exc)


app = FastAPI(
    title="SecFlow系统分析服务",
    description="测试环境自动化分析业务微服务",
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

