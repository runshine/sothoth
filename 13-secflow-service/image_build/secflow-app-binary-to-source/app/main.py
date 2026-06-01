"""SecFlow Binary-to-Source adapter service."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from threading import Lock
from typing import Callable, Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool

from app.api.tasks import router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.model import get_engine, init_database
from app.metrics_summary import build_ai_summary, build_generic_observability_summary, build_rest_api_summary, parse_prometheus_metrics
from app.observability import get_observability
from app.service.dispatcher import get_dispatcher
from app.service.llm_provider import materialize_llm_provider
from app.service.registry import get_registry_service
from app.service.task_syncer import get_task_syncer


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)
_SUMMARY_CACHE_TTL_SECONDS = 5.0
_summary_cache: dict[str, tuple[float, Any]] = {}
_summary_cache_lock = Lock()


def _cached_summary(key: str, builder: Callable[[], Any]) -> Any:
    now = time.monotonic()
    with _summary_cache_lock:
        cached = _summary_cache.get(key)
        if cached and now - cached[0] <= _SUMMARY_CACHE_TTL_SECONDS:
            return cached[1]
    value = builder()
    with _summary_cache_lock:
        _summary_cache[key] = (time.monotonic(), value)
    return value


def _metrics_rows():
    response = get_observability().metrics_response()
    return parse_prometheus_metrics(response.body)


def _service_role() -> str:
    raw_role = os.environ.get("SECFLOW_B2S_ROLE") or ""
    normalized = str(raw_role).strip().lower()
    return normalized if normalized in {"api", "worker"} else "all"


def _api_enabled() -> bool:
    return _service_role() in {"all", "api"}


def _worker_enabled() -> bool:
    return _service_role() in {"all", "worker"}


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
        if _api_enabled():
            await get_registry_service().start()
        if _worker_enabled():
            get_dispatcher().start()
            get_task_syncer().start()
    except Exception as exc:
        logger.exception("B2S服务启动失败: %s", exc)
        sys.exit(1)
    logger.info("SecFlow B2S后端适配服务启动成功")
    yield
    try:
        if _worker_enabled():
            await get_task_syncer().stop()
            await get_dispatcher().stop()
        if _api_enabled():
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
app.middleware("http")(get_observability().http_middleware)


@app.middleware("http")
async def worker_role_route_guard(request, call_next):
    if _service_role() == "worker":
        path = request.url.path
        allowed = (
            path in {
                "/api/app/binary-to-source/health",
                "/api/app/binary-to-source/ready",
                "/api/app/binary-to-source/metrics",
                "/metrics",
                "/openapi.json",
            }
            or path.startswith("/docs")
            or path.startswith("/redoc")
        )
        if not allowed:
            from fastapi.responses import JSONResponse

            return JSONResponse(status_code=404, content={"detail": "not found"})
    return await call_next(request)

setup_exception_handlers(app)
app.include_router(router)


@app.get("/metrics")
@app.get("/api/app/binary-to-source/metrics", include_in_schema=False)
async def metrics():
    return get_observability().metrics_response()


@app.get("/api/app/binary-to-source/metrics/summary", include_in_schema=False)
async def metrics_summary():
    return await run_in_threadpool(
        _cached_summary,
        "summary",
        lambda: build_generic_observability_summary(_metrics_rows(), title="二进制逆向"),
    )


@app.get("/api/app/binary-to-source/metrics/rest-api-summary", include_in_schema=False)
async def metrics_rest_api_summary():
    return await run_in_threadpool(
        _cached_summary,
        "rest-api-summary",
        lambda: build_rest_api_summary(_metrics_rows()),
    )


@app.get("/api/app/binary-to-source/metrics/ai-summary", include_in_schema=False)
async def metrics_ai_summary():
    return await run_in_threadpool(
        _cached_summary,
        "ai-summary",
        lambda: build_ai_summary(_metrics_rows(), coverage_text="二进制逆向 AI 指标覆盖函数恢复、评审、缓存与 token/cost。"),
    )


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
