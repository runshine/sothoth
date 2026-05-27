"""SecFlow Binary Security orchestrator service."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request as FastAPIRequest
from fastapi.responses import Response

from app.api.tasks import router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.metrics_aggregate import get_metrics_aggregator
from app.model import get_engine, init_database
from app.observability import (
    normalize_http_route,
    observe_http_request,
    observe_http_request_inflight,
    observe_auth_token_validation,
    observe_downstream_request,
    render_metrics,
)
from app.service.http_client import close_all_async_clients
from app.service.reducer_metrics_snapshot import close_reducer_metrics_snapshot_store
from app.service.reducer_metrics_snapshot import get_reducer_metrics_snapshot_store
from app.service.registry import get_registry_service
from app.service.task_queue import close_task_queue
from app.service.task_manager import get_task_manager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def _service_role() -> str:
    raw_role = os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or ""
    normalized = str(raw_role).strip().lower()
    return normalized if normalized in {"api", "worker", "reducer"} else "all"


def _scheduler_enabled() -> bool:
    env_value = os.environ.get("SECFLOW_BINARY_SECURITY_ENABLE_SCHEDULER")
    if env_value is not None:
        return str(env_value).strip().lower() in {"1", "true", "yes", "on"}
    role = _service_role()
    if role == "api":
        return False
    if role in {"worker", "reducer"}:
        return True
    return bool(get_config().scheduler.enabled)


def _registry_enabled() -> bool:
    role = _service_role()
    if role in {"worker", "reducer"}:
        return False
    return bool(get_config().registry.enabled)


def verify_auth_service_or_exit() -> None:
    cfg = get_config().auth_service
    machine_token = cfg.service_machine_token
    if not machine_token:
        logger.error("未配置 auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    health_url = f"http://{cfg.host}:{cfg.port}/api/auth/health"
    try:
        started = time.perf_counter()
        with urlopen(health_url, timeout=cfg.timeout) as response:
            if response.status != 200:
                observe_downstream_request(
                    service="auth_service",
                    method="GET",
                    operation="health",
                    status=str(response.status),
                    duration_seconds=time.perf_counter() - started,
                )
                logger.error("Auth 服务健康检查失败: status=%s", response.status)
                sys.exit(1)
            observe_downstream_request(
                service="auth_service",
                method="GET",
                operation="health",
                status=str(response.status),
                duration_seconds=time.perf_counter() - started,
            )
    except Exception as exc:
        observe_downstream_request(
            service="auth_service",
            method="GET",
            operation="health",
            status="error",
            duration_seconds=None,
        )
        logger.error("Auth 服务不可达: %s", exc)
        sys.exit(1)

    try:
        request = Request(cfg.validate_url, method="POST")
        request.add_header("Authorization", f"Bearer {machine_token}")
        started = time.perf_counter()
        with urlopen(request, timeout=cfg.timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            if response.status != 200:
                observe_auth_token_validation(result="failed", source="startup")
                observe_downstream_request(
                    service="auth_service",
                    method="POST",
                    operation="validate_machine_token",
                    status=str(response.status),
                    duration_seconds=time.perf_counter() - started,
                )
                logger.error("机机 Token 校验失败: status=%s body=%s", response.status, body)
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                observe_auth_token_validation(result="invalid_type", source="startup")
                logger.error("机机 Token 类型异常: token_type=%s", payload.get("token_type"))
                sys.exit(1)
            observe_auth_token_validation(result="success", source="startup")
            observe_downstream_request(
                service="auth_service",
                method="POST",
                operation="validate_machine_token",
                status=str(response.status),
                duration_seconds=time.perf_counter() - started,
            )
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        observe_auth_token_validation(result="failed", source="startup")
        observe_downstream_request(
            service="auth_service",
            method="POST",
            operation="validate_machine_token",
            status=str(exc.code),
            duration_seconds=None,
        )
        logger.error("机机 Token 校验失败: status=%s body=%s", exc.code, body)
        sys.exit(1)
    except URLError as exc:
        observe_auth_token_validation(result="connect_error", source="startup")
        observe_downstream_request(
            service="auth_service",
            method="POST",
            operation="validate_machine_token",
            status="connect_error",
            duration_seconds=None,
        )
        logger.error("Auth 服务不可达，机机 Token 校验失败: %s", exc)
        sys.exit(1)
    except Exception as exc:
        observe_auth_token_validation(result="error", source="startup")
        observe_downstream_request(
            service="auth_service",
            method="POST",
            operation="validate_machine_token",
            status="error",
            duration_seconds=None,
        )
        logger.error("机机 Token 校验失败: %s", exc)
        sys.exit(1)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("正在启动 SecFlow Binary Security 服务...")
    try:
        load_config()
        init_database()
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        verify_auth_service_or_exit()
        if _registry_enabled():
            await get_registry_service().start()
        if _scheduler_enabled():
            await get_task_manager().start()
    except Exception as exc:
        logger.exception("Binary Security 服务启动失败: %s", exc)
        sys.exit(1)

    logger.info("SecFlow Binary Security 服务启动成功")
    yield
    try:
        if _scheduler_enabled():
            await get_task_manager().stop()
        if _registry_enabled():
            await get_registry_service().stop()
        await close_task_queue()
        await close_reducer_metrics_snapshot_store()
        await close_all_async_clients()
    except Exception as exc:
        logger.warning("Binary Security 服务关闭警告: %s", exc)


app = FastAPI(
    title="SecFlow Binary Security",
    description="统一串联固件解包、系统分析、反编译、入口分析、数据流分析和漏洞扫描的编排微服务",
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
async def prometheus_http_middleware(request: FastAPIRequest, call_next):
    import time

    started = time.perf_counter()
    status_code = 500
    route = request.scope.get("route")
    path = getattr(route, "path", None) or request.url.path
    normalized_route = normalize_http_route(str(path))
    observe_http_request_inflight(request.method, normalized_route, 1)
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        observe_http_request(
            method=request.method,
            path=str(path),
            status_code=status_code,
            duration_seconds=time.perf_counter() - started,
        )
        observe_http_request_inflight(request.method, normalized_route, -1)


@app.middleware("http")
async def service_role_route_guard(request: FastAPIRequest, call_next):
    role = _service_role()
    if role in {"worker", "reducer"}:
        path = request.url.path
        allowed = (
            path in {
                "/api/app/binary-security/health",
                "/api/app/binary-security/ready",
                "/api/app/binary-security/metrics",
                "/api/app/binary-security/metrics/aggregate",
                "/api/app/binary-security/metrics/reducer",
                "/metrics",
                "/openapi.json",
            }
            or path.startswith("/docs")
            or path.startswith("/redoc")
        )
        if not allowed:
            return Response(
                content=json.dumps({"detail": "not found"}),
                media_type="application/json",
                status_code=404,
            )
    return await call_next(request)


@app.get("/metrics", include_in_schema=False)
@app.get("/api/app/binary-security/metrics", include_in_schema=False)
async def metrics_endpoint():
    payload, content_type = render_metrics()
    return Response(content=payload, media_type=content_type)


@app.get("/api/app/binary-security/metrics/aggregate", include_in_schema=False)
async def aggregate_metrics_endpoint():
    started = time.perf_counter()
    try:
        aggregated = await get_metrics_aggregator().aggregate()
    except Exception as exc:
        observe_downstream_request(
            service="binary_security_metrics",
            method="GET",
            operation="aggregate",
            status="error",
            duration_seconds=None,
        )
        raise HTTPException(status_code=502, detail=f"Aggregate metrics generation failed: {exc}") from exc
    observe_downstream_request(
        service="binary_security_metrics",
        method="GET",
        operation="aggregate",
        status="200",
        duration_seconds=time.perf_counter() - started,
    )
    return Response(content=aggregated.payload, media_type=aggregated.content_type)


@app.get("/api/app/binary-security/metrics/reducer", include_in_schema=False)
async def reducer_metrics_endpoint():
    started = time.perf_counter()
    try:
        fallback_payload = None
        if _service_role() == "reducer":
            fallback_payload = render_metrics()[0].decode("utf-8", errors="ignore")
        payload, content_type = await get_reducer_metrics_snapshot_store().render_metrics(
            fallback_payload=fallback_payload
        )
    except Exception as exc:
        observe_downstream_request(
            service="binary_security_reducer",
            method="GET",
            operation="metrics_snapshot",
            status="error",
            duration_seconds=None,
        )
        raise HTTPException(status_code=502, detail=f"Reducer metrics snapshot failed: {exc}") from exc
    observe_downstream_request(
        service="binary_security_reducer",
        method="GET",
        operation="metrics_snapshot",
        status="200",
        duration_seconds=time.perf_counter() - started,
    )
    return Response(content=payload, media_type=content_type)

setup_exception_handlers(app)
app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
