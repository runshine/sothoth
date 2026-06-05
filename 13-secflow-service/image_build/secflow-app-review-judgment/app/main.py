from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import router
from app.api.health import collect_probe_snapshot, mark_probe_state
from app.config import get_config, load_config
from app.models.database import get_engine, init_database
from app.observability import build_metrics_response, observe_http_request, observe_http_request_inflight
from app.runtime_bootstrap import get_runtime_bootstrap
from app.services.auth import get_auth_service
from app.services.http_client import close_all_shared_async_clients
from app.services.project import get_project_service
from app.services.scheduler import get_scheduler_service
from app.services.vuln_engine import get_vuln_engine_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting secflow review judgment service...")
    load_config()
    role = get_scheduler_service().role
    logger.info("secflow review judgment role=%s", role)
    mark_probe_state(
        shutting_down=False,
        services_ready=False,
        auth_ready=False,
        project_ready=False,
        startup_error=None,
    )

    async def _after_db_ready() -> None:
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        await get_auth_service().startup_validate()
        mark_probe_state(auth_ready=True)
        get_project_service().startup_validate()
        mark_probe_state(project_ready=True)
        get_vuln_engine_service().startup_validate()
        if role != "api":
            await get_scheduler_service().start()
        mark_probe_state(services_ready=True, startup_error=None)

    try:
        await get_runtime_bootstrap().start(_after_db_ready)
    except Exception as exc:
        mark_probe_state(startup_error=str(exc), services_ready=False)
        raise
    yield
    mark_probe_state(shutting_down=True, services_ready=False)
    await get_runtime_bootstrap().stop()
    if role != "api":
        await get_scheduler_service().stop()
    await close_all_shared_async_clients()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecFlow Review Judgment",
        description="漏洞评审研判任务管理、调度与执行服务",
        version="1.0.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def roles_route_guard(request, call_next):
        role = get_scheduler_service().role
        if role in {"worker", "manager"}:
            path = request.url.path
            if role == "worker":
                allowed = (
                    path.startswith("/api/v1/jobs")
                    or path in {
                        "/api/review-judgment/health",
                        "/api/review-judgment/ready",
                        "/api/app/review-judgment/metrics",
                        "/metrics",
                        "/openapi.json",
                    }
                    or path.startswith("/docs")
                    or path.startswith("/redoc")
                )
            else:
                allowed = (
                    path.startswith("/api/review-judgment/admin")
                    or path in {
                        "/api/review-judgment/health",
                        "/api/review-judgment/ready",
                        "/api/app/review-judgment/metrics",
                        "/metrics",
                        "/openapi.json",
                    }
                    or path.startswith("/docs")
                    or path.startswith("/redoc")
                )
            if not allowed:
                return JSONResponse(status_code=404, content={"detail": "not found"})
        return await call_next(request)

    @app.middleware("http")
    async def metrics_http_middleware(request: Request, call_next):
        started = time.perf_counter()
        response = None
        route = request.scope.get("route")
        route_path = getattr(route, "path", None) or request.url.path
        observe_http_request_inflight(request.method, str(route_path), 1)
        try:
            response = await call_next(request)
            return response
        finally:
            duration_seconds = max(time.perf_counter() - started, 0.0)
            status_code = response.status_code if response is not None else 500
            observe_http_request(request.method, route_path, status_code, duration_seconds)
            observe_http_request_inflight(request.method, str(route_path), -1)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)

    @app.get("/metrics", include_in_schema=False)
    @app.get("/api/app/review-judgment/metrics", include_in_schema=False)
    async def metrics():
        return build_metrics_response()

    return app


app = create_app()


def cli_entry() -> None:
    import uvicorn

    load_config()
    config = get_config()
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)


if __name__ == "__main__":
    cli_entry()