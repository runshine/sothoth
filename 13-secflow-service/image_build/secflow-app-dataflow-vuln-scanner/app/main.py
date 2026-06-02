from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from threading import Lock
from typing import Any, Callable

import time

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import router
from app.api.health import collect_probe_snapshot, mark_probe_state
from app.config import get_config, load_config
from app.models.database import get_engine, init_database
from app.pi_vuln_core.config.loader import ConfigValidationError
from app.pi_vuln_core.runner import load_framework_config_from_path, run_framework_config
from app.pi_vuln_core.utils.win_compat import ensure_event_loop_policy
from app.probe_server import ThreadedProbeServer
from app.observability import build_metrics_response, observe_http_request, observe_http_request_inflight
from app.metrics_summary import build_ai_summary, build_generic_observability_summary, build_rest_api_summary, parse_prometheus_metrics
from app.runtime_bootstrap import get_runtime_bootstrap
from app.services.auth import get_auth_service
from app.services.http_client import close_all_shared_async_clients
from app.services.llm_provider_sync import sync_providers_to_pi
from app.services.project import get_project_service
from app.services.registry import get_registry_service
from app.services.scheduler import get_scheduler_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)
_SUMMARY_CACHE_TTL_SECONDS = 5.0
_summary_cache: dict[str, tuple[float, Any]] = {}
_summary_cache_lock = Lock()
_probe_server: ThreadedProbeServer | None = None


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
    response = build_metrics_response()
    return parse_prometheus_metrics(response.body)


def _ensure_probe_server_started() -> None:
    global _probe_server
    if _probe_server is not None:
        _probe_server.start()
        return
    port = int((getattr(get_config().app, "port", 8080) or 8080) + 1000)
    port = int(os.environ.get("SECFLOW_DATAFLOW_VULN_SCANNER_PROBE_PORT", str(port)))
    _probe_server = ThreadedProbeServer(
        host="0.0.0.0",
        port=port,
        payload_provider=collect_probe_snapshot,
        health_paths=("/health", "/api/dataflow-vuln-scanner/health"),
        ready_paths=("/ready", "/api/dataflow-vuln-scanner/ready"),
    )
    _probe_server.start()


def _stop_probe_server() -> None:
    global _probe_server
    if _probe_server is not None:
        _probe_server.stop()
        _probe_server = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting secflow dataflow vuln scanner service...")
    load_config()
    role = get_scheduler_service().role
    logger.info("secflow dataflow vuln scanner role=%s", role)
    sync_providers_to_pi()
    mark_probe_state(
        shutting_down=False,
        services_ready=False,
        auth_ready=False,
        project_ready=False,
        registry_ready=False,
        startup_error=None,
    )
    _ensure_probe_server_started()

    async def _after_db_ready() -> None:
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        await get_auth_service().startup_validate()
        mark_probe_state(auth_ready=True)
        get_project_service().startup_validate()
        mark_probe_state(project_ready=True)
        if role in {"standalone", "api"}:
            await get_registry_service().start()
            mark_probe_state(registry_ready=True)
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
    if role in {"standalone", "api"}:
        await get_registry_service().stop()
    await close_all_shared_async_clients()
    _stop_probe_server()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecFlow Dataflow Vulnerability Scanner",
        description="项目级数据流漏洞扫描任务、配置、调度与执行服务",
        version="3.0.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def worker_role_route_guard(request, call_next):
        role = get_scheduler_service().role
        if role in {"worker", "manager"}:
            path = request.url.path
            if role == "worker":
                allowed = (
                    path.startswith("/api/v1/jobs")
                    or path in {
                        "/api/dataflow-vuln-scanner/health",
                        "/api/dataflow-vuln-scanner/ready",
                        "/api/dataflow-vuln-scanner/workers/cluster-capacity",
                        "/api/app/dataflow-vuln-scanner/metrics",
                        "/api/app/dataflow-vuln-scanner/metrics/summary",
                        "/api/app/dataflow-vuln-scanner/metrics/rest-api-summary",
                        "/api/app/dataflow-vuln-scanner/metrics/ai-summary",
                        "/api/dataflow-vuln-scanner/metrics",
                        "/api/dataflow-vuln-scanner/metrics/summary",
                        "/api/dataflow-vuln-scanner/metrics/rest-api-summary",
                        "/api/dataflow-vuln-scanner/metrics/ai-summary",
                        "/metrics",
                        "/openapi.json",
                    }
                    or path.startswith("/docs")
                    or path.startswith("/redoc")
                )
            else:
                allowed = (
                    path.startswith("/api/dataflow-vuln-scanner/admin")
                    or path in {
                        "/api/dataflow-vuln-scanner/health",
                        "/api/dataflow-vuln-scanner/ready",
                        "/api/app/dataflow-vuln-scanner/metrics",
                        "/api/app/dataflow-vuln-scanner/metrics/summary",
                        "/api/app/dataflow-vuln-scanner/metrics/rest-api-summary",
                        "/api/app/dataflow-vuln-scanner/metrics/ai-summary",
                        "/api/dataflow-vuln-scanner/metrics",
                        "/api/dataflow-vuln-scanner/metrics/summary",
                        "/api/dataflow-vuln-scanner/metrics/rest-api-summary",
                        "/api/dataflow-vuln-scanner/metrics/ai-summary",
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
    @app.get("/api/app/dataflow-vuln-scanner/metrics", include_in_schema=False)
    @app.get("/api/dataflow-vuln-scanner/metrics", include_in_schema=False)
    async def metrics():
        return build_metrics_response()

    @app.get("/api/app/dataflow-vuln-scanner/metrics/summary", include_in_schema=False)
    @app.get("/api/dataflow-vuln-scanner/metrics/summary", include_in_schema=False)
    async def metrics_summary():
        return await run_in_threadpool(
            _cached_summary,
            "summary",
            lambda: build_generic_observability_summary(_metrics_rows(), title="数据流漏洞挖掘"),
        )

    @app.get("/api/app/dataflow-vuln-scanner/metrics/rest-api-summary", include_in_schema=False)
    @app.get("/api/dataflow-vuln-scanner/metrics/rest-api-summary", include_in_schema=False)
    async def metrics_rest_api_summary():
        return await run_in_threadpool(
            _cached_summary,
            "rest-api-summary",
            lambda: build_rest_api_summary(_metrics_rows()),
        )

    @app.get("/api/app/dataflow-vuln-scanner/metrics/ai-summary", include_in_schema=False)
    @app.get("/api/dataflow-vuln-scanner/metrics/ai-summary", include_in_schema=False)
    async def metrics_ai_summary():
        return await run_in_threadpool(
            _cached_summary,
            "ai-summary",
            lambda: build_ai_summary(_metrics_rows(), coverage_text="数据流漏洞挖掘 AI 指标覆盖 cycle、candidate、judge 与 token/cost。"),
        )

    return app


app = create_app()


async def _run_cli(config_path: str, clean_workspace: bool) -> int:
    try:
        load_config()
        sync_providers_to_pi()
        framework_config = load_framework_config_from_path(config_path)
        artifacts = await run_framework_config(
            framework_config,
            clean_workspace=clean_workspace,
        )
        if artifacts.result.success:
            return framework_config.execution.on_completion.exit_code_on_success
        return framework_config.execution.on_completion.exit_code_on_failure
    except ConfigValidationError:
        logger.exception("pi-vuln config validation failed")
        return 1
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.warning("pi-vuln cli execution interrupted")
        return 130
    except Exception:
        logger.exception("pi-vuln cli execution failed")
        return 1


def cli_entry() -> None:
    parser = argparse.ArgumentParser(description="SecFlow Dataflow Vulnerability Scanner")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("serve", help="run REST service")

    run_parser = subparsers.add_parser("run", help="run a pi-vuln workflow config once")
    run_parser.add_argument("--config", "-c", required=True, help="pi-vuln JSON config path")
    workspace_group = run_parser.add_mutually_exclusive_group()
    workspace_group.add_argument("--keep-workspace", action="store_true", default=True)
    workspace_group.add_argument("--clean-workspace", action="store_true", default=False)

    args = parser.parse_args()
    if args.command in {None, "serve"}:
        import uvicorn

        load_config()
        config = get_config()
        uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
        return
    if args.command == "run":
        ensure_event_loop_policy()
        sys.exit(asyncio.run(_run_cli(args.config, clean_workspace=args.clean_workspace)))


if __name__ == "__main__":
    cli_entry()
