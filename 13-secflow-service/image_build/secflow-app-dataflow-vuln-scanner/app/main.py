from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from contextlib import asynccontextmanager

import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import router
from app.config import get_config, load_config
from app.models.database import get_engine, init_database
from app.pi_vuln_core.config.loader import ConfigValidationError
from app.pi_vuln_core.runner import load_framework_config_from_path, run_framework_config
from app.pi_vuln_core.utils.win_compat import ensure_event_loop_policy
from app.observability import build_metrics_response, observe_http_request, observe_http_request_inflight
from app.runtime_bootstrap import get_runtime_bootstrap
from app.services.auth import get_auth_service
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting secflow dataflow vuln scanner service...")
    load_config()
    role = get_scheduler_service().role
    logger.info("secflow dataflow vuln scanner role=%s", role)
    sync_providers_to_pi()

    async def _after_db_ready() -> None:
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        await get_auth_service().startup_validate()
        get_project_service().startup_validate()
        if role != "worker":
            await get_registry_service().start()
        await get_scheduler_service().start()

    await get_runtime_bootstrap().start(_after_db_ready)
    yield
    await get_runtime_bootstrap().stop()
    await get_scheduler_service().stop()
    if role != "worker":
        await get_registry_service().stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecFlow Dataflow Vulnerability Scanner",
        description="项目级数据流漏洞扫描任务、配置、调度与执行服务",
        version="3.0.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def worker_role_route_guard(request, call_next):
        if get_scheduler_service().role == "worker":
            path = request.url.path
            allowed = (
                path.startswith("/api/v1/jobs")
                or path in {
                    "/api/dataflow-vuln-scanner/health",
                    "/api/dataflow-vuln-scanner/ready",
                    "/api/dataflow-vuln-scanner/workers/cluster-capacity",
                    "/api/app/dataflow-vuln-scanner/metrics",
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
    async def metrics():
        return build_metrics_response()

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
