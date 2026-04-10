from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.config import get_config, load_config
from app.models.database import get_engine, init_database
from app.pi_vuln_core.config.loader import ConfigValidationError
from app.pi_vuln_core.runner import load_framework_config_from_path, run_framework_config
from app.services.auth import get_auth_service
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
    logger.info("starting secflow ai agent framework service...")
    load_config()
    init_database()
    with get_engine().connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    await get_auth_service().startup_validate()
    await get_registry_service().start()
    await get_scheduler_service().start()
    yield
    await get_scheduler_service().stop()
    await get_registry_service().stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecFlow AI Agent Framework",
        description="多智能体漏洞工作流管理与调度服务",
        version="2.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


app = create_app()


async def _run_cli(config_path: str, clean_workspace: bool) -> int:
    try:
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
    except Exception:
        logger.exception("pi-vuln cli execution failed")
        return 1


def cli_entry() -> None:
    parser = argparse.ArgumentParser(description="SecFlow AI Agent Framework")
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
        sys.exit(asyncio.run(_run_cli(args.config, clean_workspace=args.clean_workspace)))


if __name__ == "__main__":
    cli_entry()
