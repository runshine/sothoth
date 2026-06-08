"""Main entrypoint for secflow-platform-vuln."""

import logging
import os
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.actions import router as actions_router
from app.api.cases import router as cases_router
from app.api.config import router as config_router
from app.api.health import router as health_router
from app.api.public import router as public_router
from app.api.services import router as services_router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.models import init_database
from app.services.lifecycle_engine import ensure_default_workflow
from app.services.auth import init_auth_service
from app.services.download_center import get_download_center_service
from app.services.project import init_project_service
from app.services.registry import get_registry_service


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("Starting secflow-platform-vuln")
    try:
        load_config()
        config = get_config()
        init_auth_service(
            base_url=f"http://{config.auth_service.host}:{config.auth_service.port}",
            validate_path=config.auth_service.validate_token_path,
            timeout=config.auth_service.timeout,
        )
        init_project_service(
            base_url=f"http://{config.project_service.host}:{config.project_service.port}",
            get_project_path=config.project_service.get_project_path,
            timeout=config.project_service.timeout,
            service_machine_token=config.auth_service.service_machine_token,
        )
        if os.environ.get("SECFLOW_VULN_SKIP_STARTUP") != "1":
            init_database()
            from app.models.database import get_session_factory
            session = get_session_factory()()
            try:
                ensure_default_workflow(session)
            finally:
                session.close()
            await get_registry_service().start()
            await get_download_center_service().start()
    except Exception as exc:
        logger.error("Startup failed: %s", exc)
        raise

    yield

    if os.environ.get("SECFLOW_VULN_SKIP_STARTUP") != "1":
        try:
            await get_download_center_service().stop()
        except Exception as exc:
            logger.warning("Download center stop failed: %s", exc)
        try:
            await get_registry_service().stop()
        except Exception as exc:
            logger.warning("Registry stop failed: %s", exc)


app = FastAPI(
    title="SecFlow Vulnerability Lifecycle Engine",
    description="Capability registry and lifecycle engine for vulnerability cases",
    version="0.1.0",
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

app.include_router(health_router)
app.include_router(public_router)
app.include_router(services_router)
app.include_router(config_router)
app.include_router(cases_router)
app.include_router(actions_router)


if __name__ == "__main__":
    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
