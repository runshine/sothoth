"""
SecFlow Workflow Service Main Entry
"""

import logging
import sys
import json
from contextlib import asynccontextmanager
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.app_templates import router as app_template_router
from app.api.job_templates import router as job_template_router
from app.api.template_tags import router as template_tag_router
from app.api.workflow_instances import router as workflow_instance_router
from app.api.app_workflows import router as app_workflow_router
from app.api.terminal_proxy import router as terminal_proxy_router
from app.config import load_config, get_config
from app.exception import setup_exception_handlers
from app.models import create_tables, get_engine
from app.services import get_registry_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def verify_auth_service_or_exit():
    """Startup check: auth connectivity + machine token validation."""
    cfg = get_config().auth_service
    machine_token = getattr(cfg, "service_machine_token", None)
    if not machine_token:
        logger.error("auth_service.service_machine_token is required")
        sys.exit(1)

    base_url = f"http://{cfg.host}:{cfg.port}"
    health_url = f"{base_url}/api/auth/health"
    validate_url = cfg.validate_url

    try:
        with urlopen(health_url, timeout=cfg.timeout) as resp:
            if resp.status != 200:
                logger.error(f"Auth health check failed: status={resp.status}")
                sys.exit(1)
    except Exception as e:
        logger.error(f"Auth service unreachable: {e}")
        sys.exit(1)

    try:
        req = Request(validate_url, method="POST")
        req.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(req, timeout=cfg.timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if resp.status != 200:
                logger.error(f"Machine token validation failed: status={resp.status}, body={body}")
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error(f"Invalid machine token type: {payload.get('token_type')}")
                sys.exit(1)
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        logger.error(f"Machine token validation failed: status={e.code}, body={body}")
        sys.exit(1)
    except URLError as e:
        logger.error(f"Machine token validation failed, auth unreachable: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Machine token validation failed: {e}")
        sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    # Startup
    logger.info("Starting SecFlow Workflow Service...")

    # Load configuration
    try:
        config = load_config()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    # Initialize database
    try:
        create_tables()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)

    # Verify K8S service configuration
    config = get_config()
    logger.info(f"K8S service mode enabled, endpoint: {config.k8s_service.host}:{config.k8s_service.port}")

    verify_auth_service_or_exit()
    logger.info("Auth connectivity and machine token validation passed")

    # Register with Menu service
    try:
        registry_service = get_registry_service()
        await registry_service.start()
    except Exception as e:
        logger.warning(f"Menu registration failed: {e}, service will continue running")

    logger.info("SecFlow Workflow Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down SecFlow Workflow Service...")

    # Unregister from Menu service
    try:
        registry_service = get_registry_service()
        await registry_service.stop()
    except Exception as e:
        logger.warning(f"Menu unregistration failed: {e}")


# Create FastAPI application
app = FastAPI(
    title="SecFlow Workflow Service",
    description="Provides application templates, job templates, and workflow orchestration management",
    version="1.0.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup exception handlers
setup_exception_handlers(app)


# Health check endpoints
@app.get("/api/workflow/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint
    """
    return JSONResponse(
        content={"status": "ok", "service": "secflow-workflow-service"},
        status_code=200
    )


@app.get("/api/workflow/ready", tags=["Health"])
async def ready_check():
    """
    Readiness check endpoint
    """
    return JSONResponse(
        content={"status": "ready"},
        status_code=200
    )

# Register routers
app.include_router(app_template_router, prefix="/api/workflow")
app.include_router(job_template_router, prefix="/api/workflow")
app.include_router(template_tag_router, prefix="/api/workflow")
app.include_router(workflow_instance_router, prefix="/api/workflow")
app.include_router(app_workflow_router, prefix="/api/workflow")
app.include_router(terminal_proxy_router)


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
