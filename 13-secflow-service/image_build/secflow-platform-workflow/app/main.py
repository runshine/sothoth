"""
SecFlow Workflow Service Main Entry
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.app_templates import router as app_template_router
from app.api.job_templates import router as job_template_router
from app.api.workflow_instances import router as workflow_instance_router
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
app.include_router(workflow_instance_router, prefix="/api/workflow")


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
