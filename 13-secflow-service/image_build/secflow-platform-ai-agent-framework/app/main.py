from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.config import get_config, load_config
from app.models.database import get_engine, init_database
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


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
