from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.config import get_config, load_config
from app.model import get_engine, init_database
from app.observability import get_observability
from app.service.auth import get_auth_service
from app.service.project import get_project_service
from app.service.registry import get_registry_service
from app.service.scheduler import get_scheduler_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("starting binary evolution center...")
    load_config()
    init_database()
    with get_engine().connect() as conn:
        conn.exec_driver_sql("SELECT 1")
    await get_auth_service().startup_validate()
    get_project_service().startup_validate()
    if get_scheduler_service().role != "worker":
        await get_registry_service().start()
    await get_scheduler_service().start()
    yield
    await get_scheduler_service().stop()
    if get_scheduler_service().role != "worker":
        await get_registry_service().stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecFlow Binary Evolution Center",
        description="围绕数据流漏洞结果执行多轮智能体进化",
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
    app.include_router(router)

    @app.get("/metrics")
    @app.get("/api/app/binary-evolution/metrics", include_in_schema=False)
    async def metrics():
        return get_observability().metrics_response()

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    load_config()
    config = get_config()
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
