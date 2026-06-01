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
from app.metrics_summary import build_ai_summary, build_generic_observability_summary, build_rest_api_summary, parse_prometheus_metrics
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

    @app.get("/api/app/binary-evolution/metrics/summary", include_in_schema=False)
    async def metrics_summary():
        response = get_observability().metrics_response()
        rows = parse_prometheus_metrics(response.body)
        return build_generic_observability_summary(rows, title="进化中心")

    @app.get("/api/app/binary-evolution/metrics/rest-api-summary", include_in_schema=False)
    async def metrics_rest_api_summary():
        response = get_observability().metrics_response()
        rows = parse_prometheus_metrics(response.body)
        return build_rest_api_summary(rows)

    @app.get("/api/app/binary-evolution/metrics/ai-summary", include_in_schema=False)
    async def metrics_ai_summary():
        response = get_observability().metrics_response()
        rows = parse_prometheus_metrics(response.body)
        return build_ai_summary(rows, coverage_text="进化中心 AI 指标覆盖轮次、评分、派生任务与 token/cost。")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    load_config()
    config = get_config()
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
