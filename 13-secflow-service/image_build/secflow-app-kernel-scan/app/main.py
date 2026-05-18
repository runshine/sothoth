from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.core.config import get_config, load_config
from app.db.database import get_database, init_database
from app.workers.scheduler import get_scheduler_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("starting secflow kernel scan service...")
    load_config()
    cfg = get_config()
    Path(cfg.state_root).mkdir(parents=True, exist_ok=True)
    init_database()
    with get_database().connect() as conn:
        conn.execute("SELECT 1")
    await get_scheduler_service().start()
    logger.info("secflow kernel scan service started")
    yield
    await get_scheduler_service().stop()
    logger.info("secflow kernel scan service stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecFlow Kernel Scan Service",
        description="内核攻击入口扫描、漏洞审计与 PoC 验证微服务",
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
    app.include_router(router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    cfg = load_config()
    uvicorn.run("app.main:app", host=cfg.app.host, port=cfg.app.port, reload=cfg.app.debug)
