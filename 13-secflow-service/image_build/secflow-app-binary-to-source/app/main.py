"""SecFlow Binary-to-Source adapter service."""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.tasks import router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.model import get_engine, init_database


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("正在启动SecFlow B2S后端适配服务...")
    try:
        load_config()
        init_database()
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception as exc:
        logger.exception("B2S服务启动失败: %s", exc)
        sys.exit(1)
    logger.info("SecFlow B2S后端适配服务启动成功")
    yield
    logger.info("SecFlow B2S后端适配服务已关闭")


app = FastAPI(
    title="SecFlow Binary-to-Source Adapter",
    description="项目隔离的B2S后端，适配SecFlow前端与pi-re-agent REST API",
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

setup_exception_handlers(app)
app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run("app.main:app", host=config.app.host, port=config.app.port, reload=config.app.debug)
