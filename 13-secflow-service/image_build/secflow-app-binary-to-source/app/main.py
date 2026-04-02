"""Manager main entry."""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.tasks import router as task_router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.model import apply_table_prefix_if_needed, init_database
from app.services.registry import get_registry_service
from app.services.scheduler import get_scheduler_service


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        cfg = load_config()
        logging.getLogger().setLevel(getattr(logging, cfg.logging.level.upper(), logging.INFO))

        apply_table_prefix_if_needed()
        init_database()

        scheduler = get_scheduler_service()
        scheduler.start()

        await get_registry_service().start()
        logger.info("binary-to-source manager started")
    except Exception as exc:
        logger.exception("startup failed: %s", exc)
        sys.exit(1)

    yield

    try:
        get_scheduler_service().stop()
        await get_registry_service().stop()
    except Exception as exc:
        logger.warning("shutdown warning: %s", exc)


app = FastAPI(
    title="SecFlow Binary To Source Manager",
    description="ELF 到源码还原任务管理服务",
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
app.include_router(task_router)


if __name__ == "__main__":
    import uvicorn

    cfg = get_config()
    uvicorn.run("app.main:app", host=cfg.app.host, port=cfg.app.port, reload=cfg.app.debug)
