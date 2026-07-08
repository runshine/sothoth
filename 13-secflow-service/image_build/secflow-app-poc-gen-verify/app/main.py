"""FastAPI app factory + lifespan for secflow-app-poc-gen-verify (API pod)."""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_config
from .routes import router
from .service.runtime_bootstrap import get_runtime_bootstrap

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("poc-gen-verify")


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = get_config()
    log.info("starting %s (state_root=%s, poc_bin=%s, model=%s)",
             cfg.service_id, cfg.state_root, cfg.poc_bin, cfg.default_model)
    bootstrap = get_runtime_bootstrap()
    bootstrap.start(app)
    yield
    bootstrap.stop()
    log.info("stopped %s", cfg.service_id)


def create_app() -> FastAPI:
    app = FastAPI(title="SecFlow PoC Gen & Verify Service", version="1.0.0", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])
    app.include_router(router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    cfg = get_config()
    uvicorn.run("app.main:app", host=cfg.host, port=cfg.port, log_level="info")
