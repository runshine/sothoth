from __future__ import annotations

import logging

from fastapi import FastAPI

from app.api.routes import router
from app.config import ensure_runtime_dirs, get_service_yaml
from app.db import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

ensure_runtime_dirs()
init_db()
cfg = get_service_yaml()

app = FastAPI(
    title="secflow-platform-diagnostic-assistant",
    version="0.1.0",
)
app.include_router(router)

