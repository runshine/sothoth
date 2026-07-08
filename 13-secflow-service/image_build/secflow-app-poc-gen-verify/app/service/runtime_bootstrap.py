"""Bootstrap DB + registry for the API pod (daemon thread, with retry).

Only the API pod runs this. The worker pod runs `celery -A app.celery_app worker`
(DB inited in celery_app._ensure_db), the scheduler pod runs `python -m
app.dispatcher` (DB inited in celery_app._ensure_db). Neither goes through here.
"""
from __future__ import annotations

import logging
import os
import threading
from dataclasses import asdict, dataclass
from typing import Optional

from fastapi import FastAPI

from app.config import get_service_yaml
from app.runtime_context import INSTANCE_ID, PUBLIC_API_ENABLED, REGISTRY_ENABLED, ROLE

logger = logging.getLogger("poc.bootstrap")

DB_INIT_RETRY_SECONDS = int(os.environ.get("POC_DB_INIT_RETRY_SECONDS", "5"))


@dataclass
class RuntimeBootstrapStatus:
    db_ready: bool = False
    registry_ready: bool = False
    ready: bool = False
    phase: str = "booting"
    error: str | None = None
    attempts: int = 0


class RuntimeBootstrap:
    def __init__(self) -> None:
        self._task: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._status = RuntimeBootstrapStatus()

    def start(self, app: FastAPI) -> None:
        if self._task and self._task.is_alive():
            return
        self._stop_event = threading.Event()
        self._status = RuntimeBootstrapStatus()
        self._task = threading.Thread(target=self._bootstrap_loop, args=(app,), name="poc_runtime_bootstrap", daemon=True)
        self._task.start()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            from app.service.registry_service import get_registry_service
            get_registry_service().stop()
        except Exception as _e:
            logger.warning("registry stop error: %s", _e, exc_info=True)
        if self._task and self._task.is_alive():
            self._task.join(timeout=5.0)
        self._task = None
        logger.info("runtime bootstrap stopped (instance=%s)", INSTANCE_ID)

    def status(self) -> dict:
        return asdict(self._status)

    def _bootstrap_loop(self, app: FastAPI) -> None:
        svc_yaml = get_service_yaml()
        while not self._stop_event.is_set():
            made_progress = False
            if not self._status.db_ready:
                made_progress = self._init_db(svc_yaml)
            if self._status.db_ready:
                if REGISTRY_ENABLED and not self._status.registry_ready:
                    made_progress = self._attempt("registry_register", self._register_registry) or made_progress
                if self._all_ready():
                    self._status.phase = "ready"
                    self._status.ready = True
                    self._status.error = None
                    logger.info("startup ready (instance=%s role=%s)", INSTANCE_ID, ROLE)
                    return
            if made_progress:
                continue
            try:
                self._stop_event.wait(DB_INIT_RETRY_SECONDS)
            except Exception:
                pass

    def _init_db(self, svc_yaml) -> bool:
        self._status.phase = "db_init"
        self._status.attempts += 1
        try:
            from app.db import init_db
            init_db(svc_yaml.database.url, svc_yaml.database.pool_size, svc_yaml.database.max_overflow)
            self._status.db_ready = True
            self._status.error = None
            logger.info("DB initialized: %s:%s/%s", svc_yaml.database.host, svc_yaml.database.port, svc_yaml.database.name)
            return True
        except Exception as exc:
            self._status.error = f"db_init: {exc}"
            logger.warning("startup DB init failed (attempt %s, retry in %ss): %s",
                           self._status.attempts, DB_INIT_RETRY_SECONDS, exc)
            return False

    def _attempt(self, phase: str, starter) -> bool:
        self._status.phase = phase
        try:
            starter()
            self._status.error = None
            return True
        except Exception as exc:
            self._status.error = f"{phase}: {exc}"
            logger.warning("%s failed (retry in %ss): %s", phase, DB_INIT_RETRY_SECONDS, exc, exc_info=True)
            return False

    def _register_registry(self) -> None:
        from app.service.registry_service import get_registry_service
        reg = get_registry_service()
        reg.register()
        reg.start()
        self._status.registry_ready = True

    def _all_ready(self) -> bool:
        if not self._status.db_ready:
            return False
        if REGISTRY_ENABLED and not self._status.registry_ready:
            return False
        return True


_runtime_bootstrap: RuntimeBootstrap | None = None


def get_runtime_bootstrap() -> RuntimeBootstrap:
    global _runtime_bootstrap
    if _runtime_bootstrap is None:
        _runtime_bootstrap = RuntimeBootstrap()
    return _runtime_bootstrap
