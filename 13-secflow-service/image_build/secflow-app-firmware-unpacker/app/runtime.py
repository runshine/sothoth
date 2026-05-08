"""Process-local runtime bootstrap for firmware unpacker service."""

from __future__ import annotations

import logging
import threading

from app.model import init_database
from app.services.registry import get_registry_service
from app.services.task_manager import start as start_task_dispatcher
from app.services.task_manager import stop as stop_task_dispatcher
from app.services.worker import (
    deregister_worker,
    register_worker,
    start_heartbeat,
    stop_heartbeat,
)


logger = logging.getLogger(__name__)

_runtime_lock = threading.Lock()
_runtime_started = False


def _verify_auth_service_or_exit() -> None:
    from app.main import verify_auth_service_or_exit

    verify_auth_service_or_exit()


async def start_runtime() -> None:
    global _runtime_started

    with _runtime_lock:
        if _runtime_started:
            return
        try:
            _verify_auth_service_or_exit()
            init_database()
            register_worker()
            start_heartbeat()
            start_task_dispatcher()
            _runtime_started = True
        except Exception:
            stop_task_dispatcher()
            stop_heartbeat()
            deregister_worker()
            _runtime_started = False
            raise

    try:
        await get_registry_service().start()
    except Exception:
        await stop_runtime()
        raise
    logger.info("firmware unpacker runtime started")


async def stop_runtime() -> None:
    global _runtime_started

    with _runtime_lock:
        if not _runtime_started:
            return
        _runtime_started = False

    try:
        stop_task_dispatcher()
        stop_heartbeat()
        deregister_worker()
        await get_registry_service().stop()
    except Exception as exc:
        logger.warning("firmware unpacker runtime shutdown warning: %s", exc)
    else:
        logger.info("firmware unpacker runtime stopped")
