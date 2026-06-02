"""Process-local runtime bootstrap for firmware unpacker service."""

from __future__ import annotations

import logging
import threading
import time

from app.config import get_runtime_roles, runtime_has_role
from app.model import init_database
from app.services.registry import get_registry_service
from app.services.task_manager import start as start_task_dispatcher
from app.services.task_manager import stop as stop_task_dispatcher
from app.services.worker import (
    deregister_worker,
    register_worker,
    start_cleanup_loop,
    start_cluster_maintenance,
    start_evolution_loop,
    start_worker_heartbeat,
    stop_all_loops,
)


logger = logging.getLogger(__name__)

_runtime_lock = threading.Lock()
_runtime_started = False
_runtime_state = {
    "worker_registered": False,
    "worker_heartbeat": False,
    "cluster_maintenance": False,
    "cleanup_loop": False,
    "evolution_loop": False,
    "dispatcher": False,
    "registry": False,
    "startup_error": None,
    "started_at": 0.0,
    "shutting_down": False,
}


def _verify_auth_service_or_exit() -> None:
    from app.main import verify_auth_service_or_exit

    verify_auth_service_or_exit()


async def start_runtime() -> None:
    global _runtime_started

    with _runtime_lock:
        if _runtime_started:
            return
        try:
            _runtime_state["shutting_down"] = False
            _runtime_state["startup_error"] = None
            if not _runtime_state["started_at"]:
                _runtime_state["started_at"] = time.time()
            _verify_auth_service_or_exit()
            init_database()
            roles = get_runtime_roles()
            logger.info("firmware unpacker runtime roles: %s", ",".join(sorted(roles)))
            if any(runtime_has_role(role) for role in ("dispatcher", "worker", "cleanup-worker")):
                register_worker()
                _runtime_state["worker_registered"] = True
            if any(runtime_has_role(role) for role in ("dispatcher", "worker", "cleanup-worker")):
                start_worker_heartbeat()
                _runtime_state["worker_heartbeat"] = True
            if runtime_has_role("dispatcher") or runtime_has_role("cleanup-worker"):
                start_cluster_maintenance()
                _runtime_state["cluster_maintenance"] = True
            if runtime_has_role("dispatcher"):
                start_task_dispatcher()
                _runtime_state["dispatcher"] = True
            if runtime_has_role("cleanup-worker"):
                start_cleanup_loop()
                _runtime_state["cleanup_loop"] = True
                start_evolution_loop()
                _runtime_state["evolution_loop"] = True
            _runtime_started = True
        except Exception:
            _runtime_state["dispatcher"] = False
            stop_task_dispatcher()
            stop_all_loops()
            if _runtime_state["worker_registered"]:
                deregister_worker()
                _runtime_state["worker_registered"] = False
            _runtime_state["startup_error"] = "runtime_start_failed"
            _runtime_started = False
            raise

    if runtime_has_role("api") or runtime_has_role("all"):
        try:
            await get_registry_service().start()
            _runtime_state["registry"] = True
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
        _runtime_state["shutting_down"] = True

    try:
        if _runtime_state["dispatcher"]:
            stop_task_dispatcher()
            _runtime_state["dispatcher"] = False
        stop_all_loops()
        _runtime_state["worker_heartbeat"] = False
        _runtime_state["cluster_maintenance"] = False
        _runtime_state["cleanup_loop"] = False
        _runtime_state["evolution_loop"] = False
        if _runtime_state["worker_registered"]:
            deregister_worker()
            _runtime_state["worker_registered"] = False
        if _runtime_state["registry"]:
            await get_registry_service().stop()
            _runtime_state["registry"] = False
    except Exception as exc:
        logger.warning("firmware unpacker runtime shutdown warning: %s", exc)
    else:
        logger.info("firmware unpacker runtime stopped")


def runtime_snapshot() -> dict[str, object]:
    with _runtime_lock:
        return {
            "started_at": _runtime_state.get("started_at") or None,
            "running": bool(_runtime_started),
            "shutting_down": bool(_runtime_state.get("shutting_down")),
            "startup_error": _runtime_state.get("startup_error"),
            "worker_registered": bool(_runtime_state.get("worker_registered")),
            "worker_heartbeat": bool(_runtime_state.get("worker_heartbeat")),
            "cluster_maintenance": bool(_runtime_state.get("cluster_maintenance")),
            "cleanup_loop": bool(_runtime_state.get("cleanup_loop")),
            "evolution_loop": bool(_runtime_state.get("evolution_loop")),
            "dispatcher": bool(_runtime_state.get("dispatcher")),
            "registry": bool(_runtime_state.get("registry")),
            "roles": sorted(get_runtime_roles()),
        }
