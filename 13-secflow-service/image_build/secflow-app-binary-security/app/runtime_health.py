"""Lightweight runtime health and readiness checks."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

from app.config import get_config
from app.service.task_manager import get_task_manager

_state_lock = threading.Lock()
_startup_state: dict[str, Any] = {
    "started_at": 0.0,
    "startup_ready": False,
    "startup_error": None,
    "auth_ready": False,
    "registry_ready": False,
    "database_ready": False,
    "shutting_down": False,
}


def _service_role() -> str:
    raw_role = os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or ""
    normalized = str(raw_role).strip().lower()
    return normalized if normalized in {"api", "worker", "reducer"} else "all"


def mark_startup_state(
    *,
    startup_ready: bool | None = None,
    startup_error: str | None = None,
    auth_ready: bool | None = None,
    registry_ready: bool | None = None,
    database_ready: bool | None = None,
    shutting_down: bool | None = None,
) -> None:
    with _state_lock:
        if not _startup_state["started_at"]:
            _startup_state["started_at"] = time.time()
        if startup_ready is not None:
            _startup_state["startup_ready"] = bool(startup_ready)
        if startup_error is not None or startup_error == "":
            _startup_state["startup_error"] = startup_error or None
        if auth_ready is not None:
            _startup_state["auth_ready"] = bool(auth_ready)
        if registry_ready is not None:
            _startup_state["registry_ready"] = bool(registry_ready)
        if database_ready is not None:
            _startup_state["database_ready"] = bool(database_ready)
        if shutting_down is not None:
            _startup_state["shutting_down"] = bool(shutting_down)


def snapshot_startup_state() -> dict[str, Any]:
    with _state_lock:
        return dict(_startup_state)


def _loop_ready(loop_name: str, runtime: dict[str, Any]) -> bool:
    details = runtime.get("loop_details") if isinstance(runtime.get("loop_details"), dict) else {}
    detail = details.get(loop_name) if isinstance(details.get(loop_name), dict) else None
    if isinstance(detail, dict):
        return bool(detail.get("alive")) and not bool(detail.get("stale"))
    loops = runtime.get("loops") if isinstance(runtime.get("loops"), dict) else {}
    return bool(loops.get(loop_name))


def _scheduler_readiness() -> tuple[bool, dict[str, Any]]:
    scheduler_enabled = bool(get_config().scheduler.enabled)
    runtime = get_task_manager().runtime_status()
    loops = runtime.get("loops") if isinstance(runtime.get("loops"), dict) else {}
    loop_details = runtime.get("loop_details") if isinstance(runtime.get("loop_details"), dict) else {}
    if not scheduler_enabled:
        return True, {"enabled": False, "running": False, "loops": loops, "loop_details": loop_details}

    running = bool(runtime.get("running"))
    required_loops = ("task_dispatch", "operation_dispatch", "archive_dispatch", "downstream_reconcile", "readless_reconcile")
    missing = [loop_name for loop_name in required_loops if not _loop_ready(loop_name, runtime)]
    return running and not missing, {
        "enabled": True,
        "running": running,
        "loops": loops,
        "loop_details": loop_details,
        "missing_loops": missing,
    }


def _reducer_readiness() -> tuple[bool, dict[str, Any]]:
    scheduler_enabled = bool(get_config().scheduler.enabled)
    runtime = get_task_manager().runtime_status()
    loops = runtime.get("loops") if isinstance(runtime.get("loops"), dict) else {}
    loop_details = runtime.get("loop_details") if isinstance(runtime.get("loop_details"), dict) else {}
    if not scheduler_enabled:
        return True, {"enabled": False, "running": False, "loops": loops, "loop_details": loop_details}

    running = bool(runtime.get("running"))
    required_loops = ("state_reducer", "reducer_metrics_snapshot")
    missing = [loop_name for loop_name in required_loops if not _loop_ready(loop_name, runtime)]
    reducer_has_active_tail = bool(runtime.get("tail_reconcile_active"))
    return running and not missing, {
        "enabled": True,
        "running": running,
        "loops": loops,
        "loop_details": loop_details,
        "missing_loops": missing,
        "tail_reconcile_active": reducer_has_active_tail,
    }


def collect_probe_snapshot() -> dict[str, object]:
    role = _service_role()
    startup = snapshot_startup_state()
    runtime = get_task_manager().runtime_status()
    checks: dict[str, dict[str, Any]] = {
        "process": {"ok": True, "detail": "alive"},
        "database": {"ok": bool(startup.get("database_ready")), "detail": {"cached": True}},
        "auth": {"ok": bool(startup.get("auth_ready")), "detail": {"cached": True}},
        "registry": {"ok": bool(startup.get("registry_ready") or role in {"worker", "reducer"}), "detail": {"cached": True}},
    }

    scheduler_ok = True
    reducer_ok = True
    if role in {"worker", "all"}:
        scheduler_ok, scheduler_detail = _scheduler_readiness()
        checks["scheduler"] = {"ok": scheduler_ok, "detail": scheduler_detail}
    if role in {"reducer", "all"}:
        reducer_ok, reducer_detail = _reducer_readiness()
        checks["reducer"] = {"ok": reducer_ok, "detail": reducer_detail}

    startup_ready = bool(startup.get("startup_ready"))
    shutting_down = bool(startup.get("shutting_down"))
    liveness_ok = not shutting_down
    readiness_ok = startup_ready and not shutting_down
    if role in {"worker", "all"}:
        readiness_ok = readiness_ok and scheduler_ok
    if role in {"reducer", "all"}:
        readiness_ok = readiness_ok and reducer_ok
    if role == "api":
        readiness_ok = readiness_ok and bool(startup.get("auth_ready"))

    return {
        "status": "ready" if readiness_ok else ("stopping" if shutting_down else "not_ready"),
        "role": role,
        "started_at": startup.get("started_at") or None,
        "updated_at": time.time(),
        "shutting_down": shutting_down,
        "startup_phase": "ready" if startup_ready and not shutting_down else ("stopping" if shutting_down else "booting"),
        "startup_ready": startup_ready,
        "startup_error": startup.get("startup_error"),
        "last_error": startup.get("startup_error"),
        "liveness_ok": liveness_ok,
        "readiness_ok": readiness_ok,
        "reason": None if readiness_ok else (startup.get("startup_error") or "runtime checks not ready"),
        "checks": checks,
        "runtime": runtime,
    }


def collect_liveness() -> dict[str, Any]:
    snapshot = collect_probe_snapshot()
    return {
        "status": "ok" if snapshot["liveness_ok"] else "degraded",
        "role": snapshot["role"],
        "scheduler_enabled": snapshot["role"] != "api" and bool(get_config().scheduler.enabled),
        "liveness_ok": snapshot["liveness_ok"],
        "readiness_ok": snapshot["readiness_ok"],
        "checks": snapshot["checks"],
        "started_at": snapshot["started_at"],
        "updated_at": snapshot["updated_at"],
        "shutting_down": snapshot["shutting_down"],
        "reason": snapshot["reason"],
    }


async def collect_readiness() -> dict[str, object]:
    snapshot = collect_probe_snapshot()
    return {
        "status": "ready" if snapshot["readiness_ok"] else "not_ready",
        "role": snapshot["role"],
        "checks": snapshot["checks"],
        "started_at": snapshot["started_at"],
        "updated_at": snapshot["updated_at"],
        "shutting_down": snapshot["shutting_down"],
        "startup_phase": snapshot["startup_phase"],
        "last_error": snapshot["last_error"],
        "reason": snapshot["reason"],
    }
