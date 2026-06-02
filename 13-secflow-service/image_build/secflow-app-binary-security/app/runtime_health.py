"""Lightweight runtime health and readiness checks."""

from __future__ import annotations

import os
import time
from typing import Any

from app.config import get_config
from app.model import get_engine
from app.service.task_manager import get_task_manager
from sqlalchemy import text


def _service_role() -> str:
    raw_role = os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or ""
    normalized = str(raw_role).strip().lower()
    return normalized if normalized in {"api", "worker", "reducer"} else "all"


def collect_liveness() -> dict[str, Any]:
    role = _service_role()
    scheduler_enabled = role != "api" and bool(get_config().scheduler.enabled)
    return {
        "status": "ok",
        "role": role,
        "scheduler_enabled": scheduler_enabled,
        "checks": {
            "process": {"ok": True, "detail": "alive"},
        },
    }


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
    return running and not missing, {
        "enabled": True,
        "running": running,
        "loops": loops,
        "loop_details": loop_details,
        "missing_loops": missing,
    }


def _db_ready_check() -> dict[str, Any]:
    started_at = time.perf_counter()
    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
    latency_ms = max(0.0, (time.perf_counter() - started_at) * 1000.0)
    return {"ok": True, "detail": {"ping": "ok", "latency_ms": round(latency_ms, 3)}}


async def collect_readiness() -> dict[str, object]:
    import asyncio

    role = _service_role()
    checks: dict[str, dict[str, Any]] = {
        "process": {"ok": True, "detail": "alive"},
    }

    if role in {"worker", "all"}:
        scheduler_ok, scheduler_detail = _scheduler_readiness()
        checks["scheduler"] = {"ok": scheduler_ok, "detail": scheduler_detail}
    if role in {"reducer", "all"}:
        reducer_ok, reducer_detail = _reducer_readiness()
        checks["reducer"] = {"ok": reducer_ok, "detail": reducer_detail}
    try:
        checks["database"] = await asyncio.to_thread(_db_ready_check)
    except Exception as exc:
        checks["database"] = {"ok": False, "detail": {"ping": "failed", "error": str(exc)}}

    status = "ready" if all(item.get("ok") for item in checks.values()) else "not_ready"
    return {
        "status": status,
        "role": role,
        "checks": checks,
    }
