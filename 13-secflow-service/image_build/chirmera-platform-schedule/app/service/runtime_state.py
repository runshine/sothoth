"""Runtime readiness state."""

from __future__ import annotations


_state = {
    "startup_ready": False,
    "startup_error": None,
    "shutting_down": False,
    "database_ready": False,
    "redis_ready": False,
    "auth_ready": False,
    "registry_ready": False,
    "scheduler_ready": False,
    "worker_ready": False,
    "runtime_role": "all",
}


def mark_state(**kwargs) -> None:
    _state.update(kwargs)


def collect_liveness() -> dict:
    return {
        "status": "ok",
        "service": "chirmera-platform-schedule",
        "checks": {"process": {"ok": True}},
    }


async def collect_readiness() -> dict:
    checks = {
        "database": {"ok": bool(_state["database_ready"])},
        "redis": {"ok": bool(_state["redis_ready"])},
        "auth": {"ok": bool(_state["auth_ready"])},
        "registry": {"ok": bool(_state["registry_ready"])},
        "scheduler": {"ok": bool(_state["scheduler_ready"])},
        "worker": {"ok": bool(_state["worker_ready"])},
    }
    ready = bool(_state["startup_ready"]) and all(item["ok"] for item in checks.values())
    return {
        "status": "ready" if ready else "not_ready",
        "service": "chirmera-platform-schedule",
        "runtime_role": _state["runtime_role"],
        "shutting_down": bool(_state["shutting_down"]),
        "startup_error": _state["startup_error"],
        "checks": checks,
    }
