from __future__ import annotations

from app.runtime_bootstrap import get_runtime_bootstrap


def build_runtime_status() -> dict[str, object]:
    status = get_runtime_bootstrap().status()
    status["ready"] = get_runtime_bootstrap().ready()
    return status