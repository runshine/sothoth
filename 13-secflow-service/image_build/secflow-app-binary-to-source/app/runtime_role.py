from __future__ import annotations

import os


def get_service_role() -> str:
    raw_role = os.environ.get("SECFLOW_B2S_ROLE") or os.environ.get("ROLE") or ""
    normalized = str(raw_role).strip().lower()
    if normalized == "manager":
        return "api"
    return normalized if normalized in {"api", "worker"} else "all"
