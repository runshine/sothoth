from __future__ import annotations

import json
from pathlib import Path

from app.config import config


BUILD_META_PATH = Path(__file__).resolve().parents[1] / "build_meta.json"


def _read_build_version() -> str | None:
    try:
        payload = json.loads(BUILD_META_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = str(payload.get("build_version") or "").strip()
    return value or None


def build_service_meta() -> dict[str, str | None]:
    return {
        "service_id": getattr(config, "service_id", "secflow-platform-auth"),
        "service_name": getattr(config, "service_name", "SecFlow Auth Service"),
        "build_version": _read_build_version(),
    }
