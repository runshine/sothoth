from __future__ import annotations

import json
from pathlib import Path

from app.config import get_config


BUILD_META_PATH = Path(__file__).resolve().parents[1] / "build_meta.json"


def _read_build_version() -> str | None:
    try:
        payload = json.loads(BUILD_META_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = str(payload.get("build_version") or "").strip()
    return value or None


def build_service_meta() -> dict[str, str | None]:
    registry = get_config().registry
    return {
        "service_id": registry.service_id,
        "service_name": registry.service_name,
        "build_version": _read_build_version(),
    }
