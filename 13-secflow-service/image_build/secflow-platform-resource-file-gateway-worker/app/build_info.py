from __future__ import annotations

import json
from pathlib import Path


BUILD_META_PATH = Path(__file__).resolve().parents[1] / "build_meta.json"
SERVICE_ID = "secflow-platform-resource-file-gateway-worker"
SERVICE_NAME = "Resource File Gateway Worker"


def _read_build_version() -> str | None:
    try:
        payload = json.loads(BUILD_META_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = str(payload.get("build_version") or "").strip()
    return value or None


def build_service_meta() -> dict[str, str | None]:
    return {
        "service_id": SERVICE_ID,
        "service_name": SERVICE_NAME,
        "build_version": _read_build_version(),
    }
