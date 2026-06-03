#!/usr/bin/env python3
"""Startup script for the firmware unpacker API process."""

from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent

os.environ["PYTHONPATH"] = str(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.config import get_config


def _env_int(name: str, default: int) -> int:
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def build_uvicorn_argv() -> list[str]:
    config = get_config()
    timeout_keep_alive = _env_int("UVICORN_TIMEOUT_KEEP_ALIVE", 10)
    backlog = _env_int("UVICORN_BACKLOG", 2048)

    return [
        "uvicorn",
        "app.main:app",
        "--host",
        str(config.app.host),
        "--port",
        str(config.app.port),
        "--timeout-keep-alive",
        str(timeout_keep_alive),
        "--backlog",
        str(backlog),
        "--proxy-headers",
        "--no-server-header",
    ]


def main() -> int:
    import uvicorn

    sys.argv = build_uvicorn_argv()
    uvicorn.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
