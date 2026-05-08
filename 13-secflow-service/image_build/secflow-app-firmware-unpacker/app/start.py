#!/usr/bin/env python3
"""Startup script — launches Gunicorn with an ASGI worker."""

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


def _default_workers() -> int:
    # Task cancel hooks live in-process. Keep a single Gunicorn worker so
    # runtime cancellation requests always reach the executing task thread.
    return 1


if __name__ == "__main__":
    import gunicorn.app.wsgiapp

    config = get_config()
    workers = _env_int("GUNICORN_WORKERS", _default_workers())
    threads = _env_int("GUNICORN_THREADS", 8)
    timeout = _env_int("GUNICORN_TIMEOUT", 600)
    keepalive = _env_int("GUNICORN_KEEPALIVE", 10)

    sys.argv = [
        "gunicorn",
        "--bind",
        f"{config.app.host}:{config.app.port}",
        "--workers",
        str(workers),
        "--threads",
        str(threads),
        "--worker-class",
        "uvicorn.workers.UvicornWorker",
        "--timeout",
        str(timeout),
        "--keep-alive",
        str(keepalive),
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "--capture-output",
        "app.main:app",
    ]
    gunicorn.app.wsgiapp.run()
