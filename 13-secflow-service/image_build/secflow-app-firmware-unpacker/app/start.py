#!/usr/bin/env python3
"""Startup script for the threaded Gunicorn WSGI adapter."""

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
    # Task runners are subprocesses, but concurrency limits are calculated per
    # service process. Keep one Gunicorn worker by default to avoid Pod-level
    # overcommit from multiple independent dispatchers.
    return 1


def build_gunicorn_argv() -> list[str]:
    config = get_config()
    workers = _env_int("GUNICORN_WORKERS", _default_workers())
    threads = _env_int("GUNICORN_THREADS", 512)
    timeout = _env_int("GUNICORN_TIMEOUT", 600)
    keepalive = _env_int("GUNICORN_KEEPALIVE", 10)

    return [
        "gunicorn",
        "--bind",
        f"{config.app.host}:{config.app.port}",
        "--workers",
        str(workers),
        "--threads",
        str(threads),
        "--worker-class",
        "gthread",
        "--timeout",
        str(timeout),
        "--keep-alive",
        str(keepalive),
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "--capture-output",
        "app.wsgi:app",
    ]


if __name__ == "__main__":
    import gunicorn.app.wsgiapp

    sys.argv = build_gunicorn_argv()
    gunicorn.app.wsgiapp.run()
