#!/usr/bin/env python3
"""Startup script — launches Gunicorn with a threaded WSGI adapter."""

from __future__ import annotations

import multiprocessing
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
    pod_cpu_millis = _env_int("POD_CPU_LIMIT_MILLICORES", 0)
    if pod_cpu_millis > 0:
        return max(2, min(4, pod_cpu_millis // 500))
    cpu_count = max(1, multiprocessing.cpu_count())
    return max(2, min(4, cpu_count))


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
    gunicorn.app.wsgiapp.run()
