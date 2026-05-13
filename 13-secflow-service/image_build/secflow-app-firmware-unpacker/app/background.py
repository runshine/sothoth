#!/usr/bin/env python3
"""Dedicated background runtime entrypoint for dispatcher and cleanup roles."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import threading
from contextlib import suppress
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent

os.environ["PYTHONPATH"] = str(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.config import get_config, get_runtime_roles, load_config
from app.logging_utils import configure_container_logging
from app.runtime import start_runtime, stop_runtime


configure_container_logging("secflow-app-firmware-unpacker")
logger = logging.getLogger(__name__)


class _RuntimeState:
    def __init__(self) -> None:
        self.ready = threading.Event()
        self.stopping = threading.Event()
        self.error_lock = threading.Lock()
        self.last_error: str | None = None

    def set_error(self, error_message: str | None) -> None:
        with self.error_lock:
            self.last_error = str(error_message or "").strip() or None

    def snapshot(self) -> dict[str, object]:
        with self.error_lock:
            return {
                "status": "stopping" if self.stopping.is_set() else ("ready" if self.ready.is_set() else "starting"),
                "roles": sorted(get_runtime_roles()),
                "error": self.last_error,
            }


_STATE = _RuntimeState()


class _HealthHandler(BaseHTTPRequestHandler):
    server_version = "secflow-fw-background/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path not in {
            "/api/app/firmware-unpacker/health",
            "/api/app/firmware-unpacker/ready",
        }:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        payload = _STATE.snapshot()
        is_ready_path = self.path.endswith("/ready")
        status = HTTPStatus.OK if (not is_ready_path or _STATE.ready.is_set()) else HTTPStatus.SERVICE_UNAVAILABLE
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        logger.debug("background health server: " + format, *args)


def _start_health_server() -> ThreadingHTTPServer:
    config = get_config()
    server = ThreadingHTTPServer((config.app.host, int(config.app.port)), _HealthHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        name="fw-background-health",
        kwargs={"poll_interval": 0.5},
        daemon=True,
    )
    thread.start()
    logger.info("background health server started on %s:%s", config.app.host, config.app.port)
    return server


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def _handle_signal(signum: int, _frame: object) -> None:
        logger.info("received signal %s, stopping background runtime", signum)
        _STATE.stopping.set()
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _handle_signal)


def main() -> int:
    stop_event = threading.Event()
    _install_signal_handlers(stop_event)

    health_server: ThreadingHTTPServer | None = None
    try:
        config = load_config()
        logging.getLogger().setLevel(
            getattr(logging, config.logging.level.upper(), logging.INFO)
        )
        health_server = _start_health_server()
        asyncio.run(start_runtime())
        _STATE.ready.set()
        logger.info("firmware unpacker background runtime started with roles: %s", ",".join(sorted(get_runtime_roles())))
        stop_event.wait()
        return 0
    except KeyboardInterrupt:
        _STATE.stopping.set()
        return 0
    except Exception as exc:
        _STATE.set_error(str(exc))
        logger.exception("background runtime failed: %s", exc)
        return 1
    finally:
        _STATE.ready.clear()
        _STATE.stopping.set()
        with suppress(Exception):
            asyncio.run(stop_runtime())
        if health_server is not None:
            with suppress(Exception):
                health_server.shutdown()
            with suppress(Exception):
                health_server.server_close()
            logger.info("background health server stopped")
