#!/usr/bin/env python3
"""Dedicated background runtime entrypoint for dispatcher and cleanup roles."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent

os.environ["PYTHONPATH"] = str(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.config import get_config, get_runtime_roles, load_config
from app.logging_utils import configure_container_logging
from app.probe_server import ThreadedProbeServer
from app.runtime import runtime_snapshot, start_runtime, stop_runtime


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
_PROBE_SERVER: ThreadedProbeServer | None = None


def _probe_payload() -> dict[str, object]:
    runtime = runtime_snapshot()
    ready = _STATE.ready.is_set() and bool(runtime.get("running")) and not _STATE.stopping.is_set() and not str(runtime.get("startup_error") or "").strip()
    return {
        "status": "ready" if ready else ("stopping" if _STATE.stopping.is_set() else "starting"),
        "role": ",".join(sorted(get_runtime_roles())),
        "roles": sorted(get_runtime_roles()),
        "error": _STATE.last_error or runtime.get("startup_error"),
        "service": "secflow-app-firmware-unpacker",
        "started_at": runtime.get("started_at"),
        "updated_at": time.time(),
        "shutting_down": _STATE.stopping.is_set() or bool(runtime.get("shutting_down")),
        "startup_phase": "ready" if ready else ("stopping" if _STATE.stopping.is_set() else "booting"),
        "liveness_ok": bool(runtime.get("running")) and not _STATE.stopping.is_set(),
        "readiness_ok": ready,
        "last_error": _STATE.last_error or runtime.get("startup_error"),
        "reason": None if ready else (_STATE.last_error or runtime.get("startup_error") or "background runtime not ready"),
        "checks": {
            "dispatcher": {"ok": bool(runtime.get("dispatcher"))},
            "worker_heartbeat": {"ok": bool(runtime.get("worker_heartbeat"))},
            "cluster_maintenance": {"ok": bool(runtime.get("cluster_maintenance"))},
            "cleanup_loop": {"ok": bool(runtime.get("cleanup_loop"))},
            "evolution_loop": {"ok": bool(runtime.get("evolution_loop"))},
        },
    }


def _start_probe_server() -> None:
    global _PROBE_SERVER
    if _PROBE_SERVER is not None:
        _PROBE_SERVER.start()
        return
    config = get_config()
    port = int(os.environ.get("SECFLOW_FIRMWARE_UNPACKER_PROBE_PORT", str(int(config.app.port) + 1000)))
    _PROBE_SERVER = ThreadedProbeServer(
        host=config.app.host,
        port=port,
        payload_provider=_probe_payload,
        health_paths=("/health", "/api/app/firmware-unpacker/health"),
        ready_paths=("/ready", "/api/app/firmware-unpacker/ready"),
    )
    _PROBE_SERVER.start()


def _stop_probe_server() -> None:
    global _PROBE_SERVER
    if _PROBE_SERVER is not None:
        with suppress(Exception):
            _PROBE_SERVER.stop()
        _PROBE_SERVER = None


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

    try:
        config = load_config()
        logging.getLogger().setLevel(
            getattr(logging, config.logging.level.upper(), logging.INFO)
        )
        _start_probe_server()
        asyncio.run(start_runtime())
        _STATE.ready.set()
        _STATE.set_error(None)
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
        _stop_probe_server()
