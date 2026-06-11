"""Firmware unpacker FastAPI main entry point."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from contextlib import suppress
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_app_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_app_dir)
for candidate in (_project_root, _app_dir):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request as FastAPIRequest

from app.api.firmware import router as firmware_router
from app.build_info import build_service_meta
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.logging_utils import configure_container_logging
from app.probe_server import ThreadedProbeServer
from app.runtime import runtime_snapshot, start_runtime, stop_runtime
from app.services.observability import record_api_request


configure_container_logging("secflow-app-firmware-unpacker")
logger = logging.getLogger(__name__)
_probe_server: ThreadedProbeServer | None = None


def _external_probe_process_enabled() -> bool:
    return str(os.environ.get("SECFLOW_EXTERNAL_PROBE_PROCESS", "")).strip().lower() in {"1", "true", "yes", "on"}


def _probe_payload() -> dict[str, object]:
    runtime = runtime_snapshot()
    running = bool(runtime.get("running"))
    shutting_down = bool(runtime.get("shutting_down"))
    ready = running and not shutting_down and not str(runtime.get("startup_error") or "").strip()
    return {
        "service": "secflow-app-firmware-unpacker",
        "started_at": runtime.get("started_at"),
        "updated_at": time.time(),
        "shutting_down": shutting_down,
        "startup_phase": "ready" if ready else ("stopping" if shutting_down else "booting"),
        "liveness_ok": running and not shutting_down,
        "readiness_ok": ready,
        "last_error": runtime.get("startup_error"),
        "reason": None if ready else (runtime.get("startup_error") or "runtime not ready"),
        "checks": {
            "registry": {"ok": bool(runtime.get("registry"))},
            "dispatcher": {"ok": bool(runtime.get("dispatcher"))},
            "worker_heartbeat": {"ok": bool(runtime.get("worker_heartbeat"))},
            "cluster_maintenance": {"ok": bool(runtime.get("cluster_maintenance"))},
            "cleanup_loop": {"ok": bool(runtime.get("cleanup_loop"))},
            "evolution_loop": {"ok": bool(runtime.get("evolution_loop"))},
        },
        "role": ",".join(runtime.get("roles") or []),
        "roles": runtime.get("roles") or [],
        **build_service_meta(),
    }


def _ensure_probe_server_started() -> None:
    global _probe_server
    if _probe_server is not None:
        _probe_server.start()
        return
    config = get_config()
    port = int(
        os.environ.get(
            "SECFLOW_FIRMWARE_UNPACKER_PROBE_PORT",
            os.environ.get("SECFLOW_PROBE_PORT", str(int(config.app.port) + 1000)),
        )
    )
    _probe_server = ThreadedProbeServer(
        host=config.app.host,
        port=port,
        payload_provider=_probe_payload,
        health_paths=("/health", "/api/app/firmware-unpacker/health"),
        ready_paths=("/ready", "/api/app/firmware-unpacker/ready"),
    )
    _probe_server.start()


def _stop_probe_server() -> None:
    global _probe_server
    if _probe_server is not None:
        with suppress(Exception):
            _probe_server.stop()
        _probe_server = None


def verify_auth_service_or_exit() -> None:
    """Validate auth service health and the configured machine token."""
    config = get_config().auth_service

    if not config.enabled:
        return

    machine_token = getattr(config, "service_machine_token", None)
    if not machine_token:
        logger.error("未配置 auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    try:
        with urlopen(config.health_url, timeout=config.timeout) as response:
            if response.status != 200:
                logger.error("认证服务健康检查失败: status=%s", response.status)
                sys.exit(1)
    except Exception as exc:
        logger.error("认证服务不可达: %s", exc)
        sys.exit(1)

    try:
        request = Request(config.validate_url, method="POST")
        request.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(request, timeout=config.timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            if response.status != 200:
                logger.error("机机 Token 校验失败: status=%s body=%s", response.status, body)
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error("机机 Token 类型异常: token_type=%s", payload.get("token_type"))
                sys.exit(1)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        logger.error("机机 Token 校验失败: status=%s body=%s", exc.code, body)
        sys.exit(1)
    except URLError as exc:
        logger.error("认证服务不可达，机机 Token 校验失败: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("机机 Token 校验失败: %s", exc)
        sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        config = load_config()
        logging.getLogger().setLevel(
            getattr(logging, config.logging.level.upper(), logging.INFO)
        )
        if not _external_probe_process_enabled():
            _ensure_probe_server_started()
        await start_runtime()
        logger.info("secflow-app-firmware-unpacker started")
    except Exception as exc:
        logger.exception("service startup failed: %s", exc)
        sys.exit(1)

    yield

    try:
        await stop_runtime()
    except Exception as exc:
        logger.warning("service shutdown warning: %s", exc)
    finally:
        if not _external_probe_process_enabled():
            _stop_probe_server()


app = FastAPI(
    title="SecFlow Firmware Unpacker",
    description="固件解包任务管理服务",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def prometheus_http_middleware(request: FastAPIRequest, call_next):
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        path = getattr(route, "path", None) or request.url.path
        record_api_request(
            method=request.method,
            path=str(path),
            status_code=status_code,
            duration_seconds=time.perf_counter() - started,
        )


setup_exception_handlers(app)
app.include_router(firmware_router)


if __name__ == "__main__":
    from app.start import build_gunicorn_argv
    import gunicorn.app.wsgiapp

    sys.argv = build_gunicorn_argv()
    gunicorn.app.wsgiapp.run()
