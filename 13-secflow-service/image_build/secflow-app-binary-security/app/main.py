"""SecFlow Binary Security orchestrator service."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager
from contextlib import suppress
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request as FastAPIRequest
from fastapi.responses import Response

from app.api.tasks import router
from app.build_info import build_service_meta
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.metrics_aggregate import get_metrics_aggregator
from app.metrics_summary import build_ai_summary, build_binary_security_observability_summary, build_rest_api_summary, parse_prometheus_metrics
from app.model import get_engine, init_database
from app.observability import (
    normalize_http_route,
    observe_http_request,
    observe_http_request_inflight,
    observe_auth_token_validation,
    observe_downstream_request,
    render_metrics,
)
from app.probe_server import ThreadedProbeServer
from app.runtime_health import collect_probe_snapshot, mark_startup_state
from app.service.http_client import close_all_async_clients
from app.service.reducer_metrics_snapshot import close_reducer_metrics_snapshot_store
from app.service.reducer_metrics_snapshot import get_reducer_metrics_snapshot_store
from app.service.registry import get_registry_service
from app.service.task_queue import close_task_queue
from app.service.task_manager import get_task_manager
from app.time_utils import UTC_PLUS_8


def _utc_plus_8_log_converter(timestamp: float, *_unused):
    return datetime.fromtimestamp(timestamp, UTC_PLUS_8).timetuple()


logging.Formatter.converter = staticmethod(_utc_plus_8_log_converter)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)
_probe_server: ThreadedProbeServer | None = None


def _emit_startup_banner(*, cfg) -> None:
    build_meta = build_service_meta()
    app_cfg = getattr(cfg, "app", None)
    lines = [
        "",
        "=" * 88,
        "SecFlow Binary Security Boot Banner",
        "=" * 88,
        f"service_id={build_meta.get('service_id') or 'secflow-app-binary-security'}",
        f"service_name={build_meta.get('service_name') or 'SecFlow Binary Security'}",
        f"build_version={build_meta.get('build_version') or 'unknown'}",
        f"role={_service_role()} scheduler_enabled={_scheduler_enabled()} registry_enabled={_registry_enabled()}",
        f"listen={getattr(app_cfg, 'host', '0.0.0.0')}:{getattr(app_cfg, 'port', '8080')} "
        f"debug={bool(getattr(app_cfg, 'debug', False))} "
        f"keepalive={getattr(app_cfg, 'timeout_keep_alive_seconds', None)}",
        f"database=mysql+pymysql://{cfg.database.host}:{cfg.database.port}/{cfg.database.name}",
        f"redis_url={cfg.queue.redis_url}",
        f"task_queue_key={cfg.queue.task_queue_key}",
        f"external_probe_process={_external_probe_process_enabled()} probe_port={os.environ.get('SECFLOW_PROBE_PORT', '18080')}",
        f"probe_pid_file={os.environ.get('SECFLOW_MAIN_PID_FILE', '/tmp/secflow-main.pid')}",
        f"probe_started_at_file={os.environ.get('SECFLOW_MAIN_STARTED_AT_FILE', '/tmp/secflow-main.started_at')}",
        f"auth_service={cfg.auth_service.host}:{cfg.auth_service.port} timeout={cfg.auth_service.timeout}s",
        f"pod_name={os.environ.get('POD_NAME') or '-'} pod_ip={os.environ.get('POD_IP') or '-'} pod_uid={os.environ.get('POD_UID') or '-'}",
        "=" * 88,
    ]
    banner = "\n".join(lines)
    print(banner, file=sys.stdout, flush=True)
    logger.info("Binary Security startup banner\n%s", banner)


def _log_startup_step(step: str, *, detail: str | None = None) -> None:
    suffix = f" detail={detail}" if detail else ""
    logger.info("Binary Security startup step=%s%s", str(step or "unknown").strip(), suffix)


def _log_startup_step_done(step: str, *, detail: str | None = None) -> None:
    suffix = f" detail={detail}" if detail else ""
    logger.info("Binary Security startup step=%s status=ok%s", str(step or "unknown").strip(), suffix)


def _external_probe_process_enabled() -> bool:
    return str(os.environ.get("SECFLOW_EXTERNAL_PROBE_PROCESS", "")).strip().lower() in {"1", "true", "yes", "on"}


def _external_probe_started_at_file() -> Path:
    return Path(os.environ.get("SECFLOW_MAIN_STARTED_AT_FILE", "/tmp/secflow-main.started_at"))


def _mark_external_probe_startup_complete() -> None:
    if not _external_probe_process_enabled():
        return
    _external_probe_started_at_file().write_text(f"{time.time()}\n", encoding="utf-8")


def _service_role() -> str:
    raw_role = os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or ""
    normalized = str(raw_role).strip().lower()
    return normalized if normalized in {"api", "worker", "reducer"} else "all"


def _scheduler_enabled() -> bool:
    env_value = os.environ.get("SECFLOW_BINARY_SECURITY_ENABLE_SCHEDULER")
    if env_value is not None:
        return str(env_value).strip().lower() in {"1", "true", "yes", "on"}
    role = _service_role()
    if role == "api":
        return False
    if role in {"worker", "reducer"}:
        return True
    return bool(get_config().scheduler.enabled)


def _registry_enabled() -> bool:
    role = _service_role()
    if role in {"worker", "reducer"}:
        return False
    return bool(get_config().registry.enabled)


def verify_auth_service_or_exit() -> None:
    cfg = get_config().auth_service
    machine_token = cfg.service_machine_token
    if not machine_token:
        logger.error("未配置 auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    health_url = f"http://{cfg.host}:{cfg.port}/api/auth/health"
    try:
        started = time.perf_counter()
        with urlopen(health_url, timeout=cfg.timeout) as response:
            if response.status != 200:
                observe_downstream_request(
                    service="auth_service",
                    method="GET",
                    operation="health",
                    status=str(response.status),
                    duration_seconds=time.perf_counter() - started,
                )
                logger.error("Auth 服务健康检查失败: status=%s", response.status)
                sys.exit(1)
            observe_downstream_request(
                service="auth_service",
                method="GET",
                operation="health",
                status=str(response.status),
                duration_seconds=time.perf_counter() - started,
            )
    except Exception as exc:
        observe_downstream_request(
            service="auth_service",
            method="GET",
            operation="health",
            status="error",
            duration_seconds=None,
        )
        logger.error("Auth 服务不可达: %s", exc)
        sys.exit(1)

    try:
        request = Request(cfg.validate_url, method="POST")
        request.add_header("Authorization", f"Bearer {machine_token}")
        started = time.perf_counter()
        with urlopen(request, timeout=cfg.timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            if response.status != 200:
                observe_auth_token_validation(result="failed", source="startup")
                observe_downstream_request(
                    service="auth_service",
                    method="POST",
                    operation="validate_machine_token",
                    status=str(response.status),
                    duration_seconds=time.perf_counter() - started,
                )
                logger.error("机机 Token 校验失败: status=%s body=%s", response.status, body)
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                observe_auth_token_validation(result="invalid_type", source="startup")
                logger.error("机机 Token 类型异常: token_type=%s", payload.get("token_type"))
                sys.exit(1)
            observe_auth_token_validation(result="success", source="startup")
            observe_downstream_request(
                service="auth_service",
                method="POST",
                operation="validate_machine_token",
                status=str(response.status),
                duration_seconds=time.perf_counter() - started,
            )
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        observe_auth_token_validation(result="failed", source="startup")
        observe_downstream_request(
            service="auth_service",
            method="POST",
            operation="validate_machine_token",
            status=str(exc.code),
            duration_seconds=None,
        )
        logger.error("机机 Token 校验失败: status=%s body=%s", exc.code, body)
        sys.exit(1)
    except URLError as exc:
        observe_auth_token_validation(result="connect_error", source="startup")
        observe_downstream_request(
            service="auth_service",
            method="POST",
            operation="validate_machine_token",
            status="connect_error",
            duration_seconds=None,
        )
        logger.error("Auth 服务不可达，机机 Token 校验失败: %s", exc)
        sys.exit(1)
    except Exception as exc:
        observe_auth_token_validation(result="error", source="startup")
        observe_downstream_request(
            service="auth_service",
            method="POST",
            operation="validate_machine_token",
            status="error",
            duration_seconds=None,
        )
        logger.error("机机 Token 校验失败: %s", exc)
        sys.exit(1)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("正在启动 SecFlow Binary Security 服务...")
    mark_startup_state(shutting_down=False, startup_ready=False, startup_error=None)
    startup_step = "bootstrap"
    try:
        startup_step = "load_config"
        _log_startup_step(startup_step)
        load_config()
        cfg = get_config()
        _emit_startup_banner(cfg=cfg)
        _log_startup_step_done(
            startup_step,
            detail=(
                f"role={_service_role()} scheduler_enabled={_scheduler_enabled()} "
                f"registry_enabled={_registry_enabled()} db_host={cfg.database.host}:{cfg.database.port} "
                f"redis_url={cfg.queue.redis_url}"
            ),
        )

        startup_step = "probe_server"
        if not _external_probe_process_enabled():
            _log_startup_step(startup_step, detail="mode=embedded")
            _ensure_probe_server_started()
            _log_startup_step_done(startup_step, detail="mode=embedded")
        else:
            _log_startup_step_done(startup_step, detail="mode=external")

        startup_step = "init_database"
        _log_startup_step(
            startup_step,
            detail=f"engine=mysql+pymysql://{cfg.database.host}:{cfg.database.port}/{cfg.database.name}",
        )
        init_database()
        _log_startup_step_done(startup_step)

        startup_step = "database_ping"
        _log_startup_step(startup_step, detail="sql=SELECT 1")
        mark_startup_state(database_ready=True)
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        _log_startup_step_done(startup_step)

        startup_step = "verify_auth"
        _log_startup_step(
            startup_step,
            detail=f"auth_host={cfg.auth_service.host}:{cfg.auth_service.port} timeout={cfg.auth_service.timeout}s",
        )
        verify_auth_service_or_exit()
        mark_startup_state(auth_ready=True)
        _log_startup_step_done(startup_step)

        if _registry_enabled():
            startup_step = "registry_start"
            _log_startup_step(
                startup_step,
                detail=f"menu_service_url={cfg.registry.menu_service_url} service_id={cfg.registry.service_id}",
            )
            await get_registry_service().start()
            mark_startup_state(registry_ready=True)
            _log_startup_step_done(startup_step)
        if _scheduler_enabled():
            startup_step = "task_manager_start"
            _log_startup_step(
                startup_step,
                detail=f"role={_service_role()} queue_redis={cfg.queue.redis_url} task_queue_key={cfg.queue.task_queue_key}",
            )
            await get_task_manager().start()
            _log_startup_step_done(startup_step)
        mark_startup_state(startup_ready=True, startup_error=None)
        _mark_external_probe_startup_complete()
    except Exception as exc:
        mark_startup_state(startup_ready=False, startup_error=str(exc))
        logger.exception(
            "Binary Security 服务启动失败: step=%s role=%s scheduler_enabled=%s registry_enabled=%s error=%s",
            startup_step,
            _service_role(),
            _scheduler_enabled(),
            _registry_enabled(),
            exc,
        )
        sys.exit(1)

    logger.info("SecFlow Binary Security 服务启动成功")
    yield
    try:
        mark_startup_state(shutting_down=True, startup_ready=False)
        if _scheduler_enabled():
            await get_task_manager().stop()
        if _registry_enabled():
            await get_registry_service().stop()
        await close_task_queue()
        await close_reducer_metrics_snapshot_store()
        await close_all_async_clients()
    except Exception as exc:
        logger.warning("Binary Security 服务关闭警告: %s", exc)
    finally:
        mark_startup_state(registry_ready=False, auth_ready=False, database_ready=False)
        if not _external_probe_process_enabled():
            _stop_probe_server()


app = FastAPI(
    title="SecFlow Binary Security",
    description="统一串联固件解包、系统分析、反编译、入口分析、数据流分析和漏洞扫描的编排微服务",
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


def _probe_payload() -> dict[str, object]:
    snapshot = collect_probe_snapshot()
    return {
        "service": "secflow-app-binary-security",
        **snapshot,
        **build_service_meta(),
    }


def _ensure_probe_server_started() -> None:
    global _probe_server
    if _probe_server is not None:
        _probe_server.start()
        return
    port = int(os.environ.get("SECFLOW_BINARY_SECURITY_PROBE_PORT", "18080"))
    _probe_server = ThreadedProbeServer(
        host="0.0.0.0",
        port=port,
        payload_provider=_probe_payload,
        health_paths=("/health", "/api/app/binary-security/health"),
        ready_paths=("/ready", "/api/app/binary-security/ready"),
    )
    _probe_server.start()


def _stop_probe_server() -> None:
    global _probe_server
    if _probe_server is not None:
        with suppress(Exception):
            _probe_server.stop()
        _probe_server = None


@app.middleware("http")
async def prometheus_http_middleware(request: FastAPIRequest, call_next):
    import time

    started = time.perf_counter()
    status_code = 500
    route = request.scope.get("route")
    path = getattr(route, "path", None) or request.url.path
    normalized_route = normalize_http_route(str(path))
    observe_http_request_inflight(request.method, normalized_route, 1)
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        observe_http_request(
            method=request.method,
            path=str(path),
            status_code=status_code,
            duration_seconds=time.perf_counter() - started,
        )
        observe_http_request_inflight(request.method, normalized_route, -1)


@app.middleware("http")
async def service_role_route_guard(request: FastAPIRequest, call_next):
    role = _service_role()
    if role in {"worker", "reducer"}:
        path = request.url.path
        allowed = (
            path in {
                "/api/app/binary-security/health",
                "/api/app/binary-security/ready",
                "/api/app/binary-security/metrics",
                "/api/app/binary-security/metrics/aggregate",
                "/api/app/binary-security/metrics/reducer",
                "/metrics",
                "/openapi.json",
            }
            or path.startswith("/docs")
            or path.startswith("/redoc")
        )
        if not allowed:
            return Response(
                content=json.dumps({"detail": "not found"}),
                media_type="application/json",
                status_code=404,
            )
    return await call_next(request)


@app.get("/metrics", include_in_schema=False)
@app.get("/api/app/binary-security/metrics", include_in_schema=False)
async def metrics_endpoint():
    payload, content_type = render_metrics()
    return Response(content=payload, media_type=content_type)


@app.get("/api/app/binary-security/metrics/aggregate", include_in_schema=False)
async def aggregate_metrics_endpoint():
    started = time.perf_counter()
    try:
        aggregated = await get_metrics_aggregator().aggregate()
    except Exception as exc:
        observe_downstream_request(
            service="binary_security_metrics",
            method="GET",
            operation="aggregate",
            status="error",
            duration_seconds=None,
        )
        raise HTTPException(status_code=502, detail=f"Aggregate metrics generation failed: {exc}") from exc
    observe_downstream_request(
        service="binary_security_metrics",
        method="GET",
        operation="aggregate",
        status="200",
        duration_seconds=time.perf_counter() - started,
    )
    return Response(content=aggregated.payload, media_type=aggregated.content_type)


@app.get("/api/app/binary-security/metrics/summary", include_in_schema=False)
async def metrics_summary_endpoint():
    aggregated = await get_metrics_aggregator().aggregate()
    rows = parse_prometheus_metrics(aggregated.payload.decode("utf-8", errors="ignore"))
    return build_binary_security_observability_summary(rows)


@app.get("/api/app/binary-security/metrics/rest-api-summary", include_in_schema=False)
async def metrics_rest_api_summary_endpoint():
    aggregated = await get_metrics_aggregator().aggregate()
    rows = parse_prometheus_metrics(aggregated.payload.decode("utf-8", errors="ignore"))
    return build_rest_api_summary(rows)


@app.get("/api/app/binary-security/metrics/ai-summary", include_in_schema=False)
async def metrics_ai_summary_endpoint():
    aggregated = await get_metrics_aggregator().aggregate()
    rows = parse_prometheus_metrics(aggregated.payload.decode("utf-8", errors="ignore"))
    return build_ai_summary(rows, coverage_text="编排器 AI 指标聚合，覆盖调度、状态同步与下游协同相关调用。")


@app.get("/api/app/binary-security/metrics/reducer", include_in_schema=False)
async def reducer_metrics_endpoint():
    started = time.perf_counter()
    try:
        fallback_payload = None
        if _service_role() == "reducer":
            fallback_payload = render_metrics()[0].decode("utf-8", errors="ignore")
        payload, content_type = await get_reducer_metrics_snapshot_store().render_metrics(
            fallback_payload=fallback_payload
        )
    except Exception as exc:
        observe_downstream_request(
            service="binary_security_reducer",
            method="GET",
            operation="metrics_snapshot",
            status="error",
            duration_seconds=None,
        )
        raise HTTPException(status_code=502, detail=f"Reducer metrics snapshot failed: {exc}") from exc
    observe_downstream_request(
        service="binary_security_reducer",
        method="GET",
        operation="metrics_snapshot",
        status="200",
        duration_seconds=time.perf_counter() - started,
    )
    return Response(content=payload, media_type=content_type)

setup_exception_handlers(app)
app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
        timeout_keep_alive=config.app.timeout_keep_alive_seconds,
    )
