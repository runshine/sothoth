"""chirmera-platform-schedule main entry."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.config import get_config, load_config
from app.exception import setup_exception_handlers
from app.model import get_engine, init_database
from app.service.http_client import close_all_async_clients
from app.service.redis_runtime import close_redis_runtime, get_redis_runtime
from app.service.registry import get_registry_service
from app.service.runtime_state import mark_state
from app.service.schedule_manager import get_delete_worker_runtime, get_scheduler_runtime, get_user_task_sync_worker_runtime, get_worker_runtime


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def verify_auth_service_or_exit():
    cfg = get_config().auth_service
    machine_token = getattr(cfg, "service_machine_token", None)
    if not machine_token:
        logger.error("未配置auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    base_url = f"http://{cfg.host}:{cfg.port}"
    health_url = f"{base_url}/api/auth/health"
    validate_url = cfg.validate_url

    try:
        with urlopen(health_url, timeout=cfg.timeout) as response:
            if response.status != 200:
                logger.error("Auth服务健康检查失败: status=%s", response.status)
                sys.exit(1)
    except Exception as exc:
        logger.error("Auth服务不可达: %s", exc)
        sys.exit(1)

    try:
        request = Request(validate_url, method="POST")
        request.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(request, timeout=cfg.timeout) as response:
            body = response.read().decode("utf-8", errors="ignore")
            if response.status != 200:
                logger.error("机机Token校验失败: status=%s, body=%s", response.status, body)
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error("机机Token类型异常: token_type=%s", payload.get("token_type"))
                sys.exit(1)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
        logger.error("机机Token校验失败: status=%s, body=%s", exc.code, body)
        sys.exit(1)
    except URLError as exc:
        logger.error("机机Token校验失败，Auth服务不可达: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.error("机机Token校验失败: %s", exc)
        sys.exit(1)


def _role_enabled(role: str, expected: str) -> bool:
    return role in {"all", expected}


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("正在启动 chirmera-platform-schedule 服务...")
    mark_state(shutting_down=False, startup_ready=False, startup_error=None)
    try:
        load_config()
        role = get_config().runtime.role
        mark_state(runtime_role=role)
        init_database()
        mark_state(database_ready=True)
        with get_engine().connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        redis_available = await get_redis_runtime().is_redis_available()
        if redis_available:
            mark_state(redis_ready=True)
        elif get_config().runtime.redis_degraded_ready:
            logger.warning("Redis 不可用，按 degraded-ready 模式继续启动")
            mark_state(redis_ready=True)
        else:
            mark_state(redis_ready=False)
        verify_auth_service_or_exit()
        mark_state(auth_ready=True)
        await get_registry_service().start()
        mark_state(registry_ready=True)
        if get_config().scheduler.enabled and _role_enabled(role, "scheduler"):
            await get_scheduler_runtime().start()
            mark_state(scheduler_ready=True)
        else:
            mark_state(scheduler_ready=True)
        if _role_enabled(role, "worker"):
            await get_worker_runtime().start()
            await get_delete_worker_runtime().start()
            await get_user_task_sync_worker_runtime().start()
            mark_state(worker_ready=True)
        else:
            mark_state(worker_ready=True)
        mark_state(startup_ready=True)
    except Exception as exc:
        mark_state(startup_ready=False, startup_error=str(exc))
        logger.error("服务启动失败: %s", exc)
        sys.exit(1)

    yield

    logger.info("正在关闭 chirmera-platform-schedule 服务...")
    mark_state(shutting_down=True, startup_ready=False)
    try:
        if get_config().scheduler.enabled and _role_enabled(get_config().runtime.role, "scheduler"):
            await get_scheduler_runtime().stop()
        if _role_enabled(get_config().runtime.role, "worker"):
            await get_user_task_sync_worker_runtime().stop()
            await get_delete_worker_runtime().stop()
            await get_worker_runtime().stop()
        await get_registry_service().stop()
        await close_all_async_clients()
        await close_redis_runtime()
    except Exception as exc:
        logger.warning("服务关闭异常: %s", exc)


app = FastAPI(
    title="chirmera-platform-schedule",
    description="REST 调度与 LiteLLM 虚拟 Key 管理服务",
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
    )
