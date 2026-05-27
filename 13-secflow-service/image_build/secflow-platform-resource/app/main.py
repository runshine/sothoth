"""Main FastAPI application entry point."""

import os
import sys
import uuid
import yaml
import asyncio
import logging
import json
import aiofiles
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import text
from starlette.responses import StreamingResponse

from app.build_info import build_service_meta

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def verify_auth_service_or_exit(config: dict):
    """启动时校验Auth服务连通性与机机Token有效性。"""
    auth_cfg = config.get("auth_service", {})
    base_url = (auth_cfg.get("base_url") or "").rstrip("/")
    validate_path = auth_cfg.get("validate_token_path", "/api/auth/validate-token")
    timeout = auth_cfg.get("timeout", 10)
    machine_token = auth_cfg.get("service_machine_token")

    if not base_url:
        logger.error("auth_service.base_url 未配置，拒绝启动")
        sys.exit(1)
    if not machine_token:
        logger.error("auth_service.service_machine_token 未配置，拒绝启动")
        sys.exit(1)

    health_url = f"{base_url}/api/auth/health"
    validate_url = f"{base_url}{validate_path}"

    try:
        with urlopen(health_url, timeout=timeout) as resp:
            if resp.status != 200:
                logger.error(f"Auth服务健康检查失败: status={resp.status}")
                sys.exit(1)
    except Exception as e:
        logger.error(f"Auth服务不可达: {e}")
        sys.exit(1)

    try:
        req = Request(validate_url, method="POST")
        req.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if resp.status != 200:
                logger.error(f"机机Token校验失败: status={resp.status}, body={body}")
                sys.exit(1)
            payload = json.loads(body or "{}")
            if payload.get("token_type") != "machine":
                logger.error(f"机机Token类型异常: token_type={payload.get('token_type')}")
                sys.exit(1)
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        logger.error(f"机机Token校验失败: status={e.code}, body={body}")
        sys.exit(1)
    except URLError as e:
        logger.error(f"机机Token校验失败，Auth服务不可达: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"机机Token校验失败: {e}")
        sys.exit(1)


def load_config(config_path: str = None) -> dict:
    """
    加载配置文件.

    Args:
        config_path: 配置文件路径，默认使用当前目录下的config.yaml

    Returns:
        dict: 配置内容
    """
    if config_path is None:
        config_path = os.environ.get(
            "CONFIG_PATH",
            str(Path(__file__).parent.parent / "config.yaml")
        )

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # 支持环境变量覆盖
    if os.environ.get("DB_HOST"):
        config["database"]["host"] = os.environ["DB_HOST"]

    if os.environ.get("DB_PASSWORD"):
        config["database"]["password"] = os.environ["DB_PASSWORD"]

    # 支持端口环境变量覆盖（Docker环境）
    if os.environ.get("APP_PORT"):
        config["app"]["port"] = int(os.environ["APP_PORT"])

    # 支持Token缓存TTL环境变量覆盖（Docker环境）
    if os.environ.get("TOKEN_CACHE_TTL"):
        if "auth_service" not in config:
            config["auth_service"] = {}
        config["auth_service"]["token_cache_ttl"] = int(os.environ["TOKEN_CACHE_TTL"])

    # File gateway runtime overrides
    if os.environ.get("FILE_GATEWAY_ENABLED"):
        if "file_gateway" not in config:
            config["file_gateway"] = {}
        config["file_gateway"]["enabled"] = os.environ["FILE_GATEWAY_ENABLED"].strip().lower() in {"1", "true", "yes", "on"}
    if os.environ.get("FILE_GATEWAY_FALLBACK_TO_EXEC"):
        if "file_gateway" not in config:
            config["file_gateway"] = {}
        config["file_gateway"]["fallback_to_exec"] = os.environ["FILE_GATEWAY_FALLBACK_TO_EXEC"].strip().lower() in {"1", "true", "yes", "on"}
    if os.environ.get("FILE_GATEWAY_INTERNAL_TOKEN"):
        if "file_gateway" not in config:
            config["file_gateway"] = {}
        config["file_gateway"]["internal_token"] = os.environ["FILE_GATEWAY_INTERNAL_TOKEN"]

    return config


# 全局配置，用于工厂模式
_global_config = None


def get_config() -> dict:
    """获取全局配置确保配置只加载一次。"""
    global _global_config
    if _global_config is None:
        _global_config = load_config()
    return _global_config


def validate_config(config: dict) -> tuple[bool, list[str]]:
    """
    验证配置参数是否完整有效。

    Returns:
        tuple: (是否有效, 错误列表)
    """
    errors = []

    # 检查数据库配置
    db_config = config.get("database", {})
    if not db_config.get("host"):
        errors.append("database.host is required")
    if not db_config.get("port"):
        errors.append("database.port is required")
    if not db_config.get("username"):
        errors.append("database.username is required")
    if not db_config.get("name"):
        errors.append("database.name is required")

    # 检查K8S配置
    # 资源服务已统一通过 platform-k8s，保留 k8s.storage_class_name 供PVC默认值使用
    k8s_config = config.get("k8s", {})
    if not k8s_config.get("storage_class_name"):
        errors.append("k8s.storage_class_name is required")
    k8s_service_config = config.get("k8s_service", {})
    if not k8s_service_config.get("base_url"):
        if not (k8s_service_config.get("host") and k8s_service_config.get("port")):
            errors.append("k8s_service.base_url or k8s_service.host+port is required")
    file_gateway_config = config.get("file_gateway", {})
    if bool(file_gateway_config.get("enabled", True)):
        if not file_gateway_config.get("worker_image"):
            errors.append("file_gateway.worker_image is required when file_gateway.enabled=true")

    # 检查认证服务配置
    auth_config = config.get("auth_service", {})
    if not auth_config.get("base_url"):
        errors.append("auth_service.base_url is required")
    if not auth_config.get("service_machine_token"):
        errors.append("auth_service.service_machine_token is required")

    # 检查项目服务配置
    project_config = config.get("project_service", {})
    if not project_config.get("base_url"):
        errors.append("project_service.base_url is required")

    return len(errors) == 0, errors


def test_k8s_connection(config: dict) -> tuple[bool, str]:
    """测试Kubernetes连接。"""
    try:
        from app.services.k8s import init_k8s_service
        k8s_service = init_k8s_service(config)
        return True, "Kubernetes connection successful"
    except ConnectionError as e:
        return False, f"Kubernetes connection failed: {str(e)}"
    except Exception as e:
        return False, f"Kubernetes connection error: {str(e)}"


def test_database_connection(config: dict) -> tuple[bool, str]:
    """测试数据库连接。"""
    try:
        from app.models.database import test_database_connection
        return test_database_connection()
    except Exception as e:
        return False, f"Database connection error: {str(e)}"


def init_database(config: dict):
    """初始化数据库连接并创建表结构。"""
    from app.models.database import Base, engine, create_tables

    # 确保引擎已初始化
    from app.models.database import init_database_engine
    init_database_engine()

    # 自动创建所有表结构
    create_tables()
    logger.info("Database tables created/verified successfully")


def init_services(config: dict):
    """初始化服务组件。"""
    from app.services.auth import init_auth_service
    from app.services.project import init_project_service
    from app.services.k8s import init_k8s_service
    from app.tasks.manager import init_task_manager

    # 初始化上传文件目录
    app_config = config.get("app", {})
    upload_dir = app_config.get("upload_dir", "/tmp/uploads")
    Path(upload_dir).mkdir(parents=True, exist_ok=True)
    logger.info(f"Upload directory initialized: {upload_dir}")

    # 初始化认证服务
    auth_config = config.get("auth_service", {})
    init_auth_service(
        base_url=auth_config.get("base_url", "http://localhost:8080"),
        validate_path=auth_config.get("validate_token_path", "/api/auth/validate-token"),
        timeout=auth_config.get("timeout", 10),
        token_cache_ttl=auth_config.get("token_cache_ttl", 900)
    )
    logger.info("Auth service initialized")

    # 初始化项目服务（调用secflow_project验证项目）
    project_config = config.get("project_service", {})
    init_project_service(
        base_url=project_config.get("base_url", "http://localhost:10001"),
        get_project_path=project_config.get("get_project_path", "/api/project"),
        timeout=project_config.get("timeout", 10),
        service_machine_token=auth_config.get("service_machine_token"),
    )
    logger.info("Project service initialized")

    # 初始化K8S服务
    try:
        init_k8s_service(config)
        logger.info("Kubernetes service initialized")
    except ConnectionError as e:
        logger.error(f"Failed to connect to Kubernetes: {e}")
        sys.exit(1)

    # 初始化任务管理器
    task_config = config.get("task", {})
    task_log_dir = task_config.get("log_dir", "/data/task_log")
    Path(task_log_dir).mkdir(parents=True, exist_ok=True)
    init_task_manager(
        log_dir=task_log_dir,
        max_concurrent=task_config.get("max_concurrent_tasks", 10)
    )
    logger.info("Task manager initialized")


def create_app(config: dict = None) -> FastAPI:
    """
    创建FastAPI应用实例（工厂函数，用于uvicorn --factory模式）。

    Args:
        config: 配置字典如果为None则从配置文件加载

    Returns:
        FastAPI: 配置好的FastAPI应用
    """
    if config is None:
        config = get_config()

    app = FastAPI(
        title="Secflow Resource Management Service",
        description="项目管理四类资源（文档、软件、代码、其他）的异步上传和解压服务",
        version="2.1.0"
    )

    # CORS配置
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 启动事件
    @app.on_event("startup")
    async def startup_event():
        logger.info("Secflow Resource Management Service starting...")

        # 加载配置
        config = get_config()

        # 1. 验证配置参数
        logger.info("Validating configuration...")
        config_valid, config_errors = validate_config(config)
        if not config_valid:
            logger.error(f"Configuration validation failed: {config_errors}")
            sys.exit(1)
        logger.info("Configuration validated successfully")

        verify_auth_service_or_exit(config)
        logger.info("Auth服务连通性与机机Token校验通过")

        # 2. 测试数据库连接
        logger.info("Testing database connection...")
        db_healthy, db_message = test_database_connection(config)
        if not db_healthy:
            logger.error(f"Database connection failed: {db_message}")
            sys.exit(1)
        logger.info(f"Database connection: {db_message}")

        # 3. 初始化数据库表结构
        logger.info("Initializing database tables...")
        init_database(config)

        # 4. 测试K8S连接
        logger.info("Testing Kubernetes connection...")
        k8s_healthy, k8s_message = test_k8s_connection(config)
        if not k8s_healthy:
            logger.error(f"Kubernetes connection failed: {k8s_message}")
            sys.exit(1)
        logger.info(f"Kubernetes connection: {k8s_message}")

        # 5. 初始化服务组件
        logger.info("Initializing services...")
        init_services(config)

        # 向菜单注册中心注册服务
        try:
            from app.services.registry import register_to_menu_service, periodic_register
            asyncio.create_task(periodic_register(config))
            register_to_menu_service(config)
            logger.info("Service registered to menu service")
        except Exception as e:
            logger.warning(f"Failed to register to menu service: {e}")

        logger.info("Secflow Resource Management Service started successfully")

    # 关闭事件
    @app.on_event("shutdown")
    async def shutdown_event():
        logger.info("Secflow Resource Management Service shutting down...")
        from app.services.registry import shutdown_registry
        shutdown_registry()
        logger.info("Secflow Resource Management Service stopped")

    # 健康检查端点
    @app.get("/api/resource/health")
    async def health_check():
        """健康检查端点，包含依赖服务状态。"""
        from app.services.k8s import get_k8s_service

        k8s_healthy = False
        try:
            k8s_service = get_k8s_service()
            k8s_healthy = k8s_service.check_connection()
        except Exception:
            pass

        # 检查数据库连接
        db_healthy = True
        try:
            from app.models.database import SessionLocal
            session = SessionLocal()
            session.execute(text("SELECT 1"))
            session.close()
        except Exception:
            db_healthy = False

        overall_status = "healthy" if (k8s_healthy and db_healthy) else "degraded"

        return {
            "status": overall_status,
            "service": "secflow-resource-management",
            "dependencies": {
                "kubernetes": "healthy" if k8s_healthy else "unhealthy",
                "database": "healthy" if db_healthy else "unhealthy"
            },
            **build_service_meta(),
        }

    # 就绪检查端点
    @app.get("/api/resource/ready")
    async def readiness_check():
        """就绪检查端点 - 检查服务是否准备好接收请求。"""
        try:
            from app.services.k8s import get_k8s_service
            k8s_service = get_k8s_service()
            if not k8s_service.check_connection():
                return {"status": "not_ready", "reason": "Kubernetes not connected"}
        except Exception:
            return {"status": "not_ready", "reason": "Service not initialized"}

        return {"status": "ready"}

    # ============ 静态文件服务（供K8S Job下载） ============

    @app.get("/api/resource/uploads/{file_uuid}")
    async def download_uploaded_file(file_uuid: str):
        """
        静态文件下载服务，供K8S Job下载上传的文件。

        Args:
            file_uuid: 文件UUID（从数据库获取）
        """
        from app.models.database import SessionLocal, Resource

        config = get_config()
        app_config = config.get("app", {})
        upload_dir = app_config.get("upload_dir", "/tmp/uploads")

        # 查找资源记录
        session = SessionLocal()
        try:
            resource = session.query(Resource).filter(
                Resource.resource_uuid == file_uuid
            ).first()

            if not resource:
                raise HTTPException(status_code=404, detail="File not found")

            file_path = os.path.join(upload_dir, file_uuid)

            if not os.path.exists(file_path):
                raise HTTPException(status_code=404, detail="File not found on disk")

            # 返回文件
            return FileResponse(
                path=file_path,
                filename=resource.original_file_name,
                media_type="application/octet-stream"
            )
        finally:
            session.close()

    # 注册API路由
    from app.api import api_router
    app.include_router(api_router)

    return app


def main():
    """应用主入口。"""
    config = load_config()

    # 启动前验证配置
    logger.info("Validating configuration...")
    config_valid, config_errors = validate_config(config)
    if not config_valid:
        logger.error(f"Configuration validation failed: {config_errors}")
        for error in config_errors:
            logger.error(f"  - {error}")
        sys.exit(1)

    # 启动前测试连接
    logger.info("Testing database connection...")
    db_healthy, db_message = test_database_connection(config)
    if not db_healthy:
        logger.error(f"Database connection failed: {db_message}")
        sys.exit(1)

    logger.info("Testing Kubernetes connection...")
    k8s_healthy, k8s_message = test_k8s_connection(config)
    if not k8s_healthy:
        logger.error(f"Kubernetes connection failed: {k8s_message}")
        sys.exit(1)

    # 创建并运行应用
    app = create_app(config)
    app_config = config.get("app", {})
    host = app_config.get("host", "0.0.0.0")
    port = app_config.get("port", 10002)
    debug = app_config.get("debug", False)

    uvicorn.run(
        "app.main:create_app",
        host=host,
        port=port,
        reload=debug,
        factory=True
    )


if __name__ == "__main__":
    main()
