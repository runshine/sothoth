"""
Code Server Manager - 主入口
"""

import logging
import sys
import asyncio
import json
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import load_config, get_config
from app.build_info import build_service_meta
from app.exception import setup_exception_handlers
from app.model import init_database
from app.services.k8s import get_k8s_service
from app.services.task_manager import get_task_manager
from app.api.code_server import router as code_server_router

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def verify_auth_service_or_exit():
    """启动时校验Auth服务连通性与机机Token有效性。"""
    cfg = get_config().auth_service
    machine_token = getattr(cfg, "service_machine_token", None)
    if not machine_token:
        logger.error("未配置auth_service.service_machine_token，拒绝启动")
        sys.exit(1)

    base_url = f"http://{cfg.host}:{cfg.port}"
    health_url = f"{base_url}/api/auth/health"
    validate_url = cfg.validate_url

    try:
        with urlopen(health_url, timeout=cfg.timeout) as resp:
            if resp.status != 200:
                logger.error(f"Auth服务健康检查失败: status={resp.status}")
                sys.exit(1)
    except Exception as e:
        logger.error(f"Auth服务不可达: {e}")
        sys.exit(1)

    try:
        req = Request(validate_url, method="POST")
        req.add_header("Authorization", f"Bearer {machine_token}")
        with urlopen(req, timeout=cfg.timeout) as resp:
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


def register_to_menu_service():
    """向菜单注册中心注册服务"""
    config = get_config()
    registry_config = config.registry

    if not registry_config.enabled:
        return

    menu_url = registry_config.menu_service_url
    register_url = f"{menu_url}/api/menu/register"

    host = registry_config.host
    port = registry_config.port
    service_id = registry_config.service_id
    service_name = registry_config.service_name
    maturity = registry_config.maturity
    description = registry_config.description
    api_prefix = registry_config.api_prefix

    actual_host = "127.0.0.1" if host == "0.0.0.0" else host

    menu_config = registry_config.menu
    level1 = menu_config.level1
    level2 = menu_config.level2
    level3 = menu_config.level3

    menu_name_cn = []
    menu_name_en = []
    if level1.name:
        menu_name_cn.append(level1.name)
        menu_name_en.append(level1.name_en or "")
    if level2.name:
        menu_name_cn.append(level2.name)
        menu_name_en.append(level2.name_en or "")
    if level3.name:
        menu_name_cn.append(level3.name)
        menu_name_en.append(level3.name_en or "")

    payload = {
        "service_id": service_id,
        "service_name": service_name,
        "host": actual_host,
        "port": port,
        "maturity": maturity,
        "description": description,
        "api_prefix": api_prefix,
        "menu_item": {
            "id": menu_config.id,
            "name": "/".join(menu_name_cn) if menu_name_cn else service_name,
            "name_en": "/".join(menu_name_en) if menu_name_en else service_name,
            "path": menu_config.path,
            "parent_id": menu_config.parent_id,
            "icon": menu_config.icon,
            "order": menu_config.order,
            "level1_name": level1.name,
            "level1_name_en": level1.name_en,
            "level2_name": level2.name,
            "level2_name_en": level2.name_en,
            "level3_name": level3.name,
            "level3_name_en": level3.name_en,
        }
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(register_url, data=data, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as response:
            if response.status == 200:
                logger.info(f"[Service Registry] Successfully registered to {register_url}")
            elif response.status == 404:
                logger.warning(f"[Service Registry] Menu service returned 404, re-registering...")
                register_to_menu_service()
            else:
                logger.warning(f"[Service Registry] Failed to register: {response.status}")
    except HTTPError as e:
        if e.code == 404:
            logger.warning(f"[Service Registry] Menu service returned 404, re-registering...")
            register_to_menu_service()
        else:
            logger.error(f"[Service Registry] Error registering to menu service: {e}")
    except URLError as e:
        logger.error(f"[Service Registry] Error registering to menu service: {e}")


async def periodic_register():
    """定期向菜单注册中心注册服务"""
    while True:
        try:
            register_to_menu_service()
        except Exception as e:
            logger.error(f"[Service Registry] Error: {e}")
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时执行
    logger.info("正在启动Code Server Manager服务...")

    # 加载配置
    try:
        config = load_config()
        logger.info("配置加载成功")
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        sys.exit(1)

    # 设置日志级别
    logging.getLogger().setLevel(getattr(logging, config.logging.level.upper()))

    verify_auth_service_or_exit()
    logger.info("Auth服务连通性与机机Token校验通过")

    # 初始化数据库
    try:
        init_database()
        logger.info("数据库初始化成功")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        sys.exit(1)

    # 验证K8S连接
    try:
        k8s_service = get_k8s_service()
        if not k8s_service.connect():
            logger.error("K8S连接验证失败")
            sys.exit(1)
        logger.info("K8S连接验证成功")
    except Exception as e:
        logger.error(f"K8S连接验证失败: {e}")
        sys.exit(1)

    # 启动任务管理器
    try:
        task_manager = get_task_manager()
        task_manager.start()
        logger.info("任务管理器启动成功")
    except Exception as e:
        logger.error(f"任务管理器启动失败: {e}")
        sys.exit(1)

    # 向菜单服务注册
    try:
        register_to_menu_service()
        asyncio.create_task(periodic_register())
        logger.info("菜单服务注册成功")
    except Exception as e:
        logger.error(f"菜单服务注册失败: {e}")

    logger.info("Code Server Manager服务启动成功")

    yield

    # 关闭时执行
    logger.info("正在关闭Code Server Manager服务...")

    # 停止任务管理器
    try:
        task_manager = get_task_manager()
        task_manager.stop()
        logger.info("任务管理器已停止")
    except Exception as e:
        logger.warning(f"停止任务管理器失败: {e}")


# 创建FastAPI应用
app = FastAPI(
    title="Code Server Manager",
    description="提供Code Server实例的创建、销毁、重建、状态查询、日志查看等功能",
    version="1.0.0",
    lifespan=lifespan,
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册异常处理器
setup_exception_handlers(app)

# 注册路由
app.include_router(code_server_router)


@app.get("/api/code-server/health")
async def health_check_alias():
    """兼容 menu 健康探测路径。"""
    return {
        "status": "ok",
        "service": "code-server-manager",
        **build_service_meta(),
    }


if __name__ == "__main__":
    import uvicorn

    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
