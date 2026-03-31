#!/usr/bin/env python3
"""启动脚本 - 从配置文件读取host和port"""

import os
import logging
import secrets
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from pathlib import Path
from contextlib import asynccontextmanager

# 项目根目录 (app 的父目录)
PROJECT_ROOT = Path(__file__).parent.parent

# 设置环境变量 (供 uvicorn 子进程使用)
os.environ["PYTHONPATH"] = str(PROJECT_ROOT)

# 添加到 sys.path（供当前进程使用）
import sys
sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
import asyncio
import json
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# Lifespan context管理器 - 必须在 create_app 之前定义
def lifespan_factory():
    """创建 lifespan 上下文管理器"""
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """应用生命周期管理 - 启动时注册服务"""
        # 延迟导入以避免循环依赖
        from app.config import config

        def register_to_menu_service():
            """向菜单注册中心注册服务"""
            registry_config = config.get("registry", {})
            if not registry_config.get("enabled", False):
                return

            menu_url = registry_config.get("menu_service_url", "http://secflow-menu:5000")
            register_url = f"{menu_url}/api/menu/register"

            host = registry_config.get("host", "0.0.0.0")
            port = registry_config.get("port", 10000)
            service_id = registry_config.get("service_id", "secflow-user")
            service_name = registry_config.get("service_name", "用户服务")
            maturity = registry_config.get("maturity", "已上线")
            description = registry_config.get("description", "用户管理与认证微服务")
            api_prefix = registry_config.get("api_prefix", "/api/auth")

            actual_host = "127.0.0.1" if host == "0.0.0.0" else host

            menu_config = registry_config.get("menu", {})
            level1 = menu_config.get("level1", {})
            level2 = menu_config.get("level2", {})
            level3 = menu_config.get("level3", {})

            menu_name_cn = []
            menu_name_en = []
            if level1.get("name"):
                menu_name_cn.append(level1["name"])
                menu_name_en.append(level1.get("name_en", ""))
            if level2.get("name"):
                menu_name_cn.append(level2["name"])
                menu_name_en.append(level2.get("name_en", ""))
            if level3.get("name"):
                menu_name_cn.append(level3["name"])
                menu_name_en.append(level3.get("name_en", ""))

            payload = {
                "service_id": service_id,
                "service_name": service_name,
                "host": actual_host,
                "port": port,
                "maturity": maturity,
                "description": description,
                "api_prefix": api_prefix,
                "menu_item": {
                    "id": menu_config.get("id", service_id),
                    "name": "/".join(menu_name_cn) if menu_name_cn else service_name,
                    "name_en": "/".join(menu_name_en) if menu_name_en else service_name,
                    "path": menu_config.get("path", f"/{service_id}"),
                    "parent_id": menu_config.get("parent_id"),
                    "icon": menu_config.get("icon", "app"),
                    "order": menu_config.get("order", 0),
                    "level1_name": level1.get("name"),
                    "level1_name_en": level1.get("name_en"),
                    "level2_name": level2.get("name"),
                    "level2_name_en": level2.get("name_en"),
                    "level3_name": level3.get("name"),
                    "level3_name_en": level3.get("name_en"),
                }
            }

            try:
                data = json.dumps(payload).encode("utf-8")
                req = Request(register_url, data=data, headers={"Content-Type": "application/json"})
                with urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        print(f"[Service Registry] Successfully registered to {register_url}")
                    elif response.status == 404:
                        # 404 时重新触发注册流程
                        logger.warning(f"[Service Registry] Menu service returned 404, re-registering...")
                        register_to_menu_service()
                    else:
                        print(f"[Service Registry] Failed to register: {response.status}")
            except HTTPError as e:
                if e.code == 404:
                    # 404 时重新触发注册流程并记录 warning 日志
                    logger.warning(f"[Service Registry] Menu service returned 404, re-registering...")
                    register_to_menu_service()
                else:
                    print(f"[Service Registry] Error registering to menu service: {e}")
            except URLError as e:
                print(f"[Service Registry] Error registering to menu service: {e}")

        async def periodic_register():
            """定期向菜单注册中心注册服务"""
            while True:
                try:
                    register_to_menu_service()
                except Exception as e:
                    print(f"[Service Registry] Error: {e}")
                await asyncio.sleep(30)

        async def periodic_cleanup():
            """定期清理过期资源"""
            while True:
                try:
                    from app.auth import cleanup_expired_sessions, cleanup_expired_machine_tokens
                    from app.database import get_db
                    
                    db = next(get_db())
                    
                    # 清理过期会话
                    session_count = cleanup_expired_sessions(db)
                    if session_count > 0:
                        print(f"[Cleanup] Cleaned up {session_count} expired sessions")
                    
                    # 清理过期机机Token
                    token_count = cleanup_expired_machine_tokens(db)
                    if token_count > 0:
                        print(f"[Cleanup] Cleaned up {token_count} expired machine tokens")
                        
                except Exception as e:
                    print(f"[Cleanup] Error: {e}")
                
                # 每5分钟执行一次清理
                await asyncio.sleep(300)

        # 启动时执行
        register_to_menu_service()
        asyncio.create_task(periodic_register())
        asyncio.create_task(periodic_cleanup())
        yield
        # 关闭时执行
        print("[Service] Shutting down...")

    return lifespan


# 创建应用工厂函数
def create_app():
    import logging
    logger = logging.getLogger(__name__)

    from app.db_base import Base, engine  # noqa: F401
    from app.database import init_db, verify_tables_exist, SessionLocal  # noqa: F401
    from app.model import MachineToken  # noqa: F401
    from app.config import config
    from app.rbac import ensure_platform_roles_seeded

    logger.info(f"[Database] Initializing database and running startup migrations...")
    # 初始化数据库，创建所有表并自动执行幂等迁移
    init_db()

    # 验证数据库表是否真正存在
    try:
        verify_tables_exist()
        logger.info(f"[Database] Table verification passed: all required tables exist")
    except RuntimeError as e:
        logger.error(str(e))
        raise

    logger.info(f"[Database] Database initialization and startup migrations completed")

    def ensure_platform_roles_ready():
        db = SessionLocal()
        try:
            ensure_platform_roles_seeded(db)
        finally:
            db.close()

    def ensure_machine_token_seeded():
        """
        启动时检查机机Token是否存在。
        - 若不存在：自动生成一个机机Token并写入数据库
        - 将Token明文写入文件，便于配置其他微服务
        """
        db = SessionLocal()
        try:
            existing = db.query(MachineToken).order_by(MachineToken.id.asc()).all()
            if existing:
                logger.info(f"[MachineToken] 机机Token已存在，无需自动生成，count={len(existing)}")
                return

            token_value = secrets.token_urlsafe(48)
            machine_code = "secflow-service-token-auto"
            auto_token = MachineToken(
                token=token_value,
                machine_code=machine_code,
                description=f"Auto generated at startup ({datetime.utcnow().isoformat()}Z)",
                is_active=True,
            )
            db.add(auto_token)
            db.commit()
            db.refresh(auto_token)

            # 日志明文输出（按需求）
            logger.warning("[MachineToken] 未检测到机机Token，已自动生成")
            logger.warning(f"[MachineToken] machine_code={auto_token.machine_code}")
            logger.warning(f"[MachineToken] token={auto_token.token}")

            # 明文落盘（按需求）
            service_auth_cfg = config.get("service_auth", {}) if isinstance(config, dict) else {}
            output_file = (
                service_auth_cfg.get("machine_token_record_file")
                or os.environ.get("SECFLOW_MACHINE_TOKEN_RECORD_FILE")
                or "/tmp/secflow-machine-token.txt"
            )
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write("# Auto generated machine token for microservice auth\n")
                f.write(f"generated_at={datetime.utcnow().isoformat()}Z\n")
                f.write(f"machine_code={auto_token.machine_code}\n")
                f.write(f"token={auto_token.token}\n\n")
                f.write("# Suggested config snippet\n")
                f.write("auth_service:\n")
                f.write("  validate_token_path: \"/api/auth/validate-token\"\n")
                f.write(f"  service_machine_token: \"{auto_token.token}\"\n")

            try:
                os.chmod(output_file, 0o600)
            except Exception:
                pass
            logger.warning(f"[MachineToken] 机机Token已写入明文文件: {output_file}")
        except Exception as e:
            db.rollback()
            logger.error(f"[MachineToken] 自动生成机机Token失败: {e}")
            raise
        finally:
            db.close()

    ensure_platform_roles_ready()
    ensure_machine_token_seeded()

    # 创建FastAPI应用，使用 lifespan
    app = FastAPI(
        title="SecFlow User Service",
        description="用户管理与认证微服务",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan_factory()
    )

    # CORS配置
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 路由导入
    from app.router import auth, users, role_router, machine_tokens_router, org_router

    # 注册路由
    app.include_router(auth.router, prefix="/api/auth")
    app.include_router(users.router, prefix="/api/auth")
    app.include_router(role_router, prefix="/api/auth")
    app.include_router(machine_tokens_router, prefix="/api/auth")
    app.include_router(org_router, prefix="/api/auth")

    @app.get("/")
    def root():
        return {
            "service": "secflow-user",
            "version": "1.0.0",
            "docs": "/docs"
        }

    return app


if __name__ == "__main__":
    app = create_app()
    from app.config import config

    host = config.get("app", {}).get("host", "0.0.0.0")
    port = config.get("app", {}).get("port", 8080)
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=False
    )
