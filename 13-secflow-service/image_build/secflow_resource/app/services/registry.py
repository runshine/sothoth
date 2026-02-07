"""Menu Service Registry - 服务注册中心客户端模块."""

import asyncio
from typing import Optional
import json
import logging
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


def register_to_menu_service(config: dict):
    """向菜单注册中心注册服务"""
    registry_config = config.get("registry", {})
    if not registry_config.get("enabled", False):
        logger.info("Service registry is disabled")
        return

    menu_url = registry_config.get("menu_service_url", "http://secflow-menu:5000")
    register_url = f"{menu_url}/api/menu/register"

    # 构建注册数据
    host = registry_config.get("host", "0.0.0.0")
    port = registry_config.get("port", 10000)
    service_id = registry_config.get("service_id", "secflow-resource")
    service_name = registry_config.get("service_name", "资源管理服务")
    maturity = registry_config.get("maturity", "已上线")
    description = registry_config.get("description", "资源管理服务")
    api_prefix = registry_config.get("api_prefix", "/api/resource")

    # 获取实际可访问的地址
    actual_host = "127.0.0.1" if host == "0.0.0.0" else host

    # 构建菜单配置
    menu_config = registry_config.get("menu", {})
    level1 = menu_config.get("level1", {})
    level2 = menu_config.get("level2", {})
    level3 = menu_config.get("level3", {})

    # 菜单名称组合
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
                logger.info(f"[Service Registry] Successfully registered to {register_url}")
            else:
                logger.warning(f"[Service Registry] Failed to register: {response.status}")
    except (URLError, HTTPError) as e:
        logger.error(f"[Service Registry] Error registering to menu service: {e}")


async def periodic_register(config: dict):
    """定期向菜单注册中心注册服务"""
    while True:
        try:
            register_to_menu_service(config)
        except Exception as e:
            logger.error(f"[Service Registry] Error: {e}")
        await asyncio.sleep(30)  # 每30秒注册一次


# 取消注册标志
_shutdown_event: Optional[asyncio.Event] = None


def shutdown_registry():
    """停止服务注册"""
    global _shutdown_event
    if _shutdown_event:
        _shutdown_event.set()
    logger.info("[Service Registry] Service registry stopped")