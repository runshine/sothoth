"""
SecFlow Menu Service - 动态菜单注册管理微服务

该服务提供菜单的动态注册与查询功能，支持服务成熟度分类。
"""

import os
import time
import threading
from flask import Flask, jsonify, request, Blueprint
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ServiceMaturity(Enum):
    """服务成熟度枚举"""
    ONLINE = "已上线"
    DEVELOPING = "开发中"
    PLANNING = "规划中"


@dataclass
class MenuItem:
    """菜单项数据类"""
    id: str
    name: str
    path: str
    parent_id: Optional[str] = None
    icon: Optional[str] = None
    order: int = 0
    maturity: ServiceMaturity = ServiceMaturity.DEVELOPING
    service_name: Optional[str] = None
    description: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class ServiceInfo:
    """服务注册信息"""
    service_id: str
    service_name: str
    host: str
    port: int
    register_time: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    maturity: ServiceMaturity = ServiceMaturity.DEVELOPING
    menu_items: Optional[MenuItem] = None


class MenuManager:
    """菜单管理类"""

    def __init__(self, heartbeat_timeout: float = 30.0):
        self.services: Dict[str, ServiceInfo] = {}
        self.heartbeat_timeout = heartbeat_timeout
        self.lock = threading.Lock()

    def register_service(self, service_id: str, service_name: str, host: str, port: int,
                         maturity: str = "开发中", menu_id: str = None, menu_name: str = None,
                         menu_path: str = None, parent_id: str = None, icon: str = None,
                         order: int = 0, description: str = None) -> Dict:
        """注册服务"""
        with self.lock:
            # 验证成熟度
            try:
                maturity_enum = ServiceMaturity(maturity)
            except ValueError:
                maturity_enum = ServiceMaturity.DEVELOPING

            # 检查服务是否已存在
            if service_id in self.services:
                service = self.services[service_id]
                service.last_heartbeat = time.time()
                service.maturity = maturity_enum

                # 更新菜单项
                if menu_id and menu_name:
                    service.menu_items = MenuItem(
                        id=menu_id,
                        name=menu_name,
                        path=menu_path or f"/{service_name}",
                        parent_id=parent_id,
                        icon=icon,
                        order=order,
                        maturity=maturity_enum,
                        service_name=service_name,
                        description=description,
                        updated_at=time.time()
                    )
                logger.info(f"Service updated: {service_id}")
                return {"status": "updated", "service_id": service_id}

            # 创建菜单项
            menu_item = None
            if menu_id and menu_name:
                menu_item = MenuItem(
                    id=menu_id,
                    name=menu_name,
                    path=menu_path or f"/{service_name}",
                    parent_id=parent_id,
                    icon=icon,
                    order=order,
                    maturity=maturity_enum,
                    service_name=service_name,
                    description=description
                )

            # 创建服务信息
            service = ServiceInfo(
                service_id=service_id,
                service_name=service_name,
                host=host,
                port=port,
                maturity=maturity_enum,
                menu_items=menu_item
            )
            self.services[service_id] = service
            logger.info(f"Service registered: {service_id}")
            return {"status": "registered", "service_id": service_id}

    def heartbeat(self, service_id: str) -> Dict:
        """心跳检测"""
        with self.lock:
            if service_id not in self.services:
                return {"status": "error", "message": "Service not found"}
            self.services[service_id].last_heartbeat = time.time()
            return {"status": "ok", "service_id": service_id}

    def unregister_service(self, service_id: str) -> Dict:
        """注销服务"""
        with self.lock:
            if service_id not in self.services:
                return {"status": "error", "message": "Service not found"}
            del self.services[service_id]
            logger.info(f"Service unregistered: {service_id}")
            return {"status": "ok", "service_id": service_id}

    def get_all_services_info(self) -> List[Dict]:
        """获取所有服务信息"""
        with self.lock:
            return [
                {
                    "service_id": s.service_id,
                    "service_name": s.service_name,
                    "host": s.host,
                    "port": s.port,
                    "register_time": s.register_time,
                    "last_heartbeat": s.last_heartbeat,
                    "maturity": s.maturity.value,
                    "menu_item": {
                        "id": s.menu_items.id,
                        "name": s.menu_items.name,
                        "path": s.menu_items.path,
                        "parent_id": s.menu_items.parent_id,
                        "icon": s.menu_items.icon,
                        "order": s.menu_items.order,
                        "maturity": s.menu_items.maturity.value,
                        "service_name": s.menu_items.service_name,
                        "description": s.menu_items.description
                    } if s.menu_items else None
                }
                for s in self.services.values()
            ]

    def get_dynamic_menu(self) -> List[Dict]:
        """获取动态菜单"""
        with self.lock:
            menu_items = []
            for service in self.services.values():
                if service.menu_items:
                    menu_item = {
                        "id": service.menu_items.id,
                        "name": service.menu_items.name,
                        "path": service.menu_items.path,
                        "parentId": service.menu_items.parent_id,
                        "icon": service.menu_items.icon,
                        "order": service.menu_items.order,
                        "maturity": service.menu_items.maturity.value,
                        "service_name": service.menu_items.service_name,
                        "description": service.menu_items.description
                    }
                    menu_items.append(menu_item)

            # 按order排序
            menu_items.sort(key=lambda x: x.get("order", 0))
            return menu_items

    def cleanup_expired_services(self):
        """清理过期服务"""
        current_time = time.time()
        with self.lock:
            expired = [sid for sid, s in self.services.items()
                      if current_time - s.last_heartbeat > self.heartbeat_timeout]
            for sid in expired:
                del self.services[sid]
                logger.info(f"Service expired and removed: {sid}")
            return len(expired)


# 创建Flask应用
app = Flask(__name__)

# 创建蓝图
menu_bp = Blueprint('menu', __name__, url_prefix='/api/menu')

# 全局菜单管理器实例
menu_manager: Optional[MenuManager] = None


def get_menu_manager() -> MenuManager:
    """获取菜单管理器单例"""
    global menu_manager
    if menu_manager is None:
        menu_manager = MenuManager()
    return menu_manager


@menu_bp.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({"status": "ok", "service": "secflow-menu"})


@menu_bp.route('/menu', methods=['GET'])
def get_menu():
    """
    获取动态菜单

    返回所有已注册的菜单项

    Response:
    {
        "code": 0,
        "message": "success",
        "data": [
            {
                "id": "home",
                "name": "首页",
                "path": "/home",
                "parentId": null,
                "icon": "home",
                "order": 0,
                "maturity": "已上线",
                "description": "系统首页"
            }
        ]
    }
    """
    manager = get_menu_manager()
    menu_items = manager.get_dynamic_menu()
    return jsonify({
        "code": 0,
        "message": "success",
        "data": menu_items
    })


@menu_bp.route('/services', methods=['GET'])
def get_all_services():
    """
    获取所有已注册服务信息

    返回所有已注册服务的详细信息

    Response:
    {
        "code": 0,
        "message": "success",
        "data": [...]
    }
    """
    manager = get_menu_manager()
    services = manager.get_all_services_info()
    return jsonify({
        "code": 0,
        "message": "success",
        "data": services
    })


@menu_bp.route('/register', methods=['POST'])
def register_service():
    """
    注册服务

    请求体 (JSON):
    {
        "service_id": "secflow-user",
        "service_name": "用户服务",
        "host": "192.168.1.100",
        "port": 8080,
        "maturity": "已上线",  // 可选: 已上线、开发中、规划中
        "menu_item": {
            "id": "user-manage",
            "name": "用户管理",
            "path": "/user",
            "parent_id": null,  // 可选，父菜单ID
            "icon": "user",      // 可选
            "order": 1,         // 可选
            "description": "用户管理模块"  // 可选
        }
    }

    Response:
    {
        "code": 0,
        "message": "success",
        "status": "registered"  // 或 "updated"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"code": -1, "message": "Request body required"}), 400

    required_fields = ['service_id', 'service_name', 'host', 'port']
    for field in required_fields:
        if field not in data:
            return jsonify({"code": -1, "message": f"Field '{field}' is required"}), 400

    manager = get_menu_manager()
    menu_data = data.get('menu_item', {})

    result = manager.register_service(
        service_id=data['service_id'],
        service_name=data['service_name'],
        host=data['host'],
        port=data['port'],
        maturity=data.get('maturity', '开发中'),
        menu_id=menu_data.get('id'),
        menu_name=menu_data.get('name'),
        menu_path=menu_data.get('path'),
        parent_id=menu_data.get('parent_id'),
        icon=menu_data.get('icon'),
        order=menu_data.get('order', 0),
        description=menu_data.get('description')
    )

    return jsonify({
        "code": 0,
        "message": "success",
        "status": result['status']
    })


@menu_bp.route('/unregister/<service_id>', methods=['DELETE'])
def unregister_service(service_id: str):
    """
    注销服务

    URL参数:
        service_id: 服务ID

    Response:
    {
        "code": 0,
        "message": "success"
    }
    """
    manager = get_menu_manager()
    result = manager.unregister_service(service_id)

    if result['status'] == 'error':
        return jsonify({"code": -1, "message": result['message']}), 404

    return jsonify({"code": 0, "message": "success"})


@menu_bp.route('/heartbeat/<service_id>', methods=['POST'])
def heartbeat(service_id: str):
    """
    心跳检测

    URL参数:
        service_id: 服务ID

    Response:
    {
        "code": 0,
        "message": "success"
    }
    """
    manager = get_menu_manager()
    result = manager.heartbeat(service_id)

    if result['status'] == 'error':
        return jsonify({"code": -1, "message": result['message']}), 404

    return jsonify({"code": 0, "message": "success"})


@menu_bp.route('/maturity/list', methods=['GET'])
def get_maturity_list():
    """
    获取成熟度列表

    Response:
    {
        "code": 0,
        "message": "success",
        "data": ["已上线", "开发中", "规划中"]
    }
    """
    return jsonify({
        "code": 0,
        "message": "success",
        "data": [m.value for m in ServiceMaturity]
    })


def create_app(config: Dict = None) -> Flask:
    """创建Flask应用"""
    global menu_manager

    if config:
        menu_manager = MenuManager(heartbeat_timeout=config.get('heartbeat_timeout', 30.0))

    app.register_blueprint(menu_bp)
    return app


def cleanup_task(interval: int = 10):
    """定期清理过期服务"""
    while True:
        try:
            manager = get_menu_manager()
            removed = manager.cleanup_expired_services()
            if removed > 0:
                logger.info(f"Cleaned up {removed} expired services")
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")
        time.sleep(interval)


if __name__ == '__main__':
    import argparse
    import yaml

    parser = argparse.ArgumentParser(description='SecFlow Menu Service')
    parser.add_argument('--config', type=str, default='config.yaml',
                       help='配置文件路径')
    args = parser.parse_args()

    # 读取配置文件
    config = {}
    if os.path.exists(args.config):
        with open(args.config, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}

    # 初始化菜单管理器
    menu_manager = MenuManager(heartbeat_timeout=config.get('heartbeat_timeout', 30.0))

    # 注册蓝图
    app.register_blueprint(menu_bp)

    # 启动清理任务
    cleanup_interval = config.get('cleanup_interval', 10)
    cleanup_thread = threading.Thread(target=cleanup_task, args=(cleanup_interval,), daemon=True)
    cleanup_thread.start()

    # 启动服务
    host = config.get('host', '0.0.0.0')
    port = config.get('port', 5000)
    debug = config.get('debug', False)

    logger.info(f"Starting SecFlow Menu Service on {host}:{port}")
    app.run(host=host, port=port, debug=debug)