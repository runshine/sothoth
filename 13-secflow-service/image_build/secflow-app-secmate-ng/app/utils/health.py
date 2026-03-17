"""
Secmate-NG Manager - 健康检查工具
"""

import logging
import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


def check_k8s_api_health() -> bool:
    """
    检查K8s API服务健康状态

    Returns:
        bool: K8s API服务是否健康
    """
    try:
        config = get_config()
        client = httpx.Client(timeout=5)
        url = f"{config.k8s_api_service.base_url}/api/k8s/health"
        response = client.get(url)
        client.close()
        return response.status_code == 200
    except Exception as e:
        logger.error(f"K8s API健康检查失败: {e}")
        return False


def check_database_health() -> bool:
    """
    检查数据库连接健康状态

    Returns:
        bool: 数据库是否可连接
    """
    try:
        from app.model import get_db_session
        db = get_db_session()
        # 执行简单查询测试连接
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        logger.error(f"数据库健康检查失败: {e}")
        return False


def check_auth_service_health() -> bool:
    """
    检查认证服务健康状态

    Returns:
        bool: 认证服务是否可用（如果禁用则返回True）
    """
    try:
        config = get_config()
        if not config.auth_service.enabled:
            return True

        # 简单的健康检查 - 尝试连接认证服务
        client = httpx.Client(timeout=5)
        # 尝试访问认证服务的根路径或健康检查端点
        auth_base_url = f"http://{config.auth_service.host}:{config.auth_service.port}"
        try:
            response = client.get(f"{auth_base_url}/health")
            client.close()
            return response.status_code == 200
        except:
            # 如果没有 /health 端点，尝试根路径
            try:
                response = client.get(auth_base_url)
                client.close()
                return response.status_code in [200, 404]  # 404 也表示服务在运行
            except:
                client.close()
                return False
    except Exception as e:
        logger.error(f"认证服务健康检查失败: {e}")
        return False
