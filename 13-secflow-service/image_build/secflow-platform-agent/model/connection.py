import requests
import redis

from .db import DatabaseConnection

from typing import Dict, List, Any, Optional, Tuple, Union

# ===================== 连接检查工具 =====================

class ConnectionChecker:
    """连接检查器"""

    @staticmethod
    def check_database(db_config: Dict) -> Tuple[bool, str]:
        """检查数据库连接"""
        try:
            db = DatabaseConnection(db_config)
            if db.test_connection():
                return True, f"{db_config.get('type', 'sqlite').upper()}数据库连接正常"
            else:
                return False, f"{db_config.get('type', 'sqlite').upper()}数据库连接失败"
        except Exception as e:
            return False, f"数据库连接检查失败: {str(e)}"

    @staticmethod
    def check_nacos(nacos_url: str, namespace: str = 'public',
                    username: str = None, password: str = None) -> Tuple[bool, str]:
        """检查Nacos连接（支持v3 API认证）"""
        try:
            url = f"{nacos_url.rstrip('/')}/nacos/v1/ns/service/list"
            params = {
                'pageNo': 1,
                'pageSize': 10,
                'namespaceId': namespace
            }

            # 准备认证信息
            auth = None
            if username and password:
                auth = (username, password)

            response = requests.get(url, params=params, timeout=10, auth=auth)
            if response.status_code == 200:
                return True, "Nacos连接正常"
            elif response.status_code == 401:
                # 尝试使用v3 API
                v3_url = f"{nacos_url.rstrip('/')}/nacos/v3/ns/service/list"
                v3_response = requests.get(v3_url, params=params, timeout=10, auth=auth)
                if v3_response.status_code == 200:
                    return True, "Nacos v3 API连接正常"
                else:
                    return False, f"Nacos v3 API连接失败: HTTP {v3_response.status_code}"
            else:
                return False, f"Nacos连接失败: HTTP {response.status_code}"

        except requests.exceptions.ConnectionError as e:
            return False, f"Nacos连接失败: {str(e)}"
        except requests.exceptions.Timeout as e:
            return False, f"Nacos连接超时: {str(e)}"
        except Exception as e:
            return False, f"Nacos连接检查失败: {str(e)}"

    @staticmethod
    def check_redis(redis_url: str) -> Tuple[bool, str]:
        """检查Redis连接"""
        try:
            client = redis.from_url(redis_url, socket_timeout=5, socket_connect_timeout=5)
            if client.ping():
                return True, "Redis连接正常"
            else:
                return False, "Redis连接测试失败"

        except redis.exceptions.ConnectionError as e:
            return False, f"Redis连接失败: {str(e)}"
        except Exception as e:
            return False, f"Redis连接检查失败: {str(e)}"

    @staticmethod
    def check_all_connections(config: Dict) -> Dict[str, Tuple[bool, str]]:
        """检查所有连接"""
        results = {}

        # 检查数据库
        db_result = ConnectionChecker.check_database(config.get('database', {}))
        results['database'] = db_result

        # 检查Nacos（必须连接）
        nacos_result = ConnectionChecker.check_nacos(
            config.get('nacos_url', ''),
            config.get('nacos_namespace', 'public'),
            config.get('nacos_username'),
            config.get('nacos_password')
        )
        results['nacos'] = nacos_result

        # 检查Redis（可选）
        if config.get('redis_enabled', True):
            redis_result = ConnectionChecker.check_redis(config.get('redis_url', ''))
            results['redis'] = redis_result
        else:
            results['redis'] = (True, "Redis已禁用")

        return results