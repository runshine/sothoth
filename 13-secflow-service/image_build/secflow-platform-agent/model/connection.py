import json
from typing import Dict, Tuple

import redis
import requests

from .db import DatabaseConnection


LEGACY_API_FALLBACK_STATUSES = {401, 404, 410, 501}

# ===================== 连接检查工具 =====================

class ConnectionChecker:
    """连接检查器"""

    @staticmethod
    def _login_v3(
        nacos_url: str,
        username: str = None,
        password: str = None,
        timeout: int = 10,
    ) -> Dict[str, str]:
        """登录 Nacos 3.x，获取 access token。"""
        if not username or not password:
            return {}

        login_url = f"{nacos_url.rstrip('/')}/nacos/v3/auth/user/login"
        response = requests.post(
            login_url,
            data={
                'username': username,
                'password': password,
            },
            timeout=timeout,
        )
        if response.status_code != 200:
            return {}

        payload = response.json() if response.content else {}
        token = (
            payload.get('accessToken')
            or payload.get('data', {}).get('accessToken')
            or payload.get('data')
        )
        token = str(token or '').strip()
        if not token:
            return {}
        return {
            'accessToken': token,
            'Authorization': f'Bearer {token}',
        }

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
        """检查Nacos连接，兼容 legacy/v3 API。"""
        try:
            base_url = nacos_url.rstrip('/')
            auth = None
            if username and password:
                auth = (username, password)

            legacy_url = f"{base_url}/nacos/v1/ns/service/list"
            params = {
                'pageNo': 1,
                'pageSize': 10,
                'namespaceId': namespace,
            }
            response = requests.get(legacy_url, params=params, timeout=10, auth=auth)
            if response.status_code == 200:
                return True, "Nacos连接正常"

            if response.status_code in LEGACY_API_FALLBACK_STATUSES:
                # 3.x 中 legacy API 可能已移除。启动检查只需要验证服务可达与鉴权可用，
                # 不应依赖权限要求更高的 service list。
                v3_url = f"{base_url}/nacos/v3/admin/core/state"
                headers = ConnectionChecker._login_v3(base_url, username, password, timeout=10)
                v3_response = requests.get(
                    v3_url,
                    timeout=10,
                    auth=auth,
                    headers=headers or None,
                )
                if v3_response.status_code == 200:
                    return True, "Nacos v3 API连接正常"

                return False, (
                    f"Nacos legacy API返回 HTTP {response.status_code}，"
                    f"且 v3 state API连接失败: HTTP {v3_response.status_code}"
                )

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
