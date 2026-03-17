"""
Secmate-NG Manager - K8s API客户端服务
通过secflow-platform-k8s API管理K8s资源
"""

import logging
from typing import Optional, List, Dict, Any

import httpx

from app.config import get_config
from app.exception import K8sApiError, NotFoundError, ForbiddenError, ValidationError

logger = logging.getLogger(__name__)


class K8sApiClient:
    """K8s API客户端（通过secflow-platform-k8s）"""

    def __init__(self):
        self.config = get_config()
        self.client = httpx.Client(timeout=self.config.k8s_api_service.timeout)

    def _get_headers(self, user_token: str = None) -> dict:
        """构建请求头"""
        headers = {"Content-Type": "application/json"}
        if user_token:
            headers["Authorization"] = f"Bearer {user_token}"
        return headers

    def _build_url(self, path: str, project_id: str) -> str:
        """构建完整API URL"""
        base = self.config.k8s_api_service.base_url
        return f"{base}{path}?project_id={project_id}"

    def _handle_response(self, response: httpx.Response) -> dict:
        """处理API响应"""
        if response.status_code in (200, 201):
            return response.json()
        elif response.status_code == 404:
            raise NotFoundError("K8s资源", "unknown")
        elif response.status_code == 401:
            raise ForbiddenError("Token无效或已过期")
        elif response.status_code == 403:
            raise ForbiddenError("权限不足")
        elif response.status_code == 400:
            error_detail = response.json().get("detail", "请求参数错误")
            raise ValidationError(error_detail)
        else:
            raise K8sApiError(f"API调用失败: {response.status_code} - {response.text}")

    # ============ PVC操作 ============

    def check_pvc_exists(self, project_id: str, pvc_name: str, user_token: str = None) -> bool:
        """检查PVC是否存在"""
        try:
            url = self._build_url(f"/api/k8s/pvcs/{pvc_name}", project_id)
            response = self.client.get(url, headers=self._get_headers(user_token))
            return response.status_code == 200
        except Exception as e:
            if "404" in str(e):
                return False
            logger.error(f"检查PVC存在失败: {e}")
            return False

    def create_pvc(self, project_id: str, manifest: dict, user_token: str = None) -> dict:
        """创建PVC"""
        try:
            url = self._build_url("/api/k8s/pvcs", project_id)
            response = self.client.post(url, json={"manifest": manifest}, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except Exception as e:
            if "already exists" in str(e).lower() or "409" in str(e):
                logger.info(f"PVC已存在")
                return {"message": "PVC已存在"}
            raise

    def delete_pvc(self, project_id: str, name: str, user_token: str = None) -> dict:
        """删除PVC"""
        try:
            url = self._build_url(f"/api/k8s/pvcs/{name}", project_id)
            response = self.client.delete(url, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except NotFoundError:
            return {"message": "PVC不存在"}

    # ============ Deployment操作 ============

    def create_deployment(self, project_id: str, manifest: dict, user_token: str = None) -> dict:
        """创建Deployment"""
        try:
            url = self._build_url("/api/k8s/deployments", project_id)
            response = self.client.post(url, json={"manifest": manifest}, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except Exception as e:
            if "already exists" in str(e).lower() or "409" in str(e):
                logger.info(f"Deployment已存在")
                return {"message": "Deployment已存在"}
            raise

    def delete_deployment(self, project_id: str, name: str, user_token: str = None) -> dict:
        """删除Deployment"""
        try:
            url = self._build_url(f"/api/k8s/deployments/{name}", project_id)
            response = self.client.delete(url, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except NotFoundError:
            return {"message": "Deployment不存在"}

    def scale_deployment(self, project_id: str, name: str, replicas: int, user_token: str = None) -> dict:
        """调整Deployment副本数"""
        try:
            url = self._build_url(f"/api/k8s/deployments/{name}/scale", project_id)
            response = self.client.post(url, json={"replica": replicas}, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except Exception as e:
            raise

    def restart_deployment(self, project_id: str, name: str, user_token: str = None) -> dict:
        """重启Deployment"""
        try:
            url = self._build_url(f"/api/k8s/deployments/{name}/restart", project_id)
            response = self.client.post(url, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except Exception as e:
            raise

    def get_deployment_status(self, project_id: str, name: str, user_token: str = None) -> Optional[dict]:
        """获取Deployment状态"""
        try:
            url = self._build_url(f"/api/k8s/deployments/{name}", project_id)
            response = self.client.get(url, headers=self._get_headers(user_token))
            data = self._handle_response(response)
            return {
                "name": data.get("name"),
                "replicas": data.get("replicas", 0),
                "ready_replicas": data.get("ready_replicas", 0),
                "available_replicas": data.get("available_replicas", 0),
            }
        except NotFoundError:
            return None
        except Exception as e:
            logger.error(f"获取Deployment状态失败: {e}")
            return None

    # ============ Service操作 ============

    def create_service(self, project_id: str, manifest: dict, user_token: str = None) -> dict:
        """创建Service"""
        try:
            url = self._build_url("/api/k8s/services", project_id)
            response = self.client.post(url, json={"manifest": manifest}, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except Exception as e:
            if "already exists" in str(e).lower() or "409" in str(e):
                logger.info(f"Service已存在")
                return {"message": "Service已存在"}
            raise

    def delete_service(self, project_id: str, name: str, user_token: str = None) -> dict:
        """删除Service"""
        try:
            url = self._build_url(f"/api/k8s/services/{name}", project_id)
            response = self.client.delete(url, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except NotFoundError:
            return {"message": "Service不存在"}

    # ============ Ingress操作 ============

    def create_ingress(self, project_id: str, manifest: dict, user_token: str = None) -> dict:
        """创建Ingress"""
        try:
            url = self._build_url("/api/k8s/ingresses", project_id)
            response = self.client.post(url, json={"manifest": manifest}, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except Exception as e:
            if "already exists" in str(e).lower() or "409" in str(e):
                logger.info(f"Ingress已存在")
                return {"message": "Ingress已存在"}
            raise

    def delete_ingress(self, project_id: str, name: str, user_token: str = None) -> dict:
        """删除Ingress"""
        try:
            url = self._build_url(f"/api/k8s/ingresses/{name}", project_id)
            response = self.client.delete(url, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except NotFoundError:
            return {"message": "Ingress不存在"}

    # ============ Pod操作 ============

    def get_pods_by_deployment(self, project_id: str, label_selector: str, user_token: str = None) -> list:
        """通过标签选择器获取Pod列表"""
        try:
            url = self._build_url("/api/k8s/pods", project_id)
            url += f"&label_selector={label_selector}"
            response = self.client.get(url, headers=self._get_headers(user_token))
            data = self._handle_response(response)
            return data.get("items", [])
        except Exception as e:
            logger.error(f"获取Pod列表失败: {e}")
            return []

    def get_pod_logs(self, project_id: str, pod_name: str, container: str = None,
                     tail_lines: int = 100, user_token: str = None) -> str:
        """获取Pod日志"""
        try:
            url = self._build_url(f"/api/k8s/pods/{pod_name}/logs", project_id)
            url += f"&tail_lines={tail_lines}"
            if container:
                url += f"&container={container}"
            response = self.client.get(url, headers=self._get_headers(user_token))
            data = self._handle_response(response)
            return data.get("logs", "")
        except Exception as e:
            logger.error(f"获取Pod日志失败: {e}")
            return ""

    def get_pod_status(self, project_id: str, pod_name: str, user_token: str = None) -> dict:
        """获取Pod状态"""
        try:
            url = self._build_url(f"/api/k8s/pods/{pod_name}/status", project_id)
            response = self.client.get(url, headers=self._get_headers(user_token))
            return self._handle_response(response)
        except Exception as e:
            logger.error(f"获取Pod状态失败: {e}")
            return {}

    # ============ 辅助方法 ============

    def get_websocket_exec_url(self, project_id: str, pod_name: str, token: str = None) -> str:
        """获取WebSocket exec URL"""
        base = self.config.k8s_api_service.base_url.replace("http://", "ws://").replace("https://", "wss://")
        url = f"{base}/ws/pods/{pod_name}/exec?project_id={project_id}"
        if token:
            url += f"&token={token}"
        return url

    def close(self):
        """关闭客户端"""
        self.client.close()


# 单例实例
_k8s_api_client: Optional[K8sApiClient] = None


def get_k8s_api_client() -> K8sApiClient:
    """获取K8s API客户端实例"""
    global _k8s_api_client
    if _k8s_api_client is None:
        _k8s_api_client = K8sApiClient()
    return _k8s_api_client
