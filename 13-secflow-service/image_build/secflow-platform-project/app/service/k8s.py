"""
K8S客户端模块（统一通过 secflow-platform-k8s）
"""

import base64
import logging
from typing import Optional, Dict

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class K8SClient:
    """K8S客户端"""

    def __init__(self):
        config = get_config()
        self.k8s_service = config.k8s_service
        self.tls_config = config.tls_secret
        self.client = httpx.Client(timeout=self.k8s_service.timeout)

    @property
    def base_url(self) -> str:
        return f"http://{self.k8s_service.host}:{self.k8s_service.port}/api/k8s"

    def connect(self) -> bool:
        """连接K8S服务"""
        try:
            resp = self.client.get(f"{self.base_url}/health")
            ok = resp.status_code == 200
            if ok:
                logger.info("K8S连接验证成功（通过platform-k8s）")
            else:
                logger.error(f"K8S连接验证失败: {resp.status_code} {resp.text}")
            return ok
        except Exception as e:
            logger.error(f"K8S连接失败: {e}")
            return False

    def generate_namespace_name(self, project_id: str) -> str:
        return f"secflow-{project_id}".replace("_", "-")

    def create_namespace(self, project_id: str) -> bool:
        namespace_name = self.generate_namespace_name(project_id)
        try:
            # 已存在则直接成功
            check = self.client.get(f"{self.base_url}/namespaces/{namespace_name}")
            if check.status_code == 200 and check.json().get("exists", False):
                return True
            resp = self.client.post(f"{self.base_url}/namespaces/{namespace_name}")
            if resp.status_code in (200, 201):
                return True
            logger.error(f"创建namespace失败: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            logger.error(f"创建namespace异常: {e}")
            return False

    def create_tls_secret(self, project_id: str) -> tuple[bool, Optional[str]]:
        """在项目命名空间创建TLS Secret（通过 platform-k8s /secrets）"""
        namespace_name = self.generate_namespace_name(project_id)
        secret_name = self.tls_config.name
        try:
            # 若已存在直接成功
            exists_resp = self.client.get(
                f"{self.base_url}/secrets/{secret_name}",
                params={"project_id": project_id}
            )
            if exists_resp.status_code == 200:
                return True, None

            with open(self.tls_config.crt_file, "rb") as f:
                crt_data = base64.b64encode(f.read()).decode("utf-8")
            with open(self.tls_config.key_file, "rb") as f:
                key_data = base64.b64encode(f.read()).decode("utf-8")

            payload = {
                "name": secret_name,
                "type": "kubernetes.io/tls",
                "data": {"tls.crt": crt_data, "tls.key": key_data},
                "label": {"app": "secflow-project", "project-id": project_id},
                "annotation": {"description": "TLS secret for project ingress"},
            }
            resp = self.client.post(
                f"{self.base_url}/secrets",
                params={"project_id": project_id},
                json=payload
            )
            if resp.status_code in (200, 201):
                logger.info(f"TLS Secret {secret_name} 在Namespace {namespace_name} 中创建成功")
                return True, None
            err = f"创建TLS Secret失败: {resp.status_code} {resp.text}"
            logger.error(err)
            return False, err
        except Exception as e:
            logger.error(f"创建TLS Secret失败: {e}")
            return False, str(e)

    def delete_namespace(self, project_id: str, force: bool = True) -> bool:
        namespace_name = self.generate_namespace_name(project_id)
        try:
            resp = self.client.delete(f"{self.base_url}/namespaces/{namespace_name}")
            if resp.status_code in (200, 404):
                return True
            logger.error(f"删除namespace失败: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            logger.error(f"删除namespace异常: {e}")
            return False

    def get_namespace_status(self, project_id: str) -> Optional[dict]:
        namespace_name = self.generate_namespace_name(project_id)
        try:
            resp = self.client.get(f"{self.base_url}/namespaces/{namespace_name}")
            if resp.status_code != 200:
                return None
            data = resp.json()
            if not data.get("exists", False):
                return None
            return {"name": namespace_name, "status": data.get("status")}
        except Exception as e:
            logger.error(f"获取namespace状态失败: {e}")
            return None

    def list_namespace_resources(self, project_id: str) -> Dict:
        """获取项目下资源列表（通过 platform-k8s 逐类汇总）"""
        try:
            params = {"project_id": project_id}
            def _items(path: str, key: str = "items"):
                r = self.client.get(f"{self.base_url}{path}", params=params)
                if r.status_code != 200:
                    return []
                return (r.json() or {}).get(key, [])

            resources = {
                "pods": [],
                "services": [],
                "configmaps": [],
                "secrets": [],
                "deployments": [],
                "statefulsets": [],
                "pvcs": [],
                "ingresses": [],
            }
            resources["pods"] = _items("/pods")
            resources["services"] = _items("/services")
            resources["configmaps"] = _items("/configmaps")
            resources["secrets"] = _items("/secrets")
            resources["deployments"] = _items("/deployments")
            resources["statefulsets"] = _items("/statefulsets")
            resources["pvcs"] = _items("/pvcs")
            resources["ingresses"] = _items("/ingresses")
            return resources
        except Exception as e:
            logger.error(f"获取资源列表失败: {e}")
            return {
                "pods": [],
                "services": [],
                "configmaps": [],
                "secrets": [],
                "deployments": [],
                "statefulsets": [],
                "pvcs": [],
                "ingresses": [],
            }

    def get_pod_logs(self, project_id: str, pod_name: str,
                     container: str = None, tail_lines: int = 100) -> Optional[str]:
        try:
            params = {"project_id": project_id, "tail_lines": tail_lines}
            if container:
                params["container"] = container
            resp = self.client.get(f"{self.base_url}/pods/{pod_name}/logs", params=params)
            if resp.status_code != 200:
                return None
            return (resp.json() or {}).get("logs")
        except Exception as e:
            logger.error(f"获取Pod日志失败: {e}")
            return None

    def delete_pod(self, project_id: str, pod_name: str) -> bool:
        try:
            resp = self.client.delete(f"{self.base_url}/pods/{pod_name}", params={"project_id": project_id})
            return resp.status_code in (200, 404)
        except Exception as e:
            logger.error(f"删除Pod失败: {e}")
            return False

    def delete_pvc(self, project_id: str, pvc_name: str) -> tuple[bool, Optional[str]]:
        try:
            resp = self.client.delete(f"{self.base_url}/pvcs/{pvc_name}", params={"project_id": project_id})
            if resp.status_code in (200, 404):
                return True, None
            return False, f"删除PVC失败: {resp.status_code} {resp.text}"
        except Exception as e:
            logger.error(f"删除PVC失败: {e}")
            return False, str(e)


_k8s_client: Optional[K8SClient] = None


def get_k8s_client() -> K8SClient:
    global _k8s_client
    if _k8s_client is None:
        _k8s_client = K8SClient()
    return _k8s_client
