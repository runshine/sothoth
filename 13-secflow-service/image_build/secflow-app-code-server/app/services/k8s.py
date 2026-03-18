"""
Code Server Manager - K8S API 客户端服务（统一通过 secflow-platform-k8s）
"""

import logging
from typing import Optional, List, Dict, Any, Tuple

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class K8SService:
    """K8S服务类（通过 platform-k8s 微服务）"""

    def __init__(self):
        self.config = get_config()
        timeout = getattr(self.config.kubernetes, "connection_timeout", 30)
        self.client = httpx.Client(timeout=timeout)
        self.base_url = self._build_base_url()

    def _build_base_url(self) -> str:
        # 优先读取统一的 k8s_service 配置，兼容旧配置
        k8s_service = getattr(self.config, "k8s_service", None)
        if k8s_service:
            return f"http://{k8s_service.host}:{k8s_service.port}/api/k8s"
        return "http://secflow-platform-k8s:80/api/k8s"

    @staticmethod
    def _project_id_from_namespace(namespace: str) -> str:
        if not namespace or not namespace.startswith("secflow-"):
            raise ValueError(f"无效namespace，无法解析project_id: {namespace}")
        return namespace.replace("secflow-", "", 1)

    def _request(self, method: str, path: str, project_id: Optional[str] = None, **kwargs) -> httpx.Response:
        url = f"{self.base_url}{path}"
        params = dict(kwargs.pop("params", {}) or {})
        if project_id:
            params["project_id"] = project_id
        resp = self.client.request(method=method.upper(), url=url, params=params, **kwargs)
        return resp

    def connect(self) -> bool:
        """连接检查（检查 platform-k8s 健康）"""
        try:
            resp = self._request("GET", "/health")
            ok = resp.status_code == 200
            if ok:
                logger.info("通过 platform-k8s 连接验证成功")
            else:
                logger.error(f"通过 platform-k8s 连接验证失败: {resp.status_code} {resp.text}")
            return ok
        except Exception as e:
            logger.error(f"通过 platform-k8s 连接失败: {e}")
            return False

    def check_namespace_exists(self, namespace: str) -> bool:
        """检查Namespace是否存在"""
        try:
            resp = self._request("GET", f"/namespaces/{namespace}")
            if resp.status_code != 200:
                return False
            data = resp.json()
            return bool(data.get("exists", False))
        except Exception as e:
            logger.error(f"检查namespace失败: {e}")
            return False

    def check_pvc_exists(self, namespace: str, pvc_name: str) -> bool:
        """检查PVC是否存在"""
        try:
            project_id = self._project_id_from_namespace(namespace)
            resp = self._request("GET", f"/pvcs/{pvc_name}", project_id=project_id)
            return resp.status_code == 200
        except Exception:
            return False

    def create_pvc(self, namespace: str, pvc_name: str, storage_size: str,
                   storage_class: str = None, access_mode: str = "ReadWriteOnce") -> bool:
        """创建PVC"""
        try:
            project_id = self._project_id_from_namespace(namespace)
            manifest = {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {
                    "name": pvc_name,
                    "namespace": namespace,
                    "labels": {
                        "app": "code-server",
                        "managed-by": "vscode-web-manager"
                    }
                },
                "spec": {
                    "accessModes": [access_mode],
                    "resources": {
                        "requests": {
                            "storage": storage_size
                        }
                    }
                }
            }
            sc = storage_class or self.config.pvc.storage_class
            if sc:
                manifest["spec"]["storageClassName"] = sc
            resp = self._request("POST", "/pvcs", project_id=project_id, json={"manifest": manifest})
            if resp.status_code in (200, 201):
                return True
            if resp.status_code == 409:
                return True
            logger.error(f"创建PVC失败: {resp.status_code} {resp.text}")
            return False
        except Exception as e:
            logger.error(f"创建PVC失败: {e}")
            return False

    def delete_pvc(self, namespace: str, pvc_name: str) -> bool:
        """删除PVC"""
        try:
            project_id = self._project_id_from_namespace(namespace)
            resp = self._request("DELETE", f"/pvcs/{pvc_name}", project_id=project_id)
            return resp.status_code in (200, 404)
        except Exception as e:
            logger.error(f"删除PVC失败: {e}")
            return False

    def create_deployment(self, namespace: str, name: str, code_server_id: str,
                         source_pvcs: List[Dict], output_pvcs: List[Dict],
                         custom_env: Dict[str, str] = None,
                         code_server_env: Dict[str, Any] = None,
                         image: str = None) -> tuple[bool, Optional[Dict[str, Any]]]:
        """创建Deployment"""
        try:
            project_id = self._project_id_from_namespace(namespace)
            config = self.config.code_server

            volumes = []
            volume_mounts = []
            volume_index = 0
            for pvc_info in source_pvcs:
                volume_name = f"source-volume-{volume_index}"
                volumes.append({"name": volume_name, "persistentVolumeClaim": {"claimName": pvc_info["pvc_name"]}})
                volume_mounts.append({"name": volume_name, "mountPath": pvc_info["mount_path"]})
                volume_index += 1
            for pvc_info in output_pvcs:
                volume_name = f"output-volume-{volume_index}"
                volumes.append({"name": volume_name, "persistentVolumeClaim": {"claimName": pvc_info["pvc_name"]}})
                volume_mounts.append({"name": volume_name, "mountPath": pvc_info["mount_path"]})
                volume_index += 1

            import secrets
            final_code_server_env = {}
            cs_env_config = config.code_server_env
            if code_server_env:
                final_code_server_env["PUID"] = str(code_server_env.get("PUID", cs_env_config.get("PUID", 1000)))
                final_code_server_env["PGID"] = str(code_server_env.get("PGID", cs_env_config.get("PGID", 1000)))
                final_code_server_env["TZ"] = code_server_env.get("TZ", cs_env_config.get("TZ", "Asia/Shanghai"))
                final_code_server_env["DEFAULT_WORKSPACE"] = code_server_env.get("DEFAULT_WORKSPACE", cs_env_config.get("DEFAULT_WORKSPACE", "/config/workspace"))
                final_code_server_env["PWA_APPNAME"] = code_server_env.get("PWA_APPNAME", cs_env_config.get("PWA_APPNAME", "code-server"))
                if code_server_env.get("HASHED_PASSWORD"):
                    final_code_server_env["HASHED_PASSWORD"] = code_server_env["HASHED_PASSWORD"]
                elif code_server_env.get("PASSWORD"):
                    final_code_server_env["PASSWORD"] = code_server_env["PASSWORD"]
                elif cs_env_config.get("HASHED_PASSWORD"):
                    final_code_server_env["HASHED_PASSWORD"] = cs_env_config["HASHED_PASSWORD"]
                elif cs_env_config.get("PASSWORD"):
                    final_code_server_env["PASSWORD"] = cs_env_config["PASSWORD"]
                else:
                    final_code_server_env["PASSWORD"] = secrets.token_urlsafe(16)
                if code_server_env.get("SUDO_PASSWORD_HASH"):
                    final_code_server_env["SUDO_PASSWORD_HASH"] = code_server_env["SUDO_PASSWORD_HASH"]
                elif code_server_env.get("SUDO_PASSWORD"):
                    final_code_server_env["SUDO_PASSWORD"] = code_server_env["SUDO_PASSWORD"]
                elif cs_env_config.get("SUDO_PASSWORD_HASH"):
                    final_code_server_env["SUDO_PASSWORD_HASH"] = cs_env_config["SUDO_PASSWORD_HASH"]
                elif cs_env_config.get("SUDO_PASSWORD"):
                    final_code_server_env["SUDO_PASSWORD"] = cs_env_config["SUDO_PASSWORD"]
                else:
                    final_code_server_env["SUDO_PASSWORD"] = secrets.token_urlsafe(16)
                proxy_domain = code_server_env.get("PROXY_DOMAIN", cs_env_config.get("PROXY_DOMAIN"))
                if proxy_domain:
                    final_code_server_env["PROXY_DOMAIN"] = proxy_domain
            else:
                final_code_server_env["PUID"] = str(cs_env_config.get("PUID", 1000))
                final_code_server_env["PGID"] = str(cs_env_config.get("PGID", 1000))
                final_code_server_env["TZ"] = cs_env_config.get("TZ", "Asia/Shanghai")
                final_code_server_env["DEFAULT_WORKSPACE"] = cs_env_config.get("DEFAULT_WORKSPACE", "/config/workspace")
                final_code_server_env["PWA_APPNAME"] = cs_env_config.get("PWA_APPNAME", "code-server")
                if cs_env_config.get("HASHED_PASSWORD"):
                    final_code_server_env["HASHED_PASSWORD"] = cs_env_config["HASHED_PASSWORD"]
                elif cs_env_config.get("PASSWORD"):
                    final_code_server_env["PASSWORD"] = cs_env_config["PASSWORD"]
                else:
                    final_code_server_env["PASSWORD"] = secrets.token_urlsafe(16)
                if cs_env_config.get("SUDO_PASSWORD_HASH"):
                    final_code_server_env["SUDO_PASSWORD_HASH"] = cs_env_config["SUDO_PASSWORD_HASH"]
                elif cs_env_config.get("SUDO_PASSWORD"):
                    final_code_server_env["SUDO_PASSWORD"] = cs_env_config["SUDO_PASSWORD"]
                else:
                    final_code_server_env["SUDO_PASSWORD"] = secrets.token_urlsafe(16)
                if cs_env_config.get("PROXY_DOMAIN"):
                    final_code_server_env["PROXY_DOMAIN"] = cs_env_config["PROXY_DOMAIN"]

            env = []
            for key, value in final_code_server_env.items():
                env.append({"name": key, "value": value})
            for key, value in config.env.items():
                if key not in final_code_server_env:
                    env.append({"name": key, "value": value})
            if custom_env:
                for key, value in custom_env.items():
                    if key not in final_code_server_env:
                        env.append({"name": key, "value": value})

            container_image = image if image else config.image
            deployment_manifest = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {
                        "app": "code-server",
                        "code-server-id": code_server_id,
                        "managed-by": "vscode-web-manager"
                    }
                },
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "code-server", "code-server-id": code_server_id}},
                    "template": {
                        "metadata": {"labels": {"app": "code-server", "code-server-id": code_server_id}},
                        "spec": {
                            "containers": [{
                                "name": "code-server",
                                "image": container_image,
                                "imagePullPolicy": config.image_pull_policy,
                                "ports": [{"containerPort": 8443, "name": "http"}],
                                "env": env,
                                "volumeMounts": volume_mounts,
                                "resources": config.resources
                            }],
                            "volumes": volumes
                        }
                    }
                }
            }
            resp = self._request("POST", "/deployments", project_id=project_id, json={"manifest": deployment_manifest})
            if resp.status_code in (200, 201):
                return True, final_code_server_env
            logger.error(f"创建Deployment失败: {resp.status_code} {resp.text}")
            return False, None
        except Exception as e:
            logger.error(f"创建Deployment失败: {e}")
            return False, None

    def delete_deployment(self, namespace: str, name: str) -> bool:
        try:
            project_id = self._project_id_from_namespace(namespace)
            resp = self._request("DELETE", f"/deployments/{name}", project_id=project_id)
            return resp.status_code in (200, 404)
        except Exception as e:
            logger.error(f"删除Deployment失败: {e}")
            return False

    def scale_deployment(self, namespace: str, name: str, replicas: int) -> bool:
        try:
            project_id = self._project_id_from_namespace(namespace)
            resp = self._request("POST", f"/deployments/{name}/scale", project_id=project_id, json={"replica": replicas})
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"调整Deployment副本数失败: {e}")
            return False

    def get_deployment_status(self, namespace: str, name: str) -> Optional[Dict]:
        try:
            project_id = self._project_id_from_namespace(namespace)
            resp = self._request("GET", f"/deployments/{name}", project_id=project_id)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            dep = resp.json()
            return {
                "name": dep.get("name"),
                "replicas": dep.get("replicas", 0),
                "ready_replicas": dep.get("ready_replicas", 0),
                "available_replicas": dep.get("available_replicas", 0),
            }
        except Exception as e:
            logger.error(f"获取Deployment状态失败: {e}")
            return None

    def create_service(self, namespace: str, name: str, code_server_id: str) -> Optional[str]:
        try:
            project_id = self._project_id_from_namespace(namespace)
            config = self.config.code_server
            manifest = {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {
                        "app": "code-server",
                        "code-server-id": code_server_id,
                        "managed-by": "vscode-web-manager"
                    }
                },
                "spec": {
                    "type": config.service_type,
                    "selector": {"app": "code-server", "code-server-id": code_server_id},
                    "ports": [{
                        "port": 8443,
                        "targetPort": 8443,
                        "protocol": "TCP",
                        "name": "http"
                    }]
                }
            }
            resp = self._request("POST", "/services", project_id=project_id, json={"manifest": manifest})
            if resp.status_code in (200, 201):
                data = resp.json()
                return data.get("cluster_ip")
            if resp.status_code == 409:
                detail = self._request("GET", f"/services/{name}", project_id=project_id)
                if detail.status_code == 200:
                    return detail.json().get("cluster_ip")
            logger.error(f"创建Service失败: {resp.status_code} {resp.text}")
            return None
        except Exception as e:
            logger.error(f"创建Service失败: {e}")
            return None

    def delete_service(self, namespace: str, name: str) -> bool:
        try:
            project_id = self._project_id_from_namespace(namespace)
            resp = self._request("DELETE", f"/services/{name}", project_id=project_id)
            return resp.status_code in (200, 404)
        except Exception as e:
            logger.error(f"删除Service失败: {e}")
            return False

    def create_ingress(self, namespace: str, name: str, code_server_id: str, service_name: str) -> Optional[str]:
        """创建Ingress（统一 host 规则，由 platform-k8s 生成）"""
        try:
            project_id = self._project_id_from_namespace(namespace)
            config = self.config.ingress
            payload = {
                "name": name,
                "service_name": service_name,
                "service_port": 8443,
                "host_prefix": code_server_id,
                "ingress_type": config.ingress_class,
                "path": "/",
                "path_type": "Prefix"
            }
            resp = self._request("POST", "/ingresses/simple", project_id=project_id, json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                rules = data.get("rules") or []
                if rules and rules[0].get("host"):
                    return rules[0]["host"]
            logger.error(f"创建Ingress失败: {resp.status_code} {resp.text}")
            return None
        except Exception as e:
            logger.error(f"创建Ingress失败: {e}")
            return None

    def delete_ingress(self, namespace: str, name: str) -> bool:
        try:
            project_id = self._project_id_from_namespace(namespace)
            resp = self._request("DELETE", f"/ingresses/{name}", project_id=project_id)
            return resp.status_code in (200, 404)
        except Exception as e:
            logger.error(f"删除Ingress失败: {e}")
            return False

    def get_pod_by_deployment(self, namespace: str, deployment_name: str) -> Optional[Dict]:
        try:
            project_id = self._project_id_from_namespace(namespace)
            dep_resp = self._request("GET", f"/deployments/{deployment_name}", project_id=project_id)
            if dep_resp.status_code != 200:
                return None
            dep = dep_resp.json()
            selector = dep.get("selector") or {}
            label_selector = ",".join([f"{k}={v}" for k, v in selector.items()]) if selector else None
            pods_resp = self._request("GET", "/pods", project_id=project_id, params={"label_selector": label_selector} if label_selector else None)
            if pods_resp.status_code != 200:
                return None
            items = (pods_resp.json() or {}).get("items", [])
            if not items:
                return None
            pod = items[0]
            return {
                "name": pod.get("name"),
                "status": pod.get("status"),
                "ip": pod.get("pod_ip"),
                "node_name": pod.get("node_name"),
                "start_time": pod.get("created_at"),
            }
        except Exception as e:
            logger.error(f"获取Pod信息失败: {e}")
            return None

    def get_pod_logs(self, namespace: str, pod_name: str,
                     container: str = None, tail_lines: int = 100) -> Optional[str]:
        try:
            project_id = self._project_id_from_namespace(namespace)
            params = {"tail_lines": tail_lines}
            if container:
                params["container"] = container
            resp = self._request("GET", f"/pods/{pod_name}/logs", project_id=project_id, params=params)
            if resp.status_code != 200:
                return None
            return (resp.json() or {}).get("logs")
        except Exception as e:
            logger.error(f"获取Pod日志失败: {e}")
            return None


_k8s_service: Optional[K8SService] = None


def get_k8s_service() -> K8SService:
    """获取K8S服务实例"""
    global _k8s_service
    if _k8s_service is None:
        _k8s_service = K8SService()
    return _k8s_service
