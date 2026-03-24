# -*- coding: utf-8 -*-
"""
K8S Service API Client
通过HTTP调用secflow-platform-k8s微服务的API接口
支持资源状态查询和资源生命周期管理（创建/删除）
"""

import logging
from typing import Optional, Dict, List, Any, Tuple

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class K8SClient:
    """K8S微服务API客户端"""

    def __init__(self):
        config = get_config()
        self.k8s_service_config = config.k8s_service
        self.auth_service_config = config.auth_service
        self._client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None

        if self.k8s_service_config and self.k8s_service_config.enabled:
            logger.info(f"K8S微服务客户端初始化: {self.k8s_service_config.base_url}")
        else:
            logger.warning("K8S微服务客户端未启用")

    def _default_headers(self) -> Dict[str, str]:
        """构建默认请求头（用于服务间认证）"""
        headers: Dict[str, str] = {}
        machine_token = getattr(self.auth_service_config, "service_machine_token", None)
        if machine_token:
            headers["Authorization"] = f"Bearer {machine_token}"
        return headers

    @property
    def client(self) -> httpx.Client:
        """获取同步HTTP客户端"""
        if self._client is None:
            config = get_config()
            timeout = config.k8s_service.timeout if (config.k8s_service and hasattr(config.k8s_service, 'timeout')) else 30
            self._client = httpx.Client(timeout=timeout, headers=self._default_headers())
        return self._client

    def _get_base_url(self) -> str:
        """获取K8S微服务基础URL"""
        if not self.k8s_service_config:
            raise ValueError("K8S service config is not initialized")
        return self.k8s_service_config.base_url

    # ============ Deployment 状态查询 ============

    def get_deployment_status(self, project_id: str, name: str) -> Optional[Dict[str, Any]]:
        """
        获取Deployment状态
        Args:
            project_id: 项目ID
            name: Deployment名称

        Returns:
            状态字典，包含:
            - name: Deployment名称
            - replicas: 期望副本数
            - ready_replicas: 就绪副本数
            - available_replicas: 可用副本数
            - updated_replicas: 已更新副本数
            - status: Running/Pending
        """
        try:
            url = f"{self._get_base_url()}/deployments/{name}?project_id={project_id}"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()

            # 兼容不同的字段命名
            replicas = data.get("replicas") or data.get("replica", 0)
            ready_replicas = data.get("ready_replicas") or data.get("ready_replica", 0)
            available_replicas = data.get("available_replicas") or data.get("available_replica", 0)
            updated_replicas = data.get("updated_replicas") or data.get("updated_replica", 0)

            return {
                "name": data.get("name"),
                "replicas": replicas,
                "available_replicas": available_replicas,
                "ready_replicas": ready_replicas,
                "updated_replicas": updated_replicas,
                "status": "Running" if ready_replicas >= replicas and replicas > 0 else "Pending"
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            logger.error(f"获取Deployment状态失败: {e}")
            return None
        except httpx.HTTPError as e:
            logger.error(f"获取Deployment状态失败: {e}")
            return None
        except Exception as e:
            logger.error(f"获取Deployment状态异常: {e}")
            return None

    # ============ Job 状态查询 ============

    def get_job_status(self, project_id: str, name: str) -> Optional[Dict[str, Any]]:
        """
        获取Job状态
        Args:
            project_id: 项目ID
            name: Job名称

        Returns:
            状态字典，包含:
            - name: Job名称
            - status: Pending/Running/Succeeded/Failed
            - succeeded: 成功次数
            - failed: 失败次数
            - active: 活跃次数
        """
        try:
            url = f"{self._get_base_url()}/jobs/{name}?project_id={project_id}"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()

            # 解析状态
            status = "Pending"
            if data.get("succeeded", 0) > 0:
                status = "Succeeded"
            elif data.get("failed", 0) > 0:
                status = "Failed"
            elif data.get("active", 0) > 0:
                status = "Running"

            return {
                "name": data.get("name"),
                "status": status,
                "succeeded": data.get("succeeded", 0),
                "failed": data.get("failed", 0),
                "active": data.get("active", 0),
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            logger.error(f"获取Job状态失败: {e}")
            return None
        except httpx.HTTPError as e:
            logger.error(f"获取Job状态失败: {e}")
            return None
        except Exception as e:
            logger.error(f"获取Job状态异常: {e}")
            return None

    # ============ Pod 操作 ============

    def get_deployment_pods(self, project_id: str, deployment_name: str) -> List[Dict[str, Any]]:
        """获取Deployment的pod列表"""
        try:
            url = f"{self._get_base_url()}/pods?project_id={project_id}&label_selector=app={deployment_name}"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"获取Deployment Pods失败: {e}")
            return []
        except Exception as e:
            logger.error(f"获取Deployment Pods异常: {e}")
            return []

    def get_job_pods(self, project_id: str, job_name: str) -> List[Dict[str, Any]]:
        """获取Job的pod列表"""
        try:
            url = f"{self._get_base_url()}/pods?project_id={project_id}&label_selector=job-name={job_name}"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"获取Job Pods失败: {e}")
            return []
        except Exception as e:
            logger.error(f"获取Job Pods异常: {e}")
            return []

    def get_pod_logs(
        self,
        project_id: str,
        pod_name: str,
        container: Optional[str] = None,
        tail_lines: int = 100,
        previous: bool = False
    ) -> Optional[str]:
        """
        获取Pod日志

        Args:
            project_id: 项目ID
            pod_name: Pod名称
            container: 容器名称（多容器时指定）
            tail_lines: 返回日志行数
            previous: 是否获取前一个容器的日志

        Returns:
            日志字符串
        """
        try:
            url = f"{self._get_base_url()}/pods/{pod_name}/logs?project_id={project_id}&tail_lines={tail_lines}&previous={previous}"
            if container:
                url += f"&container={container}"

            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("logs", "")
        except httpx.HTTPError as e:
            logger.error(f"获取Pod日志失败: {e}")
            return None
        except Exception as e:
            logger.error(f"获取Pod日志异常: {e}")
            return None

    # ============ List Resources Operations ============

    def list_deployments(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出 namespace 中的 Deployments"""
        try:
            url = f"{self._get_base_url()}/deployments?project_id={project_id}"
            if label_selector:
                url += f"&label_selector={label_selector}"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"列出 Deployments 失败: {e}")
            return []
        except Exception as e:
            logger.error(f"列出 Deployments 异常: {e}")
            return []

    def list_services(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出 namespace 中的 Services"""
        try:
            url = f"{self._get_base_url()}/services?project_id={project_id}"
            if label_selector:
                url += f"&label_selector={label_selector}"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"列出 Services 失败: {e}")
            return []
        except Exception as e:
            logger.error(f"列出 Services 异常: {e}")
            return []

    def list_jobs(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出 namespace 中的 Jobs"""
        try:
            url = f"{self._get_base_url()}/jobs?project_id={project_id}"
            if label_selector:
                url += f"&label_selector={label_selector}"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"列出 Jobs 失败: {e}")
            return []
        except Exception as e:
            logger.error(f"列出 Jobs 异常: {e}")
            return []

    # ============ Ingress Controller Operations ============

    def get_ingress_controllers(self) -> List[Dict[str, Any]]:
        """获取集群中可用的 Ingress Controller 列表"""
        try:
            url = f"{self._get_base_url()}/ingress-controllers"
            response = self.client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"获取 Ingress Controller 列表失败: {e}")
            return []
        except Exception as e:
            logger.error(f"获取 Ingress Controller 列表异常: {e}")
            return []

    def get_service_access_info(self, project_id: str, service_name: str) -> Dict[str, Any]:
        """获取 Service 访问与 Ingress 访问信息。"""
        try:
            url = f"{self._get_base_url()}/services/{service_name}/access?project_id={project_id}"
            response = self.client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取 Service 访问详情失败: {e}")
            raise
        except Exception as e:
            logger.error(f"获取 Service 访问详情异常: {e}")
            raise

    # ============ Namespace 操作 ============

    def get_project_namespace(self, project_id: str) -> str:
        """获取项目namespace名称"""
        return f"secflow-{project_id}"

    def ensure_namespace(self, project_id: str) -> Tuple[bool, str]:
        """
        确保namespace存在

        Returns:
            tuple[bool, str]: (是否存在, 错误信息或状态)
        """
        namespace = self.get_project_namespace(project_id)
        try:
            result = self.check_namespace_exists(namespace)
            if result.get("exists", False):
                return True, "Namespace exists"
            else:
                status = result.get("status", "Unknown")
                error = result.get("error", "")
                if status == "ServerError":
                    return False, f"K8S服务内部错误: {error}"
                elif status == "ConnectionError":
                    return False, "无法连接K8S服务"
                else:
                    return False, f"Namespace不存在或状态异常: {status}"
        except Exception as e:
            logger.error(f"检测namespace失败: {e}")
            return False, f"检测namespace异常: {str(e)}"

    def check_namespace_exists(self, namespace: str) -> Dict:
        """检测namespace是否存在"""
        try:
            url = f"{self._get_base_url()}/namespaces/{namespace}"
            response = self.client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 500:
                logger.error(f"K8S服务内部错误: {e.response.text}")
                return {"exists": False, "name": namespace, "status": "ServerError", "error": e.response.text}
            logger.error(f"检测namespace失败: {e}")
            return {"exists": False, "name": namespace, "status": "Error"}
        except httpx.HTTPError as e:
            logger.error(f"检测namespace失败: {e}")
            return {"exists": False, "name": namespace, "status": "ConnectionError"}
        except Exception as e:
            logger.error(f"检测namespace异常: {e}")
            return {"exists": False, "name": namespace, "status": "Exception", "error": str(e)}

    # ============ Deployment 操作 ============

    def create_deployment(
        self,
        project_id: str,
        name: str,
        containers: List[Dict[str, Any]],
        ports: Optional[List[Dict[str, Any]]] = None,
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        replicas: int = 1
    ) -> Tuple[bool, Optional[str]]:
        """
        创建Deployment

        Args:
            project_id: 项目ID
            name: Deployment名称
            containers: 容器配置列表
            ports: 端口配置
            volume_mounts: 卷挂载
            replicas: 副本数

        Returns:
            (success, error_message)
        """
        try:
            namespace = self.get_project_namespace(project_id)

            # 构建Deployment manifest
            manifest = self._build_deployment_manifest(
                name=name,
                namespace=namespace,
                containers=containers,
                ports=ports,
                volume_mounts=volume_mounts,
                replicas=replicas
            )

            # 确保replicas在manifest中
            if "spec" not in manifest:
                manifest["spec"] = {}
            if manifest["spec"].get("replicas", 1) < 1:
                manifest["spec"]["replicas"] = 1
            logger.info(f"创建Deployment {name}, replicas={manifest['spec'].get('replicas', 1)}")

            url = f"{self._get_base_url()}/deployments?project_id={project_id}"
            response = self.client.post(url, json={"manifest": manifest})
            response.raise_for_status()
            logger.info(f"Deployment {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Deployment {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Deployment {name} 失败: {e.response.text}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"创建Deployment {name} 异常: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def _build_deployment_manifest(
        self,
        name: str,
        namespace: str,
        containers: List[Dict[str, Any]],
        ports: Optional[List[Dict[str, Any]]] = None,
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        replicas: int = 1
    ) -> Dict:
        """构建Deployment manifest"""

        # 构建容器列表
        k8s_containers = []
        volumes = []
        pvc_volumes = {}
        volume_index = 0

        for idx, container in enumerate(containers):
            container_name = container.get("name", f"container-{idx}")

            # 构建容器端口
            container_ports = []
            if idx == 0 and ports:
                for port in ports:
                    container_ports.append({
                        "name": port.get("name", f"port-{port.get('containerPort', 8080)}"),
                        "containerPort": port.get("containerPort", port.get("port", 8080)),
                        "protocol": port.get("protocol", "TCP")
                    })

            # 构建环境变量
            env = []
            for e in container.get("env_vars", []):
                if e.get("name"):
                    env.append({"name": e["name"], "value": e.get("value", "")})

            # 构建卷挂载
            container_mounts = []
            for vm in container.get("volume_mounts", []):
                pvc_name = vm.get("pvc_name")
                mount_path = vm.get("mount_path")
                if not pvc_name or not mount_path:
                    continue

                if pvc_name not in pvc_volumes:
                    volume_name = f"volume-{volume_index}"
                    pvc_volumes[pvc_name] = volume_name
                    volumes.append({
                        "name": volume_name,
                        "persistentVolumeClaim": {"claimName": pvc_name}
                    })
                    volume_index += 1

                container_mounts.append({
                    "name": pvc_volumes[pvc_name],
                    "mountPath": mount_path,
                    "subPath": vm.get("sub_path"),
                    "readOnly": vm.get("read_only", False)
                })

            # 构建资源需求
            resources = container.get("resources") or None

            k8s_container = {
                "name": container_name,
                "image": container.get("image"),
                "ports": container_ports or [],
                "env": env or [],
                "volumeMounts": container_mounts or [],
                "resources": resources,
                "imagePullPolicy": container.get("image_pull_policy", "IfNotPresent"),
            }

            # 添加健康检查
            if container.get("liveness_probe"):
                k8s_container["livenessProbe"] = self._build_probe(container["liveness_probe"])
            if container.get("readiness_probe"):
                k8s_container["readinessProbe"] = self._build_probe(container["readiness_probe"])

            # 添加命令和参数
            if container.get("command"):
                k8s_container["command"] = container["command"]
            if container.get("args"):
                k8s_container["args"] = container["args"]

            # 添加特权模式
            if container.get("privileged"):
                k8s_container["securityContext"] = {"privileged": True}

            k8s_containers.append(k8s_container)

        manifest = {
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "app": name,
                    "managed-by": "secflow-workflow-status"
                }
            },
            "spec": {
                "replicas": replicas,
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {"labels": {"app": name}},
                    "spec": {
                        "containers": k8s_containers,
                        "volumes": volumes or []
                    }
                }
            }
        }

        return manifest

    def _build_probe(self, probe_config: Dict) -> Dict:
        """构建健康检查配置"""
        probe_type = probe_config.get("type", "http")
        probe = {
            "initialDelaySeconds": probe_config.get("initialDelaySeconds", 10),
            "periodSeconds": probe_config.get("periodSeconds", 10),
            "timeoutSeconds": probe_config.get("timeoutSeconds", 5),
            "failureThreshold": probe_config.get("failureThreshold", 3),
            "successThreshold": probe_config.get("successThreshold", 1),
        }

        if probe_type == "http":
            probe["httpGet"] = {
                "path": probe_config.get("path", "/health"),
                "port": probe_config.get("port", 8080)
            }
        elif probe_type == "tcp":
            probe["tcpSocket"] = {
                "port": probe_config.get("port", 8080)
            }
        elif probe_type == "exec":
            probe["exec"] = {
                "command": probe_config.get("command", ["echo", "ok"])
            }

        return probe

    def delete_deployment(self, project_id: str, name: str) -> bool:
        """删除Deployment"""
        try:
            url = f"{self._get_base_url()}/deployments/{name}?project_id={project_id}"
            response = self.client.delete(url)
            response.raise_for_status()
            logger.info(f"Deployment {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Deployment {name} 失败: {e}")
            return False
        except Exception as e:
            logger.error(f"删除Deployment {name} 异常: {e}")
            return False

    # ============ Service 操作 ============

    def create_service(
        self,
        project_id: str,
        name: str,
        selector: Dict[str, str],
        ports: List[Dict[str, Any]],
        service_type: str = "ClusterIP"
    ) -> Tuple[bool, Optional[str]]:
        """创建Service"""
        try:
            url = f"{self._get_base_url()}/services?project_id={project_id}"

            service_ports = []
            for port in ports:
                service_ports.append({
                    "name": port.get("name", f"port-{port['port']}"),
                    "port": port["port"],
                    "targetPort": port.get("targetPort", port["port"]),
                    "protocol": port.get("protocol", "TCP")
                })

            payload = {
                "name": name,
                "type": service_type,
                "selector": selector,
                "ports": service_ports
            }

            response = self.client.post(url, json=payload)
            response.raise_for_status()
            logger.info(f"Service {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Service {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Service {name} 失败: {e.response.text}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"创建Service {name} 异常: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def delete_service(self, project_id: str, name: str) -> bool:
        """删除Service"""
        try:
            url = f"{self._get_base_url()}/services/{name}?project_id={project_id}"
            response = self.client.delete(url)
            response.raise_for_status()
            logger.info(f"Service {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Service {name} 失败: {e}")
            return False
        except Exception as e:
            logger.error(f"删除Service {name} 异常: {e}")
            return False

    # ============ Ingress 操作 ============

    def create_ingress(
        self,
        project_id: str,
        name: str,
        service_name: str,
        service_port: int,
        host: Optional[str] = None,
        host_prefix: Optional[str] = None,
        ingress_type: str = "nginx",
        ingress_ip: Optional[str] = None,
        path: str = "/",
        path_type: str = "Prefix"
    ) -> Tuple[bool, Optional[str]]:
        """
        创建Ingress

        Args:
            project_id: 项目ID
            name: Ingress名称
            service_name: 后端Service名称
            service_port: 后端Service端口
            host: 域名（可选，优先级高于host_prefix）
            host_prefix: 域名前缀（可选，不传时默认按name映射）
            ingress_type: Ingress类型 (nginx)
            ingress_ip: Ingress IP地址 (可选)
            path: 路径，默认为根路径
            path_type: 路径类型

        Returns:
            (success, error_message)
        """
        try:
            url = f"{self._get_base_url()}/ingresses/simple?project_id={project_id}"

            payload = {
                "name": name,
                "service_name": service_name,
                "service_port": service_port,
                "host": host,
                "host_prefix": host_prefix,
                "ingress_type": ingress_type,
                "ingress_ip": ingress_ip,
                "path": path,
                "path_type": path_type
            }

            response = self.client.post(url, json=payload)
            response.raise_for_status()
            logger.info(f"Ingress {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Ingress {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Ingress {name} 失败: {e.response.text}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"创建Ingress {name} 异常: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def bind_ingress_domain(
        self,
        project_id: str,
        name: str,
        service_name: str,
        service_port: int,
        host: str,
        ingress_type: str = "nginx",
        ingress_ip: Optional[str] = None,
        path: str = "/",
        path_type: str = "Prefix"
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """为指定 Ingress 绑定域名与所选 IP。"""
        try:
            url = f"{self._get_base_url()}/ingresses/{name}/bind-domain?project_id={project_id}"
            payload = {
                "service_name": service_name,
                "service_port": service_port,
                "host": host,
                "ingress_type": ingress_type,
                "ingress_ip": ingress_ip,
                "path": path,
                "path_type": path_type,
            }
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Ingress {name} 域名绑定成功")
            return True, None, data
        except httpx.HTTPError as e:
            error_msg = f"Ingress {name} 域名绑定失败: {e}"
            if hasattr(e, "response") and e.response is not None:
                error_msg = f"Ingress {name} 域名绑定失败: {e.response.text}"
            logger.error(error_msg)
            return False, error_msg, None
        except Exception as e:
            error_msg = f"Ingress {name} 域名绑定异常: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None

    def delete_ingress(self, project_id: str, name: str) -> bool:
        """删除Ingress"""
        try:
            url = f"{self._get_base_url()}/ingresses/{name}?project_id={project_id}"
            response = self.client.delete(url)
            response.raise_for_status()
            logger.info(f"Ingress {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Ingress {name} 失败: {e}")
            return False
        except Exception as e:
            logger.error(f"删除Ingress {name} 异常: {e}")
            return False

    # ============ Job 操作 ============

    def create_job(
        self,
        project_id: str,
        name: str,
        containers: List[Dict[str, Any]],
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        ttl_seconds_after_finished: Optional[int] = 3600,
        backoff_limit: int = 3
    ) -> Tuple[bool, Optional[str]]:
        """创建Job"""
        try:
            namespace = self.get_project_namespace(project_id)

            manifest = self._build_job_manifest(
                name=name,
                namespace=namespace,
                containers=containers,
                volume_mounts=volume_mounts,
                ttl_seconds_after_finished=ttl_seconds_after_finished,
                backoff_limit=backoff_limit
            )

            url = f"{self._get_base_url()}/jobs?project_id={project_id}"
            response = self.client.post(url, json={"manifest": manifest})
            response.raise_for_status()
            logger.info(f"Job {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Job {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Job {name} 失败: {e.response.text}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"创建Job {name} 异常: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def _build_job_manifest(
        self,
        name: str,
        namespace: str,
        containers: List[Dict[str, Any]],
        volume_mounts: Optional[List[Dict[str, Any]]] = None,
        ttl_seconds_after_finished: Optional[int] = 3600,
        backoff_limit: int = 3
    ) -> Dict:
        """构建Job manifest"""

        k8s_containers = []
        volumes = []
        pvc_volumes = {}
        volume_index = 0

        for idx, container in enumerate(containers):
            container_name = container.get("name", f"container-{idx}")

            # 构建环境变量
            env = []
            for e in container.get("env_vars", []):
                if e.get("name"):
                    env.append({"name": e["name"], "value": e.get("value", "")})

            # 构建卷挂载
            container_mounts = []
            for vm in container.get("volume_mounts", []):
                pvc_name = vm.get("pvc_name")
                mount_path = vm.get("mount_path")
                if not pvc_name or not mount_path:
                    continue

                if pvc_name not in pvc_volumes:
                    volume_name = f"volume-{volume_index}"
                    pvc_volumes[pvc_name] = volume_name
                    volumes.append({
                        "name": volume_name,
                        "persistentVolumeClaim": {"claimName": pvc_name}
                    })
                    volume_index += 1

                container_mounts.append({
                    "name": pvc_volumes[pvc_name],
                    "mountPath": mount_path,
                    "subPath": vm.get("sub_path"),
                    "readOnly": vm.get("read_only", False)
                })

            k8s_container = {
                "name": container_name,
                "image": container.get("image"),
                "env": env or [],
                "volumeMounts": container_mounts or [],
                "imagePullPolicy": container.get("image_pull_policy", "IfNotPresent"),
            }

            if container.get("resources"):
                k8s_container["resources"] = container["resources"]
            if container.get("command"):
                k8s_container["command"] = container["command"]
            if container.get("args"):
                k8s_container["args"] = container["args"]
            if container.get("privileged"):
                k8s_container["securityContext"] = {"privileged": True}

            k8s_containers.append(k8s_container)

        manifest = {
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {"managed-by": "secflow-workflow-status"}
            },
            "spec": {
                "ttlSecondsAfterFinished": ttl_seconds_after_finished,
                "backoffLimit": backoff_limit,
                "template": {
                    "metadata": {"labels": {"job-name": name}},
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": k8s_containers,
                        "volumes": volumes or []
                    }
                }
            }
        }

        return manifest

    def delete_job(self, project_id: str, name: str) -> bool:
        """删除Job"""
        try:
            url = f"{self._get_base_url()}/jobs/{name}?project_id={project_id}"
            response = self.client.delete(url)
            response.raise_for_status()
            logger.info(f"Job {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Job {name} 失败: {e}")
            return False
        except Exception as e:
            logger.error(f"删除Job {name} 异常: {e}")
            return False

    def close(self):
        """关闭客户端连接"""
        if self._client:
            self._client.close()
            self._client = None
        # 异步客户端未实现，这里预留关闭逻辑
        if self._async_client:
            import asyncio
            asyncio.run(self._async_client.aclose())
            self._async_client = None


# 单例实例
_k8s_client: Optional[K8SClient] = None


def get_k8s_client() -> K8SClient:
    """获取K8S微服务客户端实例"""
    global _k8s_client
    if _k8s_client is None:
        _k8s_client = K8SClient()
    return _k8s_client
