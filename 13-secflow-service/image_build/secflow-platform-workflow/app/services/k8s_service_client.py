"""
K8S Service API Client
通过HTTP调用secflow-platform-k8s微服务的API接口
"""

import logging
from typing import Optional, Dict, List, Any, Tuple

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class K8SServiceClient:
    """K8S微服务API客户端"""

    def __init__(self):
        config = get_config()
        self.k8s_service_config = config.k8s_service
        self.auth_service_config = config.auth_service
        self._client: Optional[httpx.AsyncClient] = None
        self._sync_client: Optional[httpx.Client] = None

        # 直接连接的回退客户端
        self._fallback_client = None
        if self.k8s_service_config and self.k8s_service_config.enabled:
            logger.info(f"K8S微服务客户端初始化: {self.k8s_service_config.base_url}")
        else:
            logger.info("K8S微服务客户端未启用，使用直接连接模式")

    def _default_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        machine_token = getattr(self.auth_service_config, "service_machine_token", None)
        if machine_token:
            headers["Authorization"] = f"Bearer {machine_token}"
        return headers

    @property
    def client(self) -> httpx.AsyncClient:
        """获取异步HTTP客户端"""
        if self._client is None:
            config = get_config()
            timeout = config.k8s_service.timeout if config.k8s_service else 30
            self._client = httpx.AsyncClient(timeout=timeout, headers=self._default_headers())
        return self._client

    @property
    def sync_client(self) -> httpx.Client:
        """获取同步HTTP客户端"""
        if self._sync_client is None:
            config = get_config()
            timeout = config.k8s_service.timeout if config.k8s_service else 30
            self._sync_client = httpx.Client(timeout=timeout, headers=self._default_headers())
        return self._sync_client

    def _get_base_url(self) -> str:
        """获取K8S微服务基础URL"""
        return self.k8s_service_config.base_url

    def get_project_namespace(self, project_id: str) -> str:
        """获取项目namespace名称"""
        return f"secflow-{project_id}"

    # ============ Namespace 操作 ============

    def ensure_namespace(self, project_id: str) -> tuple[bool, str]:
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
                    return False, f"无法连接K8S服务"
                else:
                    return False, f"Namespace不存在或状态异常: {status}"
        except Exception as e:
            logger.error(f"检查namespace失败: {e}")
            return False, f"检查namespace异常: {str(e)}"

    def check_namespace_exists(self, namespace: str) -> Dict:
        """检查namespace是否存在"""
        url = f"{self._get_base_url()}/namespaces/{namespace}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 500:
                logger.error(f"K8S服务内部错误: {e.response.text}")
                return {"exists": False, "name": namespace, "status": "ServerError", "error": e.response.text}
            logger.error(f"检查namespace失败: {e}")
            return {"exists": False, "name": namespace, "status": "Error"}
        except httpx.HTTPError as e:
            logger.error(f"检查namespace失败: {e}")
            return {"exists": False, "name": namespace, "status": "ConnectionError"}

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
        try:
            response = self.sync_client.post(url, json={"manifest": manifest})
            response.raise_for_status()
            logger.info(f"Deployment {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Deployment {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Deployment {name} 失败: {e.response.text}"
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
        attached_volumes = {}
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
                mount_path = vm.get("mount_path")
                volume_type = vm.get("volume_type", "pvc")
                if not mount_path:
                    continue

                if volume_type == "nfs":
                    nfs_server = vm.get("nfs_server")
                    nfs_path = vm.get("nfs_path")
                    if not nfs_server or not nfs_path:
                        continue
                    volume_key = f"nfs::{nfs_server}::{nfs_path}"
                    volume_spec = {"nfs": {"server": nfs_server, "path": nfs_path}}
                else:
                    pvc_name = vm.get("pvc_name")
                    if not pvc_name:
                        continue
                    volume_key = f"pvc::{pvc_name}"
                    volume_spec = {"persistentVolumeClaim": {"claimName": pvc_name}}

                if volume_key not in attached_volumes:
                    volume_name = f"volume-{volume_index}"
                    attached_volumes[volume_key] = volume_name
                    volumes.append({
                        "name": volume_name,
                        **volume_spec,
                    })
                    volume_index += 1

                container_mounts.append({
                    "name": attached_volumes[volume_key],
                    "mountPath": mount_path,
                    "subPath": vm.get("sub_path"),
                    "readOnly": vm.get("read_only", False)
                })

            # 构建资源需求
            resources = None
            if container.get("resources"):
                resources = container["resources"]

            k8s_container = {
                "name": container_name,
                "image": container.get("image"),
                "ports": container_ports if container_ports else None,
                "env": env if env else None,
                "volumeMounts": container_mounts if container_mounts else None,
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
                    "managed-by": "secflow-workflow"
                }
            },
            "spec": {
                "replicas": replicas,
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {"labels": {"app": name}},
                    "spec": {
                        "containers": k8s_containers,
                        "volumes": volumes if volumes else None
                    }
                }
            }
        }

        return manifest

    def _build_probe(self, probe_config: Dict) -> Dict:
        """构建健康检查探针"""
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
        url = f"{self._get_base_url()}/deployments/{name}?project_id={project_id}"
        try:
            response = self.sync_client.delete(url)
            response.raise_for_status()
            logger.info(f"Deployment {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Deployment {name} 失败: {e}")
            return False

    def get_deployment_status(self, project_id: str, name: str) -> Optional[Dict[str, Any]]:
        """获取Deployment状态"""
        url = f"{self._get_base_url()}/deployments/{name}?project_id={project_id}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
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
        except httpx.HTTPError as e:
            if hasattr(e, 'response') and e.response and e.response.status_code == 404:
                return None
            logger.error(f"获取Deployment状态失败: {e}")
            return None

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
        url = f"{self._get_base_url()}/services?project_id={project_id}"

        service_ports = []
        for port in ports:
            service_ports.append({
                "name": port.get("name", f"port-{port['port']}"),
                "port": port["port"],
                "target_port": port.get("targetPort", port["port"]),
                "protocol": port.get("protocol", "TCP")
            })

        payload = {
            "name": name,
            "type": service_type,
            "selector": selector,
            "ports": service_ports
        }

        try:
            response = self.sync_client.post(url, json=payload)
            response.raise_for_status()
            logger.info(f"Service {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Service {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Service {name} 失败: {e.response.text}"
            logger.error(error_msg)
            return False, error_msg

    def delete_service(self, project_id: str, name: str) -> bool:
        """删除Service"""
        url = f"{self._get_base_url()}/services/{name}?project_id={project_id}"
        try:
            response = self.sync_client.delete(url)
            response.raise_for_status()
            logger.info(f"Service {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Service {name} 失败: {e}")
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
            host_prefix: 域名前缀（可选，不传时平台按name推导）
            ingress_type: Ingress类型 (nginx)
            ingress_ip: Ingress IP地址 (可选)
            path: 路径，默认为根路径
            path_type: 路径类型

        Returns:
            (success, error_message)
        """
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

        try:
            response = self.sync_client.post(url, json=payload)
            response.raise_for_status()
            logger.info(f"Ingress {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Ingress {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Ingress {name} 失败: {e.response.text}"
            logger.error(error_msg)
            return False, error_msg

    def delete_ingress(self, project_id: str, name: str) -> bool:
        """删除Ingress"""
        url = f"{self._get_base_url()}/ingresses/{name}?project_id={project_id}"
        try:
            response = self.sync_client.delete(url)
            response.raise_for_status()
            logger.info(f"Ingress {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Ingress {name} 失败: {e}")
            return False

    def get_ingress(self, project_id: str, name: str) -> Optional[Dict[str, Any]]:
        """获取Ingress信息"""
        url = f"{self._get_base_url()}/ingresses/{name}?project_id={project_id}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            if hasattr(e, 'response') and e.response and e.response.status_code == 404:
                return None
            logger.error(f"获取Ingress {name} 失败: {e}")
            return None

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
        try:
            response = self.sync_client.post(url, json={"manifest": manifest})
            response.raise_for_status()
            logger.info(f"Job {name} 创建成功")
            return True, None
        except httpx.HTTPError as e:
            error_msg = f"创建Job {name} 失败: {e}"
            if hasattr(e, 'response') and e.response:
                error_msg = f"创建Job {name} 失败: {e.response.text}"
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
        attached_volumes = {}
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
                mount_path = vm.get("mount_path")
                volume_type = vm.get("volume_type", "pvc")
                if not mount_path:
                    continue

                if volume_type == "nfs":
                    nfs_server = vm.get("nfs_server")
                    nfs_path = vm.get("nfs_path")
                    if not nfs_server or not nfs_path:
                        continue
                    volume_key = f"nfs::{nfs_server}::{nfs_path}"
                    volume_spec = {"nfs": {"server": nfs_server, "path": nfs_path}}
                else:
                    pvc_name = vm.get("pvc_name")
                    if not pvc_name:
                        continue
                    volume_key = f"pvc::{pvc_name}"
                    volume_spec = {"persistentVolumeClaim": {"claimName": pvc_name}}

                if volume_key not in attached_volumes:
                    volume_name = f"volume-{volume_index}"
                    attached_volumes[volume_key] = volume_name
                    volumes.append({
                        "name": volume_name,
                        **volume_spec,
                    })
                    volume_index += 1

                container_mounts.append({
                    "name": attached_volumes[volume_key],
                    "mountPath": mount_path,
                    "subPath": vm.get("sub_path"),
                    "readOnly": vm.get("read_only", False)
                })

            k8s_container = {
                "name": container_name,
                "image": container.get("image"),
                "env": env if env else None,
                "volumeMounts": container_mounts if container_mounts else None,
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
                "labels": {"managed-by": "secflow-workflow"}
            },
            "spec": {
                "ttlSecondsAfterFinished": ttl_seconds_after_finished,
                "backoffLimit": backoff_limit,
                "template": {
                    "metadata": {"labels": {"job-name": name}},
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": k8s_containers,
                        "volumes": volumes if volumes else None
                    }
                }
            }
        }

        return manifest

    def delete_job(self, project_id: str, name: str) -> bool:
        """删除Job"""
        url = f"{self._get_base_url()}/jobs/{name}?project_id={project_id}"
        try:
            response = self.sync_client.delete(url)
            response.raise_for_status()
            logger.info(f"Job {name} 删除成功")
            return True
        except httpx.HTTPError as e:
            logger.error(f"删除Job {name} 失败: {e}")
            return False

    def get_job_status(self, project_id: str, name: str) -> Optional[Dict[str, Any]]:
        """获取Job状态"""
        url = f"{self._get_base_url()}/jobs/{name}?project_id={project_id}"
        try:
            response = self.sync_client.get(url)
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
        except httpx.HTTPError as e:
            if hasattr(e, 'response') and e.response and e.response.status_code == 404:
                return None
            logger.error(f"获取Job状态失败: {e}")
            return None

    # ============ Pod 操作 ============

    def get_deployment_pods(self, project_id: str, deployment_name: str) -> List[Dict[str, Any]]:
        """获取Deployment的Pod列表"""
        url = f"{self._get_base_url()}/pods?project_id={project_id}&label_selector=app={deployment_name}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"获取Deployment Pods失败: {e}")
            return []

    def get_job_pods(self, project_id: str, job_name: str) -> List[Dict[str, Any]]:
        """获取Job的Pod列表"""
        url = f"{self._get_base_url()}/pods?project_id={project_id}&label_selector=job-name={job_name}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"获取Job Pods失败: {e}")
            return []

    def get_pod_logs(
        self,
        project_id: str,
        pod_name: str,
        container: Optional[str] = None,
        tail_lines: int = 100,
        previous: bool = False,
        timestamps: bool = True
    ) -> Optional[str]:
        """获取Pod日志"""
        url = f"{self._get_base_url()}/pods/{pod_name}/logs?project_id={project_id}&tail_lines={tail_lines}&previous={previous}"
        if container:
            url += f"&container={container}"

        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("logs", "")
        except httpx.HTTPError as e:
            logger.error(f"获取Pod日志失败: {e}")
            return None

    # ============ List Resources Operations ============

    def list_deployments(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出namespace中的Deployments"""
        url = f"{self._get_base_url()}/deployments?project_id={project_id}"
        if label_selector:
            url += f"&label_selector={label_selector}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"列出Deployments失败: {e}")
            return []

    def list_services(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出namespace中的Services"""
        url = f"{self._get_base_url()}/services?project_id={project_id}"
        if label_selector:
            url += f"&label_selector={label_selector}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"列出Services失败: {e}")
            return []

    def list_jobs(self, project_id: str, label_selector: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出namespace中的Jobs"""
        url = f"{self._get_base_url()}/jobs?project_id={project_id}"
        if label_selector:
            url += f"&label_selector={label_selector}"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"列出Jobs失败: {e}")
            return []

    # ============ Ingress Controller 操作 ============

    def get_ingress_controllers(self) -> List[Dict[str, Any]]:
        """
        获取集群中可用的Ingress Controller列表

        Returns:
            Ingress Controller列表，每个包含:
            - name: Service名称
            - namespace: 所在namespace
            - type: Service类型
            - external_ip: 外部IP地址
            - ports: 端口列表
            - ingress_class: Ingress类型
        """
        url = f"{self._get_base_url()}/ingress-controllers"
        try:
            response = self.sync_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except httpx.HTTPError as e:
            logger.error(f"获取Ingress Controller列表失败: {e}")
            return []


# 单例实例
_k8s_service_client: Optional[K8SServiceClient] = None


def get_k8s_service_client() -> K8SServiceClient:
    """获取K8S微服务客户端实例"""
    global _k8s_service_client
    if _k8s_service_client is None:
        _k8s_service_client = K8SServiceClient()
    return _k8s_service_client
