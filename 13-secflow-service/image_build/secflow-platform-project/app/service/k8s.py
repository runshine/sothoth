"""
K8S客户端模块
"""

import logging
from typing import Optional, Dict, List

import httpx
from kubernetes import client, config
from kubernetes.client import ApiClient
from kubernetes.client.rest import ApiException

from app.config import get_config

logger = logging.getLogger(__name__)


class K8SClient:
    """K8S客户端"""

    def __init__(self):
        self.config = get_config().kubernetes
        self.k8s_service_config = get_config().k8s_service
        self.tls_config = get_config().tls_secret
        self.client: Optional[ApiClient] = None
        self.core_v1 = None
        self.apps_v1 = None

    def connect(self) -> bool:
        """
        连接K8S集群

        Returns:
            是否连接成功
        """
        try:
            if self.config.in_cluster:
                # 使用ServiceAccount（K8S集群内）
                config.load_incluster_config()
                logger.info("使用ServiceAccount加载K8S配置")
            else:
                # 使用kubeconfig（集群外调试）
                kubeconfig_path = self.config.kubeconfig or "~/.kube/config"
                config.load_kube_config(config_file=kubeconfig_path)
                logger.info(f"使用kubeconfig加载K8S配置: {kubeconfig_path}")

            self.client = client.ApiClient()
            self.core_v1 = client.CoreV1Api(self.client)
            self.apps_v1 = client.AppsV1Api(self.client)

            # 验证连接
            self.core_v1.read_namespace_status("default")
            logger.info("K8S连接验证成功")
            return True

        except Exception as e:
            logger.error(f"K8S连接失败: {e}")
            return False

    def generate_namespace_name(self, project_id: str) -> str:
        """
        生成项目Namespace名称

        Args:
            project_id: 项目ID

        Returns:
            Namespace名称（符合RFC 1123规范）
        """
        # 将下划线替换为连字符，确保符合RFC 1123 DNS命名规范
        return f"secflow-{project_id}".replace("_", "-")

    def create_namespace(self, project_id: str) -> bool:
        """
        创建项目的Namespace

        Args:
            project_id: 项目ID

        Returns:
            是否创建成功
        """
        namespace_name = self.generate_namespace_name(project_id)

        try:
            # 检查namespace是否存在
            try:
                self.core_v1.read_namespace(name=namespace_name)
                logger.info(f"Namespace {namespace_name}已存在")
                return True
            except ApiException as e:
                if e.status != 404:
                    raise

            # 创建namespace
            namespace_manifest = {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace_name,
                    "labels": {
                        "app": "secflow",
                        "project-id": project_id,
                    }
                }
            }

            self.core_v1.create_namespace(body=namespace_manifest)
            logger.info(f"Namespace {namespace_name}创建成功")
            return True

        except ApiException as e:
            logger.error(f"创建Namespace失败: {e}")
            return False

    def create_tls_secret(self, project_id: str, authorization: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
        通过 platform-k8s 在项目Namespace中同步TLS Secret

        Args:
            project_id: 项目ID
            authorization: Bearer Token

        Returns:
            tuple: (是否创建成功, 错误信息)
        """
        base_url = f"http://{self.k8s_service_config.host}:{self.k8s_service_config.port}"
        url = f"{base_url}/api/k8s/projects/{project_id}/tls-secret/sync"
        payload = {
            "source_namespace": self.tls_config.source_namespace,
            "source_secret_name": self.tls_config.source_secret_name,
            "target_secret_name": self.tls_config.name,
        }
        headers = {}
        if authorization:
            headers["Authorization"] = authorization

        try:
            with httpx.Client(timeout=self.k8s_service_config.timeout) as client_http:
                resp = client_http.post(url, json=payload, headers=headers)

            if 200 <= resp.status_code < 300:
                logger.info(
                    "TLS Secret同步成功: project_id=%s, source=%s/%s, target=%s",
                    project_id,
                    self.tls_config.source_namespace,
                    self.tls_config.source_secret_name,
                    self.tls_config.name,
                )
                return True, None

            error_msg = f"{resp.status_code} {resp.text}"
            logger.error("调用platform-k8s同步TLS Secret失败: %s", error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"调用platform-k8s同步TLS Secret异常: {e}"
            logger.error(error_msg)
            return False, error_msg

    def delete_namespace(self, project_id: str, force: bool = True) -> bool:
        """
        删除项目的Namespace及其所有资源

        Args:
            project_id: 项目ID
            force: 是否强制删除（级联删除）

        Returns:
            是否删除成功
        """
        namespace_name = self.generate_namespace_name(project_id)

        try:
            # 检查namespace是否存在
            try:
                self.core_v1.read_namespace(name=namespace_name)
            except ApiException as e:
                if e.status == 404:
                    logger.info(f"Namespace {namespace_name}不存在，视为已删除")
                    return True
                raise

            # 删除namespace（K8S会自动删除namespace下的资源）
            if force:
                self.core_v1.delete_namespace(name=namespace_name)
                logger.info(f"Namespace {namespace_name}删除请求已提交")
            else:
                logger.info(f"Namespace {namespace_name}待手动删除")
            return True

        except ApiException as e:
            logger.error(f"删除Namespace失败: {e}")
            return False

    def get_namespace_status(self, project_id: str) -> Optional[dict]:
        """
        获取Namespace状态

        Args:
            project_id: 项目ID

        Returns:
            Namespace状态信息
        """
        namespace_name = self.generate_namespace_name(project_id)

        try:
            ns = self.core_v1.read_namespace(name=namespace_name)
            return {
                "name": ns.metadata.name,
                "status": ns.status.phase,
                "created_at": ns.metadata.creation_timestamp,
            }
        except ApiException as e:
            if e.status == 404:
                return None
            raise

    def list_namespace_resources(self, project_id: str) -> Dict:
        """
        列出Namespace下的所有资源

        Args:
            project_id: 项目ID

        Returns:
            资源统计信息
        """
        namespace_name = self.generate_namespace_name(project_id)

        try:
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

            # Pods
            pods = self.core_v1.list_namespaced_pod(namespace=namespace_name)
            resources["pods"] = [{"name": p.metadata.name, "status": p.status.phase,
                                  "ip": p.status.pod_ip, "node": p.spec.node_name}
                                 for p in pods.items]

            # Services
            services = self.core_v1.list_namespaced_service(namespace=namespace_name)
            resources["services"] = [{"name": s.metadata.name, "type": s.spec.type,
                                      "cluster_ip": s.spec.cluster_ip, "ports": [p.port for p in s.spec.ports]}
                                     for s in services.items]

            # ConfigMaps
            cms = self.core_v1.list_namespaced_config_map(namespace=namespace_name)
            resources["configmaps"] = [cm.metadata.name for cm in cms.items]

            # Secrets
            secrets_list = self.core_v1.list_namespaced_secret(namespace=namespace_name)
            resources["secrets"] = [s.metadata.name for s in secrets_list.items]

            # Deployments
            deps = self.apps_v1.list_namespaced_deployment(namespace=namespace_name)
            resources["deployments"] = [{"name": d.metadata.name, "replica": d.spec.replicas,
                                         "available_replicas": d.status.available_replicas,
                                         "ready_replicas": d.status.ready_replicas}
                                        for d in deps.items]

            # StatefulSet
            sts = self.apps_v1.list_namespaced_stateful_set(namespace=namespace_name)
            resources["statefulsets"] = [{"name": s.metadata.name, "replica": s.spec.replicas,
                                          "ready_replicas": s.status.ready_replicas}
                                         for s in sts.items]

            # PVCs
            pvcs = self.core_v1.list_namespaced_persistent_volume_claim(namespace=namespace_name)
            resources["pvcs"] = [{"name": pvc.metadata.name, "status": pvc.status.phase,
                                  "capacity": pvc.status.capacity,
                                  "storage_class": pvc.spec.storage_class_name}
                                 for pvc in pvcs.items]

            # Ingresses
            try:
                networking_v1 = client.NetworkingV1Api(self.client)
                ingresses = networking_v1.list_namespaced_ingress(namespace=namespace_name)
                resources["ingresses"] = [{"name": ing.metadata.name,
                                            "host": ing.spec.rules[0].host if ing.spec.rules else None,
                                            "tls": [t.host for t in ing.spec.tls] if ing.spec.tls else []}
                                           for ing in ingresses.items]
            except Exception:
                # 旧版本可能不支持networking.k8s.io/v1
                resources["ingresses"] = []

            return resources

        except ApiException as e:
            logger.error(f"列出资源失败: {e}")
            return {}

    def get_pod_logs(self, project_id: str, pod_name: str,
                     container: Optional[str] = None,
                     tail_lines: int = 100) -> Optional[str]:
        """
        获取Pod日志

        Args:
            project_id: 项目ID
            pod_name: Pod名称
            container: 容器名称（多容器Pod时需要）
            tail_lines: 返回最后行数

        Returns:
            Pod日志内容，失败返回None
        """
        namespace_name = self.generate_namespace_name(project_id)

        try:
            kwargs = {"name": pod_name, "namespace": namespace_name,
                      "tail_lines": tail_lines}
            if container:
                kwargs["container"] = container

            logs = self.core_v1.read_namespaced_pod_log(**kwargs)
            return logs

        except ApiException as e:
            logger.error(f"获取Pod日志失败: {e}")
            return None

    def delete_pod(self, project_id: str, pod_name: str) -> bool:
        """
        删除指定Pod

        Args:
            project_id: 项目ID
            pod_name: Pod名称

        Returns:
            是否删除成功
        """
        namespace_name = self.generate_namespace_name(project_id)

        try:
            self.core_v1.delete_namespaced_pod(name=pod_name, namespace=namespace_name)
            logger.info(f"Pod {pod_name} 删除成功")
            return True

        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Pod {pod_name} 不存在，视为已删除")
                return True
            logger.error(f"删除Pod失败: {e}")
            return False

    def is_pvc_in_use(self, namespace_name: str, pvc_name: str) -> bool:
        """
        检查PVC是否被任何Pod使用

        Args:
            namespace_name: Namespace名称
            pvc_name: PVC名称

        Returns:
            是否被使用
        """
        try:
            pods = self.core_v1.list_namespaced_pod(namespace=namespace_name)
            for pod in pods.items:
                if pod.spec.volumes:
                    for volume in pod.spec.volumes:
                        if volume.persistent_volume_claim:
                            if volume.persistent_volume_claim.claim_name == pvc_name:
                                return True
            return False

        except ApiException as e:
            logger.error(f"检查PVC使用情况失败: {e}")
            return True  # 保守策略，出错时认为正在使用

    def delete_pvc(self, project_id: str, pvc_name: str) -> tuple[bool, Optional[str]]:
        """
        删除指定PVC，删除前检查是否被使用

        Args:
            project_id: 项目ID
            pvc_name: PVC名称

        Returns:
            tuple: (是否删除成功, 错误信息)
        """
        namespace_name = self.generate_namespace_name(project_id)

        try:
            # 检查PVC是否存在
            try:
                self.core_v1.read_namespaced_persistent_volume_claim(name=pvc_name, namespace=namespace_name)
            except ApiException as e:
                if e.status == 404:
                    logger.warning(f"PVC {pvc_name} 不存在，视为已删除")
                    return True, None
                raise

            # 检查PVC是否被使用
            if self.is_pvc_in_use(namespace_name, pvc_name):
                error_msg = f"PVC {pvc_name} 正在被Pod使用，无法删除"
                logger.warning(error_msg)
                return False, error_msg

            # 删除PVC
            self.core_v1.delete_namespaced_persistent_volume_claim(name=pvc_name, namespace=namespace_name)
            logger.info(f"PVC {pvc_name} 删除成功")
            return True, None

        except ApiException as e:
            error_msg = f"删除PVC失败: {e}"
            logger.error(error_msg)
            return False, error_msg


# 单例实例
_k8s_client: Optional[K8SClient] = None


def get_k8s_client() -> K8SClient:
    """获取K8S客户端实例"""
    global _k8s_client
    if _k8s_client is None:
        _k8s_client = K8SClient()
    return _k8s_client
