"""
K8S资源管理服务模块
提供对Kubernetes资源的增删查改操作
"""

import logging
from typing import Optional, List, Dict, Any

import kubernetes
from kubernetes.client import (
    CoreV1Api,
    AppsV1Api,
    NetworkingV1Api,
    BatchV1Api,
    CustomObjectsApi,
)
from kubernetes.client.exceptions import ApiException

from app.config import get_config
from app.exception import InternalError, NotFoundError, ValidationError
from app.models.database import get_project_namespace

logger = logging.getLogger(__name__)


class KubernetesServiceError(Exception):
    """K8S服务错误"""
    pass


class KubernetesService:
    """K8S资源管理服务"""

    def __init__(self):
        self.config = get_config().kubernetes
        self._core_v1: Optional[CoreV1Api] = None
        self._apps_v1: Optional[AppsV1Api] = None
        self._networking_v1: Optional[NetworkingV1Api] = None
        self._batch_v1: Optional[BatchV1Api] = None
        self._custom_objects: Optional[CustomObjectsApi] = None

    def _init_clients(self):
        """初始化K8S客户端"""
        try:
            if self.config.in_cluster:
                kubernetes.config.load_incluster_config()
            else:
                kubernetes.config.load_kube_config(config_file=self.config.kubeconfig)

            self._core_v1 = CoreV1Api()
            self._apps_v1 = AppsV1Api()
            self._networking_v1 = NetworkingV1Api()
            self._batch_v1 = BatchV1Api()
            self._custom_object = CustomObjectsApi()
            logger.info("K8S客户端初始化成功")
        except Exception as e:
            logger.error(f"K8S客户端初始化失败: {e}")
            raise KubernetesServiceError(f"K8S客户端初始化失败: {e}")

    @property
    def core_v1(self) -> CoreV1Api:
        """获取CoreV1Api客户端"""
        if self._core_v1 is None:
            self._init_clients()
        return self._core_v1

    @property
    def apps_v1(self) -> AppsV1Api:
        """获取AppsV1Api客户端"""
        if self._apps_v1 is None:
            self._init_clients()
        return self._apps_v1

    @property
    def networking_v1(self) -> NetworkingV1Api:
        """获取NetworkingV1Api客户端"""
        if self._networking_v1 is None:
            self._init_clients()
        return self._networking_v1

    @property
    def batch_v1(self) -> BatchV1Api:
        """获取BatchV1Api客户端"""
        if self._batch_v1 is None:
            self._init_clients()
        return self._batch_v1

    @property
    def custom_object(self) -> CustomObjectsApi:
        """获取CustomObjectsApi客户端"""
        if self._custom_object is None:
            self._init_clients()
        return self._custom_object

    def _handle_api_exception(self, e: ApiException, resource: str, action: str):
        """处理K8S API异常"""
        if e.status == 404:
            raise NotFoundError(resource, f"{action}失败: 资源不存在")
        elif e.status == 409:
            raise ValidationError(f"{resource}冲突: {e.reason}")
        elif e.status == 422:
            raise ValidationError(f"{resource}参数错误: {e.reason}")
        else:
            logger.error(f"K8S API错误: {e.status} - {e.reason}")
            raise InternalError(f"{resource}{action}失败: {e.reason}")

    # ==================== Namespace 管理 ====================

    def get_namespace(self, name: str) -> Dict:
        """获取Namespace详情"""
        try:
            ns = self.core_v1.read_namespace(name=name)
            return {
                "name": ns.metadata.name,
                "status": ns.status.phase if ns.status else "Unknown",
                "labels": ns.metadata.labels or {},
                "annotations": ns.metadata.annotations or {},
                "created_at": ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else None,
            }
        except ApiException as e:
            self._handle_api_exception(e, "Namespace", "获取")

    def check_namespace_exists(self, name: str) -> bool:
        """检查Namespace是否存在"""
        try:
            self.core_v1.read_namespace(name=name)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise

    def create_namespace(self, name: str, labels: Optional[Dict[str, str]] = None,
                         annotations: Optional[Dict[str, str]] = None) -> Dict:
        """创建Namespace"""
        try:
            manifest = kubernetes.client.V1Namespace(
                metadata=kubernetes.client.V1ObjectMeta(
                    name=name,
                    labels=labels or {},
                    annotations=annotations or {}
                )
            )
            ns = self.core_v1.create_namespace(body=manifest)
            return {
                "name": ns.metadata.name,
                "status": ns.status.phase if ns.status else "Unknown",
                "labels": ns.metadata.labels or {},
                "annotations": ns.metadata.annotations or {},
                "created_at": ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else None,
            }
        except ApiException as e:
            self._handle_api_exception(e, "Namespace", "创建")

    def delete_namespace(self, name: str) -> Dict:
        """删除Namespace"""
        try:
            self.core_v1.delete_namespace(name=name, body=kubernetes.client.V1DeleteOptions())
            return {"status": "deleting", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Namespace", "删除")

    # ==================== POD 管理 ====================

    def list_pods(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出Pod"""
        try:
            result = self.core_v1.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._pod_to_dict(pod) for pod in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "列表")

    def get_pod(self, namespace: str, name: str) -> Dict:
        """获取Pod详情"""
        try:
            pod = self.core_v1.read_namespaced_pod(name=name, namespace=namespace)
            return self._pod_to_dict(pod)
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "获取")

    def create_pod(self, namespace: str, manifest: Dict) -> Dict:
        """创建Pod"""
        try:
            from kubernetes.client import V1Pod
            pod = self._dict_to_v1_pod(manifest)
            result = self.core_v1.create_namespaced_pod(namespace=namespace, body=pod)
            return self._pod_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "创建")

    def delete_pod(self, namespace: str, name: str) -> Dict:
        """删除Pod"""
        try:
            result = self.core_v1.delete_namespaced_pod(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "删除")

    def get_pod_logs(
        self,
        namespace: str,
        name: str,
        container: str = None,
        tail_lines: int = 100,
        previous: bool = False
    ) -> str:
        """获取Pod日志"""
        try:
            result = self.core_v1.read_namespaced_pod_log(
                name=name,
                namespace=namespace,
                container=container,
                tail_lines=tail_lines,
                previous=previous
            )
            return result
        except ApiException as e:
            self._handle_api_exception(e, "Pod日志", "获取")

    def _pod_to_dict(self, pod) -> Dict:
        """Pod对象转字典"""
        return {
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "labels": pod.metadata.labels or {},
            "annotations": pod.metadata.annotations or {},
            "status": pod.status.phase if pod.status else "Unknown",
            "node_name": pod.spec.node_name,
            "service_account": pod.spec.service_account_name,
            "containers": [
                {
                    "name": c.name,
                    "image": c.image,
                    "ports": [{"containerPort": p.container_port} for p in (c.ports or [])],
                    "env": [{"name": e.name, "value": e.value} for e in (c.env or [])],
                    "resources": {
                        "requests": c.resources.requests if c.resources and c.resources.requests else {},
                        "limits": c.resources.limits if c.resources and c.resources.limits else {},
                    } if c.resources else {}
                }
                for c in (pod.spec.containers or [])
            ],
            "created_at": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_pod(self, manifest: Dict):
        """字典转V1Pod对象"""
        from kubernetes.client import V1Pod, V1ObjectMeta, V1PodSpec, V1Container

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        pod_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {})
        )

        containers = []
        for c in spec.get("containers", []):
            container = V1Container(
                name=c.get("name"),
                image=c.get("image"),
                ports=[kubernetes.client.V1ContainerPort(container_port=p.get("containerPort"))
                       for p in c.get("ports", [])],
                env=[kubernetes.client.V1EnvVar(name=e.get("name"), value=e.get("value"))
                     for e in c.get("env", [])],
                command=c.get("command"),
                args=c.get("args"),
            )
            containers.append(container)

        pod_spec = V1PodSpec(
            containers=containers,
            restart_policy=spec.get("restartPolicy", "Always"),
            service_account_name=spec.get("serviceAccountName"),
            node_name=spec.get("nodeName"),
        )

        return V1Pod(metadata=pod_metadata, spec=pod_spec)

    # ==================== Service 管理 ====================

    def list_services(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出Service"""
        try:
            result = self.core_v1.list_namespaced_service(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._service_to_dict(svc) for svc in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "Service", "列表")

    def get_service(self, namespace: str, name: str) -> Dict:
        """获取Service详情"""
        try:
            svc = self.core_v1.read_namespaced_service(name=name, namespace=namespace)
            return self._service_to_dict(svc)
        except ApiException as e:
            self._handle_api_exception(e, "Service", "获取")

    def create_service(self, namespace: str, manifest: Dict) -> Dict:
        """创建Service"""
        try:
            from kubernetes.client import V1Service
            svc = self._dict_to_v1_service(manifest)
            result = self.core_v1.create_namespaced_service(namespace=namespace, body=svc)
            return self._service_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "Service", "创建")

    def delete_service(self, namespace: str, name: str) -> Dict:
        """删除Service"""
        try:
            self.core_v1.delete_namespaced_service(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Service", "删除")

    def _service_to_dict(self, svc) -> Dict:
        """Service对象转字典"""
        return {
            "name": svc.metadata.name,
            "namespace": svc.metadata.namespace,
            "label": svc.metadata.labels or {},
            "annotation": svc.metadata.annotations or {},
            "type": svc.spec.type if svc.spec else "ClusterIP",
            "cluster_ip": svc.spec.cluster_ip if svc.spec else None,
            "external_ips": svc.spec.external_i_ps if svc.spec else None,
            "ports": [
                {
                    "name": p.name,
                    "port": p.port,
                    "target_port": p.target_port,
                    "protocol": p.protocol,
                }
                for p in (svc.spec.ports or [])
            ] if svc.spec and svc.spec.ports else [],
            "selector": svc.spec.selector or {},
            "created_at": svc.metadata.creation_timestamp.isoformat() if svc.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_service(self, manifest: Dict):
        """字典转V1Service对象"""
        from kubernetes.client import V1Service, V1ObjectMeta, V1ServiceSpec, V1ServicePort

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        service_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {})
        )

        ports = []
        for p in spec.get("ports", []):
            port = V1ServicePort(
                name=p.get("name"),
                port=p.get("port"),
                target_port=p.get("target_port"),
                protocol=p.get("protocol", "TCP"),
            )
            ports.append(port)

        service_spec = V1ServiceSpec(
            type=spec.get("type", "ClusterIP"),
            selector=spec.get("selector"),
            ports=ports,
            cluster_ip=spec.get("clusterIP"),
        )

        return V1Service(metadata=service_metadata, spec=service_spec)

    # ==================== Endpoints 管理 ====================

    def create_endpoints(self, namespace: str, manifest: Dict) -> Dict:
        """创建Endpoints"""
        try:
            ep = self._dict_to_v1_endpoints(manifest)
            result = self.core_v1.create_namespaced_endpoints(namespace=namespace, body=ep)
            return self._endpoints_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "Endpoints", "创建")

    def delete_endpoints(self, namespace: str, name: str) -> Dict:
        """删除Endpoints"""
        try:
            self.core_v1.delete_namespaced_endpoints(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Endpoints", "删除")

    def _endpoints_to_dict(self, ep) -> Dict:
        """Endpoints对象转字典"""
        return {
            "name": ep.metadata.name,
            "namespace": ep.metadata.namespace,
            "subsets": [
                {
                    "addresses": [{"ip": addr.ip} for addr in (subset.addresses or [])],
                    "ports": [{"port": p.port, "protocol": p.protocol} for p in (subset.ports or [])]
                }
                for subset in (ep.subsets or [])
            ]
        }

    def _dict_to_v1_endpoints(self, manifest: Dict):
        """字典转V1Endpoints对象"""
        from kubernetes.client import (
            V1Endpoints, V1ObjectMeta, V1EndpointSubset,
            V1EndpointAddress, V1EndpointPort
        )

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        endpoints_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {})
        )

        subsets = []
        for subset in spec.get("subsets", []):
            addresses = [
                V1EndpointAddress(ip=addr.get("ip"))
                for addr in subset.get("addresses", [])
            ]
            ports = [
                V1EndpointPort(
                    port=p.get("port"),
                    protocol=p.get("protocol", "TCP")
                )
                for p in subset.get("ports", [])
            ]
            subsets.append(V1EndpointSubset(addresses=addresses, ports=ports))

        return V1Endpoints(metadata=endpoints_metadata, subsets=subsets)

    # ==================== Ingress 管理 ====================

    def list_ingresses(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出Ingress"""
        try:
            result = self.networking_v1.list_namespaced_ingress(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._ingress_to_dict(ing) for ing in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "Ingress", "列表")

    def get_ingress(self, namespace: str, name: str) -> Dict:
        """获取Ingress详情"""
        try:
            ing = self.networking_v1.read_namespaced_ingress(name=name, namespace=namespace)
            return self._ingress_to_dict(ing)
        except ApiException as e:
            self._handle_api_exception(e, "Ingress", "获取")

    def create_ingress(self, namespace: str, manifest: Dict) -> Dict:
        """创建Ingress"""
        try:
            from kubernetes.client import V1Ingress
            ing = self._dict_to_v1_ingress(manifest)
            result = self.networking_v1.create_namespaced_ingress(namespace=namespace, body=ing)
            return self._ingress_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "Ingress", "创建")

    def create_simple_ingress(
        self,
        namespace: str,
        name: str,
        service_name: str,
        service_port: int,
        host: str,
        ingress_type: str = "nginx",
        ingress_ip: str = None,
        path: str = "/",
        path_type: str = "Prefix"
    ) -> Dict:
        """
        创建简化版Ingress（供工作流服务使用）

        Args:
            namespace: 命名空间
            name: Ingress名称
            service_name: 后端Service名称
            service_port: 后端Service端口
            host: 域名
            ingress_type: Ingress类型 (nginx)
            ingress_ip: Ingress Controller的外部IP地址（用于记录，方便用户访问）
            path: 路径，默认为根路径
            path_type: 路径类型

        Returns:
            创建的Ingress信息
        """
        # 构建 manifest
        manifest = {
            "metadata": {
                "name": name,
                "namespace": namespace,
                "annotations": {},
                "labels": {
                    "app": name,
                    "managed-by": "secflow-workflow"
                }
            },
            "spec": {
                "ingressClassName": ingress_type,
                "rules": [
                    {
                        "host": host,
                        "http": {
                            "paths": [
                                {
                                    "path": path,
                                    "path_type": path_type,
                                    "backend": {
                                        "service": {
                                            "name": service_name,
                                            "port": {
                                                "number": service_port
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }

        return self.create_ingress(namespace, manifest)

    def create_external_ingress(
        self,
        namespace: str,
        name: str,
        external_ips: List[str],
        external_port: int,
        host: str,
        path: str = "/",
        path_type: str = "Prefix",
        ingress_type: str = "nginx",
        service_port: int = 80,
        tls_enabled: bool = False,
        tls_secret_name: str = None,
        websocket_enabled: bool = False,
        proxy_body_size: str = "10m",
        proxy_connect_timeout: int = 60,
        proxy_send_timeout: int = 60,
        proxy_read_timeout: int = 60,
        ssl_redirect: bool = True
    ) -> Dict:
        """
        创建外部端点Ingress（路由到外部IP:端口）

        Args:
            namespace: 命名空间
            name: Ingress名称
            external_ips: 外部IP地址列表（支持多个IP负载均衡）
            external_port: 外部端口
            host: 域名
            path: 路径，默认为根路径
            path_type: 路径类型
            ingress_type: Ingress类型 (nginx)
            service_port: Service端口（Ingress指向此端口）
            tls_enabled: 是否启用TLS
            tls_secret_name: TLS Secret名称
            websocket_enabled: 是否启用WebSocket支持
            proxy_body_size: 最大上传文件大小
            proxy_connect_timeout: 连接超时时间（秒）
            proxy_send_timeout: 发送超时时间（秒）
            proxy_read_timeout: 读取超时时间（秒）
            ssl_redirect: 是否强制HTTPS重定向

        Returns:
            创建的资源信息，包含ingress、service、endpoints和access_url
        """
        import ipaddress

        # 验证所有IP地址格式
        for ip in external_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValidationError(f"无效的IP地址格式: {ip}")

        # 生成 Service/Endpoints 名称
        service_name = f"{name}-external-svc"

        # 记录已创建的资源，用于回滚
        created_resources = []

        try:
            # 步骤1: 创建 Service (无 selector)
            service_manifest = {
                "metadata": {
                    "name": service_name,
                    "namespace": namespace,
                    "labels": {
                        "app": name,
                        "managed-by": "secflow-external-ingress"
                    }
                },
                "spec": {
                    "type": "ClusterIP",
                    "ports": [{
                        "name": "http",
                        "port": service_port,
                        "targetPort": external_port,
                        "protocol": "TCP"
                    }]
                }
            }

            service_result = self.create_service(namespace, service_manifest)
            created_resources.append(("service", service_name))
            logger.info(f"创建Service成功: {service_name}")

            # 步骤2: 创建 Endpoints
            endpoints_manifest = {
                "metadata": {
                    "name": service_name,  # 必须与 Service 名称相同
                    "namespace": namespace,
                    "labels": {
                        "app": name,
                        "managed-by": "secflow-external-ingress"
                    }
                },
                "spec": {
                    "subsets": [{
                        "addresses": [{"ip": ip} for ip in external_ips],
                        "ports": [{
                            "port": external_port,
                            "protocol": "TCP"
                        }]
                    }]
                }
            }

            endpoints_result = self.create_endpoints(namespace, endpoints_manifest)
            created_resources.append(("endpoints", service_name))
            logger.info(f"创建Endpoints成功: {service_name}")

            # 步骤3: 创建 Ingress
            # 构建 NGINX Ingress 注解
            annotations = {
                "nginx.ingress.kubernetes.io/ssl-redirect": str(ssl_redirect).lower(),
                "nginx.ingress.kubernetes.io/proxy-body-size": proxy_body_size,
                "nginx.ingress.kubernetes.io/proxy-connect-timeout": str(proxy_connect_timeout),
                "nginx.ingress.kubernetes.io/proxy-send-timeout": str(proxy_send_timeout),
                "nginx.ingress.kubernetes.io/proxy-read-timeout": str(proxy_read_timeout),
            }

            # WebSocket 支持
            if websocket_enabled:
                annotations["nginx.ingress.kubernetes.io/proxy-http-version"] = "1.1"
                annotations["nginx.ingress.kubernetes.io/proxy-buffering"] = "off"
                # 兼容默认关闭 snippet annotations 的集群策略，避免 Admission 拒绝
                annotations["nginx.ingress.kubernetes.io/enable-websocket"] = "true"

            ingress_manifest = {
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "annotations": annotations,
                    "labels": {
                        "app": name,
                        "managed-by": "secflow-external-ingress"
                    }
                },
                "spec": {
                    "ingressClassName": ingress_type,
                    "rules": [{
                        "host": host,
                        "http": {
                            "paths": [{
                                "path": path,
                                "path_type": path_type,
                                "backend": {
                                    "service": {
                                        "name": service_name,
                                        "port": {"number": service_port}
                                    }
                                }
                            }]
                        }
                    }]
                }
            }

            # 添加 TLS 配置
            if tls_enabled and tls_secret_name:
                ingress_manifest["spec"]["tls"] = [{
                    "hosts": [host],
                    "secret_name": tls_secret_name
                }]

            ingress_result = self.create_ingress(namespace, ingress_manifest)
            created_resources.append(("ingress", name))
            logger.info(f"创建Ingress成功: {name}")

            # 返回完整结果
            return {
                "ingress": ingress_result,
                "service": service_result,
                "endpoints": endpoints_result,
                "access_url": f"{'https' if tls_enabled else 'http'}://{host}{path}"
            }

        except Exception as e:
            logger.error(f"创建外部Ingress失败: {e}, 开始回滚")

            # 按逆序回滚
            for resource_type, resource_name in reversed(created_resources):
                try:
                    if resource_type == "ingress":
                        self.delete_ingress(namespace, resource_name)
                        logger.info(f"回滚删除Ingress: {resource_name}")
                    elif resource_type == "endpoints":
                        self.delete_endpoints(namespace, resource_name)
                        logger.info(f"回滚删除Endpoints: {resource_name}")
                    elif resource_type == "service":
                        self.delete_service(namespace, resource_name)
                        logger.info(f"回滚删除Service: {resource_name}")
                except Exception as rollback_error:
                    logger.error(f"回滚删除{resource_type}失败: {rollback_error}")

            # 重新抛出原始异常
            raise

    def delete_external_ingress(self, namespace: str, name: str) -> Dict:
        """
        删除外部端点Ingress（级联删除Service和Endpoints）

        Args:
            namespace: 命名空间
            name: Ingress名称

        Returns:
            删除结果
        """
        service_name = f"{name}-external-svc"

        # 按顺序删除: Ingress → Endpoints → Service
        try:
            self.delete_ingress(namespace, name)
            logger.info(f"删除Ingress成功: {name}")
        except Exception as e:
            logger.warning(f"删除Ingress失败: {e}")

        try:
            self.delete_endpoints(namespace, service_name)
            logger.info(f"删除Endpoints成功: {service_name}")
        except Exception as e:
            logger.warning(f"删除Endpoints失败: {e}")

        try:
            self.delete_service(namespace, service_name)
            logger.info(f"删除Service成功: {service_name}")
        except Exception as e:
            logger.warning(f"删除Service失败: {e}")

        return {
            "status": "deleted",
            "name": name,
            "cascade": ["ingress", "endpoints", "service"]
        }

    def get_ingress_controllers(self) -> List[Dict]:
        """
        获取集群中可用的Ingress Controller列表

        从特定namespace（如ingress-nginx）中查找Ingress Controller Service，
        返回其名称、类型、外部IP等信息，供前端选择使用。

        Returns:
            Ingress Controller列表，每个包含:
            - name: Service名称
            - namespace: 所在namespace
            - type: Service类型 (LoadBalancer, NodePort等)
            - external_ip: 外部IP地址
            - ports: 端口列表
        """
        controllers = []

        # 常见的Ingress Controller namespace列表
        ingress_namespaces = ["ingress-nginx", "nginx-ingress", "kube-system"]

        for ns in ingress_namespaces:
            try:
                services = self.core_v1.list_namespaced_service(namespace=ns)
                for svc in services.items:
                    # 查找Ingress Controller相关的Service
                    # 通常名称包含 "ingress" 或 "controller"
                    svc_name = svc.metadata.name
                    if "ingress" in svc_name.lower() or "controller" in svc_name.lower():
                        # 跳过admission webhook服务
                        if "admission" in svc_name.lower():
                            continue

                        # 获取外部IP
                        external_ip = None
                        if svc.status.load_balancer and svc.status.load_balancer.ingress:
                            # LoadBalancer类型，从status获取
                            external_ip = svc.status.load_balancer.ingress[0].ip or svc.status.load_balancer.ingress[0].hostname
                        elif svc.spec.external_ips:
                            # 有externalIPs配置
                            external_ip = svc.spec.external_ips[0]

                        # 获取端口信息
                        ports = []
                        for p in svc.spec.ports:
                            port_info = {
                                "name": p.name,
                                "port": p.port,
                                "protocol": p.protocol,
                                "node_port": p.node_port
                            }
                            ports.append(port_info)

                        controllers.append({
                            "name": svc_name,
                            "namespace": ns,
                            "type": svc.spec.type,
                            "external_ip": external_ip,
                            "cluster_ip": svc.spec.cluster_ip,
                            "ports": ports,
                            "ingress_class": "nginx" if "nginx" in svc_name.lower() else svc_name.lower()
                        })
            except ApiException as e:
                if e.status != 404:
                    logger.warning(f"Failed to list services in namespace {ns}: {e}")
                continue

        return controllers

    def delete_ingress(self, namespace: str, name: str) -> Dict:
        """删除Ingress"""
        try:
            result = self.networking_v1.delete_namespaced_ingress(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Ingress", "删除")

    def _ingress_to_dict(self, ing) -> Dict:
        """Ingress对象转字典"""
        return {
            "name": ing.metadata.name,
            "namespace": ing.metadata.namespace,
            "labels": ing.metadata.labels or {},
            "annotations": ing.metadata.annotations or {},
            "ingress_class_name": ing.spec.ingress_class_name,
            "tls": [
                {
                    "hosts": t.hosts,
                    "secret_name": t.secret_name,
                }
                for t in (ing.spec.tls or [])
            ] if ing.spec and ing.spec.tls else [],
            "rules": [
                {
                    "host": rule.host,
                    "paths": [
                        {
                            "path": p.path,
                            "path_type": p.path_type,
                            "backend": {
                                "service": {
                                    "name": p.backend.service.name,
                                    "port": {
                                        "number": p.backend.service.port.number
                                    } if p.backend.service.port and p.backend.service.port.number else None,
                                } if p.backend and p.backend.service else None,
                            },
                        }
                        for p in (rule.http.paths or [])
                    ] if rule.http and rule.http.paths else []
                }
                for rule in (ing.spec.rules or [])
            ] if ing.spec and ing.spec.rules else [],
            "created_at": ing.metadata.creation_timestamp.isoformat() if ing.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_ingress(self, manifest: Dict):
        """字典转V1Ingress对象"""
        from kubernetes.client import (
            V1Ingress, V1ObjectMeta, V1IngressSpec, V1IngressTLS,
            V1IngressRule, V1HTTPIngressRuleValue, V1HTTPIngressPath,
            V1IngressBackend, V1ServiceBackendPort
        )

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        ingress_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            labels=metadata.get("labels", metadata.get("label", {})),
            annotations=metadata.get("annotations", metadata.get("annotation", {}))
        )

        tls_list = []
        for t in spec.get("tls", []):
            tls = V1IngressTLS(
                hosts=t.get("hosts"),
                secret_name=t.get("secret_name"),
            )
            tls_list.append(tls)

        rules_list = []
        for rule in spec.get("rules", []):
            http = rule.get("http", {})
            paths = []
            for p in http.get("paths", []):
                backend = p.get("backend", {})
                service = backend.get("service", {})
                port = service.get("port", {})
                v1_port = V1ServiceBackendPort(
                    number=port.get("number"),
                    name=port.get("name"),
                )
                v1_service = kubernetes.client.V1ServiceBackend(
                    name=service.get("name"),
                    port=v1_port,
                )
                v1_backend = V1IngressBackend(service=v1_service)
                path = V1HTTPIngressPath(
                    path=p.get("path"),
                    path_type=p.get("path_type", "Prefix"),
                    backend=v1_backend,
                )
                paths.append(path)

            http_rule = V1HTTPIngressRuleValue(paths=paths) if paths else None
            v1_rule = V1IngressRule(host=rule.get("host"), http=http_rule)
            rules_list.append(v1_rule)

        ingress_spec = V1IngressSpec(
            ingress_class_name=spec.get("ingressClassName"),
            tls=tls_list,
            rules=rules_list,
        )

        return V1Ingress(metadata=ingress_metadata, spec=ingress_spec)

    # ==================== Secret 管理 ====================

    def list_secrets(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出Secret"""
        try:
            result = self.core_v1.list_namespaced_secret(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._secret_to_dict(sec) for sec in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "Secret", "列表")

    def get_secret(self, namespace: str, name: str) -> Dict:
        """获取Secret详情"""
        try:
            sec = self.core_v1.read_namespaced_secret(name=name, namespace=namespace)
            return self._secret_to_dict(sec)
        except ApiException as e:
            self._handle_api_exception(e, "Secret", "获取")

    def create_secret(self, namespace: str, manifest: Dict) -> Dict:
        """创建Secret"""
        try:
            from kubernetes.client import V1Secret
            sec = self._dict_to_v1_secret(manifest)
            result = self.core_v1.create_namespaced_secret(namespace=namespace, body=sec)
            return self._secret_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "Secret", "创建")

    def delete_secret(self, namespace: str, name: str) -> Dict:
        """删除Secret"""
        try:
            result = self.core_v1.delete_namespaced_secret(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Secret", "删除")

    def _secret_to_dict(self, sec) -> Dict:
        """Secret对象转字典"""
        return {
            "name": sec.metadata.name,
            "namespace": sec.metadata.namespace,
                "label": sec.metadata.label or {},
            "annotation": sec.metadata.annotation or {},
    "type": sec.type,
            "data": sec.data or {},
            "created_at": sec.metadata.creation_timestamp.isoformat() if sec.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_secret(self, manifest: Dict):
        """字典转V1Secret对象"""
        from kubernetes.client import V1Secret, V1ObjectMeta

        metadata = manifest.get("metadata", {})
        data = manifest.get("data", {})

        secret_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            label=metadata.get("label", {}),
            annotation=metadata.get("annotation", {})
        )

        return V1Secret(
            metadata=secret_metadata,
            data=data,
            type=manifest.get("type", "Opaque"),
        )

    # ==================== ConfigMap 管理 ====================

    def list_configmaps(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出ConfigMap"""
        try:
            result = self.core_v1.list_namespaced_config_map(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._configmap_to_dict(cm) for cm in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "ConfigMap", "列表")

    def get_configmap(self, namespace: str, name: str) -> Dict:
        """获取ConfigMap详情"""
        try:
            cm = self.core_v1.read_namespaced_config_map(name=name, namespace=namespace)
            return self._configmap_to_dict(cm)
        except ApiException as e:
            self._handle_api_exception(e, "ConfigMap", "获取")

    def create_configmap(self, namespace: str, manifest: Dict) -> Dict:
        """创建ConfigMap"""
        try:
            from kubernetes.client import V1ConfigMap
            cm = self._dict_to_v1_configmap(manifest)
            result = self.core_v1.create_namespaced_config_map(namespace=namespace, body=cm)
            return self._configmap_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "ConfigMap", "创建")

    def delete_configmap(self, namespace: str, name: str) -> Dict:
        """删除ConfigMap"""
        try:
            result = self.core_v1.delete_namespaced_config_map(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "ConfigMap", "删除")

    def _configmap_to_dict(self, cm) -> Dict:
        """ConfigMap对象转字典"""
        return {
            "name": cm.metadata.name,
            "namespace": cm.metadata.namespace,
                    "label": cm.metadata.label or {},
            "annotation": cm.metadata.annotation or {},
"data": cm.data or {},
            "binary_data": cm.binary_data or {},
            "created_at": cm.metadata.creation_timestamp.isoformat() if cm.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_configmap(self, manifest: Dict):
        """字典转V1ConfigMap对象"""
        from kubernetes.client import V1ConfigMap, V1ObjectMeta

        metadata = manifest.get("metadata", {})
        data = manifest.get("data", {})
        binary_data = manifest.get("binaryData", {})

        configmap_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            label=metadata.get("label", {}),
            annotation=metadata.get("annotation", {})
        )

        return V1ConfigMap(
            metadata=configmap_metadata,
            data=data,
            binary_data=binary_data,
        )

    # ==================== Deployment 管理 ====================

    def list_deployments(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出Deployment"""
        try:
            result = self.apps_v1.list_namespaced_deployment(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._deployment_to_dict(dep) for dep in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "Deployment", "列表")

    def get_deployment(self, namespace: str, name: str) -> Dict:
        """获取Deployment详情"""
        try:
            dep = self.apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
            return self._deployment_to_dict(dep)
        except ApiException as e:
            self._handle_api_exception(e, "Deployment", "获取")

    def create_deployment(self, namespace: str, manifest: Dict) -> Dict:
        """创建Deployment"""
        try:
            from kubernetes.client import V1Deployment
            replicas = manifest.get("spec", {}).get("replicas", 1)
            logger.info(f"创建Deployment: {manifest.get('metadata', {}).get('name')}, replicas={replicas}")
            dep = self._dict_to_v1_deployment(manifest)
            result = self.apps_v1.create_namespaced_deployment(namespace=namespace, body=dep)
            logger.info(f"Deployment创建成功: {result.metadata.name}, spec.replicas={result.spec.replicas}")
            return self._deployment_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "Deployment", "创建")

    def delete_deployment(self, namespace: str, name: str) -> Dict:
        """删除Deployment"""
        try:
            result = self.apps_v1.delete_namespaced_deployment(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Deployment", "删除")

    def scale_deployment(self, namespace: str, name: str, replicas: int) -> Dict:
        """扩缩容Deployment"""
        try:
            from kubernetes.client import V1Scale
            scale = V1Scale(replicas=replicas)
            result = self.apps_v1.replace_namespaced_deployment_scale(
                name=name,
                namespace=namespace,
                body=scale
            )
            return {"name": name, "replicas": result.spec.replicas}
        except ApiException as e:
            self._handle_api_exception(e, "Deployment", "扩缩容")

    def _deployment_to_dict(self, dep) -> Dict:
        """Deployment对象转字典"""
        # 处理conditions字段
        conditions = []
        if dep.status and dep.status.conditions:
            for cond in dep.status.conditions:
                conditions.append({
                    "type": cond.type,
                    "status": cond.status,
                    "reason": cond.reason,
                    "message": cond.message,
                })

        return {
            "name": dep.metadata.name,
            "namespace": dep.metadata.namespace,
            "labels": dep.metadata.labels or {},
            "annotations": dep.metadata.annotations or {},
            "replicas": dep.spec.replicas if dep.spec else 0,
            "ready_replicas": (dep.status.ready_replicas or 0) if dep.status else 0,  # 修改这行
            "available_replicas": (dep.status.available_replicas or 0) if dep.status else 0,  # 修改这行
            "updated_replicas": (dep.status.updated_replicas or 0) if dep.status else 0,  # 修改这行
            "conditions": conditions,
            "selector": dep.spec.selector.match_labels if dep.spec and dep.spec.selector else {},
            "containers": [
                {
                    "name": c.name,
                    "image": c.image,
                    "ports": [{"containerPort": p.container_port} for p in (c.ports or [])],
                    "env": [{"name": e.name, "value": e.value} for e in (c.env or [])],
                    "resources": {
                        "requests": c.resources.requests if c.resources and c.resources.requests else {},
                        "limits": c.resources.limits if c.resources and c.resources.limits else {},
                    } if c.resources else {},
                    "volume_mounts": [
                        {"name": vm.name, "mount_path": vm.mount_path}
                        for vm in (c.volume_mounts or [])
                    ],
                }
                for c in (dep.spec.template.spec.containers or []) if dep.spec and dep.spec.template and dep.spec.template.spec
            ],
            "created_at": dep.metadata.creation_timestamp.isoformat() if dep.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_deployment(self, manifest: Dict):
        """字典转V1Deployment对象"""
        from kubernetes.client import (
            V1Deployment, V1ObjectMeta, V1DeploymentSpec,
            V1LabelSelector, V1PodTemplateSpec, V1PodSpec, V1Container,
            V1EnvVar, V1VolumeMount, V1SecurityContext, V1Volume, V1PersistentVolumeClaimVolumeSource,
            V1ContainerPort,
        )

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})
        template_spec = spec.get("template", {}).get("spec", {})

        deployment_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {})
        )

        selector = V1LabelSelector(match_labels=spec.get("selector", {}).get("matchLabels", {}))

        containers = []
        for c in template_spec.get("containers", []):
            ports = [V1ContainerPort(container_port=p.get("containerPort")) for p in c.get("ports", [])] if c.get("ports") else None
            env = [V1EnvVar(name=e.get("name"), value=e.get("value")) for e in c.get("env", [])] if c.get("env") else None
            
            volume_mounts = None
            if c.get("volumeMounts"):
                volume_mounts = [
                    V1VolumeMount(
                        name=vm.get("name"),
                        mount_path=vm.get("mountPath"),
                        sub_path=vm.get("subPath"),
                        read_only=vm.get("readOnly", False)
                    ) for vm in c.get("volumeMounts", [])
                ]
            
            security_context = None
            if c.get("securityContext"):
                security_context = V1SecurityContext(privileged=c["securityContext"].get("privileged", False))
            
            container = V1Container(
                name=c.get("name"),
                image=c.get("image"),
                ports=ports,
                env=env,
                volume_mounts=volume_mounts,
                command=c.get("command"),
                args=c.get("args"),
                image_pull_policy=c.get("imagePullPolicy", "IfNotPresent"),
                security_context=security_context,
            )
            if c.get("resources"):
                container.resources = c["resources"]
            containers.append(container)

        volumes = None
        if template_spec.get("volumes"):
            volumes = []
            for v in template_spec.get("volumes", []):
                if v.get("persistentVolumeClaim"):
                    volumes.append(V1Volume(
                        name=v.get("name"),
                        persistent_volume_claim=V1PersistentVolumeClaimVolumeSource(
                            claim_name=v["persistentVolumeClaim"].get("claimName")
                        )
                    ))

        pod_spec = V1PodSpec(
            containers=containers,
            volumes=volumes
        )
        
        pod_metadata = V1ObjectMeta(
            labels=spec.get("template", {}).get("metadata", {}).get("labels", {})
        )
        pod_template = V1PodTemplateSpec(
            metadata=pod_metadata,
            spec=pod_spec,
        )

        deployment_spec = V1DeploymentSpec(
            replicas=spec.get("replicas", 1),
            selector=selector,
            template=pod_template,
        )

        return V1Deployment(metadata=deployment_metadata, spec=deployment_spec)

    # ==================== StatefulSet 管理 ====================

    def list_statefulsets(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出StatefulSet"""
        try:
            result = self.apps_v1.list_namespaced_stateful_set(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._statefulset_to_dict(ss) for ss in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "StatefulSet", "列表")

    def get_statefulset(self, namespace: str, name: str) -> Dict:
        """获取StatefulSet详情"""
        try:
            ss = self.apps_v1.read_namespaced_stateful_set(name=name, namespace=namespace)
            return self._statefulset_to_dict(ss)
        except ApiException as e:
            self._handle_api_exception(e, "StatefulSet", "获取")

    def create_statefulset(self, namespace: str, manifest: Dict) -> Dict:
        """创建StatefulSet"""
        try:
            from kubernetes.client import V1StatefulSet
            ss = self._dict_to_v1_statefulset(manifest)
            result = self.apps_v1.create_namespaced_stateful_set(namespace=namespace, body=ss)
            return self._statefulset_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "StatefulSet", "创建")

    def delete_statefulset(self, namespace: str, name: str) -> Dict:
        """删除StatefulSet"""
        try:
            result = self.apps_v1.delete_namespaced_stateful_set(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "StatefulSet", "删除")

    def _statefulset_to_dict(self, ss) -> Dict:
        """StatefulSet对象转字典"""
        return {
            "name": ss.metadata.name,
            "namespace": ss.metadata.namespace,
            "label": ss.metadata.label or {},
            "annotation": ss.metadata.annotation or {},
            "replica": ss.spec.replicas if ss.spec else 0,
            "ready_replicas": ss.status.ready_replicas if ss.status else 0,
            "current_replica": ss.status.current_replicas if ss.status else 0,
            "updated_replica": ss.status.updated_replica if ss.status else 0,
            "service_name": ss.spec.service_name if ss.spec else None,
            "selector": ss.spec.selector.match_label if ss.spec and ss.spec.selector else {},
            "created_at": ss.metadata.creation_timestamp.isoformat() if ss.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_statefulset(self, manifest: Dict):
        """字典转V1StatefulSet对象"""
        from kubernetes.client import (
            V1StatefulSet, V1ObjectMeta, V1StatefulSetSpec,
            V1LabelSelector, V1PodTemplateSpec, V1PodSpec, V1Container,
        )

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        sts_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            label=metadata.get("label", {}),
            annotation=metadata.get("annotation", {})
        )

        selector = V1LabelSelector(match_label=spec.get("selector", {}).get("matchLabels", {}))

        containers = []
        for c in spec.get("template", {}).get("spec", {}).get("containers", []):
            container = V1Container(
                name=c.get("name"),
                image=c.get("image"),
            )
            containers.append(container)

        pod_spec = V1PodSpec(containers=containers)
        pod_template = V1PodTemplateSpec(
            metadata=metadata,
            spec=pod_spec,
        )

        sts_spec = V1StatefulSetSpec(
            replicas=spec.get("replicas"),
            selector=selector,
            service_name=spec.get("serviceName"),
            template=pod_template,
        )

        return V1StatefulSet(metadata=sts_metadata, spec=sts_spec)

    # ==================== DaemonSet 管理 ====================

    def list_daemonsets(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出DaemonSet"""
        try:
            result = self.apps_v1.list_namespaced_daemon_set(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._daemonset_to_dict(ds) for ds in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "DaemonSet", "列表")

    def get_daemonset(self, namespace: str, name: str) -> Dict:
        """获取DaemonSet详情"""
        try:
            ds = self.apps_v1.read_namespaced_daemon_set(name=name, namespace=namespace)
            return self._daemonset_to_dict(ds)
        except ApiException as e:
            self._handle_api_exception(e, "DaemonSet", "获取")

    def create_daemonset(self, namespace: str, manifest: Dict) -> Dict:
        """创建DaemonSet"""
        try:
            from kubernetes.client import V1DaemonSet
            ds = self._dict_to_v1_daemonset(manifest)
            result = self.apps_v1.create_namespaced_daemon_set(namespace=namespace, body=ds)
            return self._daemonset_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "DaemonSet", "创建")

    def delete_daemonset(self, namespace: str, name: str) -> Dict:
        """删除DaemonSet"""
        try:
            result = self.apps_v1.delete_namespaced_daemon_set(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "DaemonSet", "删除")

    def _daemonset_to_dict(self, ds) -> Dict:
        """DaemonSet对象转字典"""
        return {
            "name": ds.metadata.name,
            "namespace": ds.metadata.namespace,
            "label": ds.metadata.label or {},
            "annotation": ds.metadata.annotation or {},
            "desired_scheduled": ds.status.desired_scheduled if ds.status else 0,
            "current_scheduled": ds.status.current_scheduled if ds.status else 0,
            "ready": ds.status.ready_replicas if ds.status else 0,
            "updated_ready": ds.status.updated_ready_replicas if ds.status else 0,
            "selector": ds.spec.selector.match_label if ds.spec and ds.spec.selector else {},
            "created_at": ds.metadata.creation_timestamp.isoformat() if ds.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_daemonset(self, manifest: Dict):
        """字典转V1DaemonSet对象"""
        from kubernetes.client import (
            V1DaemonSet, V1ObjectMeta, V1DaemonSetSpec,
            V1LabelSelector, V1PodTemplateSpec, V1PodSpec, V1Container,
        )

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        ds_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            label=metadata.get("label", {}),
            annotation=metadata.get("annotation", {})
        )

        selector = V1LabelSelector(match_label=spec.get("selector", {}).get("matchLabels", {}))

        containers = []
        for c in spec.get("template", {}).get("spec", {}).get("containers", []):
            container = V1Container(
                name=c.get("name"),
                image=c.get("image"),
            )
            containers.append(container)

        pod_spec = V1PodSpec(containers=containers)
        pod_template = V1PodTemplateSpec(
            metadata=metadata,
            spec=pod_spec,
        )

        ds_spec = V1DaemonSetSpec(
            selector=selector,
            template=pod_template,
        )

        return V1DaemonSet(metadata=ds_metadata, spec=ds_spec)

    # ==================== Job 管理 ====================

    def list_jobs(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出Job"""
        try:
            result = self.batch_v1.list_namespaced_job(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._job_to_dict(job) for job in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "Job", "列表")

    def get_job(self, namespace: str, name: str) -> Dict:
        """获取Job详情"""
        try:
            job = self.batch_v1.read_namespaced_job(name=name, namespace=namespace)
            return self._job_to_dict(job)
        except ApiException as e:
            self._handle_api_exception(e, "Job", "获取")

    def create_job(self, namespace: str, manifest: Dict) -> Dict:
        """创建Job"""
        try:
            from kubernetes.client import V1Job
            logger.info(f"创建Job manifest: {manifest}")
            job = self._dict_to_v1_job(manifest)
            logger.info(f"转换后的Job对象: metadata={job.metadata.name}, namespace={job.metadata.namespace}")
            result = self.batch_v1.create_namespaced_job(namespace=namespace, body=job)
            return self._job_to_dict(result)
        except ApiException as e:
            logger.error(f"K8S API错误: {e.status} - {e.reason} - {e.body}")
            self._handle_api_exception(e, "Job", "创建")
        except Exception as e:
            logger.error(f"创建Job异常: {type(e).__name__} - {str(e)}")
            raise

    def delete_job(self, namespace: str, name: str) -> Dict:
        """删除Job"""
        try:
            result = self.batch_v1.delete_namespaced_job(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "Job", "删除")

    def _job_to_dict(self, job) -> Dict:
        """Job对象转字典"""
        return {
            "name": job.metadata.name,
            "namespace": job.metadata.namespace,
            "labels": job.metadata.labels or {},
            "annotations": job.metadata.annotations or {},
            "parallelism": job.spec.parallelism if job.spec else None,
            "completions": job.spec.completions if job.spec else None,
            "active": job.status.active if job.status and job.status.active is not None else 0,
            "succeeded": job.status.succeeded if job.status and job.status.succeeded is not None else 0,
            "failed": job.status.failed if job.status and job.status.failed is not None else 0,
            "selector": job.spec.selector.match_labels if job.spec and job.spec.selector else {},
            "created_at": job.metadata.creation_timestamp.isoformat() if job.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_job(self, manifest: Dict):
        """字典转V1Job对象"""
        from kubernetes.client import (
            V1Job, V1ObjectMeta, V1JobSpec, V1LabelSelector,
            V1PodTemplateSpec, V1PodSpec, V1Container,
            V1EnvVar, V1VolumeMount, V1SecurityContext, V1Volume, V1PersistentVolumeClaimVolumeSource,
        )

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})
        template_spec = spec.get("template", {}).get("spec", {})
        #修改labels
        job_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {})
        )

        selector = V1LabelSelector(match_labels=spec.get("selector", {}).get("matchLabels", {}))

        containers = []
        for c in template_spec.get("containers", []):
            env = [V1EnvVar(name=e.get("name"), value=e.get("value")) for e in c.get("env", [])] if c.get("env") else None
            
            volume_mounts = None
            if c.get("volumeMounts"):
                volume_mounts = [
                    V1VolumeMount(
                        name=vm.get("name"),
                        mount_path=vm.get("mountPath"),
                        sub_path=vm.get("subPath"),
                        read_only=vm.get("readOnly", False)
                    ) for vm in c.get("volumeMounts", [])
                ]
            
            security_context = None
            if c.get("securityContext"):
                security_context = V1SecurityContext(privileged=c["securityContext"].get("privileged", False))
            
            container = V1Container(
                name=c.get("name"),
                image=c.get("image"),
                env=env,
                volume_mounts=volume_mounts,
                command=c.get("command"),
                args=c.get("args"),
                image_pull_policy=c.get("imagePullPolicy", "IfNotPresent"),
                security_context=security_context,
            )
            if c.get("resources"):
                container.resources = c["resources"]
            containers.append(container)

        volumes = None
        if template_spec.get("volumes"):
            volumes = []
            for v in template_spec.get("volumes", []):
                if v.get("persistentVolumeClaim"):
                    volumes.append(V1Volume(
                        name=v.get("name"),
                        persistent_volume_claim=V1PersistentVolumeClaimVolumeSource(
                            claim_name=v["persistentVolumeClaim"].get("claimName")
                        )
                    ))

        pod_spec = V1PodSpec(
            containers=containers,
            restart_policy=template_spec.get("restartPolicy", "Never"),
            volumes=volumes
        )
        
        pod_metadata = V1ObjectMeta(
            labels=spec.get("template", {}).get("metadata", {}).get("labels", {})
        )
        pod_template = V1PodTemplateSpec(
            metadata=pod_metadata,
            spec=pod_spec,
        )

        job_spec = V1JobSpec(
            parallelism=spec.get("parallelism"),
            completions=spec.get("completions"),
            selector=selector,
            template=pod_template,
            ttl_seconds_after_finished=spec.get("ttlSecondsAfterFinished"),
            backoff_limit=spec.get("backoffLimit"),
        )

        return V1Job(metadata=job_metadata, spec=job_spec)

    # ==================== PVC 管理 ====================

    def list_pvcs(self, namespace: str, label_selector: str = None) -> List[Dict]:
        """列出PVC"""
        try:
            result = self.core_v1.list_namespaced_persistent_volume_claim(
                namespace=namespace,
                label_selector=label_selector
            )
            return [self._pvc_to_dict(pvc) for pvc in result.items]
        except ApiException as e:
            self._handle_api_exception(e, "PVC", "列表")

    def get_pvc(self, namespace: str, name: str) -> Dict:
        """获取PVC详情"""
        try:
            pvc = self.core_v1.read_namespaced_persistent_volume_claim(name=name, namespace=namespace)
            return self._pvc_to_dict(pvc)
        except ApiException as e:
            self._handle_api_exception(e, "PVC", "获取")

    def create_pvc(self, namespace: str, manifest: Dict) -> Dict:
        """创建PVC"""
        try:
            from kubernetes.client import V1PersistentVolumeClaim
            pvc = self._dict_to_v1_pvc(manifest)
            result = self.core_v1.create_namespaced_persistent_volume_claim(namespace=namespace, body=pvc)
            return self._pvc_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "PVC", "创建")

    def delete_pvc(self, namespace: str, name: str) -> Dict:
        """删除PVC"""
        try:
            result = self.core_v1.delete_namespaced_persistent_volume_claim(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            return {"status": "deleted", "name": name}
        except ApiException as e:
            self._handle_api_exception(e, "PVC", "删除")

    def check_pvc_in_use(self, namespace: str, name: str) -> Dict:
        """检查PVC是否被Pod/Job使用"""
        try:
            # PVC存在性检查
            self.core_v1.read_namespaced_persistent_volume_claim(name=name, namespace=namespace)
        except ApiException as e:
            if e.status == 404:
                return {"in_use": False, "message": f"PVC {name} does not exist"}
            self._handle_api_exception(e, "PVC", "检查使用状态")

        # 检查Pod挂载
        try:
            pods = self.core_v1.list_namespaced_pod(namespace=namespace)
            for pod in pods.items:
                if not pod.spec or not pod.spec.volumes:
                    continue
                for volume in pod.spec.volumes:
                    pvc = getattr(volume, "persistent_volume_claim", None)
                    if pvc and pvc.claim_name == name:
                        phase = pod.status.phase if pod.status else "Unknown"
                        if phase in ["Running", "Pending", "Unknown"]:
                            return {"in_use": True, "message": f"PVC mounted by pod {pod.metadata.name} ({phase})"}
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "检查PVC使用状态")

        # 检查Job模板引用
        try:
            jobs = self.batch_v1.list_namespaced_job(namespace=namespace)
            for job in jobs.items:
                tpl = getattr(job.spec, "template", None)
                pod_spec = getattr(tpl, "spec", None) if tpl else None
                volumes = getattr(pod_spec, "volumes", None) if pod_spec else None
                if not volumes:
                    continue
                for volume in volumes:
                    pvc = getattr(volume, "persistent_volume_claim", None)
                    if pvc and pvc.claim_name == name:
                        active = job.status.active if job.status else 0
                        if active and active > 0:
                            return {"in_use": True, "message": f"PVC used by active job {job.metadata.name}"}
        except ApiException as e:
            self._handle_api_exception(e, "Job", "检查PVC使用状态")

        return {"in_use": False, "message": "PVC is not in use"}

    def _pvc_to_dict(self, pvc) -> Dict:
        """PVC对象转字典"""
        return {
            "name": pvc.metadata.name,
            "namespace": pvc.metadata.namespace,
            "label": pvc.metadata.label or {},
            "annotation": pvc.metadata.annotation or {},
            "status": pvc.status.phase if pvc.status else "Unknown",
            "access_modes": pvc.spec.access_modes if pvc.spec else [],
            "volume_mode": pvc.spec.volume_mode if pvc.spec else None,
            "storage_class": pvc.spec.storage_class_name if pvc.spec else None,
            "volume_name": pvc.spec.volume_name if pvc.spec else None,
            "capacity": {
                k: v for k, v in (pvc.status.capacity or {}).items()
            } if pvc.status and pvc.status.capacity else {},
            "created_at": pvc.metadata.creation_timestamp.isoformat() if pvc.metadata.creation_timestamp else None,
        }

    def _dict_to_v1_pvc(self, manifest: Dict):
        """字典转V1PersistentVolumeClaim对象"""
        from kubernetes.client import (
            V1PersistentVolumeClaim, V1ObjectMeta,
            V1PersistentVolumeClaimSpec, V1PersistentVolumeClaimResources,
        )

        metadata = manifest.get("metadata", {})
        spec = manifest.get("spec", {})

        pvc_metadata = V1ObjectMeta(
            name=metadata.get("name"),
            namespace=metadata.get("namespace"),
            label=metadata.get("label", {}),
            annotation=metadata.get("annotation", {})
        )

        resources = V1PersistentVolumeClaimResources(
            requests=spec.get("resources", {}).get("requests", {})
        )

        pvc_spec = V1PersistentVolumeClaimSpec(
            access_modes=spec.get("accessModes", ["ReadWriteOnce"]),
            volume_mode=spec.get("volumeMode"),
            storage_class_name=spec.get("storageClassName"),
            volume_name=spec.get("volumeName"),
            resources=resources,
        )

        return V1PersistentVolumeClaim(metadata=pvc_metadata, spec=pvc_spec)

    # ==================== WebSocket Exec (类似 kubectl exec -it) ====================

    class K8sExecStream:
        """
        Kubernetes Exec WebSocket 流包装类
        实现 Kubernetes Exec 协议的数据帧格式

        协议格式: [stream_type (1 byte)][data]
        stream_type: 0=stdin, 1=stdout, 2=stderr, 3=error, 4=resize
        """

        def __init__(self, ws):
            self._ws = ws
            self._closed = False

        def write_stdin(self, data):
            """
            发送 stdin 数据到 K8s
            添加 stream_type 前缀 (0x00)
            """
            if self._closed:
                raise RuntimeError("Stream is closed")

            # Kubernetes 协议: stdin 数据需要以 0x00 开头
            if isinstance(data, str):
                data = data.encode('utf-8')
            frame = b'\x00' + data
            self._ws.send(frame, opcode=0x02)  # 0x02 = binary frame

        def send_resize(self, rows: int, cols: int):
            """
            发送终端 resize 消息
            stream_type = 4
            """
            if self._closed:
                return
            import json
            resize_data = json.dumps({"Width": cols, "Height": rows})
            frame = b'\x04' + resize_data.encode('utf-8')
            self._ws.send(frame, opcode=0x02)

        def recv(self):
            """接收数据"""
            if self._closed:
                return None
            return self._ws.recv()

        def close(self):
            """关闭连接"""
            if not self._closed:
                self._closed = True
                try:
                    self._ws.close()
                except:
                    pass

        @property
        def closed(self):
            return self._closed

    def get_exec_websocket_url(
        self,
        namespace: str,
        pod_name: str,
        command: List[str] = None,
        container: str = None,
        stdin: bool = True,
        stdout: bool = True,
        stderr: bool = True,
        tty: bool = True
    ) -> str:
        """
        获取Pod exec的WebSocket URL

        Args:
            namespace: Namespace
            pod_name: Pod名称
            command: 执行命令列表
            container: 容器名称
            stdin: 启用stdin
            stdout: 启用stdout
            stderr: 启用stderr
            tty: 分配伪终端

        Returns:
            WebSocket URL 字符串
        """
        if command is None:
            command = ["/bin/sh"]

        logger.info(f"[EXEC] 获取 exec WebSocket URL:")
        logger.info(f"[EXEC]   name: {pod_name}, namespace: {namespace}")
        logger.info(f"[EXEC]   command: {command}, container: {container}")

        try:
            # 使用 kubernetes client 获取 api_client
            api_client = self.core_v1.api_client

            # 获取 API 服务器配置
            # 从 api_client 获取 host 和认证信息
            config = api_client.configuration
            host = config.host

            # 如果 host 是 http:// 或 https:// 开头，去掉它
            if host.startswith('http://'):
                host = host[7:]
            elif host.startswith('https://'):
                host = host[8:]

            # 构建 WebSocket URL 参数
            from urllib.parse import urlencode
            params = {}

            # 命令参数 - 需要按正确格式传递
            if command:
                if isinstance(command, list):
                    # K8s exec API 接受多个 command 参数
                    for cmd in command:
                        params['command'] = cmd
                else:
                    params['command'] = command

            if container:
                params['container'] = container
            params['stdin'] = 'true' if stdin else 'false'
            params['stdout'] = 'true' if stdout else 'false'
            params['stderr'] = 'true' if stderr else 'false'
            params['tty'] = 'true' if tty else 'false'

            # 过滤掉 None 值
            params = {k: v for k, v in params.items() if v is not None}

            # 构建 WebSocket URL
            ws_url = f"wss://{host}/api/v1/namespaces/{namespace}/pods/{pod_name}/exec?{urlencode(params)}"
            logger.info(f"[EXEC] 构建的 WebSocket URL: {ws_url[:150]}...")

            return ws_url

        except Exception as e:
            logger.error(f"[EXEC] 构建 URL 失败: {e}")
            raise

    def exec_pod_stream(
        self,
        namespace: str,
        pod_name: str,
        command: List[str] = None,
        container: str = None,
        stdin: bool = True,
        stdout: bool = True,
        stderr: bool = True,
        tty: bool = True
    ):
        """
        在Pod中执行命令并返回WebSocket流
        类似 kubectl exec -it 的能力

        使用 websocket-client 库建立真实的 WebSocket 连接
        """
        import ssl
        import websocket

        if command is None:
            command = ["/bin/sh"]

        logger.info(f"[EXEC] 开始执行 exec, 参数详情:")
        logger.info(f"[EXEC]   name: {pod_name}")
        logger.info(f"[EXEC]   namespace: {namespace}")
        logger.info(f"[EXEC]   command: {command}")
        logger.info(f"[EXEC]   container: {container}")
        logger.info(f"[EXEC]   stdin: {stdin}, stdout: {stdout}, stderr: {stderr}, tty: {tty}")

        try:
            # 第一步：获取 WebSocket URL
            ws_url = self.get_exec_websocket_url(
                namespace=namespace,
                pod_name=pod_name,
                command=command,
                container=container,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                tty=tty
            )

            # 第二步：获取认证头
            api_client = self.core_v1.api_client

            # 正确获取认证信息
            auth_header = ''
            try:
                # 优先从配置文件获取 token
                config = api_client.configuration
                if hasattr(config, 'api_key'):
                    # 获取 Authorization header
                    api_key = config.get_api_key_with_prefix('Authorization')
                    if api_key:
                        auth_header = f"Bearer {api_key}"
                        logger.info(f"[EXEC] 从 api_key 获取认证头成功")
                    else:
                        logger.info(f"[EXEC] api_key 存在但为空")

                # 如果没有获取到，尝试从 token 文件读取
                if not auth_header:
                    token_file = '/var/run/secrets/kubernetes.io/serviceaccount/token'
                    try:
                        with open(token_file, 'r') as f:
                            token = f.read().strip()
                            if token:
                                auth_header = f"Bearer {token}"
                                logger.info(f"[EXEC] 从 ServiceAccount token 文件获取认证头成功")
                    except FileNotFoundError:
                        logger.info(f"[EXEC] ServiceAccount token 文件不存在，跳过")

            except Exception as e:
                logger.warning(f"[EXEC] 获取认证头失败: {e}")

            logger.info(f"[EXEC] 认证头: {auth_header[:60] if auth_header else '无'}...")

            # 第三步：建立 WebSocket 连接
            logger.info(f"[EXEC] 正在建立 WebSocket 连接...")

            # 创建 WebSocket 应用
            ws = websocket.WebSocket(
                sslopt={"cert_reqs": ssl.CERT_NONE} if hasattr(ssl, 'CERT_NONE') else {}
            )

            # 添加认证头
            headers = []
            if auth_header:
                headers.append(f'Authorization: {auth_header}')

            # 连接 WebSocket
            ws.connect(ws_url, header={'Authorization': auth_header})
            logger.info(f"[EXEC] WebSocket 连接成功!")

            # 返回包装后的流对象，实现 Kubernetes Exec 协议
            return self.K8sExecStream(ws)

        except Exception as e:
            logger.error(f"[EXEC] 执行失败: {type(e).__name__}: {e}")
            raise

    def resize_pod_exec(
        self,
        namespace: str,
        pod_name: str,
        rows: int = 24,
        cols: int = 80,
        container: str = None
    ):
        """
        调整Pod终端大小
        类似 kubectl exec 中的终端resize能力

        Args:
            namespace: Namespace
            pod_name: Pod名称
            rows: 终端行数
            cols: 终端列数
            container: 容器名称

        Returns:
            bool: 是否成功
        """
        try:
            # 使用Kubernetes API resize终端
            from kubernetes.client import V1TerminalSize

            terminal_size = V1TerminalSize(
                rows=rows,
                cols=cols
            )

            self.core_v1.connect_get_namespaced_pod_exec(
                name=pod_name,
                namespace=namespace,
                container=container,
                command=["/bin/sh", "-c", "stty rows {} cols {}".format(rows, cols)],
                stdin=False,
                stdout=False,
                stderr=False,
                tty=False,
                _preload_content=True
            )
            logger.debug(f"终端大小已调整: {rows}x{cols}")
            return True
        except ApiException as e:
            # resize失败不抛出异常，只记录日志
            logger.debug(f"调整终端大小失败: {e}")
            return False
        except Exception as e:
            logger.debug(f"调整终端大小异常: {e}")
            return False

    # ==================== WebSocket Attach (类似 kubectl attach) ====================

    def attach_pod_stream(
        self,
        namespace: str,
        pod_name: str,
        container: str = None,
        stdin: bool = True,
        stdout: bool = True,
        stderr: bool = False,
        tty: bool = True
    ):
        """
        附加到运行中的容器并返回WebSocket流
        类似 kubectl attach 的能力

        Args:
            namespace: Namespace
            pod_name: Pod名称
            container: 容器名称
            stdin: 启用stdin
            stdout: 启用stdout
            stderr: 启用stderr
            tty: 分配伪终端

        Returns:
            WebSocket流对象
        """
        try:
            resp = self.core_v1.connect_get_namespaced_pod_attach(
                name=pod_name,
                namespace=namespace,
                container=container,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                tty=tty,
                _preload_content=False  # 关键：不预加载内容保持流打开
            )
            return resp
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "附加")

    # ==================== 获取Pod容器列表 ====================

    def get_pod_containers(self, namespace: str, pod_name: str) -> List[Dict]:
        """
        获取Pod的容器列表

        Args:
            namespace: Namespace
            pod_name: Pod名称

        Returns:
            容器信息列表
        """
        try:
            pod = self.core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            return [
                {
                    "name": c.name,
                    "image": c.image,
                    "image_pull_policy": c.image_pull_policy,
                    "ports": [{"containerPort": p.container_port, "protocol": p.protocol}
                              for p in (c.ports or [])],
                    "command": c.command,
                    "args": c.args,
                }
                for c in (pod.spec.containers or [])
            ]
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "获取容器列表")

    # ==================== 节点交互操作扩展 ====================

    def get_pod_events(self, namespace: str, pod_name: str) -> List[Dict]:
        """
        获取Pod相关事件
        
        Args:
            namespace: Namespace
            pod_name: Pod名称
            
        Returns:
            事件列表
        """
        try:
            events = self.core_v1.list_namespaced_event(
                namespace=namespace,
                field_selector=f"involvedObject.name={pod_name}"
            )
            return [
                {
                    "type": event.type,
                    "reason": event.reason,
                    "message": event.message,
                    "count": event.count,
                    "first_timestamp": event.first_timestamp.isoformat() if event.first_timestamp else None,
                    "last_timestamp": event.last_timestamp.isoformat() if event.last_timestamp else None,
                    "source": event.source.component if event.source else None,
                }
                for event in (events.items or [])
            ]
        except ApiException as e:
            self._handle_api_exception(e, "Pod事件", "获取")

    def get_pod_status_detail(self, namespace: str, pod_name: str) -> Dict:
        """
        获取Pod详细状态
        
        Args:
            namespace: Namespace
            pod_name: Pod名称
            
        Returns:
            Pod详细状态信息
        """
        try:
            pod = self.core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            return {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "phase": pod.status.phase,
                "message": pod.status.message,
                "reason": pod.status.reason,
                "start_time": pod.status.start_time.isoformat() if pod.status.start_time else None,
                "pod_ip": pod.status.pod_ip,
                "host_ip": pod.status.host_ip,
                "node_name": pod.spec.node_name,
                "conditions": [
                    {
                        "type": c.type,
                        "status": c.status,
                        "reason": c.reason,
                        "message": c.message,
                        "last_transition_time": c.last_transition_time.isoformat() if c.last_transition_time else None,
                    }
                    for c in (pod.status.conditions or [])
                ],
                "container_statuses": [
                    {
                        "name": cs.name,
                        "state": self._get_container_state(cs.state),
                        "ready": cs.ready,
                        "restart_count": cs.restart_count,
                        "image": cs.image,
                        "container_id": cs.container_id,
                    }
                    for cs in (pod.status.container_statuses or [])
                ],
                "labels": pod.metadata.labels or {},
            }
        except ApiException as e:
            self._handle_api_exception(e, "Pod状态", "获取")

    def _get_container_state(self, state) -> str:
        """获取容器状态字符串"""
        if state is None:
            return "unknown"
        if state.running:
            return f"running (since {state.running.started_at.isoformat() if state.running.started_at else 'unknown'})"
        if state.waiting:
            return f"waiting ({state.waiting.reason}: {state.waiting.message})"
        if state.terminated:
            return f"terminated ({state.terminated.reason}, exit_code={state.terminated.exit_code})"
        return "unknown"

    def get_pod_metrics(self, namespace: str, pod_name: str) -> Dict:
        """
        获取Pod资源指标（需要Metrics Server）
        
        Args:
            namespace: Namespace
            pod_name: Pod名称
            
        Returns:
            Pod资源指标
        """
        try:
            metrics = self.custom_object.get_namespaced_custom_object(
                group="metrics.k8s.io",
                version="v1beta1",
                namespace=namespace,
                plural="pods",
                name=pod_name
            )
            return {
                "name": metrics["metadata"]["name"],
                "namespace": metrics["metadata"]["namespace"],
                "containers": [
                    {
                        "name": c["name"],
                        "cpu": c["usage"]["cpu"],
                        "memory": c["usage"]["memory"],
                    }
                    for c in metrics.get("containers", [])
                ],
                "timestamp": metrics.get("timestamp"),
            }
        except ApiException as e:
            if e.status == 404:
                raise NotFoundError("Pod指标", "Metrics Server未安装或Pod不存在")
            self._handle_api_exception(e, "Pod指标", "获取")

    def restart_deployment(self, namespace: str, name: str) -> Dict:
        """
        重启Deployment（通过更新annotation触发滚动更新）
        
        Args:
            namespace: Namespace
            name: Deployment名称
            
        Returns:
            重启结果
        """
        try:
            import datetime
            
            deployment = self.apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
            
            if not deployment.spec.template.metadata:
                from kubernetes.client import V1ObjectMeta
                deployment.spec.template.metadata = V1ObjectMeta()
            if not deployment.spec.template.metadata.annotations:
                deployment.spec.template.metadata.annotations = {}
            
            deployment.spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"] = datetime.datetime.now().isoformat()
            
            result = self.apps_v1.patch_namespaced_deployment(
                name=name,
                namespace=namespace,
                body=deployment
            )
            return {
                "name": name,
                "message": "Deployment重启已触发",
                "restarted_at": deployment.spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"]
            }
        except ApiException as e:
            self._handle_api_exception(e, "Deployment", "重启")

    def recreate_job(self, namespace: str, name: str) -> Dict:
        """
        删除并重建Job
        
        Args:
            namespace: Namespace
            name: Job名称
            
        Returns:
            新Job信息
        """
        try:
            import time
            
            job = self.batch_v1.read_namespaced_job(name=name, namespace=namespace)
            
            job_manifest = {
                "metadata": {
                    "name": job.metadata.name,
                    "namespace": job.metadata.namespace,
                    "labels": dict(job.metadata.labels) if job.metadata.labels else {},
                    "annotations": dict(job.metadata.annotations) if job.metadata.annotations else {},
                },
                "spec": {
                    "parallelism": job.spec.parallelism,
                    "completions": job.spec.completions,
                    "backoffLimit": job.spec.backoff_limit,
                    "ttlSecondsAfterFinished": job.spec.ttl_seconds_after_finished,
                    "template": {
                        "metadata": {
                            "labels": dict(job.spec.template.metadata.labels) if job.spec.template.metadata and job.spec.template.metadata.labels else {},
                        },
                        "spec": {
                            "containers": [
                                {
                                    "name": c.name,
                                    "image": c.image,
                                    "command": list(c.command) if c.command else None,
                                    "args": list(c.args) if c.args else None,
                                    "env": [{"name": e.name, "value": e.value} for e in (c.env or [])],
                                    "resources": {
                                        "requests": dict(c.resources.requests) if c.resources and c.resources.requests else {},
                                        "limits": dict(c.resources.limits) if c.resources and c.resources.limits else {},
                                    } if c.resources else {},
                                    "volumeMounts": [
                                        {"name": vm.name, "mountPath": vm.mount_path, "subPath": vm.sub_path, "readOnly": vm.read_only}
                                        for vm in (c.volume_mounts or [])
                                    ],
                                }
                                for c in (job.spec.template.spec.containers or [])
                            ],
                            "volumes": [
                                {
                                    "name": v.name,
                                    "persistentVolumeClaim": {"claimName": v.persistent_volume_claim.claim_name}
                                }
                                for v in (job.spec.template.spec.volumes or [])
                                if v.persistent_volume_claim
                            ],
                            "restartPolicy": job.spec.template.spec.restart_policy,
                        }
                    }
                }
            }
            
            self.batch_v1.delete_namespaced_job(
                name=name,
                namespace=namespace,
                body=kubernetes.client.V1DeleteOptions()
            )
            
            for _ in range(30):
                try:
                    self.batch_v1.read_namespaced_job(name=name, namespace=namespace)
                    time.sleep(1)
                except ApiException as e:
                    if e.status == 404:
                        break
            
            new_job = self._dict_to_v1_job(job_manifest)
            result = self.batch_v1.create_namespaced_job(namespace=namespace, body=new_job)
            return self._job_to_dict(result)
        except ApiException as e:
            self._handle_api_exception(e, "Job", "重建")

    def _get_node_ips(self) -> List[str]:
        """
        获取集群节点IP地址列表

        优先返回ExternalIP，如果没有则返回InternalIP

        Returns:
            节点IP地址列表
        """
        try:
            nodes = self.core_v1.list_node()
            ips = []
            for node in nodes.items:
                if not node.status or not node.status.addresses:
                    continue
                # 优先使用 ExternalIP，其次使用 InternalIP
                external_ip = None
                internal_ip = None
                for addr in node.status.addresses:
                    if addr.type == "ExternalIP":
                        external_ip = addr.address
                    elif addr.type == "InternalIP":
                        internal_ip = addr.address
                # 优先添加 ExternalIP
                if external_ip:
                    ips.append(external_ip)
                elif internal_ip:
                    ips.append(internal_ip)
            return ips
        except Exception as e:
            logger.warning(f"获取节点IP失败: {e}")
            return []

    def get_service_access_info(self, namespace: str, service_name: str) -> Dict:
        """
        获取Service访问信息
        
        Args:
            namespace: Namespace
            service_name: Service名称
            
        Returns:
            Service访问信息
        """
        try:
            service = self.core_v1.read_namespaced_service(name=service_name, namespace=namespace)
            
            access_info = {
                "name": service.metadata.name,
                "namespace": service.metadata.namespace,
                "type": service.spec.type,
                "cluster_ip": service.spec.cluster_ip,
                "ports": [],
                "access_urls": []
            }
            
            # 解析端口信息
            for port in (service.spec.ports or []):
                port_info = {
                    "name": port.name,
                    "port": port.port,
                    "target_port": port.target_port,
                    "protocol": port.protocol,
                    "node_port": port.node_port
                }
                access_info["ports"].append(port_info)
                
                # 生成访问URL
                if service.spec.type == "NodePort" and port.node_port:
                    # NodePort类型 - 通过节点IP:NodePort访问
                    # 获取集群节点IP地址
                    node_ips = self._get_node_ips()
                    if node_ips:
                        # 为每个节点IP生成访问URL
                        for node_ip in node_ips[:3]:  # 最多返回3个节点
                            access_info["access_urls"].append({
                                "type": "NodePort",
                                "port_name": port.name,
                                "url": f"http://{node_ip}:{port.node_port}",
                                "node_ip": node_ip,
                                "node_port": port.node_port
                            })
                    else:
                        # 没有获取到节点IP时，返回提示信息
                        access_info["access_urls"].append({
                            "type": "NodePort",
                            "port_name": port.name,
                            "url": f"http://<node-ip>:{port.node_port}",
                            "node_port": port.node_port,
                            "message": "无法获取节点IP，请手动查询"
                        })
                elif service.spec.type == "LoadBalancer" and service.status.load_balancer and service.status.load_balancer.ingress:
                    # LoadBalancer类型 - 通过外部IP访问
                    for ingress in service.status.load_balancer.ingress:
                        if ingress.ip:
                            access_info["access_urls"].append({
                                "type": "LoadBalancer",
                                "port_name": port.name,
                                "url": f"http://{ingress.ip}:{port.port}"
                            })
                        if ingress.hostname:
                            access_info["access_urls"].append({
                                "type": "LoadBalancer",
                                "port_name": port.name,
                                "url": f"http://{ingress.hostname}:{port.port}"
                            })
                elif service.spec.cluster_ip and service.spec.cluster_ip != "None":
                    # ClusterIP类型 - 集群内部访问
                    access_info["access_urls"].append({
                        "type": "ClusterIP",
                        "port_name": port.name,
                        "url": f"http://{service.spec.cluster_ip}:{port.port}",
                        "cluster_ip": service.spec.cluster_ip,
                        "port": port.port
                    })
            
            return access_info
        except ApiException as e:
            self._handle_api_exception(e, "Service访问信息", "获取")

    def proxy_service_request(self, namespace: str, service_name: str, port: int, path: str = "/", method: str = "GET", body: str = None, headers: dict = None) -> Dict:
        """
        代理请求到Service
        
        Args:
            namespace: Namespace
            service_name: Service名称
            port: Service端口
            path: 请求路径
            method: HTTP方法
            body: 请求体
            headers: 请求头
            
        Returns:
            代理响应
        """
        try:
            # 使用K8S API代理
            # 构建代理URL
            proxy_path = f"/api/v1/namespaces/{namespace}/services/{service_name}:{port}/proxy{path}"
            
            # 发送请求
            response = self.core_v1.api_client.call_api(
                proxy_path,
                method,
                header_params=headers or {},
                body=body,
                response_type="str",
                _preload_content=False
            )
            
            return {
                "status": response.status,
                "data": response.data.decode('utf-8') if response.data else ""
            }
        except ApiException as e:
            return {
                "status": e.status,
                "error": str(e)
            }


# 单例实例
_k8s_service: Optional[KubernetesService] = None


def get_k8s_service() -> KubernetesService:
    """获取K8S服务实例"""
    global _k8s_service
    if _k8s_service is None:
        _k8s_service = KubernetesService()
    return _k8s_service
