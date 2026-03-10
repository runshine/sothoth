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
            "label": ing.metadata.label or {},
            "annotation": ing.metadata.annotation or {},
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
            label=metadata.get("label", {}),
            annotation=metadata.get("annotation", {})
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
            dep = self._dict_to_v1_deployment(manifest)
            result = self.apps_v1.create_namespaced_deployment(namespace=namespace, body=dep)
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
        return {
            "name": dep.metadata.name,
            "namespace": dep.metadata.namespace,
            "labels": dep.metadata.labels or {},
            "annotations": dep.metadata.annotations or {},
            "replicas": dep.spec.replicas if dep.spec else 0,
            "ready_replicas": dep.status.ready_replicas if dep.status else 0,
            "available_replicas": dep.status.available_replicas if dep.status else 0,
            "updated_replicas": dep.status.updated_replicas if dep.status else 0,
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
            replicas=spec.get("replicas"),
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
            "active": job.status.active if job.status else 0,
            "succeeded": job.status.succeeded if job.status else 0,
            "failed": job.status.failed if job.status else 0,
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

        Args:
            namespace: Namespace
            pod_name: Pod名称
            command: 执行命令列表，默认 ["/bin/sh"]
            container: 容器名称
            stdin: 启用stdin
            stdout: 启用stdout
            stderr: 启用stderr
            tty: 分配伪终端

        Returns:
            WebSocket流对象
        """
        if command is None:
            command = ["/bin/sh"]

        try:
            resp = self.core_v1.connect_get_namespaced_pod_exec(
                name=pod_name,
                namespace=namespace,
                command=command,
                container=container,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                tty=tty,
                _preload_content=False  # 关键：不预加载内容保持流打开
            )
            return resp
        except ApiException as e:
            self._handle_api_exception(e, "Pod", "执行命令")

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


# 单例实例
_k8s_service: Optional[KubernetesService] = None


def get_k8s_service() -> KubernetesService:
    """获取K8S服务实例"""
    global _k8s_service
    if _k8s_service is None:
        _k8s_service = KubernetesService()
    return _k8s_service