"""
Pydantic模式定义模块
定义API请求和响应模型
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# ==================== 通用模型 ====================


class TokenUser(BaseModel):
    """Token用户信息"""
    user_id: str
    username: str
    nickname: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = Field(default_factory=list)


class TokenPayload(BaseModel):
    """Token载荷"""
    sub: str  # user_id
    username: str
    exp: int


class ErrorResponse(BaseModel):
    """错误响应"""
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class SuccessResponse(BaseModel):
    """成功响应"""
    message: str
    data: Optional[Dict[str, Any]] = None


class K8SResourceMetadata(BaseModel):
    """K8S资源元数据"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)


class K8SResourceListResponse(BaseModel):
    """K8S资源列表响应"""
    total: int
    items: List[Dict[str, Any]]


# ==================== POD 模型 ====================


class PodInfo(BaseModel):
    """Pod信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    status: str
    node_name: Optional[str] = None
    service_account: Optional[str] = None
    container: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: Optional[str] = None


class PodListResponse(BaseModel):
    """Pod列表响应"""
    total: int
    items: List[PodInfo]


class PodLogRequest(BaseModel):
    """Pod日志请求"""
    container: Optional[str] = None
    tail_lines: int = 100
    previous: bool = False


class PodLogResponse(BaseModel):
    """Pod日志响应"""
    logs: str


class PodExecRequest(BaseModel):
    """Pod执行请求"""
    container: Optional[str] = None
    command: str
    timeout: int = 30


class PodCreateRequest(BaseModel):
    """Pod创建请求"""
    manifest: Dict[str, Any]


class PodUpdateRequest(BaseModel):
    """Pod更新请求"""
    manifest: Dict[str, Any]


# ==================== Service 模型 ====================


class ServicePort(BaseModel):
    """Service端口"""
    name: str
    port: int
    target_port: Optional[Any] = None
    protocol: str = "TCP"


class ServiceInfo(BaseModel):
    """Service信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    type: str = "ClusterIP"
    cluster_ip: Optional[str] = None
    external_ips: Optional[List[str]] = None
    ports: List[Dict[str, Any]] = Field(default_factory=list)
    selector: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[str] = None


class ServiceListResponse(BaseModel):
    """Service列表响应"""
    total: int
    items: List[ServiceInfo]


class ServiceCreateRequest(BaseModel):
    """Service创建请求"""
    name: str
    type: str = "ClusterIP"
    selector: Dict[str, str] = Field(default_factory=dict)
    ports: List[Dict[str, Any]]


class ServiceUpdateRequest(BaseModel):
    """Service更新请求"""
    selector: Optional[Dict[str, str]] = None
    ports: Optional[List[Dict[str, Any]]] = None


# ==================== Ingress 模型 ====================


class IngressPath(BaseModel):
    """Ingress路径"""
    path: str
    path_type: str = "Prefix"
    backend: Dict[str, Any]


class IngressRule(BaseModel):
    """Ingress规则"""
    host: Optional[str] = None
    paths: List[IngressPath] = Field(default_factory=list)


class IngressTLS(BaseModel):
    """Ingress TLS配置"""
    hosts: List[str] = Field(default_factory=list)
    secret_name: str


class IngressInfo(BaseModel):
    """Ingress信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    ingress_class_name: Optional[str] = None
    tls: List[Dict[str, Any]] = Field(default_factory=list)
    rule: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: Optional[str] = None


class IngressListResponse(BaseModel):
    """Ingress列表响应"""
    total: int
    items: List[IngressInfo]


class IngressCreateRequest(BaseModel):
    """Ingress创建请求"""
    name: str
    ingress_class_name: Optional[str] = None
    annotation: Dict[str, str] = Field(default_factory=dict)
    tls: List[Dict[str, Any]] = Field(default_factory=list)
    rule: Dict[str, Any]


class IngressUpdateRequest(BaseModel):
    """Ingress更新请求"""
    annotation: Optional[Dict[str, str]] = None
    tls: Optional[List[Dict[str, Any]]] = None
    rule: Optional[Dict[str, Any]] = None


# ==================== Secret 模型 ====================


class SecretInfo(BaseModel):
    """Secret信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    type: str
    data: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[str] = None


class SecretListResponse(BaseModel):
    """Secret列表响应"""
    total: int
    items: List[SecretInfo]


class SecretCreateRequest(BaseModel):
    """Secret创建请求"""
    name: str
    type: str = "Opaque"
    data: Dict[str, str]
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)


class SecretUpdateRequest(BaseModel):
    """Secret更新请求"""
    data: Optional[Dict[str, str]] = None
    type: Optional[str] = None


# ==================== ConfigMap 模型 ====================


class ConfigMapInfo(BaseModel):
    """ConfigMap信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    data: Dict[str, str] = Field(default_factory=dict)
    binary_data: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[str] = None


class ConfigMapListResponse(BaseModel):
    """ConfigMap列表响应"""
    total: int
    items: List[ConfigMapInfo]


class ConfigMapCreateRequest(BaseModel):
    """ConfigMap创建请求"""
    name: str
    data: Dict[str, str] = Field(default_factory=dict)
    binary_data: Dict[str, str] = Field(default_factory=dict)
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)


class ConfigMapUpdateRequest(BaseModel):
    """ConfigMap更新请求"""
    data: Optional[Dict[str, str]] = None
    binary_data: Optional[Dict[str, str]] = None


# ==================== Deployment 模型 ====================


class ContainerSpec(BaseModel):
    """容器规格"""
    name: str
    image: str
    ports: List[Dict[str, Any]] = Field(default_factory=list)
    env: List[Dict[str, Any]] = Field(default_factory=list)
    resources: Dict[str, Any] = Field(default_factory=dict)
    volume_mounts: List[Dict[str, Any]] = Field(default_factory=list)


class DeploymentInfo(BaseModel):
    """Deployment信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    replicas: int = 0
    ready_replicas: int = 0
    available_replicas: int = 0
    updated_replicas: int = 0
    conditions: List[Dict[str, Any]] = Field(default_factory=list)
    selector: Dict[str, str] = Field(default_factory=dict)
    container: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: Optional[str] = None


class DeploymentListResponse(BaseModel):
    """Deployment列表响应"""
    total: int
    items: List[DeploymentInfo]


class DeploymentCreateRequest(BaseModel):
    """Deployment创建请求"""
    manifest: Dict[str, Any]


class DeploymentUpdateRequest(BaseModel):
    """Deployment更新请求"""
    manifest: Dict[str, Any]


class DeploymentScaleRequest(BaseModel):
    """Deployment扩缩容请求"""
    replica: int


# ==================== StatefulSet 模型 ====================


class StatefulSetInfo(BaseModel):
    """StatefulSet信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    replica: int = 0
    ready_replica: int = 0
    current_replica: int = 0
    updated_replica: int = 0
    service_name: Optional[str] = None
    selector: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[str] = None


class StatefulSetListResponse(BaseModel):
    """StatefulSet列表响应"""
    total: int
    items: List[StatefulSetInfo]


# ==================== DaemonSet 模型 ====================


class DaemonSetInfo(BaseModel):
    """DaemonSet信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    desired_scheduled: int = 0
    current_scheduled: int = 0
    ready: int = 0
    updated_ready: int = 0
    selector: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[str] = None


class DaemonSetListResponse(BaseModel):
    """DaemonSet列表响应"""
    total: int
    items: List[DaemonSetInfo]


# ==================== Job 模型 ====================


class JobInfo(BaseModel):
    """Job信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    parallelism: Optional[int] = None
    completions: Optional[int] = None
    active: int = 0
    succeeded: int = 0
    failed: int = 0
    selector: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[str] = None


class JobListResponse(BaseModel):
    """Job列表响应"""
    total: int
    items: List[JobInfo]


# ==================== CronJob 模型 ====================


class CronJobInfo(BaseModel):
    """CronJob信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    schedule: Optional[str] = None
    suspend: bool = False
    active: int = 0
    last_successful_time: Optional[str] = None
    created_at: Optional[str] = None


class CronJobListResponse(BaseModel):
    """CronJob列表响应"""
    total: int
    items: List[CronJobInfo]


# ==================== PVC 模型 ====================


class PVCInfo(BaseModel):
    """PVC信息"""
    name: str
    namespace: str
    label: Dict[str, str] = Field(default_factory=dict)
    annotation: Dict[str, str] = Field(default_factory=dict)
    status: str
    access_modes: List[str] = Field(default_factory=list)
    volume_mode: Optional[str] = None
    storage_class: Optional[str] = None
    volume_name: Optional[str] = None
    capacity: Dict[str, str] = Field(default_factory=dict)
    created_at: Optional[str] = None


class PVCListResponse(BaseModel):
    """PVC列表响应"""
    total: int
    items: List[PVCInfo]


# ==================== 项目资源 ====================


class ProjectResourcesResponse(BaseModel):
    """项目资源响应"""
    project_id: str
    namespace: str
    pods: int = 0
    services: int = 0
    deployments: int = 0
    statefulsets: int = 0
    daemonsets: int = 0
    jobs: int = 0
    configmaps: int = 0
    secrets: int = 0
    ingresses: int = 0
    pvcs: int = 0


# ==================== Pod容器信息 ====================


class ContainerInfo(BaseModel):
    """Pod容器信息"""
    name: str
    image: str
    image_pull_policy: Optional[str] = None
    ports: List[Dict[str, Any]] = Field(default_factory=list)
    command: Optional[List[str]] = None
    args: Optional[List[str]] = None


class PodContainersResponse(BaseModel):
    """Pod容器列表响应"""
    pod_name: str
    containers: List[ContainerInfo]
