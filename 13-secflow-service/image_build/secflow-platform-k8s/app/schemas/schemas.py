"""
Pydantic模式定义模块
"""

from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


# ============ 认证模式 ============

class TokenUser(BaseModel):
    """Token验证返回的用户信息"""
    id: str
    username: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    role: List[str]


class TokenPayload(BaseModel):
    """Token载荷"""
    user: TokenUser


# ============ 通用模式 ============

class ErrorResponse(BaseModel):
    """错误响应"""
    code: str
    message: str
    details: Optional[dict] = None


class SuccessResponse(BaseModel):
    """成功响应"""
    message: str
    data: Optional[dict] = None


# ============ K8S资源通用模式 ============

class K8SResourceMetadata(BaseModel):
    """K8S资源元数据"""
    name: str
    namespace: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    annotations: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class K8SResourceListResponse(BaseModel):
    """K8S资源列表响应"""
    total: int
    items: List[dict]


# ============ Pod相关模式 ============

class PodInfo(BaseModel):
    """Pod信息"""
    name: str
    namespace: str
    status: str
    pod_ip: Optional[str] = None
    node_name: Optional[str] = None
    containers: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class PodListResponse(BaseModel):
    """Pod列表响应"""
    total: int
    pods: List[PodInfo]


class PodLogRequest(BaseModel):
    """Pod日志请求"""
    tail_lines: int = Field(100, ge=1, le=10000, description="返回日志行数")
    container: Optional[str] = Field(None, description="容器名称")
    since_time: Optional[datetime] = Field(None, description="起始时间")


class PodLogResponse(BaseModel):
    """Pod日志响应"""
    pod_name: str
    namespace: str
    logs: str
    container: Optional[str] = None


class PodExecRequest(BaseModel):
    """Pod执行命令请求"""
    command: List[str] = Field(..., description="执行的命令")
    container: Optional[str] = Field(None, description="容器名称")


# ============ Service相关模式 ============

class ServicePort(BaseModel):
    """Service端口"""
    name: Optional[str] = None
    port: int
    target_port: Optional[int] = None
    protocol: str = "TCP"


class ServiceInfo(BaseModel):
    """Service信息"""
    name: str
    namespace: str
    type: str
    cluster_ip: Optional[str] = None
    external_ips: List[str] = []
    ports: List[ServicePort] = []
    selector: Optional[Dict[str, str]] = None
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class ServiceListResponse(BaseModel):
    """Service列表响应"""
    total: int
    services: List[ServiceInfo]


class ServiceCreateRequest(BaseModel):
    """创建Service请求"""
    name: str = Field(..., min_length=1, max_length=63, description="Service名称")
    type: str = Field("ClusterIP", description="Service类型: ClusterIP, NodePort, LoadBalancer")
    ports: List[ServicePort] = Field(..., min_length=1, description="端口配置")
    selector: Dict[str, str] = Field(..., description="Pod选择器")
    labels: Optional[Dict[str, str]] = Field(None, description="标签")


class ServiceUpdateRequest(BaseModel):
    """更新Service请求"""
    ports: Optional[List[ServicePort]] = None
    selector: Optional[Dict[str, str]] = None
    labels: Optional[Dict[str, str]] = None


# ============ Ingress相关模式 ============

class IngressPath(BaseModel):
    """Ingress路径规则"""
    path: str
    path_type: str = "Prefix"
    service_name: str
    service_port: int


class IngressRule(BaseModel):
    """Ingress规则"""
    host: Optional[str] = None
    paths: List[IngressPath]


class IngressTLS(BaseModel):
    """Ingress TLS配置"""
    hosts: List[str]
    secret_name: str


class IngressInfo(BaseModel):
    """Ingress信息"""
    name: str
    namespace: str
    rules: List[IngressRule] = []
    tls: List[IngressTLS] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class IngressListResponse(BaseModel):
    """Ingress列表响应"""
    total: int
    ingresses: List[IngressInfo]


class IngressCreateRequest(BaseModel):
    """创建Ingress请求"""
    name: str = Field(..., min_length=1, max_length=63, description="Ingress名称")
    rules: List[IngressRule] = Field(..., min_length=1, description="路由规则")
    tls: Optional[List[IngressTLS]] = Field(None, description="TLS配置")
    labels: Optional[Dict[str, str]] = Field(None, description="标签")
    ingress_class_name: Optional[str] = Field(None, description="IngressClass名称")


class IngressUpdateRequest(BaseModel):
    """更新Ingress请求"""
    rules: Optional[List[IngressRule]] = None
    tls: Optional[List[IngressTLS]] = None
    labels: Optional[Dict[str, str]] = None


# ============ Secret相关模式 ============

class SecretInfo(BaseModel):
    """Secret信息"""
    name: str
    namespace: str
    type: str
    data_keys: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class SecretListResponse(BaseModel):
    """Secret列表响应"""
    total: int
    secrets: List[SecretInfo]


class SecretCreateRequest(BaseModel):
    """创建Secret请求"""
    name: str = Field(..., min_length=1, max_length=63, description="Secret名称")
    type: str = Field("Opaque", description="Secret类型")
    data: Dict[str, str] = Field(..., description="Secret数据(Base64编码)")
    string_data: Optional[Dict[str, str]] = Field(None, description="Secret字符串数据(自动Base64)")
    labels: Optional[Dict[str, str]] = Field(None, description="标签")


class SecretUpdateRequest(BaseModel):
    """更新Secret请求"""
    data: Optional[Dict[str, str]] = None
    string_data: Optional[Dict[str, str]] = None
    labels: Optional[Dict[str, str]] = None


# ============ ConfigMap相关模式 ============

class ConfigMapInfo(BaseModel):
    """ConfigMap信息"""
    name: str
    namespace: str
    data_keys: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class ConfigMapListResponse(BaseModel):
    """ConfigMap列表响应"""
    total: int
    configmaps: List[ConfigMapInfo]


class ConfigMapCreateRequest(BaseModel):
    """创建ConfigMap请求"""
    name: str = Field(..., min_length=1, max_length=63, description="ConfigMap名称")
    data: Dict[str, str] = Field(..., description="ConfigMap数据")
    labels: Optional[Dict[str, str]] = Field(None, description="标签")


class ConfigMapUpdateRequest(BaseModel):
    """更新ConfigMap请求"""
    data: Optional[Dict[str, str]] = None
    labels: Optional[Dict[str, str]] = None


# ============ Deployment相关模式 ============

class DeploymentInfo(BaseModel):
    """Deployment信息"""
    name: str
    namespace: str
    replicas: int
    ready_replicas: Optional[int] = None
    available_replicas: Optional[int] = None
    image: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class DeploymentListResponse(BaseModel):
    """Deployment列表响应"""
    total: int
    deployments: List[DeploymentInfo]


class ContainerSpec(BaseModel):
    """容器规格"""
    name: str
    image: str
    ports: Optional[List[int]] = None
    env: Optional[Dict[str, str]] = None
    resources: Optional[Dict[str, Any]] = None


class DeploymentCreateRequest(BaseModel):
    """创建Deployment请求"""
    name: str = Field(..., min_length=1, max_length=63, description="Deployment名称")
    replicas: int = Field(1, ge=1, le=100, description="副本数")
    containers: List[ContainerSpec] = Field(..., min_length=1, description="容器配置")
    labels: Optional[Dict[str, str]] = Field(None, description="标签")
    match_labels: Optional[Dict[str, str]] = Field(None, description="选择器标签")


class DeploymentUpdateRequest(BaseModel):
    """更新Deployment请求"""
    replicas: Optional[int] = None
    containers: Optional[List[ContainerSpec]] = None
    labels: Optional[Dict[str, str]] = None


class DeploymentScaleRequest(BaseModel):
    """Deployment扩缩容请求"""
    replicas: int = Field(..., ge=0, le=100, description="目标副本数")


# ============ StatefulSet相关模式 ============

class StatefulSetInfo(BaseModel):
    """StatefulSet信息"""
    name: str
    namespace: str
    replicas: int
    ready_replicas: Optional[int] = None
    current_replicas: Optional[int] = None
    image: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class StatefulSetListResponse(BaseModel):
    """StatefulSet列表响应"""
    total: int
    statefulsets: List[StatefulSetInfo]


# ============ DaemonSet相关模式 ============

class DaemonSetInfo(BaseModel):
    """DaemonSet信息"""
    name: str
    namespace: str
    desired_number: int
    current_number: int
    ready_number: int
    image: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class DaemonSetListResponse(BaseModel):
    """DaemonSet列表响应"""
    total: int
    daemonsets: List[DaemonSetInfo]


# ============ Job相关模式 ============

class JobInfo(BaseModel):
    """Job信息"""
    name: str
    namespace: str
    completions: Optional[int] = None
    succeeded: Optional[int] = None
    failed: Optional[int] = None
    active: Optional[int] = None
    status: str
    image: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class JobListResponse(BaseModel):
    """Job列表响应"""
    total: int
    jobs: List[JobInfo]


# ============ CronJob相关模式 ============

class CronJobInfo(BaseModel):
    """CronJob信息"""
    name: str
    namespace: str
    schedule: str
    suspend: bool
    last_schedule_time: Optional[datetime] = None
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class CronJobListResponse(BaseModel):
    """CronJob列表响应"""
    total: int
    cronjobs: List[CronJobInfo]


# ============ PVC相关模式 ============

class PVCInfo(BaseModel):
    """PVC信息"""
    name: str
    namespace: str
    status: str
    capacity: Optional[str] = None
    storage_class: Optional[str] = None
    access_modes: List[str] = []
    labels: Optional[Dict[str, str]] = None
    creation_timestamp: Optional[datetime] = None


class PVCListResponse(BaseModel):
    """PVC列表响应"""
    total: int
    pvcs: List[PVCInfo]


# ============ 项目资源总览 ============

class ProjectResourcesResponse(BaseModel):
    """项目K8S资源响应"""
    namespace: str
    pods: List[dict]
    services: List[dict]
    configmaps: List[dict]
    secrets: List[dict]
    deployments: List[dict]
    statefulsets: List[dict]
    daemonsets: List[dict]
    jobs: List[dict]
    cronjobs: List[dict]
    pvcs: List[dict]
    ingresses: List[dict]