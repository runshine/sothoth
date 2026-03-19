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


class ProjectTLSSyncRequest(BaseModel):
    """项目TLS Secret同步请求"""
    source_namespace: str = Field(..., min_length=1, description="源命名空间")
    source_secret_name: str = Field(..., min_length=1, description="源TLS Secret名称")
    target_secret_name: str = Field(..., min_length=1, description="目标TLS Secret名称")


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
    containers: List[Dict[str, Any]] = Field(default_factory=list)
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


class IngressSimpleCreateRequest(BaseModel):
    """Ingress简化创建请求（供工作流服务使用）"""
    name: str = Field(..., description="Ingress名称")
    service_name: str = Field(..., description="后端Service名称")
    service_port: int = Field(..., description="后端Service端口")
    host: Optional[str] = Field(default=None, description="完整域名，传入则优先使用")
    host_prefix: Optional[str] = Field(default=None, description="域名前缀，平台将按统一规则生成host")
    ingress_type: str = Field(default="nginx", description="Ingress类型: nginx")
    ingress_ip: Optional[str] = Field(default=None, description="Ingress Controller的外部IP地址（用于记录访问地址）")
    path: str = Field(default="/", description="路径，默认为根路径")
    path_type: str = Field(default="Prefix", description="路径类型: Prefix, Exact, ImplementationSpecific")


class IngressExternalCreateRequest(BaseModel):
    """Ingress外部端点创建请求（路由到外部IP:端口）"""
    name: str = Field(..., description="Ingress名称")
    external_ips: List[str] = Field(..., description="外部IP地址列表（支持多个IP负载均衡）")
    external_port: int = Field(..., description="外部端口")
    host: Optional[str] = Field(default=None, description="完整域名，传入则优先使用")
    host_prefix: Optional[str] = Field(default=None, description="域名前缀，平台将按统一规则生成host")
    path: str = Field(default="/", description="路径，默认为根路径")
    path_type: str = Field(default="Prefix", description="路径类型: Prefix, Exact, ImplementationSpecific")
    ingress_type: str = Field(default="nginx", description="Ingress类型: nginx")
    service_port: int = Field(default=80, description="Service端口（Ingress指向此端口）")
    tls_enabled: bool = Field(default=False, description="是否启用TLS")
    tls_secret_name: Optional[str] = Field(default=None, description="TLS Secret名称（启用TLS时必需）")
    # NGINX Ingress 注解参数
    websocket_enabled: bool = Field(default=False, description="是否启用WebSocket支持")
    proxy_body_size: str = Field(default="10m", description="最大上传文件大小，如: 10m, 10240m, 1g")
    proxy_connect_timeout: int = Field(default=60, description="连接超时时间（秒）")
    proxy_send_timeout: int = Field(default=60, description="发送超时时间（秒）")
    proxy_read_timeout: int = Field(default=60, description="读取超时时间（秒）")
    ssl_redirect: bool = Field(default=True, description="是否强制HTTPS重定向")


class AgentIngressRouteCreateRequest(BaseModel):
    """Agent动态Ingress路由创建请求"""
    agent_key: str = Field(..., description="Agent唯一标识")
    external_ips: List[str] = Field(..., min_length=1, description="Agent可达IP列表")
    target_port: int = Field(..., description="Agent目标端口")
    host: Optional[str] = Field(default=None, description="完整域名，传入则优先使用")
    host_prefix: Optional[str] = Field(default=None, description="域名前缀，不传则按agent_key和端口生成")
    path: str = Field(default="/", description="路由路径")
    path_type: str = Field(default="Prefix", description="路径类型")
    ingress_type: Optional[str] = Field(default=None, description="IngressClass，不传则使用平台默认")
    service_port: Optional[int] = Field(default=None, description="Ingress后端service端口")
    tls_enabled: Optional[bool] = Field(default=None, description="是否启用TLS")
    tls_secret_name: Optional[str] = Field(default=None, description="TLS Secret名")
    websocket_enabled: Optional[bool] = Field(default=None, description="是否开启WebSocket转发")
    proxy_body_size: Optional[str] = Field(default=None, description="Nginx代理body大小")
    proxy_connect_timeout: Optional[int] = Field(default=None, description="Nginx连接超时")
    proxy_send_timeout: Optional[int] = Field(default=None, description="Nginx发送超时")
    proxy_read_timeout: Optional[int] = Field(default=None, description="Nginx读取超时")
    ssl_redirect: Optional[bool] = Field(default=None, description="是否强制HTTPS重定向")
    owner_service: str = Field(default="platform-agent", description="创建来源服务")
    created_by: Optional[str] = Field(default=None, description="创建人")
    force_recreate: bool = Field(default=False, description="命中同一业务路由时是否强制重建")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="扩展元数据")


class AgentIngressRouteInfo(BaseModel):
    """Agent动态Ingress路由信息"""
    route_id: str
    project_id: str
    namespace: str
    agent_key: str
    target_port: int
    external_ips: List[str] = Field(default_factory=list)
    host: str
    path: str
    ingress_type: str
    path_type: str
    service_port: int
    ingress_name: str
    service_name: str
    tls_enabled: bool
    tls_secret_name: Optional[str] = None
    websocket_enabled: bool
    status: str
    access_url: Optional[str] = None
    owner_service: Optional[str] = None
    created_by: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    deleted_at: Optional[str] = None


class AgentIngressRouteListResponse(BaseModel):
    """Agent动态Ingress路由列表"""
    total: int
    items: List[AgentIngressRouteInfo]


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
