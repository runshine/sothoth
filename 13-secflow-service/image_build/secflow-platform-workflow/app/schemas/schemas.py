"""
Pydantic schemas for workflow service
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, field_validator, model_validator


# ============ Common Enums ============

class TemplateScope(str, Enum):
    """Template scope"""
    GLOBAL = "global"  # Global template, visible to all projects
    PROJECT = "project"  # Project-level template


class ImagePullPolicy(str, Enum):
    """Image pull policy"""
    ALWAYS = "Always"
    IF_NOT_PRESENT = "IfNotPresent"
    NEVER = "Never"


class ServiceType(str, Enum):
    """Service type"""
    CLUSTER_IP = "ClusterIP"
    LOAD_BALANCER = "LoadBalancer"
    NODE_PORT = "NodePort"


class WorkflowStatus(str, Enum):
    """Workflow instance status

    Status flow:
    - pending -> initializing (when initialize is triggered)
    - initializing -> initialized (after initialize completes) or failed (if init fails)
    - initialized -> running (after start)
    - running -> succeeded (all nodes complete) or failed (any node fails) or stopped (manual stop)
    - stopped -> running (after start again)

    For persistent mode with trigger:
    - initialized/running -> can be triggered multiple times
    """
    PENDING = "pending"          # 刚创建，未初始化
    INITIALIZING = "initializing"  # 正在初始化中
    INITIALIZED = "initialized"  # 已初始化，Deployment/Service已创建
    RUNNING = "running"          # 运行中
    SUCCEEDED = "succeeded"      # 执行成功
    FAILED = "failed"            # 执行失败
    STOPPED = "stopped"          # 已停止


class RunMode(str, Enum):
    """Workflow run mode"""
    ONCE = "once"  # Run once and finish
    PERSISTENT = "persistent"  # Keep running, can be triggered multiple times


class TriggerType(str, Enum):
    """Trigger type for workflow"""
    MANUAL = "manual"  # Manual trigger only
    HTTP = "http"  # HTTP endpoint trigger


class NodeType(str, Enum):
    """Workflow node type"""
    APP = "app"  # Deployment application
    JOB = "job"  # One-time job


class NodeStatus(str, Enum):
    """Workflow node status

    APP节点: PENDING, NOT_READY, READY, STOPPED, FAILED
    JOB节点: PENDING, RUNNING, SUCCEEDED, FAILED
    """
    PENDING = "pending"        # APP: Pod未运行; JOB: 等待执行
    NOT_READY = "not_ready"    # APP: Pod已运行但未就绪
    READY = "ready"            # APP: Pod全部就绪
    RUNNING = "running"        # JOB: 执行中
    SUCCEEDED = "succeeded"    # JOB: 执行成功
    FAILED = "failed"          # 执行失败
    STOPPED = "stopped"        # 已停止


# ============ Health Check Schemas ============

class HealthCheckConfig(BaseModel):
    """Health check configuration"""
    type: str = Field(..., description="Health check type: http/tcp/exec")
    port: Optional[int] = Field(None, description="Health check port")
    path: Optional[str] = Field(None, description="HTTP health check path")
    command: Optional[List[str]] = Field(None, description="Exec health check command")
    initial_delay_seconds: int = Field(10, ge=0, description="Initial delay seconds")
    period_seconds: int = Field(10, ge=1, description="Period seconds")
    timeout_seconds: int = Field(5, ge=1, description="Timeout seconds")
    failure_threshold: int = Field(3, ge=1, description="Failure threshold")
    success_threshold: int = Field(1, ge=1, description="Success threshold")


# ============ Environment Variable Schemas ============

class EnvVar(BaseModel):
    """Fixed environment variable - known key and value at template definition time"""
    name: str = Field(..., min_length=1, description="Variable name")
    value: str = Field(..., description="Variable value")


class EnvVarInput(BaseModel):
    """
    Environment variable input dependency - declare need from upstream, source determined at workflow instance.
    The value will be obtained from an upstream node's output.
    """
    name: str = Field(..., min_length=1, description="Environment variable name to set in current container")
    default_value: Optional[str] = Field(None, description="Default value if source not available")



# ============ Service Port Schemas ============

class ServicePort(BaseModel):
    """Service port configuration"""
    name: str = Field(..., min_length=1, description="Port name")
    port: int = Field(..., ge=1, le=65535, description="Service port")
    target_port: int = Field(..., ge=1, le=65535, description="Target port")
    protocol: str = Field(default="TCP", description="Protocol: TCP/UDP")


# ============ Volume Mount Schemas ============

class VolumeMount(BaseModel):
    """Fixed PVC volume mount - known PVC name at template definition time"""
    pvc_name: str = Field(..., description="PVC name")
    mount_path: str = Field(..., description="Mount path in container")
    sub_path: Optional[str] = Field(None, description="Sub-path within the PVC to mount")
    read_only: bool = Field(default=False, description="Read only")


class VolumeMountInput(BaseModel):
    """
    Volume mount input dependency - declare need from upstream PVC, source determined at workflow instance.
    The actual PVC source (source_node_id) and sub_path are specified when instantiating the workflow node.

    模板级别只声明需要挂载的路径和是否只读，具体的 sub_path 在节点实例化时指定。
    """
    mount_path: str = Field(..., description="Mount path in container where upstream PVC will be mounted")
    read_only: bool = Field(default=True, description="Read only mount (input is typically read-only)")




# ============ Instance-level Dependency Schemas ============
# These are used at workflow node instance level to specify the actual source

class DependencyEnvVar(BaseModel):
    """Environment variable dependency at instance level - specify source_node_id"""
    name: str = Field(..., min_length=1, description="Environment variable name to set in current node")
    source_node_id: str = Field(..., description="Source node ID to get value from")
    default_value: Optional[str] = Field(None, description="Default value if source not available")


class DependencyVolumeMount(BaseModel):
    """
    Volume mount dependency at instance level - specify source_node_id and source_pvc_name.
    This connects the template's VolumeMountInput to a specific upstream node's PVC.
    """
    mount_path: str = Field(..., description="Mount path in current container")
    sub_path: Optional[str] = Field(None, description="Sub-path within the PVC to mount")
    source_node_id: str = Field(..., description="Source node ID to get PVC from")
    source_pvc_name: Optional[str] = Field(None, description="Specific PVC name (optional, auto-detect if not specified)")
    read_only: bool = Field(default=True, description="Read only mount")


# ============ Resource Requirements Schemas ============

class ResourceRequirements(BaseModel):
    """Minimum resource requirements for containers"""
    requests: Optional[Dict[str, str]] = Field(None, description="Minimum resource requests (cpu, memory)")
    limits: Optional[Dict[str, str]] = Field(None, description="Resource limits (cpu, memory)")


# ============ Container Configuration Schemas ============

class ContainerConfig(BaseModel):
    """Container configuration - each container has its own definition and dependencies"""
    name: str = Field(..., min_length=1, max_length=128, description="Container name")
    image: str = Field(..., description="Container image")
    command: Optional[List[str]] = Field(None, description="Startup command")
    args: Optional[List[str]] = Field(None, description="Command arguments")

    # ============ Fixed (known at template definition) ============
    env_vars: List[EnvVar] = Field(default=[], description="Fixed environment variables (key+value)")
    volume_mounts: List[VolumeMount] = Field(default=[], description="Fixed PVC mounts (known PVC names)")

    # ============ Input Dependencies (from upstream) ============
    input_env_vars: List[EnvVarInput] = Field(default=[], description="Input env vars - need from upstream, source determined at instance")
    input_volume_mounts: List[VolumeMountInput] = Field(default=[], description="Input volume mounts - need from upstream, source determined at instance")

    # ============ Container Settings ============
    privileged: bool = Field(default=False, description="Run in privileged mode")
    image_pull_policy: ImagePullPolicy = Field(default=ImagePullPolicy.IF_NOT_PRESENT)
    resources: Optional[ResourceRequirements] = Field(None, description="Resource requirements: requests (minimum) and limits")

    # ============ Health Check Configuration ============
    # 应用模板: 每个容器都可以配置健康检查; 任务模板: 健康检查可选
    liveness_probe: Optional[HealthCheckConfig] = Field(None, description="Liveness probe configuration")
    readiness_probe: Optional[HealthCheckConfig] = Field(None, description="Readiness probe configuration")


# ============ App Template Schemas ============

class AppTemplateCreate(BaseModel):
    """Create application template request with multi-container support"""
    name: str = Field(..., min_length=1, max_length=128, description="Template name")
    description: Optional[str] = Field(None, description="Template description")
    scope: TemplateScope = Field(default=TemplateScope.PROJECT, description="Template scope")
    project_id: Optional[str] = Field(None, description="Project ID (required for project scope)")
    # Multi-container configuration
    containers: List[ContainerConfig] = Field(..., min_length=1, description="Container configurations (at least one)")
    # Deployment-level configuration
    replicas: int = Field(default=1, ge=1, description="Number of replicas")


class AppTemplateUpdate(BaseModel):
    """Update application template request"""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    containers: Optional[List[ContainerConfig]] = None
    replicas: Optional[int] = Field(None, ge=1, description="Number of replicas")


class AppTemplateResponse(BaseModel):
    """Application template response with multi-container support"""
    id: str
    name: str
    description: Optional[str]
    scope: str
    project_id: Optional[str]
    containers: List[ContainerConfig]
    replicas: int
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AppTemplateListResponse(BaseModel):
    """Application template list response"""
    total: int
    items: List[AppTemplateResponse]


# ============ Job Template Schemas ============

class JobTemplateCreate(BaseModel):
    """Create job template request with multi-container support"""
    name: str = Field(..., min_length=1, max_length=128, description="Template name")
    description: Optional[str] = Field(None, description="Template description")
    scope: TemplateScope = Field(default=TemplateScope.PROJECT, description="Template scope")
    project_id: Optional[str] = Field(None, description="Project ID (required for project scope)")
    # Multi-container configuration
    containers: List[ContainerConfig] = Field(..., min_length=1, description="Container configurations (at least one)")
    # Job-level configuration
    ttl_seconds_after_finished: Optional[int] = Field(3600, ge=0, description="TTL after finished")
    backoff_limit: int = Field(3, ge=0, description="Backoff limit")


class JobTemplateUpdate(BaseModel):
    """Update job template request"""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    containers: Optional[List[ContainerConfig]] = None
    ttl_seconds_after_finished: Optional[int] = None
    backoff_limit: Optional[int] = None


class JobTemplateResponse(BaseModel):
    """Job template response"""
    id: str
    name: str
    description: Optional[str]
    scope: str
    project_id: Optional[str]
    containers: List[ContainerConfig]
    ttl_seconds_after_finished: Optional[int]
    backoff_limit: int
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class JobTemplateListResponse(BaseModel):
    """Job template list response"""
    total: int
    items: List[JobTemplateResponse]


# ============ Workflow Node Schemas ============

class WorkflowNodeConfig(BaseModel):
    """Workflow node configuration - specifies actual sources for template dependencies

    Note: Different nodes have no dependency relationship, no depends_on needed.
    The env_vars and volume_mounts are used to satisfy template's dependency requirements
    when instantiating the template.

    ID is auto-generated, not user-specified.
    """
    node_type: NodeType = Field(..., description="Node type: app/job")
    template_id: str = Field(..., description="Template ID")
    name: str = Field(..., description="Node display name")
    position: Dict[str, float] = Field(default={"x": 0.0, "y": 0.0}, description="Node position in canvas")

    # Fixed (override template)
    env_vars: Optional[List[EnvVar]] = Field(None, description="Override/add fixed environment variables")
    volume_mounts: Optional[List[VolumeMount]] = Field(None, description="Override/add fixed volume mounts")

    # Resource Requirements
    resources: Optional[ResourceRequirements] = Field(None, description="Override resource requirements")

    # Timeout configuration (in seconds, excluding image pull time)
    # For app type: time from start to ready
    # For job type: time for entire job execution
    timeout_seconds: Optional[int] = Field(None, ge=1, description="Node execution timeout in seconds")

    # Service configuration (for app type nodes only)
    # These fields are only used when node_type is "app"
    create_service: bool = Field(default=True, description="Whether to create K8s Service")
    service_name: Optional[str] = Field(None, description="K8s Service name (default: auto-generated)")
    service_ports: List[ServicePort] = Field(default=[], description="Service ports exposed by the Deployment")
    service_type: ServiceType = Field(default=ServiceType.CLUSTER_IP, description="K8s Service type")

    # Ingress configuration (optional, for app type nodes with service)
    # These fields are only used when node_type is "app" and create_service is True
    create_ingress: bool = Field(default=False, description="Whether to create K8s Ingress")
    ingress_type: Optional[str] = Field(None, description="Ingress type: nginx or None")
    ingress_host: Optional[str] = Field(None, description="Ingress hostname (e.g., myapp.example.com)")
    ingress_ip: Optional[str] = Field(None, description="Ingress Controller external IP (for user to access the service)")

    @model_validator(mode='after')
    def validate_service_config(self):
        """Validate service configuration when create_service is True and node_type is app"""
        if self.node_type == NodeType.APP and self.create_ingress and not self.create_service:
            raise ValueError("create_service must be True when create_ingress is True")
        if self.node_type == NodeType.APP and self.create_service:
            errors = []
            if not self.service_name or not self.service_name.strip():
                errors.append("service_name is required when create_service is True")
            if not self.service_ports or len(self.service_ports) == 0:
                errors.append("service_ports cannot be empty when create_service is True")
            if self.create_ingress:
                if not self.ingress_type or self.ingress_type != "nginx":
                    errors.append("ingress_type must be nginx when create_ingress is True")
                if not self.ingress_host or not self.ingress_host.strip():
                    errors.append("ingress_host is required when create_ingress is True")
                if not self.ingress_ip or not self.ingress_ip.strip():
                    errors.append("ingress_ip is required when create_ingress is True")
            if errors:
                raise ValueError("; ".join(errors))
        return self


class WorkflowEdgeConfig(BaseModel):
    """Workflow edge (connection) configuration"""
    edge_id: str = Field(..., description="Unique edge ID")
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    # PVC sharing between nodes
    shared_pvc: Optional[str] = Field(None, description="PVC name to share between nodes")


# ============ Workflow Instance Schemas ============

class WorkflowInstanceCreate(BaseModel):
    """Create workflow instance request

    Can create empty workflow (without nodes) and add nodes later.
    Each node is an instantiation of an AppTemplate (app type) or JobTemplate (job type).
    """
    name: str = Field(..., min_length=1, max_length=128, description="Instance name")
    description: Optional[str] = Field(None, description="Instance description")
    project_id: str = Field(..., description="Project ID")

    # Workflow definition - nodes can be empty for later addition
    nodes: List[WorkflowNodeConfig] = Field(default=[], description="Workflow nodes (can be empty)")
    edges: List[WorkflowEdgeConfig] = Field(default=[], description="Workflow edges/connections")

    # Run mode: "once" (run once) or "persistent" (keep running)
    run_mode: RunMode = Field(default=RunMode.ONCE, description="Run mode: once or persistent")

    # Trigger configuration (for persistent mode)
    trigger_type: TriggerType = Field(default=TriggerType.MANUAL, description="Trigger type: manual or http")
    trigger_enabled: bool = Field(default=False, description="Enable trigger (for persistent mode)")

    # Override configurations
    node_configs: Optional[Dict[str, Dict[str, Any]]] = Field(None, description="Node-level overrides")


class WorkflowInstanceUpdate(BaseModel):
    """Update workflow instance request"""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    # Update all edges at once
    edges: Optional[List[WorkflowEdgeConfig]] = Field(None, description="Update workflow edges/connections")
    # For persistent mode - enable/disable trigger
    trigger_enabled: Optional[bool] = Field(None, description="Enable/disable trigger")
    is_active: Optional[bool] = Field(None, description="Set workflow active state")


class WorkflowInstanceInitializeRequest(BaseModel):
    """Initialize workflow instance request

    force: If True, will delete existing K8S resources (Deployment/Service) and re-initialize.
           If False (default), will fail if workflow is already initialized.
    """
    force: bool = Field(default=False, description="Force re-initialization by deleting existing resources")


# ============ Workflow Node Operation Schemas ============

class WorkflowNodeCreate(BaseModel):
    """Create workflow node request

    Adds a node to existing workflow instance.
    Node is instantiated from AppTemplate (app type) or JobTemplate (job type).

    Note: Different nodes have no dependency relationship, no depends_on needed.
    The env_vars and volume_mounts are used to satisfy template's dependency requirements
    when instantiating the template.

    ID is auto-generated, not user-specified.
    """
    node_type: NodeType = Field(..., description="Node type: app/job")
    template_id: str = Field(..., description="App template ID or Job template ID")
    name: str = Field(..., description="Node display name")
    position: Dict[str, float] = Field(default={"x": 0.0, "y": 0.0}, description="Node position in canvas")

    # Fixed (override template) - environment variables and volume mounts
    # These are used to satisfy template dependencies when instantiating
    env_vars: Optional[List[EnvVar]] = Field(None, description="Override/add fixed environment variables")
    volume_mounts: Optional[List[VolumeMount]] = Field(None, description="Override/add fixed volume mounts")

    # Resource Requirements
    resources: Optional[ResourceRequirements] = Field(None, description="Override resource requirements")

    # Timeout configuration (in seconds, excluding image pull time)
    # For app type: time from start to ready
    # For job type: time for entire job execution
    timeout_seconds: Optional[int] = Field(None, ge=1, description="Node execution timeout in seconds")

    # Service configuration (for app type nodes only)
    # These fields are only used when node_type is "app"
    create_service: bool = Field(default=True, description="Whether to create K8s Service")
    service_name: Optional[str] = Field(None, description="K8s Service name (default: auto-generated)")
    service_ports: List[ServicePort] = Field(default=[], description="Service ports exposed by the Deployment")
    service_type: ServiceType = Field(default=ServiceType.CLUSTER_IP, description="K8s Service type")

    # Ingress configuration (optional, for app type nodes with service)
    # These fields are only used when node_type is "app" and create_service is True
    create_ingress: bool = Field(default=False, description="Whether to create K8s Ingress")
    ingress_type: Optional[str] = Field(None, description="Ingress type: nginx or None")
    ingress_host: Optional[str] = Field(None, description="Ingress hostname (e.g., myapp.example.com)")
    ingress_ip: Optional[str] = Field(None, description="Ingress Controller external IP (for user to access the service)")

    @model_validator(mode='after')
    def validate_service_config(self):
        """Validate service configuration when create_service is True and node_type is app"""
        if self.node_type == NodeType.APP and self.create_ingress and not self.create_service:
            raise ValueError("create_service must be True when create_ingress is True")
        if self.node_type == NodeType.APP and self.create_service:
            errors = []
            if not self.service_name or not self.service_name.strip():
                errors.append("service_name is required when create_service is True")
            if not self.service_ports or len(self.service_ports) == 0:
                errors.append("service_ports cannot be empty when create_service is True")
            if self.create_ingress:
                if not self.ingress_type or self.ingress_type != "nginx":
                    errors.append("ingress_type must be nginx when create_ingress is True")
                if not self.ingress_host or not self.ingress_host.strip():
                    errors.append("ingress_host is required when create_ingress is True")
                if not self.ingress_ip or not self.ingress_ip.strip():
                    errors.append("ingress_ip is required when create_ingress is True")
            if errors:
                raise ValueError("; ".join(errors))
        return self


class WorkflowNodeUpdate(BaseModel):
    """Update workflow node request

    Note: Different nodes have no dependency relationship, no depends_on needed.
    """
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    position: Optional[Dict[str, float]] = Field(None, description="Node position in canvas")
    # Fixed (override template)
    env_vars: Optional[List[EnvVar]] = Field(None, description="Override/add fixed environment variables")
    volume_mounts: Optional[List[VolumeMount]] = Field(None, description="Override/add fixed volume mounts")
    # Resource Requirements
    resources: Optional[ResourceRequirements] = Field(None, description="Override resource requirements")
    # Input Dependencies (specify source_node_id at instance level)
    input_env_vars: Optional[List[DependencyEnvVar]] = Field(None, description="Input environment variable dependencies")
    input_volume_mounts: Optional[List[DependencyVolumeMount]] = Field(None, description="Input volume mount dependencies")
    # Service configuration (for app type nodes only)
    # These fields are only used when node_type is "app"
    create_service: Optional[bool] = Field(None, description="Whether to create K8s Service")
    service_name: Optional[str] = Field(None, description="K8s Service name")
    service_ports: Optional[List[ServicePort]] = Field(None, description="Service ports exposed by the Deployment")
    service_type: Optional[ServiceType] = Field(None, description="K8s Service type")

    # Ingress configuration (optional, for app type nodes with service)
    create_ingress: Optional[bool] = Field(None, description="Whether to create K8s Ingress")
    ingress_type: Optional[str] = Field(None, description="Ingress type: nginx or None")
    ingress_host: Optional[str] = Field(None, description="Ingress hostname (e.g., myapp.example.com)")
    ingress_ip: Optional[str] = Field(None, description="Ingress Controller external IP (for user to access the service)")

    @model_validator(mode='after')
    def validate_service_config(self):
        """Validate service configuration when create_service is True"""
        if self.create_ingress is True and self.create_service is False:
            raise ValueError("create_service must be True when create_ingress is True")
        if self.create_service is True:
            errors = []
            if not self.service_name or not self.service_name.strip():
                errors.append("service_name is required when create_service is True")
            if not self.service_ports or len(self.service_ports) == 0:
                errors.append("service_ports cannot be empty when create_service is True")
            if self.create_ingress is True:
                if not self.ingress_type or self.ingress_type != "nginx":
                    errors.append("ingress_type must be nginx when create_ingress is True")
                if not self.ingress_host or not self.ingress_host.strip():
                    errors.append("ingress_host is required when create_ingress is True")
                if not self.ingress_ip or not self.ingress_ip.strip():
                    errors.append("ingress_ip is required when create_ingress is True")
            if errors:
                raise ValueError("; ".join(errors))
        return self


class WorkflowEdgesUpdate(BaseModel):
    """Update workflow edges request

    Updates edges connections between nodes.
    """
    edges_id: str = Field(..., description="Unique edge ID")
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    shared_pvc: Optional[str] = Field(None, description="Shared PVC name")


class WorkflowEdgesUpdateRequest(BaseModel):
    """Request to update workflow edges list"""
    edge_id: Optional[str] = Field(None, description="Edge ID (for add/update/delete operation)")
    source: Optional[str] = Field(None, description="Source node ID (for add operation)")
    target: Optional[str] = Field(None, description="Target node ID (for add operation)")
    shared_pvc: Optional[str] = Field(None, description="Shared PVC name (for add operation)")
    action: str = Field(..., description="Operation: add, update, delete")


class TriggerResponse(BaseModel):
    """Trigger workflow response"""
    instance_id: str
    trigger_url: str
    message: str


class WorkflowNodeInstanceResponse(BaseModel):
    """Workflow node instance response

    Note: node_id is the same as id (auto-generated, not user-specified)
    """
    id: str
    node_type: str
    template_id: str
    name: str
    status: str
    k8s_resource_name: Optional[str] = None
    k8s_resource_type: Optional[str] = None
    depends_on: List[str] = []
    downstream_node_ids: List[str] = []
    service_name: Optional[str] = None
    timeout_seconds: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    message: Optional[str] = None
    # Node configuration (from creation, for query and update)
    position: Dict[str, float] = {"x": 0.0, "y": 0.0}
    env_vars: List[EnvVar] = []
    volume_mounts: List[VolumeMount] = []
    resources: Optional[ResourceRequirements] = None
    # Input dependencies (specify sources)
    input_env_vars: List[DependencyEnvVar] = []
    input_volume_mounts: List[DependencyVolumeMount] = []
    # Service configuration (for app type nodes)
    create_service: bool = True
    service_ports: List[ServicePort] = []
    service_type: Optional[str] = None
    # Ingress configuration (optional)
    create_ingress: bool = False
    ingress_type: Optional[str] = None
    ingress_host: Optional[str] = None
    ingress_ip: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WorkflowNodeIngressBindingRequest(BaseModel):
    """Bind a custom domain to a node ingress."""
    create_ingress: bool = Field(default=True, description="Whether to create K8s Ingress")
    ingress_type: str = Field(default="nginx", description="Ingress type")
    ingress_host: str = Field(..., min_length=1, description="Custom domain")
    ingress_ip: str = Field(..., min_length=1, description="Selected ingress IP")
    path: str = Field(default="/", description="Ingress path")
    path_type: str = Field(default="Prefix", description="Ingress path type")


class WorkflowNodeDomainBindingResponse(BaseModel):
    """节点域名绑定记录响应。"""
    id: str
    instance_id: str
    node_instance_id: str
    node_id: str
    project_id: str
    service_name: Optional[str] = None
    ingress_name: Optional[str] = None
    ingress_type: Optional[str] = None
    domain: str
    ingress_ip: Optional[str] = None
    service_port: Optional[int] = None
    target_port: Optional[int] = None
    binding_status: str
    message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WorkflowInstanceResponse(BaseModel):
    """Workflow instance response

    Nodes are directly stored in the instance, each referencing an AppTemplate or JobTemplate.
    """
    id: str
    name: str
    description: Optional[str]
    project_id: str
    status: str
    run_mode: str
    trigger_type: str
    trigger_enabled: bool
    trigger_url: Optional[str]
    is_active: bool
    run_count: int
    last_run_at: Optional[datetime]
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    created_by: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WorkflowInstanceListResponse(BaseModel):
    """Workflow instance list response"""
    total: int
    items: List[WorkflowInstanceResponse]


# ============ Log Schemas ============

class PodLogResponse(BaseModel):
    """Pod log response"""
    resource_name: str = Field(..., description="Deployment or Job name")
    pod_name: str = Field(..., description="Pod name")
    namespace: str = Field(..., description="Namespace")
    logs: str = Field(..., description="Log content")
    container: Optional[str] = Field(None, description="Container name")
    previous: bool = Field(default=False, description="Get previous container logs")


class LogQueryRequest(BaseModel):
    """Log query request"""
    tail_lines: int = Field(default=100, ge=1, le=10000, description="Number of lines to return")
    container: Optional[str] = Field(None, description="Container name for multi-container pods")
    previous: bool = Field(default=False, description="Get previous container logs")
    timestamps: bool = Field(default=True, description="Include timestamps")


class WorkflowInstanceNodeLogEntry(BaseModel):
    """Workflow instance node log record."""
    id: str
    task_id: Optional[str] = None
    node_id: str
    node_name: Optional[str] = None
    instance_id: str
    project_id: str
    node_type: str
    k8s_resource_name: Optional[str] = None
    k8s_resource_type: Optional[str] = None
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    message: Optional[str] = None
    init_logs: Dict[str, Any] = Field(default_factory=dict)
    execution_logs: Dict[str, Any] = Field(default_factory=dict)
    log_updated_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class WorkflowInstanceNodeLogListResponse(BaseModel):
    """Paginated workflow instance node log records."""
    total: int
    page: int
    page_size: int
    items: List[WorkflowInstanceNodeLogEntry]


# ============ Auth Schemas ============

class TokenUser(BaseModel):
    """Token validation user info"""
    id: str
    username: str
    is_active: bool
    role: List[str]


# ============ Common Response Schemas ============

class SuccessResponse(BaseModel):
    """Success response"""
    message: str


class ErrorResponse(BaseModel):
    """Error response"""
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str


# ============ Sync Record Schemas ============

class WorkflowSyncRecordResponse(BaseModel):
    """同步记录响应"""
    id: str
    instance_id: str
    sync_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class WorkflowSyncRecordListResponse(BaseModel):
    """同步记录列表响应"""
    total: int
    items: List[WorkflowSyncRecordResponse]


# ============ App Workflow Schemas (Single Application Workflow) ============

class AppWorkflowCreate(BaseModel):
    """创建单应用工作流请求

    通过template_id引用已存在的应用模板，同时提供Service配置。
    工作流和节点在同一接口中创建。
    """
    name: str = Field(..., min_length=1, max_length=128, description="工作流名称")
    description: Optional[str] = Field(None, description="描述")
    project_id: str = Field(..., description="项目ID")

    # 必须引用已存在的应用模板
    template_id: str = Field(..., description="应用模板ID")

    # Service配置（APP节点需要暴露服务）
    service_name: str = Field(..., min_length=1, description="K8s Service名称")
    service_ports: List[ServicePort] = Field(..., min_length=1, description="Service端口配置")
    service_type: ServiceType = Field(default=ServiceType.CLUSTER_IP, description="Service类型")

    # 可选的覆盖配置
    env_vars: Optional[List[EnvVar]] = Field(None, description="覆盖/添加环境变量")
    volume_mounts: Optional[List[VolumeMount]] = Field(None, description="覆盖/添加卷挂载")
    resources: Optional[ResourceRequirements] = Field(None, description="覆盖资源需求")
    replicas: Optional[int] = Field(None, ge=1, description="覆盖副本数")
    timeout_seconds: Optional[int] = Field(None, ge=1, description="超时时间（秒）")

    # Ingress配置（可选）
    ingress_type: Optional[str] = Field(None, description="Ingress类型: nginx")
    ingress_host: Optional[str] = Field(None, description="Ingress域名 (例如: myapp.example.com)")
    ingress_ip: Optional[str] = Field(None, description="Ingress Controller外部IP地址")


class AppWorkflowUpdate(BaseModel):
    """更新单应用工作流请求"""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    # Service配置
    service_name: Optional[str] = Field(None, min_length=1)
    service_ports: Optional[List[ServicePort]] = None
    service_type: Optional[ServiceType] = None
    # 覆盖配置
    env_vars: Optional[List[EnvVar]] = None
    volume_mounts: Optional[List[VolumeMount]] = None
    resources: Optional[ResourceRequirements] = None
    replicas: Optional[int] = Field(None, ge=1)

    # Ingress配置（可选）
    ingress_type: Optional[str] = Field(None, description="Ingress类型: nginx")
    ingress_host: Optional[str] = Field(None, description="Ingress域名")
    ingress_ip: Optional[str] = Field(None, description="Ingress Controller外部IP地址")


class AppWorkflowNodeResponse(BaseModel):
    """单应用工作流节点响应"""
    id: str
    name: str
    node_type: str = "app"
    template_id: str
    status: str
    k8s_resource_name: Optional[str] = None
    service_name: Optional[str] = None
    message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    init_logs: Optional[str] = None

    # 节点配置
    env_vars: List[EnvVar] = []
    volume_mounts: List[VolumeMount] = []
    resources: Optional[ResourceRequirements] = None


class AppWorkflowResponse(BaseModel):
    """单应用工作流响应"""
    id: str
    name: str
    description: Optional[str]
    project_id: str
    status: str
    workflow_type: str = "simple_app"

    # 单节点信息（扁平化）
    node: AppWorkflowNodeResponse

    # Service信息
    service_name: Optional[str] = None
    service_ports: List[ServicePort] = []

    # 模板信息
    template_id: str
    template_name: Optional[str] = None

    # 审计字段
    created_by: str
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    message: Optional[str] = None


class AppWorkflowListResponse(BaseModel):
    """单应用工作流列表响应"""
    total: int
    items: List[AppWorkflowResponse]


# ============ Callback Schemas (for workflow-status service) ============

class NodeStatusCallbackRequest(BaseModel):
    """节点状态回调请求

    用于接收来自 workflow-status 服务的节点状态更新回调。
    workflow-status 在从 K8S 同步到节点状态变化后，通过此接口通知 workflow 服务。
    """
    node_id: str = Field(..., description="节点ID")
    instance_id: str = Field(..., description="工作流实例ID")
    status: str = Field(..., description="新状态: Pending/Not_ready/Ready/Running/Succeeded/Failed/Stopped")
    message: Optional[str] = Field(None, description="状态消息")
    started_at: Optional[datetime] = Field(None, description="开始时间")
    finished_at: Optional[datetime] = Field(None, description="结束时间")


class NodeStatusCallbackResponse(BaseModel):
    """节点状态回调响应"""
    success: bool
    node_id: str
    status: str
    message: Optional[str] = None
