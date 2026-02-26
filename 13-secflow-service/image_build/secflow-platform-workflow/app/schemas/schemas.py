"""
Pydantic schemas for workflow service
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


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
    """Workflow instance status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    STOPPED = "stopped"


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
    """Workflow node status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    STOPPED = "stopped"


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
    The actual PVC source (source_node_id) is specified when instantiating the workflow.
    """
    mount_path: str = Field(..., description="Mount path in container where upstream PVC will be mounted")
    sub_path: Optional[str] = Field(None, description="Sub-path within the PVC to mount")
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
    service_ports: List[ServicePort] = Field(default=[], description="Service ports exposed by the Deployment")
    replicas: int = Field(default=1, ge=1, description="Number of replicas")
    # Service configuration
    service_name: Optional[str] = Field(None, description="K8s Service name (default: auto-generated)")
    create_service: bool = Field(default=True, description="Whether to create K8s Service")
    service_type: ServiceType = Field(default=ServiceType.CLUSTER_IP, description="K8s Service type")


class AppTemplateUpdate(BaseModel):
    """Update application template request"""
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    containers: Optional[List[ContainerConfig]] = None
    service_ports: Optional[List[ServicePort]] = None
    replicas: Optional[int] = Field(None, ge=1)
    service_name: Optional[str] = Field(None, description="K8s Service name")
    create_service: Optional[bool] = Field(None, description="Whether to create K8s Service")
    service_type: Optional[ServiceType] = Field(None, description="K8s Service type")


class AppTemplateResponse(BaseModel):
    """Application template response with multi-container support"""
    id: str
    name: str
    description: Optional[str]
    scope: str
    project_id: Optional[str]
    containers: List[ContainerConfig]
    service_ports: List[ServicePort]
    replicas: int
    service_name: Optional[str]
    create_service: bool
    service_type: str
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
    """
    node_id: str = Field(..., description="Unique node ID")
    node_type: NodeType = Field(..., description="Node type: app/job")
    template_id: str = Field(..., description="Template ID")
    name: str = Field(..., description="Node display name")
    position: Dict[str, int] = Field(default={"x": 0, "y": 0}, description="Node position in canvas")

    # Fixed (override template)
    env_vars: Optional[List[EnvVar]] = Field(None, description="Override/add fixed environment variables")
    volume_mounts: Optional[List[VolumeMount]] = Field(None, description="Override/add fixed volume mounts")

    # Resource Requirements
    resources: Optional[ResourceRequirements] = Field(None, description="Override resource requirements")

    # Timeout configuration (in seconds, excluding image pull time)
    # For app type: time from start to ready
    # For job type: time for entire job execution
    timeout_seconds: Optional[int] = Field(None, ge=1, description="Node execution timeout in seconds")


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


# ============ Workflow Node Operation Schemas ============

class WorkflowNodeCreate(BaseModel):
    """Create workflow node request

    Adds a node to existing workflow instance.
    Node is instantiated from AppTemplate (app type) or JobTemplate (job type).

    Note: Different nodes have no dependency relationship, no depends_on needed.
    The env_vars and volume_mounts are used to satisfy template's dependency requirements
    when instantiating the template.
    """
    node_id: str = Field(..., description="Unique node ID within the workflow")
    node_type: NodeType = Field(..., description="Node type: app/job")
    template_id: str = Field(..., description="App template ID or Job template ID")
    name: str = Field(..., description="Node display name")
    position: Dict[str, int] = Field(default={"x": 0, "y": 0}, description="Node position in canvas")

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


class WorkflowNodeUpdate(BaseModel):
    """Update workflow node request

    Note: Different nodes have no dependency relationship, no depends_on needed.
    """
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    position: Optional[Dict[str, int]] = Field(None, description="Node position in canvas")
    # Fixed (override template)
    env_vars: Optional[List[EnvVar]] = Field(None, description="Override/add fixed environment variables")
    volume_mounts: Optional[List[VolumeMount]] = Field(None, description="Override/add fixed volume mounts")
    # Resource Requirements
    resources: Optional[ResourceRequirements] = Field(None, description="Override resource requirements")


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
    edges_id: Optional[str] = Field(None, description="Edge ID (for add operation)")
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
    """Workflow node instance response"""
    id: str
    node_id: str
    node_type: str
    template_id: str
    name: str
    status: str
    k8s_resource_name: Optional[str]
    k8s_resource_type: Optional[str]
    depends_on: List[str]
    downstream_node_ids: List[str]
    service_name: Optional[str]
    timeout_seconds: Optional[int]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    message: Optional[str]
    # Input dependencies (specify sources)
    input_env_vars: List[DependencyEnvVar]
    input_volume_mounts: List[DependencyVolumeMount]
    created_at: datetime

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
    nodes: List[WorkflowNodeInstanceResponse]
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
