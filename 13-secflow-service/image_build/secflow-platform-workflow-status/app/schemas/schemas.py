"""
Pydantic妯″紡瀹氫箟妯″潡 - 鑺傜偣鐘舵€佺鐞?"""

from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


# ============ 鐘舵€佸父閲忓畾涔?============

class AppNodeStatus:
    """
    APP鑺傜偣鐘舵€佸父閲?
    APP鑺傜偣鐘舵€佹祦杞? Pending -> Not_ready -> Ready
    - Pending: Pod鏈繍琛岋紝绛夊緟鍚姩
    - Not_ready: Pod宸茶繍琛屼絾鏈氨缁?    - Ready: Pod鍏ㄩ儴灏辩华锛屾湇鍔″彲鐢?    """
    PENDING = "Pending"
    NOT_READY = "Not_ready"
    READY = "Ready"

    # 鎵€鏈夋湁鏁堢姸鎬?    ALL = [PENDING, NOT_READY, READY]


class JobNodeStatus:
    """
    JOB鑺傜偣鐘舵€佸父閲?
    JOB鑺傜偣鐘舵€佹祦杞? Pending -> Running -> Succeeded/Failed
    - Pending: 绛夊緟鎵ц
    - Running: 鎵ц涓?    - Succeeded: 鎵ц鎴愬姛
    - Failed: 鎵ц澶辫触
    """
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

    # 鎵€鏈夋湁鏁堢姸鎬?    ALL = [PENDING, RUNNING, SUCCEEDED, FAILED]

    # 缁堟€侊紙涓嶄細鍐嶅彉鍖栫殑鐘舵€侊級
    TERMINAL_STATES = [SUCCEEDED, FAILED]


class WorkflowStatus:
    """
    宸ヤ綔娴佺姸鎬佸父閲?
    宸ヤ綔娴佺姸鎬佸垽鏂€昏緫锛堜紭鍏堢骇浠庨珮鍒颁綆锛?
    1. Failed: 鏈塉ob鑺傜偣澶辫触
    2. Running: 鏈夎妭鐐规鍦ㄦ墽琛屼腑锛圝ob鐨凴unning 鎴?APP鐨凬ot_ready锛?    3. Succeeded: 鍏ㄩ儴鑺傜偣瀹屾垚锛圓PP鐨凴eady 鎴?Job鐨凷ucceeded锛?    4. Pending: 鍏朵粬鎯呭喌
    """
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

    # 鎵€鏈夋湁鏁堢姸鎬?    ALL = [PENDING, RUNNING, SUCCEEDED, FAILED]

    # 缁堟€?    TERMINAL_STATES = [SUCCEEDED, FAILED]


class NodeType:
    """鑺傜偣绫诲瀷甯搁噺"""
    APP = "app"   # Deployment绫诲瀷鑺傜偣
    JOB = "job"   # Job绫诲瀷鑺傜偣

    ALL = [APP, JOB]


# ============ 閫氱敤妯″紡 ============

class ErrorResponse(BaseModel):
    """ErrorResponse model."""
    code: str
    message: str
    details: Optional[dict] = None


class SuccessResponse(BaseModel):
    """SuccessResponse model."""
    message: str
    data: Optional[dict] = None


# ============ 鑺傜偣鐘舵€佹ā寮?============

class NodeStatusInfo(BaseModel):
    """NodeStatusInfo model."""
    id: str
    task_id: str
    node_id: str
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
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class NodeStatusResponse(BaseModel):
    """NodeStatusResponse model."""
    node: NodeStatusInfo


class NodeListResponse(BaseModel):
    """NodeListResponse model."""
    total: int
    nodes: List[NodeStatusInfo]


# ============ Workflow status models ===========

class WorkflowStatusInfo(BaseModel):
    """WorkflowStatusInfo model."""
    id: str
    instance_id: str
    project_id: str
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    message: Optional[str] = None
    total_nodes: int = 0
    pending_nodes: int = 0
    not_ready_nodes: int = 0
    ready_nodes: int = 0
    running_nodes: int = 0
    succeeded_nodes: int = 0
    failed_nodes: int = 0
    stopped_nodes: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class WorkflowStatusResponse(BaseModel):
    """WorkflowStatusResponse model."""
    workflow: WorkflowStatusInfo


class WorkflowStatusListResponse(BaseModel):
    """WorkflowStatusListResponse model."""
    total: int
    page: int
    page_size: int
    workflows: List[WorkflowStatusInfo]


# ============ 鐘舵€佸巻鍙叉ā寮?============

class NodeHistoryEntry(BaseModel):
    """NodeHistoryEntry model."""
    id: int
    node_id: str
    instance_id: str
    project_id: str
    from_status: Optional[str] = None
    to_status: str
    reason: Optional[str] = None
    operator: Optional[str] = None
    created_at: Optional[str] = None


class NodeHistoryResponse(BaseModel):
    """NodeHistoryResponse model."""
    node_id: str
    project_id: str
    history: List[NodeHistoryEntry]


class WorkflowHistoryResponse(BaseModel):
    """WorkflowHistoryResponse model."""
    instance_id: str
    project_id: str
    history: List[NodeHistoryEntry]


# ============ 璇锋眰妯″紡 ============

class NodeSyncRequest(BaseModel):
    """NodeSyncRequest model."""
    project_id: str
    instance_id: str
    node_type: str  # app/job
    k8s_resource_name: str
    timeout_seconds: Optional[int] = None


class NodeSyncResponse(BaseModel):
    """NodeSyncResponse model."""
    node_id: str
    status: str
    message: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class NodeInfo(BaseModel):
    """NodeInfo model."""
    node_id: str
    node_type: str  # app/job
    k8s_resource_name: str
    timeout_seconds: Optional[int] = None


class BatchSyncRequest(BaseModel):
    """BatchSyncRequest model."""
    project_id: str
    nodes: List[NodeInfo]


class BatchSyncResponse(BaseModel):
    """BatchSyncResponse model."""
    instance_id: str
    workflow_status: Dict[str, Any]
    nodes: List[NodeStatusInfo]


class NodeInitialRequest(BaseModel):
    """NodeInitialRequest model."""
    node_id: str
    instance_id: str
    project_id: str
    node_type: str
    k8s_resource_name: str
    k8s_resource_type: Optional[str] = None
    initial_status: str = "Pending"
    init_logs: Optional[str] = None


class NodeInitialResponse(BaseModel):
    """NodeInitialResponse model."""
    success: bool
    node_id: str
    task_id: str


class NodeUpdateRequest(BaseModel):
    """NodeUpdateRequest model."""
    status: str
    message: Optional[str] = None


class NodeUpdateResponse(BaseModel):
    """NodeUpdateResponse model."""
    success: bool
    node_id: str
    task_id: Optional[str] = None
    status: str


class NodeLogResponse(BaseModel):
    """NodeLogResponse model."""
    task_id: Optional[str] = None
    node_id: str
    resource_name: Optional[str] = None
    namespace: Optional[str] = None
    logs: str
    pod_name: Optional[str] = None
    container: Optional[str] = None


class NodeStoredLogsResponse(BaseModel):
    """NodeStoredLogsResponse model."""
    task_id: Optional[str] = None
    node_id: str
    init_logs: str
    execution_logs: str
    log_updated_at: Optional[str] = None


class SaveLogsRequest(BaseModel):
    """SaveLogsRequest model."""
    logs: str


class SaveLogsResponse(BaseModel):
    """SaveLogsResponse model."""
    success: bool
    node_id: str
    task_id: Optional[str] = None


class NodeTaskCollectRequest(BaseModel):
    """Create a task-scoped node record and collect current status/logs."""
    node_id: str
    instance_id: str
    project_id: str
    node_type: str
    k8s_resource_name: str
    k8s_resource_type: Optional[str] = None
    timeout_seconds: Optional[int] = None
    tail_lines: int = Field(default=500, ge=1, le=10000)
    container: Optional[str] = None
    previous: bool = False
    initial_status: str = "Pending"
    metadata: Optional[Dict[str, Any]] = None


class NodeTaskCollectResponse(BaseModel):
    """Node task collect response."""
    task_id: str
    node: NodeStatusInfo
    logs: NodeLogResponse


class InstanceNodeLogsQueryRequest(BaseModel):
    """Query node log records within one workflow instance."""
    project_id: str
    node_ids: List[str]
    node_id: Optional[str] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class InstanceNodeLogRecord(BaseModel):
    """Stored node log record."""
    id: str
    task_id: Optional[str] = None
    node_id: str
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


class InstanceNodeLogsQueryResponse(BaseModel):
    """Paginated workflow instance node log records."""
    total: int
    page: int
    page_size: int
    items: List[InstanceNodeLogRecord]


# ============ 缁熻妯″紡 ============

class StatusStatistics(BaseModel):
    """StatusStatistics model."""
    total: int = 0
    pending: int = 0
    running: int = 0
    not_ready: int = 0
    ready: int = 0
    succeeded: int = 0
    failed: int = 0
    stopped: int = 0


class StatisticsResponse(BaseModel):
    """StatisticsResponse model."""
    project_id: str
    workflows: StatusStatistics
    nodes: StatusStatistics
    period_start: Optional[str] = None
    period_end: Optional[str] = None


# ============ 璁よ瘉妯″紡 ============

class TokenUser(BaseModel):
    """TokenUser model."""
    id: str
    username: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    role: List[str]


class TokenPayload(BaseModel):
    """TokenPayload model."""
    user: TokenUser


# ============ 鐩戞帶妯″紡 ============

class MonitoringNodeInfo(BaseModel):
    """MonitoringNodeInfo model."""
    node_id: str
    node_type: str  # app/job
    k8s_resource_name: Optional[str] = None
    timeout_seconds: Optional[int] = None


class MonitoringStartRequest(BaseModel):
    """MonitoringStartRequest model."""
    instance_id: str
    project_id: str
    nodes: List[MonitoringNodeInfo]
    poll_interval: int = Field(default=10, ge=5, le=300, description="杞闂撮殧(绉?")


class MonitoringStartResponse(BaseModel):
    """MonitoringStartResponse model."""
    success: bool
    session_id: str
    instance_id: str
    message: Optional[str] = None


class MonitoringStatusResponse(BaseModel):
    """MonitoringStatusResponse model."""
    id: str
    instance_id: str
    project_id: str
    status: str  # active/paused/stopped
    started_at: str
    stopped_at: Optional[str] = None
    last_poll_at: Optional[str] = None
    poll_count: int
    nodes_count: int


class MonitoringListResponse(BaseModel):
    """MonitoringListResponse model."""
    total: int
    sessions: List[MonitoringStatusResponse]


class MonitoringOperationResponse(BaseModel):
    """MonitoringOperationResponse model."""
    success: bool
    instance_id: str
    message: Optional[str] = None


# ============ 鐘舵€侀噸缃ā寮?============

class ResetJobNodesRequest(BaseModel):
    """ResetJobNodesRequest model."""
    instance_id: str
    project_id: str
    reset_logs: bool = False


class ResetNodeStatusRequest(BaseModel):
    """ResetNodeStatusRequest model."""
    node_id: str
    reset_logs: bool = False


class ResetNodeStatusResponse(BaseModel):
    """ResetNodeStatusResponse model."""
    success: bool
    node_id: str
    old_status: Optional[str] = None
    new_status: str = "Pending"


class ResetJobNodesResponse(BaseModel):
    """ResetJobNodesResponse model."""
    success: bool
    instance_id: str
    project_id: str
    reset_count: int
    reset_nodes: List[Dict[str, Any]]


# ============ 鑺傜偣鐢熷懡鍛ㄦ湡鎿嶄綔妯″紡 ============

class ContainerConfig(BaseModel):
    """ContainerConfig model."""
    name: Optional[str] = None
    image: str
    command: Optional[List[str]] = None
    args: Optional[List[str]] = None
    env_vars: Optional[List[Dict[str, str]]] = None
    volume_mounts: Optional[List[Dict[str, Any]]] = None
    resources: Optional[Dict[str, Any]] = None
    image_pull_policy: Optional[str] = "IfNotPresent"
    privileged: Optional[bool] = False
    liveness_probe: Optional[Dict[str, Any]] = None
    readiness_probe: Optional[Dict[str, Any]] = None


class ServicePortConfig(BaseModel):
    """ServicePortConfig model."""
    name: Optional[str] = None
    port: int
    targetPort: Optional[int] = None
    protocol: Optional[str] = "TCP"


class IngressConfig(BaseModel):
    """IngressConfig model."""
    host: Optional[str] = None
    host_prefix: Optional[str] = None
    ingress_type: str = "nginx"
    ingress_ip: Optional[str] = None
    path: str = "/"
    path_type: str = "Prefix"


class NodeInitializeRequest(BaseModel):
    """NodeInitializeRequest model."""
    instance_id: str
    project_id: str
    node_type: str  # "app" or "job"
    node_name: str
    deployment_name: Optional[str] = None
    service_name: Optional[str] = None
    ingress_config: Optional[IngressConfig] = None
    containers: List[ContainerConfig]
    volume_mounts: Optional[List[Dict[str, Any]]] = None
    replicas: int = 1
    service_ports: Optional[List[ServicePortConfig]] = None
    service_type: str = "ClusterIP"


class NodeInitializeResponse(BaseModel):
    """NodeInitializeResponse model."""
    success: bool
    node_id: str
    status: str
    message: Optional[str] = None
    k8s_resource_name: Optional[str] = None
    service_name: Optional[str] = None
    error: Optional[str] = None


class NodeUninitializeRequest(BaseModel):
    """NodeUninitializeRequest model."""
    instance_id: str
    project_id: str
    node_type: str
    k8s_resource_name: str
    service_name: Optional[str] = None
    has_ingress: bool = False


class NodeUninitializeResponse(BaseModel):
    """NodeUninitializeResponse model."""
    success: bool
    node_id: str
    message: Optional[str] = None
    error: Optional[str] = None


class JobConfig(BaseModel):
    """JobConfig model."""
    containers: List[ContainerConfig]
    volume_mounts: Optional[List[Dict[str, Any]]] = None
    ttl_seconds_after_finished: Optional[int] = 3600
    backoff_limit: int = 3


class NodeStartRequest(BaseModel):
    """NodeStartRequest model."""
    instance_id: str
    project_id: str
    node_type: str
    k8s_resource_name: Optional[str] = None
    job_config: Optional[JobConfig] = None  # JOB鑺傜偣涓撶敤


class NodeStartResponse(BaseModel):
    """NodeStartResponse model."""
    success: bool
    node_id: str
    status: str
    message: Optional[str] = None
    k8s_resource_name: Optional[str] = None
    error: Optional[str] = None


class NodeStopRequest(BaseModel):
    """NodeStopRequest model."""
    instance_id: str
    project_id: str
    node_type: str
    k8s_resource_name: str
    service_name: Optional[str] = None
    has_ingress: bool = False


class NodeStopResponse(BaseModel):
    """NodeStopResponse model."""
    success: bool
    node_id: str
    message: Optional[str] = None
    error: Optional[str] = None


class NodeOperationResult(BaseModel):
    """NodeOperationResult model."""
    success: bool
    node_id: str
    status: str
    message: Optional[str] = None
    k8s_resource_name: Optional[str] = None
    service_name: Optional[str] = None
    error: Optional[str] = None


# ============ 宸ヤ綔娴佺敓鍛藉懆鏈熸搷浣滄ā寮?============

class WorkflowNodeConfig(BaseModel):
    """WorkflowNodeConfig model."""
    node_id: str
    node_type: str  # app/job
    node_name: str
    # APP鑺傜偣閰嶇疆
    deployment_name: Optional[str] = None
    service_name: Optional[str] = None
    ingress_config: Optional[Dict[str, Any]] = None
    containers: Optional[List[Dict[str, Any]]] = None
    volume_mounts: Optional[List[Dict[str, Any]]] = None
    replicas: int = 1
    service_ports: Optional[List[Dict[str, Any]]] = None
    service_type: str = "ClusterIP"
    # JOB鑺傜偣閰嶇疆
    job_config: Optional[Dict[str, Any]] = None


class WorkflowInitializeRequest(BaseModel):
    """WorkflowInitializeRequest model."""
    project_id: str
    nodes: List[WorkflowNodeConfig]


class WorkflowNodeResult(BaseModel):
    """WorkflowNodeResult model."""
    node_id: str
    task_id: Optional[str] = None
    success: bool
    status: str
    message: Optional[str] = None
    k8s_resource_name: Optional[str] = None
    service_name: Optional[str] = None
    error: Optional[str] = None


class WorkflowLifecycleResponse(BaseModel):
    """WorkflowLifecycleResponse model."""
    success: bool
    instance_id: str
    project_id: str
    total_nodes: int
    succeeded_nodes: int
    failed_nodes: int
    nodes: List[WorkflowNodeResult]
    message: Optional[str] = None


class WorkflowDeinitializeRequest(BaseModel):
    """WorkflowDeinitializeRequest model."""
    project_id: str
    nodes: Optional[List[Dict[str, Any]]] = None


class WorkflowStopRequest(BaseModel):
    """WorkflowStopRequest model."""
    project_id: str
    nodes: Optional[List[Dict[str, Any]]] = None


class WorkflowTriggerNodeConfig(BaseModel):
    """Trigger-time executable node configuration."""
    node_id: str
    node_name: str
    node_type: str
    depends_on: List[str] = []
    k8s_resource_name: Optional[str] = None
    service_name: Optional[str] = None
    timeout_seconds: Optional[int] = None
    job_config: Optional[Dict[str, Any]] = None


class WorkflowTriggerRequest(BaseModel):
    """Workflow trigger execution request."""
    project_id: str
    run_mode: str
    nodes: List[WorkflowTriggerNodeConfig]
    edges: List[Dict[str, Any]] = []


class WorkflowTriggerResponse(BaseModel):
    """Workflow trigger execution response."""
    success: bool
    instance_id: str
    project_id: str
    message: Optional[str] = None


# ============ 鑺傜偣鍚姩鎿嶄綔妯″紡 ============

class NodeStartRequest(BaseModel):
    """NodeStartRequest model."""
    project_id: str
    instance_id: str
    node_type: str  # app/job
    k8s_resource_name: Optional[str] = None
    job_config: Optional[Dict[str, Any]] = None  # JOB鑺傜偣涓撶敤


class NodeStartResponse(BaseModel):
    """NodeStartResponse model."""
    success: bool
    node_id: str
    status: str
    message: Optional[str] = None
    k8s_resource_name: Optional[str] = None
    error: Optional[str] = None

