"""Pydantic request/response models for the PoC-gen-verify service."""
from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


TaskStatus = Literal["pending", "running", "succeeded", "failed", "timeout", "cancelled"]
EffortLevel = Literal["low", "medium", "high", "xhigh", "max"]


class PocTaskRequest(BaseModel):
    """Frontend → microservice payload. Unpacked into `poc` CLI args."""
    model_config = ConfigDict(extra="allow")

    project_id: str = Field(..., description="项目 ID (任务归属)")
    task_name: Optional[str] = Field(None, description="任务名; 为空则自动生成")
    task_description: Optional[str] = None
    entry_function: Optional[str] = Field(None, description="数据流入口函数 (poc -e); 省略则 Stage0 从漏洞报告提取")
    vuln_report_path: str = Field(..., description="漏洞报告路径 (poc -r)")
    binary_dir: str = Field(..., description="全二进制文件目录 (poc -b)")
    output_dir: Optional[str] = Field(None, description="输出目录 (poc -o); 为空则服务生成时间戳目录")
    model: Optional[str] = Field(None, description="模型覆盖 (默认 glm-5.2)")
    effort: Optional[EffortLevel] = Field(None, description="effort level (传给 claude --effort)")
    session_name: Optional[str] = Field(None, description="会话名 (传给 claude -n)")
    session_id: Optional[str] = Field(None, description="会话 UUID (传给 claude --session-id)")
    session_dir: Optional[str] = Field(None, description="会话存储目录 (传给 poc --session-dir)")
    timeout: Optional[int] = None
    created_by: Optional[str] = None


class PocTaskCreateResponse(BaseModel):
    task_id: str
    status: TaskStatus
    output_dir: str
    log_path: Optional[str] = None


class PocTaskStatus(BaseModel):
    task_id: str
    project_id: str
    vuln_id: Optional[str] = None
    task_name: str
    task_description: Optional[str] = None
    entry_function: Optional[str] = None
    vuln_report_path: str
    binary_dir: str
    output_dir: str
    model: Optional[str] = None
    effort: Optional[str] = None
    session_name: Optional[str] = None
    session_id: Optional[str] = None
    session_dir: Optional[str] = None
    timeout: Optional[int] = None  # legacy field (unused — no timeout mechanism)
    cli_command: Optional[str] = None
    status: TaskStatus
    error: Optional[str] = None
    returncode: Optional[int] = None
    artifacts: List[str] = Field(default_factory=list)
    result_json: Optional[Dict[str, Any]] = None
    stages_json: Optional[Dict[str, Any]] = None
    # PoC outcome path (derived from Stage2 poc_report.md):
    # "a" = path A (vuln confirmed, PoC triggered successfully)
    # "b" = path B (false positive / unreachable proved)
    # None = Stage1 failed / no Stage2 report
    poc_path: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    execution_epoch: int = 0
    control_version: int = 0
    dispatch_status: Optional[str] = None
    celery_task_id: Optional[str] = None
    log_path: Optional[str] = None
    is_deleted: bool = False


class PocTaskListResponse(BaseModel):
    items: List[PocTaskStatus]
    total: int
    page: int
    per_page: int


class PocTaskStatsResponse(BaseModel):
    total: int = 0
    pending: int = 0
    running: int = 0
    succeeded: int = 0
    failed: int = 0
    timeout: int = 0  # legacy (unused — no timeout mechanism)
    cancelled: int = 0
    # PoC verdict breakdown (subset of succeeded/failed by poc_path)
    verified: int = 0       # poc_path=a (vuln confirmed)
    false_positive: int = 0  # poc_path=b (false positive / unreachable)


class PocTaskLogsResponse(BaseModel):
    task_id: str
    status: TaskStatus
    returncode: Optional[int] = None
    log_path: str
    log_tail: str


class PocTaskTimelineResponse(BaseModel):
    task_id: str
    events: List[Dict[str, Any]]


class PocArtifactsResponse(BaseModel):
    task_id: str
    output_dir: str
    artifacts: List[str]
    on_disk: List[str]


class PocArtifactContentResponse(BaseModel):
    task_id: str
    name: str
    content: str
    size: int


class PocSessionFile(BaseModel):
    name: str
    rel_path: str
    size: int
    mtime: float
    kind: str
    stage: str
    claude_cmd: str = ""
    session_id: str = ""
    jsonl: str = ""
    prompt_file: str = ""
    is_active: bool = False


class PocSessionListResponse(BaseModel):
    task_id: str
    output_dir: str
    sessions: List[PocSessionFile]


class PocSessionContentResponse(BaseModel):
    task_id: str
    rel_path: str
    name: str
    content: str
    size: int
    tail_lines: int


class ActionResponse(BaseModel):
    status: str = "ok"
    task_id: str
    message: str


# ─── Timeline management ─────────────────────────────────────────────────────

class TimelineClearResponse(BaseModel):
    status: str = "ok"
    task_id: str
    message: str
    deleted_event_count: int


class TimelineEventDeleteResponse(BaseModel):
    status: str = "ok"
    task_id: str
    message: str
    deleted_event_count: int


# ─── Feature flags / task config override ────────────────────────────────────

class FeatureFlagsRequest(BaseModel):
    """PATCH /tasks/{task_id}/feature-flags: merge into task_config_json.feature_flags."""
    feature_flags: Dict[str, bool]


# ─── Prompt templates ────────────────────────────────────────────────────────

class PromptTemplateCreateRequest(BaseModel):
    prompt_id: str
    name: str
    category: str = "general"
    description: Optional[str] = None
    content: str
    variables: List[str] = Field(default_factory=list)
    is_default: bool = False
    is_enabled: bool = True
    created_by: Optional[str] = None


class PromptTemplateUpdateRequest(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    content: Optional[str] = None
    variables: Optional[List[str]] = None
    is_default: Optional[bool] = None
    is_enabled: Optional[bool] = None
    updated_by: Optional[str] = None


class PromptTemplateResponse(BaseModel):
    id: int
    prompt_id: str
    name: str
    category: str
    description: Optional[str] = None
    content: str
    variables: List[str] = Field(default_factory=list)
    version: int
    is_default: bool
    is_enabled: bool
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PromptTemplateListResponse(BaseModel):
    items: List[PromptTemplateResponse]
    total: int


# ─── Service config ──────────────────────────────────────────────────────────

class ServiceConfigResponse(BaseModel):
    default_model: str = "glm-5.2"
    default_effort: str = "medium"
    available_models: List[Dict[str, str]] = Field(default_factory=list)
    available_efforts: List[str] = Field(default_factory=list)
    updated_at: Optional[str] = None


class ServiceConfigUpdateRequest(BaseModel):
    default_model: Optional[str] = None
    default_effort: Optional[str] = None


# ─── Worker cluster capacity ────────────────────────────────────────────────

class WorkerJobSnapshot(BaseModel):
    task_id: str
    task_name: str
    status: str
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    dispatch_status: Optional[str] = None
    execution_owner_id: Optional[str] = None
    execution_lease_until: Optional[str] = None
    execution_heartbeat_at: Optional[str] = None
    mapped: bool = True
    mapping_reason: str = "celery_active"


class WorkerSnapshot(BaseModel):
    worker_id: str
    host_name: str = ""
    pod_name: str = ""
    healthy: bool = True
    max_concurrent_jobs: int = 1
    running_jobs: int = 0
    available_slots: int = 0
    source: str = "celery"
    last_heartbeat_at: Optional[str] = None
    running_job_snapshots: List[WorkerJobSnapshot] = Field(default_factory=list)


class WorkerClusterCapacityResponse(BaseModel):
    total_workers: int = 0
    healthy_workers: int = 0
    total_capacity: int = 0
    total_running: int = 0
    total_available: int = 0
    workers: List[WorkerSnapshot] = Field(default_factory=list)


# ─── Agent observability (process snapshot) ──────────────────────────────────

class AgentProcessSnapshot(BaseModel):
    pid: int
    name: str = ""
    cmd: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    status: str = ""
    create_time: Optional[str] = None


class AgentProcessKillResponse(BaseModel):
    status: str = "ok"
    killed: int = 0
    message: str = ""


# ─── PoC verification (structured result verification) ──────────────────────

class PocVerificationResult(BaseModel):
    task_id: str
    verified: bool = False
    poc_path: Optional[str] = None
    checks: List[Dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


# ─── Failure debug ───────────────────────────────────────────────────────────

class FailureDebugReportResponse(BaseModel):
    id: int
    task_id: str
    project_id: str
    task_name: str
    status: str
    error_kind: Optional[str] = None
    failing_stage: Optional[str] = None
    summary: Optional[str] = None
    report_path: Optional[str] = None
    report_json: Optional[Dict[str, Any]] = None
    debug_error: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class FailureDebugReportListResponse(BaseModel):
    items: List[FailureDebugReportResponse]
    total: int
    page: int
    per_page: int


class FailureDebugConfigResponse(BaseModel):
    model: str = "glm-5.2"
    available_models: List[Dict[str, str]] = Field(default_factory=list)
    updated_at: Optional[str] = None


class FailureDebugConfigUpdateRequest(BaseModel):
    model: str
