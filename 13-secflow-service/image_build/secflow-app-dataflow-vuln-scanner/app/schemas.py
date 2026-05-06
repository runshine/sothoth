from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from app.models.contracts import TaskItem


class ProfileConfigPayload(BaseModel):
    model: str = Field(..., min_length=1)
    thinking: str = Field(default="high", min_length=1)
    review_profile: str = Field(default="balanced", min_length=1)
    max_review_cycles: int = Field(default=6, ge=1)
    worker_timeout: int = Field(default=3600, ge=1)
    advisor_timeout: int = Field(default=3600, ge=1)
    result_review_concurrency: int = Field(default=3, ge=1)
    runtime_overrides: Dict[str, Any] = Field(default_factory=dict)


class ScanProfileCreateRequest(BaseModel):
    project_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = None
    template_kind: str = Field(default="vuln_scan_default", min_length=1)
    config_payload: ProfileConfigPayload
    is_default: bool = False
    enabled: bool = True
    max_concurrency: int = Field(default=1, ge=1)
    default_priority: int = 100
    max_retry_count: int = Field(default=3, ge=0)
    execution_timeout_seconds: int = Field(default=7200, ge=1)


class ScanProfileUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    template_kind: Optional[str] = Field(default=None, min_length=1)
    config_payload: Optional[ProfileConfigPayload] = None
    is_default: Optional[bool] = None
    enabled: Optional[bool] = None
    max_concurrency: Optional[int] = Field(default=None, ge=1)
    default_priority: Optional[int] = None
    max_retry_count: Optional[int] = Field(default=None, ge=0)
    execution_timeout_seconds: Optional[int] = Field(default=None, ge=1)


class ScanProfileResponse(BaseModel):
    profile_id: str
    project_id: str
    name: str
    description: Optional[str]
    template_kind: str
    config_payload: Dict[str, Any]
    compiled_config: Dict[str, Any]
    is_default: bool
    enabled: bool
    max_concurrency: int
    default_priority: int
    max_retry_count: int
    execution_timeout_seconds: int
    created_by: str
    updated_by: str
    version: int
    created_at: datetime
    updated_at: datetime


class ScanProfileVersionResponse(BaseModel):
    version_id: str
    profile_id: str
    version: int
    config_payload: Dict[str, Any]
    compiled_config: Dict[str, Any]
    created_by: str
    created_at: datetime


class ArtifactRef(BaseModel):
    storage_key: str = Field(..., min_length=1)
    relative_path: Optional[str] = None
    filename: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DataflowInputRef(BaseModel):
    source: str = Field(default="project_filesystem", min_length=1)
    path: Optional[str] = None
    storage_key: Optional[str] = None
    relative_path: Optional[str] = None
    filename: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanTaskCreateRequest(BaseModel):
    project_id: str = Field(..., min_length=1)
    profile_id: Optional[str] = None
    title: str = Field(..., min_length=1)
    task_markdown: Optional[str] = Field(default=None, min_length=1)
    workspace_dir: Optional[DataflowInputRef] = None
    data_flow: Optional[DataflowInputRef] = None
    source_dir: Optional[DataflowInputRef] = None
    output_dir: Optional[DataflowInputRef] = None
    model: Optional[str] = Field(default=None, min_length=1)
    provider: Optional[str] = None
    thinking: Optional[str] = Field(default=None, min_length=1)
    review_profile: Optional[str] = Field(default=None, min_length=1)
    max_review_cycles: Optional[int] = Field(default=None, ge=1)
    worker_timeout: Optional[int] = Field(default=None, ge=1)
    advisor_timeout: Optional[int] = Field(default=None, ge=1)
    result_review_concurrency: Optional[int] = Field(default=None, ge=1)
    scan_options: Dict[str, Any] = Field(default_factory=dict)
    artifact_refs: List[ArtifactRef] = Field(default_factory=list)
    priority: Optional[int] = None
    runtime_overrides: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_task_input(self) -> "ScanTaskCreateRequest":
        if bool(self.workspace_dir) != bool(self.output_dir):
            raise ValueError("workspace_dir and output_dir must be provided together")
        if self.task_markdown:
            return self
        if self.data_flow and self.source_dir:
            return self
        raise ValueError("task_markdown or both data_flow and source_dir must be provided")


class ScanTaskPriorityUpdateRequest(BaseModel):
    priority: int


class ScanTaskResponse(BaseModel):
    task_id: str
    project_id: str
    profile_id: str
    profile_version: int
    status: str
    latest_attempt_no: int
    retry_count: int
    max_retry_count: int
    priority: int
    created_by: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    message: Optional[str]
    latest_execution_id: Optional[str]


class ScanTaskAttemptResponse(BaseModel):
    execution_id: str
    task_id: str
    attempt_no: int
    status: str
    history_run_id: Optional[str] = None
    owner_pod_id: Optional[str]
    lease_expires_at: Optional[datetime]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    recovery_reason: Optional[str]
    message: Optional[str]
    workspace_root: Optional[str]
    output_manifest_path: Optional[str]
    output_task_count: int
    created_at: datetime
    updated_at: datetime


class ScanTaskEventResponse(BaseModel):
    event_id: str
    execution_id: str
    attempt_no: int
    event_type: str
    stage_id: Optional[str]
    round_no: Optional[int]
    level: str
    message: str
    payload_json: Optional[Dict[str, Any]]
    created_at: datetime


class ScanTaskArtifactFileResponse(BaseModel):
    path: str
    size: int


class ScanTaskArtifactsResponse(BaseModel):
    task_id: str
    execution_id: Optional[str]
    workspace_root: Optional[str]
    output_manifest_path: Optional[str]
    files: List[ScanTaskArtifactFileResponse] = Field(default_factory=list)


class ScanTaskDetailResponse(ScanTaskResponse):
    title: str
    task_markdown: str
    artifact_refs: List[ArtifactRef] = Field(default_factory=list)
    runtime_overrides: Dict[str, Any] = Field(default_factory=dict)
    task_metadata: Dict[str, Any] = Field(default_factory=dict)
    attempts: List[ScanTaskAttemptResponse] = Field(default_factory=list)


class ProjectEffectiveConfigResponse(BaseModel):
    project_id: str
    default_profile_id: Optional[str]
    effective_config: Dict[str, Any]


class ServiceEffectiveConfigResponse(BaseModel):
    service_name: str
    api_prefix: str
    config: Dict[str, Any]


class WorkflowDefinitionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = None
    project_id: str
    definition_json: Dict[str, Any]
    trigger_type: str = "manual"
    trigger_enabled: bool = False
    is_active: bool = False
    enabled: bool = True
    max_concurrency: int = Field(default=1, ge=1)
    priority_default: int = 100
    workspace_base_dir: Optional[str] = None
    execution_timeout_seconds: int = Field(default=7200, ge=1)


class WorkflowDefinitionUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    definition_json: Optional[Dict[str, Any]] = None
    trigger_type: Optional[str] = None
    trigger_enabled: Optional[bool] = None
    is_active: Optional[bool] = None
    enabled: Optional[bool] = None
    max_concurrency: Optional[int] = Field(default=None, ge=1)
    priority_default: Optional[int] = None
    workspace_base_dir: Optional[str] = None
    execution_timeout_seconds: Optional[int] = Field(default=None, ge=1)


class WorkflowDefinitionResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    project_id: str
    root_workflow_id: str
    trigger_type: str
    trigger_enabled: bool
    is_active: bool
    enabled: bool
    max_concurrency: int
    priority_default: int
    workspace_base_dir: Optional[str]
    execution_timeout_seconds: int
    entry_input_task_type: str
    final_output_task_type: str
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class WorkflowDefinitionVersionResponse(BaseModel):
    id: str
    workflow_definition_id: str
    version_no: int
    created_by: str
    created_at: datetime
    definition_json: Dict[str, Any]


class TriggerTaskCreate(BaseModel):
    input_tasks: List["TriggerTaskInputTask"]
    priority: Optional[int] = None


class TriggerTaskInputTask(BaseModel):
    task_id: Optional[str] = None
    task_type: Optional[str] = None
    title: str = Field(..., min_length=1)
    task_markdown: Optional[str] = None
    task_md_path: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    upstream_refs: List[str] = Field(default_factory=list)


class TriggerTaskInputPreview(TaskItem):
    task_input_dir: Optional[str] = None


class TriggerTaskResponse(BaseModel):
    id: str
    workflow_definition_id: str
    project_id: str
    trigger_type: str
    priority: int
    status: str
    submitted_by: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    message: Optional[str]
    created_at: datetime
    updated_at: datetime


class WorkflowExecutionResponse(BaseModel):
    id: str
    trigger_task_id: str
    workflow_definition_id: str
    project_id: str
    status: str
    workspace_root: Optional[str]
    output_manifest_path: Optional[str]
    output_task_count: int
    current_stage_id: Optional[str]
    owner_pod_id: Optional[str]
    lease_expires_at: Optional[datetime]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    message: Optional[str]
    created_at: datetime
    updated_at: datetime


class WorkflowExecutionEventResponse(BaseModel):
    id: str
    execution_id: str
    event_type: str
    stage_id: Optional[str]
    round_no: Optional[int]
    level: str
    message: str
    payload_json: Optional[Dict[str, Any]]
    created_at: datetime


class SchedulerWorkerResponse(BaseModel):
    pod_id: str
    host_name: str
    capacity: int
    running_count: int
    last_heartbeat_at: datetime
    status: str
    metadata_json: Optional[Dict[str, Any]]


class SuccessResponse(BaseModel):
    success: bool = True
    message: str


class HealthResponse(BaseModel):
    status: str
    pod_id: str
    database: str
    scheduler: str


class HistoryRunSummaryResponse(BaseModel):
    history_run_id: str
    project_id: str
    source_type: str
    source_key: str
    linked_task_id: Optional[str] = None
    linked_execution_id: Optional[str] = None
    profile_id: Optional[str] = None
    name: str
    path: str
    root_path: str
    status: str
    start_time: str = ""
    start_epoch: int = 0
    duration_seconds: int = 0
    last_activity: str = ""
    model: str = ""
    provider: str = ""
    thinking: str = ""
    max_cycles: int = 0
    cycles_used: int = 0
    result_count: int = 0
    passed_count: int = 0
    failed_count: int = 0
    workflow_mode: str = ""
    updated_at: Optional[str] = None


class HistoryRunFileResponse(BaseModel):
    category: str
    path: str
    name: str
    size: int
    mtime: float
    type: str


class HistoryRunSessionResponse(BaseModel):
    session_id: str
    format: str
    worker_id: str = ""
    jsonl_path: str = ""
    size: int = 0
    mtime: float = 0
    calls: List[Dict[str, Any]] = Field(default_factory=list)


class HistoryRunDetailResponse(HistoryRunSummaryResponse):
    config: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    cycles: List[Dict[str, Any]] = Field(default_factory=list)
    results: List[Dict[str, Any]] = Field(default_factory=list)
    removed_results: List[Dict[str, Any]] = Field(default_factory=list)
    manifests: Dict[str, Any] = Field(default_factory=dict)
    latest_issues: List[Dict[str, Any]] = Field(default_factory=list)
    atomic_work_path: str = ""
    files: List[HistoryRunFileResponse] = Field(default_factory=list)
    sessions: List[HistoryRunSessionResponse] = Field(default_factory=list)
    run_log: str = ""
    raw: Dict[str, Any] = Field(default_factory=dict)


class HistoryRunCycleResponse(BaseModel):
    cycle: int
    global_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    result_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    summary_snapshot: str = ""
    metrics: Dict[str, Any] = Field(default_factory=dict)


class HistoryRunFileContentResponse(BaseModel):
    path: str
    type: str
    content: str


class HistoryRunLogResponse(BaseModel):
    content: str


class HistoryRunResolveResponse(BaseModel):
    history_run_id: str
    project_id: str
    run_name: str
    root_path: str
    source_type: str
    linked_task_id: Optional[str] = None
    linked_execution_id: Optional[str] = None
