from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from app.models.contracts import TaskItem


class ProfileConfigPayload(BaseModel):
    model: str = Field(..., min_length=1)
    review_profile: str = Field(default="balanced", min_length=1)
    max_review_cycles: int = Field(default=6, ge=1)
    agent_run_timeout_seconds: int = Field(default=3600, ge=-1, description="单次智能体输入最大运行时长（秒），-1=不限制")
    agent_timeout_retry_enabled: bool = Field(default=True)
    agent_timeout_max_retries: int = Field(default=3, ge=0)
    worker_timeout: int = Field(default=3600, ge=1, description="Deprecated compatibility field; RPC prompt timeout is controlled by Pi/provider native timeout settings.")
    advisor_timeout: int = Field(default=3600, ge=1, description="Deprecated compatibility field; RPC prompt timeout is controlled by Pi/provider native timeout settings.")
    timeout_max_retries: int = Field(default=3, ge=1)
    timeout_retry_interval_seconds: int = Field(default=30, ge=0)
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
    default_priority: int = 100
    max_retry_count: int = Field(default=0, ge=0)
    execution_timeout_seconds: int = Field(default=0, ge=0, description="Deprecated compatibility field; service-managed run_vuln_scan.py process timeout is disabled.")


class ScanProfileUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    template_kind: Optional[str] = Field(default=None, min_length=1)
    config_payload: Optional[ProfileConfigPayload] = None
    is_default: Optional[bool] = None
    enabled: Optional[bool] = None
    default_priority: Optional[int] = None
    max_retry_count: Optional[int] = Field(default=None, ge=0)
    execution_timeout_seconds: Optional[int] = Field(default=None, ge=0, description="Deprecated compatibility field; service-managed run_vuln_scan.py process timeout is disabled.")


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


class DataflowAgentStateRootPayload(BaseModel):
    root_dir: DataflowInputRef


class DataflowAgentStateDirResponse(BaseModel):
    agent_id: str
    root_dir: str
    skills_dir: str
    memory_dir: str
    source: Literal["shared_default", "task_override"] = "shared_default"


class CreateEvolutionTaskRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=128)
    profile_id: Optional[str] = None
    priority: Optional[int] = None
    agent_state_roots: Dict[str, DataflowAgentStateRootPayload] = Field(default_factory=dict)
    model: Optional[str] = Field(default=None, min_length=1)
    provider: Optional[str] = None
    review_profile: Optional[str] = Field(default=None, min_length=1)
    max_review_cycles: Optional[int] = Field(default=None, ge=1)
    agent_run_timeout_seconds: Optional[int] = Field(default=None, ge=-1)
    agent_timeout_retry_enabled: Optional[bool] = None
    agent_timeout_max_retries: Optional[int] = Field(default=None, ge=0)
    timeout_max_retries: Optional[int] = Field(default=None, ge=1)
    timeout_retry_interval_seconds: Optional[int] = Field(default=None, ge=0)
    result_review_concurrency: Optional[int] = Field(default=None, ge=1)
    scan_options: Dict[str, Any] = Field(default_factory=dict)
    runtime_overrides: Dict[str, Any] = Field(default_factory=dict)
    auto_report_vulnerabilities: Optional[bool] = None
    evolution_task_id: Optional[str] = None
    evolution_round: Optional[int] = Field(default=None, ge=1)
    evolution_source_task_id: Optional[str] = None
    evolution_source_execution_id: Optional[str] = None


class ReplayReadyResponse(BaseModel):
    task_id: str
    project_id: str
    task_purpose: Literal["normal", "evolution"]
    replay_ready: bool
    reason: Optional[str] = None
    latest_execution_id: Optional[str] = None
    latest_run_id: Optional[str] = None
    agent_state_dirs: Dict[str, DataflowAgentStateDirResponse] = Field(default_factory=dict)


class ScanTaskCreateRequest(BaseModel):
    project_id: str = Field(..., min_length=1)
    profile_id: Optional[str] = None
    title: str = Field(default="", max_length=128)
    task_markdown: Optional[str] = Field(default=None, min_length=1)
    workspace_dir: Optional[DataflowInputRef] = None
    data_flow: Optional[DataflowInputRef] = None
    source_dir: Optional[DataflowInputRef] = None
    output_dir: Optional[DataflowInputRef] = None
    model: Optional[str] = Field(default=None, min_length=1)
    provider: Optional[str] = None
    review_profile: Optional[str] = Field(default=None, min_length=1)
    max_review_cycles: Optional[int] = Field(default=None, ge=1)
    agent_run_timeout_seconds: Optional[int] = Field(default=None, ge=-1)
    agent_timeout_retry_enabled: Optional[bool] = None
    agent_timeout_max_retries: Optional[int] = Field(default=None, ge=0)
    worker_timeout: Optional[int] = Field(default=None, ge=1, description="Deprecated compatibility field; RPC prompt timeout is controlled by Pi/provider native timeout settings.")
    advisor_timeout: Optional[int] = Field(default=None, ge=1, description="Deprecated compatibility field; RPC prompt timeout is controlled by Pi/provider native timeout settings.")
    timeout_max_retries: Optional[int] = Field(default=None, ge=1)
    timeout_retry_interval_seconds: Optional[int] = Field(default=None, ge=0)
    result_review_concurrency: Optional[int] = Field(default=None, ge=1)
    scan_options: Dict[str, Any] = Field(default_factory=dict)
    artifact_refs: List[ArtifactRef] = Field(default_factory=list)
    priority: Optional[int] = None
    runtime_overrides: Dict[str, Any] = Field(default_factory=dict)
    task_purpose: Literal["normal", "evolution"] = "normal"
    agent_state_roots: Dict[str, DataflowAgentStateRootPayload] = Field(default_factory=dict)
    task_origin_type: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    create_dedupe_key: Optional[str] = None
    auto_report_vulnerabilities: bool = True

    @model_validator(mode="after")
    def validate_task_input(self) -> "ScanTaskCreateRequest":
        if self.output_dir and not self.workspace_dir:
            raise ValueError("workspace_dir is required when output_dir is provided")
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
    task_purpose: Literal["normal", "evolution"] = "normal"
    agent_state_dirs: Dict[str, DataflowAgentStateDirResponse] = Field(default_factory=dict)
    derived_from_task_id: Optional[str] = None
    derived_from_execution_id: Optional[str] = None
    derived_from_run_id: Optional[str] = None
    derivation_kind: Optional[Literal["evolution_replay"]] = None
    task_origin_type: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    origin_label: Optional[str] = None
    parent_task_display: Optional[str] = None
    profile_id: str
    profile_version: int
    title: str = ""
    status: str
    control_state: str = "none"
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
    owner_pod_id: Optional[str] = None
    dispatch_status: Optional[str] = None
    slot_binding_state: Optional[str] = None
    slot_binding_reason: Optional[str] = None
    dispatch_backoff_until: Optional[datetime] = None
    dispatch_backoff_reason: Optional[str] = None
    resolved_status_source: Optional[str] = None
    run_name: Optional[str] = None
    runs_root: Optional[str] = None
    run_path: Optional[str] = None
    run: Dict[str, Any] = Field(default_factory=dict)
    latest_run: Dict[str, Any] = Field(default_factory=dict)
    auto_report_vulnerabilities: bool = True
    vuln_report_status: Dict[str, Any] = Field(default_factory=dict)
    abnormal_reason_title: Optional[str] = None
    abnormal_reason_code: Optional[str] = None
    abnormal_reason_category: Optional[str] = None
    abnormal_reason: Optional[Dict[str, Any]] = None


class ScanTaskListItemResponse(BaseModel):
    task_id: str
    project_id: str
    task_purpose: Literal["normal", "evolution"] = "normal"
    task_origin_type: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    origin_mode: Literal["manual", "binary", "source"] = "manual"
    origin_label: Optional[str] = None
    parent_task_display: Optional[str] = None
    profile_id: str
    profile_version: int
    title: str = ""
    status: str
    control_state: str = "none"
    latest_attempt_no: int
    priority: int
    created_by: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    updated_at: datetime
    message: Optional[str]
    latest_execution_id: Optional[str]
    owner_pod_id: Optional[str] = None
    dispatch_status: Optional[str] = None
    slot_binding_state: Optional[str] = None
    slot_binding_reason: Optional[str] = None
    dispatch_backoff_until: Optional[datetime] = None
    dispatch_backoff_reason: Optional[str] = None
    resolved_status_source: Optional[str] = None
    latest_run_id: Optional[str] = None
    latest_run_status: Optional[str] = None
    run_name: Optional[str] = None
    runs_root: Optional[str] = None
    run_path: Optional[str] = None
    run: Dict[str, Any] = Field(default_factory=dict)
    latest_run: Dict[str, Any] = Field(default_factory=dict)
    auto_report_vulnerabilities: bool = True
    vuln_report_status: Dict[str, Any] = Field(default_factory=dict)
    abnormal_reason_title: Optional[str] = None
    abnormal_reason_code: Optional[str] = None
    abnormal_reason_category: Optional[str] = None


class ScanTaskListResponse(BaseModel):
    items: List[ScanTaskListItemResponse] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 50
    page_size: int = 50
    projection_backfill_pending: bool = False
    projection_backfill_enqueued: bool = False
    projection_total_missing: int = 0


class ScanTaskStatsResponse(BaseModel):
    total: int = 0
    pending: int = 0
    running: int = 0
    succeeded: int = 0
    failed: int = 0
    cancelled: int = 0
    projection_backfill_pending: bool = False

class ScanTaskProjectionRepairResponse(BaseModel):
    status: str = "success"
    task_id: Optional[str] = None
    project_id: Optional[str] = None
    repaired_count: int = 0
    message: str


class ActiveTaskReconcileRequest(BaseModel):
    project_id: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    statuses: List[str] = Field(default_factory=list)
    dry_run: bool = False


class ActiveTaskReconcileResponse(BaseModel):
    status: str = "success"
    scanned_count: int = 0
    reconciled_count: int = 0
    requeued_count: int = 0
    terminalized_count: int = 0
    projection_refreshed_count: int = 0
    sample_task_ids: List[str] = Field(default_factory=list)
    dry_run: bool = False
    message: str = ""


class ScanTaskAttemptResponse(BaseModel):
    execution_id: str
    task_id: str
    attempt_no: int
    status: str
    run_id: Optional[str] = None
    owner_pod_id: Optional[str]
    worker_url: Optional[str] = None
    worker_job_id: Optional[str] = None
    dispatch_status: Optional[str] = None
    slot_binding_state: Optional[str] = None
    slot_binding_reason: Optional[str] = None
    dispatch_backoff_until: Optional[datetime] = None
    dispatch_backoff_reason: Optional[str] = None
    resolved_status_source: Optional[str] = None
    dispatch_error: Optional[str] = None
    process_pid: Optional[int] = None
    process_host: Optional[str] = None
    process_status: Optional[str] = None
    process_started_at: Optional[datetime] = None
    process_finished_at: Optional[datetime] = None
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    recovery_reason: Optional[str]
    message: Optional[str]
    workspace_root: Optional[str]
    output_manifest_path: Optional[str]
    output_task_count: int
    created_at: datetime
    updated_at: datetime


class ScanTaskDetailResponse(ScanTaskResponse):
    title: str
    task_markdown: str
    artifact_refs: List[ArtifactRef] = Field(default_factory=list)
    runtime_overrides: Dict[str, Any] = Field(default_factory=dict)
    task_metadata: Dict[str, Any] = Field(default_factory=dict)
    input_summary: Dict[str, Any] = Field(default_factory=dict)
    output_summary: Dict[str, Any] = Field(default_factory=dict)
    effective_config_summary: Dict[str, Any] = Field(default_factory=dict)
    task_root: Optional[str] = None
    run_root: Optional[str] = None
    workspace_root: Optional[str] = None
    attempts: List[ScanTaskAttemptResponse] = Field(default_factory=list)
    abnormal_reason_history: List[Dict[str, Any]] = Field(default_factory=list)


class DataflowTaskTimelineEvent(BaseModel):
    id: str
    task_id: str
    project_id: str
    execution_id: str
    attempt_no: Optional[int] = None
    stage_name: Optional[str] = None
    stage_key: Optional[str] = None
    event_type: str
    level: str = "info"
    message: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class DataflowTaskTimelineResponse(BaseModel):
    task_id: str
    items: List[DataflowTaskTimelineEvent] = Field(default_factory=list)


class DataflowTaskTimelineActionResponse(BaseModel):
    status: str = "success"
    task_id: str
    message: str
    deleted_event_count: int = 0


class ProjectEffectiveConfigResponse(BaseModel):
    project_id: str
    default_profile_id: Optional[str]
    effective_config: Dict[str, Any]


class ServiceEffectiveConfigResponse(BaseModel):
    service_name: str
    api_prefix: str
    config: Dict[str, Any]


class ServiceConfigSaveRequest(BaseModel):
    config: Dict[str, Any]


class ServiceConfigResponse(BaseModel):
    service_name: str
    api_prefix: str
    config: Dict[str, Any]


class ProjectFilesystemBreadcrumbItemResponse(BaseModel):
    node_type: str
    name: str
    path: str


class ProjectFilesystemEntryResponse(BaseModel):
    node_type: str
    name: str
    path: str
    content_type: Optional[str] = None
    size: Optional[int] = None
    updated_at: Optional[str] = None
    has_children: bool
    special_badge: Optional[str] = None


class ProjectFilesystemRootResponse(BaseModel):
    project_id: str
    root_name: str
    total: int
    items: List[ProjectFilesystemEntryResponse] = Field(default_factory=list)


class ProjectFilesystemChildrenResponse(BaseModel):
    project_id: str
    current_path: str
    current_name: str
    breadcrumbs: List[ProjectFilesystemBreadcrumbItemResponse] = Field(default_factory=list)
    directories: List[ProjectFilesystemEntryResponse] = Field(default_factory=list)
    files: List[ProjectFilesystemEntryResponse] = Field(default_factory=list)


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


class SchedulerWorkerResponse(BaseModel):
    pod_id: str
    host_name: str
    capacity: int
    running_count: int
    last_heartbeat_at: datetime
    status: str
    metadata_json: Optional[Dict[str, Any]]


class WorkerActiveJobResponse(BaseModel):
    execution_id: str
    task_id: Optional[str] = None
    task_title: Optional[str] = None
    status: str
    worker_job_id: str
    worker_url: Optional[str] = None
    dispatch_status: Optional[str] = None
    started_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    run_name: Optional[str] = None
    run_path: Optional[str] = None
    project_id: Optional[str] = None
    mapped: bool = False
    mapping_reason: str = "orphan_job"


class WorkerClusterWorkerResponse(BaseModel):
    worker_id: str
    host_name: str
    healthy: bool
    max_concurrent_jobs: int
    running_jobs: int
    used_slots: int = 0
    available_slots: int
    schedulable_slots: int = 0
    source: str = "scheduler_worker"
    last_heartbeat_at: Optional[datetime] = None
    error: Optional[str] = None
    active_jobs: List[WorkerActiveJobResponse] = Field(default_factory=list)


class WorkerClusterCapacityResponse(BaseModel):
    worker_count: int
    healthy_workers: int
    stale_workers: int
    total_capacity: int
    running_jobs: int
    used_slots: int = 0
    queued_jobs: int
    available_slots: int
    schedulable_slots: int = 0
    updated_at: datetime
    workers: List[WorkerClusterWorkerResponse] = Field(default_factory=list)


class WorkerClusterCapacitySummaryResponse(WorkerClusterCapacityResponse):
    detail_mode: Literal["summary", "detail"] = "summary"


class SuccessResponse(BaseModel):
    success: bool = True
    message: str


class RunRetryRequest(BaseModel):
    extra_cycles: int = Field(default=5, ge=1)
    model: Optional[str] = Field(default=None, min_length=1)
    provider: Optional[str] = None
    clean_workspace: bool = False


class RunResumePreviewResponse(BaseModel):
    success: bool = True
    run_id: str
    project_id: str
    can_retry: bool = True
    reason: str = ""
    process_state: Dict[str, Any] = Field(default_factory=dict)
    resume_preflight: Dict[str, Any] = Field(default_factory=dict)


class RunVulnReportRequest(BaseModel):
    result_files: List[str] = Field(default_factory=list)


class RunVulnReportResponse(BaseModel):
    status: str
    enabled: bool = True
    total: int = 0
    reported: int = 0
    failed: int = 0
    pending: int = 0
    items: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None


class RunMutationResponse(BaseModel):
    success: bool = True
    run_id: str
    project_id: str
    status: str
    control_state: str = "none"
    message: str
    linked_task_id: Optional[str] = None
    linked_execution_id: Optional[str] = None
    process_pid: Optional[int] = None
    process_host: Optional[str] = None
    process_signal: Optional[str] = None
    resume_preflight: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    pod_id: str
    database: str
    scheduler: str
    scheduler_role: str = "standalone"
    worker_enabled: str = "true"
    service_id: Optional[str] = None
    service_name: Optional[str] = None
    build_version: Optional[str] = None


class RunSummaryResponse(BaseModel):
    run_id: str
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
    review_profile: str = ""
    max_cycles: int = 0
    cycles_used: int = 0
    result_count: int = 0
    passed_count: int = 0
    failed_count: int = 0
    workflow_mode: str = ""
    updated_at: Optional[str] = None
    process_state: Dict[str, Any] = Field(default_factory=dict)
    retry_command_display: Optional[str] = None
    linked_task_purpose: Optional[Literal["normal", "evolution"]] = None
    linked_task_agent_state_dirs: Dict[str, DataflowAgentStateDirResponse] = Field(default_factory=dict)


class RunFileResponse(BaseModel):
    category: str
    path: str
    name: str
    size: int
    mtime: float
    type: str


class RunSessionResponse(BaseModel):
    session_id: str
    format: str
    worker_id: str = ""
    jsonl_path: str = ""
    size: int = 0
    mtime: float = 0
    event_count: int = 0
    line_count: int = 0
    warnings: List[str] = Field(default_factory=list)
    display_name: str = ""
    stage_group: str = ""
    role_name: str = ""
    watch_project_path: str = ""
    model: str = ""
    raw_model: str = ""
    provider: str = ""
    thinking: str = ""
    calls: List[Dict[str, Any]] = Field(default_factory=list)


class RunOverviewResponse(RunSummaryResponse):
    config: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    cycles: List[Dict[str, Any]] = Field(default_factory=list)
    results: List[Dict[str, Any]] = Field(default_factory=list)
    removed_results: List[Dict[str, Any]] = Field(default_factory=list)
    manifests: Dict[str, Any] = Field(default_factory=dict)
    latest_issues: List[Dict[str, Any]] = Field(default_factory=list)
    atomic_work_path: str = ""
    command: List[str] = Field(default_factory=list)
    command_display: str = ""
    current_step: Dict[str, Any] = Field(default_factory=dict)
    step_history: List[Dict[str, Any]] = Field(default_factory=list)
    cycle_timing: Dict[str, Any] = Field(default_factory=dict)
    raw: Dict[str, Any] = Field(default_factory=dict)


class RunDetailResponse(RunOverviewResponse):
    files: List[RunFileResponse] = Field(default_factory=list)
    sessions: List[RunSessionResponse] = Field(default_factory=list)
    run_log: str = ""


class RunCycleResponse(BaseModel):
    cycle: int
    global_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    result_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    new_result_count: int = 0
    new_results: List[Dict[str, Any]] = Field(default_factory=list)
    summary_snapshot: str = ""
    metrics: Dict[str, Any] = Field(default_factory=dict)
    global_review_summary: Dict[str, Any] = Field(default_factory=dict)
    profile_gate: Dict[str, Any] = Field(default_factory=dict)


class RunFileContentResponse(BaseModel):
    path: str
    type: str
    content: str


class RunLogResponse(BaseModel):
    content: str


class RunResolveResponse(BaseModel):
    run_id: str
    project_id: str
    run_name: str
    root_path: str
    source_type: str
    linked_task_id: Optional[str] = None
    linked_execution_id: Optional[str] = None
