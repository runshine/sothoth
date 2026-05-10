from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ExecutorMode = Literal["mock", "codex_cli", "opencode_cli"]


class HealthResponse(BaseModel):
    status: str
    service: str


class ReadyResponse(BaseModel):
    status: str
    service: str
    ready: bool
    checks: dict[str, bool]


class CapabilityResponse(BaseModel):
    service: str
    runtime_mode: str
    pipeline_modes: list[str]
    executor_modes: list[ExecutorMode]
    default_executor_mode: ExecutorMode | None
    input_kinds: list[str]
    allow_custom_project_path: bool
    show_scan_strategy: bool
    supports_sessions: bool
    supports_sse: bool
    supports_poc: bool
    poc_runtime_available: bool
    default_workspace_id: str | None
    default_pipeline_mode: str | None
    artifact_kinds: list[str]
    max_parallel_tasks: int


class RuntimeConfigResponse(BaseModel):
    max_parallel_tasks: int
    default_max_parallel_tasks: int
    active_attempts: int
    updated_at: str | None = None
    updated_by: str | None = None


class RuntimeConfigUpdateRequest(BaseModel):
    max_parallel_tasks: int = Field(ge=1, le=32)


class WorkspaceSummaryResponse(BaseModel):
    workspace_id: str
    display_name: str
    allow_custom_project_path: bool
    supports_poc: bool
    default_pipeline_mode: str
    is_default: bool


class WorkspaceTreeItemResponse(BaseModel):
    name: str
    path: str
    kind: Literal["file", "directory"]


class WorkspaceTreeResponse(BaseModel):
    workspace_id: str
    path: str
    items: list[WorkspaceTreeItemResponse]


class InputRef(BaseModel):
    kind: Literal["preset_project", "custom_project", "existing_audit_report"]
    project_path: str | None = None
    report_path: str | None = None


class ValidateInputRequest(BaseModel):
    workspace_id: str
    input_ref: InputRef


class ValidateInputResponse(BaseModel):
    valid: bool
    normalized_input_ref: InputRef
    resolved_kind: Literal["directory", "file"]
    message: str


class PresetProjectResponse(BaseModel):
    project_key: str
    project_path: str
    display_name: str
    source: str
    has_idl: bool
    has_on_remote_request_cpp: bool
    has_existing_audit_report: bool
    has_existing_poc_report: bool
    last_scanned_at: str


class PagedPresetProjectsResponse(BaseModel):
    items: list[PresetProjectResponse]
    total: int
    page: int
    per_page: int


class RefreshCatalogRequest(BaseModel):
    source: Literal["entries_file", "bundle_scan"] = "bundle_scan"
    write_entries_file: bool = False


class CatalogRefreshJobResponse(BaseModel):
    refresh_job_id: str
    workspace_id: str
    source: str
    status: str
    requested_by: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    discovered_count: int | None = None
    error_message: str | None = None
    message: str | None = None


class TaskCreateRequest(BaseModel):
    project_id: str | None = None
    title: str
    workspace_id: str
    pipeline_mode: Literal["audit_then_poc", "audit_only", "poc_only"] = "audit_then_poc"
    input_ref: InputRef
    executor_mode: ExecutorMode | None = None
    model: str | None = None
    notes: str | None = None
    idempotency_key: str | None = None


class TaskRetryRequest(BaseModel):
    retry_scope: Literal["task", "from_stage"] = "task"
    stage: Literal["audit", "poc"] | None = None


class TaskSummaryResponse(BaseModel):
    task_id: str
    project_id: str | None = None
    workspace_id: str
    title: str
    pipeline_mode: str
    status: str
    current_stage: str | None = None
    input_ref: InputRef
    latest_attempt_id: str | None = None
    created_by: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    message: str | None = None


class AttemptWorkerResponse(BaseModel):
    worker_id: str | None = None
    claimed_at: str | None = None
    heartbeat_at: str | None = None
    lease_expires_at: str | None = None


class StageRunResponse(BaseModel):
    stage_name: str
    status: str
    attempt_no: int
    started_at: str | None = None
    finished_at: str | None = None
    return_code: int | None = None
    log_artifact_id: str | None = None
    message: str | None = None


class AttemptDetailResponse(BaseModel):
    attempt_id: str
    task_id: str
    attempt_no: int
    status: str
    worker: AttemptWorkerResponse
    effective_config: dict[str, Any] = Field(default_factory=dict)
    stage_runs: list[StageRunResponse] = Field(default_factory=list)
    message: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None


class TaskDetailResponse(TaskSummaryResponse):
    attempt_count: int
    latest_attempt: AttemptDetailResponse | None = None


class PagedTaskResponse(BaseModel):
    items: list[TaskSummaryResponse]
    total: int
    page: int
    per_page: int


class EventResponse(BaseModel):
    event_seq: int
    event_id: str
    task_id: str
    attempt_id: str | None = None
    stage_name: str | None = None
    event_type: str
    level: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class EventPageResponse(BaseModel):
    items: list[EventResponse]
    next_cursor: int | None = None


class ArtifactResponse(BaseModel):
    artifact_id: str
    task_id: str
    attempt_id: str
    stage_name: str | None = None
    artifact_kind: str
    display_name: str
    relative_path: str
    content_type: str
    size: int
    sha256: str | None = None
    preview_url: str
    download_url: str
    created_at: str


class ArtifactListResponse(BaseModel):
    task_id: str
    attempt_id: str
    items: list[ArtifactResponse]


class ArtifactContentResponse(BaseModel):
    artifact_id: str
    content: str
    truncated: bool
    content_type: str


class StageLogResponse(BaseModel):
    task_id: str
    attempt_id: str
    stage_name: str
    content: str
    next_cursor: int


class SuccessResponse(BaseModel):
    success: bool
    task_id: str | None = None
    status: str | None = None
    message: str
