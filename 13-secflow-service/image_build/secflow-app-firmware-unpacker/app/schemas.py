"""Pydantic schemas for firmware unpacker API."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class UnpackRequest(BaseModel):
    firmware_path: str
    output_path: Optional[str] = None
    project_id: Optional[str] = None
    task_origin_type: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None


class TaskSubmitResponse(BaseModel):
    task_id: str
    status: str
    message: str
    input_path: Optional[str] = None
    output_path: Optional[str] = None
    run_path: Optional[str] = None


class ActionResponse(BaseModel):
    message: str
    task_id: Optional[str] = None
    new_task_id: Optional[str] = None
    deleted_count: Optional[int] = None
    skipped_ids: Optional[List[str]] = None


class BatchDeleteRequest(BaseModel):
    task_ids: List[str]


class ConfigUpdateRequest(BaseModel):
    value: str
    description: Optional[str] = None


class ConfigBatchUpdateItem(BaseModel):
    key: str
    value: str
    description: Optional[str] = None


class TaskResponse(BaseModel):
    id: str
    project_id: Optional[str]
    task_origin_type: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    origin_label: Optional[str] = None
    parent_task_display: Optional[str] = None
    firmware_path: str
    output_path: str
    status: str
    owner_id: Optional[str] = None
    current_stage: Optional[str] = None
    lease_expires_at: Optional[str] = None
    cancel_requested_at: Optional[str] = None
    last_progress_at: Optional[str] = None
    runner_pid: Optional[int] = None
    runner_started_at: Optional[str] = None
    runner_heartbeat_at: Optional[str] = None
    cancel_grace_deadline: Optional[str] = None
    cancel_force_deadline: Optional[str] = None
    result_status: Optional[str] = None
    result_message: Optional[str] = None
    rounds: Optional[int] = None
    error_message: Optional[str] = None
    matched_skill: Optional[str] = None
    matched_skill_version: Optional[int] = None
    matched_skill_score: Optional[int] = None
    fallback_to_llm: bool = False
    generated_skill_path: Optional[str] = None
    generated_skill_status: Optional[str] = None
    promotion_success_count: Optional[int] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    class Config:
        from_attributes = True


class TaskResourceContainerResponse(BaseModel):
    name: Optional[str] = None
    cpu_millicores: int
    memory_mib: int


class TaskResourceUsageResponse(BaseModel):
    task_id: str
    owner_id: Optional[str] = None
    available: bool
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    phase: Optional[str] = None
    timestamp: Optional[str] = None
    window: Optional[str] = None
    cpu_millicores: Optional[int] = None
    memory_mib: Optional[int] = None
    pod_cpu_limit_millicores: Optional[int] = None
    pod_memory_limit_mib: Optional[int] = None
    containers: List[TaskResourceContainerResponse] = []
    message: Optional[str] = None


class TaskProgressPhaseResponse(BaseModel):
    key: str
    label: str
    status: str
    detail: Optional[str] = None
    updated_at: Optional[str] = None
    current_round: Optional[int] = None
    total_rounds: Optional[int] = None


class TaskProgressResponse(BaseModel):
    task_id: str
    current_phase: Optional[str] = None
    summary: Optional[str] = None
    current_round: Optional[int] = None
    total_rounds: Optional[int] = None
    phases: List[TaskProgressPhaseResponse]


class TaskLogResponse(BaseModel):
    task_id: str
    run_path: Optional[str] = None
    available: bool
    log_text: str = ""
    files: List[str] = []
    phase: Optional[str] = None
    message: Optional[str] = None


class TaskResultSummaryResponse(BaseModel):
    top_level_entries: List[dict] = []
    file_extension_breakdown: List[dict] = []
    largest_files: List[dict] = []
    deepest_path: Optional[dict] = None
    output_file_count: int = 0
    output_dir_count: int = 0
    output_total_size_bytes: int = 0
    largest_file_path: Optional[str] = None
    largest_file_size_bytes: int = 0
    top_level_entry_count: int = 0
    avg_file_size_bytes: int = 0
    small_file_count: int = 0
    medium_file_count: int = 0
    large_file_count: int = 0
    matched_skill: Optional[str] = None
    fallback_to_llm: bool = False
    generated_skill_path: Optional[str] = None
    promotion_success_count: int = 0
    executor_rounds: int = 0
    session_count: int = 0
    event_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[int] = None


class TaskResultResponse(BaseModel):
    task_id: str
    available: bool
    status: str
    output_root: Optional[str] = None
    run_root: Optional[str] = None
    summary_path: Optional[str] = None
    reason_path: Optional[str] = None
    tokens_summary_path: Optional[str] = None
    summary_text: Optional[str] = None
    reason_text: Optional[str] = None
    warnings: List[str] = []
    summary: TaskResultSummaryResponse


class TaskEventResponse(BaseModel):
    id: str
    task_id: str
    project_id: Optional[str] = None
    event_type: str
    stage_key: Optional[str] = None
    status: Optional[str] = None
    summary: str
    detail: Optional[dict] = None
    owner_id: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None


class TaskEventListResponse(BaseModel):
    total: int
    items: List[TaskEventResponse]


class TaskMetricsTaskResponse(BaseModel):
    status: str
    result_status: Optional[str] = None
    current_stage: Optional[str] = None
    owner_id: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    last_progress_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    queue_wait_seconds: Optional[int] = None
    running_seconds: Optional[int] = None


class TaskMetricsResourceResponse(BaseModel):
    available: bool
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    cpu_millicores: Optional[int] = None
    memory_mib: Optional[int] = None
    pod_cpu_limit_millicores: Optional[int] = None
    pod_memory_limit_mib: Optional[int] = None
    cpu_usage_percent: Optional[float] = None
    memory_usage_percent: Optional[float] = None
    containers: List[TaskResourceContainerResponse] = []
    message: Optional[str] = None


class TaskMetricsProgressResponse(BaseModel):
    current_phase: Optional[str] = None
    current_round: Optional[int] = None
    total_rounds: Optional[int] = None
    phase_count: int = 0
    completed_phase_count: int = 0
    failed_phase_count: int = 0
    running_phase_count: int = 0


class TaskMetricsEventsResponse(BaseModel):
    event_count: int = 0
    latest_event_type: Optional[str] = None
    latest_event_summary: Optional[str] = None
    latest_event_at: Optional[str] = None


class TaskMetricsSessionsResponse(BaseModel):
    session_count: int = 0
    running_session_count: int = 0
    failed_session_count: int = 0
    closed_session_count: int = 0


class TaskMetricsResultResponse(BaseModel):
    cache_available: bool
    cache_updated_at: Optional[str] = None
    output_file_count: int = 0
    output_dir_count: int = 0
    output_total_size_bytes: int = 0
    largest_file_size_bytes: int = 0
    top_level_entry_count: int = 0
    small_file_count: int = 0
    medium_file_count: int = 0
    large_file_count: int = 0
    executor_rounds: int = 0
    fallback_to_llm: bool = False
    matched_skill: Optional[str] = None


class TaskMetricsHealthResponse(BaseModel):
    is_terminal: bool
    has_owner: bool
    resource_available: bool
    result_cache_available: bool
    warnings: List[str] = []


class TaskMetricsResponse(BaseModel):
    task_id: str
    task: TaskMetricsTaskResponse
    resource: TaskMetricsResourceResponse
    progress: TaskMetricsProgressResponse
    events: TaskMetricsEventsResponse
    sessions: TaskMetricsSessionsResponse
    result: TaskMetricsResultResponse
    health: TaskMetricsHealthResponse


class TaskListResponse(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[TaskResponse]


class WorkerInstanceResponse(BaseModel):
    owner_id: str
    hostname: Optional[str] = None
    pod_ip: Optional[str] = None
    started_at: Optional[str] = None
    last_heartbeat: Optional[str] = None
    is_alive: bool
    active_tasks: int


class ConcurrencyInfoResponse(BaseModel):
    mode: str
    resource_based: bool
    effective_max_concurrent: int
    executor_capacity: int
    manual_max_concurrent: int
    auto_max_concurrent: int
    cpu_based_limit: Optional[int] = None
    memory_based_limit: Optional[int] = None
    cpu_millis_per_task: int
    memory_mb_per_task: int
    reserved_cpu_millis: int
    reserved_memory_mb: int
    pod_cpu_limit_millicores: Optional[int] = None
    pod_memory_limit_mib: Optional[int] = None
    pod_cpu_request_millicores: Optional[int] = None
    pod_memory_request_mib: Optional[int] = None


class ClusterInfoResponse(BaseModel):
    this_owner: str
    total_workers: int
    alive_workers: int
    workers: List[WorkerInstanceResponse]
    task_counts: dict[str, int]
    total_tasks: int
    concurrency: ConcurrencyInfoResponse


class ConfigEntryResponse(BaseModel):
    key: str
    value: str
    value_type: str
    description: Optional[str] = None
    updated_at: Optional[str] = None


class ConfigListResponse(BaseModel):
    total: int
    items: List[ConfigEntryResponse]


class LlmProviderSummaryResponse(BaseModel):
    provider_key: str
    display_name: str
    provider_type: str
    enabled: bool
    is_default: bool
    model: str
    description: Optional[str] = None
    updated_at: Optional[str] = None


class LlmProviderSummaryListResponse(BaseModel):
    total: int
    default_provider_key: Optional[str] = None
    items: List[LlmProviderSummaryResponse]


class LlmConfigFileModelOptionResponse(BaseModel):
    value: str
    label: str
    source: Optional[str] = None


class LlmConfigFileSummaryResponse(BaseModel):
    config_file_key: str
    display_name: str
    provider_type: str
    enabled: bool
    is_default: bool
    default_model: Optional[str] = None
    description: Optional[str] = None
    updated_at: Optional[str] = None
    model_options: List[LlmConfigFileModelOptionResponse] = []


class LlmConfigFileSummaryListResponse(BaseModel):
    total: int
    items: List[LlmConfigFileSummaryResponse]


class ToolEntryResponse(BaseModel):
    filename: str
    path: str
    name: str
    format_id: str
    description: str
    extensions: List[str]
    magic_hex: str
    keywords: List[str]
    binwalk_sigs: List[str]
    skill_status: str
    skill_version: int
    family_id: str
    promotion_success_count: int
    promotion_threshold: int


class ToolListResponse(BaseModel):
    total: int
    items: List[ToolEntryResponse]


class HealthResponse(BaseModel):
    status: str
    owner_id: Optional[str] = None


class ReadyResponse(BaseModel):
    status: str
    owner_id: Optional[str] = None
