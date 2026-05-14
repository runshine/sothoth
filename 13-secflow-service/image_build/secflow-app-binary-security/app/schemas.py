"""Pydantic schemas for Binary Security APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.model import STAGE_SEQUENCE, TASK_TYPE_BINARY


class TokenUser(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    token_type: Optional[str] = None


class BinarySecurityInputFile(BaseModel):
    filename: str = Field(..., min_length=1)
    size: Optional[int] = Field(default=None, ge=0)
    content_type: Optional[str] = None
    relative_path: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class StageOptions(BaseModel):
    enabled: bool = True


class TaskPolicyOverrides(BaseModel):
    max_stage_parallelism: Optional[int] = Field(default=None, ge=1, le=32)
    max_retries_per_item: Optional[int] = Field(default=None, ge=0, le=20)
    continue_on_item_failure: Optional[bool] = None
    stage_parallelism: dict[str, int] = Field(default_factory=dict)
    module_selection_mode: Optional[str] = None
    module_risk_levels: Optional[list[str]] = None


class BinarySecurityTaskCreate(BaseModel):
    task_id: Optional[str] = None
    task_type: str = Field(default=TASK_TYPE_BINARY)
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    input_files: list[BinarySecurityInputFile] = Field(default_factory=list)
    output_root: Optional[str] = None
    stage_options: dict[str, StageOptions] = Field(default_factory=dict)
    policy_overrides: TaskPolicyOverrides = Field(default_factory=TaskPolicyOverrides)


class BinarySecurityUploadCompletePayload(BaseModel):
    files: list[BinarySecurityInputFile] = Field(default_factory=list)


class BinarySecurityTaskConcurrencyUpdatePayload(BaseModel):
    stage_parallelism: dict[str, int] = Field(default_factory=dict)


class BinarySecurityTaskPolicyUpdatePayload(BaseModel):
    stage_options: dict[str, StageOptions] = Field(default_factory=dict)
    max_retries_per_item: Optional[int] = Field(default=None, ge=0, le=20)
    continue_on_item_failure: Optional[bool] = None
    stage_parallelism: dict[str, int] = Field(default_factory=dict)
    module_selection_mode: Optional[str] = None
    module_risk_levels: Optional[list[str]] = None


class BinarySecurityTaskPrepareResponse(BaseModel):
    task_id: str


class BinarySecurityStageSummary(BaseModel):
    stage_name: str
    sequence_no: int
    status: str
    retry_count: int = 0
    retry_supported: bool = False
    retry_reason: Optional[str] = None
    total_items: int = 0
    success_items: int = 0
    failed_items: int = 0
    skipped_items: int = 0
    running_items: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_error: Optional[str] = None


class BinarySecurityTaskResponse(BaseModel):
    id: str
    project_id: str
    task_type: str = TASK_TYPE_BINARY
    name: str
    status: str
    current_stage: Optional[str] = None
    pending_action: Optional[str] = None
    firmware_path: str
    stage_sequence: list[str] = Field(default_factory=list)
    is_queued: bool = False
    queue_position: Optional[int] = None
    dispatcher_instance_id: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    high_risk_module_count: int = 0
    medium_risk_module_count: int = 0
    low_risk_module_count: int = 0
    candidate_module_count: int = 0
    selected_module_count: int = 0
    selected_risk_levels: list[str] = Field(default_factory=list)
    module_selection_mode: str = "auto"
    entry_count: int = 0
    vuln_result_count: int = 0
    firmware_item_count: int = 0
    unpacked_firmware_count: int = 0
    failed_firmware_count: int = 0
    task_retry_supported: bool = False
    task_retry_reason: Optional[str] = None
    task_continue_supported: bool = False
    task_continue_reason: Optional[str] = None
    stage_summaries: list[BinarySecurityStageSummary] = Field(default_factory=list)


class BinarySecurityProjectStats(BaseModel):
    total: int = 0
    running: int = 0
    success: int = 0
    partial_success: int = 0
    failed: int = 0
    cancelled: int = 0
    selected_module_count: int = 0
    candidate_module_count: int = 0
    high_risk_module_count: int = 0
    entry_count: int = 0
    vuln_result_count: int = 0
    input_count: int = 0
    unpacked_firmware_count: int = 0
    failed_firmware_count: int = 0


class BinarySecurityProjectStageBusinessAggregate(BaseModel):
    task_count: int = 0
    total_items: int = 0
    success_items: int = 0
    failed_items: int = 0
    skipped_items: int = 0
    running_items: int = 0
    cancelled_items: int = 0
    status_counts: dict[str, int] = Field(default_factory=dict)


class BinarySecurityProjectStageArchiveAggregate(BaseModel):
    job_count: int = 0
    success_count: int = 0
    failed_count: int = 0
    running_count: int = 0
    applying_count: int = 0
    pending_count: int = 0
    status_counts: dict[str, int] = Field(default_factory=dict)


class BinarySecurityProjectStageAggregate(BaseModel):
    stage_name: str
    sequence_no: int
    business: BinarySecurityProjectStageBusinessAggregate = Field(default_factory=BinarySecurityProjectStageBusinessAggregate)
    archive: BinarySecurityProjectStageArchiveAggregate = Field(default_factory=BinarySecurityProjectStageArchiveAggregate)


class BinarySecurityTaskListResponse(BaseModel):
    total: int
    running_count: int = 0
    queued_count: int = 0
    max_concurrent_tasks: int = 50
    project_stats: BinarySecurityProjectStats = Field(default_factory=BinarySecurityProjectStats)
    project_stage_aggregates: list[BinarySecurityProjectStageAggregate] = Field(default_factory=list)
    items: list[BinarySecurityTaskResponse] = Field(default_factory=list)


class BinarySecurityStageItemResponse(BaseModel):
    id: str
    stage_name: str
    item_key: str
    item_name: Optional[str] = None
    parent_key: Optional[str] = None
    status: str
    retry_count: int = 0
    downstream_service: Optional[str] = None
    downstream_task_id: Optional[str] = None
    input_ref: dict[str, Any] = Field(default_factory=dict)
    output_ref: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class BinarySecurityArchiveJobResponse(BaseModel):
    id: str
    stage_name: str
    item_id: str
    item_key: Optional[str] = None
    downstream_service: Optional[str] = None
    downstream_task_id: Optional[str] = None
    archive_status: str
    archive_root: Optional[str] = None
    error_message: Optional[str] = None
    attempts: int = 0
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    copy_stats: dict[str, Any] = Field(default_factory=dict)


class BinarySecurityOverviewBusinessDetail(BaseModel):
    total_items: int = 0
    success_items: int = 0
    failed_items: int = 0
    skipped_items: int = 0
    running_items: int = 0
    cancelled_items: int = 0
    downstream_status_counts: dict[str, int] = Field(default_factory=dict)
    downstream_services: list[str] = Field(default_factory=list)
    representative_item_key: Optional[str] = None
    representative_downstream_task_id: Optional[str] = None


class BinarySecurityOverviewArchiveDetail(BaseModel):
    job_count: int = 0
    success_count: int = 0
    failed_count: int = 0
    running_count: int = 0
    applying_count: int = 0
    pending_count: int = 0
    first_created_at: Optional[datetime] = None
    last_updated_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    latest_error: Optional[str] = None
    jobs: list[BinarySecurityArchiveJobResponse] = Field(default_factory=list)


class BinarySecurityOverviewNode(BaseModel):
    node_id: str
    node_type: str
    stage_name: str
    sequence_no: int
    title: str
    status: str
    status_label: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_error: Optional[str] = None
    retry_supported: bool = False
    retry_reason: Optional[str] = None
    detail: BinarySecurityOverviewBusinessDetail | BinarySecurityOverviewArchiveDetail


class BinarySecurityTaskDetailResponse(BinarySecurityTaskResponse):
    description: Optional[str] = None
    output_root: str
    workspace_root: str
    fileserver_subproject_name: Optional[str] = None
    policy: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    item_stats: dict[str, dict[str, int]] = Field(default_factory=dict)
    stage_items: list[BinarySecurityStageItemResponse] = Field(default_factory=list)
    archive_jobs: list[BinarySecurityArchiveJobResponse] = Field(default_factory=list)
    overview_nodes: list[BinarySecurityOverviewNode] = Field(default_factory=list)


class BinarySecurityTaskEventResponse(BaseModel):
    id: str
    stage_name: Optional[str] = None
    item_id: Optional[str] = None
    item_key: Optional[str] = None
    level: str
    event_type: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class BinarySecurityTimelineResponse(BaseModel):
    task_id: str
    events: list[BinarySecurityTaskEventResponse] = Field(default_factory=list)


class BinarySecurityArtifactEntry(BaseModel):
    path: str
    size: int


class BinarySecurityArtifactsResponse(BaseModel):
    task_id: str
    workspace_root: str
    output_root: str
    fileserver_path: Optional[str] = None
    total: int = 0
    limit: int = 200
    offset: int = 0
    has_more: bool = False
    files: list[BinarySecurityArtifactEntry] = Field(default_factory=list)


class BinarySecurityActionResponse(BaseModel):
    status: str = "ok"
    task_id: str
    message: str
    accepted: bool = False
    action: Optional[str] = None
    cancelled_downstream_count: int = 0
    deleted_downstream_count: int = 0
    cleanup_status: Optional[str] = None
    synced_downstream_count: int = 0
    skipped_downstream_count: int = 0
    failed_downstream_count: int = 0
    deleted_event_count: int = 0


class BinarySecurityDownstreamStatusSyncPayload(BaseModel):
    stage_name: Optional[str] = None
    item_id: Optional[str] = None
    force: bool = False


class BinarySecurityModuleSelectionResponse(BaseModel):
    task_id: str
    status: str
    selection_mode: str = "auto"
    risk_levels: list[str] = Field(default_factory=list)
    requires_confirmation: bool = False
    system_analysis_modules: list[dict[str, Any]] = Field(default_factory=list)
    candidate_modules: list[dict[str, Any]] = Field(default_factory=list)
    selected_modules: list[dict[str, Any]] = Field(default_factory=list)


class BinarySecurityModuleSelectionConfirmPayload(BaseModel):
    selected_module_keys: list[str] = Field(default_factory=list)


class BinarySecurityProjectConfigPayload(BaseModel):
    max_stage_parallelism: int = Field(default=4, ge=1, le=32)
    max_retries_per_item: int = Field(default=2, ge=0, le=20)
    continue_on_item_failure: bool = True
    stage_parallelism: dict[str, int] = Field(
        default_factory=lambda: {stage: 4 for stage in STAGE_SEQUENCE}
    )
    stage_options: dict[str, StageOptions] = Field(
        default_factory=lambda: {stage: StageOptions(enabled=True) for stage in STAGE_SEQUENCE}
    )


class BinarySecurityProjectConfigResponse(BaseModel):
    project_id: str
    config: BinarySecurityProjectConfigPayload


class BinarySecurityServiceConfigPayload(BaseModel):
    max_concurrent_tasks: int = Field(default=50, ge=1, le=200)
    dispatch_timeout_seconds: int = Field(default=60, ge=10, le=600)
    lease_timeout_seconds: int = Field(default=90, ge=15, le=1800)


class BinarySecurityServiceConfigResponse(BaseModel):
    config: BinarySecurityServiceConfigPayload
