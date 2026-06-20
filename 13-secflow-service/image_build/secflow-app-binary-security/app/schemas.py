"""Pydantic schemas for Binary Security APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.model import PIPELINE_PROFILE_DEFAULT, STAGE_SEQUENCE, TASK_TYPE_BINARY


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
    mode: Optional[str] = None
    engine: Optional[str] = None


class TaskPolicyOverrides(BaseModel):
    pipeline_mode: Optional[str] = None
    pipeline_profile: Optional[str] = None
    max_stage_parallelism: Optional[int] = Field(default=None, ge=1, le=32)
    max_retries_per_item: Optional[int] = Field(default=None, ge=0, le=20)
    continue_on_item_failure: Optional[bool] = None
    partial_success_stage_advancement: dict[str, bool] = Field(default_factory=dict)
    stage_parallelism: dict[str, int] = Field(default_factory=dict)
    module_selection_mode: Optional[str] = None
    module_risk_levels: Optional[list[str]] = None
    entry_selection_mode: Optional[str] = None
    knowledge_graph_entries_url: Optional[str] = None


class BinarySecurityTaskCreate(BaseModel):
    task_id: Optional[str] = None
    task_type: str = Field(default=TASK_TYPE_BINARY)
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    module_name: Optional[str] = None
    input_files: list[BinarySecurityInputFile] = Field(default_factory=list)
    output_root: Optional[str] = None
    stage_options: dict[str, StageOptions] = Field(default_factory=dict)
    policy_overrides: TaskPolicyOverrides = Field(default_factory=TaskPolicyOverrides)
    root_task_key_id: Optional[str] = None
    root_task_key_name: Optional[str] = None
    root_task_key_prefix: Optional[str] = None
    root_task_key_secret: Optional[str] = None
    task_key_source: Optional[str] = None


class BinarySecurityUploadCompletePayload(BaseModel):
    files: list[BinarySecurityInputFile] = Field(default_factory=list)


class BinarySecurityTaskConcurrencyUpdatePayload(BaseModel):
    stage_parallelism: dict[str, int] = Field(default_factory=dict)


class BinarySecurityTaskRuntimePolicyUpdatePayload(BaseModel):
    expected_version: int = Field(default=0, ge=0)
    stage_parallelism: dict[str, int] = Field(default_factory=dict)
    dispatch_throttle: dict[str, dict[str, int]] = Field(default_factory=dict)
    max_retries_per_item: Optional[int] = Field(default=None, ge=0, le=20)
    continue_on_item_failure: Optional[bool] = None
    tail_reconcile_poll_interval_seconds: Optional[int] = Field(default=None, ge=1, le=300)
    updated_by: Optional[str] = None


class BinarySecurityTaskPolicyUpdatePayload(BaseModel):
    pipeline_mode: Optional[str] = None
    stage_options: dict[str, StageOptions] = Field(default_factory=dict)
    max_retries_per_item: Optional[int] = Field(default=None, ge=0, le=20)
    continue_on_item_failure: Optional[bool] = None
    partial_success_stage_advancement: dict[str, bool] = Field(default_factory=dict)
    stage_parallelism: dict[str, int] = Field(default_factory=dict)
    module_selection_mode: Optional[str] = None
    module_risk_levels: Optional[list[str]] = None


class BinarySecurityTaskPrepareResponse(BaseModel):
    task_id: str


class BinarySecurityStageSummary(BaseModel):
    stage_name: str
    sequence_no: int
    status: str
    stage_terminalization_ready: bool = False
    stage_failure_escalation_ready: bool = False
    previous_stages_terminal: bool = False
    has_unresolved_expected_outputs: bool = False
    retry_count: int = 0
    retry_supported: bool = False
    retry_reason: Optional[str] = None
    retry_failed_supported: bool = False
    retry_failed_reason: Optional[str] = None
    retry_full_supported: bool = False
    retry_full_reason: Optional[str] = None
    total_items: int = 0
    success_items: int = 0
    failed_items: int = 0
    orchestration_failed_items: int = 0
    downstream_missing_items: int = 0
    skipped_items: int = 0
    running_items: int = 0
    cancelled_items: int = 0
    downstream_status_counts: dict[str, int] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    last_error: Optional[str] = None
    abnormal_reason: Optional["BinarySecurityAbnormalReason"] = None


class BinarySecurityAbnormalEvidence(BaseModel):
    key: str
    label: str
    value: str


class BinarySecurityAbnormalReason(BaseModel):
    is_abnormal: bool = True
    category: str
    code: str
    title: str
    message: str
    terminal: bool = True
    source_layer: str
    status: str
    service: str
    stage_name: Optional[str] = None
    item_key: Optional[str] = None
    downstream_task_id: Optional[str] = None
    downstream_service: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    evidence: list[BinarySecurityAbnormalEvidence] = Field(default_factory=list)
    recommended_action: Optional[str] = None
    related_event_ids: list[str] = Field(default_factory=list)


class BinarySecurityAbnormalReasonEventSummary(BaseModel):
    event_id: str
    created_at: datetime
    reason: BinarySecurityAbnormalReason


class BinarySecurityTaskResponse(BaseModel):
    id: str
    project_id: str
    task_type: str = TASK_TYPE_BINARY
    pipeline_profile: str = PIPELINE_PROFILE_DEFAULT
    name: str
    status: str
    runtime_phase: str = "owned_execution"
    tail_reconcile_state: str = "idle"
    task_control_mode: str = "owned_execution"
    current_operation_id: Optional[str] = None
    execution_epoch: int = 0
    current_stage: Optional[str] = None
    workflow_terminalization_ready: bool = False
    workflow_blocked_by_stage: Optional[str] = None
    last_error: Optional[str] = None
    terminal_failure: bool = False
    requeue_suppressed: bool = False
    failure_code: Optional[str] = None
    failure_category: Optional[str] = None
    failure_message: Optional[str] = None
    firmware_path: str
    stage_sequence: list[str] = Field(default_factory=list)
    is_queued: bool = False
    queue_position: Optional[int] = None
    queue_state: str = "idle"
    recoverable_reason: Optional[str] = None
    last_reconcile_at: Optional[datetime] = None
    dispatcher_instance_id: Optional[str] = None
    task_lease_owner_instance_id: Optional[str] = None
    task_lease_expires_at: Optional[datetime] = None
    task_lease_source: Optional[str] = None
    tail_control_mode: str = "idle"
    tail_has_runnable_unbound_items: bool = False
    tail_unbound_runnable_item_count: int = 0
    tail_bound_active_item_count: int = 0
    tail_has_downstream_refs: bool = False
    tail_takeover_required: bool = False
    tail_takeover_reason: Optional[str] = None
    runtime_override_version: int = 0
    runtime_override_updated_at: Optional[datetime] = None
    runtime_override_updated_by: Optional[str] = None
    runtime_policy_effect_scope: dict[str, str] = Field(default_factory=dict)
    base_policy: dict[str, Any] = Field(default_factory=dict)
    runtime_override: dict[str, Any] = Field(default_factory=dict)
    effective_runtime_policy: dict[str, Any] = Field(default_factory=dict)
    last_successful_downstream_sync_at: Optional[datetime] = None
    last_sync_attempt_at: Optional[datetime] = None
    last_sync_error_at: Optional[datetime] = None
    last_sync_error_type: Optional[str] = None
    last_sync_error_message: Optional[str] = None
    active_sync_error_item_count: int = 0
    never_synced_item_count: int = 0
    stale_synced_item_count: int = 0
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
    entry_selection_mode: str = "auto"
    candidate_entry_count: int = 0
    selected_entry_count: int = 0
    entry_count: int = 0
    vuln_result_count: int = 0
    firmware_item_count: int = 0
    unpacked_firmware_count: int = 0
    failed_firmware_count: int = 0
    task_retry_supported: bool = False
    task_retry_reason: Optional[str] = None
    task_continue_supported: bool = False
    task_continue_reason: Optional[str] = None
    task_retry_failed_items_supported: bool = False
    task_retry_failed_items_reason: Optional[str] = None
    abnormal_reason_title: Optional[str] = None
    abnormal_reason_code: Optional[str] = None
    abnormal_reason_category: Optional[str] = None
    abnormal_reason: Optional[BinarySecurityAbnormalReason] = None
    stage_summaries: list[BinarySecurityStageSummary] = Field(default_factory=list)
    manual_operation_state: dict[str, Any] = Field(default_factory=dict)
    cancel_state: dict[str, Any] = Field(default_factory=dict)
    cleanup_state: dict[str, Any] = Field(default_factory=dict)


class BinarySecurityTaskOperationResponse(BaseModel):
    id: str
    task_id: str
    project_id: str
    operation_type: str
    target_stage: Optional[str] = None
    requested_by: Optional[str] = None
    request_source: Optional[str] = None
    status: str
    operation_token: str
    execution_model: str = "task_owner_inbox"
    owner_model: str = "task_lease_owner"
    request_payload: dict[str, Any] = Field(default_factory=dict)
    result_payload: dict[str, Any] = Field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    current_step: Optional[str] = None
    step_attempts: dict[str, Any] = Field(default_factory=dict)
    step_payload: dict[str, Any] = Field(default_factory=dict)
    resume_cursor: dict[str, Any] = Field(default_factory=dict)
    superseded_by_operation_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class BinarySecurityTaskOperationPageResponse(BaseModel):
    task_id: str
    items: list[BinarySecurityTaskOperationResponse] = Field(default_factory=list)


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


class BinarySecurityReducerEventSummaryResponse(BaseModel):
    pending_count: int = 0
    processing_count: int = 0
    retryable_count: int = 0
    dead_letter_count: int = 0
    processed_count: int = 0
    failed_like_count: int = 0
    slow_event_count: int = 0
    max_processing_duration_ms: Optional[int] = None
    p95_processing_duration_ms: Optional[int] = None
    avg_processing_duration_ms: Optional[float] = None


class BinarySecurityReducerEventRecordResponse(BaseModel):
    event_id: str
    task_id: str
    project_id: str
    stage_name: Optional[str] = None
    event_type: str
    queue_status: str
    attempts: int = 0
    leased_by: Optional[str] = None
    created_at: Optional[datetime] = None
    available_at: Optional[datetime] = None
    lease_expires_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None
    processing_started_at: Optional[datetime] = None
    queue_wait_ms: Optional[int] = None
    processing_duration_ms: Optional[int] = None
    end_to_end_duration_ms: Optional[int] = None
    result: str
    failure_kind: str = "none"
    failure_reason: Optional[str] = None
    last_error: Optional[str] = None
    handler_pod: Optional[str] = None
    handler_instance: Optional[str] = None
    idempotency_key: Optional[str] = None


class BinarySecurityReducerEventPageResponse(BaseModel):
    total: int = 0
    page: int = 1
    page_size: int = 50
    truncated: bool = False
    items: list[BinarySecurityReducerEventRecordResponse] = Field(default_factory=list)
    summary: BinarySecurityReducerEventSummaryResponse = Field(default_factory=BinarySecurityReducerEventSummaryResponse)


class BinarySecurityTaskListResponse(BaseModel):
    total: int
    page: int = 1
    page_size: int = 50
    total_pages: int = 1
    running_count: int = 0
    queued_count: int = 0
    max_concurrent_tasks: int = 50
    project_stats: BinarySecurityProjectStats = Field(default_factory=BinarySecurityProjectStats)
    project_stage_aggregates: list[BinarySecurityProjectStageAggregate] = Field(default_factory=list)
    queue_runtime: dict[str, Any] = Field(default_factory=dict)
    items: list[BinarySecurityTaskResponse] = Field(default_factory=list)


class BinarySecurityStageItemResponse(BaseModel):
    id: str
    stage_name: str
    item_key: str
    item_name: Optional[str] = None
    parent_key: Optional[str] = None
    # Parent-orchestrator status, not the downstream task's authoritative status.
    status: str
    retry_count: int = 0
    rerun_count: int = 0
    auto_retry_count: int = 0
    total_retry_count: int = 0
    downstream_service: Optional[str] = None
    downstream_task_id: Optional[str] = None
    archive_bound_downstream_task_id: Optional[str] = None
    downstream_status: Optional[str] = None
    latest_binding_mismatch: Optional[dict[str, Any]] = None
    downstream_binding_state: Optional[str] = None
    downstream_create_attempts: int = 0
    downstream_create_last_attempt_at: Optional[datetime] = None
    downstream_create_next_retry_at: Optional[datetime] = None
    downstream_create_last_error: Optional[str] = None
    downstream_create_last_error_type: Optional[str] = None
    downstream_create_recoverable: Optional[bool] = None
    downstream_binding_message: Optional[str] = None
    downstream_cancel_phase: Optional[str] = None
    downstream_summary: Optional[dict[str, Any]] = None
    input_ref: dict[str, Any] = Field(default_factory=dict)
    output_ref: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    abnormal_reason: Optional[BinarySecurityAbnormalReason] = None
    sync_status: Optional[str] = None
    last_synced_at: Optional[datetime] = None
    last_sync_attempt_at: Optional[datetime] = None
    last_sync_success_at: Optional[datetime] = None
    last_sync_error_at: Optional[datetime] = None
    last_sync_error_message: Optional[str] = None
    last_sync_error_type: Optional[str] = None
    sync_freshness_state: Optional[str] = None
    downstream_raw_status: Optional[str] = None
    downstream_mapped_status: Optional[str] = None
    downstream_state_applied: Optional[bool] = None
    sync_observation_error_message: Optional[str] = None
    sync_observation_error_type: Optional[str] = None
    sync_observation_http_status: Optional[int] = None
    first_started_at: Optional[datetime] = None
    latest_started_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class BinarySecurityArchiveJobResponse(BaseModel):
    id: str
    stage_name: str
    item_id: str
    item_key: Optional[str] = None
    downstream_service: Optional[str] = None
    downstream_task_id: Optional[str] = None
    archive_source_primary_path: Optional[str] = None
    archive_source_paths: list[str] = Field(default_factory=list)
    source_root: Optional[str] = None
    source_root_path: Optional[str] = None
    source_dir: Optional[str] = None
    archive_status: str
    archive_root: Optional[str] = None
    error_message: Optional[str] = None
    abnormal_reason: Optional[BinarySecurityAbnormalReason] = None
    attempts: int = 0
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    retry_supported: bool = False
    retry_reason: Optional[str] = None
    retry_failed_supported: bool = False
    retry_failed_reason: Optional[str] = None
    copy_stats: dict[str, Any] = Field(default_factory=dict)


class BinarySecurityOverviewBusinessDetail(BaseModel):
    total_items: int = 0
    success_items: int = 0
    failed_items: int = 0
    orchestration_failed_items: int = 0
    downstream_missing_items: int = 0
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
    abnormal_reason: Optional[BinarySecurityAbnormalReason] = None
    retry_supported: bool = False
    retry_reason: Optional[str] = None
    retry_failed_supported: bool = False
    retry_failed_reason: Optional[str] = None
    retry_full_supported: bool = False
    retry_full_reason: Optional[str] = None
    detail: BinarySecurityOverviewBusinessDetail | BinarySecurityOverviewArchiveDetail


class BinarySecurityRuntimeHealthEvidence(BaseModel):
    label: str
    value: Optional[str] = None


class BinarySecurityRuntimeHealthUnit(BaseModel):
    unit_key: str
    unit_label: str
    unit_kind: str
    status: str
    task_scoped: bool = True
    owner_instance_id: Optional[str] = None
    started_at: Optional[datetime] = None
    last_heartbeat_at: Optional[datetime] = None
    age_seconds: Optional[float] = None
    detail: Optional[str] = None
    reason: Optional[str] = None
    evidence: list[BinarySecurityRuntimeHealthEvidence] = Field(default_factory=list)


class BinarySecurityRuntimeHealthSpotlightItem(BaseModel):
    slot_key: str
    title: str
    subtitle: Optional[str] = None
    status: str
    unit_key: Optional[str] = None
    owner_instance_id: Optional[str] = None
    last_heartbeat_at: Optional[datetime] = None
    age_seconds: Optional[float] = None
    reason: Optional[str] = None
    evidence: list[BinarySecurityRuntimeHealthEvidence] = Field(default_factory=list)


class BinarySecurityRuntimeHealthGroup(BaseModel):
    group_key: str
    group_label: str
    description: Optional[str] = None
    status: str = "unknown"
    active_unit_count: int = 0
    units: list[BinarySecurityRuntimeHealthUnit] = Field(default_factory=list)


class BinarySecurityRuntimeHealthSnapshotCard(BaseModel):
    card_key: str
    title: str
    subtitle: Optional[str] = None
    status: str = "unknown"
    message: Optional[str] = None
    rows: list[BinarySecurityRuntimeHealthEvidence] = Field(default_factory=list)


class BinarySecurityRuntimeHealthLoopSnapshot(BaseModel):
    loop_key: str
    loop_label: str
    status: str = "unknown"
    alive: bool = False
    task_running: bool = False
    heartbeat_alive: bool = False
    heartbeat_at: Optional[datetime] = None
    heartbeat_age_seconds: Optional[float] = None
    stale_after_seconds: Optional[int] = None
    message: Optional[str] = None


class BinarySecurityRuntimeHealthSummary(BaseModel):
    overall_status: str = "unknown"
    active_unit_count: int = 0
    healthy_unit_count: int = 0
    degraded_unit_count: int = 0
    unhealthy_unit_count: int = 0
    last_updated_at: Optional[datetime] = None
    message: Optional[str] = None


class BinarySecurityRuntimeHealthResponse(BaseModel):
    summary: BinarySecurityRuntimeHealthSummary = Field(default_factory=BinarySecurityRuntimeHealthSummary)
    spotlight: list[BinarySecurityRuntimeHealthSpotlightItem] = Field(default_factory=list)
    snapshot_cards: list[BinarySecurityRuntimeHealthSnapshotCard] = Field(default_factory=list)
    related_loops: list[BinarySecurityRuntimeHealthLoopSnapshot] = Field(default_factory=list)
    groups: list[BinarySecurityRuntimeHealthGroup] = Field(default_factory=list)
    units: list[BinarySecurityRuntimeHealthUnit] = Field(default_factory=list)


class BinarySecurityRootTaskKeySnapshot(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    prefix: Optional[str] = None
    source: Optional[str] = None
    has_secret: bool = False
    used: bool = False


class BinarySecurityWorkKeySnapshot(BaseModel):
    stage_name: Optional[str] = None
    service: Optional[str] = None
    stage_item_id: Optional[str] = None
    stage_item_key: Optional[str] = None
    downstream_task_id: Optional[str] = None
    agent_task_key_id: Optional[str] = None
    agent_task_key_name: Optional[str] = None
    agent_task_key_prefix: Optional[str] = None
    agent_task_key_source: Optional[str] = None
    has_secret: bool = False
    created_at: Optional[datetime] = None


class BinarySecurityTaskKeySnapshot(BaseModel):
    root_task_key: BinarySecurityRootTaskKeySnapshot = Field(default_factory=BinarySecurityRootTaskKeySnapshot)
    work_keys: list[BinarySecurityWorkKeySnapshot] = Field(default_factory=list)


class BinarySecurityTaskDetailResponse(BinarySecurityTaskResponse):
    description: Optional[str] = None
    output_root: str
    workspace_root: str
    fileserver_subproject_name: Optional[str] = None
    policy: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    item_stats: dict[str, dict[str, int]] = Field(default_factory=dict)
    stage_items_total: int = 0
    stage_items_truncated: bool = False
    stage_items: list[BinarySecurityStageItemResponse] = Field(default_factory=list)
    archive_jobs: list[BinarySecurityArchiveJobResponse] = Field(default_factory=list)
    overview_nodes: list[BinarySecurityOverviewNode] = Field(default_factory=list)
    orchestration_observability: dict[str, Any] = Field(default_factory=dict)
    cleanup_snapshot: dict[str, Any] = Field(default_factory=dict)
    runtime_health: BinarySecurityRuntimeHealthResponse = Field(default_factory=BinarySecurityRuntimeHealthResponse)
    abnormal_reason_history: list[BinarySecurityAbnormalReasonEventSummary] = Field(default_factory=list)
    task_key_source: Optional[str] = None
    root_task_key_id: Optional[str] = None
    root_task_key_name: Optional[str] = None
    root_task_key_prefix: Optional[str] = None
    has_root_task_key: bool = False
    task_key_snapshot: BinarySecurityTaskKeySnapshot = Field(default_factory=BinarySecurityTaskKeySnapshot)


class BinarySecurityStageItemPageResponse(BaseModel):
    task_id: str
    stage_name: str
    total: int = 0
    page: int = 1
    per_page: int = 100
    items: list[BinarySecurityStageItemResponse] = Field(default_factory=list)


class BinarySecurityArchiveJobPageResponse(BaseModel):
    task_id: str
    stage_name: Optional[str] = None
    total: int = 0
    page: int = 1
    per_page: int = 100
    items: list[BinarySecurityArchiveJobResponse] = Field(default_factory=list)


class BinarySecurityOverviewResponse(BaseModel):
    task_id: str
    nodes: list[BinarySecurityOverviewNode] = Field(default_factory=list)


class BinarySecurityAbnormalReasonHistoryResponse(BaseModel):
    task_id: str
    items: list[BinarySecurityAbnormalReasonEventSummary] = Field(default_factory=list)


class BinarySecurityTaskEventResponse(BaseModel):
    id: str
    stage_name: Optional[str] = None
    item_id: Optional[str] = None
    item_key: Optional[str] = None
    level: str
    event_type: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    compressed: bool = False
    repeat_count: int = 1
    created_at: datetime


class BinarySecurityTimelineResponse(BaseModel):
    task_id: str
    total: int = 0
    page: int = 1
    page_size: int = 200
    has_more: bool = False
    events: list[BinarySecurityTaskEventResponse] = Field(default_factory=list)


class BinarySecurityArtifactEntry(BaseModel):
    path: str
    size: int


class BinarySecurityArtifactIndexedEntry(BaseModel):
    relative_path: str
    kind: str
    size: int = 0
    stage: Optional[str] = None
    section: Optional[str] = None
    batch_no: Optional[int] = None
    attempt_no: Optional[int] = None


class BinarySecurityArtifactGroup(BaseModel):
    module_key: str
    module_name: Optional[str] = None
    source_root: Optional[str] = None
    primary_result_kind: Optional[str] = None
    result_kinds: list[str] = Field(default_factory=list)
    artifact_kind_summary: dict[str, int] = Field(default_factory=dict)
    result_kind_summary: dict[str, int] = Field(default_factory=dict)
    artifact_index_path: Optional[str] = None
    result_summary_version: int = 1
    artifacts: list[BinarySecurityArtifactIndexedEntry] = Field(default_factory=list)


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
    grouped_by_index: bool = False
    artifact_groups: list[BinarySecurityArtifactGroup] = Field(default_factory=list)


BinarySecurityTaskDetailResponse.model_rebuild()


class BinarySecurityActionResponse(BaseModel):
    status: str = "ok"
    task_id: str
    operation_id: Optional[str] = None
    message: str
    accepted: bool = False
    action: Optional[str] = None
    task_status_after_accept: Optional[str] = None
    cancelled_downstream_count: int = 0
    deleted_downstream_count: int = 0
    cleanup_status: Optional[str] = None
    synced_downstream_count: int = 0
    skipped_downstream_count: int = 0
    failed_downstream_count: int = 0
    deleted_event_count: int = 0
    binding_mismatch_count: int = 0
    revived_count: int = 0
    revival_rejected_count: int = 0


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


class BinarySecurityModuleReportDetailResponse(BaseModel):
    task_id: str
    module_key: str
    module_name: str
    module_report_path: Optional[str] = None
    module_report_markdown: Optional[str] = None
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    file_count: Optional[int] = None
    source_tags: list[str] = Field(default_factory=list)
    available: bool = False
    warning: Optional[str] = None
    error_message: Optional[str] = None


class BinarySecurityModuleSelectionConfirmPayload(BaseModel):
    selected_module_keys: list[str] = Field(default_factory=list)


class BinarySecurityEntrySelectionResponse(BaseModel):
    task_id: str
    status: str
    selection_mode: str = "auto"
    requires_confirmation: bool = False
    candidate_entries: list[dict[str, Any]] = Field(default_factory=list)
    selected_entry_keys: list[str] = Field(default_factory=list)
    selected_entries: list[dict[str, Any]] = Field(default_factory=list)
    entry_results: list[dict[str, Any]] = Field(default_factory=list)
    confirmed_at: Optional[datetime] = None


class BinarySecurityEntrySelectionConfirmPayload(BaseModel):
    selected_entry_keys: list[str] = Field(default_factory=list)


class BinarySecurityTaskPolicyConfigPayload(BaseModel):
    pipeline_mode: str = Field(default="mixed_streaming")
    max_stage_parallelism: int = Field(default=5, ge=1, le=32)
    max_retries_per_item: int = Field(default=2, ge=0, le=20)
    continue_on_item_failure: bool = True
    partial_success_stage_advancement: dict[str, bool] = Field(
        default_factory=lambda: {
            "binary_to_source": True,
            "entry_analysis": True,
            "dataflow_vuln_scan": True,
        }
    )
    stage_parallelism: dict[str, int] = Field(
        default_factory=lambda: {stage: 5 for stage in STAGE_SEQUENCE}
    )
    stage_options: dict[str, StageOptions] = Field(
        default_factory=lambda: {stage: StageOptions(enabled=True) for stage in STAGE_SEQUENCE}
    )


class BinarySecurityTaskPolicyConfigResponse(BaseModel):
    project_id: str
    config: BinarySecurityTaskPolicyConfigPayload


class BinarySecurityProjectConfigPayload(BinarySecurityTaskPolicyConfigPayload):
    """Backward-compatible alias for the global task policy config payload."""


class BinarySecurityProjectConfigResponse(BinarySecurityTaskPolicyConfigResponse):
    """Backward-compatible alias for the global task policy config response."""


class BinarySecurityServiceConfigPayload(BaseModel):
    max_concurrent_tasks: int = Field(default=20, ge=1, le=200)
    dispatch_timeout_seconds: int = Field(default=60, ge=10, le=600)
    lease_timeout_seconds: int = Field(default=90, ge=15, le=1800)


class BinarySecurityServiceConfigResponse(BaseModel):
    config: BinarySecurityServiceConfigPayload


class BinarySecurityGlobalConfigPayload(BaseModel):
    max_concurrent_tasks: int = Field(default=20, ge=1, le=200)
    dispatch_timeout_seconds: int = Field(default=60, ge=10, le=600)
    lease_timeout_seconds: int = Field(default=90, ge=15, le=1800)
    pipeline_mode: str = Field(default="mixed_streaming")
    max_stage_parallelism: int = Field(default=5, ge=1, le=32)
    max_retries_per_item: int = Field(default=2, ge=0, le=20)
    continue_on_item_failure: bool = True
    partial_success_stage_advancement: dict[str, bool] = Field(
        default_factory=lambda: {
            "binary_to_source": True,
            "entry_analysis": True,
            "dataflow_vuln_scan": True,
        }
    )
    stage_parallelism: dict[str, int] = Field(
        default_factory=lambda: {stage: 5 for stage in STAGE_SEQUENCE}
    )
    stage_options: dict[str, StageOptions] = Field(
        default_factory=lambda: {stage: StageOptions(enabled=True) for stage in STAGE_SEQUENCE}
    )


class BinarySecurityGlobalConfigResponse(BaseModel):
    config: BinarySecurityGlobalConfigPayload
