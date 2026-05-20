"""Pydantic schemas for B2S adapter API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class TokenUser(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    token_type: Optional[str] = None


class ElfTaskInput(BaseModel):
    elf_path: str
    file_list: list[str] = Field(default_factory=list)
    output_subdir: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaskCreate(BaseModel):
    task_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    priority: int = 5
    tags: list[str] = Field(default_factory=list)
    llm_provider_key: Optional[str] = None
    concurrency: Optional[int] = None
    agent_run_timeout_seconds: Optional[int] = None
    agent_timeout_retry_enabled: Optional[bool] = None
    agent_timeout_max_retries: Optional[int] = None
    mode: Optional[Literal["fast", "deep"]] = None
    engine: Optional[Literal["hybrid", "agent"]] = None
    reuse_cache: Optional[bool] = None
    task_origin_type: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    elf_tasks: list[ElfTaskInput]


class B2SServiceConfig(BaseModel):
    project_id: str
    budget_exhausted_action: Literal["treat_as_passed", "treat_as_failed"] = "treat_as_passed"
    llm_provider_key: Optional[str] = None
    effective_llm_provider: Optional["LlmProviderSummary"] = None
    updated_at: Optional[str] = None


class RetryRequest(BaseModel):
    item_ids: Optional[list[str]] = None


class RerunRequest(BaseModel):
    """Deprecated request body kept only for compatibility."""

    clean_output: Optional[bool] = None
    cancel_running: Optional[bool] = None


class B2SProgress(BaseModel):
    phase: Optional[str] = None
    raw_phase: Optional[str] = None
    phase_label: Optional[str] = None
    message: Optional[str] = None
    total_functions: Optional[int] = None
    completed_functions: Optional[int] = None
    total_bytes: Optional[int] = None
    completed_bytes: Optional[int] = None
    total_batches: Optional[int] = None
    completed_batches: Optional[int] = None
    current_batch: Optional[int] = None
    current_attempt: Optional[int] = None
    current_function: Optional[str] = None
    percent: Optional[float] = None
    bytes_percent: Optional[float] = None
    batches_percent: Optional[float] = None


class B2SOverallProgress(BaseModel):
    total_items: int = 0
    completed_items: int = 0
    total_functions: Optional[int] = None
    completed_functions: Optional[int] = None
    total_bytes: Optional[int] = None
    completed_bytes: Optional[int] = None
    total_batches: Optional[int] = None
    completed_batches: Optional[int] = None
    percent: Optional[float] = None
    percent_basis: Optional[str] = None
    phase_summary: dict[str, int] = Field(default_factory=dict)


class TaskItemResponse(BaseModel):
    id: str
    sequence_no: int
    elf_path: str
    output_dir: str
    status: str
    phase: Optional[str] = None
    phase_label: Optional[str] = None
    phase_message: Optional[str] = None
    progress: Optional[B2SProgress] = None
    failure_type: Optional[str] = None
    error_reason: Optional[str] = None
    pi_job_id: Optional[str] = None
    pi_worker_url: Optional[str] = None
    generated_files: list[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class TaskConfigInputItem(BaseModel):
    item_id: str
    sequence_no: int
    elf_path: str
    source_elf_path: Optional[str] = None
    output_dir: str
    output_subdir: Optional[str] = None
    file_list: list[str] = Field(default_factory=list)


class TaskConfigSnapshot(BaseModel):
    name: str
    description: Optional[str] = None
    priority: int = 5
    tags: list[str] = Field(default_factory=list)
    task_origin_type: Optional[str] = None
    origin_label: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    mode: Optional[str] = None
    mode_label: Optional[str] = None
    engine: Optional[str] = None
    llm_provider_key: Optional[str] = None
    llm_provider_display_name: Optional[str] = None
    llm_provider_type: Optional[str] = None
    llm_provider_model: Optional[str] = None
    concurrency: Optional[int] = None
    agent_run_timeout_seconds: Optional[int] = None
    agent_timeout_retry_enabled: Optional[bool] = None
    agent_timeout_max_retries: Optional[int] = None
    reuse_cache: Optional[bool] = None
    budget_exhausted_action: Optional[str] = None
    input_count: int = 0
    input_items: list[TaskConfigInputItem] = Field(default_factory=list)


class AgentRuntimeEntry(BaseModel):
    key: str
    label: str
    item_id: Optional[str] = None
    sequence_no: Optional[int] = None
    item_name: Optional[str] = None
    run_name: Optional[str] = None
    stage: Optional[str] = None
    agent: Optional[str] = None
    role: Optional[str] = None
    batch_no: Optional[int] = None
    attempt_no: Optional[int] = None
    relative_path: Optional[str] = None
    full_path: Optional[str] = None
    updated_at: Optional[str] = None
    is_active: bool = False
    size: int = 0


class AgentRuntimeSummary(BaseModel):
    total_sessions: int = 0
    active_agent_count: int = 0
    header_agent_count: int = 0
    executor_agent_count: int = 0
    validator_agent_count: int = 0
    active_agents: list[AgentRuntimeEntry] = Field(default_factory=list)


class TaskResultItemSummary(BaseModel):
    item_id: str
    sequence_no: int
    item_name: str
    elf_path: str
    output_dir: str
    status: str
    result_file_count: int = 0
    key_result_files: list[str] = Field(default_factory=list)
    session_file_count: int = 0
    review_round_count: int = 0
    final_verdict: Optional[str] = None
    final_verdict_label: Optional[str] = None


class TaskResultSummary(BaseModel):
    task_id: str
    success_items: int = 0
    partial_items: int = 0
    failed_items: int = 0
    cancelled_items: int = 0
    result_file_count: int = 0
    session_file_count: int = 0
    review_round_count: int = 0
    items: list[TaskResultItemSummary] = Field(default_factory=list)


class TaskObservabilityItem(BaseModel):
    item_id: str
    sequence_no: int
    item_name: str
    status: str
    duration_ms: Optional[int] = None
    batch_count: int = 0
    session_count: int = 0
    attempt_count: int = 0
    final_verdict: Optional[str] = None
    final_confidence: int = 0
    final_quality_score: int = 0
    issue_total: int = 0
    issue_resolved: int = 0
    issue_remaining: int = 0


class TaskObservabilitySummary(BaseModel):
    task_id: str
    total_duration_ms: Optional[int] = None
    avg_item_duration_ms: Optional[int] = None
    total_batches: int = 0
    avg_batches_per_item: float = 0
    total_sessions: int = 0
    active_agent_count: int = 0
    total_review_attempts: int = 0
    avg_review_attempts: float = 0
    passed_items: int = 0
    not_passed_items: int = 0
    issue_total: int = 0
    issue_resolved: int = 0
    issue_remaining: int = 0
    issue_closure_rate: float = 0
    completed_functions: int = 0
    total_functions: int = 0
    completed_bytes: int = 0
    total_bytes: int = 0
    avg_confidence: float = 0
    avg_quality_score: float = 0
    residual_risk_distribution: dict[str, int] = Field(default_factory=dict)
    business_runtime_metrics: Optional[dict[str, Any]] = None
    items: list[TaskObservabilityItem] = Field(default_factory=list)


class SessionIndexNode(BaseModel):
    node_id: str
    item_id: str
    sequence_no: int
    item_name: str
    run_name: str
    stage: str
    stage_order: int = 0
    section: Optional[str] = None
    round: Optional[str] = None
    round_order: Optional[int] = None
    agent: Optional[str] = None
    role: Optional[str] = None
    batch_no: Optional[int] = None
    attempt_no: Optional[int] = None
    relative_path: str
    full_path: str
    size: int = 0
    updated_at: Optional[str] = None
    is_active: bool = False
    kind: str = "agent_session"


class SessionIndexResponse(BaseModel):
    task_id: str
    nodes: list[SessionIndexNode] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    generated_at: Optional[str] = None


class SessionFileResponse(BaseModel):
    task_id: str
    node_id: Optional[str] = None
    item_id: Optional[str] = None
    relative_path: str
    full_path: str
    size: int = 0
    content: str = ""
    truncated: bool = False
    next_offset: Optional[int] = None
    offset: int = 0
    limit: int = 0
    mime_type: str = "text/plain"


class RelationshipNode(BaseModel):
    node_id: str
    node_type: str
    item_id: Optional[str] = None
    sequence_no: Optional[int] = None
    title: str
    subtitle: Optional[str] = None
    status: Optional[str] = None
    relative_path: Optional[str] = None
    full_path: Optional[str] = None
    batch_no: Optional[int] = None
    attempt_no: Optional[int] = None
    group_key: Optional[str] = None
    is_active: bool = False


class RelationshipEdge(BaseModel):
    edge_id: str
    source_node_id: str
    target_node_id: str
    kind: str
    label: Optional[str] = None


class TaskRelationshipResponse(BaseModel):
    task_id: str
    nodes: list[RelationshipNode] = Field(default_factory=list)
    edges: list[RelationshipEdge] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class TaskResponse(BaseModel):
    id: str
    project_id: str
    task_origin_type: Optional[str] = None
    parent_project_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    parent_task_type: Optional[str] = None
    parent_stage_name: Optional[str] = None
    parent_stage_item_id: Optional[str] = None
    parent_stage_item_key: Optional[str] = None
    origin_label: Optional[str] = None
    parent_task_display: Optional[str] = None
    mode: Optional[str] = None
    mode_label: Optional[str] = None
    input_filenames: list[str] = Field(default_factory=list)
    name: str
    status: str
    total_items: int
    pending_items: int
    queued_items: int
    running_items: int
    success_items: int
    partial_items: int
    failed_items: int
    cancelled_items: int
    total_functions: Optional[int] = None
    completed_functions: Optional[int] = None
    failed_functions: Optional[int] = None
    uncompleted_functions: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    run_duration_ms: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class TaskDetailResponse(TaskResponse):
    overall_progress: Optional[B2SOverallProgress] = None
    items: list[TaskItemResponse] = Field(default_factory=list)
    task_config_snapshot: Optional[TaskConfigSnapshot] = None
    effective_llm_provider: Optional["LlmProviderSummary"] = None
    agent_runtime_summary: Optional[AgentRuntimeSummary] = None
    result_summary: Optional[TaskResultSummary] = None
    observability_summary: Optional[TaskObservabilitySummary] = None
    event_summary: Optional["B2STaskEventSummary"] = None


class B2STaskEvent(BaseModel):
    id: str
    task_id: str
    project_id: str
    item_id: Optional[str] = None
    sequence_no: Optional[int] = None
    pi_job_id: Optional[str] = None
    source: str
    level: str
    event_type: str
    phase: Optional[str] = None
    batch_id: Optional[int] = None
    attempt: Optional[int] = None
    function_name: Optional[str] = None
    status: Optional[str] = None
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class B2STaskEventSummary(BaseModel):
    total_events: int = 0
    latest_event_type: Optional[str] = None
    latest_event_at: Optional[datetime] = None
    last_batch_id: Optional[int] = None
    current_function: Optional[str] = None
    current_attempt: Optional[int] = None


class B2STaskTimelineResponse(BaseModel):
    task_id: str
    events: list[B2STaskEvent] = Field(default_factory=list)


class AdvancedFile(BaseModel):
    name: str
    path: str
    kind: str
    size: int = 0
    content: Optional[str] = None
    truncated: bool = False
    stage: Optional[str] = None
    stage_order: Optional[int] = None
    section: Optional[str] = None
    section_order: Optional[int] = None
    round: Optional[str] = None
    round_order: Optional[int] = None
    agent: Optional[str] = None
    role: Optional[str] = None
    batch_no: Optional[int] = None
    attempt_no: Optional[int] = None


class AdvancedBatch(BaseModel):
    name: str
    batch_no: Optional[int] = None
    source: Optional[AdvancedFile] = None
    disasm: Optional[AdvancedFile] = None
    reviews: list[AdvancedFile] = Field(default_factory=list)
    review_snapshots: list[AdvancedFile] = Field(default_factory=list)


class AdvancedRun(BaseModel):
    name: str
    path: str
    batches: list[AdvancedBatch] = Field(default_factory=list)
    agent_sessions: list[AdvancedFile] = Field(default_factory=list)
    files: list[AdvancedFile] = Field(default_factory=list)


class TaskItemAdvancedResponse(BaseModel):
    task_id: str
    item_id: str
    sequence_no: int
    mode: Optional[str] = None
    mode_label: Optional[str] = None
    output_dir: str
    work_dir: Optional[str] = None
    runs: list[AdvancedRun] = Field(default_factory=list)
    ida_files: list[AdvancedFile] = Field(default_factory=list)


class B2SArtifact(BaseModel):
    id: str
    name: str
    path: str
    relative_path: str
    kind: str
    size: int = 0
    stage: Optional[str] = None
    stage_order: Optional[int] = None
    section: Optional[str] = None
    section_order: Optional[int] = None
    round: Optional[str] = None
    round_order: Optional[int] = None
    agent: Optional[str] = None
    role: Optional[str] = None
    batch_no: Optional[int] = None
    attempt_no: Optional[int] = None
    content_url: str


class TaskItemArtifactsResponse(BaseModel):
    task_id: str
    item_id: str
    output_dir: str
    work_dir: Optional[str] = None
    artifacts: list[B2SArtifact] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class B2SArtifactContentResponse(BaseModel):
    artifact_id: str
    name: str
    path: str
    kind: str
    mime_type: str = "text/plain"
    encoding: str = "utf-8"
    size: int = 0
    offset: int = 0
    limit: int = 0
    content: str = ""
    truncated: bool = False
    next_offset: Optional[int] = None


class B2SCacheSummary(BaseModel):
    visible_entries: int = 0
    current_project_entries: int = 0
    fast_entries: int = 0
    deep_entries: int = 0
    total_hit_count: int = 0
    latest_hit_at: Optional[str] = None


class B2SCacheEntry(BaseModel):
    cache_key: str
    status: str
    mode: str
    elf_basename: Optional[str] = None
    source_project_id: Optional[str] = None
    source_task_id: Optional[str] = None
    source_item_id: Optional[str] = None
    file_sha256: str
    file_size: int = 0
    analysis_signature: Optional[str] = None
    hit_count: int = 0
    last_hit_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    canonical_output_dir: Optional[str] = None
    canonical_input_path: Optional[str] = None
    cache_dir_exists: bool = False
    ready_marker_exists: bool = False
    manifest_exists: bool = False
    output_dir_exists: bool = False


class B2SCacheListResponse(BaseModel):
    total: int = 0
    items: list[B2SCacheEntry] = Field(default_factory=list)
    summary: B2SCacheSummary = Field(default_factory=B2SCacheSummary)


class B2SCacheDetailResponse(B2SCacheEntry):
    generated_files: list[str] = Field(default_factory=list)
    source_metadata: dict[str, Any] = Field(default_factory=dict)
    manifest: Optional[dict[str, Any]] = None
    manifest_parse_error: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class B2SCacheDeleteResponse(BaseModel):
    status: str
    cache_key: str
    deleted: bool = False
    message: Optional[str] = None


class B2SCacheBatchDeleteRequest(BaseModel):
    cache_keys: list[str] = Field(min_length=1)


class B2SCacheBatchDeleteResponse(BaseModel):
    status: str
    deleted_count: int = 0
    failed_count: int = 0
    results: list[B2SCacheDeleteResponse] = Field(default_factory=list)


class TaskListResponse(BaseModel):
    total: int
    items: list[TaskResponse]


class ReviewAnalyticsAttempt(BaseModel):
    attempt_no: int
    label: Optional[str] = None
    verdict: str = "UNKNOWN"
    verdict_label: Optional[str] = None
    total_functions: int = 0
    verified_functions: int = 0
    blocking_issues: int = 0
    warnings: int = 0
    semantic_score: int = 0
    confidence: int = 0
    quality_score: int = 0
    issues_discovered: int = 0
    issues_resolved: int = 0
    issues_open_after_attempt: int = 0
    status_label: Optional[str] = None


class ReviewAnalyticsIssue(BaseModel):
    id: str
    label: str
    display_label: Optional[str] = None
    description: Optional[str] = None
    function: str = "global"
    category: str = "Semantic"
    category_label: Optional[str] = None
    severity: str = "blocking"
    severity_label: Optional[str] = None
    introduced_attempt: int
    resolved_attempt: Optional[int] = None
    status: str = "remaining"
    status_label: Optional[str] = None


class ReviewAnalyticsFunctionAttempt(BaseModel):
    attempt_no: int
    risk: str = "unknown"
    score: int = 0


class ReviewAnalyticsFunction(BaseModel):
    function: str
    attempts: list[ReviewAnalyticsFunctionAttempt] = Field(default_factory=list)


class ReviewAnalyticsRadar(BaseModel):
    attempt_no: int
    completeness: int = 0
    control_flow: int = 0
    return_semantics: int = 0
    input_validation: int = 0
    call_fidelity: int = 0
    type_struct_fidelity: int = 0


class ReviewAnalyticsSummary(BaseModel):
    attempts: int = 0
    attempt_count: int = 0
    final_verdict: str = "UNKNOWN"
    final_verdict_label: Optional[str] = None
    final_confidence: int = 0
    final_quality_score: int = 0
    final_quality_label: Optional[str] = None
    initial_quality_score: int = 0
    quality_delta: int = 0
    quality_delta_percent: int = 0
    issue_total: int = 0
    issue_resolved: int = 0
    issue_remaining: int = 0
    issue_closure_rate: float = 0
    residual_risk: str = "unknown"
    residual_risk_label: Optional[str] = None


class ReviewAnalyticsMeta(BaseModel):
    schema_version: str = "review_analytics.v2"
    scoring_version: str = "b2s_quality.v1"
    source: str = "validator_verdict"
    data_quality: str = "estimated"
    generated_at: Optional[str] = None


class ReviewAnalyticsTrendPoint(BaseModel):
    attempt_no: int
    label: str
    score: int


class ReviewAnalyticsTrendSeries(BaseModel):
    key: str
    label: str
    color_hint: Optional[str] = None
    points: list[ReviewAnalyticsTrendPoint] = Field(default_factory=list)


class ReviewAnalyticsTrendInsight(BaseModel):
    title: str = "逐轮质量趋势"
    conclusion: str = "暂无足够轮次数据生成趋势结论。"
    tone: str = "neutral"
    primary_metric: str = "质量分"
    first_score: int = 0
    final_score: int = 0
    delta: int = 0
    series: list[ReviewAnalyticsTrendSeries] = Field(default_factory=list)


class ReviewAnalyticsDimension(BaseModel):
    key: str
    label: str
    score: int = 0
    initial_score: int = 0
    delta: int = 0
    delta_percent: int = 0
    level: str = "unknown"
    level_label: str = "未知"
    description: str = ""
    formula: Optional[str] = None
    color_hint: Optional[str] = None
    points: list[ReviewAnalyticsTrendPoint] = Field(default_factory=list)
    components: dict[str, int] = Field(default_factory=dict)


class ReviewAnalyticsResponse(BaseModel):
    task_id: str
    item_id: str
    status: str = "ready"
    meta: ReviewAnalyticsMeta = Field(default_factory=ReviewAnalyticsMeta)
    summary: ReviewAnalyticsSummary
    attempts: list[ReviewAnalyticsAttempt] = Field(default_factory=list)
    issues: list[ReviewAnalyticsIssue] = Field(default_factory=list)
    dimensions: list[ReviewAnalyticsDimension] = Field(default_factory=list)
    trend: Optional[ReviewAnalyticsTrendInsight] = None
    function_matrix: list[ReviewAnalyticsFunction] = Field(default_factory=list)
    radar: list[ReviewAnalyticsRadar] = Field(default_factory=list)
    trend_insight: Optional[ReviewAnalyticsTrendInsight] = None


class LlmProviderSummary(BaseModel):
    provider_key: str
    display_name: Optional[str] = None
    provider_type: Optional[str] = None
    enabled: bool = True
    is_default: bool = False
    model: Optional[str] = None


class LlmProviderListResponse(BaseModel):
    items: list[LlmProviderSummary] = Field(default_factory=list)
    total: int = 0
    default_provider_key: Optional[str] = None


class TaskPrepareResponse(BaseModel):
    task_id: str


class ActionResponse(BaseModel):
    status: str
    task_id: Optional[str] = None
    message: Optional[str] = None
    deleted_event_count: int = 0


class TaskBatchDeleteRequest(BaseModel):
    task_ids: list[str] = Field(min_length=1)


class TaskBatchDeleteItemResult(BaseModel):
    task_id: str
    status: str
    message: Optional[str] = None
    deleted_event_count: int = 0


class TaskBatchDeleteResponse(BaseModel):
    status: str
    deleted_count: int = 0
    failed_count: int = 0
    deleted_event_count: int = 0
    results: list[TaskBatchDeleteItemResult] = Field(default_factory=list)


_SCHEMA_TYPES = {
    "Optional": Optional,
    "LlmProviderSummary": LlmProviderSummary,
    "B2STaskEventSummary": B2STaskEventSummary,
}

B2SServiceConfig.model_rebuild(_types_namespace=_SCHEMA_TYPES)
TaskDetailResponse.model_rebuild(_types_namespace=_SCHEMA_TYPES)
