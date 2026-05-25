from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


DEFAULT_EVOLVE_AGENTS = ["pi-worker", "pi-advisor"]


class EvolutionPreviewRequest(BaseModel):
    case_ids: List[str] = Field(default_factory=list, min_length=1)


class EvolutionTaskCreateRequest(BaseModel):
    case_ids: List[str] = Field(default_factory=list, min_length=1)
    title: str = Field(..., min_length=1, max_length=255)
    objective: str = Field(default="", max_length=4000)
    metrics: Dict[str, bool] = Field(default_factory=dict)
    min_rounds: Optional[int] = Field(default=None, ge=1, le=100)
    max_rounds: Optional[int] = Field(default=None, ge=1, le=100)
    max_concurrent_source_tasks: Optional[int] = Field(default=None, ge=1, le=64)
    profile_id: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    review_profile: Optional[str] = None
    agent_run_timeout_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
    evolve_agents: List[str] = Field(default_factory=lambda: list(DEFAULT_EVOLVE_AGENTS))
    auto_start: bool = True


class EvolutionExperimentCreateRequest(BaseModel):
    project_id: str = Field(..., min_length=1)
    direction: str = Field(default="", max_length=4000)
    selected_results: List[str] = Field(default_factory=list, min_length=1)
    max_rounds: Optional[int] = Field(default=None, ge=1, le=100)
    min_rounds: Optional[int] = Field(default=None, ge=1, le=100)
    title: Optional[str] = Field(default=None, max_length=255)
    metrics: Dict[str, bool] = Field(default_factory=dict)
    max_concurrent_source_tasks: Optional[int] = Field(default=None, ge=1, le=64)
    profile_id: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    review_profile: Optional[str] = None
    agent_run_timeout_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
    evolve_agents: List[str] = Field(default_factory=lambda: list(DEFAULT_EVOLVE_AGENTS))


class EvolutionConfigPayload(BaseModel):
    max_concurrent_tasks: int = Field(default=2, ge=1, le=64)
    max_concurrent_source_tasks: int = Field(default=4, ge=1, le=64)
    default_min_rounds: int = Field(default=1, ge=1, le=100)
    default_max_rounds: int = Field(default=3, ge=1, le=100)
    evolution_agent_model: str = Field(default="pi-agent", min_length=1)
    evolution_agent_timeout_seconds: int = Field(default=1800, ge=1, le=86400)
    evolution_agent_context_window: int = Field(default=131072, ge=1024, le=10485760)


class EvolutionConfigResponse(BaseModel):
    config: EvolutionConfigPayload
    updated_at: Optional[datetime] = None


class EvolutionPreviewSource(BaseModel):
    source_task_id: str
    source_execution_id: Optional[str] = None
    source_run_id: Optional[str] = None
    source_title: Optional[str] = None
    selected_case_ids: List[str] = Field(default_factory=list)
    all_case_ids: List[str] = Field(default_factory=list)
    auto_expanded_case_ids: List[str] = Field(default_factory=list)
    blocked_reasons: List[str] = Field(default_factory=list)
    replay_ready: bool = False
    replay_reason: Optional[str] = None
    source_task_summary: Dict[str, Any] = Field(default_factory=dict)


class EvolutionPreviewResponse(BaseModel):
    project_id: str
    requested_case_ids: List[str] = Field(default_factory=list)
    effective_case_ids: List[str] = Field(default_factory=list)
    can_create: bool = False
    blocked_reasons: List[str] = Field(default_factory=list)
    sources: List[EvolutionPreviewSource] = Field(default_factory=list)


class EvolutionTaskSummary(BaseModel):
    task_id: str
    project_id: str
    title: str
    status: str
    objective: Optional[str] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)
    current_round: int = 0
    best_round: Optional[int] = None
    overall_score: Optional[int] = None
    convergence_reason: Optional[str] = None
    apply_status: str = "not_applied"
    source_task_ids: List[str] = Field(default_factory=list)
    source_case_ids: List[str] = Field(default_factory=list)
    evolve_agents: List[str] = Field(default_factory=list)
    config: Dict[str, Any] = Field(default_factory=dict)
    message: Optional[str] = None
    created_by: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    updated_at: datetime


class EvolutionTaskRoundResponse(BaseModel):
    round_no: int
    status: str
    metrics: Dict[str, Any] = Field(default_factory=dict)
    score: Optional[int] = None
    score_reason: Optional[str] = None
    adjustment_summary: Optional[str] = None
    convergence_decision: Optional[bool] = None
    convergence_reason: Optional[str] = None
    derived_tasks: List[Dict[str, Any]] = Field(default_factory=list)
    diff_summary: Dict[str, Any] = Field(default_factory=dict)
    candidate_agent_state_roots: Dict[str, str] = Field(default_factory=dict)
    meta_evaluation: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class EvolutionTaskDetail(EvolutionTaskSummary):
    preview: EvolutionPreviewResponse
    agent_state_roots: Dict[str, str] = Field(default_factory=dict)
    default_agent_source_dirs: Dict[str, str] = Field(default_factory=dict)
    best_candidate_agent_state_roots: Dict[str, str] = Field(default_factory=dict)
    sources: List[Dict[str, Any]] = Field(default_factory=list)
    rounds: List[EvolutionTaskRoundResponse] = Field(default_factory=list)
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    events: List[Dict[str, Any]] = Field(default_factory=list)


class EvolutionApplyResponse(BaseModel):
    status: str
    task_id: str
    snapshot_path: Optional[str] = None
    message: str


class EvolutionMemoryModePatchRequest(BaseModel):
    mode: Literal["shared", "evolution"] = "shared"
    enabled_agents: List[str] = Field(default_factory=lambda: list(DEFAULT_EVOLVE_AGENTS))
    promoted_task_id: Optional[str] = None
    promoted_round: Optional[int] = Field(default=None, ge=1)


class EvolutionMemoryModeResponse(BaseModel):
    project_id: str
    mode: Literal["shared", "evolution"] = "shared"
    enabled_agents: List[str] = Field(default_factory=list)
    promoted_task_id: Optional[str] = None
    promoted_round: Optional[int] = None
    agent_state_roots: Dict[str, str] = Field(default_factory=dict)
    config_path: Optional[str] = None
    updated_at: Optional[datetime] = None


class SuccessResponse(BaseModel):
    success: bool = True
    message: str = "ok"
