"""Pydantic schemas for system analysis service."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


TaskStatus = Literal["pending", "preparing", "running", "partial_success", "success", "failed", "cancelled"]
TaskNodeStatus = Literal["pending", "session_creating", "session_created", "analyzing", "success", "failed", "cancelled"]
RiskLevel = Literal["unknown", "low", "medium", "high", "critical"]
AnalysisType = Literal[
    "general_env_check",
    "service_dependency_check",
    "tool_readiness_check",
    "network_connectivity_check",
    "custom",
]


class MessageResponse(BaseModel):
    message: str


class AiAgentOption(BaseModel):
    agent_id: str
    agent_name: str


class AnalysisCapabilityNodeItem(BaseModel):
    agent_key: str
    agent_hostname: Optional[str] = None
    agent_ip: Optional[str] = None
    agent_status: str = "unknown"
    helper_installed: bool = False
    helper_service_name: Optional[str] = None
    helper_status: Optional[str] = None
    available_ai_agents: List[AiAgentOption] = Field(default_factory=list)
    last_analysis_at: Optional[datetime] = None
    last_analysis_summary: Optional[str] = None


class AnalysisCapabilitySummary(BaseModel):
    total_nodes: int = 0
    online_nodes: int = 0
    helper_ready_nodes: int = 0
    analyzable_nodes: int = 0


class ProjectAnalysisCapabilitiesResponse(BaseModel):
    project_id: str
    summary: AnalysisCapabilitySummary
    items: List[AnalysisCapabilityNodeItem] = Field(default_factory=list)


class PromptTemplateCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str = Field(default="general", min_length=1, max_length=64)
    description: Optional[str] = Field(default=None, max_length=500)
    content: str = Field(..., min_length=1)
    variables_json: List[str] = Field(default_factory=list)
    is_default: bool = False
    is_enabled: bool = True


class PromptTemplateUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    category: Optional[str] = Field(default=None, min_length=1, max_length=64)
    description: Optional[str] = Field(default=None, max_length=500)
    content: Optional[str] = Field(default=None, min_length=1)
    variables_json: Optional[List[str]] = None
    is_default: Optional[bool] = None
    is_enabled: Optional[bool] = None


class PromptTemplateCloneRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


class PromptTemplateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    prompt_id: str
    name: str
    category: str
    description: Optional[str] = None
    content: str
    variables_json: List[str] = Field(default_factory=list)
    version: int
    is_default: bool
    is_enabled: bool
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PromptTemplateListItem(BaseModel):
    prompt_id: str
    name: str
    category: str
    description: Optional[str] = None
    version: int
    is_default: bool
    is_enabled: bool
    updated_at: datetime


class PromptTemplateListResponse(BaseModel):
    items: List[PromptTemplateListItem]
    page: int
    per_page: int
    total: int


class ExecutionConfig(BaseModel):
    timeout_seconds: int = Field(default=600, ge=30, le=7200)
    max_concurrency: int = Field(default=5, ge=1, le=50)


class AnalysisTaskTarget(BaseModel):
    agent_key: str = Field(..., min_length=1, max_length=64)
    ai_agent_id: str = Field(..., min_length=1, max_length=128)


class AnalysisTaskCreateRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=100)
    task_name: str = Field(..., min_length=1, max_length=255)
    analysis_type: AnalysisType
    prompt_template_id: Optional[str] = Field(default=None, max_length=64)
    prompt_content: str = Field(..., min_length=1)
    execution_config: ExecutionConfig = Field(default_factory=ExecutionConfig)
    targets: List[AnalysisTaskTarget] = Field(..., min_length=1)

    @field_validator("targets")
    @classmethod
    def validate_unique_agent_keys(cls, value: List[AnalysisTaskTarget]) -> List[AnalysisTaskTarget]:
        seen = set()
        for item in value:
            if item.agent_key in seen:
                raise ValueError(f"duplicate agent_key: {item.agent_key}")
            seen.add(item.agent_key)
        return value


class AnalysisTaskResponse(BaseModel):
    task_id: str
    status: TaskStatus


class AnalysisTaskListItem(BaseModel):
    task_id: str
    project_id: str
    task_name: str
    analysis_type: AnalysisType
    status: TaskStatus
    risk_level: RiskLevel
    total_nodes: int
    success_nodes: int
    failed_nodes: int
    created_by: Optional[str] = None
    created_at: datetime
    finished_at: Optional[datetime] = None


class AnalysisTaskListResponse(BaseModel):
    items: List[AnalysisTaskListItem]
    page: int
    per_page: int
    total: int


class AnalysisTaskDetailResponse(BaseModel):
    task_id: str
    project_id: str
    task_name: str
    analysis_type: AnalysisType
    prompt_template_id: Optional[str] = None
    prompt_content: str
    status: TaskStatus
    risk_level: RiskLevel
    total_nodes: int
    success_nodes: int
    failed_nodes: int
    running_nodes: int
    cancelled_nodes: int
    execution_config: Dict[str, Any] = Field(default_factory=dict)
    summary_json: Dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AnalysisTaskNodeListItem(BaseModel):
    agent_key: str
    agent_hostname: Optional[str] = None
    agent_ip: Optional[str] = None
    helper_service_name: str
    helper_session_id: Optional[str] = None
    ai_agent_id: str
    status: TaskNodeStatus
    risk_level: RiskLevel
    result_summary: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AnalysisTaskNodeListResponse(BaseModel):
    task_id: str
    items: List[AnalysisTaskNodeListItem]
    total: int


class AnalysisTaskNodeDetailResponse(BaseModel):
    task_id: str
    agent_key: str
    agent_hostname: Optional[str] = None
    agent_ip: Optional[str] = None
    helper_service_name: str
    helper_session_id: Optional[str] = None
    ai_agent_id: str
    status: TaskNodeStatus
    risk_level: RiskLevel
    result_summary: Optional[str] = None
    normalized_result_json: Dict[str, Any] = Field(default_factory=dict)
    raw_response_json: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AnalysisReportResponse(BaseModel):
    report_id: str
    task_id: str
    project_id: str
    risk_level: RiskLevel
    summary_markdown: str = ""
    summary_json: Dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime


class RetryNodeRequest(BaseModel):
    agent_key: str = Field(..., min_length=1, max_length=64)


class OverviewTaskSummary(BaseModel):
    total_tasks: int = 0
    last_task_id: Optional[str] = None
    last_task_status: Optional[TaskStatus] = None
    last_task_at: Optional[datetime] = None


class OverviewRiskSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class RecentFindingItem(BaseModel):
    task_id: str
    agent_key: str
    risk_level: RiskLevel = "unknown"
    summary: str


class AnalysisOverviewResponse(BaseModel):
    project_id: str
    node_summary: AnalysisCapabilitySummary
    task_summary: OverviewTaskSummary
    risk_summary: OverviewRiskSummary
    recent_findings: List[RecentFindingItem] = Field(default_factory=list)

