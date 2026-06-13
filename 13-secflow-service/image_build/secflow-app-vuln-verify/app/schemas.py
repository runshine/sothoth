from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TokenUser(BaseModel):
    user_id: str | None = None
    username: str | None = None
    token_type: str | None = None


class TaskCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    reports_dir: str
    source_root: str
    binary_root: str
    threat_path: str
    model: str | None = None
    concurrency: int | None = Field(default=None, ge=1, le=64)
    resume: bool = False
    task_id: str | None = None


class TaskResponse(BaseModel):
    id: str
    project_id: str
    name: str
    description: str | None = None
    status: str
    reports_dir: str
    source_root: str
    binary_root: str
    threat_path: str
    output_dir: str
    model: str | None = None
    concurrency: int
    resume: bool
    pid: int | None = None
    return_code: int | None = None
    worker_id: str | None = None
    error_reason: str | None = None
    progress: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] = Field(default_factory=dict)
    created_by: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class TaskListResponse(BaseModel):
    total: int
    items: list[TaskResponse]


class ProjectStatsResponse(BaseModel):
    total_tasks: int = 0
    verified_tasks: int = 0
    total_results: int = 0
    confirmed_count: int = 0
    ruled_out_count: int = 0
    unresolved_count: int = 0
    unverified_count: int = 0


class TaskDetailResponse(TaskResponse):
    events: list["TaskEventResponse"] = Field(default_factory=list)


class TaskEventResponse(BaseModel):
    id: str
    task_id: str
    project_id: str
    event_type: str
    level: str
    status: str | None = None
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class ActionResponse(BaseModel):
    status: str
    task_id: str
    message: str


class ArtifactEntry(BaseModel):
    path: str
    size: int
    modified_at: datetime | None = None
    kind: str = "file"


class ArtifactListResponse(BaseModel):
    task_id: str
    output_dir: str
    items: list[ArtifactEntry]


class ArtifactContentResponse(BaseModel):
    task_id: str
    path: str
    offset: int
    limit: int
    size: int
    content: str
    truncated: bool


class TaskResultResponse(BaseModel):
    task_id: str
    status: str
    result_count: int
    results: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class ReportDimension(BaseModel):
    status: bool | None = None
    detail: str = ""


class ReportExploitability(BaseModel):
    preconditions: str = ""
    complexity: str = ""
    impact: str = ""


class ReportEvidence(BaseModel):
    type: str = ""
    claim: str = ""
    finding: str = ""


class ReportDataItem(BaseModel):
    id: str
    title: str = ""
    severity: str = "unknown"
    verdict: str = "unverified"
    ruled_out_by: str | None = None
    dimensions: dict[str, ReportDimension] = Field(default_factory=dict)
    root_cause: str = ""
    exploit: ReportExploitability | None = None
    evidence: list[ReportEvidence] = Field(default_factory=list)
    raw_result: dict[str, Any] | None = None


class ReportDataGroup(BaseModel):
    id: str
    file: str = ""
    function: str = ""
    report_count: int = 0
    verdicts: dict[str, int] = Field(default_factory=dict)
    dominant: str = "unverified"
    reports: list[ReportDataItem] = Field(default_factory=list)


class ReportDataResponse(BaseModel):
    task_id: str
    status: str
    title: str = "漏洞验证报告"
    target: str = ""
    total_verified: int = 0
    total_reports: int = 0
    total_groups: int = 0
    verdicts: dict[str, int] = Field(default_factory=dict)
    severities: dict[str, int] = Field(default_factory=dict)
    groups: list[ReportDataGroup] = Field(default_factory=list)


TaskDetailResponse.model_rebuild()
