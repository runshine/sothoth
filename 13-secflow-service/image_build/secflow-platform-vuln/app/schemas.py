"""Pydantic schemas."""

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class ServiceCapabilityRegister(BaseModel):
    capability_code: str
    action_type: str
    priority: int = 100
    timeout_seconds: int = 300
    concurrency_limit: int = 1
    input_schema_meta: dict[str, Any] = Field(default_factory=dict)
    output_schema_meta: dict[str, Any] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)


class ServiceRegisterRequest(BaseModel):
    service_id: str
    service_name: str
    service_type: str
    endpoint: str
    healthcheck_url: Optional[str] = None
    callback_mode: str = "push"
    auth_mode: str = "machine_token"
    version: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[ServiceCapabilityRegister] = Field(default_factory=list)


class ServiceResponse(BaseModel):
    service_id: str
    service_name: str
    service_type: str
    endpoint: str
    status: str
    version: Optional[str] = None
    last_heartbeat_at: datetime
    capabilities: list[dict[str, Any]]


class CaseCreateRequest(BaseModel):
    project_id: str
    title: str
    summary: Optional[str] = None
    severity: str = "medium"
    confidence: int = 0
    source_meta: dict[str, Any] = Field(default_factory=dict)
    target_meta: dict[str, Any] = Field(default_factory=dict)
    display_meta: dict[str, Any] = Field(default_factory=dict)
    created_by_type: str = "human"
    created_by: Optional[str] = None


class PublicIntakeSubmissionRequest(BaseModel):
    project_id: str
    title: str
    summary: Optional[str] = None
    severity: str = "medium"
    confidence: int = 0
    source_meta: dict[str, Any] = Field(default_factory=dict)
    target_meta: dict[str, Any] = Field(default_factory=dict)
    display_meta: dict[str, Any] = Field(default_factory=dict)
    reporter_type: Literal["cli", "plugin", "skill", "api", "other"] = "other"
    reporter_name: Optional[str] = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    attachments: list[dict[str, Any]] = Field(default_factory=list)

    def to_case_create_request(self) -> CaseCreateRequest:
        source_meta = dict(self.source_meta)
        source_meta.setdefault("reporter_type", self.reporter_type)
        source_meta.setdefault("reporter_name", self.reporter_name)
        source_meta.setdefault("raw_payload", self.raw_payload)
        source_meta.setdefault("attachments", self.attachments)
        source_meta.setdefault("anonymous_submission", True)

        display_meta = dict(self.display_meta)
        display_meta.setdefault("preferred_render_type", "generic")

        created_by = self.reporter_name or f"anonymous:{self.reporter_type}"
        return CaseCreateRequest(
            project_id=self.project_id,
            title=self.title,
            summary=self.summary,
            severity=self.severity,
            confidence=self.confidence,
            source_meta=source_meta,
            target_meta=self.target_meta,
            display_meta=display_meta,
            created_by_type="anonymous",
            created_by=created_by,
        )


class CaseResponse(BaseModel):
    id: str
    project_id: str
    title: str
    summary: Optional[str]
    severity: str
    confidence: int
    current_stage: str
    current_status: str
    decision_status: str
    created_by_type: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class StageTransitionRequest(BaseModel):
    to_stage: str
    reason: Optional[str] = None


class DecisionRequest(BaseModel):
    decision_status: str
    summary: Optional[str] = None


class ManualTaskCreateRequest(BaseModel):
    task_type: str
    title: str
    summary: Optional[str] = None
    assignee: Optional[str] = None
    due_at: Optional[datetime] = None
    context: dict[str, Any] = Field(default_factory=dict)


class ManualTaskStatusUpdateRequest(BaseModel):
    status: str


class RoutedActionDispatchRequest(BaseModel):
    action_type: Optional[str] = None
    service_id: Optional[str] = None
    stage: Optional[str] = None
    input_meta: dict[str, Any] = Field(default_factory=dict)
    input_artifact_refs: list[dict[str, Any]] = Field(default_factory=list)


class ActionCallbackRequest(BaseModel):
    source_service_id: Optional[str] = None
    result_type: str
    status: str = "succeeded"
    summary: Optional[str] = None
    confidence: int = 0
    suggested_stage: Optional[str] = None
    suggested_decision: Optional[str] = None
    result_meta: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    artifact_refs: list[dict[str, Any]] = Field(default_factory=list)


class ActionControlRequest(BaseModel):
    operation: str


class TimelineItem(BaseModel):
    id: str
    item_type: str
    created_at: datetime
    payload: dict[str, Any]
