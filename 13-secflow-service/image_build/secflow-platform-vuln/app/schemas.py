"""Pydantic schemas."""

from datetime import datetime
from typing import Any, Optional

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


class TimelineItem(BaseModel):
    id: str
    item_type: str
    created_at: datetime
    payload: dict[str, Any]
