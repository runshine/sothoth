"""Pydantic schemas."""

from __future__ import annotations

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


class ReporterInfo(BaseModel):
    name: str
    version: str
    type: Literal["plugin", "service", "cli", "skill", "api", "human", "other"] = "other"
    vendor: Optional[str] = None
    endpoint: Optional[str] = None
    instance_id: Optional[str] = None


class SubjectInfo(BaseModel):
    type: str
    locator: str
    name: Optional[str] = None
    version: Optional[str] = None


class EvidenceInfo(BaseModel):
    summary: Optional[str] = None
    reproduction_hint: Optional[str] = None
    references: list[dict[str, Any]] = Field(default_factory=list)


class ArtifactItem(BaseModel):
    artifact_id: Optional[str] = None
    kind: Literal[
        "file",
        "directory",
        "tree",
        "json",
        "text",
        "binary",
        "archive",
        "screenshot",
        "pcap",
        "request_response",
        "report",
        "script",
        "other",
    ] = "other"
    name: str
    path: Optional[str] = None
    media_type: Optional[str] = None
    sha256: Optional[str] = None
    size: int = 0
    encoding: Optional[Literal["plain", "base64", "utf-8"]] = None
    content: Optional[str] = None
    content_ref: Optional[str] = None
    children: list["ArtifactItem"] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SuspicionSubmissionRequest(BaseModel):
    project_id: str
    report_id: Optional[str] = None
    title: str
    summary: Optional[str] = None
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    cvss_score: float = 0.0
    confidence: int = 0
    state: Literal["suspected", "confirmed", "rejected"] = "suspected"
    category: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    fingerprint: Optional[str] = None
    reported_at: Optional[datetime] = None
    reporter: ReporterInfo
    subject: SubjectInfo
    evidence: EvidenceInfo = Field(default_factory=EvidenceInfo)
    artifacts: list[ArtifactItem] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_case_create_request(
        self,
        *,
        created_by_type: str,
        created_by: Optional[str],
        anonymous_submission: bool = False,
    ) -> "CaseCreateRequest":
        metadata = dict(self.metadata)
        source_meta = dict(metadata.get("source") or {})
        source_meta.setdefault("anonymous_submission", anonymous_submission)
        metadata["source"] = source_meta
        return CaseCreateRequest(
            project_id=self.project_id,
            report_id=self.report_id,
            title=self.title,
            summary=self.summary,
            severity=self.severity,
            cvss_score=self.cvss_score,
            confidence=self.confidence,
            state=self.state,
            category=self.category,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            fingerprint=self.fingerprint,
            reported_at=self.reported_at,
            reporter=self.reporter,
            subject=self.subject,
            evidence=self.evidence,
            artifacts=self.artifacts,
            metadata=metadata,
            created_by_type=created_by_type,
            created_by=created_by or self.reporter.name,
        )


class CaseCreateRequest(SuspicionSubmissionRequest):
    created_by_type: str = "human"
    created_by: Optional[str] = None

    def build_storage_payloads(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        source_meta = {
            "report_id": self.report_id,
            "state": self.state,
            "category": self.category,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "fingerprint": self.fingerprint,
            "reported_at": self.reported_at.isoformat() if self.reported_at else None,
            "cvss_score": self.cvss_score,
            "reporter": self.reporter.model_dump(mode="json"),
        }
        target_meta = self.subject.model_dump(mode="json")
        display_meta = {
            "entity_label": "疑点",
            "preferred_render_type": "generic",
            "evidence": self.evidence.model_dump(mode="json"),
            "artifacts": [artifact.model_dump(mode="json") for artifact in self.artifacts],
            "metadata": self.metadata,
        }
        return source_meta, target_meta, display_meta


class PublicIntakeSubmissionRequest(SuspicionSubmissionRequest):
    pass


class DraftCaseCreateRequest(BaseModel):
    project_id: str
    title: Optional[str] = None
    summary: Optional[str] = None
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    cvss_score: float = 0.0
    confidence: int = 0
    state: Literal["suspected", "confirmed", "rejected"] = "suspected"
    category: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    fingerprint: Optional[str] = None
    reported_at: Optional[datetime] = None
    reporter: Optional[ReporterInfo] = None
    subject: Optional[SubjectInfo] = None
    evidence: EvidenceInfo = Field(default_factory=EvidenceInfo)
    artifacts: list[ArtifactItem] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_case_create_request(self, *, created_by_type: str, created_by: Optional[str]) -> "CaseCreateRequest":
        reporter = self.reporter or ReporterInfo(
            name=created_by or "draft-intake",
            version="0.0.0",
            type="human",
        )
        subject = self.subject or SubjectInfo(
            type="unknown",
            locator=f"draft://{self.project_id}",
            name="待补充",
        )
        metadata = dict(self.metadata)
        draft_meta = dict(metadata.get("draft") or {})
        draft_meta.setdefault("is_draft", True)
        metadata["draft"] = draft_meta
        return CaseCreateRequest(
            project_id=self.project_id,
            report_id=None,
            title=self.title or "未命名疑点草稿",
            summary=self.summary or "草稿疑点，等待补充详情与文件。",
            severity=self.severity,
            cvss_score=self.cvss_score,
            confidence=self.confidence,
            state=self.state,
            category=self.category,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            fingerprint=self.fingerprint,
            reported_at=self.reported_at,
            reporter=reporter,
            subject=subject,
            evidence=self.evidence,
            artifacts=self.artifacts,
            metadata=metadata,
            created_by_type=created_by_type,
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
    triage_decision: Optional[str] = None
    triage_gate: Optional[str] = None
    triage_round: Optional[int] = None
    triage_history: list[dict[str, Any]] = Field(default_factory=list)
    validation_result: Optional[str] = None
    finished_reason: Optional[str] = None
    created_by_type: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class CaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[Literal["critical", "high", "medium", "low"]] = None
    cvss_score: Optional[float] = None
    confidence: Optional[int] = None
    state: Optional[Literal["suspected", "confirmed", "rejected"]] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    fingerprint: Optional[str] = None
    reported_at: Optional[datetime] = None
    reporter: Optional[ReporterInfo] = None
    subject: Optional[SubjectInfo] = None
    evidence: Optional[EvidenceInfo] = None
    artifacts: Optional[list[ArtifactItem]] = None
    metadata: Optional[dict[str, Any]] = None


class StageTransitionRequest(BaseModel):
    to_stage: str
    reason: Optional[str] = None
    finished_reason: Optional[Literal["vulnerable", "non_vulnerable", "inconclusive", "non_issue", "observe", "manual_terminated"]] = None
    summary: Optional[str] = None


class DecisionRequest(BaseModel):
    decision_status: str
    summary: Optional[str] = None


class TriageDecisionRequest(BaseModel):
    triage_decision: Literal["issue", "non_issue", "observe"]
    summary: Optional[str] = None


class TriageGateRequest(BaseModel):
    triage_gate: Literal["pending", "approved_to_validation", "rejected_to_validation"]
    summary: Optional[str] = None


class TriageRoundStartRequest(BaseModel):
    summary: Optional[str] = None


class ValidationResultRequest(BaseModel):
    validation_result: Literal["vulnerable", "not_vulnerable", "inconclusive"]
    summary: Optional[str] = None


class FinishCaseRequest(BaseModel):
    finished_reason: Literal["vulnerable", "non_vulnerable", "inconclusive", "non_issue", "observe", "manual_terminated"]
    summary: str


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
