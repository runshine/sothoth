from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class DiagnosticSessionSummary(BaseModel):
    id: int
    title: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    agent_session_id: str | None = None
    agent_id: str | None = None
    session_mode: str | None = None


class DiagnosticMessageRecord(BaseModel):
    id: int
    session_id: int
    role: Literal["system", "user", "assistant"]
    content: str
    created_at: datetime


class DiagnosticReadableItem(BaseModel):
    id: str
    title: str
    body: str


class DiagnosticAssistantArtifacts(BaseModel):
    reasoning: str = ""
    items: list[DiagnosticReadableItem] = Field(default_factory=list)


class DiagnosticConversationBlock(BaseModel):
    id: str
    message_id: int | None = None
    run_id: int | None = None
    kind: Literal["user", "thinking", "text", "tool_call", "tool_result"]
    title: str = ""
    body: str = ""
    created_at: datetime
    updated_at: datetime | None = None
    running: bool = False


class DiagnosticExecutionRecord(BaseModel):
    id: int
    session_id: int
    message_id: int | None = None
    command_text: str
    stdout: str
    stderr: str
    exit_code: int
    status: Literal["running", "completed", "failed", "timeout"]
    started_at: datetime
    finished_at: datetime | None = None


class DiagnosticAuditRecord(BaseModel):
    id: int
    user_id: str
    session_id: int | None = None
    action_type: str
    request_text: str
    command_text: str | None = None
    result_summary: str | None = None
    created_at: datetime


class DiagnosticSessionDetail(BaseModel):
    session: DiagnosticSessionSummary
    messages: list[DiagnosticMessageRecord]
    assistant_artifacts: dict[int, DiagnosticAssistantArtifacts] = Field(default_factory=dict)
    conversation_blocks: list[DiagnosticConversationBlock] = Field(default_factory=list)


class CreateSessionRequest(BaseModel):
    title: str | None = None


class ChatRequest(BaseModel):
    session_id: int | None = None
    message: str = Field(min_length=1)
    provider_key: str | None = None


class ChatResponse(BaseModel):
    session: DiagnosticSessionSummary
    assistant_message: DiagnosticMessageRecord
    executions: list[DiagnosticExecutionRecord]
    provider_key: str


class PlannerDecision(BaseModel):
    needs_execution: bool = False
    command: str | None = None
    explanation: str = ""


class LlmProviderConfig(BaseModel):
    provider_key: str
    provider_type: str
    api_base: str
    api_key: str
    model: str
    enabled: bool = True
    extra_config: dict[str, Any] = Field(default_factory=dict)


class LlmProviderSummary(BaseModel):
    provider_key: str
    display_name: str
    provider_type: str
    api_base: str
    api_key: str = ""
    model: str
    enabled: bool = True
    is_default: bool = False
    mapped_env_keys: list[str] = Field(default_factory=list)
    mapped_file_paths: list[str] = Field(default_factory=list)
    updated_at: str | None = None


class StreamEvent(BaseModel):
    event: str
    data: dict[str, Any]


class DiagnosticAgentSummary(BaseModel):
    agent_id: str
    name: str
    backend_type: str
    enabled: bool = True
    active: bool = False
    running: bool = False
    description: str = ""


class AgentRunRequest(BaseModel):
    session_id: int | None = None
    message: str = Field(min_length=1)
    agent_id: str | None = None
    session_mode: str | None = None
    provider_key: str | None = None
    agent_task_key_secret: str | None = None


class DiagnosticAgentRunRecord(BaseModel):
    id: int
    session_id: int
    user_message_id: int | None = None
    assistant_message_id: int | None = None
    agent_id: str
    agent_session_id: str | None = None
    upstream_response_id: str | None = None
    task_text: str
    final_text: str
    status: Literal["running", "completed", "failed", "cancelled"]
    created_at: datetime
    finished_at: datetime | None = None


class DiagnosticAgentEventRecord(BaseModel):
    id: int
    run_id: int
    event_type: str
    payload_json: str
    created_at: datetime

    @property
    def payload(self) -> dict[str, Any]:
        try:
            import json
            raw = json.loads(self.payload_json)
            return raw if isinstance(raw, dict) else {"value": raw}
        except Exception:
            return {"raw": self.payload_json}


class DiagnosticAgentProbeRequest(BaseModel):
    provider_key: str | None = None
    prompt: str | None = None
    agent_task_key_secret: str | None = None


class DiagnosticAgentProbeResult(BaseModel):
    ok: bool
    agent_id: str
    provider_key: str
    model_ref: str
    api_base: str
    elapsed_ms: int
    output_text: str = ""
    error_message: str | None = None
