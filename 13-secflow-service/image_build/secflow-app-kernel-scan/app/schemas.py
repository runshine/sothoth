from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    service: str


class ReadyResponse(BaseModel):
    status: str
    service: str
    ready: bool
    checks: dict[str, bool]


class TaskCreateRequest(BaseModel):
    title: str
    pipeline_mode: Literal["entry_only", "audit_only", "poc_only", "entry_audit_poc"] = "entry_audit_poc"
    kernel_dir: str | None = None
    report_dir: str | None = None
    device_ip: str | None = None
    entrylist: str | None = None
    notes: str | None = None


class TaskCreateResponse(BaseModel):
    task_id: str
    attempt_id: str
    status: str


class TaskSummaryResponse(BaseModel):
    task_id: str
    title: str
    pipeline_mode: str
    kernel_dir: str
    status: str
    current_stage: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    message: str | None = None


class PagedTaskResponse(BaseModel):
    items: list[TaskSummaryResponse]
    total: int
    page: int
    per_page: int


class EventResponse(BaseModel):
    event_seq: int
    event_id: str
    task_id: str
    attempt_id: str | None = None
    stage_name: str | None = None
    event_type: str
    level: str
    message: str
    payload_json: str = "{}"
    created_at: str


class EventPageResponse(BaseModel):
    items: list[EventResponse]
    next_cursor: int | None = None
