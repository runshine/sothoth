"""Pydantic schemas for B2S adapter API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

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
    elf_tasks: list[ElfTaskInput]


class RetryRequest(BaseModel):
    item_ids: Optional[list[str]] = None


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
    generated_files: list[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class TaskResponse(BaseModel):
    id: str
    project_id: str
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
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class TaskDetailResponse(TaskResponse):
    overall_progress: Optional[B2SOverallProgress] = None
    items: list[TaskItemResponse] = Field(default_factory=list)


class TaskListResponse(BaseModel):
    total: int
    items: list[TaskResponse]


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
