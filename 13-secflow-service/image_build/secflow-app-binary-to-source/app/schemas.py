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
    name: str
    description: Optional[str] = None
    priority: int = 5
    tags: list[str] = Field(default_factory=list)
    elf_tasks: list[ElfTaskInput]


class RetryRequest(BaseModel):
    item_ids: Optional[list[str]] = None


class TaskItemResponse(BaseModel):
    id: str
    sequence_no: int
    elf_path: str
    output_dir: str
    status: str
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
    items: list[TaskItemResponse] = Field(default_factory=list)


class TaskListResponse(BaseModel):
    total: int
    items: list[TaskResponse]


class ActionResponse(BaseModel):
    status: str
    task_id: Optional[str] = None
    message: Optional[str] = None
