"""Pydantic schemas."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ElfTaskInput(BaseModel):
    elf_path: str = Field(..., description="ELF 在共享PVC中的绝对路径")
    file_list: List[str] = Field(default_factory=list, description="相关文件路径列表")
    output_subdir: Optional[str] = Field(None, description="可选输出子目录")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BinaryToSourceTaskCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = None
    priority: int = 5
    tags: List[str] = Field(default_factory=list)
    elf_tasks: List[ElfTaskInput] = Field(default_factory=list)


class BinaryToSourceTaskPatchRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = None
    priority: Optional[int] = None
    tags: Optional[List[str]] = None


class RetryRequest(BaseModel):
    item_ids: Optional[List[str]] = Field(None, description="为空表示重试该任务下全部可重试子任务")


class TaskItemResponse(BaseModel):
    id: str
    parent_task_id: str
    project_id: str
    sequence_no: int
    elf_path: str
    file_list: List[str]
    output_dir: str
    status: str
    failure_type: Optional[str]
    error_reason: Optional[str]
    result_message: Optional[str]
    generated_files: List[str]
    raw_payload: Dict[str, Any]
    worker_id: Optional[str]
    worker_queue: Optional[str]
    celery_task_id: Optional[str]
    attempt_count: int
    auto_retry_count: int
    manual_retry_count: int
    can_auto_retry: bool
    queued_at: Optional[str]
    started_at: Optional[str]
    finished_at: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]


class TaskResponse(BaseModel):
    id: str
    project_id: str
    name: str
    description: Optional[str]
    priority: int
    tags: List[str]
    status: str
    created_by: Optional[str]
    total_items: int
    pending_items: int
    queued_items: int
    running_items: int
    success_items: int
    partial_items: int
    failed_items: int
    cancelled_items: int
    result_summary: Dict[str, Any]
    error_summary: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]
    started_at: Optional[str]
    finished_at: Optional[str]
    cancel_requested_at: Optional[str]


class TaskDetailResponse(TaskResponse):
    items: List[TaskItemResponse] = Field(default_factory=list)


class TaskListResponse(BaseModel):
    total: int
    items: List[TaskResponse]


class TaskCreatedResponse(BaseModel):
    message: str
    task_id: str


class ActionResponse(BaseModel):
    message: str
    task_id: str


class SuccessResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
