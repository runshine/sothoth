"""Pydantic schemas for firmware unpacker API."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class UnpackRequest(BaseModel):
    firmware_path: str
    output_path: str
    project_id: Optional[str] = None


class TaskSubmitResponse(BaseModel):
    task_id: str
    status: str
    message: str


class ActionResponse(BaseModel):
    message: str
    task_id: Optional[str] = None
    new_task_id: Optional[str] = None
    deleted_count: Optional[int] = None
    skipped_ids: Optional[List[str]] = None


class BatchDeleteRequest(BaseModel):
    task_ids: List[str]


class ConfigUpdateRequest(BaseModel):
    value: str
    description: Optional[str] = None


class ConfigBatchUpdateItem(BaseModel):
    key: str
    value: str
    description: Optional[str] = None


class TaskResponse(BaseModel):
    id: str
    project_id: Optional[str]
    firmware_path: str
    output_path: str
    status: str
    worker_id: Optional[str] = None
    result_status: Optional[str] = None
    result_message: Optional[str] = None
    rounds: Optional[int] = None
    error_message: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    class Config:
        from_attributes = True


class TaskListResponse(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[TaskResponse]


class WorkerInstanceResponse(BaseModel):
    worker_id: str
    hostname: Optional[str] = None
    pod_ip: Optional[str] = None
    started_at: Optional[str] = None
    last_heartbeat: Optional[str] = None
    is_alive: bool
    active_tasks: int


class ClusterInfoResponse(BaseModel):
    this_worker: str
    total_workers: int
    alive_workers: int
    workers: List[WorkerInstanceResponse]
    task_counts: dict[str, int]
    total_tasks: int


class ConfigEntryResponse(BaseModel):
    key: str
    value: str
    value_type: str
    description: Optional[str] = None
    updated_at: Optional[str] = None


class ConfigListResponse(BaseModel):
    total: int
    items: List[ConfigEntryResponse]


class HealthResponse(BaseModel):
    status: str
    worker_id: Optional[str] = None


class ReadyResponse(BaseModel):
    status: str
    worker_id: Optional[str] = None
