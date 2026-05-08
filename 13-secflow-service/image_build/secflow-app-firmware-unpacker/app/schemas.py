"""Pydantic schemas for firmware unpacker API."""

from __future__ import annotations

from typing import Any, List, Optional

from pydantic import BaseModel


class UnpackRequest(BaseModel):
    firmware_path: str
    output_path: Optional[str] = None
    project_id: Optional[str] = None


class TaskSubmitResponse(BaseModel):
    task_id: str
    status: str
    message: str
    input_path: Optional[str] = None
    output_path: Optional[str] = None
    run_path: Optional[str] = None


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
    matched_skill: Optional[str] = None
    matched_skill_version: Optional[int] = None
    matched_skill_score: Optional[int] = None
    fallback_to_llm: bool = False
    generated_skill_path: Optional[str] = None
    generated_skill_status: Optional[str] = None
    promotion_success_count: Optional[int] = None
    agentflow_run_id: Optional[str] = None
    node_attempts: Optional[dict[str, Any]] = None
    failure_summary: Optional[dict[str, Any]] = None
    total_tokens: Optional[int] = None
    engine_error: Optional[str] = None
    run_path: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    class Config:
        from_attributes = True


class TaskResourceContainerResponse(BaseModel):
    name: Optional[str] = None
    cpu_millicores: int
    memory_mib: int


class TaskResourceUsageResponse(BaseModel):
    task_id: str
    worker_id: Optional[str] = None
    available: bool
    pod_name: Optional[str] = None
    namespace: Optional[str] = None
    phase: Optional[str] = None
    timestamp: Optional[str] = None
    window: Optional[str] = None
    cpu_millicores: Optional[int] = None
    memory_mib: Optional[int] = None
    pod_cpu_limit_millicores: Optional[int] = None
    pod_memory_limit_mib: Optional[int] = None
    containers: List[TaskResourceContainerResponse] = []
    message: Optional[str] = None


class TaskProgressPhaseResponse(BaseModel):
    key: str
    label: str
    status: str
    detail: Optional[str] = None
    updated_at: Optional[str] = None


class TaskProgressResponse(BaseModel):
    task_id: str
    current_phase: Optional[str] = None
    summary: Optional[str] = None
    phases: List[TaskProgressPhaseResponse]


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


class ConcurrencyInfoResponse(BaseModel):
    mode: str
    resource_based: bool
    effective_max_concurrent: int
    executor_capacity: int
    manual_max_concurrent: int
    auto_max_concurrent: int
    cpu_based_limit: Optional[int] = None
    memory_based_limit: Optional[int] = None
    cpu_millis_per_task: int
    memory_mb_per_task: int
    reserved_cpu_millis: int
    reserved_memory_mb: int
    pod_cpu_limit_millicores: Optional[int] = None
    pod_memory_limit_mib: Optional[int] = None
    pod_cpu_request_millicores: Optional[int] = None
    pod_memory_request_mib: Optional[int] = None


class ClusterInfoResponse(BaseModel):
    this_worker: str
    total_workers: int
    alive_workers: int
    workers: List[WorkerInstanceResponse]
    task_counts: dict[str, int]
    total_tasks: int
    concurrency: ConcurrencyInfoResponse


class ConfigEntryResponse(BaseModel):
    key: str
    value: str
    value_type: str
    description: Optional[str] = None
    updated_at: Optional[str] = None


class ConfigListResponse(BaseModel):
    total: int
    items: List[ConfigEntryResponse]


class ToolEntryResponse(BaseModel):
    filename: str
    path: str
    name: str
    format_id: str
    description: str
    extensions: List[str]
    magic_hex: str
    keywords: List[str]
    binwalk_sigs: List[str]
    skill_status: str
    skill_version: int
    family_id: str
    promotion_success_count: int
    promotion_threshold: int


class ToolListResponse(BaseModel):
    total: int
    items: List[ToolEntryResponse]


class HealthResponse(BaseModel):
    status: str
    worker_id: Optional[str] = None


class ReadyResponse(BaseModel):
    status: str
    worker_id: Optional[str] = None
