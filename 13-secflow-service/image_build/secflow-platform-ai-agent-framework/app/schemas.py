from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.contracts import TaskItem


class WorkflowDefinitionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = None
    project_id: str
    definition_json: Dict[str, Any]
    trigger_type: str = "manual"
    trigger_enabled: bool = False
    is_active: bool = False
    enabled: bool = True
    max_concurrency: int = Field(default=1, ge=1)
    priority_default: int = 100
    workspace_base_dir: Optional[str] = None
    execution_timeout_seconds: int = Field(default=7200, ge=1)


class WorkflowDefinitionUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    definition_json: Optional[Dict[str, Any]] = None
    trigger_type: Optional[str] = None
    trigger_enabled: Optional[bool] = None
    is_active: Optional[bool] = None
    enabled: Optional[bool] = None
    max_concurrency: Optional[int] = Field(default=None, ge=1)
    priority_default: Optional[int] = None
    workspace_base_dir: Optional[str] = None
    execution_timeout_seconds: Optional[int] = Field(default=None, ge=1)


class WorkflowDefinitionResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    project_id: str
    root_workflow_id: Optional[str] = None
    trigger_type: str
    trigger_enabled: bool
    is_active: bool
    enabled: bool
    max_concurrency: int
    priority_default: int
    workspace_base_dir: Optional[str]
    execution_timeout_seconds: int
    entry_input_task_type: Optional[str] = None
    final_output_task_type: Optional[str] = None
    definition_valid: bool = True
    validation_error: Optional[str] = None
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class WorkflowDefinitionVersionResponse(BaseModel):
    id: str
    workflow_definition_id: str
    version_no: int
    created_by: str
    created_at: datetime
    definition_json: Dict[str, Any]


class TriggerTaskCreate(BaseModel):
    input_tasks: List["TriggerTaskInputTask"]
    priority: Optional[int] = None


class TriggerTaskInputTask(BaseModel):
    task_id: Optional[str] = None
    task_type: Optional[str] = None
    title: str = Field(..., min_length=1)
    task_markdown: Optional[str] = None
    task_md_path: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    upstream_refs: List[str] = Field(default_factory=list)


class TriggerTaskInputPreview(TaskItem):
    task_input_dir: Optional[str] = None


class TriggerTaskResponse(BaseModel):
    id: str
    workflow_definition_id: str
    project_id: str
    trigger_type: str
    priority: int
    status: str
    submitted_by: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    message: Optional[str]
    created_at: datetime
    updated_at: datetime


class WorkflowExecutionResponse(BaseModel):
    id: str
    trigger_task_id: str
    workflow_definition_id: str
    project_id: str
    status: str
    workspace_root: Optional[str]
    output_manifest_path: Optional[str]
    output_task_count: int
    current_stage_id: Optional[str]
    owner_pod_id: Optional[str]
    lease_expires_at: Optional[datetime]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    message: Optional[str]
    created_at: datetime
    updated_at: datetime


class WorkflowExecutionEventResponse(BaseModel):
    id: str
    execution_id: str
    event_type: str
    stage_id: Optional[str]
    round_no: Optional[int]
    level: str
    message: str
    payload_json: Optional[Dict[str, Any]]
    created_at: datetime


class SchedulerWorkerResponse(BaseModel):
    pod_id: str
    host_name: str
    capacity: int
    running_count: int
    last_heartbeat_at: datetime
    status: str
    metadata_json: Optional[Dict[str, Any]]


class SuccessResponse(BaseModel):
    success: bool = True
    message: str


class HealthResponse(BaseModel):
    status: str
    pod_id: str
    database: str
    scheduler: str
