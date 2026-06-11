"""Pydantic schemas for chirmera-platform-schedule."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


TriggerType = Literal["cron", "interval", "manual"]
AuthMode = Literal["none", "bearer_passthrough", "machine_token", "static_bearer"]
MisfirePolicy = Literal["skip", "fire_once", "catch_up_limited"]


class TokenUser(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    token_type: Optional[str] = None


class MessageResponse(BaseModel):
    message: str


class ScheduleJobBase(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    name: str
    description: Optional[str] = None
    enabled: bool = True
    trigger_type: TriggerType = "manual"
    cron_expr: Optional[str] = None
    interval_seconds: Optional[int] = None
    timezone: str = "UTC"
    target_method: str = "POST"
    target_url: str
    target_headers: dict[str, Any] = Field(default_factory=dict)
    target_query: dict[str, Any] = Field(default_factory=dict)
    target_body_template: dict[str, Any] = Field(default_factory=dict)
    auth_mode: AuthMode = "machine_token"
    static_bearer_token: Optional[str] = None
    success_status_codes: list[int] = Field(default_factory=lambda: [200, 201, 202])
    response_task_id_path: Optional[str] = None
    dedupe_window_seconds: int = 0
    max_concurrency: int = 1
    dispatch_timeout_seconds: Optional[int] = None
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    target_bucket: Optional[str] = None
    misfire_policy: MisfirePolicy = "fire_once"
    paused_until: Optional[datetime] = None

    @field_validator("name", "target_url")
    @classmethod
    def validate_required(cls, value: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise ValueError("字段不能为空")
        return value

    @field_validator("target_method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        normalized = str(value or "").strip().upper()
        if normalized not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("target_method 不支持")
        return normalized

    @field_validator("interval_seconds")
    @classmethod
    def validate_interval(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value <= 0:
            raise ValueError("interval_seconds 必须大于 0")
        return value

    @field_validator("dedupe_window_seconds")
    @classmethod
    def validate_dedupe(cls, value: int) -> int:
        if value < 0:
            raise ValueError("dedupe_window_seconds 不能小于 0")
        return value

    @field_validator("max_concurrency")
    @classmethod
    def validate_max_concurrency(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max_concurrency 必须大于 0")
        return value


class ScheduleJobCreate(ScheduleJobBase):
    pass


class ScheduleJobUpdate(ScheduleJobBase):
    pass


class ScheduleJobResponse(ScheduleJobBase):
    id: str
    project_id: str
    version: int = 1
    deleted: bool = False
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    inflight_count: int = 0
    last_execution_status: Optional[str] = None
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class ScheduleJobListResponse(BaseModel):
    total: int
    items: list[ScheduleJobResponse]


class ScheduleExecutionResponse(BaseModel):
    id: str
    schedule_job_id: str
    project_id: str
    trigger_source: str
    status: str
    scheduled_for: Optional[datetime] = None
    dedupe_key: str
    attempt_no: int = 1
    lease_owner: Optional[str] = None
    lease_expire_at: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    reserved_at: Optional[datetime] = None
    worker_pod: Optional[str] = None
    target_bucket: Optional[str] = None
    retry_at: Optional[datetime] = None
    capacity_reject_count: int = 0
    capacity_reject_reason: Optional[str] = None
    capacity_reject_at: Optional[datetime] = None
    result_code: Optional[str] = None
    result_reason: Optional[str] = None
    request_snapshot: dict[str, Any]
    response_snapshot: dict[str, Any]
    http_status: Optional[int] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    downstream_task_id: Optional[str] = None
    downstream_task_name: Optional[str] = None
    trace_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ScheduleExecutionListResponse(BaseModel):
    total: int
    items: list[ScheduleExecutionResponse]


class ScheduleExecutionEventResponse(BaseModel):
    id: str
    execution_id: str
    event_type: str
    event_source: str
    attempt_no: Optional[int] = None
    lease_token: Optional[str] = None
    message: str
    payload: dict[str, Any]
    created_at: datetime


class ManualTriggerPayload(BaseModel):
    trigger_source: str = "manual"
    force: bool = False


class RuntimeOverviewResponse(BaseModel):
    queue: dict[str, Any]
    leader: dict[str, Any]
    workers: dict[str, Any]
    stats: dict[str, Any]
    redis_available: bool


class JobRuntimeResponse(BaseModel):
    job_id: str
    project_id: str
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    inflight_count: int
    queued_count: int = 0
    last_execution_status: Optional[str] = None
    recent_error_rate: float


class VirtualKeyBudgetConfig(BaseModel):
    max_budget: Optional[float] = None
    soft_budget: Optional[float] = None


class VirtualKeyCreate(BaseModel):
    name: str
    alias: Optional[str] = None
    models: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    duration: Optional[str] = None
    budget_config: VirtualKeyBudgetConfig = Field(default_factory=VirtualKeyBudgetConfig)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise ValueError("name 不能为空")
        return value


class VirtualKeyResponse(BaseModel):
    id: str
    project_id: str
    name: str
    alias: Optional[str] = None
    status: str
    litellm_key_id: Optional[str] = None
    key_suffix: Optional[str] = None
    models: list[str]
    metadata: dict[str, Any]
    budget_config: dict[str, Any]
    expires_at: Optional[datetime] = None
    last_synced_at: Optional[datetime] = None
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def model_validate(cls, obj, *, strict=None, from_attributes=None, context=None):
        if from_attributes and hasattr(obj, "metadata_json"):
            payload = {
                "id": obj.id,
                "project_id": obj.project_id,
                "name": obj.name,
                "alias": obj.alias,
                "status": obj.status,
                "litellm_key_id": obj.litellm_key_id,
                "key_suffix": obj.key_suffix,
                "models": obj.models,
                "metadata": obj.metadata_json,
                "budget_config": obj.budget_config,
                "expires_at": obj.expires_at,
                "last_synced_at": obj.last_synced_at,
                "created_by": obj.created_by,
                "updated_by": obj.updated_by,
                "created_at": obj.created_at,
                "updated_at": obj.updated_at,
            }
            return super().model_validate(payload, strict=strict, from_attributes=False, context=context)
        return super().model_validate(obj, strict=strict, from_attributes=from_attributes, context=context)


class VirtualKeyCreateResponse(VirtualKeyResponse):
    plain_text_key: Optional[str] = None


class VirtualKeyListResponse(BaseModel):
    total: int
    items: list[VirtualKeyResponse]


class VirtualKeyEventResponse(BaseModel):
    id: str
    virtual_key_id: str
    event_type: str
    payload: dict[str, Any]
    created_at: datetime


UserTaskType = Literal["binary_firmware_e2e", "source_scan_e2e", "binary_module_e2e", "ai4red", "ai4apk"]
InputSelectionType = Literal["file", "file_list", "directory"]


class UserTaskInputBindingResponse(BaseModel):
    input_upload_id: str
    input_type: str
    input_label: str
    target_path: str
    latest_batch_id: Optional[str] = None
    keep_original: bool = False
    selection_type: Optional[str] = None
    relative_path: Optional[str] = None
    relative_paths: list[str] = Field(default_factory=list)
    resolved_path: Optional[str] = None
    display_name: Optional[str] = None


class UserTaskInputBindingRequest(BaseModel):
    upload_id: str
    selection_type: InputSelectionType
    relative_path: Optional[str] = None
    relative_paths: list[str] = Field(default_factory=list)

    @field_validator("upload_id")
    @classmethod
    def validate_upload_id(cls, value: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise ValueError("upload_id 不能为空")
        return value

    @field_validator("relative_path")
    @classmethod
    def normalize_relative_path(cls, value: Optional[str]) -> Optional[str]:
        normalized = str(value or "").strip().replace("\\", "/")
        return normalized or None

    @field_validator("relative_paths")
    @classmethod
    def normalize_relative_paths(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in value or []:
            raw = str(item or "").strip().replace("\\", "/")
            if raw:
                normalized.append(raw)
        return normalized


class UserTaskCreateRequest(BaseModel):
    task_type: UserTaskType
    name: str
    description: Optional[str] = None
    input_upload_ids: list[str] = Field(default_factory=list)
    input_binding: Optional[UserTaskInputBindingRequest] = None
    policy: dict[str, Any] = Field(default_factory=dict)
    dispatch_policy: dict[str, Any] = Field(default_factory=dict)
    module_name: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        value = str(value or "").strip()
        if not value:
            raise ValueError("字段不能为空")
        return value


class UserTaskDispatchRequest(BaseModel):
    force: bool = False


class UserTaskDispatchResponse(BaseModel):
    id: str
    user_task_id: str
    project_id: str
    dispatch_status: str
    root_task_key_id: Optional[str] = None
    root_task_key_name: Optional[str] = None
    root_task_key_prefix: Optional[str] = None
    root_task_capacity_pool_ids: list[int] = Field(default_factory=list)
    dispatched_task_key_id: Optional[str] = None
    dispatched_task_key_name: Optional[str] = None
    dispatched_task_key_prefix: Optional[str] = None
    dispatched_task_capacity_pool_ids: list[int] = Field(default_factory=list)
    downstream_task_id: Optional[str] = None
    downstream_detail_view: Optional[str] = None
    downstream_status_raw: Optional[str] = None
    downstream_status_mapped: Optional[str] = None
    downstream_report_ready: bool = False
    last_error: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime




class UserTaskResponse(BaseModel):
    id: str
    project_id: str
    task_type: UserTaskType | str
    name: str
    description: Optional[str] = None
    create_status: str
    dispatch_status: str
    business_status: str
    input_upload_count: int = 0
    inputs: list[UserTaskInputBindingResponse] = Field(default_factory=list)
    parent_task_key_id: Optional[str] = None
    parent_task_key_name: Optional[str] = None
    parent_task_key_prefix: Optional[str] = None
    parent_task_capacity_pool_ids: list[int] = Field(default_factory=list)
    root_task_key_id: Optional[str] = None
    root_task_key_name: Optional[str] = None
    root_task_key_prefix: Optional[str] = None
    root_task_capacity_pool_ids: list[int] = Field(default_factory=list)
    dispatched_task_key_id: Optional[str] = None
    dispatched_task_key_name: Optional[str] = None
    dispatched_task_key_prefix: Optional[str] = None
    module_name: Optional[str] = None
    downstream_task_id: Optional[str] = None
    downstream_detail_view: Optional[str] = None
    downstream_status_raw: Optional[str] = None
    downstream_status_mapped: Optional[str] = None
    downstream_report_ready: bool = False
    last_error: Optional[str] = None
    created_by: str
    updated_at: datetime
    created_at: datetime


class UserTaskListResponse(BaseModel):
    total: int
    items: list[UserTaskResponse]
    stats: dict[str, int] = Field(default_factory=dict)


class UserTaskDispatchListResponse(BaseModel):
    total: int
    items: list[UserTaskDispatchResponse]
