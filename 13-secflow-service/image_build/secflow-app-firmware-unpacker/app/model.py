"""Database models for firmware unpacker service."""

from __future__ import annotations

import enum
import hashlib
import os
import socket
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_config
from app.time_utils import isoformat_local, now_local


Base = declarative_base()


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    RETRY_PREPARING = "retry_preparing"
    ARCHIVE_PENDING = "archive_pending"
    ARCHIVING = "archiving"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    SUCCESS = "success"
    FAILED = "failed"


TERMINAL_STATUSES = {
    TaskStatus.CANCELLED,
    TaskStatus.SUCCESS,
    TaskStatus.FAILED,
}


def is_terminal(status: str) -> bool:
    return status in {item.value for item in TERMINAL_STATUSES}


class UnpackTask(Base):
    __tablename__ = "secflow_app_firmware_unpacker_unpack_tasks"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(64), nullable=True, index=True)
    task_origin_type = Column(String(32), nullable=True, index=True)
    parent_project_id = Column(String(64), nullable=True, index=True)
    parent_task_id = Column(String(64), nullable=True, index=True)
    parent_task_type = Column(String(32), nullable=True)
    parent_stage_name = Column(String(64), nullable=True)
    parent_stage_item_id = Column(String(64), nullable=True)
    parent_stage_item_key = Column(String(255), nullable=True)
    firmware_path = Column(String(512), nullable=False)
    output_path = Column(String(512), nullable=False)
    status = Column(
        String(32),
        nullable=False,
        default=TaskStatus.PENDING.value,
        index=True,
    )
    owner_id = Column(String(96), nullable=True, index=True)
    dispatch_token = Column(String(64), nullable=True, index=True)
    dispatch_owner_id = Column(String(96), nullable=True, index=True)
    dispatch_claimed_at = Column(DateTime, nullable=True, index=True)
    dispatch_lease_expires_at = Column(DateTime, nullable=True, index=True)
    heartbeat_at = Column(DateTime, nullable=True, index=True)
    current_stage = Column(String(64), nullable=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    cancel_requested_at = Column(DateTime, nullable=True)
    last_progress_at = Column(DateTime, nullable=True)
    runner_pid = Column(Integer, nullable=True, index=True)
    runner_started_at = Column(DateTime, nullable=True)
    runner_heartbeat_at = Column(DateTime, nullable=True)
    run_token = Column(String(64), nullable=True, index=True)
    cancel_grace_deadline = Column(DateTime, nullable=True)
    cancel_force_deadline = Column(DateTime, nullable=True)
    result_status = Column(String(32), nullable=True)
    result_message = Column(Text, nullable=True)
    rounds = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    matched_skill = Column(String(512), nullable=True)
    matched_skill_version = Column(Integer, nullable=True)
    matched_skill_score = Column(Integer, nullable=True)
    fallback_to_llm = Column(Boolean, nullable=False, default=False)
    generated_skill_path = Column(String(512), nullable=True)
    generated_skill_status = Column(String(32), nullable=True)
    archive_root = Column(String(512), nullable=True)
    runtime_root = Column(String(512), nullable=True)
    archive_status = Column(String(32), nullable=True, index=True)
    archive_error_message = Column(Text, nullable=True)
    archive_started_at = Column(DateTime, nullable=True)
    archive_completed_at = Column(DateTime, nullable=True)
    promotion_success_count = Column(Integer, nullable=True)
    skill_generation_status = Column(String(32), nullable=True)
    skill_generation_error = Column(Text, nullable=True)
    skill_generation_job_id = Column(String(32), nullable=True, index=True)
    skill_generation_started_at = Column(DateTime, nullable=True)
    skill_generation_completed_at = Column(DateTime, nullable=True)
    latest_evolution_job_id = Column(String(32), nullable=True, index=True)
    latest_evolution_status = Column(String(32), nullable=True)
    latest_evolution_started_at = Column(DateTime, nullable=True)
    latest_evolution_completed_at = Column(DateTime, nullable=True)
    latest_evolution_final_skill_path = Column(String(512), nullable=True)
    llm_binding_snapshot = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_local)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        task_origin_type = str(self.task_origin_type or "").strip() or "manual"
        parent_task_type = str(self.parent_task_type or "").strip() or None
        if task_origin_type == "binary_security":
            origin_label = "二进制安全-源码扫描" if parent_task_type == "source" else "二进制安全-二进制类扫描"
        else:
            origin_label = "手动任务"
        return {
            "id": self.id,
            "project_id": self.project_id,
            "task_origin_type": task_origin_type,
            "parent_project_id": self.parent_project_id,
            "parent_task_id": self.parent_task_id,
            "parent_task_type": parent_task_type,
            "parent_stage_name": self.parent_stage_name,
            "parent_stage_item_id": self.parent_stage_item_id,
            "parent_stage_item_key": self.parent_stage_item_key,
            "origin_label": origin_label,
            "parent_task_display": self.parent_task_id,
            "firmware_path": self.firmware_path,
            "output_path": self.output_path,
            "status": self.status,
            "owner_id": self.owner_id,
            "dispatch_token": self.dispatch_token,
            "dispatch_owner_id": self.dispatch_owner_id,
            "dispatch_claimed_at": isoformat_local(self.dispatch_claimed_at),
            "dispatch_lease_expires_at": isoformat_local(self.dispatch_lease_expires_at),
            "heartbeat_at": isoformat_local(self.heartbeat_at),
            "current_stage": self.current_stage,
            "lease_expires_at": isoformat_local(self.lease_expires_at),
            "cancel_requested_at": isoformat_local(self.cancel_requested_at),
            "last_progress_at": isoformat_local(self.last_progress_at),
            "runner_pid": self.runner_pid,
            "runner_started_at": isoformat_local(self.runner_started_at),
            "runner_heartbeat_at": isoformat_local(self.runner_heartbeat_at),
            "cancel_grace_deadline": isoformat_local(self.cancel_grace_deadline),
            "cancel_force_deadline": isoformat_local(self.cancel_force_deadline),
            "result_status": self.result_status,
            "result_message": self.result_message,
            "rounds": self.rounds,
            "error_message": self.error_message,
            "matched_skill": self.matched_skill,
            "matched_skill_version": self.matched_skill_version,
            "matched_skill_score": self.matched_skill_score,
            "fallback_to_llm": self.fallback_to_llm,
            "generated_skill_path": self.generated_skill_path,
            "generated_skill_status": self.generated_skill_status,
            "archive_root": self.archive_root,
            "runtime_root": self.runtime_root,
            "archive_status": self.archive_status,
            "archive_error_message": self.archive_error_message,
            "archive_started_at": isoformat_local(self.archive_started_at),
            "archive_completed_at": isoformat_local(self.archive_completed_at),
            "promotion_success_count": self.promotion_success_count,
            "skill_generation_status": self.skill_generation_status,
            "skill_generation_error": self.skill_generation_error,
            "skill_generation_job_id": self.skill_generation_job_id,
            "skill_generation_started_at": isoformat_local(self.skill_generation_started_at),
            "skill_generation_completed_at": isoformat_local(self.skill_generation_completed_at),
            "latest_evolution_job_id": self.latest_evolution_job_id,
            "latest_evolution_status": self.latest_evolution_status,
            "latest_evolution_started_at": isoformat_local(self.latest_evolution_started_at),
            "latest_evolution_completed_at": isoformat_local(self.latest_evolution_completed_at),
            "latest_evolution_final_skill_path": self.latest_evolution_final_skill_path,
            "created_at": isoformat_local(self.created_at),
            "started_at": isoformat_local(self.started_at),
            "completed_at": isoformat_local(self.completed_at),
        }


class WorkerInstance(Base):
    __tablename__ = "secflow_app_firmware_unpacker_worker_instances"

    worker_id = Column(String(96), primary_key=True)
    hostname = Column(String(128), nullable=True)
    pod_ip = Column(String(64), nullable=True)
    started_at = Column(DateTime, default=now_local)
    last_heartbeat = Column(DateTime, default=now_local)
    is_alive = Column(Boolean, default=True)
    active_tasks = Column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "owner_id": self.worker_id,
            "hostname": self.hostname,
            "pod_ip": self.pod_ip,
            "started_at": isoformat_local(self.started_at),
            "last_heartbeat": isoformat_local(self.last_heartbeat),
            "is_alive": self.is_alive,
            "active_tasks": self.active_tasks,
        }


class ServiceConfig(Base):
    __tablename__ = "secflow_app_firmware_unpacker_service_configs"

    key = Column(String(128), primary_key=True)
    value = Column(Text, nullable=False)
    value_type = Column(String(32), nullable=False, default="string")
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "value_type": self.value_type,
            "description": self.description,
            "updated_at": isoformat_local(self.updated_at),
        }


class UnpackTaskEvent(Base):
    __tablename__ = "secflow_app_firmware_unpacker_task_events"

    id = Column(String(32), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    stage_key = Column(String(64), nullable=True, index=True)
    status = Column(String(32), nullable=True, index=True)
    summary = Column(Text, nullable=False)
    detail_json = Column(Text, nullable=True)
    owner_id = Column(String(96), nullable=True, index=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_local, index=True)

    def to_dict(self) -> dict:
        detail = None
        if self.detail_json:
            try:
                import json

                detail = json.loads(self.detail_json)
            except Exception:
                detail = {"raw": self.detail_json}
        return {
            "id": self.id,
            "task_id": self.task_id,
            "project_id": self.project_id,
            "event_type": self.event_type,
            "stage_key": self.stage_key,
            "status": self.status,
            "summary": self.summary,
            "detail": detail,
            "owner_id": self.owner_id,
            "created_by": self.created_by,
            "created_at": isoformat_local(self.created_at),
        }


class WorkspaceCleanupJob(Base):
    __tablename__ = "secflow_app_firmware_unpacker_workspace_cleanup_jobs"

    id = Column(String(32), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    owner_id = Column(String(96), nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    reason = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "project_id": self.project_id,
            "status": self.status,
            "owner_id": self.owner_id,
            "lease_expires_at": isoformat_local(self.lease_expires_at),
            "attempts": self.attempts,
            "reason": self.reason,
            "error_message": self.error_message,
            "created_by": self.created_by,
            "created_at": isoformat_local(self.created_at),
            "started_at": isoformat_local(self.started_at),
            "completed_at": isoformat_local(self.completed_at),
        }


class SkillGenerationJob(Base):
    __tablename__ = "secflow_app_firmware_unpacker_skill_generation_jobs"

    id = Column(String(32), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    owner_id = Column(String(96), nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "project_id": self.project_id,
            "status": self.status,
            "owner_id": self.owner_id,
            "lease_expires_at": isoformat_local(self.lease_expires_at),
            "attempts": self.attempts,
            "error_message": self.error_message,
            "created_by": self.created_by,
            "created_at": isoformat_local(self.created_at),
            "started_at": isoformat_local(self.started_at),
            "completed_at": isoformat_local(self.completed_at),
        }


class FirmwareEvolutionJob(Base):
    __tablename__ = "secflow_app_firmware_unpacker_evolution_jobs"

    id = Column(String(32), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    current_round = Column(Integer, nullable=True)
    max_rounds = Column(Integer, nullable=False, default=3)
    current_stage = Column(String(32), nullable=True, index=True)
    owner_id = Column(String(96), nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    final_skill_path = Column(String(512), nullable=True)
    replaced_skill_path = Column(String(512), nullable=True)
    review_passed = Column(Boolean, nullable=False, default=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "project_id": self.project_id,
            "status": self.status,
            "current_round": self.current_round,
            "max_rounds": self.max_rounds,
            "current_stage": self.current_stage,
            "owner_id": self.owner_id,
            "lease_expires_at": isoformat_local(self.lease_expires_at),
            "attempts": self.attempts,
            "error_message": self.error_message,
            "created_by": self.created_by,
            "created_at": isoformat_local(self.created_at),
            "started_at": isoformat_local(self.started_at),
            "completed_at": isoformat_local(self.completed_at),
            "final_skill_path": self.final_skill_path,
            "replaced_skill_path": self.replaced_skill_path,
            "review_passed": bool(self.review_passed),
        }


class FirmwareEvolutionRound(Base):
    __tablename__ = "secflow_app_firmware_unpacker_evolution_rounds"

    id = Column(String(32), primary_key=True)
    job_id = Column(String(32), nullable=False, index=True)
    round = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False, index=True)
    tool_skill_path_before = Column(String(512), nullable=True)
    tool_skill_path_after = Column(String(512), nullable=True)
    tool_changed = Column(Boolean, nullable=False, default=False)
    review_result = Column(Text, nullable=True)
    summary_path = Column(String(512), nullable=True)
    reason_path = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "round": self.round,
            "status": self.status,
            "tool_skill_path_before": self.tool_skill_path_before,
            "tool_skill_path_after": self.tool_skill_path_after,
            "tool_changed": bool(self.tool_changed),
            "review_result": self.review_result,
            "summary_path": self.summary_path,
            "reason_path": self.reason_path,
            "created_at": isoformat_local(self.created_at),
            "completed_at": isoformat_local(self.completed_at),
        }


DEFAULT_CONFIGS = [
    ("concurrency_mode", "auto", "string", "并发控制模式：auto=按 Pod CPU/内存自动计算，manual=手动指定"),
    ("manual_max_concurrent", "3", "int", "手动模式下单个 Pod 最大并发解包任务数"),
    ("cpu_millis_per_task", "250", "int", "自动模式下单个解包任务预估占用 CPU(millicores)"),
    ("memory_mb_per_task", "512", "int", "自动模式下单个解包任务预估占用内存(MiB)"),
    ("reserved_cpu_millis", "100", "int", "自动模式下为 Pod 自身保留的 CPU(millicores)"),
    ("reserved_memory_mb", "256", "int", "自动模式下为 Pod 自身保留的内存(MiB)"),
    ("max_concurrent", "3", "int", "兼容旧版本：单个 Worker 最大并发解包任务数"),
    ("max_retries", "5", "int", "pi agent 最大重试轮数"),
    ("agent_run_timeout_seconds", "3600", "int", "单次智能体输入最大运行时长（秒），-1=不限制"),
    ("agent_timeout_retry_enabled", "true", "bool", "单次智能体输入超时后是否自动重试"),
    ("agent_timeout_max_retries", "3", "int", "单次智能体输入超时后的最大自动重试次数，-1=无限"),
    ("max_retries_reached_action", "success", "string", "达到最大重试轮数后默认动作：success=按通过处理，failed=按失败处理"),
    ("reuse_agent_between_rounds", "true", "bool", "兼容旧版的全局轮次间智能体复用策略；新版本请改用各角色独立配置"),
    ("reuse_agent_between_rounds_executor", "true", "bool", "不同重试轮次之间是否复用固件解包通用执行器智能体会话：true=复用，false=每轮新建"),
    ("reuse_agent_between_rounds_reviewer", "true", "bool", "不同重试轮次之间是否复用固件解包评审器智能体会话：true=复用，false=每轮新建"),
    ("reuse_agent_between_rounds_cleaner", "true", "bool", "是否复用固件解包清理器智能体会话：true=复用，false=每次新建"),
    ("reuse_agent_between_rounds_skill_author", "true", "bool", "是否复用固件解包技能生成器智能体会话：true=复用，false=每次新建"),
    ("reuse_agent_between_rounds_skill_executor", "true", "bool", "是否复用固件解包命中技能执行器智能体会话：true=复用，false=每次新建"),
    ("reuse_agent_between_rounds_evolution_improver", "true", "bool", "是否复用固件解包工具进化器智能体会话：true=复用，false=每次新建"),
    ("dead_threshold", "300", "int", "Worker 心跳超时秒数"),
    ("auto_cleanup_days", "7", "int", "已完成任务自动清理天数"),
    ("task_lease_seconds", "45", "int", "已废弃：任务执行不再使用租约，仅兼容清理任务配置"),
    ("task_lease_renew_interval_seconds", "10", "int", "已废弃：任务执行不再续租，保留用于旧配置兼容"),
    ("cancel_timeout_seconds", "120", "int", "任务取消最长等待秒数"),
    ("cancel_grace_seconds", "10", "int", "取消后发送 SIGTERM 的宽限秒数"),
    ("cancel_force_seconds", "30", "int", "取消后强制 SIGKILL 的最长等待秒数"),
    ("llm_config_file_key_executor", "", "string", "固件解包通用执行器角色绑定的 models.json 配置文件 key"),
    ("llm_model_executor", "", "string", "固件解包通用执行器角色绑定的模型；留空则使用配置文件默认模型"),
    ("llm_config_file_key_reviewer", "", "string", "固件解包评审器角色绑定的 models.json 配置文件 key"),
    ("llm_model_reviewer", "", "string", "固件解包评审器角色绑定的模型；留空则使用配置文件默认模型"),
    ("llm_config_file_key_cleaner", "", "string", "固件解包清理器角色绑定的 models.json 配置文件 key"),
    ("llm_model_cleaner", "", "string", "固件解包清理器角色绑定的模型；留空则使用配置文件默认模型"),
    ("llm_config_file_key_skill_author", "", "string", "固件解包技能生成器角色绑定的 models.json 配置文件 key"),
    ("llm_model_skill_author", "", "string", "固件解包技能生成器角色绑定的模型；留空则使用配置文件默认模型"),
    ("llm_config_file_key_skill_executor", "", "string", "固件解包命中技能执行器角色绑定的 models.json 配置文件 key"),
    ("llm_model_skill_executor", "", "string", "固件解包命中技能执行器角色绑定的模型；留空则使用配置文件默认模型"),
    ("llm_config_file_key_evolution_improver", "", "string", "固件解包工具进化器角色绑定的 models.json 配置文件 key"),
    ("llm_model_evolution_improver", "", "string", "固件解包工具进化器角色绑定的模型；留空则使用配置文件默认模型"),
]


_engine = None
_SessionFactory = None
_OWNER_ID = None
_WORKER_ID_MAX_LEN = 64


def get_engine():
    global _engine
    if _engine is None:
        database = get_config().database
        kwargs = {
            "pool_pre_ping": True,
            "pool_recycle": 1800,
        }
        if database.type == "sqlite":
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            kwargs["pool_size"] = database.pool_size
            kwargs["max_overflow"] = database.max_overflow
        _engine = create_engine(database.url, **kwargs)
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            bind=get_engine(),
        )
    return _SessionFactory


def get_db():
    session_local = get_session_factory()
    db = session_local()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    return get_session_factory()()


def apply_table_prefix_if_needed() -> None:
    prefix = get_config().database.table_prefix
    UnpackTask.__table__.name = f"{prefix}unpack_tasks"
    WorkerInstance.__table__.name = f"{prefix}worker_instances"
    ServiceConfig.__table__.name = f"{prefix}service_configs"
    UnpackTaskEvent.__table__.name = f"{prefix}task_events"
    WorkspaceCleanupJob.__table__.name = f"{prefix}workspace_cleanup_jobs"
    SkillGenerationJob.__table__.name = f"{prefix}skill_generation_jobs"
    FirmwareEvolutionJob.__table__.name = f"{prefix}evolution_jobs"
    FirmwareEvolutionRound.__table__.name = f"{prefix}evolution_rounds"


def init_database() -> None:
    apply_table_prefix_if_needed()
    Base.metadata.create_all(bind=get_engine())
    _ensure_unpack_task_columns()
    _seed_default_configs()


def _ensure_unpack_task_columns() -> None:
    engine = get_engine()
    inspector = inspect(engine)
    try:
        columns = {column["name"] for column in inspector.get_columns(UnpackTask.__table__.name)}
    except Exception:
        return

    statements = {
        "task_origin_type": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN task_origin_type VARCHAR(32)",
        "parent_project_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN parent_project_id VARCHAR(64)",
        "parent_task_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN parent_task_id VARCHAR(64)",
        "parent_task_type": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN parent_task_type VARCHAR(32)",
        "parent_stage_name": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN parent_stage_name VARCHAR(64)",
        "parent_stage_item_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN parent_stage_item_id VARCHAR(64)",
        "parent_stage_item_key": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN parent_stage_item_key VARCHAR(255)",
        "owner_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN owner_id VARCHAR(96)",
        "dispatch_token": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN dispatch_token VARCHAR(64)",
        "dispatch_owner_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN dispatch_owner_id VARCHAR(96)",
        "dispatch_claimed_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN dispatch_claimed_at DATETIME",
        "dispatch_lease_expires_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN dispatch_lease_expires_at DATETIME",
        "heartbeat_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN heartbeat_at DATETIME",
        "current_stage": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN current_stage VARCHAR(64)",
        "lease_expires_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN lease_expires_at DATETIME",
        "cancel_requested_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN cancel_requested_at DATETIME",
        "last_progress_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN last_progress_at DATETIME",
        "runner_pid": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN runner_pid INTEGER",
        "runner_started_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN runner_started_at DATETIME",
        "runner_heartbeat_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN runner_heartbeat_at DATETIME",
        "run_token": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN run_token VARCHAR(64)",
        "cancel_grace_deadline": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN cancel_grace_deadline DATETIME",
        "cancel_force_deadline": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN cancel_force_deadline DATETIME",
        "matched_skill": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN matched_skill VARCHAR(512)",
        "matched_skill_version": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN matched_skill_version INTEGER",
        "matched_skill_score": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN matched_skill_score INTEGER",
        "fallback_to_llm": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN fallback_to_llm BOOLEAN DEFAULT 0",
        "generated_skill_path": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN generated_skill_path VARCHAR(512)",
        "generated_skill_status": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN generated_skill_status VARCHAR(32)",
        "archive_root": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN archive_root VARCHAR(512)",
        "runtime_root": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN runtime_root VARCHAR(512)",
        "archive_status": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN archive_status VARCHAR(32)",
        "archive_error_message": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN archive_error_message TEXT",
        "archive_started_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN archive_started_at DATETIME",
        "archive_completed_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN archive_completed_at DATETIME",
        "promotion_success_count": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN promotion_success_count INTEGER",
        "skill_generation_status": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN skill_generation_status VARCHAR(32)",
        "skill_generation_error": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN skill_generation_error TEXT",
        "skill_generation_job_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN skill_generation_job_id VARCHAR(32)",
        "skill_generation_started_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN skill_generation_started_at DATETIME",
        "skill_generation_completed_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN skill_generation_completed_at DATETIME",
        "latest_evolution_job_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN latest_evolution_job_id VARCHAR(32)",
        "latest_evolution_status": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN latest_evolution_status VARCHAR(32)",
        "latest_evolution_started_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN latest_evolution_started_at DATETIME",
        "latest_evolution_completed_at": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN latest_evolution_completed_at DATETIME",
        "latest_evolution_final_skill_path": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN latest_evolution_final_skill_path VARCHAR(512)",
        "llm_binding_snapshot": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN llm_binding_snapshot TEXT",
    }

    with engine.begin() as conn:
        for column_name, statement in statements.items():
            if column_name in columns:
                continue
            conn.execute(text(statement))
    indexes = {index["name"] for index in inspector.get_indexes(UnpackTask.__table__.name)}
    index_statements = []
    if "ix_fu_tasks_project_created_id" not in indexes:
        index_statements.append(
            f"CREATE INDEX ix_fu_tasks_project_created_id ON {UnpackTask.__table__.name} (project_id, created_at, id)"
        )
    if "ix_fu_tasks_project_status_created_id" not in indexes:
        index_statements.append(
            f"CREATE INDEX ix_fu_tasks_project_status_created_id ON {UnpackTask.__table__.name} (project_id, status, created_at, id)"
        )
    if "ix_fu_tasks_owner_created_id" not in indexes:
        index_statements.append(
            f"CREATE INDEX ix_fu_tasks_owner_created_id ON {UnpackTask.__table__.name} (owner_id, created_at, id)"
        )
    if "ix_fu_tasks_status_created_id" not in indexes:
        index_statements.append(
            f"CREATE INDEX ix_fu_tasks_status_created_id ON {UnpackTask.__table__.name} (status, created_at, id)"
        )
    if "ix_fu_tasks_dispatch_owner_created_id" not in indexes:
        index_statements.append(
            f"CREATE INDEX ix_fu_tasks_dispatch_owner_created_id ON {UnpackTask.__table__.name} (dispatch_owner_id, created_at, id)"
        )
    if "ix_fu_tasks_dispatch_status_created_id" not in indexes:
        index_statements.append(
            f"CREATE INDEX ix_fu_tasks_dispatch_status_created_id ON {UnpackTask.__table__.name} (status, dispatch_claimed_at, id)"
        )
    with engine.begin() as conn:
        for statement in index_statements:
            conn.execute(text(statement))


def _seed_default_configs() -> None:
    db = get_db_session()
    try:
        for key, value, value_type, description in DEFAULT_CONFIGS:
            existing = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
            if existing:
                continue
            db.add(
                ServiceConfig(
                    key=key,
                    value=value,
                    value_type=value_type,
                    description=description,
                )
            )
        db.commit()
    finally:
        db.close()


def generate_id() -> str:
    raw = f"{uuid.uuid4()}_{now_local().timestamp()}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _normalize_worker_id(raw_value: str) -> str:
    normalized = str(raw_value or "").strip() or "unknown-worker"
    if len(normalized) <= _WORKER_ID_MAX_LEN:
        return normalized
    digest = hashlib.md5(normalized.encode()).hexdigest()[:8]
    keep = max(8, _WORKER_ID_MAX_LEN - len(digest) - 1)
    return f"{normalized[:keep]}-{digest}"[:_WORKER_ID_MAX_LEN]


def get_worker_id() -> str:
    global _OWNER_ID
    if _OWNER_ID is not None:
        return _OWNER_ID

    owner_id = os.environ.get("WORKER_ID")
    if owner_id:
        _OWNER_ID = _normalize_worker_id(owner_id)
        return _OWNER_ID

    pod_name = (os.environ.get("HOSTNAME") or socket.gethostname()).strip() or "unknown-pod"
    pid = os.getpid()
    digest = hashlib.md5(f"{pod_name}:{pid}".encode()).hexdigest()[:8]
    _OWNER_ID = _normalize_worker_id(f"{pod_name}-{digest}")
    return _OWNER_ID


def get_config_value(db: Session, key: str, default=None):
    row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
    if not row:
        return default
    if row.value_type == "int":
        try:
            return int(row.value)
        except ValueError:
            return default
    if row.value_type == "bool":
        return row.value.lower() in ("1", "true", "yes")
    return row.value
