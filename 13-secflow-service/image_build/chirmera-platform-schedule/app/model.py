"""Database models for chirmera-platform-schedule."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text, UniqueConstraint, create_engine, inspect, text
from sqlalchemy.dialects.mysql import JSON as MySQLJSON
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.types import JSON

from app.config import get_config


Base = declarative_base()
TABLE_PREFIX = get_config().database.table_prefix


def generate_id() -> str:
    return uuid.uuid4().hex[:24]


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ScheduleJob(Base):
    __tablename__ = f"{TABLE_PREFIX}schedule_job"
    __table_args__ = (
        UniqueConstraint("project_id", "name", name=f"uk_{TABLE_PREFIX}schedule_job_project_name"),
    )

    id = Column(String(64), primary_key=True, default=generate_id)
    project_id = Column(String(128), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    trigger_type = Column(String(32), nullable=False, default="manual")
    cron_expr = Column(String(128), nullable=True)
    interval_seconds = Column(Integer, nullable=True)
    timezone = Column(String(64), nullable=False, default="UTC")
    target_method = Column(String(16), nullable=False, default="POST")
    target_url = Column(String(1024), nullable=False)
    target_headers = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    target_query = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    target_body_template = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    auth_mode = Column(String(32), nullable=False, default="machine_token")
    static_bearer_token = Column(Text, nullable=True)
    success_status_codes = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=list)
    response_task_id_path = Column(String(256), nullable=True)
    dedupe_window_seconds = Column(Integer, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=1)
    max_concurrency = Column(Integer, nullable=False, default=1)
    dispatch_timeout_seconds = Column(Integer, nullable=True)
    retry_policy = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    target_bucket = Column(String(128), nullable=True)
    misfire_policy = Column(String(32), nullable=False, default="fire_once")
    paused_until = Column(DateTime, nullable=True)
    deleted = Column(Boolean, nullable=False, default=False, index=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True, index=True)
    created_by = Column(String(128), nullable=False)
    updated_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ScheduleExecution(Base):
    __tablename__ = f"{TABLE_PREFIX}schedule_execution"
    __table_args__ = (
        UniqueConstraint("project_id", "schedule_job_id", "dedupe_key", name=f"uk_{TABLE_PREFIX}schedule_execution_dedupe"),
        Index(f"idx_{TABLE_PREFIX}exec_status_created", "status", "created_at"),
        Index(f"idx_{TABLE_PREFIX}exec_status_retry", "status", "retry_at", "lease_expire_at"),
        Index(f"idx_{TABLE_PREFIX}exec_job_status", "schedule_job_id", "status"),
        Index(f"idx_{TABLE_PREFIX}exec_proj_target_status", "project_id", "target_bucket", "status"),
    )

    id = Column(String(64), primary_key=True, default=generate_id)
    schedule_job_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(128), nullable=False, index=True)
    trigger_source = Column(String(32), nullable=False, default="manual")
    status = Column(String(32), nullable=False, default="queued", index=True)
    scheduled_for = Column(DateTime, nullable=True, index=True)
    dedupe_key = Column(String(255), nullable=False, default="", index=True)
    attempt_no = Column(Integer, nullable=False, default=1)
    lease_owner = Column(String(255), nullable=True, index=True)
    lease_token = Column(String(255), nullable=True, index=True)
    lease_expire_at = Column(DateTime, nullable=True, index=True)
    heartbeat_at = Column(DateTime, nullable=True)
    reserved_at = Column(DateTime, nullable=True, index=True)
    worker_pod = Column(String(255), nullable=True)
    target_bucket = Column(String(128), nullable=True, index=True)
    retry_at = Column(DateTime, nullable=True, index=True)
    capacity_reject_count = Column(Integer, nullable=False, default=0)
    capacity_reject_reason = Column(String(128), nullable=True)
    capacity_reject_at = Column(DateTime, nullable=True, index=True)
    result_code = Column(String(64), nullable=True)
    result_reason = Column(Text, nullable=True)
    request_snapshot = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    response_snapshot = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    http_status = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    downstream_task_id = Column(String(128), nullable=True)
    downstream_task_name = Column(String(256), nullable=True)
    trace_id = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ScheduleExecutionEvent(Base):
    __tablename__ = f"{TABLE_PREFIX}schedule_execution_event"

    id = Column(String(64), primary_key=True, default=generate_id)
    execution_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    event_source = Column(String(32), nullable=False, default="api")
    attempt_no = Column(Integer, nullable=True)
    lease_token = Column(String(255), nullable=True)
    message = Column(Text, nullable=False)
    payload = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class LiteLLMVirtualKey(Base):
    __tablename__ = f"{TABLE_PREFIX}litellm_virtual_key"

    id = Column(String(64), primary_key=True, default=generate_id)
    project_id = Column(String(128), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    alias = Column(String(128), nullable=True)
    status = Column(String(32), nullable=False, default="active", index=True)
    litellm_key_id = Column(String(256), nullable=True, index=True)
    key_suffix = Column(String(32), nullable=True)
    key_hash = Column(String(128), nullable=True)
    models = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=list)
    metadata_json = Column("metadata", JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    budget_config = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    sync_status = Column(String(32), nullable=False, default="synced")
    remote_status = Column(String(64), nullable=True)
    last_error = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    last_synced_at = Column(DateTime, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    created_by = Column(String(128), nullable=False)
    updated_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class LiteLLMKeyEvent(Base):
    __tablename__ = f"{TABLE_PREFIX}litellm_key_event"

    id = Column(String(64), primary_key=True, default=generate_id)
    virtual_key_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    payload = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ScheduleUserTask(Base):
    __tablename__ = f"{TABLE_PREFIX}user_task"
    __table_args__ = (
        Index(f"idx_{TABLE_PREFIX}user_task_project_status", "project_id", "create_status", "dispatch_status"),
        Index(f"idx_{TABLE_PREFIX}user_task_project_display", "project_id", "display_status", "updated_at"),
        Index(f"idx_{TABLE_PREFIX}user_task_sync_status_next", "sync_required", "sync_status", "next_sync_at"),
        Index(f"idx_{TABLE_PREFIX}user_task_sync_queue_next", "sync_queue", "sync_status", "next_sync_at"),
        Index(f"idx_{TABLE_PREFIX}user_task_sync_lease", "sync_status", "sync_lease_expires_at"),
        Index(f"idx_{TABLE_PREFIX}user_task_task_type_sync", "task_type", "sync_required", "next_sync_at"),
    )

    id = Column(String(64), primary_key=True, default=generate_id)
    project_id = Column(String(128), nullable=False, index=True)
    task_type = Column(String(32), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    module_name = Column(String(255), nullable=True)
    create_status = Column(String(32), nullable=False, default="created")
    dispatch_status = Column(String(32), nullable=False, default="ready_for_dispatch")
    business_status = Column(String(32), nullable=False, default="created")
    parent_task_key_id = Column(String(64), nullable=False)
    parent_task_key_name = Column(String(255), nullable=False)
    parent_task_key_prefix = Column(String(128), nullable=False)
    parent_task_capacity_pool_ids = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=list)
    parent_task_key_secret_cipher = Column(Text, nullable=False)
    parent_task_key_secret_nonce = Column(String(128), nullable=False)
    parent_task_key_secret_version = Column(String(32), nullable=False, default="aesgcm-v1")
    downstream_task_id = Column(String(128), nullable=True, index=True)
    downstream_detail_view = Column(String(128), nullable=True)
    downstream_status_raw = Column(String(64), nullable=True)
    downstream_status_mapped = Column(String(64), nullable=True)
    downstream_report_ready = Column(Boolean, nullable=False, default=False)
    display_status = Column(String(32), nullable=False, default="queued", index=True)
    sync_status = Column(String(32), nullable=False, default="none", index=True)
    sync_queue = Column(String(32), nullable=True, index=True)
    sync_required = Column(Boolean, nullable=False, default=False, index=True)
    sync_policy_key = Column(String(64), nullable=True)
    last_synced_at = Column(DateTime, nullable=True)
    last_sync_started_at = Column(DateTime, nullable=True)
    next_sync_at = Column(DateTime, nullable=True, index=True)
    sync_attempt_count = Column(Integer, nullable=False, default=0)
    sync_consecutive_error_count = Column(Integer, nullable=False, default=0)
    sync_worker_id = Column(String(128), nullable=True, index=True)
    sync_lease_token = Column(String(255), nullable=True, index=True)
    sync_lease_expires_at = Column(DateTime, nullable=True, index=True)
    last_sync_error = Column(Text, nullable=True)
    last_sync_http_status = Column(Integer, nullable=True)
    sync_priority = Column(Integer, nullable=False, default=100)
    delete_status = Column(String(32), nullable=False, default="none", index=True)
    delete_error = Column(Text, nullable=True)
    delete_requested_at = Column(DateTime, nullable=True)
    delete_started_at = Column(DateTime, nullable=True)
    delete_finished_at = Column(DateTime, nullable=True)
    delete_attempt_count = Column(Integer, nullable=False, default=0)
    delete_worker_id = Column(String(128), nullable=True)
    delete_lease_expires_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=False)
    updated_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ScheduleUserTaskInputBinding(Base):
    __tablename__ = f"{TABLE_PREFIX}user_task_input_binding"
    __table_args__ = (
        Index(f"idx_{TABLE_PREFIX}user_task_input_binding_task", "user_task_id"),
        UniqueConstraint("user_task_id", "input_upload_id", name="uk_cps_utib_task_input"),
    )

    id = Column(String(64), primary_key=True, default=generate_id)
    user_task_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(128), nullable=False, index=True)
    input_upload_id = Column(String(64), nullable=False, index=True)
    input_type = Column(String(32), nullable=False, index=True)
    input_label = Column(String(255), nullable=False)
    target_path = Column(String(1024), nullable=False)
    latest_batch_id = Column(String(64), nullable=True)
    keep_original = Column(Boolean, nullable=False, default=False)
    selection_type = Column(String(32), nullable=True)
    relative_path = Column(String(1024), nullable=True)
    relative_paths = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=list)
    resolved_path = Column(String(1024), nullable=True)
    display_name = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ScheduleUserTaskDispatch(Base):
    __tablename__ = f"{TABLE_PREFIX}user_task_dispatch"
    __table_args__ = (
        Index(f"idx_{TABLE_PREFIX}user_task_dispatch_task", "user_task_id", "created_at"),
    )

    id = Column(String(64), primary_key=True, default=generate_id)
    user_task_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(128), nullable=False, index=True)
    dispatch_status = Column(String(32), nullable=False, default="pending")
    dispatched_task_key_id = Column(String(64), nullable=True)
    dispatched_task_key_name = Column(String(255), nullable=True)
    dispatched_task_key_prefix = Column(String(128), nullable=True)
    dispatched_task_capacity_pool_ids = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=list)
    dispatched_task_key_secret_cipher = Column(Text, nullable=True)
    dispatched_task_key_secret_nonce = Column(String(128), nullable=True)
    dispatched_task_key_secret_version = Column(String(32), nullable=True)
    downstream_task_id = Column(String(128), nullable=True)
    downstream_detail_view = Column(String(128), nullable=True)
    downstream_status_raw = Column(String(64), nullable=True)
    downstream_status_mapped = Column(String(64), nullable=True)
    downstream_report_ready = Column(Boolean, nullable=False, default=False)
    last_error = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class ScheduleRuntimeConfig(Base):
    __tablename__ = f"{TABLE_PREFIX}runtime_config"
    __table_args__ = (
        UniqueConstraint("config_key", name=f"uk_{TABLE_PREFIX}runtime_config_key"),
    )

    id = Column(String(64), primary_key=True, default=generate_id)
    config_key = Column(String(64), nullable=False, default="global_default")
    scheduler_policy_json = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    tool_defaults_json = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    time_windows_json = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=list)
    timezone = Column(String(64), nullable=False, default="Asia/Shanghai")
    version = Column(Integer, nullable=False, default=1)
    updated_by = Column(String(128), nullable=False, default="system")
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        config = get_config()
        engine_kwargs = {"pool_pre_ping": True}
        database_url = config.database.database_url
        if not database_url.startswith("sqlite"):
            engine_kwargs["pool_size"] = config.database.pool_size
            engine_kwargs["max_overflow"] = config.database.max_overflow
        _engine = create_engine(database_url, **engine_kwargs)
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionFactory


def init_database():
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _ensure_schedule_execution_columns(engine)
    _ensure_user_task_constraints(engine)
    _ensure_user_task_columns(engine)
    _ensure_user_task_dispatch_columns(engine)
    _ensure_runtime_config_columns(engine)


def _ensure_schedule_execution_columns(engine) -> None:
    inspector = inspect(engine)
    if ScheduleExecution.__tablename__ not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns(ScheduleExecution.__tablename__)}
    statements: list[str] = []
    if "reserved_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleExecution.__tablename__} ADD COLUMN reserved_at DATETIME NULL")
    if "capacity_reject_count" not in columns:
        statements.append(f"ALTER TABLE {ScheduleExecution.__tablename__} ADD COLUMN capacity_reject_count INTEGER NOT NULL DEFAULT 0")
    if "capacity_reject_reason" not in columns:
        statements.append(f"ALTER TABLE {ScheduleExecution.__tablename__} ADD COLUMN capacity_reject_reason VARCHAR(128) NULL")
    if "capacity_reject_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleExecution.__tablename__} ADD COLUMN capacity_reject_at DATETIME NULL")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _ensure_user_task_constraints(engine) -> None:
    inspector = inspect(engine)
    if ScheduleUserTask.__tablename__ not in inspector.get_table_names():
        return
    indexes = {index["name"] for index in inspector.get_indexes(ScheduleUserTask.__tablename__)}
    unique_constraints = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints(ScheduleUserTask.__tablename__)
        if constraint.get("name")
    }
    legacy_unique_name = f"uk_{TABLE_PREFIX}user_task_project_name"
    statements: list[str] = []
    if legacy_unique_name in unique_constraints or legacy_unique_name in indexes:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} DROP INDEX {legacy_unique_name}")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _ensure_user_task_columns(engine) -> None:
    inspector = inspect(engine)
    if ScheduleUserTask.__tablename__ not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns(ScheduleUserTask.__tablename__)}
    statements: list[str] = []
    if "downstream_status_raw" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN downstream_status_raw VARCHAR(64) NULL")
    if "downstream_status_mapped" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN downstream_status_mapped VARCHAR(64) NULL")
    if "downstream_report_ready" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN downstream_report_ready BOOLEAN NOT NULL DEFAULT 0"
        )
    if "display_status" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN display_status VARCHAR(32) NOT NULL DEFAULT 'queued'"
        )
    if "sync_status" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_status VARCHAR(32) NOT NULL DEFAULT 'none'"
        )
    if "sync_queue" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_queue VARCHAR(32) NULL")
    if "sync_required" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_required BOOLEAN NOT NULL DEFAULT 0"
        )
    if "sync_policy_key" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_policy_key VARCHAR(64) NULL")
    if "last_synced_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN last_synced_at DATETIME NULL")
    if "last_sync_started_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN last_sync_started_at DATETIME NULL")
    if "next_sync_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN next_sync_at DATETIME NULL")
    if "sync_attempt_count" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_attempt_count INTEGER NOT NULL DEFAULT 0"
        )
    if "sync_consecutive_error_count" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_consecutive_error_count INTEGER NOT NULL DEFAULT 0"
        )
    if "sync_worker_id" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_worker_id VARCHAR(128) NULL")
    if "sync_lease_token" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_lease_token VARCHAR(255) NULL")
    if "sync_lease_expires_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_lease_expires_at DATETIME NULL")
    if "last_sync_error" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN last_sync_error TEXT NULL")
    if "last_sync_http_status" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN last_sync_http_status INTEGER NULL")
    if "sync_priority" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN sync_priority INTEGER NOT NULL DEFAULT 100"
        )
    if "delete_status" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_status VARCHAR(32) NOT NULL DEFAULT 'none'"
        )
    if "delete_error" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_error TEXT NULL")
    if "delete_requested_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_requested_at DATETIME NULL")
    if "delete_started_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_started_at DATETIME NULL")
    if "delete_finished_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_finished_at DATETIME NULL")
    if "delete_attempt_count" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_attempt_count INTEGER NOT NULL DEFAULT 0"
        )
    if "delete_worker_id" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_worker_id VARCHAR(128) NULL")
    if "delete_lease_expires_at" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTask.__tablename__} ADD COLUMN delete_lease_expires_at DATETIME NULL")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _ensure_user_task_dispatch_columns(engine) -> None:
    inspector = inspect(engine)
    if ScheduleUserTaskDispatch.__tablename__ not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns(ScheduleUserTaskDispatch.__tablename__)}
    statements: list[str] = []
    if "downstream_status_raw" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTaskDispatch.__tablename__} ADD COLUMN downstream_status_raw VARCHAR(64) NULL")
    if "downstream_status_mapped" not in columns:
        statements.append(f"ALTER TABLE {ScheduleUserTaskDispatch.__tablename__} ADD COLUMN downstream_status_mapped VARCHAR(64) NULL")
    if "downstream_report_ready" not in columns:
        statements.append(
            f"ALTER TABLE {ScheduleUserTaskDispatch.__tablename__} ADD COLUMN downstream_report_ready BOOLEAN NOT NULL DEFAULT 0"
        )
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _ensure_runtime_config_columns(engine) -> None:
    inspector = inspect(engine)
    if ScheduleRuntimeConfig.__tablename__ not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns(ScheduleRuntimeConfig.__tablename__)}
    statements: list[str] = []
    if "timezone" not in columns:
        statements.append(f"ALTER TABLE {ScheduleRuntimeConfig.__tablename__} ADD COLUMN timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Shanghai'")
    if "version" not in columns:
        statements.append(f"ALTER TABLE {ScheduleRuntimeConfig.__tablename__} ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
    if "updated_by" not in columns:
        statements.append(f"ALTER TABLE {ScheduleRuntimeConfig.__tablename__} ADD COLUMN updated_by VARCHAR(128) NOT NULL DEFAULT 'system'")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def get_db():
    session_local = get_session_factory()
    db = session_local()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    return get_session_factory()()
