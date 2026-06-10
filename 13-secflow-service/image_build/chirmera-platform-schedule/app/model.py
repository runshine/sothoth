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
        UniqueConstraint("project_id", "name", name=f"uk_{TABLE_PREFIX}user_task_project_name"),
        Index(f"idx_{TABLE_PREFIX}user_task_project_status", "project_id", "create_status", "dispatch_status"),
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
    task_key_ref = Column(String(255), nullable=False)
    active_work_key_prefix = Column(String(128), nullable=True)
    downstream_task_id = Column(String(128), nullable=True, index=True)
    downstream_detail_view = Column(String(128), nullable=True)
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
    task_key_ref = Column(String(255), nullable=False)
    work_key_id = Column(String(64), nullable=True)
    work_key_prefix = Column(String(128), nullable=True)
    work_key_secret = Column(Text, nullable=True)
    downstream_task_id = Column(String(128), nullable=True)
    downstream_detail_view = Column(String(128), nullable=True)
    last_error = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=False)
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
    _ensure_user_task_columns(engine)


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


def _ensure_user_task_columns(engine) -> None:
    inspector = inspect(engine)
    for table_name, columns_to_add in {
        ScheduleUserTask.__tablename__: {
            "module_name": "VARCHAR(255) NULL",
            "active_work_key_prefix": "VARCHAR(128) NULL",
            "downstream_task_id": "VARCHAR(128) NULL",
            "downstream_detail_view": "VARCHAR(128) NULL",
            "last_error": "TEXT NULL",
        },
        ScheduleUserTaskDispatch.__tablename__: {
            "work_key_id": "VARCHAR(64) NULL",
            "work_key_prefix": "VARCHAR(128) NULL",
            "work_key_secret": "TEXT NULL",
            "downstream_task_id": "VARCHAR(128) NULL",
            "downstream_detail_view": "VARCHAR(128) NULL",
            "last_error": "TEXT NULL",
        },
        ScheduleUserTaskInputBinding.__tablename__: {
            "selection_type": "VARCHAR(32) NULL",
            "relative_path": "VARCHAR(1024) NULL",
            "relative_paths": "JSON NULL",
            "resolved_path": "VARCHAR(1024) NULL",
            "display_name": "VARCHAR(255) NULL",
        },
    }.items():
        if table_name not in inspector.get_table_names():
            continue
        existing = {column["name"] for column in inspector.get_columns(table_name)}
        statements: list[str] = []
        for column_name, definition in columns_to_add.items():
            if column_name not in existing:
                statements.append(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")
        if statements:
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
