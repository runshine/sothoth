from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_config

Base = declarative_base()
_engine = None
_SessionFactory = None


def now_utc() -> datetime:
    return datetime.utcnow()


def _prefix(name: str) -> str:
    return f"{get_config().database.table_prefix}{name}"


class WorkflowDefinition(Base):
    __tablename__ = _prefix("workflow_definition")

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    description = Column(Text)
    project_id = Column(String(64), nullable=False, index=True)
    template_kind = Column(String(64), nullable=False, default="vuln_scan_default")
    config_payload_json = Column(JSON, nullable=False, default=dict)
    definition_json = Column(JSON, nullable=False)
    root_workflow_id = Column(String(128), nullable=False)
    trigger_type = Column(String(16), nullable=False, default="manual")
    trigger_enabled = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=False)
    is_default = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    max_concurrency = Column(Integer, nullable=False, default=1)
    priority_default = Column(Integer, nullable=False, default=100)
    max_retry_count = Column(Integer, nullable=False, default=3)
    workspace_base_dir = Column(String(512))
    execution_timeout_seconds = Column(Integer, nullable=False, default=7200)
    created_by = Column(String(128), nullable=False)
    updated_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class WorkflowDefinitionVersion(Base):
    __tablename__ = _prefix("workflow_definition_version")

    id = Column(String(64), primary_key=True)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False, index=True)
    version_no = Column(Integer, nullable=False)
    config_payload_json = Column(JSON, nullable=False, default=dict)
    compiled_config_json = Column(JSON, nullable=False, default=dict)
    definition_json = Column(JSON, nullable=False)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=now_utc)


class TriggerTask(Base):
    __tablename__ = _prefix("trigger_task")

    id = Column(String(64), primary_key=True)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False, index=True)
    workflow_definition_version_id = Column(String(64), ForeignKey(f"{WorkflowDefinitionVersion.__tablename__}.id"), nullable=True, index=True)
    profile_id = Column(String(64), nullable=True, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    trigger_type = Column(String(16), nullable=False, default="manual")
    input_tasks_json = Column(JSON, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    status = Column(String(32), nullable=False, default="pending", index=True)
    submitted_by = Column(String(128), nullable=False)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retry_count = Column(Integer, nullable=False, default=3)
    latest_execution_id = Column(String(64), nullable=True, index=True)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    message = Column(Text)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class WorkflowExecution(Base):
    __tablename__ = _prefix("workflow_execution")

    id = Column(String(64), primary_key=True)
    trigger_task_id = Column(String(64), ForeignKey(f"{TriggerTask.__tablename__}.id"), nullable=False, index=True)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False, index=True)
    workflow_definition_version_id = Column(String(64), ForeignKey(f"{WorkflowDefinitionVersion.__tablename__}.id"), nullable=True, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    attempt_no = Column(Integer, nullable=False, default=1)
    status = Column(String(32), nullable=False, default="pending", index=True)
    recovery_reason = Column(String(255))
    workspace_root = Column(String(1024))
    output_manifest_path = Column(String(1024))
    output_task_count = Column(Integer, nullable=False, default=0)
    current_stage_id = Column(String(128))
    owner_pod_id = Column(String(128), index=True)
    lease_token = Column(String(128))
    lease_expires_at = Column(DateTime, index=True)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    message = Column(Text)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class WorkflowExecutionEvent(Base):
    __tablename__ = _prefix("workflow_execution_event")

    id = Column(String(64), primary_key=True)
    execution_id = Column(String(64), ForeignKey(f"{WorkflowExecution.__tablename__}.id"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    stage_id = Column(String(128))
    round_no = Column(Integer)
    level = Column(String(16), nullable=False, default="info")
    message = Column(Text, nullable=False)
    payload_json = Column(JSON)
    created_at = Column(DateTime, default=now_utc, index=True)


class SchedulerWorker(Base):
    __tablename__ = _prefix("scheduler_worker")

    pod_id = Column(String(128), primary_key=True)
    host_name = Column(String(256), nullable=False)
    capacity = Column(Integer, nullable=False, default=1)
    running_count = Column(Integer, nullable=False, default=0)
    last_heartbeat_at = Column(DateTime, default=now_utc, index=True)
    status = Column(String(16), nullable=False, default="active", index=True)
    metadata_json = Column(JSON)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


Index(f"ix_{WorkflowExecution.__tablename__}_definition_status", WorkflowExecution.workflow_definition_id, WorkflowExecution.status)
Index(f"ix_{WorkflowExecution.__tablename__}_trigger_attempt", WorkflowExecution.trigger_task_id, WorkflowExecution.attempt_no, unique=True)
Index(f"ix_{TriggerTask.__tablename__}_definition_status", TriggerTask.workflow_definition_id, TriggerTask.status)
Index(f"ix_{WorkflowDefinition.__tablename__}_project_default", WorkflowDefinition.project_id, WorkflowDefinition.is_default)
Index(f"ix_{WorkflowDefinitionVersion.__tablename__}_definition_version", WorkflowDefinitionVersion.workflow_definition_id, WorkflowDefinitionVersion.version_no, unique=True)


def get_engine():
    global _engine
    if _engine is None:
        config = get_config()
        kwargs = {"pool_pre_ping": True}
        url = config.database.sqlalchemy_url
        if not url.startswith("sqlite"):
            kwargs.update({
                "pool_size": config.database.pool_size,
                "max_overflow": config.database.max_overflow,
            })
        else:
            kwargs["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(url, **kwargs)
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionFactory


def _column_exists(inspector, table_name: str, column_name: str) -> bool:
    return column_name in {column["name"] for column in inspector.get_columns(table_name)}


def _index_exists(inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _column_sql(dialect: str, sqltype: str) -> str:
    if dialect == "sqlite" and sqltype == "JSON":
        return "TEXT"
    return sqltype


def run_auto_migrations() -> None:
    engine = get_engine()
    dialect = engine.dialect.name
    tables = {
        "workflow_definition": WorkflowDefinition.__tablename__,
        "workflow_definition_version": WorkflowDefinitionVersion.__tablename__,
        "trigger_task": TriggerTask.__tablename__,
        "workflow_execution": WorkflowExecution.__tablename__,
    }

    column_migrations = [
        (tables["workflow_definition"], "template_kind", f"ALTER TABLE {tables['workflow_definition']} ADD COLUMN template_kind VARCHAR(64) NOT NULL DEFAULT 'vuln_scan_default'"),
        (tables["workflow_definition"], "config_payload_json", f"ALTER TABLE {tables['workflow_definition']} ADD COLUMN config_payload_json {_column_sql(dialect, 'JSON')} NULL"),
        (tables["workflow_definition"], "is_default", f"ALTER TABLE {tables['workflow_definition']} ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT FALSE"),
        (tables["workflow_definition"], "max_retry_count", f"ALTER TABLE {tables['workflow_definition']} ADD COLUMN max_retry_count INTEGER NOT NULL DEFAULT 3"),
        (tables["workflow_definition_version"], "config_payload_json", f"ALTER TABLE {tables['workflow_definition_version']} ADD COLUMN config_payload_json {_column_sql(dialect, 'JSON')} NULL"),
        (tables["workflow_definition_version"], "compiled_config_json", f"ALTER TABLE {tables['workflow_definition_version']} ADD COLUMN compiled_config_json {_column_sql(dialect, 'JSON')} NULL"),
        (tables["trigger_task"], "workflow_definition_version_id", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN workflow_definition_version_id VARCHAR(64) NULL"),
        (tables["trigger_task"], "profile_id", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN profile_id VARCHAR(64) NULL"),
        (tables["trigger_task"], "retry_count", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0"),
        (tables["trigger_task"], "max_retry_count", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN max_retry_count INTEGER NOT NULL DEFAULT 3"),
        (tables["trigger_task"], "latest_execution_id", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN latest_execution_id VARCHAR(64) NULL"),
        (tables["workflow_execution"], "workflow_definition_version_id", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN workflow_definition_version_id VARCHAR(64) NULL"),
        (tables["workflow_execution"], "attempt_no", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN attempt_no INTEGER NOT NULL DEFAULT 1"),
        (tables["workflow_execution"], "recovery_reason", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN recovery_reason VARCHAR(255) NULL"),
    ]
    index_migrations = [
        (tables["workflow_definition"], f"ix_{WorkflowDefinition.__tablename__}_project_default", f"CREATE INDEX ix_{WorkflowDefinition.__tablename__}_project_default ON {tables['workflow_definition']} (project_id, is_default)"),
        (tables["workflow_definition_version"], f"ix_{WorkflowDefinitionVersion.__tablename__}_definition_version", f"CREATE UNIQUE INDEX ix_{WorkflowDefinitionVersion.__tablename__}_definition_version ON {tables['workflow_definition_version']} (workflow_definition_id, version_no)"),
        (tables["workflow_execution"], f"ix_{WorkflowExecution.__tablename__}_trigger_attempt", f"CREATE UNIQUE INDEX ix_{WorkflowExecution.__tablename__}_trigger_attempt ON {tables['workflow_execution']} (trigger_task_id, attempt_no)"),
    ]

    with engine.begin() as connection:
        inspector = inspect(connection)
        for table_name, column_name, sql in column_migrations:
            if table_name not in inspector.get_table_names():
                continue
            if _column_exists(inspector, table_name, column_name):
                continue
            connection.execute(text(sql))
            inspector = inspect(connection)

        # Backfill newly added columns for old rows.
        if tables["workflow_definition"] in inspector.get_table_names():
            if _column_exists(inspector, tables["workflow_definition"], "config_payload_json"):
                connection.execute(text(
                    f"UPDATE {tables['workflow_definition']} "
                    "SET config_payload_json = definition_json "
                    "WHERE config_payload_json IS NULL"
                ))
            if _column_exists(inspector, tables["workflow_definition"], "template_kind"):
                connection.execute(text(
                    f"UPDATE {tables['workflow_definition']} "
                    "SET template_kind = 'vuln_scan_default' "
                    "WHERE template_kind IS NULL OR template_kind = ''"
                ))
            if _column_exists(inspector, tables['workflow_definition'], 'max_retry_count'):
                connection.execute(text(
                    f"UPDATE {tables['workflow_definition']} "
                    "SET max_retry_count = 3 WHERE max_retry_count IS NULL OR max_retry_count < 0"
                ))

        if tables["workflow_definition_version"] in inspector.get_table_names():
            if _column_exists(inspector, tables["workflow_definition_version"], "config_payload_json"):
                connection.execute(text(
                    f"UPDATE {tables['workflow_definition_version']} "
                    "SET config_payload_json = definition_json "
                    "WHERE config_payload_json IS NULL"
                ))
            if _column_exists(inspector, tables["workflow_definition_version"], "compiled_config_json"):
                connection.execute(text(
                    f"UPDATE {tables['workflow_definition_version']} "
                    "SET compiled_config_json = definition_json "
                    "WHERE compiled_config_json IS NULL"
                ))

        if tables["trigger_task"] in inspector.get_table_names():
            if _column_exists(inspector, tables["trigger_task"], "profile_id"):
                connection.execute(text(
                    f"UPDATE {tables['trigger_task']} "
                    "SET profile_id = workflow_definition_id "
                    "WHERE profile_id IS NULL OR profile_id = ''"
                ))
            if _column_exists(inspector, tables["trigger_task"], "latest_execution_id"):
                connection.execute(text(
                    f"UPDATE {tables['trigger_task']} "
                    "SET latest_execution_id = ("
                    f"SELECT e.id FROM {tables['workflow_execution']} e "
                    f"WHERE e.trigger_task_id = {tables['trigger_task']}.id "
                    "ORDER BY e.created_at DESC LIMIT 1"
                    ") "
                    "WHERE latest_execution_id IS NULL"
                ))

        if tables["workflow_execution"] in inspector.get_table_names():
            if _column_exists(inspector, tables["workflow_execution"], "attempt_no"):
                connection.execute(text(
                    f"UPDATE {tables['workflow_execution']} "
                    "SET attempt_no = 1 WHERE attempt_no IS NULL OR attempt_no = 0"
                ))

        inspector = inspect(connection)
        for table_name, index_name, sql in index_migrations:
            if table_name not in inspector.get_table_names():
                continue
            if _index_exists(inspector, table_name, index_name):
                continue
            connection.execute(text(sql))
            inspector = inspect(connection)


def init_database() -> None:
    Base.metadata.create_all(bind=get_engine())
    run_auto_migrations()


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    return get_session_factory()()


def reset_database_state() -> None:
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None
