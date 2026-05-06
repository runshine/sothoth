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
    project_id = Column(String(64), nullable=False)
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
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False)
    version_no = Column(Integer, nullable=False)
    config_payload_json = Column(JSON, nullable=False, default=dict)
    compiled_config_json = Column(JSON, nullable=False, default=dict)
    definition_json = Column(JSON, nullable=False)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=now_utc)


class TriggerTask(Base):
    __tablename__ = _prefix("trigger_task")

    id = Column(String(64), primary_key=True)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False)
    workflow_definition_version_id = Column(String(64), ForeignKey(f"{WorkflowDefinitionVersion.__tablename__}.id"), nullable=True)
    profile_id = Column(String(64), nullable=True)
    project_id = Column(String(64), nullable=False)
    trigger_type = Column(String(16), nullable=False, default="manual")
    input_tasks_json = Column(JSON, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    status = Column(String(32), nullable=False, default="pending")
    submitted_by = Column(String(128), nullable=False)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retry_count = Column(Integer, nullable=False, default=3)
    latest_execution_id = Column(String(64), nullable=True)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    message = Column(Text)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class WorkflowExecution(Base):
    __tablename__ = _prefix("workflow_execution")

    id = Column(String(64), primary_key=True)
    trigger_task_id = Column(String(64), ForeignKey(f"{TriggerTask.__tablename__}.id"), nullable=False)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False)
    workflow_definition_version_id = Column(String(64), ForeignKey(f"{WorkflowDefinitionVersion.__tablename__}.id"), nullable=True)
    project_id = Column(String(64), nullable=False)
    attempt_no = Column(Integer, nullable=False, default=1)
    status = Column(String(32), nullable=False, default="pending")
    recovery_reason = Column(String(255))
    workspace_root = Column(String(1024))
    output_manifest_path = Column(String(1024))
    output_task_count = Column(Integer, nullable=False, default=0)
    current_stage_id = Column(String(128))
    owner_pod_id = Column(String(128))
    lease_token = Column(String(128))
    lease_expires_at = Column(DateTime)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    message = Column(Text)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class WorkflowExecutionEvent(Base):
    __tablename__ = _prefix("workflow_execution_event")

    id = Column(String(64), primary_key=True)
    execution_id = Column(String(64), ForeignKey(f"{WorkflowExecution.__tablename__}.id"), nullable=False)
    event_type = Column(String(64), nullable=False)
    stage_id = Column(String(128))
    round_no = Column(Integer)
    level = Column(String(16), nullable=False, default="info")
    message = Column(Text, nullable=False)
    payload_json = Column(JSON)
    created_at = Column(DateTime, default=now_utc)


class SchedulerWorker(Base):
    __tablename__ = _prefix("scheduler_worker")

    pod_id = Column(String(128), primary_key=True)
    host_name = Column(String(256), nullable=False)
    capacity = Column(Integer, nullable=False, default=1)
    running_count = Column(Integer, nullable=False, default=0)
    last_heartbeat_at = Column(DateTime, default=now_utc)
    status = Column(String(16), nullable=False, default="active")
    metadata_json = Column(JSON)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


INDEX_DEFINITIONS = [
    (WorkflowDefinition.__tablename__, "ix_dfvs_wfd_project", "CREATE INDEX ix_dfvs_wfd_project ON {table} (project_id)"),
    (WorkflowDefinition.__tablename__, "ix_dfvs_wfd_project_default", "CREATE INDEX ix_dfvs_wfd_project_default ON {table} (project_id, is_default)"),
    (WorkflowDefinitionVersion.__tablename__, "ix_dfvs_wfdv_def", "CREATE INDEX ix_dfvs_wfdv_def ON {table} (workflow_definition_id)"),
    (WorkflowDefinitionVersion.__tablename__, "ux_dfvs_wfdv_def_ver", "CREATE UNIQUE INDEX ux_dfvs_wfdv_def_ver ON {table} (workflow_definition_id, version_no)"),
    (TriggerTask.__tablename__, "ix_dfvs_task_def", "CREATE INDEX ix_dfvs_task_def ON {table} (workflow_definition_id)"),
    (TriggerTask.__tablename__, "ix_dfvs_task_defver", "CREATE INDEX ix_dfvs_task_defver ON {table} (workflow_definition_version_id)"),
    (TriggerTask.__tablename__, "ix_dfvs_task_profile", "CREATE INDEX ix_dfvs_task_profile ON {table} (profile_id)"),
    (TriggerTask.__tablename__, "ix_dfvs_task_project", "CREATE INDEX ix_dfvs_task_project ON {table} (project_id)"),
    (TriggerTask.__tablename__, "ix_dfvs_task_status", "CREATE INDEX ix_dfvs_task_status ON {table} (status)"),
    (TriggerTask.__tablename__, "ix_dfvs_task_latest_exec", "CREATE INDEX ix_dfvs_task_latest_exec ON {table} (latest_execution_id)"),
    (TriggerTask.__tablename__, "ix_dfvs_task_def_status", "CREATE INDEX ix_dfvs_task_def_status ON {table} (workflow_definition_id, status)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_task", "CREATE INDEX ix_dfvs_exec_task ON {table} (trigger_task_id)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_def", "CREATE INDEX ix_dfvs_exec_def ON {table} (workflow_definition_id)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_defver", "CREATE INDEX ix_dfvs_exec_defver ON {table} (workflow_definition_version_id)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_project", "CREATE INDEX ix_dfvs_exec_project ON {table} (project_id)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_status", "CREATE INDEX ix_dfvs_exec_status ON {table} (status)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_owner", "CREATE INDEX ix_dfvs_exec_owner ON {table} (owner_pod_id)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_lease", "CREATE INDEX ix_dfvs_exec_lease ON {table} (lease_expires_at)"),
    (WorkflowExecution.__tablename__, "ix_dfvs_exec_def_status", "CREATE INDEX ix_dfvs_exec_def_status ON {table} (workflow_definition_id, status)"),
    (WorkflowExecution.__tablename__, "ux_dfvs_exec_task_attempt", "CREATE UNIQUE INDEX ux_dfvs_exec_task_attempt ON {table} (trigger_task_id, attempt_no)"),
    (WorkflowExecutionEvent.__tablename__, "ix_dfvs_event_exec", "CREATE INDEX ix_dfvs_event_exec ON {table} (execution_id)"),
    (WorkflowExecutionEvent.__tablename__, "ix_dfvs_event_type", "CREATE INDEX ix_dfvs_event_type ON {table} (event_type)"),
    (WorkflowExecutionEvent.__tablename__, "ix_dfvs_event_created", "CREATE INDEX ix_dfvs_event_created ON {table} (created_at)"),
    (SchedulerWorker.__tablename__, "ix_dfvs_worker_heartbeat", "CREATE INDEX ix_dfvs_worker_heartbeat ON {table} (last_heartbeat_at)"),
    (SchedulerWorker.__tablename__, "ix_dfvs_worker_status", "CREATE INDEX ix_dfvs_worker_status ON {table} (status)"),
]

for table_name, index_name, sql_template in INDEX_DEFINITIONS:
    table = next(
        cls.__table__
        for cls in [WorkflowDefinition, WorkflowDefinitionVersion, TriggerTask, WorkflowExecution, WorkflowExecutionEvent, SchedulerWorker]
        if cls.__tablename__ == table_name
    )
    columns_sql = sql_template.split("(", 1)[1].rsplit(")", 1)[0]
    column_names = [column.strip() for column in columns_sql.split(",")]
    columns = [getattr(table.c, column_name) for column_name in column_names]
    Index(index_name, *columns, unique=sql_template.startswith("CREATE UNIQUE INDEX"))


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
        (table_name, index_name, sql_template.format(table=table_name))
        for table_name, index_name, sql_template in INDEX_DEFINITIONS
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
