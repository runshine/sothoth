from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.dialects.mysql import DOUBLE, MEDIUMTEXT
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_config
from app.time_utils import now_local

Base = declarative_base()
_engine = None
_SessionFactory = None

MYSQL_INDEX_LENGTHS = {
    "ix_dfvs_ri_source_key": {"source_key": 512},
    "ix_dfvs_rif_run_path": {"path": 512},
}


def now_utc() -> datetime:
    return now_local()


def _prefix(name: str) -> str:
    return f"{get_config().database.table_prefix}{name}"


def run_source_hash(source_type: str | None, source_key: str | None) -> str:
    payload = f"{source_type or ''}\0{source_key or ''}".encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(payload).hexdigest()


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
    execution_timeout_seconds = Column(Integer, nullable=False, default=0)
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
    task_origin_type = Column(String(32), nullable=True, index=True)
    parent_project_id = Column(String(64), nullable=True, index=True)
    parent_task_id = Column(String(64), nullable=True, index=True)
    parent_task_type = Column(String(32), nullable=True)
    parent_stage_name = Column(String(64), nullable=True)
    parent_stage_item_id = Column(String(64), nullable=True)
    parent_stage_item_key = Column(String(255), nullable=True)
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
    process_pid = Column(Integer)
    process_host = Column(String(256))
    process_status = Column(String(32))
    process_started_at = Column(DateTime)
    process_finished_at = Column(DateTime)
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


class RunIndex(Base):
    __tablename__ = _prefix("run_index")

    id = Column(String(64), primary_key=True)
    project_id = Column(String(64), nullable=False)
    source_type = Column(String(64), nullable=False)
    source_key = Column(String(1024), nullable=False)
    source_hash = Column(String(64), nullable=False, default="")
    run_name = Column(String(255), nullable=False)
    run_root_path = Column(String(1024), nullable=False)
    atomic_work_path = Column(String(1024))
    linked_task_id = Column(String(64))
    linked_execution_id = Column(String(64))
    profile_id = Column(String(64))
    status = Column(String(32), nullable=False, default="pending")
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    duration_seconds = Column(Integer, nullable=False, default=0)
    last_activity_at = Column(DateTime)
    model = Column(String(255), nullable=False, default="")
    provider = Column(String(255), nullable=False, default="")
    thinking = Column(String(64), nullable=False, default="")
    max_cycles = Column(Integer, nullable=False, default=0)
    cycles_used = Column(Integer, nullable=False, default=0)
    result_count = Column(Integer, nullable=False, default=0)
    passed_count = Column(Integer, nullable=False, default=0)
    failed_count = Column(Integer, nullable=False, default=0)
    workflow_mode = Column(String(128), nullable=False, default="")
    error = Column(Text)
    config_json = Column(JSON, nullable=False, default=dict)
    manifests_json = Column(JSON, nullable=False, default=dict)
    latest_issues_json = Column(JSON, nullable=False, default=list)
    raw_summary_json = Column(JSON, nullable=False, default=dict)
    log_tail_text = Column(Text().with_variant(MEDIUMTEXT(), "mysql"))
    log_size_bytes = Column(Integer, nullable=False, default=0)
    source_mtime = Column(Float().with_variant(DOUBLE(asdecimal=False), "mysql"), nullable=False, default=0)
    last_synced_at = Column(DateTime, default=now_utc)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class RunIndexCycle(Base):
    __tablename__ = _prefix("run_index_cycle")

    id = Column(String(64), primary_key=True)
    run_index_id = Column(String(64), ForeignKey(f"{RunIndex.__tablename__}.id"), nullable=False)
    cycle = Column(Integer, nullable=False)
    timestamp = Column(String(128), nullable=False, default="")
    outcome = Column(String(64), nullable=False, default="")
    workflow_mode = Column(String(128), nullable=False, default="")
    global_passed = Column(Boolean, nullable=False, default=False)
    failed_advisor_id = Column(String(255), nullable=False, default="")
    failed_role_name = Column(String(255), nullable=False, default="")
    result_total = Column(Integer, nullable=False, default=0)
    result_passed = Column(Integer, nullable=False, default=0)
    result_failed = Column(Integer, nullable=False, default=0)
    scores_json = Column(JSON, nullable=False, default=dict)
    metrics_json = Column(JSON, nullable=False, default=dict)
    issues_json = Column(JSON, nullable=False, default=list)
    plateau_status_json = Column(JSON, nullable=False, default=dict)
    summary_snapshot_text = Column(Text)
    raw_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class RunIndexGlobalReview(Base):
    __tablename__ = _prefix("run_index_global_review")

    id = Column(String(64), primary_key=True)
    run_index_id = Column(String(64), ForeignKey(f"{RunIndex.__tablename__}.id"), nullable=False)
    cycle = Column(Integer, nullable=False)
    advisor_id = Column(String(255), nullable=False, default="")
    path = Column(String(1024), nullable=False, default="")
    role_name = Column(String(255), nullable=False, default="")
    passed = Column(Boolean, nullable=False, default=False)
    verdict = Column(String(128), nullable=False, default="")
    confidence = Column(Float, nullable=False, default=0)
    scores_json = Column(JSON, nullable=False, default=dict)
    feedback = Column(Text)
    feedback_detail = Column(Text)
    schema_valid = Column(Boolean)
    parser_mode = Column(String(64), nullable=False, default="")
    repair_attempts = Column(Integer, nullable=False, default=0)
    issues_json = Column(JSON, nullable=False, default=list)
    resolved_issue_ids_json = Column(JSON, nullable=False, default=list)
    raw_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class RunIndexResult(Base):
    __tablename__ = _prefix("run_index_result")

    id = Column(String(64), primary_key=True)
    run_index_id = Column(String(64), ForeignKey(f"{RunIndex.__tablename__}.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    path = Column(String(1024), nullable=False, default="")
    title = Column(String(512), nullable=False, default="")
    size = Column(Integer, nullable=False, default=0)
    passed = Column(Boolean)
    verdict = Column(String(128), nullable=False, default="")
    confidence = Column(Float, nullable=False, default=0)
    review_cycle = Column(Integer, nullable=False, default=0)
    feedback = Column(Text)
    feedback_detail = Column(Text)
    schema_valid = Column(Boolean)
    parser_mode = Column(String(64), nullable=False, default="")
    review_path = Column(String(1024), nullable=False, default="")
    role = Column(String(255), nullable=False, default="")
    lifecycle_status = Column(String(64), nullable=False, default="")
    active = Column(Boolean, nullable=False, default=True)
    taskable = Column(Boolean, nullable=False, default=True)
    delivery_bucket = Column(String(64), nullable=False, default="")
    multi_finding = Column(Boolean, nullable=False, default=False)
    vulnerability_headings_json = Column(JSON, nullable=False, default=list)
    related_to = Column(String(1024), nullable=False, default="")
    raw_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class RunIndexResultReview(Base):
    __tablename__ = _prefix("run_index_result_review")

    id = Column(String(64), primary_key=True)
    run_index_id = Column(String(64), ForeignKey(f"{RunIndex.__tablename__}.id"), nullable=False)
    cycle = Column(Integer, nullable=False)
    result_file = Column(String(255), nullable=False, default="")
    path = Column(String(1024), nullable=False, default="")
    advisor_id = Column(String(255), nullable=False, default="")
    passed = Column(Boolean, nullable=False, default=False)
    verdict = Column(String(128), nullable=False, default="")
    confidence = Column(Float, nullable=False, default=0)
    feedback = Column(Text)
    feedback_detail = Column(Text)
    schema_valid = Column(Boolean)
    parser_mode = Column(String(64), nullable=False, default="")
    repair_attempts = Column(Integer, nullable=False, default=0)
    raw_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class RunIndexRemovedResult(Base):
    __tablename__ = _prefix("run_index_removed_result")

    id = Column(String(64), primary_key=True)
    run_index_id = Column(String(64), ForeignKey(f"{RunIndex.__tablename__}.id"), nullable=False)
    filename = Column(String(255), nullable=False, default="")
    path = Column(String(1024), nullable=False, default="")
    meta_path = Column(String(1024), nullable=False, default="")
    cycle = Column(Integer, nullable=False, default=0)
    lifecycle_status = Column(String(64), nullable=False, default="")
    reason = Column(Text)
    signals_json = Column(JSON, nullable=False, default=list)
    raw_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class RunIndexSession(Base):
    __tablename__ = _prefix("run_index_session")

    id = Column(String(64), primary_key=True)
    run_index_id = Column(String(64), ForeignKey(f"{RunIndex.__tablename__}.id"), nullable=False)
    session_id = Column(String(255), nullable=False)
    format = Column(String(32), nullable=False, default="")
    worker_id = Column(String(255), nullable=False, default="")
    jsonl_path = Column(String(1024), nullable=False, default="")
    size = Column(Integer, nullable=False, default=0)
    mtime = Column(Float, nullable=False, default=0)
    calls_json = Column(JSON, nullable=False, default=list)
    raw_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class RunIndexFile(Base):
    __tablename__ = _prefix("run_index_file")

    id = Column(String(64), primary_key=True)
    run_index_id = Column(String(64), ForeignKey(f"{RunIndex.__tablename__}.id"), nullable=False)
    category = Column(String(255), nullable=False, default="")
    path = Column(String(1024), nullable=False)
    name = Column(String(255), nullable=False)
    size = Column(Integer, nullable=False, default=0)
    mtime = Column(Float, nullable=False, default=0)
    type = Column(String(32), nullable=False, default="")
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


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


MODEL_CLASSES = [
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    TriggerTask,
    WorkflowExecution,
    WorkflowExecutionEvent,
    RunIndex,
    RunIndexCycle,
    RunIndexGlobalReview,
    RunIndexResult,
    RunIndexResultReview,
    RunIndexRemovedResult,
    RunIndexSession,
    RunIndexFile,
    SchedulerWorker,
]


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
    (RunIndex.__tablename__, "ix_dfvs_ri_project", "CREATE INDEX ix_dfvs_ri_project ON {table} (project_id)"),
    (RunIndex.__tablename__, "ix_dfvs_ri_status", "CREATE INDEX ix_dfvs_ri_status ON {table} (status)"),
    (RunIndex.__tablename__, "ux_dfvs_ri_source_hash", "CREATE UNIQUE INDEX ux_dfvs_ri_source_hash ON {table} (source_type, source_hash)"),
    (RunIndex.__tablename__, "ix_dfvs_ri_source_key", "CREATE INDEX ix_dfvs_ri_source_key ON {table} (source_type, source_key)"),
    (RunIndex.__tablename__, "ix_dfvs_ri_execution", "CREATE INDEX ix_dfvs_ri_execution ON {table} (linked_execution_id)"),
    (RunIndex.__tablename__, "ix_dfvs_ri_task", "CREATE INDEX ix_dfvs_ri_task ON {table} (linked_task_id)"),
    (RunIndex.__tablename__, "ix_dfvs_ri_project_started", "CREATE INDEX ix_dfvs_ri_project_started ON {table} (project_id, started_at)"),
    (RunIndexCycle.__tablename__, "ix_dfvs_ric_run", "CREATE INDEX ix_dfvs_ric_run ON {table} (run_index_id)"),
    (RunIndexCycle.__tablename__, "ix_dfvs_ric_run_cycle", "CREATE UNIQUE INDEX ix_dfvs_ric_run_cycle ON {table} (run_index_id, cycle)"),
    (RunIndexGlobalReview.__tablename__, "ix_dfvs_rigr_run_cycle", "CREATE INDEX ix_dfvs_rigr_run_cycle ON {table} (run_index_id, cycle)"),
    (RunIndexResult.__tablename__, "ix_dfvs_rir_run", "CREATE INDEX ix_dfvs_rir_run ON {table} (run_index_id)"),
    (RunIndexResult.__tablename__, "ix_dfvs_rir_run_filename", "CREATE INDEX ix_dfvs_rir_run_filename ON {table} (run_index_id, filename)"),
    (RunIndexResultReview.__tablename__, "ix_dfvs_rirr_run_cycle", "CREATE INDEX ix_dfvs_rirr_run_cycle ON {table} (run_index_id, cycle)"),
    (RunIndexRemovedResult.__tablename__, "ix_dfvs_rirm_run", "CREATE INDEX ix_dfvs_rirm_run ON {table} (run_index_id)"),
    (RunIndexSession.__tablename__, "ix_dfvs_ris_run", "CREATE INDEX ix_dfvs_ris_run ON {table} (run_index_id)"),
    (RunIndexFile.__tablename__, "ix_dfvs_rif_run", "CREATE INDEX ix_dfvs_rif_run ON {table} (run_index_id)"),
    (RunIndexFile.__tablename__, "ix_dfvs_rif_run_path", "CREATE INDEX ix_dfvs_rif_run_path ON {table} (run_index_id, path)"),
    (SchedulerWorker.__tablename__, "ix_dfvs_worker_heartbeat", "CREATE INDEX ix_dfvs_worker_heartbeat ON {table} (last_heartbeat_at)"),
    (SchedulerWorker.__tablename__, "ix_dfvs_worker_status", "CREATE INDEX ix_dfvs_worker_status ON {table} (status)"),
]


def _index_column_names(sql_template: str) -> list[str]:
    columns_sql = sql_template.split("(", 1)[1].rsplit(")", 1)[0]
    return [column.strip() for column in columns_sql.split(",")]


def _render_index_sql(table_name: str, index_name: str, sql_template: str, dialect: str) -> str:
    if dialect != "mysql" or index_name not in MYSQL_INDEX_LENGTHS:
        return sql_template.format(table=table_name)
    prefix_lengths = MYSQL_INDEX_LENGTHS[index_name]
    rendered_columns = []
    for column_name in _index_column_names(sql_template):
        prefix_length = prefix_lengths.get(column_name)
        if prefix_length:
            rendered_columns.append(f"{column_name}({prefix_length})")
        else:
            rendered_columns.append(column_name)
    unique_sql = "UNIQUE " if sql_template.startswith("CREATE UNIQUE INDEX") else ""
    return f"CREATE {unique_sql}INDEX {index_name} ON {table_name} ({', '.join(rendered_columns)})"

for table_name, index_name, sql_template in INDEX_DEFINITIONS:
    table = next(
        cls.__table__
        for cls in MODEL_CLASSES
        if cls.__tablename__ == table_name
    )
    column_names = _index_column_names(sql_template)
    columns = [getattr(table.c, column_name) for column_name in column_names]
    index_kwargs = {}
    if index_name in MYSQL_INDEX_LENGTHS:
        index_kwargs["mysql_length"] = MYSQL_INDEX_LENGTHS[index_name]
    Index(index_name, *columns, unique=sql_template.startswith("CREATE UNIQUE INDEX"), **index_kwargs)


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


def _column_type_name(inspector, table_name: str, column_name: str) -> str:
    for column in inspector.get_columns(table_name):
        if column["name"] == column_name:
            return str(column.get("type") or "").upper()
    return ""


def _index_exists(inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _column_sql(dialect: str, sqltype: str) -> str:
    if dialect == "sqlite" and sqltype == "JSON":
        return "TEXT"
    return sqltype


def _quote(connection, identifier: str) -> str:
    return connection.dialect.identifier_preparer.quote(identifier)


def _legacy_run_table_name(suffix: str = "") -> str:
    legacy_base = ("history" + "_run") + suffix
    if RunIndex.__tablename__.endswith("run_index"):
        return f"{RunIndex.__tablename__[:-len('run_index')]}{legacy_base}"
    return _prefix(legacy_base)


def _legacy_run_fk_column() -> str:
    return "history" + "_run_id"


def _drop_index_sql(connection, table_name: str, index_name: str) -> str:
    if connection.dialect.name == "mysql":
        return f"DROP INDEX {_quote(connection, index_name)} ON {_quote(connection, table_name)}"
    return f"DROP INDEX {_quote(connection, index_name)}"


def _table_columns(inspector, table_name: str) -> list[str]:
    return [column["name"] for column in inspector.get_columns(table_name)]


def _run_row_exists(connection, table_name: str, *, run_id: str, source_type: str, source_hash: str) -> bool:
    return _target_run_id(
        connection,
        table_name,
        run_id=run_id,
        source_type=source_type,
        source_hash=source_hash,
    ) is not None


def _target_run_id(connection, table_name: str, *, run_id: str, source_type: str, source_hash: str) -> str | None:
    row = connection.execute(
        text(
            f"SELECT {_quote(connection, 'id')} FROM {_quote(connection, table_name)} "
            f"WHERE {_quote(connection, 'id')} = :run_id "
            f"OR ({_quote(connection, 'source_type')} = :source_type "
            f"AND {_quote(connection, 'source_hash')} = :source_hash) "
            "LIMIT 1"
        ),
        {"run_id": run_id, "source_type": source_type, "source_hash": source_hash},
    ).mappings().first()
    return str(row.get("id") or "") if row else None


def _row_exists_by_id(connection, table_name: str, row_id: str) -> bool:
    row = connection.execute(
        text(
            f"SELECT 1 FROM {_quote(connection, table_name)} "
            f"WHERE {_quote(connection, 'id')} = :row_id LIMIT 1"
        ),
        {"row_id": row_id},
    ).first()
    return row is not None


def _run_parent_exists(connection, table_name: str, run_id: str) -> bool:
    return _row_exists_by_id(connection, table_name, run_id)


def _legacy_run_id_map(connection, inspector) -> dict[str, str]:
    table_names = set(inspector.get_table_names())
    legacy_table = _legacy_run_table_name()
    target_table = RunIndex.__tablename__
    if legacy_table not in table_names or target_table not in table_names:
        return {}
    legacy_columns = set(_table_columns(inspector, legacy_table))
    if not {"id", "source_type", "source_key"}.issubset(legacy_columns):
        return {}
    rows = connection.execute(
        text(
            f"SELECT {_quote(connection, 'id')}, {_quote(connection, 'source_type')}, {_quote(connection, 'source_key')} "
            f"FROM {_quote(connection, legacy_table)}"
        )
    ).mappings()
    mapping: dict[str, str] = {}
    for row in rows:
        legacy_id = str(row.get("id") or "")
        source_type = str(row.get("source_type") or "")
        source_key = str(row.get("source_key") or "")
        if not legacy_id or not source_type or not source_key:
            continue
        target_id = _target_run_id(
            connection,
            target_table,
            run_id=legacy_id,
            source_type=source_type,
            source_hash=run_source_hash(source_type, source_key),
        )
        if target_id:
            mapping[legacy_id] = target_id
    return mapping


def _backfill_run_source_hash(connection, inspector) -> None:
    table_name = RunIndex.__tablename__
    table_names = set(inspector.get_table_names())
    if table_name not in table_names or not _column_exists(inspector, table_name, "source_hash"):
        return
    rows = connection.execute(
        text(
            f"SELECT {_quote(connection, 'id')}, {_quote(connection, 'source_type')}, {_quote(connection, 'source_key')} "
            f"FROM {_quote(connection, table_name)} "
            f"WHERE {_quote(connection, 'source_hash')} IS NULL OR {_quote(connection, 'source_hash')} = ''"
        )
    ).mappings()
    for row in rows:
        source_hash = run_source_hash(str(row.get("source_type") or ""), str(row.get("source_key") or ""))
        connection.execute(
            text(
                f"UPDATE {_quote(connection, table_name)} "
                f"SET {_quote(connection, 'source_hash')} = :source_hash "
                f"WHERE {_quote(connection, 'id')} = :run_id"
            ),
            {"source_hash": source_hash, "run_id": row.get("id")},
        )


def _drop_unique_source_key_index(connection, inspector) -> None:
    table_name = RunIndex.__tablename__
    table_names = set(inspector.get_table_names())
    if table_name not in table_names:
        return
    for index in inspector.get_indexes(table_name):
        if index.get("name") == "ix_dfvs_ri_source_key" and bool(index.get("unique")):
            connection.execute(text(_drop_index_sql(connection, table_name, "ix_dfvs_ri_source_key")))
            break


LEGACY_RUN_CHILD_TABLES = [
    ("_cycle", RunIndexCycle.__tablename__),
    ("_global_review", RunIndexGlobalReview.__tablename__),
    ("_result", RunIndexResult.__tablename__),
    ("_result_review", RunIndexResultReview.__tablename__),
    ("_removed_result", RunIndexRemovedResult.__tablename__),
    ("_session", RunIndexSession.__tablename__),
    ("_file", RunIndexFile.__tablename__),
]


def _copy_legacy_run_rows(connection, inspector) -> None:
    table_names = set(inspector.get_table_names())
    legacy_table = _legacy_run_table_name()
    target_table = RunIndex.__tablename__
    if legacy_table not in table_names or target_table not in table_names:
        return
    legacy_columns = _table_columns(inspector, legacy_table)
    target_columns = _table_columns(inspector, target_table)
    common_columns = [
        column
        for column in target_columns
        if column in legacy_columns and column != "source_hash"
    ]
    required = {"id", "source_type", "source_key"}
    if not required.issubset(set(common_columns)):
        return
    select_sql = ", ".join(_quote(connection, column) for column in common_columns)
    rows = connection.execute(
        text(f"SELECT {select_sql} FROM {_quote(connection, legacy_table)}")
    ).mappings()
    for row in rows:
        run_id = str(row.get("id") or "")
        source_type = str(row.get("source_type") or "")
        source_key = str(row.get("source_key") or "")
        if not run_id or not source_type or not source_key:
            continue
        source_hash = run_source_hash(source_type, source_key)
        if _run_row_exists(
            connection,
            target_table,
            run_id=run_id,
            source_type=source_type,
            source_hash=source_hash,
        ):
            continue
        insert_columns = list(common_columns)
        params = {column: row.get(column) for column in common_columns}
        if "source_hash" in target_columns:
            insert_columns.append("source_hash")
            params["source_hash"] = source_hash
        column_sql = ", ".join(_quote(connection, column) for column in insert_columns)
        value_sql = ", ".join(f":{column}" for column in insert_columns)
        connection.execute(
            text(f"INSERT INTO {_quote(connection, target_table)} ({column_sql}) VALUES ({value_sql})"),
            params,
        )


def _copy_legacy_run_child_rows(connection, inspector) -> None:
    table_names = set(inspector.get_table_names())
    target_parent_table = RunIndex.__tablename__
    if target_parent_table not in table_names:
        return
    run_id_map = _legacy_run_id_map(connection, inspector)
    legacy_fk = _legacy_run_fk_column()
    for suffix, target_table in LEGACY_RUN_CHILD_TABLES:
        legacy_table = _legacy_run_table_name(suffix)
        if legacy_table not in table_names or target_table not in table_names:
            continue
        legacy_columns = _table_columns(inspector, legacy_table)
        target_columns = _table_columns(inspector, target_table)
        insert_columns: list[str] = []
        select_expressions: list[str] = []
        for target_column in target_columns:
            legacy_column = legacy_fk if target_column == "run_index_id" else target_column
            if legacy_column not in legacy_columns:
                continue
            insert_columns.append(target_column)
            select_expressions.append(f"{_quote(connection, legacy_column)} AS {_quote(connection, target_column)}")
        if "id" not in insert_columns or "run_index_id" not in insert_columns:
            continue
        rows = connection.execute(
            text(
                f"SELECT {', '.join(select_expressions)} "
                f"FROM {_quote(connection, legacy_table)}"
            )
        ).mappings()
        for row in rows:
            row_id = str(row.get("id") or "")
            run_id = str(row.get("run_index_id") or "")
            if not row_id or not run_id:
                continue
            target_run_id = run_id_map.get(run_id, run_id)
            if not _run_parent_exists(connection, target_parent_table, target_run_id):
                continue
            if _row_exists_by_id(connection, target_table, row_id):
                continue
            params = {column: row.get(column) for column in insert_columns}
            params["run_index_id"] = target_run_id
            column_sql = ", ".join(_quote(connection, column) for column in insert_columns)
            value_sql = ", ".join(f":{column}" for column in insert_columns)
            connection.execute(
                text(f"INSERT INTO {_quote(connection, target_table)} ({column_sql}) VALUES ({value_sql})"),
                params,
            )


def _legacy_table_rows_missing_in_target(connection, legacy_table: str, target_table: str) -> bool:
    row = connection.execute(
        text(
            f"SELECT 1 FROM {_quote(connection, legacy_table)} legacy "
            f"LEFT JOIN {_quote(connection, target_table)} target "
            f"ON legacy.{_quote(connection, 'id')} = target.{_quote(connection, 'id')} "
            f"WHERE target.{_quote(connection, 'id')} IS NULL LIMIT 1"
        )
    ).first()
    return row is not None


def _legacy_run_tables_fully_migrated(connection, inspector) -> bool:
    table_names = set(inspector.get_table_names())
    legacy_table = _legacy_run_table_name()
    target_table = RunIndex.__tablename__
    if legacy_table not in table_names:
        return False
    if target_table not in table_names:
        return False
    run_id_map = _legacy_run_id_map(connection, inspector)
    legacy_ids = {
        str(row.get("id") or "")
        for row in connection.execute(
            text(f"SELECT {_quote(connection, 'id')} FROM {_quote(connection, legacy_table)}")
        ).mappings()
    }
    if any(legacy_id and legacy_id not in run_id_map for legacy_id in legacy_ids):
        return False
    for suffix, target_child_table in LEGACY_RUN_CHILD_TABLES:
        legacy_child_table = _legacy_run_table_name(suffix)
        if legacy_child_table not in table_names:
            continue
        if target_child_table not in table_names:
            return False
        if _legacy_table_rows_missing_in_target(connection, legacy_child_table, target_child_table):
            return False
    return True


def _drop_legacy_run_tables(connection, inspector) -> None:
    if not _legacy_run_tables_fully_migrated(connection, inspector):
        return
    table_names = set(inspector.get_table_names())
    legacy_tables = [_legacy_run_table_name(suffix) for suffix, _ in reversed(LEGACY_RUN_CHILD_TABLES)]
    legacy_tables.append(_legacy_run_table_name())
    for table_name in legacy_tables:
        if table_name in table_names:
            connection.execute(text(f"DROP TABLE {_quote(connection, table_name)}"))


def _migrate_legacy_run_tables(connection, inspector) -> None:
    _backfill_run_source_hash(connection, inspector)
    _copy_legacy_run_rows(connection, inspector)
    inspector = inspect(connection)
    _copy_legacy_run_child_rows(connection, inspector)
    inspector = inspect(connection)
    _backfill_run_source_hash(connection, inspector)
    inspector = inspect(connection)
    _drop_unique_source_key_index(connection, inspector)
    inspector = inspect(connection)
    _drop_legacy_run_tables(connection, inspector)


def run_auto_migrations() -> None:
    engine = get_engine()
    dialect = engine.dialect.name
    tables = {
        "workflow_definition": WorkflowDefinition.__tablename__,
        "workflow_definition_version": WorkflowDefinitionVersion.__tablename__,
        "trigger_task": TriggerTask.__tablename__,
        "workflow_execution": WorkflowExecution.__tablename__,
        "run_index": RunIndex.__tablename__,
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
        (tables["trigger_task"], "task_origin_type", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN task_origin_type VARCHAR(32) NULL"),
        (tables["trigger_task"], "parent_project_id", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN parent_project_id VARCHAR(64) NULL"),
        (tables["trigger_task"], "parent_task_id", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN parent_task_id VARCHAR(64) NULL"),
        (tables["trigger_task"], "parent_task_type", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN parent_task_type VARCHAR(32) NULL"),
        (tables["trigger_task"], "parent_stage_name", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN parent_stage_name VARCHAR(64) NULL"),
        (tables["trigger_task"], "parent_stage_item_id", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN parent_stage_item_id VARCHAR(64) NULL"),
        (tables["trigger_task"], "parent_stage_item_key", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN parent_stage_item_key VARCHAR(255) NULL"),
        (tables["trigger_task"], "retry_count", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0"),
        (tables["trigger_task"], "max_retry_count", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN max_retry_count INTEGER NOT NULL DEFAULT 3"),
        (tables["trigger_task"], "latest_execution_id", f"ALTER TABLE {tables['trigger_task']} ADD COLUMN latest_execution_id VARCHAR(64) NULL"),
        (tables["workflow_execution"], "workflow_definition_version_id", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN workflow_definition_version_id VARCHAR(64) NULL"),
        (tables["workflow_execution"], "attempt_no", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN attempt_no INTEGER NOT NULL DEFAULT 1"),
        (tables["workflow_execution"], "recovery_reason", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN recovery_reason VARCHAR(255) NULL"),
        (tables["workflow_execution"], "process_pid", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN process_pid INTEGER NULL"),
        (tables["workflow_execution"], "process_host", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN process_host VARCHAR(256) NULL"),
        (tables["workflow_execution"], "process_status", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN process_status VARCHAR(32) NULL"),
        (tables["workflow_execution"], "process_started_at", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN process_started_at DATETIME NULL"),
        (tables["workflow_execution"], "process_finished_at", f"ALTER TABLE {tables['workflow_execution']} ADD COLUMN process_finished_at DATETIME NULL"),
        (tables["run_index"], "source_hash", f"ALTER TABLE {tables['run_index']} ADD COLUMN source_hash VARCHAR(64) NOT NULL DEFAULT ''"),
    ]
    index_migrations = [
        (table_name, index_name, _render_index_sql(table_name, index_name, sql_template, dialect))
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

        if dialect == "mysql" and RunIndex.__tablename__ in inspector.get_table_names():
            if _column_exists(inspector, RunIndex.__tablename__, "log_tail_text"):
                if _column_type_name(inspector, RunIndex.__tablename__, "log_tail_text") != "MEDIUMTEXT":
                    connection.execute(text(
                        f"ALTER TABLE {RunIndex.__tablename__} "
                        "MODIFY COLUMN log_tail_text MEDIUMTEXT NULL"
                    ))
                    inspector = inspect(connection)
            if _column_exists(inspector, RunIndex.__tablename__, "source_mtime"):
                if "DOUBLE" not in _column_type_name(inspector, RunIndex.__tablename__, "source_mtime"):
                    connection.execute(text(
                        f"ALTER TABLE {RunIndex.__tablename__} "
                        "MODIFY COLUMN source_mtime DOUBLE NOT NULL DEFAULT 0"
                    ))
                    inspector = inspect(connection)

        inspector = inspect(connection)
        _migrate_legacy_run_tables(connection, inspector)

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
