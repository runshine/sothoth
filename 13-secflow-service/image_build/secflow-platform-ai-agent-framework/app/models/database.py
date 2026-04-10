from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from app.config import get_config

Base = declarative_base()
_engine = None
_SessionFactory = None


def _prefix(name: str) -> str:
    return f"{get_config().database.table_prefix}{name}"


class WorkflowDefinition(Base):
    __tablename__ = _prefix("workflow_definition")

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    description = Column(Text)
    project_id = Column(String(64), nullable=False, index=True)
    definition_json = Column(JSON, nullable=False)
    root_workflow_id = Column(String(128), nullable=False)
    trigger_type = Column(String(16), nullable=False, default="manual")
    trigger_enabled = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    max_concurrency = Column(Integer, nullable=False, default=1)
    priority_default = Column(Integer, nullable=False, default=100)
    workspace_base_dir = Column(String(512))
    execution_timeout_seconds = Column(Integer, nullable=False, default=7200)
    created_by = Column(String(128), nullable=False)
    updated_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkflowDefinitionVersion(Base):
    __tablename__ = _prefix("workflow_definition_version")

    id = Column(String(64), primary_key=True)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False, index=True)
    version_no = Column(Integer, nullable=False)
    definition_json = Column(JSON, nullable=False)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class TriggerTask(Base):
    __tablename__ = _prefix("trigger_task")

    id = Column(String(64), primary_key=True)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    trigger_type = Column(String(16), nullable=False, default="manual")
    input_tasks_json = Column(JSON, nullable=False)
    priority = Column(Integer, nullable=False, default=100)
    status = Column(String(32), nullable=False, default="pending", index=True)
    submitted_by = Column(String(128), nullable=False)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkflowExecution(Base):
    __tablename__ = _prefix("workflow_execution")

    id = Column(String(64), primary_key=True)
    trigger_task_id = Column(String(64), ForeignKey(f"{TriggerTask.__tablename__}.id"), nullable=False, index=True)
    workflow_definition_id = Column(String(64), ForeignKey(f"{WorkflowDefinition.__tablename__}.id"), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class SchedulerWorker(Base):
    __tablename__ = _prefix("scheduler_worker")

    pod_id = Column(String(128), primary_key=True)
    host_name = Column(String(256), nullable=False)
    capacity = Column(Integer, nullable=False, default=1)
    running_count = Column(Integer, nullable=False, default=0)
    last_heartbeat_at = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String(16), nullable=False, default="active", index=True)
    metadata_json = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


Index(f"ix_{WorkflowExecution.__tablename__}_definition_status", WorkflowExecution.workflow_definition_id, WorkflowExecution.status)
Index(f"ix_{TriggerTask.__tablename__}_definition_status", TriggerTask.workflow_definition_id, TriggerTask.status)


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


def init_database() -> None:
    Base.metadata.create_all(bind=get_engine())


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
