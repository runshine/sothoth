"""Database models for secflow-platform-vuln."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from app.config import get_config


class Base(DeclarativeBase):
    pass


def now_utc() -> datetime:
    return datetime.utcnow()


class Case(Base):
    __tablename__ = "secflow_vuln_case"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[str] = mapped_column(String(32), default="ingest", index=True)
    current_status: Mapped[str] = mapped_column(String(32), default="new")
    decision_status: Mapped[str] = mapped_column(String(32), default="unknown")
    workflow_definition_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    active_workflow_run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    target_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    display_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dedup_status: Mapped[str] = mapped_column(String(32), default="not_processed")
    dedup_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by_type: Mapped[str] = mapped_column(String(32), default="human")
    created_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc, index=True)


class CaseEvent(Base):
    __tablename__ = "secflow_vuln_case_event"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_case.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), default="created")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    payload_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class ServiceRegistry(Base):
    __tablename__ = "secflow_vuln_service_registry"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    service_name: Mapped[str] = mapped_column(String(255))
    service_type: Mapped[str] = mapped_column(String(64))
    endpoint: Mapped[str] = mapped_column(String(512))
    healthcheck_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    callback_mode: Mapped[str] = mapped_column(String(32), default="push")
    auth_mode: Mapped[str] = mapped_column(String(32), default="machine_token")
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)

    capabilities: Mapped[list["ServiceCapability"]] = relationship(
        back_populates="service",
        cascade="all, delete-orphan",
        lazy="joined",
    )


class ServiceCapability(Base):
    __tablename__ = "secflow_vuln_service_capability"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_service_registry.id"), index=True)
    capability_code: Mapped[str] = mapped_column(String(128))
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    concurrency_limit: Mapped[int] = mapped_column(Integer, default=1)
    input_schema_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    output_schema_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    service: Mapped[ServiceRegistry] = relationship(back_populates="capabilities")


class WorkflowDefinition(Base):
    __tablename__ = "secflow_vuln_workflow_definition"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    code: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    is_default: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="active")
    trigger_rules_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stage_rules_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    transition_rules_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)


class WorkflowRun(Base):
    __tablename__ = "secflow_vuln_workflow_run"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_case.id"), index=True)
    workflow_definition_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    current_stage: Mapped[str] = mapped_column(String(32), default="ingest")
    run_status: Mapped[str] = mapped_column(String(32), default="running")
    context_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)


class ActionExecution(Base):
    __tablename__ = "secflow_vuln_action_execution"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_case.id"), index=True)
    workflow_run_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    stage: Mapped[str] = mapped_column(String(32), index=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    target_service_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    capability_code: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    dispatch_status: Mapped[str] = mapped_column(String(32), default="pending")
    execution_status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    input_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    input_artifact_refs_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retry_count: Mapped[int] = mapped_column(Integer, default=1)
    timeout_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)


class Result(Base):
    __tablename__ = "secflow_vuln_result"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_case.id"), index=True)
    action_execution_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_action_execution.id"), index=True)
    source_service_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    result_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="succeeded")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    result_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_payload_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    artifact_refs_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    suggested_stage: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    suggested_decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class Artifact(Base):
    __tablename__ = "secflow_vuln_artifact"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_case.id"), index=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    artifact_type: Mapped[str] = mapped_column(String(64), index=True)
    storage_backend: Mapped[str] = mapped_column(String(32), default="shared_pvc")
    storage_path: Mapped[str] = mapped_column(String(1024))
    storage_key: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    mime_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    uploader_type: Mapped[str] = mapped_column(String(32), default="service")
    uploader_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    display_meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class StageHistory(Base):
    __tablename__ = "secflow_vuln_stage_history"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_case.id"), index=True)
    from_stage: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    to_stage: Mapped[str] = mapped_column(String(32))
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_type: Mapped[str] = mapped_column(String(32), default="system")
    source_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class ManualTask(Base):
    __tablename__ = "secflow_vuln_manual_task"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("secflow_vuln_case.id"), index=True)
    task_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    assignee: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    due_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_config()
        _engine = create_engine(
            cfg.database.url,
            pool_size=cfg.database.pool_size,
            max_overflow=cfg.database.max_overflow,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionFactory


def init_database() -> None:
    Base.metadata.create_all(bind=get_engine())


def get_db():
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
