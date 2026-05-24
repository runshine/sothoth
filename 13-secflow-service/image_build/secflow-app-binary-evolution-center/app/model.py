from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Text, create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_config
from app.time_utils import now_local

Base = declarative_base()
_engine = None
_SessionFactory = None


def now_utc() -> datetime:
    return now_local()


def _prefix(name: str) -> str:
    return f"{get_config().database.table_prefix}{name}"


class EvolutionTask(Base):
    __tablename__ = _prefix("task")

    id = Column(String(64), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False, default="pending", index=True)
    objective = Column(Text)
    metrics_json = Column(JSON, nullable=False, default=dict)
    source_case_ids_json = Column(JSON, nullable=False, default=list)
    source_task_ids_json = Column(JSON, nullable=False, default=list)
    preview_payload_json = Column(JSON, nullable=False, default=dict)
    agent_state_roots_json = Column(JSON, nullable=False, default=dict)
    default_agent_source_dirs_json = Column(JSON, nullable=False, default=dict)
    config_json = Column(JSON, nullable=False, default=dict)
    current_round = Column(Integer, nullable=False, default=0)
    best_round = Column(Integer, nullable=True)
    overall_score = Column(Integer, nullable=True)
    convergence_reason = Column(Text)
    apply_status = Column(String(32), nullable=False, default="not_applied")
    apply_snapshot_path = Column(String(1024))
    owner_pod_id = Column(String(128), index=True)
    created_by = Column(String(128), nullable=False)
    message = Column(Text)
    last_error = Column(Text)
    created_at = Column(DateTime, default=now_utc)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc, index=True)
    deleted = Column(Boolean, nullable=False, default=False, index=True)


class EvolutionTaskSource(Base):
    __tablename__ = _prefix("task_source")

    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), nullable=False, index=True)
    source_task_id = Column(String(64), nullable=False, index=True)
    source_execution_id = Column(String(64))
    source_run_id = Column(String(64))
    source_title = Column(String(255))
    case_ids_json = Column(JSON, nullable=False, default=list)
    case_keys_json = Column(JSON, nullable=False, default=list)
    source_task_summary_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)


class EvolutionTaskRound(Base):
    __tablename__ = _prefix("task_round")

    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), nullable=False, index=True)
    round_no = Column(Integer, nullable=False, index=True)
    status = Column(String(32), nullable=False, default="pending")
    metrics_json = Column(JSON, nullable=False, default=dict)
    score = Column(Integer)
    score_reason = Column(Text)
    adjustment_summary = Column(Text)
    convergence_decision = Column(Boolean)
    convergence_reason = Column(Text)
    derived_tasks_json = Column(JSON, nullable=False, default=list)
    diff_summary_json = Column(JSON, nullable=False, default=dict)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class EvolutionTaskArtifact(Base):
    __tablename__ = _prefix("task_artifact")

    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), nullable=False, index=True)
    round_no = Column(Integer, nullable=True, index=True)
    artifact_type = Column(String(64), nullable=False, index=True)
    path = Column(String(1024), nullable=False)
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)


class EvolutionTaskEvent(Base):
    __tablename__ = _prefix("task_event")

    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    summary = Column(Text)
    payload_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)


class EvolutionServiceConfig(Base):
    __tablename__ = _prefix("service_config")

    config_key = Column(String(64), primary_key=True)
    config_json = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


class SchedulerWorker(Base):
    __tablename__ = _prefix("scheduler_worker")

    pod_id = Column(String(128), primary_key=True)
    host_name = Column(String(255), nullable=False)
    capacity = Column(Integer, nullable=False, default=1)
    running_count = Column(Integer, nullable=False, default=0)
    last_heartbeat_at = Column(DateTime, default=now_utc, index=True)
    status = Column(String(32), nullable=False, default="active")
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_config()
        _engine = create_engine(
            cfg.database.sqlalchemy_url,
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
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        try:
            conn.execute(text(f"ALTER TABLE {_prefix('task')} ADD COLUMN last_error TEXT NULL"))
            conn.commit()
        except Exception:
            conn.rollback()


def get_db():
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def get_db_session():
    return get_session_factory()()
