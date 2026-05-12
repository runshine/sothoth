"""Database models for Binary-to-Source adapter."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, inspect
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_config
from app.time_utils import now_local


Base = declarative_base()


class B2STask(Base):
    __tablename__ = "secflow_b2s_task"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    task_origin_type = Column(String(32), nullable=True, index=True)
    parent_project_id = Column(String(64), nullable=True, index=True)
    parent_task_id = Column(String(64), nullable=True, index=True)
    parent_task_type = Column(String(32), nullable=True)
    parent_stage_name = Column(String(64), nullable=True)
    parent_stage_item_id = Column(String(64), nullable=True)
    parent_stage_item_key = Column(String(255), nullable=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(Integer, nullable=False, default=5)
    tags_json = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

    @property
    def tags(self) -> list[str]:
        return _loads(self.tags_json, [])

    @tags.setter
    def tags(self, value: list[str] | None) -> None:
        self.tags_json = json.dumps(value or [], ensure_ascii=False)


class B2STaskItem(Base):
    __tablename__ = "secflow_b2s_task_item"

    id = Column(String(32), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    sequence_no = Column(Integer, nullable=False)
    elf_path = Column(Text, nullable=False)
    output_dir = Column(Text, nullable=False)
    pi_job_id = Column(String(64), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    phase = Column(String(32), nullable=True)
    progress_json = Column(Text, nullable=True)
    failure_type = Column(String(64), nullable=True)
    error_reason = Column(Text, nullable=True)
    generated_files_json = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

    @property
    def generated_files(self) -> list[str]:
        return _loads(self.generated_files_json, [])

    @generated_files.setter
    def generated_files(self, value: list[str] | None) -> None:
        self.generated_files_json = json.dumps(value or [], ensure_ascii=False)

    @property
    def extra_metadata(self) -> dict[str, Any]:
        return _loads(self.metadata_json, {})

    @extra_metadata.setter
    def extra_metadata(self, value: dict[str, Any] | None) -> None:
        self.metadata_json = json.dumps(value or {}, ensure_ascii=False)

    @property
    def progress(self) -> dict[str, Any]:
        return _loads(self.progress_json, {})

    @progress.setter
    def progress(self, value: dict[str, Any] | None) -> None:
        self.progress_json = json.dumps(value or {}, ensure_ascii=False)


class B2SProjectConfig(Base):
    __tablename__ = "secflow_b2s_project_config"

    project_id = Column(String(64), primary_key=True)
    config_json = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

    @property
    def config(self) -> dict[str, Any]:
        return _loads(self.config_json, {})

    @config.setter
    def config(self, value: dict[str, Any] | None) -> None:
        self.config_json = json.dumps(value or {}, ensure_ascii=False)


def _loads(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_config().database
        _engine = create_engine(
            cfg.url,
            pool_size=cfg.pool_size,
            max_overflow=cfg.max_overflow,
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
    _ensure_task_item_progress_columns(engine)
    _ensure_task_origin_columns(engine)


def _ensure_task_item_progress_columns(engine) -> None:
    """Add progress columns for existing deployments.

    ``create_all`` does not alter already existing tables, while this service is
    deployed incrementally.  Keep the migration intentionally small and safe.
    """
    table_name = B2STaskItem.__tablename__
    columns = {column["name"] for column in inspect(engine).get_columns(table_name)}
    statements: list[str] = []
    if "phase" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN phase VARCHAR(32) NULL")
    if "progress_json" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN progress_json TEXT NULL")
    with engine.begin() as conn:
        for statement in statements:
            conn.exec_driver_sql(statement)
    indexes = {index["name"] for index in inspect(engine).get_indexes(table_name)}
    index_statements: list[str] = []
    if "ix_b2s_task_project_created_id" not in indexes:
        index_statements.append(f"CREATE INDEX ix_b2s_task_project_created_id ON {table_name} (project_id, created_at, id)")
    if "ix_b2s_task_project_status_created_id" not in indexes:
        index_statements.append(f"CREATE INDEX ix_b2s_task_project_status_created_id ON {table_name} (project_id, status, created_at, id)")
    with engine.begin() as conn:
        for statement in index_statements:
            conn.exec_driver_sql(statement)


def _ensure_task_origin_columns(engine) -> None:
    table_name = B2STask.__tablename__
    columns = {column["name"] for column in inspect(engine).get_columns(table_name)}
    statements: list[str] = []
    if "task_origin_type" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN task_origin_type VARCHAR(32) NULL")
    if "parent_project_id" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN parent_project_id VARCHAR(64) NULL")
    if "parent_task_id" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN parent_task_id VARCHAR(64) NULL")
    if "parent_task_type" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN parent_task_type VARCHAR(32) NULL")
    if "parent_stage_name" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN parent_stage_name VARCHAR(64) NULL")
    if "parent_stage_item_id" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN parent_stage_item_id VARCHAR(64) NULL")
    if "parent_stage_item_key" not in columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN parent_stage_item_key VARCHAR(255) NULL")
    if not statements:
        return
    with engine.begin() as conn:
        for statement in statements:
            conn.exec_driver_sql(statement)


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()
