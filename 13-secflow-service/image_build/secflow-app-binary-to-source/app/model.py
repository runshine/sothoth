"""Database models for Binary-to-Source adapter."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_config


Base = declarative_base()


class B2STask(Base):
    __tablename__ = "secflow_b2s_task"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(Integer, nullable=False, default=5)
    tags_json = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

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
    failure_type = Column(String(64), nullable=True)
    error_reason = Column(Text, nullable=True)
    generated_files_json = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

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
    Base.metadata.create_all(bind=get_engine())


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()
