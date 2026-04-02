"""Database models."""

import hashlib
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from app.config import get_config


Base = declarative_base()


class ParentTaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    PARTIAL_SUCCESS = "partial_success"


class ItemTaskStatus:
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FailureType:
    WORKER_BUSINESS_ERROR = "worker_business_error"
    TRANSIENT_SYSTEM_ERROR = "transient_system_error"
    CANCELLED_BY_USER = "cancelled_by_user"


class BinaryToSourceTask(Base):
    __tablename__ = "secflow_app_binary_to_source_tasks"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(32), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text)
    priority = Column(Integer, nullable=False, default=5)
    tags = Column(JSON, default=list)
    status = Column(String(32), nullable=False, default=ParentTaskStatus.PENDING, index=True)
    created_by = Column(String(64))

    total_items = Column(Integer, default=0)
    pending_items = Column(Integer, default=0)
    queued_items = Column(Integer, default=0)
    running_items = Column(Integer, default=0)
    success_items = Column(Integer, default=0)
    partial_items = Column(Integer, default=0)
    failed_items = Column(Integer, default=0)
    cancelled_items = Column(Integer, default=0)

    result_summary = Column(JSON, default=dict)
    error_summary = Column(Text)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    cancel_requested_at = Column(DateTime)

    items = relationship(
        "BinaryToSourceTaskItem",
        back_populates="parent",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "tags": self.tags or [],
            "status": self.status,
            "created_by": self.created_by,
            "total_items": self.total_items,
            "pending_items": self.pending_items,
            "queued_items": self.queued_items,
            "running_items": self.running_items,
            "success_items": self.success_items,
            "partial_items": self.partial_items,
            "failed_items": self.failed_items,
            "cancelled_items": self.cancelled_items,
            "result_summary": self.result_summary or {},
            "error_summary": self.error_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "cancel_requested_at": self.cancel_requested_at.isoformat() if self.cancel_requested_at else None,
        }


class BinaryToSourceTaskItem(Base):
    __tablename__ = "secflow_app_binary_to_source_task_items"

    id = Column(String(32), primary_key=True)
    parent_task_id = Column(String(32), ForeignKey("secflow_app_binary_to_source_tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(32), nullable=False, index=True)
    sequence_no = Column(Integer, nullable=False)

    elf_path = Column(String(1024), nullable=False)
    file_list = Column(JSON, default=list)
    output_dir = Column(String(1024), nullable=False)

    status = Column(String(32), nullable=False, default=ItemTaskStatus.PENDING, index=True)
    failure_type = Column(String(64), index=True)
    error_reason = Column(Text)
    result_message = Column(Text)
    generated_files = Column(JSON, default=list)
    raw_payload = Column(JSON, default=dict)

    worker_id = Column(String(128), index=True)
    worker_queue = Column(String(128), index=True)
    celery_task_id = Column(String(128), index=True)

    attempt_count = Column(Integer, default=0)
    auto_retry_count = Column(Integer, default=0)
    manual_retry_count = Column(Integer, default=0)
    can_auto_retry = Column(Boolean, default=True)
    cancel_requested = Column(Boolean, default=False)

    queued_at = Column(DateTime)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    parent = relationship("BinaryToSourceTask", back_populates="items")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "parent_task_id": self.parent_task_id,
            "project_id": self.project_id,
            "sequence_no": self.sequence_no,
            "elf_path": self.elf_path,
            "file_list": self.file_list or [],
            "output_dir": self.output_dir,
            "status": self.status,
            "failure_type": self.failure_type,
            "error_reason": self.error_reason,
            "result_message": self.result_message,
            "generated_files": self.generated_files or [],
            "raw_payload": self.raw_payload or {},
            "worker_id": self.worker_id,
            "worker_queue": self.worker_queue,
            "celery_task_id": self.celery_task_id,
            "attempt_count": self.attempt_count,
            "auto_retry_count": self.auto_retry_count,
            "manual_retry_count": self.manual_retry_count,
            "can_auto_retry": self.can_auto_retry,
            "queued_at": self.queued_at.isoformat() if self.queued_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_config().database
        kwargs = {
            "pool_pre_ping": True,
            "connect_args": {"check_same_thread": False} if cfg.type == "sqlite" else {},
        }
        if cfg.type != "sqlite":
            kwargs["pool_size"] = cfg.pool_size
            kwargs["max_overflow"] = cfg.max_overflow
        _engine = create_engine(cfg.url, **kwargs)
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionFactory


def init_database():
    Base.metadata.create_all(bind=get_engine())


def get_db():
    session_local = get_session_factory()
    db = session_local()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    return get_session_factory()()


def generate_id() -> str:
    raw = f"{uuid.uuid4()}_{datetime.utcnow().timestamp()}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def apply_table_prefix_if_needed():
    """Allow custom table prefix from config while keeping stable defaults."""
    cfg = get_config().database
    if cfg.table_prefix == "secflow_app_binary_to_source_":
        return
    BinaryToSourceTask.__table__.name = f"{cfg.table_prefix}tasks"
    BinaryToSourceTaskItem.__table__.name = f"{cfg.table_prefix}task_items"
