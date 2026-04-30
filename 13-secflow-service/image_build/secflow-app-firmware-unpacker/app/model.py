"""Database models for firmware unpacker service."""

from __future__ import annotations

import enum
import hashlib
import os
import socket
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_config


Base = declarative_base()


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    SUCCESS = "success"
    FAILED = "failed"


TERMINAL_STATUSES = {
    TaskStatus.CANCELLED,
    TaskStatus.SUCCESS,
    TaskStatus.FAILED,
}


def is_terminal(status: str) -> bool:
    return status in {item.value for item in TERMINAL_STATUSES}


class UnpackTask(Base):
    __tablename__ = "secflow_app_firmware_unpacker_unpack_tasks"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(64), nullable=True, index=True)
    firmware_path = Column(String(512), nullable=False)
    output_path = Column(String(512), nullable=False)
    status = Column(
        String(32),
        nullable=False,
        default=TaskStatus.PENDING.value,
        index=True,
    )
    worker_id = Column(String(64), nullable=True, index=True)
    result_status = Column(String(32), nullable=True)
    result_message = Column(Text, nullable=True)
    rounds = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "firmware_path": self.firmware_path,
            "output_path": self.output_path,
            "status": self.status,
            "worker_id": self.worker_id,
            "result_status": self.result_status,
            "result_message": self.result_message,
            "rounds": self.rounds,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class WorkerInstance(Base):
    __tablename__ = "secflow_app_firmware_unpacker_worker_instances"

    worker_id = Column(String(64), primary_key=True)
    hostname = Column(String(128), nullable=True)
    pod_ip = Column(String(64), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    is_alive = Column(Boolean, default=True)
    active_tasks = Column(Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "worker_id": self.worker_id,
            "hostname": self.hostname,
            "pod_ip": self.pod_ip,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "is_alive": self.is_alive,
            "active_tasks": self.active_tasks,
        }


class ServiceConfig(Base):
    __tablename__ = "secflow_app_firmware_unpacker_service_configs"

    key = Column(String(128), primary_key=True)
    value = Column(Text, nullable=False)
    value_type = Column(String(32), nullable=False, default="string")
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "value_type": self.value_type,
            "description": self.description,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


DEFAULT_CONFIGS = [
    ("max_concurrent", "3", "int", "每个 Worker 最大并发解包任务数"),
    ("max_retries", "5", "int", "pi agent 最大重试轮数"),
    ("dead_threshold", "90", "int", "Worker 心跳超时秒数"),
    ("auto_cleanup_days", "7", "int", "已完成任务自动清理天数"),
]


_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        database = get_config().database
        kwargs = {
            "pool_pre_ping": True,
            "pool_recycle": 1800,
        }
        if database.type == "sqlite":
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            kwargs["pool_size"] = database.pool_size
            kwargs["max_overflow"] = database.max_overflow
        _engine = create_engine(database.url, **kwargs)
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            bind=get_engine(),
        )
    return _SessionFactory


def get_db():
    session_local = get_session_factory()
    db = session_local()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    return get_session_factory()()


def apply_table_prefix_if_needed() -> None:
    prefix = get_config().database.table_prefix
    UnpackTask.__table__.name = f"{prefix}unpack_tasks"
    WorkerInstance.__table__.name = f"{prefix}worker_instances"
    ServiceConfig.__table__.name = f"{prefix}service_configs"


def init_database() -> None:
    apply_table_prefix_if_needed()
    Base.metadata.create_all(bind=get_engine())
    _seed_default_configs()


def _seed_default_configs() -> None:
    db = get_db_session()
    try:
        for key, value, value_type, description in DEFAULT_CONFIGS:
            existing = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
            if existing:
                continue
            db.add(
                ServiceConfig(
                    key=key,
                    value=value,
                    value_type=value_type,
                    description=description,
                )
            )
        db.commit()
    finally:
        db.close()


def generate_id() -> str:
    raw = f"{uuid.uuid4()}_{datetime.utcnow().timestamp()}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def get_worker_id() -> str:
    worker_id = os.environ.get("WORKER_ID") or os.environ.get("HOSTNAME")
    if worker_id:
        return worker_id[:64]
    return socket.gethostname()[:64]


def get_config_value(db: Session, key: str, default=None):
    row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
    if not row:
        return default
    if row.value_type == "int":
        try:
            return int(row.value)
        except ValueError:
            return default
    if row.value_type == "bool":
        return row.value.lower() in ("1", "true", "yes")
    return row.value
