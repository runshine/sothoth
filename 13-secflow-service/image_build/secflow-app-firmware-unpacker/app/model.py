"""Database models for firmware unpacker service."""

from __future__ import annotations

import enum
import hashlib
import os
import socket
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, inspect, text
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
    matched_skill = Column(String(512), nullable=True)
    matched_skill_version = Column(Integer, nullable=True)
    matched_skill_score = Column(Integer, nullable=True)
    fallback_to_llm = Column(Boolean, nullable=False, default=False)
    generated_skill_path = Column(String(512), nullable=True)
    generated_skill_status = Column(String(32), nullable=True)
    promotion_success_count = Column(Integer, nullable=True)
    agentflow_run_id = Column(String(64), nullable=True)
    engine_mode = Column(String(32), nullable=True)
    engine_error = Column(Text, nullable=True)
    run_path = Column(String(512), nullable=True)
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
            "matched_skill": self.matched_skill,
            "matched_skill_version": self.matched_skill_version,
            "matched_skill_score": self.matched_skill_score,
            "fallback_to_llm": self.fallback_to_llm,
            "generated_skill_path": self.generated_skill_path,
            "generated_skill_status": self.generated_skill_status,
            "promotion_success_count": self.promotion_success_count,
            "agentflow_run_id": self.agentflow_run_id,
            "engine_mode": self.engine_mode,
            "engine_error": self.engine_error,
            "run_path": self.run_path,
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
    ("concurrency_mode", "auto", "string", "并发控制模式：auto=按 Pod CPU/内存自动计算，manual=手动指定"),
    ("manual_max_concurrent", "3", "int", "手动模式下单个 Pod 最大并发解包任务数"),
    ("cpu_millis_per_task", "250", "int", "自动模式下单个解包任务预估占用 CPU(millicores)"),
    ("memory_mb_per_task", "512", "int", "自动模式下单个解包任务预估占用内存(MiB)"),
    ("reserved_cpu_millis", "100", "int", "自动模式下为 Pod 自身保留的 CPU(millicores)"),
    ("reserved_memory_mb", "256", "int", "自动模式下为 Pod 自身保留的内存(MiB)"),
    ("max_concurrent", "3", "int", "兼容旧版本：单个 Worker 最大并发解包任务数"),
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
    _ensure_unpack_task_columns()
    _seed_default_configs()


def _ensure_unpack_task_columns() -> None:
    engine = get_engine()
    inspector = inspect(engine)
    try:
        columns = {column["name"] for column in inspector.get_columns(UnpackTask.__table__.name)}
    except Exception:
        return

    statements = {
        "matched_skill": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN matched_skill VARCHAR(512)",
        "matched_skill_version": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN matched_skill_version INTEGER",
        "matched_skill_score": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN matched_skill_score INTEGER",
        "fallback_to_llm": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN fallback_to_llm BOOLEAN DEFAULT 0",
        "generated_skill_path": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN generated_skill_path VARCHAR(512)",
        "generated_skill_status": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN generated_skill_status VARCHAR(32)",
        "promotion_success_count": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN promotion_success_count INTEGER",
        "agentflow_run_id": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN agentflow_run_id VARCHAR(64)",
        "engine_mode": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN engine_mode VARCHAR(32)",
        "engine_error": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN engine_error TEXT",
        "run_path": f"ALTER TABLE {UnpackTask.__table__.name} ADD COLUMN run_path VARCHAR(512)",
    }

    with engine.begin() as conn:
        for column_name, statement in statements.items():
            if column_name in columns:
                continue
            conn.execute(text(statement))


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
