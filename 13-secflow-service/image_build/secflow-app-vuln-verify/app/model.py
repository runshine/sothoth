"""Database models for vuln-verify app."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, inspect
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_config
from app.time_utils import now_local

Base = declarative_base()
logger = logging.getLogger(__name__)


class VulnVerifyTask(Base):
    __tablename__ = "secflow_vuln_verify_task"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    reports_dir = Column(Text, nullable=False)
    source_root = Column(Text, nullable=False)
    binary_root = Column(Text, nullable=True)
    threat_path = Column(Text, nullable=True)
    output_dir = Column(Text, nullable=False)
    model = Column(String(255), nullable=True)
    concurrency = Column(Integer, nullable=False, default=4)
    resume = Column(Integer, nullable=False, default=0)
    pid = Column(Integer, nullable=True)
    return_code = Column(Integer, nullable=True)
    worker_id = Column(String(128), nullable=True, index=True)
    lease_until = Column(DateTime, nullable=True, index=True)
    heartbeat_at = Column(DateTime, nullable=True)
    error_reason = Column(Text, nullable=True)
    progress_json = Column(Text, nullable=True)
    result_summary_json = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    @property
    def progress(self) -> dict[str, Any]:
        return _loads(self.progress_json, {})

    @progress.setter
    def progress(self, value: dict[str, Any] | None) -> None:
        self.progress_json = json.dumps(value or {}, ensure_ascii=False)

    @property
    def result_summary(self) -> dict[str, Any]:
        return _loads(self.result_summary_json, {})

    @result_summary.setter
    def result_summary(self, value: dict[str, Any] | None) -> None:
        self.result_summary_json = json.dumps(value or {}, ensure_ascii=False)


class VulnVerifyTaskEvent(Base):
    __tablename__ = "secflow_vuln_verify_task_event"

    id = Column(String(32), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    level = Column(String(16), nullable=False, default="info", index=True)
    status = Column(String(32), nullable=True, index=True)
    message = Column(Text, nullable=False)
    payload_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False, index=True)

    @property
    def payload(self) -> dict[str, Any]:
        return _loads(self.payload_json, {})

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = json.dumps(value or {}, ensure_ascii=False)


class VulnVerifyServiceConfig(Base):
    __tablename__ = "secflow_vuln_verify_service_config"

    config_key = Column(String(64), primary_key=True)
    config_json = Column(Text, nullable=False)
    updated_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
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
    _ensure_columns(engine)


def _ensure_columns(engine) -> None:
    table = VulnVerifyTask.__tablename__
    inspector = inspect(engine)
    columns = inspector.get_columns(table)
    column_by_name = {column["name"]: column for column in columns}
    existing = set(column_by_name)
    statements: list[str] = []
    for name, ddl in {
        "pid": "INTEGER NULL",
        "return_code": "INTEGER NULL",
        "worker_id": "VARCHAR(128) NULL",
        "lease_until": "DATETIME NULL",
        "heartbeat_at": "DATETIME NULL",
        "progress_json": "TEXT NULL",
        "result_summary_json": "TEXT NULL",
        "description": "TEXT NULL",
    }.items():
        if name not in existing:
            statements.append(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    # Older MySQL deployments created these columns as NOT NULL.  The current
    # native task API intentionally allows callers to omit binary_root,
    # threat_path and model so default/runtime behaviour can be used.
    # create_all() does not alter existing columns, therefore fix legacy schema
    # drift during service startup.
    if engine.dialect.name in {"mysql", "mariadb"}:
        nullable_migrations = {
            "binary_root": "TEXT NULL",
            "threat_path": "TEXT NULL",
            "model": "VARCHAR(255) NULL",
        }
        for name, ddl in nullable_migrations.items():
            column = column_by_name.get(name)
            if column and not bool(column.get("nullable", True)):
                statements.append(f"ALTER TABLE {table} MODIFY COLUMN {name} {ddl}")

    with engine.begin() as conn:
        for statement in statements:
            logger.info("Applying vuln-verify DB migration: %s", statement)
            conn.exec_driver_sql(statement)


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def get_db_session():
    return get_session_factory()()
