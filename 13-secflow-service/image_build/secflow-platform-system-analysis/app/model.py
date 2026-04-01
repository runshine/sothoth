"""Database models and session management."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, create_engine, func
from sqlalchemy.dialects.mysql import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import get_config

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class SystemAnalysisTask(Base):
    __tablename__ = "secflow_system_analysis_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    task_name: Mapped[str] = mapped_column(String(255), nullable=False)
    analysis_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    prompt_template_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prompt_content: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")

    total_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    running_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cancelled_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    execution_config_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    summary_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SystemAnalysisTaskNode(Base):
    __tablename__ = "secflow_system_analysis_task_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    agent_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    agent_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    helper_service_name: Mapped[str] = mapped_column(String(200), nullable=False)
    helper_session_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ai_agent_id: Mapped[str] = mapped_column(String(128), nullable=False)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")

    raw_response_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    normalized_result_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("task_id", "agent_key", name="uniq_system_analysis_task_node"),
    )


class SystemAnalysisPrompt(Base):
    __tablename__ = "secflow_system_analysis_prompts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prompt_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="general", index=True)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    variables_json: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SystemAnalysisReport(Base):
    __tablename__ = "secflow_system_analysis_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    summary_markdown: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    generated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())


class SystemAnalysisAuditLog(Base):
    __tablename__ = "secflow_system_analysis_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    operator: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    request_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    response_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), index=True)


_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        config = get_config()
        _engine = create_engine(
            config.database.url,
            pool_size=config.database.pool_size,
            max_overflow=config.database.max_overflow,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionFactory


def init_database():
    Base.metadata.create_all(bind=get_engine())


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    return get_session_factory()()
