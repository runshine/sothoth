"""SQLAlchemy ORM models for secflow-app-poc-gen-verify.

`AppPocTask` is the task row (DB = source of truth; `celery_task_id` links to the
Celery message). `AppPocTaskEvent` is the high-level timeline (start/running/
terminal/lease_renewed). The raw `poc` CLI log is streamed to disk (read by
GET /tasks/{id}/logs), NOT stored in DB.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import json

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.mysql import JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.time_utils import now_local


class Base(DeclarativeBase):
    pass


class AppPocTask(Base):
    """A PoC generation & GDB-verification task, scoped to a project."""
    __tablename__ = "secflow_app_poc_tasks"
    __table_args__ = (
        Index("ix_poc_tasks_sched", "is_deleted", "status", "execution_lease_until", "created_at", "id"),
        Index("ix_poc_tasks_owner", "execution_owner_id", "status"),
        Index("ix_poc_tasks_project_deleted_created_id", "project_id", "is_deleted", "created_at", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    task_name: Mapped[str] = mapped_column(String(255), nullable=False)
    task_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # `poc` CLI inputs (unpacked from the frontend request)
    entry_function: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_report_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    binary_dir: Mapped[str] = mapped_column(String(1024), nullable=False)
    output_dir: Mapped[str] = mapped_column(String(1024), nullable=False)
    model: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    effort: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    session_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    session_dir: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    timeout: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # The actual `poc` CLI command (shlex.join of the argv built by _execute_task),
    # persisted at execution start so the detail view can show the real cmd while the
    # task is still running (before stages_json/result_json are set at terminal state).
    cli_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # status: pending | running | succeeded | failed | timeout | cancelled
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    returncode: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    artifacts_json: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    result_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    stages_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # Per-task config overrides (e.g. {"feature_flags": {"poc_verifier": true}})
    task_config_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # Latest abnormal reason for observability (e.g. {"kind": "timeout", "detail": "..."})
    latest_abnormal_reason_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    execution_owner_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    execution_lease_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    execution_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    execution_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    control_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dispatch_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AppPocTaskEvent(Base):
    """High-level task timeline event for audit / /timeline."""
    __tablename__ = "secflow_app_poc_task_events"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_poc_task_events_dedupe_key"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    worker_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    execution_epoch: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    control_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, index=True)

    @property
    def payload(self) -> dict[str, Any]:
        if not self.payload_json:
            return {}
        try:
            loaded = json.loads(self.payload_json)
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {}

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = json.dumps(value or {}, ensure_ascii=False)


class AppPocPromptTemplate(Base):
    """Reusable prompt templates for secflow-app-poc-gen-verify."""
    __tablename__ = "secflow_app_poc_prompt_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    prompt_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="general")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    variables_json: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)

    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AppPocProjectConfig(Base):
    """Global PoC gen-verify configuration blob (project_id="" is the singleton)."""
    __tablename__ = "secflow_app_poc_project_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    config_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)


class AppPocFailureDebug(Base):
    """任务失败时 LLM 自动调试生成的故障定位报告."""
    __tablename__ = "secflow_app_poc_failure_debug"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    project_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    task_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # status: pending | running | done | error | skipped
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    error_kind: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    failing_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    report_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    report_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    debug_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)


class AppPocDebugConfig(Base):
    """Singleton config blob for the debugger role (e.g. debug model selection)."""
    __tablename__ = "secflow_app_poc_debug_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    config_key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True, default="global")
    config_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=now_local, onupdate=now_local)
