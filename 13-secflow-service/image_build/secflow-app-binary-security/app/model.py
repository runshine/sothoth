"""Database models for Binary Security orchestration."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_config


Base = declarative_base()

TASK_TERMINAL_STATUSES = {"success", "partial_success", "failed", "cancelled"}
ITEM_TERMINAL_STATUSES = {"success", "failed", "skipped", "cancelled"}
STAGE_SEQUENCE = [
    "firmware_unpack",
    "system_analysis",
    "binary_to_source",
    "entry_analysis",
    "dataflow_analysis",
    "vuln_scan",
]


class JsonMixin:
    def _load_json(self, raw: Optional[str], default: Any) -> Any:
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default

    def _dump_json(self, value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)


class BinarySecurityTask(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_task"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    current_stage = Column(String(64), nullable=True, index=True)
    firmware_name = Column(String(255), nullable=True)
    firmware_source = Column(String(32), nullable=False, default="project_filesystem")
    firmware_path = Column(Text, nullable=False)
    output_root = Column(Text, nullable=False)
    workspace_root = Column(Text, nullable=False)
    fileserver_subproject_id = Column(String(64), nullable=True)
    fileserver_subproject_name = Column(String(128), nullable=True)
    policy_json = Column(Text, nullable=True)
    summary_json = Column(Text, nullable=True)
    metrics_json = Column(Text, nullable=True)
    stage_summary_json = Column(Text, nullable=True)
    last_error = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def policy(self) -> dict[str, Any]:
        return self._load_json(self.policy_json, {})

    @policy.setter
    def policy(self, value: dict[str, Any] | None) -> None:
        self.policy_json = self._dump_json(value or {})

    @property
    def summary(self) -> dict[str, Any]:
        return self._load_json(self.summary_json, {})

    @summary.setter
    def summary(self, value: dict[str, Any] | None) -> None:
        self.summary_json = self._dump_json(value or {})

    @property
    def metrics(self) -> dict[str, Any]:
        return self._load_json(self.metrics_json, {})

    @metrics.setter
    def metrics(self, value: dict[str, Any] | None) -> None:
        self.metrics_json = self._dump_json(value or {})

    @property
    def stage_summary(self) -> dict[str, Any]:
        return self._load_json(self.stage_summary_json, {})

    @stage_summary.setter
    def stage_summary(self, value: dict[str, Any] | None) -> None:
        self.stage_summary_json = self._dump_json(value or {})


class BinarySecurityStageRun(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_stage_run"

    id = Column(String(40), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    stage_name = Column(String(64), nullable=False, index=True)
    sequence_no = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False, default="pending", index=True)
    retry_count = Column(Integer, nullable=False, default=0)
    input_snapshot_json = Column(Text, nullable=True)
    output_summary_json = Column(Text, nullable=True)
    counts_json = Column(Text, nullable=True)
    downstream_refs_json = Column(Text, nullable=True)
    last_error = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def input_snapshot(self) -> dict[str, Any]:
        return self._load_json(self.input_snapshot_json, {})

    @input_snapshot.setter
    def input_snapshot(self, value: dict[str, Any] | None) -> None:
        self.input_snapshot_json = self._dump_json(value or {})

    @property
    def output_summary(self) -> dict[str, Any]:
        return self._load_json(self.output_summary_json, {})

    @output_summary.setter
    def output_summary(self, value: dict[str, Any] | None) -> None:
        self.output_summary_json = self._dump_json(value or {})

    @property
    def counts(self) -> dict[str, Any]:
        return self._load_json(self.counts_json, {})

    @counts.setter
    def counts(self, value: dict[str, Any] | None) -> None:
        self.counts_json = self._dump_json(value or {})

    @property
    def downstream_refs(self) -> dict[str, Any]:
        return self._load_json(self.downstream_refs_json, {})

    @downstream_refs.setter
    def downstream_refs(self, value: dict[str, Any] | None) -> None:
        self.downstream_refs_json = self._dump_json(value or {})


class BinarySecurityStageItem(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_stage_item"

    id = Column(String(40), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    stage_run_id = Column(String(40), nullable=False, index=True)
    stage_name = Column(String(64), nullable=False, index=True)
    item_key = Column(String(128), nullable=False, index=True)
    item_name = Column(String(255), nullable=True)
    parent_key = Column(String(128), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    retry_count = Column(Integer, nullable=False, default=0)
    downstream_service = Column(String(64), nullable=True)
    downstream_task_id = Column(String(128), nullable=True, index=True)
    input_ref_json = Column(Text, nullable=True)
    output_ref_json = Column(Text, nullable=True)
    payload_json = Column(Text, nullable=True)
    result_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def input_ref(self) -> dict[str, Any]:
        return self._load_json(self.input_ref_json, {})

    @input_ref.setter
    def input_ref(self, value: dict[str, Any] | None) -> None:
        self.input_ref_json = self._dump_json(value or {})

    @property
    def output_ref(self) -> dict[str, Any]:
        return self._load_json(self.output_ref_json, {})

    @output_ref.setter
    def output_ref(self, value: dict[str, Any] | None) -> None:
        self.output_ref_json = self._dump_json(value or {})

    @property
    def payload(self) -> dict[str, Any]:
        return self._load_json(self.payload_json, {})

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = self._dump_json(value or {})

    @property
    def result(self) -> dict[str, Any]:
        return self._load_json(self.result_json, {})

    @result.setter
    def result(self, value: dict[str, Any] | None) -> None:
        self.result_json = self._dump_json(value or {})


class BinarySecurityEvent(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_event"

    id = Column(String(48), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    stage_name = Column(String(64), nullable=True, index=True)
    item_id = Column(String(40), nullable=True, index=True)
    item_key = Column(String(128), nullable=True, index=True)
    level = Column(String(16), nullable=False, default="info")
    event_type = Column(String(64), nullable=False, index=True)
    message = Column(Text, nullable=False)
    payload_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    @property
    def payload(self) -> dict[str, Any]:
        return self._load_json(self.payload_json, {})

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = self._dump_json(value or {})


class BinarySecurityProjectConfig(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_project_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(64), nullable=False, unique=True, index=True)
    config_json = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @property
    def config(self) -> dict[str, Any]:
        return self._load_json(self.config_json, {})

    @config.setter
    def config(self, value: dict[str, Any] | None) -> None:
        self.config_json = self._dump_json(value or {})


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
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=get_engine())
    return _SessionFactory


def init_database() -> None:
    Base.metadata.create_all(bind=get_engine())


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()
