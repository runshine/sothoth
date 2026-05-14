"""Database models for Binary Security orchestration."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_config
from app.time_utils import now_local


Base = declarative_base()

TASK_TERMINAL_STATUSES = {"success", "partial_success", "failed", "cancelled"}
ITEM_TERMINAL_STATUSES = {"success", "failed", "cancelled"}
STAGE_SEQUENCE = [
    "firmware_unpack",
    "system_analysis",
    "binary_to_source",
    "entry_analysis",
    "dataflow_analysis",
    "vuln_scan",
]
TASK_TYPE_BINARY = "binary"
TASK_TYPE_SOURCE = "source"
TASK_STAGE_SEQUENCES = {
    TASK_TYPE_BINARY: STAGE_SEQUENCE,
    TASK_TYPE_SOURCE: [
        "system_analysis",
        "entry_analysis",
        "dataflow_analysis",
        "vuln_scan",
    ],
}


def normalize_parent_key(value: str | None) -> str:
    return str(value or "").strip()


def build_stage_item_identity_key(item_key: str | None, parent_key: str | None) -> str:
    return f"{str(item_key or '').strip()}::{normalize_parent_key(parent_key)}"


def build_archive_job_dedupe_key(item_id: str | None, downstream_task_id: str | None) -> str:
    return f"{str(item_id or '').strip()}::{str(downstream_task_id or '').strip()}"


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
    SUMMARY_FILENAME = "task-summary.json"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    task_type = Column(String(32), nullable=False, default=TASK_TYPE_BINARY, index=True)
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
    execution_mode = Column(String(32), nullable=True, index=True)
    target_stage_name = Column(String(64), nullable=True, index=True)
    pending_action = Column(String(32), nullable=True, index=True)
    last_error = Column(Text, nullable=True)
    operation_lock_owner = Column(String(128), nullable=True, index=True)
    operation_lock_token = Column(String(64), nullable=True, index=True)
    operation_lock_type = Column(String(32), nullable=True, index=True)
    operation_lock_acquired_at = Column(DateTime, nullable=True)
    operation_lock_heartbeat_at = Column(DateTime, nullable=True)
    operation_lock_expires_at = Column(DateTime, nullable=True, index=True)
    dispatcher_instance_id = Column(String(128), nullable=True, index=True)
    dispatch_started_at = Column(DateTime, nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

    @property
    def policy(self) -> dict[str, Any]:
        return self._load_json(self.policy_json, {})

    @policy.setter
    def policy(self, value: dict[str, Any] | None) -> None:
        self.policy_json = self._dump_json(value or {})

    @property
    def summary(self) -> dict[str, Any]:
        cached = getattr(self, "_summary_cache", None)
        if isinstance(cached, dict):
            return dict(cached)
        path = self._summary_file_path()
        if path and path.is_file():
            try:
                data = json.loads(path.read_text("utf-8") or "{}")
                if isinstance(data, dict):
                    self._summary_cache = data
                    return dict(data)
            except Exception:
                pass
        return self._load_json(self.summary_json, {})

    @summary.setter
    def summary(self, value: dict[str, Any] | None) -> None:
        payload = value or {}
        self._summary_cache = dict(payload)
        path = self._summary_file_path()
        if path and path.parent.exists():
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(self._dump_json(payload), encoding="utf-8")
            tmp.replace(path)
            self.summary_json = None
            return
        self.summary_json = self._dump_json(payload)

    def _summary_file_path(self) -> Path | None:
        if not self.workspace_root:
            return None
        return Path(self.workspace_root) / self.SUMMARY_FILENAME

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
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

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
    item_identity_key = Column(String(255), nullable=True, index=True)
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
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

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


class BinarySecurityArchiveJob(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_archive_job"

    id = Column(String(48), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    stage_name = Column(String(64), nullable=False, index=True)
    item_id = Column(String(40), nullable=False, index=True)
    item_key = Column(String(128), nullable=True, index=True)
    job_dedupe_key = Column(String(255), nullable=True, index=True)
    downstream_service = Column(String(64), nullable=True, index=True)
    downstream_task_id = Column(String(128), nullable=True, index=True)
    archive_status = Column(String(32), nullable=False, default="pending", index=True)
    owner_id = Column(String(128), nullable=True, index=True)
    payload_json = Column(Text, nullable=True)
    archive_root = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=now_local, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

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


class BinarySecurityServiceConfig(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_service_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    config_key = Column(String(64), nullable=False, unique=True, index=True)
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
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _ensure_compat_columns(engine)


def _ensure_compat_columns(engine) -> None:
    inspector = inspect(engine)
    task_table = BinarySecurityTask.__tablename__
    if inspector.has_table(task_table):
        columns = {column["name"] for column in inspector.get_columns(task_table)}
        statements = []
        if "dispatcher_instance_id" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN dispatcher_instance_id VARCHAR(128) NULL"
            )
        if "dispatch_started_at" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN dispatch_started_at DATETIME NULL"
            )
        if "lease_expires_at" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN lease_expires_at DATETIME NULL"
            )
        if "task_type" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN task_type VARCHAR(32) NOT NULL DEFAULT '{TASK_TYPE_BINARY}'"
            )
        if "execution_mode" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN execution_mode VARCHAR(32) NULL"
            )
        if "target_stage_name" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN target_stage_name VARCHAR(64) NULL"
            )
        if "pending_action" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN pending_action VARCHAR(32) NULL"
            )
        if "operation_lock_owner" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN operation_lock_owner VARCHAR(128) NULL"
            )
        if "operation_lock_token" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN operation_lock_token VARCHAR(64) NULL"
            )
        if "operation_lock_type" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN operation_lock_type VARCHAR(32) NULL"
            )
        if "operation_lock_acquired_at" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN operation_lock_acquired_at DATETIME NULL"
            )
        if "operation_lock_heartbeat_at" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN operation_lock_heartbeat_at DATETIME NULL"
            )
        if "operation_lock_expires_at" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN operation_lock_expires_at DATETIME NULL"
            )
        with engine.begin() as conn:
            for statement in statements:
                conn.execute(text(statement))
        indexes = {index["name"] for index in inspector.get_indexes(task_table)}
        index_statements = []
        if "ix_bst_project_type_created_id" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bst_project_type_created_id ON {task_table} (project_id, task_type, created_at, id)"
            )
        if "ix_bst_project_status_created_id" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bst_project_status_created_id ON {task_table} (project_id, status, created_at, id)"
            )
        if "ix_bst_operation_lock_expires" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bst_operation_lock_expires ON {task_table} (operation_lock_expires_at)"
            )
        with engine.begin() as conn:
            for statement in index_statements:
                conn.execute(text(statement))
    stage_item_table = BinarySecurityStageItem.__tablename__
    if inspector.has_table(stage_item_table):
        columns = {column["name"] for column in inspector.get_columns(stage_item_table)}
        statements = []
        if "item_identity_key" not in columns:
            statements.append(
                f"ALTER TABLE {stage_item_table} ADD COLUMN item_identity_key VARCHAR(255) NULL"
            )
        with engine.begin() as conn:
            for statement in statements:
                conn.execute(text(statement))
        indexes = {index["name"] for index in inspector.get_indexes(stage_item_table)}
        index_statements = []
        if "ix_bssi_task_stage_identity_created" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssi_task_stage_identity_created ON {stage_item_table} "
                "(task_id, stage_name, item_identity_key, created_at)"
            )
        with engine.begin() as conn:
            for statement in index_statements:
                conn.execute(text(statement))
    archive_job_table = BinarySecurityArchiveJob.__tablename__
    if inspector.has_table(archive_job_table):
        columns = {column["name"] for column in inspector.get_columns(archive_job_table)}
        statements = []
        if "job_dedupe_key" not in columns:
            statements.append(
                f"ALTER TABLE {archive_job_table} ADD COLUMN job_dedupe_key VARCHAR(255) NULL"
            )
        with engine.begin() as conn:
            for statement in statements:
                conn.execute(text(statement))
        indexes = {index["name"] for index in inspector.get_indexes(archive_job_table)}
        index_statements = []
        if "ix_bsaj_task_stage_dedupe_status" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bsaj_task_stage_dedupe_status ON {archive_job_table} "
                "(task_id, stage_name, job_dedupe_key, archive_status)"
            )
        with engine.begin() as conn:
            for statement in index_statements:
                conn.execute(text(statement))


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()
