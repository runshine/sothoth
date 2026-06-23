"""Database models for Binary Security orchestration."""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint, create_engine, inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_config
from app.observability import observe_state_file_write
from app.time_utils import now_local


Base = declarative_base()

TASK_TERMINAL_STATUSES = {"success", "partial_success", "failed", "cancelled", "cancel_failed", "delete_failed"}
ITEM_TERMINAL_STATUSES = {"success", "failed", "cancelled"}
STAGE_SEQUENCE = [
    "firmware_unpack",
    "system_analysis",
    "binary_to_source",
    "entry_analysis",
    "dataflow_vuln_scan",
]
KG_SOURCE_VULN_SCAN_STAGE_SEQUENCE = [
    "knowledge_graph_entry_fetch",
    "dataflow_vuln_scan",
]
TASK_TYPE_BINARY = "binary"
TASK_TYPE_SOURCE = "source"
TASK_TYPE_BINARY_MODULE = "binary_module"
PIPELINE_PROFILE_DEFAULT = "default"
PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN = "kg_source_vuln_scan"
TASK_RUNTIME_PHASE_OWNED_EXECUTION = "owned_execution"
TASK_RUNTIME_PHASE_TAIL_RECONCILIATION = "tail_reconciliation"
TASK_RUNTIME_PHASE_TERMINAL = "terminal"
TASK_STAGE_SEQUENCES = {
    TASK_TYPE_BINARY: STAGE_SEQUENCE,
    TASK_TYPE_SOURCE: [
        "system_analysis",
        "entry_analysis",
        "dataflow_vuln_scan",
    ],
    TASK_TYPE_BINARY_MODULE: [
        "binary_to_source",
        "entry_analysis",
        "dataflow_vuln_scan",
    ],
}
TASK_PIPELINE_PROFILE_SEQUENCES = {
    (TASK_TYPE_SOURCE, PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN): KG_SOURCE_VULN_SCAN_STAGE_SEQUENCE,
}

LEGACY_STAGE_NAME_ALIASES = {
    "dataflow_analysis": "dataflow_vuln_scan",
    "vuln_scan": "dataflow_vuln_scan",
}


def normalize_stage_name(value: str | None) -> str:
    normalized = str(value or "").strip()
    return LEGACY_STAGE_NAME_ALIASES.get(normalized, normalized)


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

    def _load_externalized_json(self, value: Any, *, path_key: str) -> Any:
        if not isinstance(value, dict):
            return value
        path_value = str(value.get(path_key) or "").strip()
        if not path_value:
            return value
        try:
            loaded = json.loads(Path(path_value).read_text(encoding="utf-8"))
        except Exception:
            fallback = dict(value)
            fallback[f"missing_externalized_{path_key}"] = True
            return fallback
        return loaded if isinstance(loaded, dict) else value


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
    runtime_override_json = Column(Text, nullable=True)
    runtime_override_version = Column(Integer, nullable=False, default=0)
    runtime_override_updated_at = Column(DateTime, nullable=True)
    runtime_override_updated_by = Column(String(64), nullable=True)
    summary_json = Column(Text, nullable=True)
    metrics_json = Column(Text, nullable=True)
    stage_summary_json = Column(Text, nullable=True)
    schedule_user_task_id = Column(String(64), nullable=True, index=True)
    task_key_source = Column(String(32), nullable=True, index=True)
    root_task_key_id = Column(String(64), nullable=True, index=True)
    root_task_key_name = Column(String(255), nullable=True)
    root_task_key_prefix = Column(String(128), nullable=True)
    execution_epoch = Column(Integer, nullable=False, default=0)
    execution_mode = Column(String(32), nullable=True, index=True)
    target_stage_name = Column(String(64), nullable=True, index=True)
    current_operation_id = Column(String(48), nullable=True, index=True)
    cleanup_snapshot_json = Column(Text, nullable=True)
    last_error = Column(Text, nullable=True)
    latest_abnormal_reason_json = Column(Text, nullable=True)
    runtime_phase = Column(String(32), nullable=False, default=TASK_RUNTIME_PHASE_OWNED_EXECUTION, index=True)
    tail_reconcile_state = Column(String(32), nullable=False, default="idle", index=True)
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
    def runtime_override(self) -> dict[str, Any]:
        return self._load_json(self.runtime_override_json, {})

    @runtime_override.setter
    def runtime_override(self, value: dict[str, Any] | None) -> None:
        self.runtime_override_json = self._dump_json(value or {})

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
        cleanup_snapshot = self.cleanup_snapshot
        delete_in_progress = bool(cleanup_snapshot.get("delete_in_progress"))
        if path and path.parent.exists() and not delete_in_progress:
            tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
            started = time.perf_counter()
            try:
                tmp.write_text(self._dump_json(payload), encoding="utf-8")
                tmp.replace(path)
                observe_state_file_write(target=path.name, result="success", duration_seconds=time.perf_counter() - started)
            except Exception:
                observe_state_file_write(target=path.name, result="failed", duration_seconds=time.perf_counter() - started)
                raise
            finally:
                try:
                    if tmp.exists():
                        tmp.unlink()
                except Exception:
                    pass
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

    @property
    def cleanup_snapshot(self) -> dict[str, Any]:
        return self._load_json(self.cleanup_snapshot_json, {})

    @cleanup_snapshot.setter
    def cleanup_snapshot(self, value: dict[str, Any] | None) -> None:
        self.cleanup_snapshot_json = self._dump_json(value or {})

    @property
    def latest_abnormal_reason(self) -> dict[str, Any] | None:
        payload = self._load_json(self.latest_abnormal_reason_json, None)
        return payload if isinstance(payload, dict) else None

    @latest_abnormal_reason.setter
    def latest_abnormal_reason(self, value: dict[str, Any] | None) -> None:
        self.latest_abnormal_reason_json = self._dump_json(value or {}) if value else None


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
    rerun_count = Column(Integer, nullable=False, default=0)
    downstream_service = Column(String(64), nullable=True)
    downstream_task_id = Column(String(128), nullable=True, index=True)
    claim_owner_instance_id = Column(String(128), nullable=True, index=True)
    claim_execution_token = Column(String(64), nullable=True, index=True)
    claim_started_at = Column(DateTime, nullable=True)
    input_ref_json = Column(Text, nullable=True)
    output_ref_json = Column(Text, nullable=True)
    payload_json = Column(Text, nullable=True)
    result_json = Column(MEDIUMTEXT, nullable=True)
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
    operation_id = Column(String(48), nullable=True, index=True)
    stage_name = Column(String(64), nullable=True, index=True)
    item_id = Column(String(40), nullable=True, index=True)
    item_key = Column(String(128), nullable=True, index=True)
    level = Column(String(16), nullable=False, default="info")
    event_type = Column(String(64), nullable=False, index=True)
    message = Column(Text, nullable=False)
    payload_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False, index=True)

    @property
    def payload(self) -> dict[str, Any]:
        return self._load_json(self.payload_json, {})

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = self._dump_json(value or {})


class BinarySecuritySyncEvent(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_sync_event"

    id = Column(String(48), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    task_id = Column(String(32), nullable=False, index=True)
    stage_name = Column(String(64), nullable=True, index=True)
    item_id = Column(String(40), nullable=True, index=True)
    item_bucket_key = Column(String(255), nullable=True, index=True)
    item_key = Column(String(128), nullable=True, index=True)
    item_name = Column(String(255), nullable=True)
    downstream_service = Column(String(64), nullable=True, index=True)
    downstream_task_id = Column(String(128), nullable=True, index=True)
    operation = Column(String(64), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    sync_status = Column(String(64), nullable=True, index=True)
    outcome = Column(String(64), nullable=True, index=True)
    state_applied = Column(Boolean, nullable=True, index=True)
    error_type = Column(String(128), nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    http_status = Column(Integer, nullable=True)
    recorder_instance_id = Column(String(128), nullable=True, index=True)
    recorder_hostname = Column(String(255), nullable=True)
    recorder_pod_name = Column(String(255), nullable=True)
    recorder_node_name = Column(String(255), nullable=True)
    recorder_role = Column(String(64), nullable=True, index=True)
    origin_instance_id = Column(String(128), nullable=True, index=True)
    origin_hostname = Column(String(255), nullable=True)
    origin_pod_name = Column(String(255), nullable=True)
    origin_node_name = Column(String(255), nullable=True)
    origin_role = Column(String(64), nullable=True, index=True)
    payload_json = Column(MEDIUMTEXT, nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False, index=True)

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


class BinarySecurityTaskOperation(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_task_operation"

    id = Column(String(48), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    operation_type = Column(String(64), nullable=False, index=True)
    target_stage = Column(String(64), nullable=True, index=True)
    requested_by = Column(String(64), nullable=True, index=True)
    request_source = Column(String(32), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="requested", index=True)
    operation_token = Column(String(64), nullable=False, index=True)
    request_payload_json = Column(MEDIUMTEXT, nullable=True)
    result_payload_json = Column(MEDIUMTEXT, nullable=True)
    error_code = Column(String(64), nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    current_step = Column(String(64), nullable=True, index=True)
    step_attempts_json = Column(Text, nullable=True)
    step_payload_json = Column(Text, nullable=True)
    resume_cursor_json = Column(Text, nullable=True)
    superseded_by_operation_id = Column(String(48), nullable=True, index=True)
    created_at = Column(DateTime, default=now_local, nullable=False, index=True)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)
    started_at = Column(DateTime, nullable=True, index=True)
    finished_at = Column(DateTime, nullable=True, index=True)

    @property
    def request_payload(self) -> dict[str, Any]:
        value = self._load_json(self.request_payload_json, {})
        return self._load_externalized_json(value, path_key="request_payload_path")

    @request_payload.setter
    def request_payload(self, value: dict[str, Any] | None) -> None:
        self.request_payload_json = self._dump_json(value or {})

    @property
    def result_payload(self) -> dict[str, Any]:
        value = self._load_json(self.result_payload_json, {})
        return self._load_externalized_json(value, path_key="result_payload_path")

    @result_payload.setter
    def result_payload(self, value: dict[str, Any] | None) -> None:
        self.result_payload_json = self._dump_json(value or {})

    @property
    def step_attempts(self) -> dict[str, Any]:
        return self._load_json(self.step_attempts_json, {})

    @step_attempts.setter
    def step_attempts(self, value: dict[str, Any] | None) -> None:
        self.step_attempts_json = self._dump_json(value or {})

    @property
    def step_payload(self) -> dict[str, Any]:
        return self._load_json(self.step_payload_json, {})

    @step_payload.setter
    def step_payload(self, value: dict[str, Any] | None) -> None:
        self.step_payload_json = self._dump_json(value or {})

    @property
    def resume_cursor(self) -> dict[str, Any]:
        return self._load_json(self.resume_cursor_json, {})

    @resume_cursor.setter
    def resume_cursor(self, value: dict[str, Any] | None) -> None:
        self.resume_cursor_json = self._dump_json(value or {})


class BinarySecurityStateEvent(Base, JsonMixin):
    __tablename__ = "secflow_binary_security_state_event"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_binary_security_state_event_idempotency"),
    )

    id = Column(String(48), primary_key=True)
    task_id = Column(String(32), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    stage_name = Column(String(64), nullable=True, index=True)
    item_id = Column(String(40), nullable=True, index=True)
    archive_job_id = Column(String(48), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    idempotency_key = Column(String(255), nullable=False, index=True)
    payload_json = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    available_at = Column(DateTime, default=now_local, nullable=False, index=True)
    leased_by = Column(String(128), nullable=True, index=True)
    processed_by = Column(String(128), nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)
    processing_started_at = Column(DateTime, nullable=True, index=True)
    processing_finished_at = Column(DateTime, nullable=True, index=True)
    processed_at = Column(DateTime, nullable=True, index=True)
    processing_result = Column(String(32), nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    last_error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_local, nullable=False, index=True)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

    @property
    def payload(self) -> dict[str, Any]:
        return self._load_json(self.payload_json, {})

    @payload.setter
    def payload(self, value: dict[str, Any] | None) -> None:
        self.payload_json = self._dump_json(value or {})


class BinarySecurityTaskStateLease(Base):
    __tablename__ = "secflow_binary_security_task_state_lease"

    task_id = Column(String(32), primary_key=True)
    owner_id = Column(String(128), nullable=False, index=True)
    lease_token = Column(String(64), nullable=False, index=True)
    lease_expires_at = Column(DateTime, nullable=False, index=True)
    heartbeat_at = Column(DateTime, nullable=False)
    operation = Column(String(64), nullable=False, default="state_reduce")
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)


class BinarySecurityTaskRuntimeLease(Base):
    __tablename__ = "secflow_binary_security_task_runtime_lease"

    task_id = Column(String(32), primary_key=True)
    execution_epoch = Column(Integer, nullable=False, default=0)
    owner_instance_id = Column(String(128), nullable=False, index=True)
    owner_pod_uid = Column(String(128), nullable=True, index=True)
    owner_boot_id = Column(String(128), nullable=True, index=True)
    generation = Column(Integer, nullable=False, default=0, index=True)
    owner_started_at = Column(DateTime, nullable=True, index=True)
    last_renewed_at = Column(DateTime, nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=False, index=True)
    heartbeat_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)


class BinarySecurityCoordinatorLease(Base):
    __tablename__ = "secflow_binary_security_coordinator_lease"

    lease_name = Column(String(64), primary_key=True)
    owner_instance_id = Column(String(128), nullable=False, index=True)
    lease_expires_at = Column(DateTime, nullable=False, index=True)
    heartbeat_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=now_local, nullable=False)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)


class BinarySecurityProjectConfig(Base, JsonMixin):
    """Legacy per-project config row kept only as a migration source for global task policy."""
    __tablename__ = "secflow_binary_security_project_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(64), nullable=False, unique=True, index=True)
    config_json = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

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
    updated_at = Column(DateTime, default=now_local, onupdate=now_local, nullable=False)

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
    def _execute_compat_statements(statements: list[str]) -> None:
        if not statements:
            return
        with engine.begin() as conn:
            for statement in statements:
                try:
                    conn.execute(text(statement))
                except OperationalError as exc:
                    orig = getattr(exc, "orig", None)
                    errno = None
                    if orig is not None:
                        args = getattr(orig, "args", ())
                        if args:
                            errno = args[0]
                    # MySQL duplicate column/index errors should be treated as
                    # idempotent during multi-pod startup migrations.
                    if int(errno or 0) in {1060, 1061}:
                        continue
                    raise

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
        if "current_operation_id" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN current_operation_id VARCHAR(48) NULL"
            )
        if "runtime_override_json" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN runtime_override_json TEXT NULL"
            )
        if "runtime_override_version" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN runtime_override_version INTEGER NOT NULL DEFAULT 0"
            )
        if "schedule_user_task_id" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN schedule_user_task_id VARCHAR(64) NULL"
            )
        if "task_key_source" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN task_key_source VARCHAR(32) NULL"
            )
        if "root_task_key_id" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN root_task_key_id VARCHAR(64) NULL"
            )
        if "root_task_key_name" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN root_task_key_name VARCHAR(255) NULL"
            )
        if "root_task_key_prefix" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN root_task_key_prefix VARCHAR(128) NULL"
            )
        if "runtime_override_updated_at" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN runtime_override_updated_at DATETIME NULL"
            )
        if "runtime_override_updated_by" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN runtime_override_updated_by VARCHAR(64) NULL"
            )
        if "execution_epoch" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN execution_epoch INTEGER NOT NULL DEFAULT 0"
            )
        if "cleanup_snapshot_json" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN cleanup_snapshot_json TEXT NULL"
            )
        if "runtime_phase" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN runtime_phase VARCHAR(32) NOT NULL DEFAULT '{TASK_RUNTIME_PHASE_OWNED_EXECUTION}'"
            )
        if "tail_reconcile_state" not in columns:
            statements.append(
                "ALTER TABLE {task_table} ADD COLUMN tail_reconcile_state VARCHAR(32) NOT NULL DEFAULT 'idle'".format(
                    task_table=task_table
                )
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
        if "latest_abnormal_reason_json" not in columns:
            statements.append(
                f"ALTER TABLE {task_table} ADD COLUMN latest_abnormal_reason_json TEXT NULL"
            )
        _execute_compat_statements(statements)
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
        _execute_compat_statements(index_statements)
    event_table = BinarySecurityEvent.__tablename__
    if inspector.has_table(event_table):
        columns = {column["name"] for column in inspector.get_columns(event_table)}
        statements = []
        if "operation_id" not in columns:
            statements.append(
                f"ALTER TABLE {event_table} ADD COLUMN operation_id VARCHAR(48) NULL"
            )
        _execute_compat_statements(statements)
    sync_event_table = BinarySecuritySyncEvent.__tablename__
    if inspector.has_table(sync_event_table):
        columns = {column["name"] for column in inspector.get_columns(sync_event_table)}
        statements = []
        if "item_bucket_key" not in columns:
            statements.append(
                f"ALTER TABLE {sync_event_table} ADD COLUMN item_bucket_key VARCHAR(255) NULL"
            )
        _execute_compat_statements(statements)
        indexes = {index["name"] for index in inspector.get_indexes(sync_event_table)}
        index_statements = []
        if "ix_bssync_task_created_id" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssync_task_created_id ON {sync_event_table} (task_id, created_at, id)"
            )
        if "ix_bssync_task_stage_created" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssync_task_stage_created ON {sync_event_table} (task_id, stage_name, created_at)"
            )
        if "ix_bssync_task_event_created" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssync_task_event_created ON {sync_event_table} (task_id, event_type, created_at)"
            )
        if "ix_bssync_task_service_created" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssync_task_service_created ON {sync_event_table} (task_id, downstream_service, created_at)"
            )
        if "ix_bssync_task_bucket_created" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssync_task_bucket_created ON {sync_event_table} (task_id, item_bucket_key, created_at, id)"
            )
        _execute_compat_statements(index_statements)
    else:
        Base.metadata.tables[sync_event_table].create(bind=engine, checkfirst=True)
    stage_item_table = BinarySecurityStageItem.__tablename__
    if inspector.has_table(stage_item_table):
        column_defs = {column["name"]: column for column in inspector.get_columns(stage_item_table)}
        columns = set(column_defs)
        statements = []
        if "item_identity_key" not in columns:
            statements.append(
                f"ALTER TABLE {stage_item_table} ADD COLUMN item_identity_key VARCHAR(255) NULL"
            )
        if "rerun_count" not in columns:
            statements.append(
                f"ALTER TABLE {stage_item_table} ADD COLUMN rerun_count INTEGER NOT NULL DEFAULT 0"
            )
            statements.append(
                f"UPDATE {stage_item_table} SET rerun_count = retry_count WHERE rerun_count = 0 AND retry_count > 0"
            )
        if "claim_owner_instance_id" not in columns:
            statements.append(
                f"ALTER TABLE {stage_item_table} ADD COLUMN claim_owner_instance_id VARCHAR(128) NULL"
            )
        if "claim_execution_token" not in columns:
            statements.append(
                f"ALTER TABLE {stage_item_table} ADD COLUMN claim_execution_token VARCHAR(64) NULL"
            )
        if "claim_started_at" not in columns:
            statements.append(
                f"ALTER TABLE {stage_item_table} ADD COLUMN claim_started_at DATETIME NULL"
            )
        result_json_type = str(column_defs.get("result_json", {}).get("type") or "").lower()
        if "result_json" in columns and "mediumtext" not in result_json_type:
            statements.append(
                f"ALTER TABLE {stage_item_table} MODIFY COLUMN result_json MEDIUMTEXT NULL"
            )
        _execute_compat_statements(statements)
        indexes = {index["name"] for index in inspector.get_indexes(stage_item_table)}
        index_statements = []
        if "ix_bssi_task_stage_identity_created" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssi_task_stage_identity_created ON {stage_item_table} "
                "(task_id, stage_name, item_identity_key, created_at)"
            )
        if "ix_bssi_claim_owner_instance_id" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssi_claim_owner_instance_id ON {stage_item_table} (claim_owner_instance_id)"
            )
        if "ix_bssi_claim_execution_token" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bssi_claim_execution_token ON {stage_item_table} (claim_execution_token)"
            )
        _execute_compat_statements(index_statements)
    archive_job_table = BinarySecurityArchiveJob.__tablename__
    if inspector.has_table(archive_job_table):
        columns = {column["name"] for column in inspector.get_columns(archive_job_table)}
        statements = []
        if "job_dedupe_key" not in columns:
            statements.append(
                f"ALTER TABLE {archive_job_table} ADD COLUMN job_dedupe_key VARCHAR(255) NULL"
            )
        _execute_compat_statements(statements)
        indexes = {index["name"] for index in inspector.get_indexes(archive_job_table)}
        index_statements = []
        if "ix_bsaj_task_stage_dedupe_status" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bsaj_task_stage_dedupe_status ON {archive_job_table} "
                "(task_id, stage_name, job_dedupe_key, archive_status)"
            )
        _execute_compat_statements(index_statements)
    state_event_table = BinarySecurityStateEvent.__tablename__
    if inspector.has_table(state_event_table):
        columns = {column["name"] for column in inspector.get_columns(state_event_table)}
        statements = []
        if "processed_by" not in columns:
            statements.append(
                f"ALTER TABLE {state_event_table} ADD COLUMN processed_by VARCHAR(128) NULL"
            )
        if "processing_started_at" not in columns:
            statements.append(
                f"ALTER TABLE {state_event_table} ADD COLUMN processing_started_at DATETIME NULL"
            )
        if "processing_finished_at" not in columns:
            statements.append(
                f"ALTER TABLE {state_event_table} ADD COLUMN processing_finished_at DATETIME NULL"
            )
        if "processing_result" not in columns:
            statements.append(
                f"ALTER TABLE {state_event_table} ADD COLUMN processing_result VARCHAR(32) NULL"
            )
        if "last_error_message" not in columns:
            statements.append(
                f"ALTER TABLE {state_event_table} ADD COLUMN last_error_message TEXT NULL"
            )
        _execute_compat_statements(statements)
        indexes = {index["name"] for index in inspector.get_indexes(state_event_table)}
        index_statements = []
        if "ix_bsst_status_updated_id" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bsst_status_updated_id ON {state_event_table} (status, updated_at, id)"
            )
        if "ix_bsst_processed_by_updated" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bsst_processed_by_updated ON {state_event_table} (processed_by, updated_at)"
            )
        if "ix_bsst_event_type_status_created" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bsst_event_type_status_created ON {state_event_table} (event_type, status, created_at)"
            )
        _execute_compat_statements(index_statements)
    operation_table = BinarySecurityTaskOperation.__tablename__
    if inspector.has_table(operation_table):
        column_defs = {column["name"]: column for column in inspector.get_columns(operation_table)}
        columns = set(column_defs)
        statements = []
        if "current_step" not in columns:
            statements.append(
                f"ALTER TABLE {operation_table} ADD COLUMN current_step VARCHAR(64) NULL"
            )
        if "step_attempts_json" not in columns:
            statements.append(
                f"ALTER TABLE {operation_table} ADD COLUMN step_attempts_json TEXT NULL"
            )
        if "step_payload_json" not in columns:
            statements.append(
                f"ALTER TABLE {operation_table} ADD COLUMN step_payload_json TEXT NULL"
            )
        if "resume_cursor_json" not in columns:
            statements.append(
                f"ALTER TABLE {operation_table} ADD COLUMN resume_cursor_json TEXT NULL"
            )
        request_payload_json_type = str(column_defs.get("request_payload_json", {}).get("type") or "").lower()
        if "request_payload_json" in columns and "mediumtext" not in request_payload_json_type:
            statements.append(
                f"ALTER TABLE {operation_table} MODIFY COLUMN request_payload_json MEDIUMTEXT NULL"
            )
        result_payload_json_type = str(column_defs.get("result_payload_json", {}).get("type") or "").lower()
        if "result_payload_json" in columns and "mediumtext" not in result_payload_json_type:
            statements.append(
                f"ALTER TABLE {operation_table} MODIFY COLUMN result_payload_json MEDIUMTEXT NULL"
            )
        _execute_compat_statements(statements)
    else:
        Base.metadata.tables[operation_table].create(bind=engine, checkfirst=True)
    runtime_lease_table = BinarySecurityTaskRuntimeLease.__tablename__
    if inspector.has_table(runtime_lease_table):
        columns = {column["name"] for column in inspector.get_columns(runtime_lease_table)}
        statements = []
        if "owner_pod_uid" not in columns:
            statements.append(
                f"ALTER TABLE {runtime_lease_table} ADD COLUMN owner_pod_uid VARCHAR(128) NULL"
            )
        if "owner_boot_id" not in columns:
            statements.append(
                f"ALTER TABLE {runtime_lease_table} ADD COLUMN owner_boot_id VARCHAR(128) NULL"
            )
        if "generation" not in columns:
            statements.append(
                f"ALTER TABLE {runtime_lease_table} ADD COLUMN generation INTEGER NOT NULL DEFAULT 0"
            )
        if "owner_started_at" not in columns:
            statements.append(
                f"ALTER TABLE {runtime_lease_table} ADD COLUMN owner_started_at DATETIME NULL"
            )
        if "last_renewed_at" not in columns:
            statements.append(
                f"ALTER TABLE {runtime_lease_table} ADD COLUMN last_renewed_at DATETIME NULL"
            )
        _execute_compat_statements(statements)
        indexes = {index["name"] for index in inspector.get_indexes(runtime_lease_table)}
        index_statements = []
        if "ix_bstrl_owner_expires" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bstrl_owner_expires ON {runtime_lease_table} (owner_instance_id, lease_expires_at)"
            )
        if "ix_bstrl_owner_generation" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bstrl_owner_generation ON {runtime_lease_table} (owner_instance_id, generation, lease_expires_at)"
            )
        _execute_compat_statements(index_statements)
    else:
        Base.metadata.tables[runtime_lease_table].create(bind=engine, checkfirst=True)
    coordinator_lease_table = BinarySecurityCoordinatorLease.__tablename__
    if inspector.has_table(coordinator_lease_table):
        indexes = {index["name"] for index in inspector.get_indexes(coordinator_lease_table)}
        index_statements = []
        if "ix_bscl_owner_expires" not in indexes:
            index_statements.append(
                f"CREATE INDEX ix_bscl_owner_expires ON {coordinator_lease_table} (owner_instance_id, lease_expires_at)"
            )
        _execute_compat_statements(index_statements)
    else:
        Base.metadata.tables[coordinator_lease_table].create(bind=engine, checkfirst=True)


def get_db():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()
