"""Binary Security task orchestration manager."""

from __future__ import annotations

import asyncio
import copy
import errno
import hashlib
import httpx
import json
import inspect
import logging
import os
import re
import shutil
import tarfile
import threading
import time
import tempfile
import uuid
import zipfile
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Optional
from dataclasses import dataclass, field

from sqlalchemy import Integer, and_, case, cast, exists, func, or_, text
from sqlalchemy.exc import IntegrityError, OperationalError, TimeoutError as SATimeoutError
from sqlalchemy.orm import Session, load_only

from app.copy_utils import safe_copy2
from app.config import get_config
from app.exception import ConflictError, ForbiddenError, NotFoundError, UnauthorizedError, UpstreamError, ValidationError
from app.model import (
    PIPELINE_PROFILE_DEFAULT,
    PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
    TASK_PIPELINE_PROFILE_SEQUENCES,
    STAGE_SEQUENCE,
    TASK_TERMINAL_STATUSES,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_STAGE_SEQUENCES,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
    BinarySecurityEvent,
    BinarySecurityArchiveJob,
    BinarySecurityProjectConfig,
    BinarySecurityServiceConfig,
    BinarySecuritySyncEvent,
    BinarySecurityTaskOperation,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityStateEvent,
    BinarySecurityTaskStateLease,
    BinarySecurityCoordinatorLease,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    build_archive_job_dedupe_key,
    build_stage_item_identity_key,
    normalize_stage_name,
    get_engine,
    get_session_factory,
)
from app.observability import (
    observe_archive_action,
    observe_archive_duration,
    observe_archive_reclaim,
    observe_control_operation,
    observe_control_operation_auto_reconciled,
    observe_control_operation_duration,
    observe_control_operation_lease_lost,
    observe_control_operation_step_retry,
    observe_control_operation_stale,
    observe_control_operation_superseded,
    observe_archive_job_statuses,
    observe_downstream_reconcile_observation,
    observe_dispatch_reclaim,
    observe_heartbeat_update,
    observe_queue_depths,
    observe_running_requeue,
    observe_runtime_lease_owner_mismatch,
    observe_scheduler_loop,
    observe_slot_usage,
    observe_stage_duration,
    observe_state_dead_letter,
    observe_state_event,
    observe_state_event_lag,
    observe_state_event_queues,
    observe_state_file_write,
    observe_state_owner_health,
    observe_state_owner_event,
    observe_state_owner_run,
    observe_task_readless_reconcile,
    observe_task_snapshot_lock_retry,
    observe_task_duration,
    observe_task_error,
    observe_task_list_query,
    observe_task_list_query_stage,
    observe_task_lifecycle,
    observe_task_operation,
    observe_worker_counts,
    observe_streaming_parent_recovered,
    render_metrics,
)
from app.schemas import (
    BinarySecurityAbnormalReasonHistoryResponse,
    BinarySecurityActionResponse,
    BinarySecurityAbnormalEvidence,
    BinarySecurityAbnormalReason,
    BinarySecurityAbnormalReasonEventSummary,
    BinarySecurityArchiveJobPageResponse,
    BinarySecurityArchiveJobResponse,
    BinarySecurityArtifactsResponse,
    BinarySecurityEntrySelectionResponse,
    BinarySecurityInputFile,
    BinarySecurityModuleReportDetailResponse,
    BinarySecurityModuleSelectionConfirmPayload,
    BinarySecurityModuleSelectionResponse,
    BinarySecurityOverviewResponse,
    BinarySecurityOverviewArchiveDetail,
    BinarySecurityOverviewBusinessDetail,
    BinarySecurityOverviewNode,
    BinarySecurityProjectStageAggregate,
    BinarySecurityProjectStats,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityGlobalConfigPayload,
    BinarySecurityGlobalConfigResponse,
    BinarySecurityStateEventInboxPageResponse,
    BinarySecurityStateEventInboxRecordResponse,
    BinarySecurityStateEventInboxSummaryResponse,
    BinarySecurityServiceConfigPayload,
    BinarySecurityServiceConfigResponse,
    BinarySecurityStageItemResponse,
    BinarySecurityStageItemPageResponse,
    BinarySecurityStageSummary,
    BinarySecurityTaskCreate,
    BinarySecurityTaskConcurrencyUpdatePayload,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskEventResponse,
    BinarySecurityTaskKeySnapshot,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskOperationPageResponse,
    BinarySecurityTaskOperationResponse,
    BinarySecurityTaskPolicyUpdatePayload,
    BinarySecurityRootTaskKeySnapshot,
    BinarySecurityTaskRuntimePolicyUpdatePayload,
    BinarySecurityTaskResponse,
    BinarySecuritySyncEventPageResponse,
    BinarySecuritySyncEventResponse,
    BinarySecurityTimelineResponse,
    BinarySecurityUploadCompletePayload,
    BinarySecurityWorkKeySnapshot,
)

_GLOBAL_BINARY_SECURITY_CONFIG_PROJECT_ID = "__global__"
from app.service.downstream_tasks import get_downstream_task_controller
from app.service.binary_to_source import get_binary_to_source_client
from app.service.dataflow_vuln_scan import get_dataflow_vuln_scan_client
from app.service.entry_analyse import get_entry_analyse_client
from app.service.firmware_unpacker import get_firmware_unpacker_client
from app.service.system_analyse import get_system_analyse_client
from app.service.fileserver import get_fileserver_client
from app.service.security import app_task_root, ensure_dir, validate_task_id
from app.service.state_event_inbox_metrics_snapshot import get_state_event_inbox_metrics_snapshot_store
from app.service.readless_sync import ReadlessSyncStats, run_readless_sync_loop
from app.service.task_queue import get_task_queue
from app.service.task.archive import TaskArchiveServiceMixin
from app.service.task.contracts import TaskContractServiceMixin
from app.service.task.control import TaskControlServiceMixin
from app.service.task.downstream import TaskDownstreamServiceMixin
from app.service.task.events import TaskEventServiceMixin
from app.service.task.item_sync import TaskItemSyncServiceMixin
from app.service.task.lifecycle import TaskLifecycleServiceMixin
from app.service.task.operation import TaskOperationServiceMixin
from app.service.task.operation_events import TaskOperationEventServiceMixin
from app.service.task.owner_fact_apply import TaskOwnerFactApplyServiceMixin
from app.service.task.query import TaskQueryServiceMixin
from app.service.task.read_model import TaskReadModelServiceMixin
from app.service.task.state_event_inbox import TaskStateEventInboxServiceMixin
from app.service.task.results import TaskResultServiceMixin
from app.service.task.runtime import TaskRuntimeServiceMixin
from app.service.task.runtime_state import TaskRuntimeStateServiceMixin
from app.service.task.stage_runtime import TaskStageRuntimeMixin
from app.service.task.state_machine import TaskStateMachineMixin
from app.service.task.shared import (
    ArchiveOutputResult as _ArchiveOutputResult,
    NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
    _copytree,
    _copytree_best_effort,
    _count_files,
    _deduplicate_entry_keys,
    _deduplicate_strings,
    _dedupe_paths,
    _default_entry_function_description,
    _default_entry_reason,
    _display_task_type,
    _downstream_origin_payload,
    _elapsed_seconds_since,
    _entry_description_source,
    _entry_key_with_suffix,
    _entry_signature_params,
    _failure_shape,
    _is_b2s_runtime_temp_dir,
    _is_within_path,
    _isoformat_or_none,
    _no_candidate_modules_failure,
    _normalize_entry_function_name,
    _normalize_entry_taint_details,
    _normalize_module_risk_level,
    _normalize_module_risk_levels,
    _normalize_parameter_name,
    _normalize_pipeline_mode,
    _now,
    _parse_iso_datetime,
    _parse_signature_param_names,
    _path_has_content,
    _path_matches_task_id,
    _prefer_specific_paths,
    _read_json,
    _read_text,
    _runtime_health_status_rank,
    _seconds_until,
    _should_skip_b2s_archive_path,
    _slug,
    _split_signature_params,
    _stage_item_attr,
    _write_json,
)
from app.service.task_queue import get_task_queue
from app.service.http_client import get_shared_async_client
from app.service.stages.registry import get_binary_security_stage_registry
from app.service.knowledge_graph_audit import get_knowledge_graph_audit_client
from app.service.llm_gateway import LLMGatewayWorkKeyIssueError, get_llm_gateway_client
from app.time_utils import now_local

logger = logging.getLogger(__name__)

DB_SUMMARY_ITEM_LIMIT = 50
DB_FAILURE_ITEM_LIMIT = 20


@dataclass
class _TaskDetailContext:
    task: BinarySecurityTask
    queue_info: dict[str, Any]
    stage_sequence: list[str]
    stage_runs: list[BinarySecurityStageRun] = field(default_factory=list)
    stage_items: list[BinarySecurityStageItem] = field(default_factory=list)
    archive_jobs: list[BinarySecurityArchiveJob] = field(default_factory=list)
    stage_summaries: list[BinarySecurityStageSummary] = field(default_factory=list)
    abnormal_reason: BinarySecurityAbnormalReason | None = None
    stage_items_total: int = 0
    item_stats: dict[str, dict[str, int]] = field(default_factory=dict)
    downstream_status_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    last_successful_sync_at: datetime | None = None
    last_sync_attempt_at: datetime | None = None
    last_sync_error_at: datetime | None = None
    last_sync_error_type: str | None = None
    last_sync_error_message: str | None = None
    active_sync_error_item_count: int = 0
    never_synced_item_count: int = 0
    stale_synced_item_count: int = 0


@dataclass
class _TaskStateSnapshot:
    status: str
    current_stage: str
    runtime_phase: str


@dataclass
class _TaskLayerDecision:
    changed: bool = False
    owned_execution_requeue_required: bool = False
    owned_execution_requeue_stage_name: str | None = None
    owned_execution_requeue_reason: str | None = None
    owned_execution_requeue_message: str | None = None
    owned_execution_requeue_payload: dict[str, Any] | None = None


@dataclass
class _StageTerminalTaskDecision:
    action: str = "none"
    next_stage: str | None = None
    message: str | None = None
    event_type: str | None = None
    payload: dict[str, Any] | None = None
    level: str = "info"


@dataclass
class _TaskLayerReconcileDecision:
    action: str = "noop"
    stage_name: str | None = None
    stage_status: str | None = None
    summary: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    source_event_type: str | None = None
    reconcile_reason: str | None = None


@dataclass
class _TaskFinalizeGateDecision:
    allowed: bool = False
    reason_code: str | None = None
    blocked_by_stage: str | None = None
    next_stage: str | None = None
    has_active_items: bool = False
    has_nonterminal_items: bool = False
    has_resumable_path: bool = False
    has_pending_materialization: bool = False
    has_runtime_takeover_need: bool = False
    has_authoritative_failure: bool = False


@dataclass
class _TaskResumeDecision:
    should_resume: bool = False
    next_stage: str | None = None
    resume_reason: str | None = None
    source: str | None = None
    message: str | None = None
    event_type: str | None = None
    payload: dict[str, Any] | None = None
    owned_execution_requeue_required: bool = False


@dataclass
class _StaleParentRuntimeTakeoverDecision:
    runtime_lease_active: bool
    runtime_lease_owner: str | None
    local_handle_alive: bool
    supported_control_operation_active: bool
    allow_takeover: bool
    allow_reenqueue: bool
    allow_claim: bool
    decision_reason: str


@dataclass
class _RuntimeLeaseOwnershipDecision:
    should_continue: bool
    abort_reason: str | None = None
    runtime_lease_present: bool = False
    runtime_lease_active: bool = False
    runtime_lease_owner: str | None = None
    runtime_lease_expires_at: datetime | None = None
    local_handle_alive: bool = False
    verification_error: str | None = None

DB_ENTRY_PREVIEW_LIMIT = 50
DB_ARTIFACT_PREVIEW_LIMIT = 50
DB_EVENT_PAYLOAD_LIMIT_BYTES = 32768
DB_TIMELINE_EVENT_LIMIT = 10_000
DB_SYNC_EVENT_LIMIT = 10_000
DETAIL_STAGE_ITEMS_LIMIT = 100
READONLY_TASK_PROJECTION_CACHE_TTL_SECONDS = 15.0
MODULE_TASK_INPUT_KEY = "module-input"
ARCHIVE_COPY_MISSING_SOURCE_RETRY_REASON = "source_not_ready"
DOWNSTREAM_CREATE_RETRY_BACKOFF_SECONDS = (10, 30, 60, 120)
DOWNSTREAM_CREATE_RETRY_MAX_ATTEMPTS = 10
DOWNSTREAM_CREATE_RETRY_MAX_WINDOW_SECONDS = 15 * 60
DEFERRED_CLEANUP_RETRY_MIN_SECONDS = 60
_UNSET = object()

# Compatibility exports for older tests and call sites that monkey-patch
# downstream client factories from task_manager directly.
__all__ = [
    "get_binary_to_source_client",
    "get_dataflow_vuln_scan_client",
    "get_entry_analyse_client",
    "get_firmware_unpacker_client",
    "get_system_analyse_client",
]


STAGE_RETRY_ALLOWED_STATUSES = {"success", "failed", "partial_success", "cancelled"}
STAGE_RETRY_BLOCKED_TASK_STATUSES = {"pending", "dispatching", "running", "pending_upload", "uploading"}
TASK_STATUS_PENDING_MODULE_CONFIRMATION = "pending_module_confirmation"
TASK_STATUS_PENDING_ENTRY_CONFIRMATION = "pending_entry_confirmation"
TASK_STATUS_HARD_RESTART_FAILED = "hard_restart_failed"
TASK_STATUS_CANCELLING = "cancelling"
TASK_STATUS_CANCEL_FAILED = "cancel_failed"
TASK_STATUS_DELETE_FAILED = "delete_failed"
TASK_STATUS_FORCE_DELETE_FAILED = "force_delete_failed"
TASK_ACTION_CONTINUE = "continue"
TASK_ACTION_RETRY = "retry"
TASK_ACTION_RETRY_FAILED_ITEMS = "retry_failed_items"
TASK_ACTION_RETRY_STAGE_FAILED_ITEMS = "retry_stage_failed_items"
TASK_ACTION_RETRY_STAGE_FULL = "retry_stage_full"
TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS = "retry_archive_failed_items"
TASK_ACTION_RETRY_ARCHIVE_FULL = "retry_archive_full"
TASK_ACTION_CANCEL = "cancel"
TASK_ACTION_DELETE = "delete"
TASK_PENDING_ACTIONS = {
    TASK_ACTION_CONTINUE,
    TASK_ACTION_RETRY,
    TASK_ACTION_RETRY_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FULL,
    TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
    TASK_ACTION_RETRY_ARCHIVE_FULL,
}
TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES = {
    TASK_ACTION_CONTINUE,
    TASK_ACTION_RETRY,
    TASK_ACTION_RETRY_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FULL,
    TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
    TASK_ACTION_RETRY_ARCHIVE_FULL,
    TASK_ACTION_CANCEL,
    TASK_ACTION_DELETE,
    "force_reset_to_pending",
}
TASK_OPERATION_REQUEUE_APPLIED_TYPES = {
    TASK_ACTION_CONTINUE,
    TASK_ACTION_RETRY,
    TASK_ACTION_RETRY_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
    TASK_ACTION_RETRY_STAGE_FULL,
    TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
    TASK_ACTION_RETRY_ARCHIVE_FULL,
}
TASK_OPERATION_OWNER_GUARDED_TYPES = {
    *TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES,
}
TASK_OPERATION_ACTIVE_STATUSES = {"requested", "accepted", "queued", "claimed", "running"}
TASK_OPERATION_TERMINAL_STATUSES = {"succeeded", "failed", "superseded", "cancelled"}
TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN = "collect_cleanup_plan"
TASK_OPERATION_STEP_VERIFY_CLEANUP_STATE = "verify_cleanup_state"
TASK_OPERATION_STEP_CANCEL_DOWNSTREAM = "cancel_downstream"
TASK_OPERATION_STEP_DELETE_DOWNSTREAM = "delete_downstream"
TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_ABSENT = "verify_downstream_absent"
TASK_OPERATION_STEP_DELETE_ARCHIVES = "delete_archives"
TASK_OPERATION_STEP_DELETE_STAGE_ITEMS = "delete_stage_items"
TASK_OPERATION_STEP_DELETE_STATE_EVENTS = "delete_state_events"
TASK_OPERATION_STEP_DELETE_STAGE_TIMELINE = "delete_stage_timeline"
TASK_OPERATION_STEP_REBUILD_UPSTREAM_DERIVED_INPUTS = "rebuild_upstream_derived_inputs"
TASK_OPERATION_STEP_RESET_STAGE_RUNS = "reset_stage_runs"
TASK_OPERATION_STEP_REQUEUE_TASK = "requeue_task"
TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE = "sync_target_stage_state"
TASK_OPERATION_STEP_PREPARE_RETRY_ITEMS = "prepare_retry_items"
TASK_OPERATION_STEP_CLEANUP_ABNORMAL_CHILDREN = "cleanup_abnormal_children"
TASK_OPERATION_STEP_CREATE_REPLACEMENT_CHILDREN = "create_replacement_children"
TASK_OPERATION_STEP_VERIFY_RETRY_BINDINGS = "verify_retry_bindings"
TASK_OPERATION_STEP_FINALIZE_RETRY_OPERATION = "finalize_retry_operation"
TASK_OPERATION_STEP_MARK_TASK_CANCELLING = "mark_task_cancelling"
TASK_OPERATION_STEP_COLLECT_CANCEL_TARGETS = "collect_cancel_targets"
TASK_OPERATION_STEP_CANCEL_LOCAL_EXECUTION = "cancel_local_execution"
TASK_OPERATION_STEP_CANCEL_DOWNSTREAM_TARGETS = "cancel_downstream_targets"
TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED = "verify_downstream_quiesced"
TASK_OPERATION_STEP_FINALIZE_TASK_CANCELLED = "finalize_task_cancelled"
TASK_OPERATION_STEP_FINALIZE_TASK_CANCEL_FAILED = "finalize_task_cancel_failed"
TASK_OPERATION_STEP_FAILED = "operation_failed"
TASK_OPERATION_STEP_SUCCEEDED = "operation_succeeded"
TASK_CANCEL_BLOCKING_TARGETS_PREVIEW_LIMIT = 20
RETRY_CHILD_STRATEGY_REUSE_SUCCESS = "reuse_success"
RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = "adopt_active"
RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = "recreate_from_abnormal"
RETRY_CHILD_ABNORMAL_STATUSES = {"failed", "cancelled", "downstream_missing"}
TASK_OPERATION_SAGA_STEPS = (
    TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN,
    TASK_OPERATION_STEP_VERIFY_CLEANUP_STATE,
    TASK_OPERATION_STEP_SYNC_TARGET_STAGE_STATE,
    TASK_OPERATION_STEP_PREPARE_RETRY_ITEMS,
    TASK_OPERATION_STEP_CLEANUP_ABNORMAL_CHILDREN,
    TASK_OPERATION_STEP_CREATE_REPLACEMENT_CHILDREN,
    TASK_OPERATION_STEP_VERIFY_RETRY_BINDINGS,
    TASK_OPERATION_STEP_FINALIZE_RETRY_OPERATION,
    TASK_OPERATION_STEP_CANCEL_DOWNSTREAM,
    TASK_OPERATION_STEP_DELETE_DOWNSTREAM,
    TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_ABSENT,
    TASK_OPERATION_STEP_DELETE_ARCHIVES,
    TASK_OPERATION_STEP_DELETE_STAGE_ITEMS,
    TASK_OPERATION_STEP_DELETE_STATE_EVENTS,
    TASK_OPERATION_STEP_DELETE_STAGE_TIMELINE,
    TASK_OPERATION_STEP_REBUILD_UPSTREAM_DERIVED_INPUTS,
    TASK_OPERATION_STEP_RESET_STAGE_RUNS,
    TASK_OPERATION_STEP_REQUEUE_TASK,
    TASK_OPERATION_STEP_SUCCEEDED,
)
TASK_CANCEL_SAGA_STEPS = (
    TASK_OPERATION_STEP_MARK_TASK_CANCELLING,
    TASK_OPERATION_STEP_COLLECT_CANCEL_TARGETS,
    TASK_OPERATION_STEP_CANCEL_LOCAL_EXECUTION,
    TASK_OPERATION_STEP_CANCEL_DOWNSTREAM_TARGETS,
    TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
    TASK_OPERATION_STEP_FINALIZE_TASK_CANCELLED,
    TASK_OPERATION_STEP_FINALIZE_TASK_CANCEL_FAILED,
    TASK_OPERATION_STEP_SUCCEEDED,
)
TASK_OPERATION_LOCK_TTL_SECONDS = 1800
TASK_OPERATION_LOCK_HEARTBEAT_SECONDS = 20
TASK_CANCEL_VERIFY_TIMEOUT_SECONDS = 180
STATE_EVENT_LEASE_SECONDS = 120
TASK_STATE_LEASE_SECONDS = 300
STATE_EVENT_MAX_ATTEMPTS = 5
REDUCER_EVENT_LIMIT_CAP = 10_000
REDUCER_EVENT_SLOW_THRESHOLD_MS = 1_000
MODULE_SELECTION_MODE_AUTO = "auto"
MODULE_SELECTION_MODE_MANUAL_CONFIRM = "manual_confirm"
ENTRY_SELECTION_MODE_AUTO = "auto"
ENTRY_SELECTION_MODE_MANUAL_CONFIRM = "manual_confirm"
ENTRY_AUTO_SELECTION_STRATEGY_ALL = "all"
ENTRY_AUTO_SELECTION_STRATEGY_TOP_N_PER_MODULE_BY_CONFIDENCE = "top_n_per_module_by_confidence"
DEFAULT_ENTRY_AUTO_SELECTION_TOP_N = 20
KNOWLEDGE_GRAPH_ENTRY_FETCH_MAX_ATTEMPTS = 10
KNOWLEDGE_GRAPH_ENTRY_FETCH_RETRY_INTERVAL_SECONDS = 20
ALLOWED_MODULE_RISK_LEVELS = ("高", "中", "低")
STAGE_SUMMARY_RESULT_KEYS = {
    "firmware_unpack": ["firmware_unpack_results"],
    "system_analysis": ["system_analysis_results", "high_risk_modules", "system_analysis_modules", "candidate_modules", "selected_modules"],
    "binary_to_source": ["b2s_results"],
    "entry_analysis": ["entry_results"],
    "knowledge_graph_entry_fetch": ["knowledge_graph_entry_results", "entry_results"],
    "dataflow_vuln_scan": ["dataflow_results", "vuln_results"],
}
STAGE_METRIC_RESETTERS = {
    "firmware_unpack": {"unpacked_firmware_count": 0, "failed_firmware_count": 0},
    "system_analysis": {
        "high_risk_module_count": 0,
        "medium_risk_module_count": 0,
        "low_risk_module_count": 0,
        "candidate_module_count": 0,
        "selected_module_count": 0,
    },
    "knowledge_graph_entry_fetch": {
        "knowledge_graph_raw_entry_count": 0,
        "knowledge_graph_selected_entry_count": 0,
        "knowledge_graph_filtered_out_count": 0,
        "candidate_entry_count": 0,
        "selected_entry_count": 0,
        "entry_count": 0,
    },
    "entry_analysis": {"entry_count": 0},
    "dataflow_vuln_scan": {"vuln_result_count": 0},
}
STAGE_TITLES = {
    "firmware_unpack": "固件解包",
    "system_analysis": "系统分析",
    "binary_to_source": "二进制逆向",
    "entry_analysis": "入口分析",
    "knowledge_graph_entry_fetch": "知识图谱入口获取",
    "dataflow_vuln_scan": "数据流漏洞挖掘",
}

FAILED_ITEM_RETRYABLE_STATUSES = {"failed", "cancelled", "downstream_missing", "pending", "queued", "running", "dispatching"}
ARCHIVE_ACTIVE_STATUSES = {"pending", "running", "archived", "applying"}
ARCHIVE_SUCCESS_MAPPED_STATUSES = {"success", "partial_success"}


def _retry_mode_needs_plan(mode: str | None) -> bool:
    return bool(mode in {"task_retry_failed_items", "stage_retry_failed_items", "stage_retry_full"})
ACTIVE_RECONCILE_TARGET_STAGE_MODES = {
    "task_retry_failed_items",
    "stage_retry_failed_items",
    "stage_retry_full",
    "task_retry",
    "stage_retry",
}
STAGE_RETRY_ENDPOINTS = {
    "firmware_unpack": ("firmware_unpacker", "retry"),
    "system_analysis": ("system_analyse", "restart"),
    "binary_to_source": ("binary_to_source", "retry"),
    "entry_analysis": ("entry_analyse", "restart"),
    "dataflow_vuln_scan": ("dataflow_vuln_scan", "retry"),
}
SERVICE_STAGE_NAMES = {service: stage_name for stage_name, (service, _action) in STAGE_RETRY_ENDPOINTS.items()}
SOURCE_TASK_INPUT_KEY = "source_project"
SERVICE_OUTPUT_FOLDERS = {
    "firmware_unpacker": "firmware-unpacker",
    "system_analyse": "system-analyse",
    "binary_to_source": "binary-to-source",
    "entry_analyse": "entry-analyse",
    "dataflow_vuln_scan": "dataflow-vuln-scan",
}
LEGACY_SERVICE_OUTPUT_FOLDERS = {
    "system_analyse": ("system-analysis",),
    "entry_analyse": ("entry-analysis",),
}
STAGE_OUTPUT_SERVICES = {
    "firmware_unpack": ["firmware_unpacker"],
    "system_analysis": ["system_analyse"],
    "binary_to_source": ["binary_to_source"],
    "entry_analysis": ["entry_analyse"],
    "dataflow_vuln_scan": ["dataflow_vuln_scan"],
}
DOWNSTREAM_APP_ROOTS = {
    "firmware_unpacker": "secflow-app-firmware-unpacker",
    "system_analyse": "secflow-app-system-analyse",
    "binary_to_source": "secflow-app-binary-to-source",
    "entry_analyse": "secflow-app-entry-analyse",
    "dataflow_vuln_scan": "secflow-app-dataflow-vuln-scan",
}
SOURCE_ARCHIVE_FORMATS = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
PARTIAL_SUCCESS_ADVANCEMENT_STAGES = (
    "binary_to_source",
    "entry_analysis",
    "dataflow_vuln_scan",
)
DEFAULT_PARTIAL_SUCCESS_STAGE_ADVANCEMENT = {
    stage_name: False for stage_name in PARTIAL_SUCCESS_ADVANCEMENT_STAGES
}


def _already_isoformatted_datetime(value: Any) -> str | None:
    if isinstance(value, str):
        normalized = str(value or "").strip()
        return normalized or None
    return _isoformat_or_none(value)
PIPELINE_MODE_BARRIER = "barrier"
PIPELINE_MODE_MIXED_STREAMING = "mixed_streaming"
STREAMING_TAIL_STAGES = ("entry_analysis", "dataflow_vuln_scan")
STREAMING_ACTIVE_ITEM_STATUSES = frozenset({"pending", "queued", "dispatching", "running"})
PARENT_RECLAIM_COORDINATOR_LEASE = "parent_reclaim"


class StaleTaskExecution(RuntimeError):
    """Raised when a stale task worker observes that its dispatch token is no longer current."""


@dataclass
class DownstreamSyncSupervisorState:
    consecutive_error_count: int = 0
    budget_exhausted: bool = False
    next_retry_at: datetime | None = None
    last_result: str | None = None


@dataclass
class OrchestrationSupervisorState:
    consecutive_error_count: int = 0
    budget_exhausted: bool = False
    next_retry_at: datetime | None = None
    last_result: str | None = None


@dataclass
class TaskRuntimeHandle:
    task_id: str
    runner_task: asyncio.Task
    heartbeat_task: asyncio.Task | None
    claimed_at: datetime
    execution_token: str | None
    lease_owner_instance_id: str | None
    sync_maintenance_task: asyncio.Task | None = None
    cancel_requested: bool = False
    cancel_requested_reason: str | None = None
    last_progress_at: datetime | None = None
    active_commit_completed_at: datetime | None = None
    active_commit_succeeded: bool = False
    lease_established: bool = False
    owner_active: bool = True
    release_requested: bool = False
    release_reason: str | None = None
    last_runner_exit_at: datetime | None = None
    last_lease_refresh_at: datetime | None = None
    last_lease_verify_at: datetime | None = None
    last_sync_maintenance_progress_at: datetime | None = None
    last_runner_progress_at: datetime | None = None
    takeover_observed: bool = False
    control_wakeup_requested: bool = False
    control_wakeup_reason: str | None = None
    pending_operation_id: str | None = None
    pending_operation_type: str | None = None
    runner_generation: int = 0
    last_wakeup_at: datetime | None = None
    sync_maintenance_in_progress: bool = False

    def done(self) -> bool:
        return self.runner_task.done()

    def cancel(self, reason: str | None = None) -> None:
        self.cancel_requested = True
        self.cancel_requested_reason = str(reason or "").strip() or self.cancel_requested_reason
        if self.heartbeat_task is not None and not self.heartbeat_task.done():
            self.heartbeat_task.cancel()
        if self.sync_maintenance_task is not None and not self.sync_maintenance_task.done():
            self.sync_maintenance_task.cancel()
        if not self.runner_task.done():
            self.runner_task.cancel()


@dataclass(frozen=True)
class RuntimeLeaseClearResult:
    status: str
    deleted_count: int = 0
    owner_instance_id: str | None = None
    task_id: str | None = None
    error_message: str | None = None


class TaskManager(
    TaskQueryServiceMixin,
    TaskReadModelServiceMixin,
    TaskControlServiceMixin,
    TaskDownstreamServiceMixin,
    TaskOperationServiceMixin,
    TaskOperationEventServiceMixin,
    TaskEventServiceMixin,
    TaskOwnerFactApplyServiceMixin,
    TaskRuntimeServiceMixin,
    TaskContractServiceMixin,
    TaskStateEventInboxServiceMixin,
    TaskResultServiceMixin,
    TaskArchiveServiceMixin,
    TaskItemSyncServiceMixin,
    TaskLifecycleServiceMixin,
    TaskStateMachineMixin,
    TaskStageRuntimeMixin,
    TaskRuntimeStateServiceMixin,
):
    def __init__(self) -> None:
        # Isolate per-manager runtime config so local mutations do not leak
        # across test cases or long-lived in-process manager instances.
        self.cfg = copy.deepcopy(get_config())
        self.instance_id = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME") or f"binary-security-{uuid.uuid4().hex[:12]}"
        self.owner_pod_uid = os.environ.get("POD_UID") or self.instance_id
        self.owner_boot_id = uuid.uuid4().hex
        self.owner_started_at = _now()
        self._owner_generation = 1
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._archive_loop_task: Optional[asyncio.Task] = None
        self._delete_loop_task: Optional[asyncio.Task] = None
        self._downstream_reconcile_task: Optional[asyncio.Task] = None
        self._readless_reconcile_task: Optional[asyncio.Task] = None
        self._stage_item_sync_reconcile_task: Optional[asyncio.Task] = None
        self._archive_runtime_reconcile_task: Optional[asyncio.Task] = None
        self._state_repair_reconcile_task: Optional[asyncio.Task] = None
        self._state_event_inbox_loop_task: Optional[asyncio.Task] = None
        self._state_event_inbox_metrics_loop_task: Optional[asyncio.Task] = None
        self._stage_item_loop_task: Optional[asyncio.Task] = None
        self._workers: dict[str, TaskRuntimeHandle] = {}
        self._operation_workers: dict[str, asyncio.Task] = {}
        self._stage_item_workers: dict[str, asyncio.Task] = {}
        self._archive_workers: set[asyncio.Task] = set()
        self._worker_lock = asyncio.Lock()
        self._operation_worker_lock = asyncio.Lock()
        self._stage_item_worker_lock = asyncio.Lock()
        self._archive_worker_lock = asyncio.Lock()
        self._last_task_heartbeat_at: dict[str, datetime] = {}
        self._task_execution_owners: dict[str, set[str]] = {}
        self._task_execution_owner_lock = threading.Lock()
        self._last_queue_reconcile_at: datetime | None = None
        self._state_event_inbox_consecutive_crash_count = 0
        self._task_list_cache: dict[tuple[str, str, str], tuple[float, Any]] = {}
        self._task_list_cache_lock = threading.Lock()
        self._readonly_projection_cache: dict[tuple[str, str, str], tuple[float, Any]] = {}
        self._readonly_projection_cache_lock = threading.Lock()
        self._loop_heartbeats: dict[str, datetime] = {}
        self._runtime_loop: asyncio.AbstractEventLoop | None = None
        self._lease_watchdog_thread: threading.Thread | None = None
        self._lease_watchdog_stop_event = threading.Event()
        self._lease_watchdog_state_lock = threading.Lock()
        self._lease_watchdog_last_tick_at: datetime | None = None
        self._lease_watchdog_last_success_at: datetime | None = None
        self._lease_watchdog_last_error: str | None = None
        self._event_loop_lag_monitor_task: asyncio.Task | None = None
        self._event_loop_last_tick_at: datetime | None = None
        self._event_loop_last_lag_seconds: float = 0.0
        self._event_loop_stall_threshold_seconds = 5.0
        self._event_loop_last_stall_at: datetime | None = None
        self._last_stale_operation_requeue_at: datetime | None = None
        self._last_stage_item_sync_reconcile_at: datetime | None = None
        self._queue_reconcile_observation_state: dict[tuple[str, str], dict[str, Any]] = {}
        self._non_owner_claim_log_state: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._non_owner_claim_log_lock = threading.Lock()
        self._non_owner_claim_event_state: dict[tuple[str, str, str, str], datetime] = {}
        self._last_dispatch_claim_decision: dict[str, Any] | None = None
        self._stage_registry = get_binary_security_stage_registry()

    def __getattr__(self, item: str):
        if item == "_operation_step_snapshot":
            return lambda operation, step_name: dict(self._load_operation_step_payload(operation).get(step_name) or {})
        if item == "_lease_timeout_seconds":
            def _lease_timeout_seconds():
                db = get_session_factory()()
                try:
                    config = self._load_service_config(db)
                    return max(15, int(getattr(config, "lease_timeout_seconds", 90) or 90))
                finally:
                    db.close()
            return _lease_timeout_seconds
        if item == "_derive_downstream_work_key":
            async def _derive_downstream_work_key(*, task, item, service):
                root_secret = self._root_task_key_secret(task)
                if not root_secret:
                    return {}
                if not bool(getattr(self.cfg.llm_gateway, "enabled", True)):
                    return {}
                stage_item_id = str(getattr(item, "id", "") or "").strip() or "item"
                stage_name = str(getattr(item, "stage_name", "") or "").strip() or "unknown_stage"
                normalized_service = str(service or "child").strip() or "child"
                key_name = f"{normalized_service}-{stage_item_id}"
                description = (
                    f"binary-security worker key "
                    f"task_id={str(getattr(task, 'id', '') or '').strip() or '-'} "
                    f"stage_name={stage_name} "
                    f"stage_item_id={stage_item_id} "
                    f"service={normalized_service}"
                )
                issued = await get_llm_gateway_client().issue_work_key(
                    task_key_secret=root_secret,
                    sub_task_id=stage_item_id,
                    key_name=key_name,
                    description=description,
                    max_concurrency=0,
                    enabled=True,
                )
                key = issued.get("key") if isinstance(issued.get("key"), dict) else {}
                secret = str(issued.get("secret") or "").strip()
                key_id = str(key.get("id") or "").strip()
                key_name_value = str(key.get("key_name") or key_name).strip() or key_name
                # 网关 work key 响应不含 key_prefix（其 key_prefix 列为空），回退到 key_value 作为前缀，
                # 避免误报“响应缺少关键字段”导致下游创建永久 defer。
                key_prefix = (
                    str(key.get("key_prefix") or "").strip()
                    or str(key.get("key_value") or "").strip()
                    or None
                )
                if not secret or not key_id:
                    raise LLMGatewayWorkKeyIssueError(
                        "LLM Gateway work key 响应缺少关键字段",
                        status_code=201,
                        response_text=str(issued)[:500],
                        request_payload_preview={
                            "sub_task_id": stage_item_id,
                            "key_name": key_name,
                        },
                        retryable=False,
                    )
                return {
                    "sub_task_id": stage_item_id,
                    "agent_task_key_id": key_id,
                    "agent_task_key_name": key_name_value,
                    "agent_task_key_prefix": key_prefix,
                    "agent_task_key_source": "llm_gateway_work_key_exchange",
                    "agent_task_key_secret": secret,
                }
            return _derive_downstream_work_key
        if item == "_rebuild_archive_jobs_for_stage":
            def _rebuild_archive_jobs_for_stage(db, task, target_stage, stage_items):
                return self._rebuild_authoritative_archive_jobs_for_stage(
                    db,
                    task,
                    target_stage,
                    stage_items,
                    archive_jobs=self._archive_jobs_for_stages(db, task.id, [target_stage]),
                )
            return _rebuild_archive_jobs_for_stage
        if item == "_wait_archive_job_completion":
            async def _wait_archive_job_completion(job_id, task_id, timeout_seconds: int = 120):
                del task_id
                deadline = time.monotonic() + max(5, int(timeout_seconds))
                while time.monotonic() < deadline:
                    db = get_session_factory()()
                    try:
                        job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == job_id).first()
                        if job is None:
                            return None
                        if str(getattr(job, "archive_status", "") or "").strip() in {"success", "failed", "applying", "archived"}:
                            return copy.deepcopy(job)
                    finally:
                        db.close()
                    await asyncio.sleep(0.5)
                return None
            return _wait_archive_job_completion
        if item == "_repair_stage_item_terminal_downstream_observation":
            def _repair_stage_item_terminal_downstream_observation(db, task, stage_item, *, reason=None):
                del db, task, reason
                result = dict(self._load_stage_item_result_payload(stage_item))
                downstream = dict(result.get("downstream") or {})
                expected_status = self._normalize_downstream_status(stage_item.status) or str(stage_item.status or "").strip().lower() or None
                if not expected_status:
                    return False
                changed = False
                if downstream.get("status") != expected_status:
                    downstream["status"] = expected_status
                    changed = True
                for key in ("error", "error_message", "message"):
                    if key in downstream:
                        downstream.pop(key, None)
                        changed = True
                if changed:
                    result["downstream"] = downstream
                    observation = dict(result.get("sync_observation") or {})
                    observation["downstream_status"] = expected_status
                    observation["mapped_status"] = expected_status
                    observation["state_applied"] = True
                    observation["error_message"] = None
                    observation["error_type"] = None
                    result["sync_observation"] = observation
                    stage_item.result = result
                return changed
            return _repair_stage_item_terminal_downstream_observation
        if item == "_process_archive_job":
            async def _process_archive_job(job_id: str):
                archived_root, error, retry_scheduled = await asyncio.to_thread(self._run_archive_copy_job, job_id)
                if retry_scheduled:
                    return
                if archived_root:
                    await self._apply_archive_job_status(job_id, archived_root)
                    return
                if error:
                    raise ValidationError(str(error))
            return _process_archive_job
        if item == "_prepare_retry_stage_full":
            async def _prepare_retry_stage_full(db, task, target_stage):
                del db
                sequence = list(self._stage_sequence_for_task(task))
                normalized_target = normalize_stage_name(target_stage) or str(target_stage or "").strip()
                if normalized_target not in sequence:
                    raise ValidationError(f"不支持的阶段完全重试目标: {target_stage or '-'}")
                start_index = sequence.index(normalized_target)
                return sequence[start_index:]
            return _prepare_retry_stage_full
        if item == "_claim_pending_tasks":
            def _claim_pending_tasks(db, slots: int):
                if slots <= 0:
                    return []
                claimed_ids: list[str] = []
                service_config = self._load_service_config(db)
                lease_timeout_seconds = max(10, int(getattr(service_config, "lease_timeout_seconds", 90) or 90))
                pending_rows = (
                    db.query(BinarySecurityTask)
                    .filter(BinarySecurityTask.status == "pending", self._lease_filter_available())
                    .order_by(BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
                    .limit(max(1, int(slots)))
                    .all()
                )
                for task in pending_rows:
                    started_at = _now()
                    updated = (
                        db.query(BinarySecurityTask)
                        .filter(BinarySecurityTask.id == task.id, BinarySecurityTask.status == "pending", self._lease_filter_available())
                        .update(
                            {
                                BinarySecurityTask.status: "dispatching",
                                BinarySecurityTask.runtime_phase: TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                                BinarySecurityTask.updated_at: started_at,
                            },
                            synchronize_session=False,
                        )
                    )
                    if updated:
                        claimed_ids.append(str(task.id))
                return claimed_ids
            return _claim_pending_tasks
        if item == "_build_b2s_result_payload":
            def _build_b2s_result_payload(task, module, payload, archived_dir, *, entry_input=None, project_id=None):
                del task, project_id
                module_payload = dict(module or {})
                downstream_payload = dict(payload or {})
                entry_payload = dict(entry_input or {})
                artifacts = list(downstream_payload.get("artifacts") or [])
                artifact_index_path = str(downstream_payload.get("artifact_index_path") or "").strip()
                result_items = [dict(row) for row in artifacts if isinstance(row, dict)]
                return {
                    "module_key": module_payload.get("module_key") or entry_payload.get("module_key"),
                    "module_name": module_payload.get("module_name") or entry_payload.get("module_name"),
                    "task_type": module_payload.get("task_type"),
                    "archive_root": str(archived_dir) if archived_dir else None,
                    "artifact_index_path": artifact_index_path or None,
                    "result_items": result_items,
                    "downstream_result_summary": dict(downstream_payload.get("result_summary") or {}),
                    "downstream": self._lightweight_downstream_payload(downstream_payload),
                    "artifacts": {"files": result_items},
                    "result_summary_version": 2,
                }
            return _build_b2s_result_payload
        if item == "_mark_downstream_binding_created":
            def _mark_downstream_binding_created(stage_item, *, message=None):
                result = dict(self._load_stage_item_result_payload(stage_item))
                observation = dict(result.get("sync_observation") or {})
                observation["binding_state"] = "created"
                observation["message"] = message
                observation["replacement_in_progress"] = False
                result["sync_observation"] = observation
                stage_item.result = result
            return _mark_downstream_binding_created
        if item == "_lease_filter_available":
            def _lease_filter_available():
                active_runtime_lease_exists = exists().where(
                    and_(
                        BinarySecurityTaskRuntimeLease.task_id == BinarySecurityTask.id,
                        BinarySecurityTaskRuntimeLease.lease_expires_at >= _now(),
                    )
                )
                return ~active_runtime_lease_exists
            return _lease_filter_available
        if item == "_mark_downstream_binding_creating":
            def _mark_downstream_binding_creating(stage_item):
                result = dict(self._load_stage_item_result_payload(stage_item))
                observation = dict(result.get("sync_observation") or {})
                observation["binding_state"] = "creating"
                observation["replacement_in_progress"] = False
                result["sync_observation"] = observation
                stage_item.result = result
            return _mark_downstream_binding_creating
        if item == "_should_recreate_entry_child_from_terminal_status":
            def _should_recreate_entry_child_from_terminal_status(*, retrying, terminal_status):
                recreate, _ = self._entry_terminal_payload_requires_recreate(
                    retrying=retrying,
                    payload={"status": terminal_status},
                )
                return recreate
            return _should_recreate_entry_child_from_terminal_status
        if item == "_merge_stage_item_result":
            def _merge_stage_item_result(stage_item, updates):
                merged = {
                    **self._load_stage_item_result_payload(stage_item),
                    **dict(updates or {}),
                }
                stage_item.result = merged
                return merged
            return _merge_stage_item_result
        if item == "_clear_stage_item_sync_observation_errors":
            def _clear_stage_item_sync_observation_errors(stage_item, *, result_payload=None, touched=False):
                del touched
                result = dict(result_payload or self._load_stage_item_result_payload(stage_item))
                observation = dict(result.get("sync_observation") or {})
                for key in ("error_message", "error_type", "http_status", "last_error_at", "next_retry_at"):
                    observation.pop(key, None)
                observation["consecutive_error_count"] = 0
                observation["budget_exhausted"] = False
                result["sync_observation"] = observation
                result["last_sync_error_at"] = None
                result["last_sync_error_message"] = None
                result["last_sync_error_type"] = None
                stage_item.result = result
                return result
            return _clear_stage_item_sync_observation_errors
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {item!r}")

    def _service_role(self) -> str:
        raw_role = os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or "all"
        normalized = str(raw_role).strip().lower()
        return normalized if normalized in {"api", "worker"} else "all"

    def _is_worker_role(self) -> bool:
        return self._service_role() in {"all", "worker"}

    def _can_consume_state_events(self) -> bool:
        return False

    def _can_own_runtime_phase(self, phase: str | None) -> bool:
        normalized = str(phase or "").strip().lower()
        if normalized in {"", TASK_RUNTIME_PHASE_OWNED_EXECUTION}:
            return self._is_worker_role()
        if normalized == TASK_RUNTIME_PHASE_TERMINAL:
            return False
        return self._is_worker_role()

    def _allow_tail_runtime_write(self, task: BinarySecurityTask | None) -> bool:
        del task
        return False

    def _is_tail_control_plane_stale_error(
        self,
        *,
        error_message: str | None,
        error_type: str | None,
    ) -> bool:
        normalized_type = str(error_type or "").strip().lower()
        normalized_message = str(error_message or "").strip().lower()
        control_tokens = (
            "tail 收敛 owner 已变更",
            "tail 收敛 lease 已失效",
            "当前 tail 收敛 owner 已变更",
            "当前 tail 收敛 lease 已失效",
            "tail reconciliation owner changed",
            "tail reconciliation lease expired",
        )
        if normalized_type == "staletaskexecution":
            return any(token.lower() in normalized_message for token in control_tokens)
        return any(token.lower() in normalized_message for token in control_tokens)

    def _is_owned_execution_stale_error(
        self,
        *,
        error_message: str | None,
        error_type: str | None,
    ) -> bool:
        normalized_type = str(error_type or "").strip().lower()
        normalized_message = str(error_message or "").strip().lower()
        owned_execution_tokens = (
            "当前执行 token 已失效",
            "缺少当前执行 token",
            "当前 owned_execution runtime lease owner 已变更",
            "当前 owned_execution runtime lease 已失效",
            "当前执行 owner 已变更",
            "当前执行 lease 已失效",
            "current execution token expired",
            "missing current execution token",
            "owned_execution runtime lease owner changed",
            "owned_execution runtime lease expired",
            "current execution owner changed",
            "current execution lease expired",
        )
        if normalized_type == "staletaskexecution":
            return any(token.lower() in normalized_message for token in owned_execution_tokens)
        return any(token.lower() in normalized_message for token in owned_execution_tokens)

    def _task_is_waiting_for_manual_confirmation(
        self,
        task: BinarySecurityTask,
        stage_summaries: list[BinarySecurityStageSummary] | None = None,
    ) -> bool:
        task_status = str(task.status or "").strip()
        if task_status in {TASK_STATUS_PENDING_MODULE_CONFIRMATION, TASK_STATUS_PENDING_ENTRY_CONFIRMATION, "waiting_confirmation"}:
            return True
        if not stage_summaries:
            return False
        return any(str(summary.status or "").strip() == "waiting_confirmation" for summary in stage_summaries)

    def _has_recent_matching_task_event(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        event_type: str,
        stage_name: str | None,
        message: str | None = None,
        payload_keys: dict[str, Any] | None = None,
        within_seconds: int = 300,
    ) -> bool:
        if within_seconds <= 0:
            return False
        threshold = _now() - timedelta(seconds=within_seconds)
        rows = (
            db.query(BinarySecurityEvent)
            .filter(
                BinarySecurityEvent.task_id == task.id,
                BinarySecurityEvent.event_type == event_type,
                BinarySecurityEvent.created_at >= threshold,
            )
            .order_by(BinarySecurityEvent.created_at.desc())
            .limit(20)
            .all()
        )
        expected_message = str(message or "").strip()
        expected_stage = str(stage_name or "").strip()
        expected_payload = dict(payload_keys or {})
        for row in rows:
            if expected_stage and str(row.stage_name or "").strip() != expected_stage:
                continue
            if expected_message and str(row.message or "").strip() != expected_message:
                continue
            payload = dict(row.payload or {})
            if any(payload.get(key) != value for key, value in expected_payload.items()):
                continue
            return True
        return False

    def _record_non_owner_streaming_claim_skip(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        emit_event: bool = True,
    ) -> None:
        lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        task_owner = (
            str(getattr(lease, "owner_instance_id", "") or "").strip() or None
            if self._runtime_lease_is_active(lease)
            else None
        )
        local_owner = str(self.instance_id or "").strip() or None
        event_message = f"流式阶段子任务 claim 被非 owner pod 拦截，等待当前执行实例消费: {item.stage_name}"
        throttle_key = (
            str(task.id or ""),
            str(item.stage_name or ""),
            str(task_owner or ""),
            str(local_owner or ""),
        )
        now = _now()
        last_event_at = self._non_owner_claim_event_state.get(throttle_key)
        should_record_event = last_event_at is None or (now - last_event_at).total_seconds() >= 60
        if emit_event and should_record_event and not self._has_recent_matching_task_event(
            db,
            task,
            event_type="streaming_stage_item_claim_skipped_non_owner",
            stage_name=item.stage_name,
            message=event_message,
            payload_keys={
                "task_owner": task_owner,
                "local_owner": local_owner,
            },
            within_seconds=60,
        ):
            self._record_event(
                db,
                task,
                "streaming_stage_item_claim_skipped_non_owner",
                event_message,
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "item_id": item.id,
                    "item_key": item.item_key,
                    "task_owner": task_owner,
                    "local_owner": local_owner,
                    "task_execution_token": self._dispatch_token(task),
                },
            )
            self._non_owner_claim_event_state[throttle_key] = now
        with self._non_owner_claim_log_lock:
            state = self._non_owner_claim_log_state.get(throttle_key)
            if state is None:
                self._non_owner_claim_log_state[throttle_key] = {
                    "last_emitted_at": now,
                    "suppressed_count": 0,
                    "sample_item_ids": [str(item.id or "")] if item.id else [],
                }
                should_emit = True
                skipped_count = 1
                sample_item_ids = [str(item.id or "")] if item.id else []
            else:
                sample_item_ids = list(state.get("sample_item_ids") or [])
                item_id = str(item.id or "")
                if item_id and item_id not in sample_item_ids and len(sample_item_ids) < 5:
                    sample_item_ids.append(item_id)
                    state["sample_item_ids"] = sample_item_ids
                elapsed = (now - state["last_emitted_at"]).total_seconds()
                if elapsed < 60:
                    state["suppressed_count"] = int(state.get("suppressed_count") or 0) + 1
                    should_emit = False
                    skipped_count = int(state["suppressed_count"]) + 1
                else:
                    skipped_count = int(state.get("suppressed_count") or 0) + 1
                    state["last_emitted_at"] = now
                    state["suppressed_count"] = 0
                    state["sample_item_ids"] = [item_id] if item_id else []
                    sample_item_ids = list(state["sample_item_ids"])
                    should_emit = True
        if should_emit:
            logger.info(
                "binary-security streaming stage item claim skipped for non-owner pod: task_id=%s stage=%s task_owner=%s local_owner=%s skipped_count=%s sample_item_ids=%s",
                task.id,
                item.stage_name,
                task_owner,
                self.instance_id,
                skipped_count,
                ",".join(filter(None, sample_item_ids)),
            )

    def _downstream_tasks(self):
        return get_downstream_task_controller(self)

    def _stage_downstream_sync_max_consecutive_errors(self) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "stage_downstream_sync_max_consecutive_errors", 10) or 10))

    def _downstream_child_sync_interval_seconds(self) -> int:
        return max(5, int(getattr(self.cfg.scheduler, "downstream_reconcile_interval_seconds", 60) or 60))

    def _stage_downstream_sync_backoff_base_seconds(self) -> int:
        configured = int(
            getattr(
                self.cfg.scheduler,
                "stage_downstream_sync_backoff_base_seconds",
                self._downstream_child_sync_interval_seconds(),
            )
            or self._downstream_child_sync_interval_seconds()
        )
        return max(1, configured)

    def _stage_downstream_sync_backoff_max_seconds(self) -> int:
        base = self._stage_downstream_sync_backoff_base_seconds()
        configured = int(getattr(self.cfg.scheduler, "stage_downstream_sync_backoff_max_seconds", 60) or 60)
        return max(base, configured)

    def _stage_item_sync_stale_seconds(self) -> int:
        configured = int(getattr(self.cfg.scheduler, "stage_item_sync_stale_seconds", 300) or 300)
        return max(
            30,
            configured,
            int(getattr(self.cfg.scheduler, "downstream_reconcile_interval_seconds", 30) or 30) * 3,
        )

    def _stage_item_sync_reconcile_interval_seconds(self) -> int:
        configured = int(
            getattr(
                self.cfg.scheduler,
                "stage_item_sync_reconcile_interval_seconds",
                self._downstream_child_sync_interval_seconds(),
            )
            or self._downstream_child_sync_interval_seconds()
        )
        return max(5, configured)

    def _stage_item_sync_reconcile_batch_size(self) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "stage_item_sync_reconcile_batch_size", 100) or 100))

    def _stage_orchestration_max_consecutive_errors(self) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "stage_orchestration_max_consecutive_errors", 10) or 10))

    def _stage_orchestration_backoff_base_seconds(self) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "stage_orchestration_backoff_base_seconds", 2) or 2))

    def _stage_orchestration_backoff_max_seconds(self) -> int:
        base = self._stage_orchestration_backoff_base_seconds()
        configured = int(getattr(self.cfg.scheduler, "stage_orchestration_backoff_max_seconds", 60) or 60)
        return max(base, configured)

    def _archive_runtime_reconcile_interval_seconds(self) -> int:
        return max(5, int(getattr(self.cfg.scheduler, "archive_runtime_reconcile_interval_seconds", 30) or 30))

    def _archive_runtime_stale_seconds(self) -> int:
        return max(30, int(getattr(self.cfg.scheduler, "archive_runtime_stale_seconds", 300) or 300))

    def _state_repair_reconcile_interval_seconds(self) -> int:
        return max(5, int(getattr(self.cfg.scheduler, "state_repair_reconcile_interval_seconds", 30) or 30))

    def _state_repair_reconcile_batch_size(self) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "state_repair_reconcile_batch_size", 100) or 100))

    async def _operation_progress_heartbeat(
        self,
        db: Session,
        task: BinarySecurityTask,
        operation: BinarySecurityTaskOperation,
        *,
        step_name: str,
        resume_cursor: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        record_event: bool = False,
    ) -> None:
        merged_payload = dict(self._operation_step_snapshot(operation, step_name).get("payload") or {})
        if payload:
            merged_payload.update(payload)
        self._set_operation_step_state(
            operation,
            step_name=step_name,
            status="running",
            payload=merged_payload,
            resume_cursor=resume_cursor if resume_cursor is not None else dict(operation.resume_cursor or {}),
            increment_attempt=False,
            workspace_root=task.workspace_root,
        )
        now_value = _now()
        operation.updated_at = now_value
        if record_event:
            self._record_operation_event(
                db,
                task,
                operation,
                "operation_step_progress_heartbeat",
                f"后台操作步骤进度已刷新: {step_name}",
                stage_name=operation.target_stage,
                payload={"step_name": step_name, **merged_payload},
            )
        db.commit()
        await asyncio.sleep(0)

    async def _downstream_get_task(
        self,
        *,
        service: str,
        project_id: str | None,
        task_id: str,
        token: str | None,
    ) -> dict[str, Any]:
        return await self._downstream_tasks().get_child_task(
            service=service,
            project_id=project_id,
            task_id=task_id,
            token=token,
        )

    async def _downstream_list_tasks(
        self,
        *,
        service: str,
        project_id: str,
        token: str | None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return await self._downstream_tasks().list_child_tasks(
            service=service,
            project_id=project_id,
            token=token,
            **kwargs,
        )

    async def _downstream_create_task(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        service: str,
        token: str | None,
        payload: dict[str, Any],
        event_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._record_stage_item_sync_audit(
            db,
            task=task,
            item=item,
            stage_name=str(getattr(item, "stage_name", "") or "").strip() or None,
            downstream_service=service,
            operation="downstream_create",
            event_type="requested",
            sync_status="requested",
            outcome="requested",
            state_applied=False,
            payload={
                "service": str(service or ""),
                "request_payload_keys": sorted([str(key) for key in dict(payload or {}).keys()]),
                **(event_payload or {}),
            },
        )
        active_delete_operation = self._active_delete_operation(db, task.id)
        if active_delete_operation is not None:
            self._record_event(
                db,
                task,
                "downstream_create_skipped_due_to_delete_operation",
                f"任务删除已受理，已阻止新的下游子任务创建: {service}",
                level="warning",
                stage_name=str(getattr(item, "stage_name", "") or "").strip() or None,
                item=item,
                payload={
                    "service": str(service or ""),
                    "operation_id": str(getattr(active_delete_operation, "id", "") or "").strip() or None,
                    "operation_type": str(getattr(active_delete_operation, "operation_type", "") or "").strip() or None,
                },
            )
            raise ValidationError("任务删除已受理，后台正在清理任务及下游资源，禁止创建新的下游子任务")
        has_root_task_key = bool(self._root_task_key_secret(task))
        if has_root_task_key:
            self._record_event(
                db,
                task,
                "downstream_work_key_requested",
                f"为下游任务申请 work key: {service}",
                payload={
                    "stage_item_id": str(getattr(item, "id", "") or ""),
                    "stage_name": str(getattr(item, "stage_name", "") or ""),
                    "service": str(service or ""),
                    "sub_task_id": str(getattr(item, "id", "") or ""),
                    "has_root_task_key": True,
                },
            )
        try:
            work_key_payload = await self._derive_downstream_work_key(task=task, item=item, service=service)
        except (UnauthorizedError, ForbiddenError, LLMGatewayWorkKeyIssueError) as exc:
            status_code = getattr(exc, "gateway_status_code", None)
            response_text = getattr(exc, "response_text", None)
            retryable = bool(getattr(exc, "retryable", False))
            self._record_event(
                db,
                task,
                "downstream_work_key_request_failed",
                f"向 LLM Gateway 申请 worker key 失败: {service}",
                level="warning" if retryable else "error",
                stage_name=str(getattr(item, "stage_name", "") or "").strip() or None,
                item=item,
                payload={
                    "stage_item_id": str(getattr(item, "id", "") or ""),
                    "stage_name": str(getattr(item, "stage_name", "") or ""),
                    "service": str(service or ""),
                    "sub_task_id": str(getattr(item, "id", "") or ""),
                    "gateway_status_code": status_code,
                    "gateway_error": str(exc),
                    "gateway_response_text": response_text,
                    "retryable": retryable,
                },
            )
            raise
        effective_token = token
        effective_payload = dict(payload or {})
        if work_key_payload:
            effective_payload.update(work_key_payload)
            item_payload = dict(item.payload or {})
            item_payload.update(
                {
                    "downstream_agent_task_key_id": work_key_payload.get("agent_task_key_id"),
                    "downstream_agent_task_key_name": work_key_payload.get("agent_task_key_name"),
                    "downstream_agent_task_key_prefix": work_key_payload.get("agent_task_key_prefix"),
                    "downstream_key_source": work_key_payload.get("agent_task_key_source"),
                }
            )
            item.payload = item_payload
            self._record_event(
                db,
                task,
                "downstream_work_key_created",
                f"已为下游任务创建 work key: {service}",
                payload={
                    "stage_item_id": str(getattr(item, "id", "") or ""),
                    "stage_name": str(getattr(item, "stage_name", "") or ""),
                    "service": str(service or ""),
                    "sub_task_id": work_key_payload.get("sub_task_id"),
                    "agent_task_key_id": work_key_payload.get("agent_task_key_id"),
                    "agent_task_key_name": work_key_payload.get("agent_task_key_name"),
                    "agent_task_key_prefix": work_key_payload.get("agent_task_key_prefix"),
                    "agent_task_key_source": work_key_payload.get("agent_task_key_source"),
                },
            )
            self._record_event(
                db,
                task,
                "downstream_create_with_agent_task_key",
                f"创建下游任务时附带 agent task key: {service}",
                payload={
                    "stage_item_id": str(getattr(item, "id", "") or ""),
                    "stage_name": str(getattr(item, "stage_name", "") or ""),
                    "service": str(service or ""),
                    "sub_task_id": work_key_payload.get("sub_task_id"),
                    "agent_task_key_id": work_key_payload.get("agent_task_key_id"),
                    "agent_task_key_name": work_key_payload.get("agent_task_key_name"),
                    "agent_task_key_prefix": work_key_payload.get("agent_task_key_prefix"),
                    "agent_task_key_source": work_key_payload.get("agent_task_key_source"),
                },
            )
        created = await self._downstream_tasks().create_child_task(
            db,
            task,
            item,
            service=service,
            token=effective_token,
            payload=effective_payload,
            event_payload=event_payload,
        )
        self._record_stage_item_sync_audit(
            db,
            task=task,
            item=item,
            stage_name=str(getattr(item, "stage_name", "") or "").strip() or None,
            downstream_service=service,
            operation="downstream_create",
            event_type="applied",
            sync_status="observed",
            outcome="success",
            state_applied=True,
            payload={
                "service": str(service or ""),
                "created_task_id": created.get("task_id") or created.get("id"),
                "created_status": created.get("status"),
                **(event_payload or {}),
            },
        )
        return created

    async def _downstream_control_existing_task(
        self,
        db: Session,
        *,
        stage_name: str,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
    ) -> dict[str, Any]:
        normalized_status = str(item.status or "").strip().lower()
        if str(item.downstream_task_id or "").strip():
            try:
                payload = await self._fetch_downstream_task_payload(task, item, token or "")
            except Exception:
                payload = None
            mapped = self._map_downstream_status(str((payload or {}).get("status") or ""))
            if payload and mapped == "running":
                return {"outcome": "already_running", "payload": payload}
            if normalized_status in {"running", "dispatching"} and payload and mapped == "pending":
                return {"outcome": "already_running", "payload": payload}
        return await self._downstream_tasks().control_existing_child(
            db,
            stage_name=stage_name,
            task=task,
            item=item,
            token=token,
        )

    async def _downstream_fetch_item_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
    ) -> dict[str, Any]:
        return await self._downstream_tasks().fetch_child_payload(task, item, token)

    async def _downstream_fetch_ref_payload(
        self,
        ref: dict[str, str],
        token: str | None,
    ) -> dict[str, Any]:
        return await self._downstream_tasks().fetch_child_ref_payload(ref, token)

    async def _downstream_fetch_item_result(self, item: BinarySecurityStageItem) -> dict[str, Any]:
        return await self._downstream_tasks().fetch_child_result(item)

    async def _downstream_fetch_item_artifacts(
        self,
        item: BinarySecurityStageItem,
        token: str | None,
    ) -> dict[str, Any]:
        return await self._downstream_tasks().fetch_child_artifacts(item, token)

    async def _downstream_cancel_item(self, item: BinarySecurityStageItem, token: str | None) -> None:
        await self._downstream_tasks().cancel_child_task(item, token)

    async def _downstream_cancel_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
    ) -> int:
        return await self._downstream_tasks().cancel_child_refs(db, task, refs, token)

    async def _downstream_delete_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
        *,
        force_delete: bool = False,
        best_effort: bool = False,
        cleanup_scope: str = "retry_prepare",
    ) -> int:
        return await self._downstream_tasks().delete_child_refs(
            db,
            task,
            refs,
            token,
            force_delete=force_delete,
            best_effort=best_effort,
            cleanup_scope=cleanup_scope,
        )

    async def _downstream_ensure_refs_inactive(
        self,
        refs: list[dict[str, str]],
        token: str | None,
    ) -> None:
        await self._downstream_tasks().ensure_child_refs_inactive(refs, token)

    async def _downstream_cleanup_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
    ) -> int:
        return await self._downstream_tasks().cleanup_child_refs(db, task, refs, token)

    async def start(self) -> None:
        if self._running:
            logger.info("binary-security task manager start skipped: already_running=true")
            return
        self._running = True
        self._runtime_loop = asyncio.get_running_loop()
        observe_worker_counts(task_workers=0, operation_workers=0, archive_workers=0, task_heartbeat_workers=0)
        role = self._service_role()
        run_worker_loops = role in {"", "all", "worker"}
        logger.info(
            "binary-security task manager starting: role=%s run_worker_loops=%s "
            "queue_redis=%s task_queue_key=%s",
            role or "all",
            run_worker_loops,
            str(getattr(self.cfg.queue, "redis_url", "") or "").strip() or None,
            str(getattr(self.cfg.queue, "task_queue_key", "") or "").strip() or None,
        )
        try:
            if run_worker_loops:
                logger.info(
                    "binary-security task manager redis_warmup starting: timeout_seconds=%s retry_interval_seconds=%s",
                    int(getattr(self.cfg.queue, "startup_ready_timeout_seconds", 60) or 60),
                    int(getattr(self.cfg.queue, "startup_retry_interval_seconds", 2) or 2),
                )
                await get_task_queue().wait_until_ready(
                    context="startup_warmup",
                    timeout_seconds=int(getattr(self.cfg.queue, "startup_ready_timeout_seconds", 60) or 60),
                    retry_interval_seconds=int(getattr(self.cfg.queue, "startup_retry_interval_seconds", 2) or 2),
                )
                logger.info("binary-security task manager redis_warmup ok")
            if run_worker_loops:
                logger.info("binary-security task manager seeding work queues")
                await self._seed_work_queues()
                logger.info("binary-security task manager seeded work queues")
                logger.info("binary-security task manager starting dispatch loops")
                self._lease_watchdog_stop_event.clear()
                self._event_loop_lag_monitor_task = asyncio.create_task(
                    self._run_event_loop_lag_monitor(),
                    name="binary-security-event-loop-lag-monitor",
                )
                self._start_runtime_lease_watchdog()
                self._loop_task = asyncio.create_task(self._dispatch_loop(), name="binary-security-dispatcher")
                self._archive_loop_task = asyncio.create_task(self._archive_dispatch_loop(), name="binary-security-archive-dispatcher")
                self._delete_loop_task = asyncio.create_task(self._delete_dispatch_loop(), name="binary-security-delete-dispatcher")
                self._stage_item_loop_task = asyncio.create_task(
                    self._stage_item_dispatch_loop(),
                    name="binary-security-stage-item-dispatcher",
                )
            logger.info("binary-security task manager started")
        except Exception:
            logger.exception("binary-security task manager start failed; stopping partially started runtime")
            await self.stop()
            raise

    async def _cancel_loop_task(self, task: asyncio.Task | None) -> None:
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        self._running = False
        self._lease_watchdog_stop_event.set()
        await self._cancel_loop_task(self._loop_task)
        await self._cancel_loop_task(self._archive_loop_task)
        await self._cancel_loop_task(self._delete_loop_task)
        await self._cancel_loop_task(self._stage_item_loop_task)
        await self._cancel_loop_task(self._state_event_inbox_loop_task)
        await self._cancel_loop_task(self._state_event_inbox_metrics_loop_task)
        await self._cancel_loop_task(self._event_loop_lag_monitor_task)
        self._event_loop_lag_monitor_task = None
        await asyncio.to_thread(self._stop_runtime_lease_watchdog)
        archive_active = list(self._archive_workers)
        for task in archive_active:
            task.cancel()
        if archive_active:
            await asyncio.gather(*archive_active, return_exceptions=True)
        await asyncio.to_thread(self._requeue_owned_running_archive_jobs)
        active_handles = list(self._workers.values())
        for handle in active_handles:
            handle.cancel()
        active_tasks: list[asyncio.Task] = []
        for handle in active_handles:
            active_tasks.append(handle.runner_task)
            if handle.heartbeat_task is not None:
                active_tasks.append(handle.heartbeat_task)
            if handle.sync_maintenance_task is not None:
                active_tasks.append(handle.sync_maintenance_task)
        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)
        # 优雅退出：主动释放本实例持有的 runtime_lease + 清 task 行 owner，
        # 避免 rollout 后任务因孤儿租约卡 lease TTL（~300s）才被新 worker 接管。
        owned_task_ids = [str(tid or "").strip() for tid in self._workers.keys() if str(tid or "").strip()]
        if owned_task_ids:
            await asyncio.to_thread(self._release_owned_runtime_leases_on_shutdown, owned_task_ids)
        self._workers.clear()
        self._operation_workers.clear()
        stage_item_active = list(self._stage_item_workers.values())
        for task in stage_item_active:
            task.cancel()
        if stage_item_active:
            await asyncio.gather(*stage_item_active, return_exceptions=True)
        with self._task_execution_owner_lock:
            self._task_execution_owners.clear()
        self._last_task_heartbeat_at.clear()
        self._runtime_loop = None
        observe_worker_counts(task_workers=0, operation_workers=0, archive_workers=0, task_heartbeat_workers=0)

    def _start_runtime_lease_watchdog(self) -> None:
        thread = self._lease_watchdog_thread
        if thread is not None and thread.is_alive():
            return
        self._lease_watchdog_stop_event.clear()
        self._lease_watchdog_thread = threading.Thread(
            target=self._run_runtime_lease_watchdog,
            name="binary-security-runtime-lease-watchdog",
            daemon=True,
        )
        self._lease_watchdog_thread.start()

    def _stop_runtime_lease_watchdog(self) -> None:
        self._lease_watchdog_stop_event.set()
        thread = self._lease_watchdog_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(1.0, float(self._runtime_watchdog_interval_seconds() * 2)))
        self._lease_watchdog_thread = None

    def _watchdog_runtime_handle_snapshot(self) -> list[TaskRuntimeHandle]:
        for _ in range(3):
            try:
                return [
                    handle
                    for handle in list(self._workers.values())
                    if not handle.done() and not handle.cancel_requested and not handle.release_requested and bool(handle.owner_active)
                ]
            except RuntimeError:
                time.sleep(0.01)
        return []

    def _watchdog_should_keep_runtime_lease(self, db: Session, task: BinarySecurityTask | None, handle: TaskRuntimeHandle | None) -> bool:
        del db
        if task is None or handle is None:
            return False
        if handle.cancel_requested or handle.release_requested or handle.takeover_observed:
            return False
        if str(getattr(task, "status", "") or "").strip().lower() in TASK_TERMINAL_STATUSES:
            return False
        return True

    def _watchdog_should_skip_lease_write(self, handle: TaskRuntimeHandle | None, *, now_value: datetime) -> bool:
        if handle is None:
            return True
        last_refresh_at = getattr(handle, "last_lease_refresh_at", None)
        if last_refresh_at is None:
            return False
        interval_seconds = max(1.0, float(self._runtime_watchdog_interval_seconds()))
        return (now_value - last_refresh_at).total_seconds() < interval_seconds

    def _record_watchdog_runtime_stall_before_abort(
        self,
        task_id: str,
        *,
        decision: "_RuntimeLeaseOwnershipDecision",
        source: str,
    ) -> None:
        handle = self._runtime_handle(task_id)
        if handle is None or handle.last_lease_refresh_at is None:
            return
        max_stall_seconds = float(self._runtime_watchdog_interval_seconds() * 2)
        stalled_seconds = max(0.0, (_now() - handle.last_lease_refresh_at).total_seconds())
        if stalled_seconds <= max_stall_seconds:
            return
        db = get_session_factory()()
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is None:
                return
            self._record_event(
                db,
                task,
                "runtime_lease_refresh_stalled_before_abort",
                "本地 runtime lease 刷新长时间停滞后检测到 owner 已失租",
                level="warning",
                stage_name=str(getattr(task, "current_stage", "") or "").strip() or None,
                payload={
                    "task_id": task_id,
                    "source": str(source or "").strip() or None,
                    "runtime_lease_owner": decision.runtime_lease_owner,
                    "runtime_lease_expires_at": _isoformat_or_none(decision.runtime_lease_expires_at),
                    "last_lease_refresh_at": _isoformat_or_none(handle.last_lease_refresh_at),
                    "stalled_seconds": stalled_seconds,
                    "abort_reason": decision.abort_reason,
                },
            )
            db.commit()
        finally:
            db.close()

    def _run_runtime_lease_watchdog(self) -> None:
        logger.info("binary-security runtime lease watchdog started")
        interval_seconds = self._runtime_watchdog_interval_seconds()
        try:
            while self._running and not self._lease_watchdog_stop_event.is_set():
                tick_at = _now()
                with self._lease_watchdog_state_lock:
                    self._lease_watchdog_last_tick_at = tick_at
                handles = self._watchdog_runtime_handle_snapshot()
                for handle in handles:
                    task_id = str(getattr(handle, "task_id", "") or "").strip()
                    if not task_id:
                        continue
                    db = get_session_factory()()
                    try:
                        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
                        if not self._watchdog_should_keep_runtime_lease(db, task, handle):
                            continue
                        decision = self._assert_active_runtime_lease_owner(
                            db,
                            task_id,
                            expected_owner=str(self.instance_id or "").strip() or None,
                            allow_retryable_read_error=True,
                        )
                        self._mark_runtime_handle_lease_verify(task_id, verified_at=tick_at)
                        if self._should_abort_local_runtime_after_lease_loss(decision):
                            self._record_watchdog_runtime_stall_before_abort(
                                task_id,
                                decision=decision,
                                source="runtime_lease_watchdog",
                            )
                            self._verify_local_runtime_lease_or_abort(task_id, "runtime_lease_watchdog")
                            continue
                        if self._watchdog_should_skip_lease_write(handle, now_value=tick_at):
                            continue
                        self._write_task_heartbeat(db, task_id, now_value=tick_at, source="watchdog")
                    except StaleTaskExecution:
                        self._verify_local_runtime_lease_or_abort(task_id, "runtime_lease_watchdog")
                    except OperationalError as exc:
                        db.rollback()
                        if self._is_retryable_lock_error(exc):
                            logger.info(
                                "binary-security runtime lease watchdog deferred by lock conflict: task_id=%s error_type=%s",
                                task_id,
                                exc.__class__.__name__,
                            )
                            with self._lease_watchdog_state_lock:
                                self._lease_watchdog_last_error = f"task:{task_id}:lock_conflict"
                            continue
                        raise
                    except Exception:
                        logger.exception(
                            "binary-security runtime lease watchdog failed: task_id=%s",
                            task_id,
                        )
                        with self._lease_watchdog_state_lock:
                            self._lease_watchdog_last_error = f"task:{task_id}"
                    else:
                        with self._lease_watchdog_state_lock:
                            self._lease_watchdog_last_success_at = tick_at
                            self._lease_watchdog_last_error = None
                    finally:
                        db.close()
                if not handles:
                    with self._lease_watchdog_state_lock:
                        self._lease_watchdog_last_success_at = tick_at
                        self._lease_watchdog_last_error = None
                self._lease_watchdog_stop_event.wait(interval_seconds)
        finally:
            logger.info("binary-security runtime lease watchdog stopped")

    async def _run_event_loop_lag_monitor(self) -> None:
        interval_seconds = 1.0
        expected_at = time.monotonic()
        while self._running:
            await asyncio.sleep(interval_seconds)
            now_monotonic = time.monotonic()
            lag_seconds = max(0.0, now_monotonic - expected_at - interval_seconds)
            expected_at = now_monotonic
            self._event_loop_last_tick_at = _now()
            self._event_loop_last_lag_seconds = lag_seconds
            if lag_seconds > self._event_loop_stall_threshold_seconds:
                self._event_loop_last_stall_at = self._event_loop_last_tick_at
                logger.warning(
                    "binary-security event loop stall detected: lag_seconds=%.3f threshold_seconds=%.3f",
                    lag_seconds,
                    self._event_loop_stall_threshold_seconds,
                )

    def _release_owned_runtime_leases_on_shutdown(self, task_ids: list[str]) -> None:
        """优雅退出时释放本实例持有的 runtime_lease。

        runner/heartbeat 已在 stop() 中先取消，此处仅做 DB 侧租约释放，使新 worker
        可立即接管，无需等待 lease TTL（~300s）过期。仅在 owner_instance_id 匹配本实例时释放。
        """
        instance_id = str(self.instance_id or "").strip()
        if not instance_id or not task_ids:
            return
        grace_seconds = max(1, int(getattr(self.cfg.scheduler, "shutdown_grace_seconds", 10) or 10))
        deadline = time.monotonic() + grace_seconds
        session_factory = get_session_factory()
        released = 0
        for task_id in task_ids:
            if time.monotonic() > deadline:
                logger.warning(
                    "binary-security shutdown lease release timed out after %ss: released=%s pending=%s",
                    grace_seconds, released, len(task_ids) - released,
                )
                break
            db = session_factory()
            try:
                self._clear_runtime_lease(db, task_id, owner_instance_id=instance_id, swallow_lock_error=True)
                db.commit()
                released += 1
            except Exception:
                db.rollback()
                logger.warning("binary-security shutdown lease release failed: task_id=%s", task_id, exc_info=True)
            finally:
                db.close()
        if released:
            logger.info("binary-security shutdown released %s owned runtime lease(s)", released)

    def _register_task_execution_owner(self, task_id: str, owner_kind: str) -> None:
        normalized_task_id = str(task_id or "").strip()
        normalized_owner = str(owner_kind or "").strip()
        if not normalized_task_id or not normalized_owner:
            return
        with self._task_execution_owner_lock:
            owners = self._task_execution_owners.setdefault(normalized_task_id, set())
            owners.add(normalized_owner)

    def _release_task_execution_owner(self, task_id: str, owner_kind: str) -> None:
        normalized_task_id = str(task_id or "").strip()
        normalized_owner = str(owner_kind or "").strip()
        if not normalized_task_id or not normalized_owner:
            return
        with self._task_execution_owner_lock:
            owners = self._task_execution_owners.get(normalized_task_id)
            if not owners:
                return
            owners.discard(normalized_owner)
            if not owners:
                self._task_execution_owners.pop(normalized_task_id, None)

    def _task_execution_owner_count(self, task_id: str) -> int:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return 0
        with self._task_execution_owner_lock:
            return len(self._task_execution_owners.get(normalized_task_id) or ())

    def _has_local_task_execution_owner(self, task_id: str) -> bool:
        return self._task_execution_owner_count(task_id) > 0

    def _runtime_handle(self, task_id: str) -> TaskRuntimeHandle | None:
        return self._workers.get(str(task_id or "").strip())

    def _mark_runtime_handle_runner_progress(self, task_id: str, *, progress_at: datetime | None = None) -> None:
        handle = self._runtime_handle(task_id)
        if handle is None:
            return
        now_value = progress_at or _now()
        handle.last_runner_progress_at = now_value
        handle.last_progress_at = now_value

    def _mark_runtime_handle_sync_progress(self, task_id: str, *, progress_at: datetime | None = None) -> None:
        handle = self._runtime_handle(task_id)
        if handle is None:
            return
        now_value = progress_at or _now()
        handle.last_sync_maintenance_progress_at = now_value
        handle.last_progress_at = now_value

    def _mark_runtime_handle_lease_verify(self, task_id: str, *, verified_at: datetime | None = None) -> None:
        handle = self._runtime_handle(task_id)
        if handle is None:
            return
        handle.last_lease_verify_at = verified_at or _now()

    def _runtime_watchdog_interval_seconds(self) -> int:
        heartbeat_interval = max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15))
        return max(1, min(5, heartbeat_interval))

    def _lease_watchdog_alive(self) -> bool:
        thread = self._lease_watchdog_thread
        return bool(thread is not None and thread.is_alive())

    def _lease_watchdog_status_snapshot(self) -> dict[str, Any]:
        now_value = _now()
        with self._lease_watchdog_state_lock:
            last_tick_at = self._lease_watchdog_last_tick_at
            last_success_at = self._lease_watchdog_last_success_at
            last_error = self._lease_watchdog_last_error
        stall_seconds = (
            max(0.0, (now_value - last_tick_at).total_seconds())
            if last_tick_at is not None
            else None
        )
        return {
            "alive": self._lease_watchdog_alive(),
            "last_tick_at": last_tick_at,
            "last_success_at": last_success_at,
            "stall_seconds": stall_seconds,
            "stale": bool(stall_seconds is not None and stall_seconds > float(self._runtime_watchdog_interval_seconds() * 2)),
            "last_error": last_error,
        }

    def _event_loop_lag_snapshot(self) -> dict[str, Any]:
        now_value = _now()
        last_tick_at = self._event_loop_last_tick_at
        observed_gap = (
            max(0.0, (now_value - last_tick_at).total_seconds())
            if last_tick_at is not None
            else None
        )
        current_lag_seconds = max(
            float(self._event_loop_last_lag_seconds or 0.0),
            max(0.0, (observed_gap or 0.0) - 1.0),
        )
        return {
            "last_tick_at": last_tick_at,
            "lag_seconds": current_lag_seconds,
            "last_stall_at": self._event_loop_last_stall_at,
        }

    def _request_runtime_handle_abort(self, task_id: str, *, reason: str | None = None) -> None:
        normalized_task_id = str(task_id or "").strip()
        handle = self._runtime_handle(normalized_task_id)
        if handle is None:
            return
        handle.cancel_requested = True
        handle.cancel_requested_reason = str(reason or "").strip() or handle.cancel_requested_reason
        loop = self._runtime_loop

        def _cancel() -> None:
            current_handle = self._runtime_handle(normalized_task_id)
            if current_handle is None:
                return
            current_handle.cancel_requested = True
            current_handle.cancel_requested_reason = str(reason or "").strip() or current_handle.cancel_requested_reason
            if current_handle.runner_task is not None and not current_handle.runner_task.done():
                current_handle.runner_task.cancel()
            heartbeat_task = getattr(current_handle, "heartbeat_task", None)
            if heartbeat_task is not None and not heartbeat_task.done():
                heartbeat_task.cancel()
            sync_maintenance_task = getattr(current_handle, "sync_maintenance_task", None)
            if sync_maintenance_task is not None and not sync_maintenance_task.done():
                sync_maintenance_task.cancel()

        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(_cancel)
            return
        _cancel()

    def _mark_runner_exited_keep_owner(
        self,
        task_id: str,
        *,
        reason: str,
    ) -> None:
        handle = self._runtime_handle(task_id)
        if handle is None:
            return
        handle.last_runner_exit_at = _now()
        handle.last_progress_at = handle.last_progress_at or handle.last_runner_exit_at
        handle.release_requested = False
        handle.release_reason = str(reason or "").strip() or None
        handle.owner_active = True

    def _request_parent_runtime_release(
        self,
        task_id: str,
        *,
        reason: str,
        takeover_observed: bool = False,
    ) -> None:
        handle = self._runtime_handle(task_id)
        if handle is None:
            return
        handle.release_requested = True
        handle.release_reason = str(reason or "").strip() or None
        handle.owner_active = False
        handle.takeover_observed = bool(takeover_observed)

    async def _request_local_worker_control_wakeup(
        self,
        task_id: str,
        operation_type: str,
        *,
        operation_id: str | None = None,
        wait_for_runner: bool = False,
    ) -> bool:
        del wait_for_runner
        async with self._worker_lock:
            return self._request_local_worker_control_wakeup_nowait(
                task_id,
                operation_type,
                operation_id=operation_id,
            )

    async def _request_local_worker_retry_like_wakeup(
        self,
        task_id: str,
        operation_type: str,
        *,
        operation_id: str | None = None,
    ) -> bool:
        return await self._request_local_worker_control_wakeup(
            task_id,
            operation_type,
            operation_id=operation_id,
            wait_for_runner=False,
        )

    def _clear_local_worker_control_wakeup(self, task_id: str) -> None:
        handle = self._runtime_handle(task_id)
        if handle is None:
            return
        handle.control_wakeup_requested = False
        handle.control_wakeup_reason = None
        handle.pending_operation_id = None
        handle.pending_operation_type = None

    def _request_local_worker_control_wakeup_nowait(
        self,
        task_id: str,
        operation_type: str,
        *,
        operation_id: str | None = None,
    ) -> bool:
        normalized_task_id = str(task_id or "").strip()
        normalized_operation_type = str(operation_type or "").strip() or "unknown"
        if not normalized_task_id:
            return False
        handle = self._workers.get(normalized_task_id)
        if handle is None:
            return False
        handle.control_wakeup_requested = True
        handle.control_wakeup_reason = normalized_operation_type
        handle.pending_operation_id = str(operation_id or "").strip() or None
        handle.pending_operation_type = normalized_operation_type
        handle.last_wakeup_at = _now()
        handle.owner_active = True
        handle.release_requested = False
        return True

    async def _restart_local_runtime_for_active_owner(self, task_id: str) -> bool:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return False
        async with self._worker_lock:
            existing = self._workers.get(normalized_task_id)
            if existing is not None and not existing.done() and not existing.cancel_requested:
                return False
            runner_task = asyncio.create_task(
                self._run_task(normalized_task_id),
                name=f"binary-security-{normalized_task_id}-restart",
            )
            heartbeat_task = asyncio.create_task(
                self._run_task_heartbeat(normalized_task_id),
                name=f"binary-security-heartbeat-{normalized_task_id}-restart",
            )
            sync_maintenance_task = asyncio.create_task(
                self._run_task_sync_maintenance(normalized_task_id),
                name=f"binary-security-sync-maintenance-{normalized_task_id}-restart",
            )
            generation = int(getattr(existing, "runner_generation", 0) or 0) + 1
            handle = TaskRuntimeHandle(
                task_id=normalized_task_id,
                runner_task=runner_task,
                heartbeat_task=heartbeat_task,
                claimed_at=_now(),
                execution_token=getattr(existing, "execution_token", None),
                lease_owner_instance_id=str(self.instance_id or "").strip() or None,
                sync_maintenance_task=sync_maintenance_task,
                cancel_requested=False,
                owner_active=True,
                release_requested=False,
                release_reason=None,
                last_runner_exit_at=getattr(existing, "last_runner_exit_at", None),
                last_lease_refresh_at=getattr(existing, "last_lease_refresh_at", None),
                takeover_observed=False,
                control_wakeup_requested=bool(getattr(existing, "control_wakeup_requested", False)),
                control_wakeup_reason=getattr(existing, "control_wakeup_reason", None),
                pending_operation_id=getattr(existing, "pending_operation_id", None),
                pending_operation_type=getattr(existing, "pending_operation_type", None),
                runner_generation=generation,
                last_wakeup_at=getattr(existing, "last_wakeup_at", None),
                sync_maintenance_in_progress=bool(getattr(existing, "sync_maintenance_in_progress", False)),
            )
            self._workers[normalized_task_id] = handle
            return True

    def _task_should_remain_owned_without_active_runner(
        self,
        db: Session,
        task: BinarySecurityTask | None,
        handle: TaskRuntimeHandle | None,
    ) -> bool:
        if task is None or handle is None:
            return False
        if str(getattr(task, "status", "") or "").strip().lower() in TASK_TERMINAL_STATUSES:
            return False
        if not bool(handle.owner_active) or bool(handle.release_requested) or bool(handle.takeover_observed):
            return False
        return self._task_runtime_owner_matches_current_instance(db, task)

    def _should_continue_parent_lease_heartbeat(
        self,
        db: Session,
        task: BinarySecurityTask | None,
        handle: TaskRuntimeHandle | None,
    ) -> bool:
        if task is None or handle is None:
            return False
        if str(getattr(task, "status", "") or "").strip().lower() in TASK_TERMINAL_STATUSES:
            return False
        if bool(handle.release_requested) or not bool(handle.owner_active) or bool(handle.takeover_observed):
            return False
        return self._task_runtime_owner_matches_current_instance(db, task)

    def _can_stop_parent_lease_heartbeat(
        self,
        db: Session,
        task: BinarySecurityTask | None,
        handle: TaskRuntimeHandle | None,
    ) -> bool:
        if handle is None:
            return True
        if bool(handle.takeover_observed):
            return True
        if task is None:
            return True
        if str(getattr(task, "status", "") or "").strip().lower() in TASK_TERMINAL_STATUSES:
            return True
        if bool(handle.release_requested):
            return True
        return not self._should_continue_parent_lease_heartbeat(db, task, handle)

    async def _start_task_runtime(self, task_id: str) -> bool:
        from app.service import task_manager as task_manager_module

        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return False
        async with self._worker_lock:
            existing = self._workers.get(normalized_task_id)
            if existing is not None and not existing.done():
                task_manager_module.logger.warning(
                    "binary-security start_task_runtime skipped because local handle is still active: "
                    "task_id=%s handle_done=%s cancel_requested=%s heartbeat_done=%s sync_maintenance_done=%s execution_token=%s lease_owner_instance_id=%s",
                    normalized_task_id,
                    existing.done(),
                    existing.cancel_requested,
                    existing.heartbeat_task.done() if existing.heartbeat_task is not None else None,
                    existing.sync_maintenance_task.done() if existing.sync_maintenance_task is not None else None,
                    existing.execution_token,
                    existing.lease_owner_instance_id,
                )
                return False
            runner_task = asyncio.create_task(
                self._run_task(normalized_task_id),
                name=f"binary-security-{normalized_task_id}",
            )
            heartbeat_task = asyncio.create_task(
                self._run_task_heartbeat(normalized_task_id),
                name=f"binary-security-heartbeat-{normalized_task_id}",
            )
            sync_maintenance_task = asyncio.create_task(
                self._run_task_sync_maintenance(normalized_task_id),
                name=f"binary-security-sync-maintenance-{normalized_task_id}",
            )
            handle = TaskRuntimeHandle(
                task_id=normalized_task_id,
                runner_task=runner_task,
                heartbeat_task=heartbeat_task,
                claimed_at=_now(),
                execution_token=None,
                lease_owner_instance_id=str(self.instance_id or "").strip() or None,
                sync_maintenance_task=sync_maintenance_task,
            )
            self._workers[normalized_task_id] = handle
            task_manager_module.logger.info(
                "binary-security start_task_runtime created new local handle: task_id=%s runner_task=%s heartbeat_task=%s sync_maintenance_task=%s lease_owner_instance_id=%s",
                normalized_task_id,
                runner_task.get_name(),
                heartbeat_task.get_name(),
                sync_maintenance_task.get_name(),
                handle.lease_owner_instance_id,
            )
            return True

    async def _run_task_heartbeat(self, task_id: str) -> None:
        interval_seconds = max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15))
        failure_count = 0
        while self._running:
            handle = self._runtime_handle(task_id)
            if handle is None or handle.cancel_requested or handle.runner_task.done():
                return
            try:
                if await self._handoff_active_serial_control_operation_from_runtime(task_id):
                    return
                ownership_decision = await asyncio.to_thread(
                    self._verify_local_runtime_lease_or_abort,
                    task_id,
                    "heartbeat_verify",
                )
                if self._should_abort_local_runtime_after_lease_loss(ownership_decision):
                    return
                self._mark_runtime_handle_lease_verify(task_id)
                handle.last_progress_at = _now()
                failure_count = 0
            except asyncio.CancelledError:
                raise
            except Exception:
                failure_count += 1
                logger.exception("binary-security per-task heartbeat failed: task_id=%s failures=%s", task_id, failure_count)
                if failure_count >= 3:
                    handle.cancel_requested = True
                    if not handle.runner_task.done():
                        handle.runner_task.cancel()
                    return
            await asyncio.sleep(interval_seconds)

    async def _run_task_sync_maintenance(self, task_id: str) -> None:
        interval_seconds = max(
            1,
            int(max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15)) // 2),
        )
        logger.info("binary-security sync maintenance worker started: task_id=%s", task_id)
        try:
            while self._running:
                handle = self._runtime_handle(task_id)
                if (
                    handle is None
                    or handle.cancel_requested
                    or handle.runner_task.done()
                    or handle.release_requested
                    or handle.takeover_observed
                ):
                    return
                if not handle.active_commit_succeeded or not handle.lease_established:
                    await asyncio.sleep(interval_seconds)
                    continue
                ownership_decision = await asyncio.to_thread(
                    self._verify_local_runtime_lease_or_abort,
                    task_id,
                    "sync_maintenance_loop",
                )
                if self._should_abort_local_runtime_after_lease_loss(ownership_decision):
                    return
                try:
                    processed = await self._service_local_runtime_sync_maintenance(task_id)
                    if processed:
                        self._mark_runtime_handle_sync_progress(task_id)
                except asyncio.CancelledError:
                    raise
                except StaleTaskExecution:
                    return
                except Exception:
                    logger.exception(
                        "binary-security local runtime sync maintenance worker failed: task_id=%s",
                        task_id,
                    )
                    await asyncio.sleep(2)
                    continue
                await asyncio.sleep(interval_seconds)
        finally:
            handle = self._runtime_handle(task_id)
            logger.info(
                "binary-security sync maintenance worker exiting: task_id=%s cancel_requested=%s runner_done=%s heartbeat_done=%s source=sync_maintenance_loop",
                task_id,
                bool(getattr(handle, "cancel_requested", False)) if handle is not None else None,
                bool(handle.runner_task.done()) if handle is not None else None,
                bool(handle.heartbeat_task.done()) if handle is not None and handle.heartbeat_task is not None else None,
            )

    def _verify_local_runtime_lease_or_abort(
        self,
        task_id: str,
        source: str,
    ) -> _RuntimeLeaseOwnershipDecision:
        normalized_task_id = str(task_id or "").strip()
        session = get_session_factory()()
        try:
            decision = self._assert_active_runtime_lease_owner(
                session,
                normalized_task_id,
                expected_owner=str(self.instance_id or "").strip() or None,
                allow_retryable_read_error=True,
            )
        finally:
            session.close()
        if not self._should_abort_local_runtime_after_lease_loss(decision):
            self._mark_runtime_handle_lease_verify(normalized_task_id)
            return decision
        self._request_runtime_handle_abort(
            normalized_task_id,
            reason=decision.abort_reason,
        )
        handle = self._runtime_handle(normalized_task_id)
        event_type = (
            "runtime_lease_verification_failed_local_execution_aborted"
            if decision.abort_reason == "runtime_lease_verification_failed"
            else "runtime_lease_lost_local_execution_aborted"
        )
        message = (
            "父任务 runtime lease 校验失败，当前 Pod 已停止该任务本地执行"
            if decision.abort_reason == "runtime_lease_verification_failed"
            else "父任务 runtime lease 已丢失，当前 Pod 已停止该任务本地执行"
        )
        db = get_session_factory()()
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == normalized_task_id).first()
            if task is not None:
                self._record_event(
                    db,
                    task,
                    event_type,
                    message,
                    level="warning",
                    stage_name=str(getattr(task, "current_stage", "") or "").strip() or None,
                    payload={
                        "task_id": normalized_task_id,
                        "expected_owner": str(self.instance_id or "").strip() or None,
                        "runtime_lease_owner": decision.runtime_lease_owner,
                        "runtime_lease_expires_at": _isoformat_or_none(decision.runtime_lease_expires_at),
                        "local_handle_alive": decision.local_handle_alive,
                        "abort_reason": decision.abort_reason,
                        "verification_error": decision.verification_error,
                        "source": str(source or "").strip() or None,
                        "runner_done": None if handle is None else bool(handle.runner_task.done()),
                        "heartbeat_done": None if handle is None or getattr(handle, "heartbeat_task", None) is None else bool(handle.heartbeat_task.done()),
                        "sync_maintenance_done": None if handle is None or getattr(handle, "sync_maintenance_task", None) is None else bool(handle.sync_maintenance_task.done()),
                        "watchdog_thread_alive": self._lease_watchdog_alive(),
                    },
                )
                db.commit()
        finally:
            db.close()
        return decision

    async def _abort_local_runtime_if_lease_lost(
        self,
        task_id: str,
        source: str,
    ) -> bool:
        decision = await asyncio.to_thread(
            self._verify_local_runtime_lease_or_abort,
            task_id,
            source,
        )
        return self._should_abort_local_runtime_after_lease_loss(decision)

    async def _service_local_runtime_sync_maintenance(self, task_id: str) -> bool:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return False
        lease_decision = await asyncio.to_thread(
            self._verify_local_runtime_lease_or_abort,
            normalized_task_id,
            "runtime_sync_maintenance",
        )
        if self._should_abort_local_runtime_after_lease_loss(lease_decision):
            raise StaleTaskExecution(
                f"任务 {normalized_task_id} runtime lease 已失效，停止本地 runtime sync maintenance"
            )
        handle = self._runtime_handle(normalized_task_id)
        if (
            handle is None
            or handle.done()
            or handle.cancel_requested
            or not handle.active_commit_succeeded
            or not handle.lease_established
            or handle.sync_maintenance_in_progress
        ):
            return False
        consume_reason: str | None = None
        due_sync_request = False
        owner_signal_payload = await get_task_queue().consume_owner_signal(
            str(self.instance_id or "").strip() or None,
            normalized_task_id,
            context="owner_signal_consume",
        )
        if owner_signal_payload:
            consume_reason = str(owner_signal_payload.get("context") or "owner_signal").strip() or "owner_signal"
        due_sync_request = await get_task_queue().has_due_task_sync_request(
            normalized_task_id,
            context="task_sync_due_check",
        )
        if not consume_reason and not due_sync_request:
            return False
        handle.sync_maintenance_in_progress = True
        try:
            processed = await self._drain_local_runtime_sync_queue_once(
                normalized_task_id,
                reason=consume_reason or "due_task_sync_request",
                max_passes=5,
            )
            if processed:
                logger.info(
                    "binary-security local runtime sync maintenance processed queued sync requests: task_id=%s reason=%s",
                    normalized_task_id,
                    consume_reason or "due_task_sync_request",
                )
            return processed
        finally:
            handle.sync_maintenance_in_progress = False

    async def _drain_local_runtime_sync_queue_once(
        self,
        task_id: str,
        *,
        reason: str,
        max_passes: int = 5,
    ) -> bool:
        session = get_session_factory()()
        processed = False
        try:
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is None:
                return False
            lease = self._runtime_lease_for_task(session, task_id)
            if not (
                self._runtime_lease_is_active(lease)
                and str(getattr(lease, "owner_instance_id", "") or "").strip() == str(self.instance_id or "").strip()
            ):
                return False
            passes = 0
            while passes < max(1, int(max_passes or 1)):
                drained = await self._drain_task_sync_queue(session, task)
                if not drained:
                    break
                processed = True
                passes += 1
                session.expire_all()
                task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
                if task is None:
                    break
            if processed:
                logger.info(
                    "binary-security local runtime sync maintenance drained task sync queue: task_id=%s reason=%s passes=%s",
                    task_id,
                    reason,
                    passes,
                )
            return processed
        finally:
            session.close()

    async def _handoff_active_serial_control_operation_from_runtime(self, task_id: str) -> bool:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return False
        handle = self._runtime_handle(normalized_task_id)
        if (
            handle is None
            or handle.done()
            or handle.cancel_requested
            or not handle.active_commit_succeeded
            or not handle.lease_established
        ):
            return False
        session = get_session_factory()()
        try:
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == normalized_task_id).first()
            if task is None:
                return False
            lease = self._runtime_lease_for_task(session, normalized_task_id)
            if not (
                self._runtime_lease_is_active(lease)
                and str(getattr(lease, "owner_instance_id", "") or "").strip() == str(self.instance_id or "").strip()
            ):
                return False
            operation = self._task_active_operation(session, task)
            if operation is None:
                return False
            operation_status = str(getattr(operation, "status", "") or "").strip().lower()
            operation_type = str(getattr(operation, "operation_type", "") or "").strip()
            if operation_status not in TASK_OPERATION_ACTIVE_STATUSES:
                return False
            if operation_type not in TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES:
                return False
            if not self._operation_blocks_runtime_resume(operation):
                return False
            if self._local_operation_worker_alive(getattr(operation, "id", None)):
                return False
            self._record_event(
                session,
                task,
                "runtime_yielded_for_serial_control_operation",
                "检测到串行控制操作已入队，当前 owner business runtime 已让位给 owner inbox",
                level="info",
                stage_name=str(getattr(operation, "target_stage", "") or getattr(task, "current_stage", "") or "").strip() or None,
                payload={
                    "operation_id": str(getattr(operation, "id", "") or "").strip() or None,
                    "operation_type": operation_type or None,
                    "operation_status": operation_status or None,
                    "runtime_lease_owner": str(getattr(lease, "owner_instance_id", "") or "").strip() or None,
                },
            )
            session.commit()
        finally:
            session.close()
        await self._request_local_worker_cancel(normalized_task_id, wait_for_runner=False)
        self._enqueue_task(normalized_task_id)
        return True

    def _collect_heartbeat_candidates(self) -> list[str]:
        with self._task_execution_owner_lock:
            return sorted(task_id for task_id, owners in self._task_execution_owners.items() if owners)

    def _task_delete_snapshot(self, task: BinarySecurityTask) -> dict[str, Any]:
        snapshot = dict(getattr(task, "cleanup_snapshot", None) or {})
        return snapshot if isinstance(snapshot, dict) else {}

    def _is_task_delete_in_progress(self, task: BinarySecurityTask | None) -> bool:
        if task is None:
            return False
        snapshot = self._task_delete_snapshot(task)
        return bool(snapshot.get("delete_in_progress"))

    def _mark_task_delete_in_progress(
        self,
        task: BinarySecurityTask,
        *,
        operation_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        snapshot = self._task_delete_snapshot(task)
        snapshot["delete_in_progress"] = True
        snapshot["delete_started_at"] = _now().isoformat()
        if operation_id:
            snapshot["delete_operation_id"] = str(operation_id).strip() or None
        if reason:
            snapshot["delete_reason"] = str(reason).strip() or None
        task.cleanup_snapshot = snapshot

    def _clear_task_delete_in_progress(self, task: BinarySecurityTask) -> None:
        snapshot = self._task_delete_snapshot(task)
        if not snapshot:
            return
        if "delete_in_progress" in snapshot:
            snapshot["delete_in_progress"] = False
        task.cleanup_snapshot = snapshot

    def _guard_task_workspace_write(
        self,
        task: BinarySecurityTask | None,
        *,
        purpose: str,
        path: Path | None = None,
    ) -> bool:
        if task is None:
            return True
        delete_in_progress = self._is_task_delete_in_progress(task)
        if (
            not delete_in_progress
            and os.getenv("BINARY_SECURITY_DISABLE_WORKSPACE_DELETE_GUARD_DB_LOOKUP") == "1"
        ):
            return True
        if not delete_in_progress:
            task_id = str(getattr(task, "id", "") or "").strip()
            project_id = str(getattr(task, "project_id", "") or "").strip()
            if task_id and project_id:
                session = None
                try:
                    session = get_session_factory()()
                    current_task = (
                        session.query(BinarySecurityTask)
                        .filter(
                            BinarySecurityTask.id == task_id,
                            BinarySecurityTask.project_id == project_id,
                        )
                        .first()
                    )
                    if current_task is not None:
                        cleanup_snapshot = getattr(current_task, "cleanup_snapshot", None)
                        if isinstance(cleanup_snapshot, dict) and bool(cleanup_snapshot.get("delete_in_progress")):
                            delete_in_progress = True
                except Exception as exc:
                    logger.warning(
                        "binary-security workspace delete guard lookup failed: task_id=%s project_id=%s purpose=%s error=%s",
                        task_id,
                        project_id,
                        str(purpose or "").strip() or "unknown",
                        str(exc),
                    )
                finally:
                    if session is not None:
                        session.close()
        if not delete_in_progress:
            return True
        logger.info(
            "binary-security workspace write skipped during delete: task_id=%s purpose=%s path=%s",
            str(getattr(task, "id", "") or "").strip() or None,
            str(purpose or "").strip() or "unknown",
            str(path) if path is not None else None,
        )
        return False

    def _has_active_task_workspace_writers(self, db: Session, task: BinarySecurityTask) -> bool:
        task_id = str(getattr(task, "id", "") or "").strip()
        if not task_id:
            return False
        runtime_lease = (
            db.query(BinarySecurityTaskRuntimeLease)
            .filter(BinarySecurityTaskRuntimeLease.task_id == task_id)
            .first()
        )
        return bool(self._runtime_lease_is_active(runtime_lease))

    async def _wait_for_task_workspace_quiesce(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        timeout_seconds: int = 15,
        poll_interval_seconds: float = 1.0,
    ) -> bool:
        deadline = time.monotonic() + max(1, int(timeout_seconds))
        while time.monotonic() < deadline:
            db.expire_all()
            refreshed = (
                db.query(BinarySecurityTask)
                .filter(BinarySecurityTask.id == task.id, BinarySecurityTask.project_id == task.project_id)
                .first()
            )
            if refreshed is None:
                return True
            task.cleanup_snapshot = refreshed.cleanup_snapshot
            if not self._has_active_task_workspace_writers(db, refreshed):
                return True
            await asyncio.sleep(max(0.1, poll_interval_seconds))
        return False

    def _release_task_delete_runtime_state(self, db: Session, task: BinarySecurityTask) -> None:
        from app.model import BinarySecurityTaskStateLease

        task_id = str(getattr(task, "id", "") or "").strip()
        if not task_id:
            return
        self._invalidate_task_execution(task, force=True)
        task.operation_lock_owner = None
        task.operation_lock_token = None
        task.operation_lock_type = None
        task.operation_lock_acquired_at = None
        task.operation_lock_heartbeat_at = None
        task.operation_lock_expires_at = None
        db.query(BinarySecurityTaskRuntimeLease).filter(
            BinarySecurityTaskRuntimeLease.task_id == task_id
        ).delete(synchronize_session=False)
        db.query(BinarySecurityTaskStateLease).filter(
            BinarySecurityTaskStateLease.task_id == task_id
        ).delete(synchronize_session=False)
        with self._task_execution_owner_lock:
            self._task_execution_owners.pop(task_id, None)

    def _orphan_workspace_scan_roots(self) -> list[Path]:
        base = Path(self.cfg.storage.project_root_template.format(project_id="__placeholder__"))
        files_root = base.parent if base.name == "__placeholder__" else base
        app_root_name = str(getattr(self.cfg.storage, "app_root_name", "app/secflow-app-binary-security") or "").strip().strip("/")
        if not app_root_name:
            return []
        if not files_root.exists():
            return []
        roots: list[Path] = []
        for project_root in files_root.iterdir():
            if not project_root.is_dir():
                continue
            roots.append(project_root / app_root_name)
        return roots

    def _reconcile_orphan_task_workspaces_once(self, db: Session) -> int:
        repaired = 0
        now_value = _now()
        for app_root in self._orphan_workspace_scan_roots():
            if not app_root.is_dir():
                continue
            for task_root in app_root.iterdir():
                if not task_root.is_dir():
                    continue
                task_id = str(task_root.name or "").strip()
                if not task_id:
                    continue
                try:
                    validate_task_id(task_id)
                except Exception:
                    continue
                if (now_value - datetime.fromtimestamp(task_root.stat().st_mtime)).total_seconds() < 60:
                    continue
                existing = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
                if existing is not None:
                    continue
                try:
                    shutil.rmtree(task_root, ignore_errors=True)
                    logger.info(
                        "binary-security orphan workspace deleted: task_id=%s workspace_root=%s",
                        task_id,
                        str(task_root),
                    )
                    repaired += 1
                except Exception:
                    logger.exception(
                        "binary-security orphan workspace delete failed: task_id=%s workspace_root=%s",
                        task_id,
                        str(task_root),
                    )
        return repaired

    def _write_task_metadata(
        self,
        task: BinarySecurityTask,
        path: Path,
        *,
        status: str | None = None,
    ) -> None:
        payload = dict(task.summary or {})
        payload.update(
            {
                "task_id": str(task.id or ""),
                "project_id": str(task.project_id or ""),
                "task_name": str(task.name or ""),
                "task_type": self._task_type(task),
                "status": str(status or task.status or "").strip() or None,
                "current_stage": str(task.current_stage or "").strip() or None,
                "workspace_root": str(task.workspace_root or "").strip() or None,
                "output_root": str(task.output_root or "").strip() or None,
            }
        )
        if not self._guard_task_workspace_write(task, purpose="task_metadata", path=path):
            return
        _write_json(path, payload)

    async def _write_task_metadata_async(
        self,
        task: BinarySecurityTask,
        path: Path,
        *,
        status: str | None = None,
    ) -> None:
        await asyncio.to_thread(self._write_task_metadata, task, path, status=status)

    async def _enqueue_task_and_wait(
        self,
        task_id: str,
        *,
        context: str = "task_enqueue",
        timeout_seconds: int = 10,
        force_requeue: bool = False,
    ) -> bool:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return False

        async def _push() -> None:
            queue = get_task_queue()
            if force_requeue:
                await queue.force_requeue_task(normalized_task_id, context=context)
            else:
                await queue.push_task(normalized_task_id, context=context)

        try:
            await asyncio.wait_for(_push(), timeout=max(1, int(timeout_seconds or 10)))
        except Exception:
            logger.warning(
                "binary-security enqueue task synchronously failed: task_id=%s context=%s force_requeue=%s timeout_seconds=%s",
                normalized_task_id,
                context,
                force_requeue,
                timeout_seconds,
                exc_info=True,
            )
            return False
        logger.info(
            "binary-security enqueue task synchronously succeeded: task_id=%s context=%s force_requeue=%s timeout_seconds=%s",
            normalized_task_id,
            context,
            force_requeue,
            timeout_seconds,
        )
        return True

    def _enqueue_task_and_wait_sync(
        self,
        task_id: str,
        *,
        context: str = "task_enqueue",
        timeout_seconds: int = 10,
        force_requeue: bool = False,
    ) -> bool:
        return asyncio.run(
            self._enqueue_task_and_wait(
                task_id,
                context=context,
                timeout_seconds=timeout_seconds,
                force_requeue=force_requeue,
            )
        )

    def _enqueue_task(self, task_id: str) -> None:
        self._enqueue_task_with_context(task_id, context="task_enqueue")

    def _force_requeue_task_sync(self, task_id: str, *, context: str) -> bool:
        normalized_task_id = str(task_id or "").strip()
        normalized_context = str(context or "").strip() or "task_enqueue"
        if not normalized_task_id:
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return self._enqueue_task_and_wait_sync(
                normalized_task_id,
                context=normalized_context,
                timeout_seconds=self._initial_enqueue_wait_timeout_seconds(),
                force_requeue=True,
            )
        loop.create_task(
            get_task_queue().force_requeue_task(
                normalized_task_id,
                context=normalized_context,
            )
        )
        return True

    def _enqueue_task_with_context(self, task_id: str, *, context: str = "task_enqueue") -> None:
        normalized_task_id = str(task_id or "").strip()
        normalized_context = str(context or "").strip() or "task_enqueue"
        if not normalized_task_id:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.info(
                "binary-security enqueue without running loop started: task_id=%s context=%s",
                normalized_task_id,
                normalized_context,
            )
            try:
                asyncio.run(get_task_queue().push_task(normalized_task_id, context=normalized_context))
            except Exception:
                logger.warning(
                    "binary-security enqueue without running loop failed: task_id=%s context=%s",
                    normalized_task_id,
                    normalized_context,
                    exc_info=True,
                )
            return
        async def _push() -> None:
            try:
                await get_task_queue().push_task(normalized_task_id, context=normalized_context)
            except Exception:
                logger.warning(
                    "failed to enqueue task",
                    extra={"task_id": normalized_task_id, "context": normalized_context},
                    exc_info=True,
                )

        loop.create_task(_push())

    def _enqueue_owner_signal(self, owner_instance_id: str, task_id: str, *, context: str = "owner_signal_enqueue") -> None:
        normalized_owner = str(owner_instance_id or "").strip()
        normalized_task_id = str(task_id or "").strip()
        if not normalized_owner or not normalized_task_id:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.info(
                "binary-security owner signal enqueue without running loop started: owner_instance_id=%s task_id=%s context=%s",
                normalized_owner,
                normalized_task_id,
                context,
            )
            try:
                asyncio.run(
                    get_task_queue().push_owner_signal(
                        normalized_owner,
                        normalized_task_id,
                        context=context,
                    )
                )
            except Exception:
                logger.warning(
                    "binary-security owner signal enqueue without running loop failed: owner_instance_id=%s task_id=%s context=%s",
                    normalized_owner,
                    normalized_task_id,
                    context,
                    exc_info=True,
                )
            return

        async def _push() -> None:
            try:
                await get_task_queue().push_owner_signal(
                    normalized_owner,
                    normalized_task_id,
                    context=context,
                )
            except Exception:
                logger.warning(
                    "failed to enqueue owner signal",
                    extra={
                        "owner_instance_id": normalized_owner,
                        "task_id": normalized_task_id,
                        "context": context,
                    },
                    exc_info=True,
                )

        loop.create_task(_push())

    def _pending_shared_dispatch_signal(self, task: BinarySecurityTask) -> dict[str, Any]:
        summary = dict(getattr(task, "summary", None) or {})
        signal = summary.get("pending_shared_dispatch_signal")
        return dict(signal) if isinstance(signal, dict) else {}

    def _remember_shared_dispatch_signal(
        self,
        task: BinarySecurityTask,
        *,
        signal_type: str,
        enqueue_context: str,
        source: str,
        reason: str,
        stage_name: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        current = self._pending_shared_dispatch_signal(task)
        now_value = _now().isoformat()
        merged = {
            **current,
            **dict(extra or {}),
            "signal_type": str(signal_type or "").strip() or current.get("signal_type") or "generic_task_enqueue",
            "enqueue_context": str(enqueue_context or "").strip() or current.get("enqueue_context") or "task_enqueue",
            "source": str(source or "").strip() or current.get("source") or "unknown",
            "reason": str(reason or "").strip() or current.get("reason") or "shared_dispatch_signal",
            "stage_name": str(stage_name or "").strip() or current.get("stage_name") or None,
            "requested_by_instance_id": str(self.instance_id or "").strip() or current.get("requested_by_instance_id") or None,
            "first_requested_at": current.get("first_requested_at") or now_value,
            "last_requested_at": now_value,
            "enqueue_count": int(current.get("enqueue_count") or 0) + 1,
        }
        summary = dict(getattr(task, "summary", None) or {})
        summary["pending_shared_dispatch_signal"] = merged
        task.summary = summary
        return merged

    def _clear_pending_shared_dispatch_signal(self, task: BinarySecurityTask) -> None:
        summary = dict(getattr(task, "summary", None) or {})
        if "pending_shared_dispatch_signal" not in summary:
            return
        summary.pop("pending_shared_dispatch_signal", None)
        task.summary = summary

    def _initial_enqueue_wait_timeout_seconds(self) -> int:
        configured = getattr(self.cfg.queue, "initial_enqueue_wait_timeout_seconds", None)
        try:
            return max(1, int(configured or 10))
        except (TypeError, ValueError):
            return 10

    def _orphan_parent_reconcile_stale_seconds(self) -> int:
        configured = getattr(self.cfg.scheduler, "orphan_parent_reconcile_stale_seconds", None)
        try:
            return max(30, int(configured or 300))
        except (TypeError, ValueError):
            return 300

    def _orphan_parent_reconcile_batch_size(self) -> int:
        configured = getattr(self.cfg.scheduler, "orphan_parent_reconcile_batch_size", None)
        try:
            return max(1, int(configured or 20))
        except (TypeError, ValueError):
            return 20

    def _task_has_manual_or_retry_operation(self, db: Session, task: BinarySecurityTask) -> bool:
        from app.service import task_manager as task_manager_module

        operations = (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(task_manager_module.BinarySecurityTaskOperation.task_id == task.id)
            .all()
        )
        return any(
            str(getattr(operation, "status", "") or "").strip() in task_manager_module.TASK_OPERATION_ACTIVE_STATUSES
            for operation in operations
        )

    def _peek_orphan_parent_task_missing_initial_enqueue(
        self,
        db: Session,
        *,
        stale_after_seconds: int = 300,
    ) -> BinarySecurityTask | None:
        from app.service import task_manager as task_manager_module

        cutoff = _now() - timedelta(seconds=max(1, int(stale_after_seconds or self._orphan_parent_reconcile_stale_seconds())))
        rows = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(
                task_manager_module.BinarySecurityTask.status == "pending",
                task_manager_module.BinarySecurityTask.runtime_phase == TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                task_manager_module.BinarySecurityTask.current_stage.isnot(None),
                task_manager_module.BinarySecurityTask.updated_at <= cutoff,
            )
            .order_by(
                task_manager_module.BinarySecurityTask.updated_at.asc(),
                task_manager_module.BinarySecurityTask.created_at.asc(),
            )
            .all()
        )
        for task in rows:
            if str(getattr(task, "status", "") or "").strip() != "pending":
                continue
            if self._task_runtime_phase(task) != TASK_RUNTIME_PHASE_OWNED_EXECUTION:
                continue
            if not str(getattr(task, "current_stage", "") or "").strip():
                continue
            if getattr(task, "updated_at", None) is None or getattr(task, "updated_at", None) > cutoff:
                continue
            if (
                db.query(task_manager_module.BinarySecurityStageRun)
                .filter(task_manager_module.BinarySecurityStageRun.task_id == task.id)
                .first()
                is not None
            ):
                continue
            if (
                db.query(task_manager_module.BinarySecurityStageItem)
                .filter(task_manager_module.BinarySecurityStageItem.task_id == task.id)
                .first()
                is not None
            ):
                continue
            if self._runtime_lease_for_task(db, task.id) is not None:
                continue
            state_lease = (
                db.query(BinarySecurityTaskStateLease)
                .filter(BinarySecurityTaskStateLease.task_id == task.id)
                .first()
            )
            if state_lease is not None:
                continue
            state_event = (
                db.query(BinarySecurityStateEvent)
                .filter(BinarySecurityStateEvent.task_id == task.id)
                .first()
            )
            if state_event is not None:
                continue
            if self._task_has_manual_or_retry_operation(db, task):
                continue
            return task
        return None

    async def _reconcile_orphan_parent_task_missing_initial_enqueue(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        actor: str,
        stale_after_seconds: int = 300,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        latest = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(task_manager_module.BinarySecurityTask.id == task.id)
            .first()
        )
        if latest is None:
            return False
        candidate = self._peek_orphan_parent_task_missing_initial_enqueue(
            db,
            stale_after_seconds=stale_after_seconds,
        )
        if candidate is None or str(getattr(candidate, "id", "") or "").strip() != str(getattr(latest, "id", "") or "").strip():
            return False
        now_value = _now()
        stuck_seconds = max(0, int((now_value - (latest.updated_at or now_value)).total_seconds()))
        requeued = await self._enqueue_task_and_wait(
            latest.id,
            context="orphan_parent_initial_enqueue_reconcile",
            timeout_seconds=self._initial_enqueue_wait_timeout_seconds(),
            force_requeue=True,
        )
        if not requeued:
            logger.warning(
                "binary-security orphan parent task initial enqueue reconcile failed: task_id=%s actor=%s stale_after_seconds=%s",
                latest.id,
                actor,
                stale_after_seconds,
            )
            return False
        latest.updated_at = now_value
        self._record_event(
            db,
            latest,
            "task_initial_dispatch_reconciled",
            "检测到孤儿父任务首次入队丢失，已重新加入调度队列",
            level="warning",
            stage_name=latest.current_stage,
            payload={
                "reason": "initial_enqueue_missing_after_task_creation",
                "stale_after_seconds": max(1, int(stale_after_seconds or self._orphan_parent_reconcile_stale_seconds())),
                "current_stage": str(getattr(latest, "current_stage", "") or "").strip() or None,
                "runtime_phase": self._task_runtime_phase(latest),
                "has_stage_run": False,
                "has_stage_item": False,
                "has_runtime_lease": False,
                "has_state_lease": False,
                "has_state_event": False,
                "redis_requeue": True,
                "stuck_seconds": stuck_seconds,
                "actor": actor,
            },
        )
        db.commit()
        logger.info(
            "binary-security orphan parent task initial enqueue reconciled: task_id=%s actor=%s stuck_seconds=%s",
            latest.id,
            actor,
            stuck_seconds,
        )
        return True

    async def reconcile_orphan_parent_tasks_missing_initial_enqueue(
        self,
        db: Session,
        *,
        batch_size: int,
        actor: str,
        stale_after_seconds: int = 300,
    ) -> int:
        repaired = 0
        limit = max(1, int(batch_size or 1))
        for _ in range(limit):
            candidate = self._peek_orphan_parent_task_missing_initial_enqueue(
                db,
                stale_after_seconds=stale_after_seconds,
            )
            if candidate is None:
                break
            if not await self._reconcile_orphan_parent_task_missing_initial_enqueue(
                db,
                candidate,
                actor=actor,
                stale_after_seconds=stale_after_seconds,
            ):
                break
            repaired += 1
        return repaired

    def _peek_released_parent_task_missing_takeover_enqueue(
        self,
        db: Session,
        *,
        stale_after_seconds: int = 30,
    ) -> BinarySecurityTask | None:
        cutoff = _now() - timedelta(seconds=max(1, int(stale_after_seconds or 30)))
        rows = (
            db.query(BinarySecurityTask)
            .filter(
                BinarySecurityTask.status == "pending",
                BinarySecurityTask.runtime_phase == TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                BinarySecurityTask.current_stage.isnot(None),
                BinarySecurityTask.updated_at <= cutoff,
            )
            .order_by(BinarySecurityTask.updated_at.asc(), BinarySecurityTask.created_at.asc())
            .all()
        )
        for task in rows:
            if self._runtime_lease_is_active(self._runtime_lease_for_task(db, task.id)):
                continue
            if self._task_has_manual_or_retry_operation(db, task):
                continue
            if self._active_delete_queue_operation(db, task) is not None:
                continue
            reconcile_snapshot = dict(getattr(task, "summary", None) or {}).get("released_takeover_reconcile")
            if isinstance(reconcile_snapshot, dict):
                last_requeued_at = _parse_iso_datetime(reconcile_snapshot.get("last_requeued_at"))
                if last_requeued_at is not None and last_requeued_at > cutoff:
                    continue
            has_stage_run = (
                db.query(BinarySecurityStageRun)
                .filter(BinarySecurityStageRun.task_id == task.id)
                .first()
                is not None
            )
            has_stage_item = (
                db.query(BinarySecurityStageItem)
                .filter(BinarySecurityStageItem.task_id == task.id)
                .first()
                is not None
            )
            stage_name = str(getattr(task, "current_stage", "") or "").strip()
            has_downstream_ref = bool(stage_name) and any(
                str(getattr(item, "downstream_task_id", "") or "").strip()
                for item in self._stage_items(db, task.id, stage_name)
            )
            if not (has_stage_run or has_stage_item or has_downstream_ref):
                continue
            return task
        return None

    async def _reconcile_released_parent_task_missing_takeover_enqueue(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        actor: str,
        stale_after_seconds: int = 30,
    ) -> bool:
        latest = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task.id).first()
        if latest is None:
            return False
        candidate = self._peek_released_parent_task_missing_takeover_enqueue(
            db,
            stale_after_seconds=stale_after_seconds,
        )
        if candidate is None or str(candidate.id or "").strip() != str(latest.id or "").strip():
            return False
        latest = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task.id).first()
        if latest is None:
            return False
        if str(getattr(latest, "status", "") or "").strip().lower() != "pending":
            return False
        active_runtime_lease = self._runtime_lease_for_task(db, latest.id)
        if self._runtime_lease_is_active(active_runtime_lease):
            return False
        requeued = await self._enqueue_task_and_wait(
            latest.id,
            context="released_takeover_reconcile",
            timeout_seconds=self._initial_enqueue_wait_timeout_seconds(),
            force_requeue=True,
        )
        if not requeued:
            return False
        latest.updated_at = _now()
        latest.summary = {
            **dict(getattr(latest, "summary", None) or {}),
            "released_takeover_reconcile": {
                "last_requeued_at": _isoformat_or_none(latest.updated_at),
                "actor": actor,
            },
        }
        self._record_event(
            db,
            latest,
            "released_parent_takeover_dispatch_reconciled",
            "检测到已释放父任务未进入共享调度队列，已重新加入调度队列",
            level="warning",
            stage_name=latest.current_stage,
            payload={
                "reason": "released_parent_missing_takeover_enqueue",
                "stale_after_seconds": max(1, int(stale_after_seconds or 30)),
                "runtime_phase": self._task_runtime_phase(latest),
                "current_stage": str(getattr(latest, "current_stage", "") or "").strip() or None,
                "enqueue_context": "released_takeover_reconcile",
                "actor": actor,
            },
        )
        db.commit()
        return True

    async def reconcile_released_parent_tasks_missing_takeover_enqueue(
        self,
        db: Session,
        *,
        batch_size: int,
        actor: str,
        stale_after_seconds: int = 30,
    ) -> int:
        repaired = 0
        limit = max(1, int(batch_size or 1))
        for _ in range(limit):
            candidate = self._peek_released_parent_task_missing_takeover_enqueue(
                db,
                stale_after_seconds=stale_after_seconds,
            )
            if candidate is None:
                break
            if not await self._reconcile_released_parent_task_missing_takeover_enqueue(
                db,
                candidate,
                actor=actor,
                stale_after_seconds=stale_after_seconds,
            ):
                break
            repaired += 1
        return repaired

    async def repair_orphan_parent_tasks_missing_initial_enqueue(
        self,
        *,
        batch_size: int | None = None,
        actor: str = "binary-security-orphan-parent-repair",
        stale_after_seconds: int | None = None,
    ) -> dict[str, int]:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            requeued = await self.reconcile_orphan_parent_tasks_missing_initial_enqueue(
                db,
                batch_size=batch_size or self._orphan_parent_reconcile_batch_size(),
                actor=actor,
                stale_after_seconds=stale_after_seconds or self._orphan_parent_reconcile_stale_seconds(),
            )
            return {
                "requeued": int(requeued),
                "skipped": 0,
                "failed": 0,
            }
        finally:
            with suppress(Exception):
                db.close()

    def _task_lease_ttl_seconds(self) -> int:
        configured = getattr(self.cfg.scheduler, "task_lease_ttl_seconds", None)
        if configured is None:
            return max(120, self._lease_timeout_seconds())
        try:
            return max(30, int(configured))
        except (TypeError, ValueError):
            return max(120, self._lease_timeout_seconds())

    def _task_reclaim_grace_seconds(self) -> int:
        configured = getattr(self.cfg.scheduler, "task_reclaim_grace_seconds", None)
        if configured is None:
            return max(180, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15) * 3)
        try:
            return max(30, int(configured))
        except (TypeError, ValueError):
            return max(180, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15) * 3)

    def _task_lease_write_retry_attempts(self) -> int:
        configured = getattr(self.cfg.scheduler, "task_lease_write_retry_attempts", None)
        try:
            return max(1, int(configured or 3))
        except (TypeError, ValueError):
            return 3

    def _next_runtime_lease_expiry(self, *, now_value: datetime | None = None) -> datetime:
        return (now_value or _now()) + timedelta(seconds=self._task_lease_ttl_seconds())

    def _coordinator_lease_ttl_seconds(self) -> int:
        configured = getattr(self.cfg.scheduler, "coordinator_lease_ttl_seconds", None)
        if configured is None:
            return max(30, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15) * 4)
        try:
            return max(30, int(configured))
        except (TypeError, ValueError):
            return max(30, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15) * 4)

    def _runtime_lease_for_task(self, db: Session, task_id: str) -> BinarySecurityTaskRuntimeLease | None:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return None
        return (
            db.query(BinarySecurityTaskRuntimeLease)
            .filter(BinarySecurityTaskRuntimeLease.task_id == normalized_task_id)
            .first()
        )

    def _clear_runtime_lease(
        self,
        db: Session,
        task_id: str,
        *,
        owner_instance_id: str | None = None,
        swallow_lock_error: bool = False,
    ) -> RuntimeLeaseClearResult:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return RuntimeLeaseClearResult(status="lease_missing", task_id=None)
        query = db.query(BinarySecurityTaskRuntimeLease).filter(
            BinarySecurityTaskRuntimeLease.task_id == normalized_task_id
        )
        normalized_owner = str(owner_instance_id or "").strip()
        if normalized_owner:
            query = query.filter(BinarySecurityTaskRuntimeLease.owner_instance_id == normalized_owner)
        try:
            deleted = int(query.delete(synchronize_session=False) or 0)
        except OperationalError as exc:
            if swallow_lock_error and self._is_retryable_lock_error(exc):
                return RuntimeLeaseClearResult(
                    status="lease_locked_retry_later",
                    deleted_count=0,
                    owner_instance_id=normalized_owner or None,
                    task_id=normalized_task_id,
                    error_message=str(exc),
                )
            raise
        if deleted > 0:
            return RuntimeLeaseClearResult(
                status="lease_cleared",
                deleted_count=deleted,
                owner_instance_id=normalized_owner or None,
                task_id=normalized_task_id,
            )
        return RuntimeLeaseClearResult(
            status="lease_owner_mismatch_skipped" if normalized_owner else "lease_missing",
            deleted_count=0,
            owner_instance_id=normalized_owner or None,
            task_id=normalized_task_id,
        )

    def _upsert_runtime_lease(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        now_value: datetime,
        owner_instance_id: str | None = None,
        owner_pod_uid: str | None = None,
        owner_boot_id: str | None = None,
        generation: int | None = None,
        owner_started_at: datetime | None = None,
    ) -> BinarySecurityTaskRuntimeLease:
        phase = self._task_runtime_phase(task)
        requested_owner = str(owner_instance_id or self.instance_id or "").strip() or self.instance_id
        requested_pod_uid = str(owner_pod_uid or self.owner_pod_uid or "").strip() or self.owner_pod_uid
        requested_boot_id = str(owner_boot_id or self.owner_boot_id or "").strip() or self.owner_boot_id
        requested_generation = int(generation if generation is not None else self._owner_generation or 1)
        requested_started_at = owner_started_at or self.owner_started_at
        if not self._can_own_runtime_phase(phase):
            lease = self._runtime_lease_for_task(db, task.id)
            if lease is None:
                raise StaleTaskExecution(f"任务 {task.id} 当前实例无权持有 {phase or 'unknown'} runtime lease")
            return lease
        lease = self._runtime_lease_for_task(db, task.id)
        if lease is None:
            lease = BinarySecurityTaskRuntimeLease(
                task_id=task.id,
                execution_epoch=int(getattr(task, "execution_epoch", 0) or 0),
                owner_instance_id=requested_owner,
                owner_pod_uid=requested_pod_uid,
                owner_boot_id=requested_boot_id,
                generation=requested_generation,
                owner_started_at=requested_started_at,
                heartbeat_at=now_value,
                last_renewed_at=now_value,
                lease_expires_at=self._next_runtime_lease_expiry(now_value=now_value),
            )
            begin_nested = getattr(db, "begin_nested", None)
            nested = begin_nested() if callable(begin_nested) else None
            db.add(lease)
            try:
                db.flush()
            except IntegrityError:
                if nested is not None:
                    with suppress(Exception):
                        nested.rollback()
                else:
                    db.rollback()
                lease = self._runtime_lease_for_task(db, task.id)
                if lease is None:
                    raise
            else:
                if nested is not None:
                    with suppress(Exception):
                        nested.commit()
        else:
            current_owner = str(lease.owner_instance_id or "").strip() or None
            lease_active = self._runtime_lease_is_active(lease)
            current_generation = int(getattr(lease, "generation", 0) or 0)
            current_pod_uid = str(getattr(lease, "owner_pod_uid", "") or "").strip() or None
            current_boot_id = str(getattr(lease, "owner_boot_id", "") or "").strip() or None
            if lease_active:
                stale_owner = (
                    (current_owner and current_owner != requested_owner)
                    or (current_pod_uid and current_pod_uid != requested_pod_uid)
                    or (current_boot_id and current_boot_id != requested_boot_id)
                    or (current_generation and requested_generation < current_generation)
                )
                if stale_owner:
                    raise StaleTaskExecution(f"任务 {task.id} 当前 {phase or 'unknown'} runtime lease owner 已变更")
            lease.execution_epoch = int(getattr(task, "execution_epoch", 0) or 0)
            lease.owner_instance_id = requested_owner
            lease.owner_pod_uid = requested_pod_uid
            lease.owner_boot_id = requested_boot_id
            lease.generation = max(current_generation, requested_generation)
            lease.owner_started_at = requested_started_at
            lease.heartbeat_at = now_value
            lease.last_renewed_at = now_value
            lease.lease_expires_at = self._next_runtime_lease_expiry(now_value=now_value)
        return lease

    def _maybe_upsert_runtime_lease(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        now_value: datetime | None = None,
        owner_instance_id: str | None = None,
        owner_pod_uid: str | None = None,
        owner_boot_id: str | None = None,
        generation: int | None = None,
        owner_started_at: datetime | None = None,
    ) -> BinarySecurityTaskRuntimeLease | None:
        phase = self._task_runtime_phase(task)
        if not self._can_own_runtime_phase(phase):
            return self._runtime_lease_for_task(db, task.id)
        try:
            return self._upsert_runtime_lease(
                db,
                task,
                now_value=now_value or _now(),
                owner_instance_id=owner_instance_id,
                owner_pod_uid=owner_pod_uid,
                owner_boot_id=owner_boot_id,
                generation=generation,
                owner_started_at=owner_started_at,
            )
        except StaleTaskExecution:
            return self._runtime_lease_for_task(db, task.id)

    def _is_runtime_lease_duplicate_insert_error(self, exc: BaseException) -> bool:
        current: BaseException | None = exc
        while current is not None:
            if isinstance(current, IntegrityError):
                args = getattr(getattr(current, "orig", None), "args", ()) or ()
                code = args[0] if args else None
                message = str(current).lower()
                if code == 1062 and "secflow_binary_security_task_runtime_lease.primary" in message:
                    return True
                if "duplicate entry" in message and "secflow_binary_security_task_runtime_lease.primary" in message:
                    return True
            current = getattr(current, "__cause__", None) or getattr(current, "orig", None)
        return False

    def _runtime_lease_is_active(self, lease: BinarySecurityTaskRuntimeLease | None) -> bool:
        if lease is None:
            return False
        remaining = _seconds_until(lease.lease_expires_at)
        return remaining is not None and remaining > 0

    def _runtime_lease_context(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[BinarySecurityTaskRuntimeLease | None, str | None, datetime | None]:
        lease = self._runtime_lease_for_task(db, task.id)
        owner: str | None = None
        if lease is not None:
            owner = str(lease.owner_instance_id or "").strip() or None
        expires_at = lease.lease_expires_at if lease is not None else None
        return lease, owner, expires_at

    def _runtime_lease_ownership_snapshot(
        self,
        db: Session,
        task_id: str,
        *,
        expected_owner: str | None = None,
    ) -> _RuntimeLeaseOwnershipDecision:
        normalized_task_id = str(task_id or "").strip()
        normalized_expected_owner = str(expected_owner or self.instance_id or "").strip() or None
        local_handle_alive = bool(self._has_local_task_execution_owner(normalized_task_id))
        if not normalized_task_id:
            return _RuntimeLeaseOwnershipDecision(
                should_continue=False,
                abort_reason="task_id_missing",
                local_handle_alive=local_handle_alive,
            )
        lease = self._runtime_lease_for_task(db, normalized_task_id)
        runtime_lease_present = lease is not None
        runtime_lease_active = self._runtime_lease_is_active(lease)
        runtime_lease_owner = str(getattr(lease, "owner_instance_id", "") or "").strip() or None if lease is not None else None
        runtime_lease_expires_at = getattr(lease, "lease_expires_at", None) if lease is not None else None
        if not runtime_lease_present:
            return _RuntimeLeaseOwnershipDecision(
                should_continue=False,
                abort_reason="runtime_lease_missing",
                runtime_lease_present=False,
                runtime_lease_active=False,
                runtime_lease_owner=None,
                runtime_lease_expires_at=None,
                local_handle_alive=local_handle_alive,
            )
        if not runtime_lease_active:
            return _RuntimeLeaseOwnershipDecision(
                should_continue=False,
                abort_reason="runtime_lease_expired",
                runtime_lease_present=True,
                runtime_lease_active=False,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
                local_handle_alive=local_handle_alive,
            )
        if normalized_expected_owner and runtime_lease_owner != normalized_expected_owner:
            return _RuntimeLeaseOwnershipDecision(
                should_continue=False,
                abort_reason="runtime_lease_owner_changed",
                runtime_lease_present=True,
                runtime_lease_active=True,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
                local_handle_alive=local_handle_alive,
            )
        return _RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner=runtime_lease_owner,
            runtime_lease_expires_at=runtime_lease_expires_at,
            local_handle_alive=local_handle_alive,
        )

    def _should_abort_local_runtime_after_lease_loss(
        self,
        decision: _RuntimeLeaseOwnershipDecision,
    ) -> bool:
        return not bool(decision.should_continue)

    def _assert_active_runtime_lease_owner(
        self,
        db: Session,
        task_id: str,
        *,
        expected_owner: str | None = None,
        allow_retryable_read_error: bool = True,
        retry_attempts: int = 2,
    ) -> _RuntimeLeaseOwnershipDecision:
        attempts = max(1, int(retry_attempts or 1))
        last_decision: _RuntimeLeaseOwnershipDecision | None = None
        for attempt in range(attempts):
            try:
                decision = self._runtime_lease_ownership_snapshot(
                    db,
                    task_id,
                    expected_owner=expected_owner,
                )
            except OperationalError as exc:
                if allow_retryable_read_error and self._is_retryable_lock_error(exc) and attempt + 1 < attempts:
                    db.rollback()
                    continue
                return _RuntimeLeaseOwnershipDecision(
                    should_continue=False,
                    abort_reason="runtime_lease_verification_failed",
                    local_handle_alive=bool(self._has_local_task_execution_owner(task_id)),
                    verification_error=str(exc),
                )
            except Exception as exc:
                if allow_retryable_read_error and attempt + 1 < attempts:
                    db.rollback()
                    continue
                return _RuntimeLeaseOwnershipDecision(
                    should_continue=False,
                    abort_reason="runtime_lease_verification_failed",
                    local_handle_alive=bool(self._has_local_task_execution_owner(task_id)),
                    verification_error=str(exc),
                )
            last_decision = decision
            if decision.should_continue or not allow_retryable_read_error:
                return decision
            if decision.abort_reason != "runtime_lease_verification_failed" or attempt + 1 >= attempts:
                return decision
        return last_decision or _RuntimeLeaseOwnershipDecision(
            should_continue=False,
            abort_reason="runtime_lease_verification_failed",
            local_handle_alive=bool(self._has_local_task_execution_owner(task_id)),
        )

    def _local_runtime_handle_state(self, task_id: str) -> str:
        handle = self._workers.get(str(task_id or "").strip())
        if handle is None:
            return "missing"
        if handle.done():
            return "done"
        if handle.cancel_requested:
            return "cancel_requested"
        if handle.active_commit_succeeded and handle.lease_established:
            return "active_with_runtime_lease"
        return "started_but_not_committed"

    def _local_runtime_handle_protects_dispatching_reclaim(self, task_id: str) -> bool:
        handle = self._workers.get(str(task_id or "").strip())
        if handle is None or handle.done() or handle.cancel_requested:
            return False
        if handle.active_commit_succeeded and handle.lease_established:
            return True
        elapsed_seconds = _elapsed_seconds_since(handle.claimed_at)
        startup_window_seconds = max(5, int(self._STATE_TRANSITION_GUARD_TTL_SECONDS or 30))
        return elapsed_seconds is not None and elapsed_seconds <= startup_window_seconds

    def _tail_reconcile_context_active(self, db: Session, task: BinarySecurityTask) -> bool:
        del db, task
        return False

    def _can_preserve_dispatching_state(self, db: Session, task: BinarySecurityTask, *, stage_runs: list[BinarySecurityStageRun] | None = None) -> bool:
        if str(task.status or "").strip() != "dispatching":
            return False
        if stage_runs is None:
            stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        if self._current_stage_authoritative_failure_context(db, task, stage_runs=stage_runs) is not None:
            return False
        if any(self._is_terminal_business_stage_failure(task, run) for run in stage_runs if str(run.status or "").strip() == "failed"):
            return False
        if self._tail_requires_execution_takeover(db, task):
            return True
        return any(str(run.status or "").strip() == "dispatching" for run in stage_runs)

    def _acquire_coordinator_lease(self, lease_name: str) -> bool:
        normalized_name = str(lease_name or "").strip()
        if not normalized_name:
            return False
        now_value = _now()
        lease_expires_at = now_value + timedelta(seconds=self._coordinator_lease_ttl_seconds())
        table_name = BinarySecurityCoordinatorLease.__tablename__
        with get_engine().begin() as connection:
            updated = connection.execute(
                text(
                    f"""
                    UPDATE {table_name}
                       SET owner_instance_id = :owner,
                           heartbeat_at = :now_value,
                           lease_expires_at = :lease_expires_at,
                           updated_at = :now_value
                     WHERE lease_name = :lease_name
                       AND (
                            owner_instance_id = :owner
                            OR lease_expires_at IS NULL
                            OR lease_expires_at <= :now_value
                       )
                    """
                ),
                {
                    "owner": self.instance_id,
                    "now_value": now_value,
                    "lease_expires_at": lease_expires_at,
                    "lease_name": normalized_name,
                },
            )
            if int(getattr(updated, "rowcount", 0) or 0) > 0:
                return True
            try:
                connection.execute(
                    text(
                        f"""
                        INSERT INTO {table_name}
                            (lease_name, owner_instance_id, heartbeat_at, lease_expires_at, created_at, updated_at)
                        VALUES
                            (:lease_name, :owner, :now_value, :lease_expires_at, :now_value, :now_value)
                        """
                    ),
                    {
                        "lease_name": normalized_name,
                        "owner": self.instance_id,
                        "now_value": now_value,
                        "lease_expires_at": lease_expires_at,
                    },
                )
                return True
            except IntegrityError:
                return False

    def _should_keep_task_heartbeat(self, db: Session, task: BinarySecurityTask | None) -> bool:
        handle = self._runtime_handle(getattr(task, "id", None) if task is not None else None)
        return self._should_continue_parent_lease_heartbeat(db, task, handle)

    def _local_operation_worker_alive(self, operation_id: str | None) -> bool:
        normalized_operation_id = str(operation_id or "").strip()
        if not normalized_operation_id:
            return False
        worker = self._operation_workers.get(normalized_operation_id)
        return bool(worker is not None and not worker.done())

    def _operation_runtime_snapshot(
        self,
        operation: BinarySecurityTaskOperation | None,
    ) -> dict[str, Any]:
        if operation is None:
            return {
                "operation_id": None,
                "operation_type": None,
                "operation_status": None,
                "current_step": None,
                "updated_at": None,
                "local_operation_worker_alive": False,
                "step_updated_at": None,
                "recent_progress": False,
            }
        current_step = str(getattr(operation, "current_step", "") or "").strip() or None
        step_snapshot = self._operation_step_snapshot(operation, current_step) if current_step else {}
        step_updated_at = step_snapshot.get("updated_at")
        if not isinstance(step_updated_at, datetime):
            step_updated_at = _parse_iso_datetime(step_updated_at)
        updated_at = getattr(operation, "updated_at", None)
        recent_progress = False
        for candidate in (step_updated_at, updated_at):
            age_seconds = _elapsed_seconds_since(candidate)
            if age_seconds is not None and age_seconds <= max(30, self._task_operation_lock_heartbeat_interval_seconds() * 3):
                recent_progress = True
                break
        return {
            "operation_id": str(getattr(operation, "id", "") or "").strip() or None,
            "operation_type": str(getattr(operation, "operation_type", "") or "").strip() or None,
            "operation_status": str(getattr(operation, "status", "") or "").strip().lower() or None,
            "current_step": current_step,
            "updated_at": updated_at,
            "local_operation_worker_alive": self._local_operation_worker_alive(getattr(operation, "id", None)),
            "step_updated_at": step_updated_at,
            "recent_progress": recent_progress,
        }

    def _control_operation_takeover_window_active(
        self,
        db: Session,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> bool:
        if task is None:
            return False
        operation = active_operation
        if operation is None:
            current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
            if current_operation_id:
                operation = (
                    db.query(BinarySecurityTaskOperation)
                    .filter(BinarySecurityTaskOperation.id == current_operation_id)
                    .first()
                )
        snapshot = self._operation_runtime_snapshot(operation)
        if snapshot["operation_status"] not in TASK_OPERATION_ACTIVE_STATUSES:
            return False
        if snapshot["operation_id"] != str(getattr(task, "current_operation_id", "") or "").strip():
            return False
        if snapshot["operation_type"] not in TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES:
            return False
        runtime_lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        runtime_lease_owner = str(getattr(runtime_lease, "owner_instance_id", "") or "").strip()
        if not self._runtime_lease_is_active(runtime_lease):
            return False
        if runtime_lease_owner != str(self.instance_id or "").strip():
            return False
        takeover_window_seconds = max(30, int(self._STATE_TRANSITION_GUARD_TTL_SECONDS or 30))
        owner_started_at = getattr(runtime_lease, "owner_started_at", None) if runtime_lease is not None else None
        dispatch_age_seconds = _elapsed_seconds_since(owner_started_at)
        if dispatch_age_seconds is not None and dispatch_age_seconds <= takeover_window_seconds:
            return True
        if self._task_runtime_transition_guard_owned_by_current_instance(task):
            return True
        return False

    def _task_has_supported_control_operation_runtime(
        self,
        db: Session,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> bool:
        if task is None:
            return False
        operation = active_operation
        if operation is None:
            current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
            if current_operation_id:
                operation = (
                    db.query(BinarySecurityTaskOperation)
                    .filter(BinarySecurityTaskOperation.id == current_operation_id)
                    .first()
                )
        snapshot = self._operation_runtime_snapshot(operation)
        if snapshot["operation_status"] not in TASK_OPERATION_ACTIVE_STATUSES:
            return False
        if snapshot["operation_id"] != str(getattr(task, "current_operation_id", "") or "").strip():
            return False
        if snapshot["operation_type"] not in TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES:
            return False
        runtime_lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        return bool(
            self._runtime_lease_is_active(runtime_lease)
            and str(getattr(runtime_lease, "owner_instance_id", "") or "").strip() == str(self.instance_id or "").strip()
        )

    def _task_owner_runtime_supported_locally(
        self,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> bool:
        if task is None:
            return False
        del active_operation
        session = get_session_factory()()
        try:
            runtime_lease = self._runtime_lease_for_task(session, getattr(task, "id", None))
            return bool(
                runtime_lease is not None
                and self._runtime_lease_is_active(runtime_lease)
                and str(getattr(runtime_lease, "owner_instance_id", "") or "").strip() == str(self.instance_id or "").strip()
            )
        finally:
            session.close()

    def _task_has_supported_runtime_owner(
        self,
        db: Session,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> bool:
        if task is None:
            return False
        snapshot = self._parent_runtime_ownership_snapshot(db, task, active_operation=active_operation)
        return bool(snapshot.runtime_lease_active and snapshot.runtime_lease_owner)

    def _task_has_healthy_active_owner_runtime(
        self,
        db: Session | None,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> bool:
        if task is None:
            return False
        if db is None:
            return False
        snapshot = self._parent_runtime_ownership_snapshot(db, task, active_operation=active_operation)
        return bool(snapshot.runtime_lease_active and snapshot.runtime_lease_owner)

    def _stale_parent_runtime_takeover_decision(
        self,
        db: Session,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> _StaleParentRuntimeTakeoverDecision:
        if task is None:
            return _StaleParentRuntimeTakeoverDecision(
                runtime_lease_active=False,
                runtime_lease_owner=None,
                local_handle_alive=False,
                supported_control_operation_active=False,
                allow_takeover=False,
                allow_reenqueue=False,
                allow_claim=False,
                decision_reason="task_missing",
            )
        snapshot = self._parent_runtime_ownership_snapshot(db, task, active_operation=active_operation)
        if snapshot.runtime_lease_active:
            return _StaleParentRuntimeTakeoverDecision(
                runtime_lease_active=True,
                runtime_lease_owner=snapshot.runtime_lease_owner,
                local_handle_alive=snapshot.local_handle_alive,
                supported_control_operation_active=snapshot.supported_control_operation_active,
                allow_takeover=False,
                allow_reenqueue=False,
                allow_claim=False,
                decision_reason="active_runtime_lease",
            )
        if snapshot.supported_control_operation_active:
            return _StaleParentRuntimeTakeoverDecision(
                runtime_lease_active=False,
                runtime_lease_owner=snapshot.runtime_lease_owner,
                local_handle_alive=snapshot.local_handle_alive,
                supported_control_operation_active=True,
                allow_takeover=False,
                allow_reenqueue=False,
                allow_claim=False,
                decision_reason="supported_control_operation_active",
            )
        return _StaleParentRuntimeTakeoverDecision(
            runtime_lease_active=False,
            runtime_lease_owner=snapshot.runtime_lease_owner,
            local_handle_alive=snapshot.local_handle_alive,
            supported_control_operation_active=snapshot.supported_control_operation_active,
            allow_takeover=True,
            allow_reenqueue=True,
            allow_claim=True,
            decision_reason="runtime_lease_expired_without_local_owner",
        )

    def _should_enqueue_parent_dispatch_for_task_sync(
        self,
        db: Session | None,
        task: BinarySecurityTask,
        *,
        sync_kind: str,
        force: bool,
    ) -> bool:
        normalized_sync_kind = str(sync_kind or "downstream_status").strip() or "downstream_status"
        normalized_status = str(getattr(task, "status", "") or "").strip().lower()
        if self._task_is_hidden_by_delete_queue(task):
            return False
        if normalized_status in TASK_TERMINAL_STATUSES and not str(getattr(task, "current_operation_id", "") or "").strip():
            return False
        if self._task_has_healthy_active_owner_runtime(db, task):
            return False
        if normalized_sync_kind in {
            "downstream_status",
            "binding_repair",
            "late_child_terminal_sync",
            "stale_sync_retry",
        }:
            return normalized_status in {"pending", "dispatching", "running", TASK_STATUS_CANCELLING} or bool(force)
        return normalized_status in {"pending", "dispatching", "running", TASK_STATUS_CANCELLING, "failed"} or bool(force)

    def _release_task_without_supported_runtime_owner(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        active_operation=None,
        reason: str,
    ) -> bool:
        snapshot = self._parent_runtime_ownership_snapshot(db, task, active_operation=active_operation)
        active_runtime_lease_owner = snapshot.runtime_lease_owner if snapshot.runtime_lease_active else None
        guard = self._should_preserve_parent_runtime_ownership(snapshot, reason=reason)
        if guard.preserve and snapshot.supported_control_operation_active:
            self._record_event(
                db,
                task,
                "task_owner_release_deferred_for_control_operation_takeover",
                "检测到控制操作仍由有效 runtime lease 持有，本次不释放 owner",
                level="info",
                stage_name=task.current_stage,
                payload={
                    "reason": reason,
                    "current_operation_id": str(getattr(task, "current_operation_id", "") or "").strip() or None,
                    "active_runtime_lease_owner": active_runtime_lease_owner,
                    "operation_runtime": self._operation_runtime_snapshot(active_operation),
                    **self._parent_runtime_ownership_snapshot_payload(snapshot, reason=reason),
                },
            )
            return False
        if self._task_has_supported_runtime_owner(db, task, active_operation=active_operation):
            return False
        if guard.preserve:
            self._record_event(
                db,
                task,
                "parent_runtime_reopen_suppressed_active_lease",
                "父任务 authoritative runtime ownership 仍有效，不释放任务 owner",
                level="warning",
                stage_name=task.current_stage,
                payload={
                    "decision_reason": guard.decision_reason,
                    **self._parent_runtime_ownership_snapshot_payload(snapshot, reason=reason),
                },
            )
            return False
        decision = self._can_reopen_parent_task_after_lease_loss(db, task, reason=reason)
        if not decision.allowed:
            self._record_parent_runtime_lease_decision(
                db,
                task,
                event_type="parent_runtime_reopen_suppressed_active_lease",
                message="父任务 authoritative runtime lease 仍有效，不释放任务 owner",
                decision=decision,
                reason=reason,
                stage_name=task.current_stage,
            )
            return False
        previous_status = str(getattr(task, "status", "") or "").strip().lower()
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip() or None
        if previous_status in {"running", "dispatching"}:
            self._apply_release_for_takeover_main_state(
                db,
                task,
                source="task_manager",
                reason="检测到任务已无可用 runtime owner，已释放 owner 并回到可重新调度态等待新实例接管",
                status="pending",
                stage_name=task.current_stage,
                finished_at=None,
                last_error=None,
            )
        elif previous_status == TASK_STATUS_CANCELLING:
            self._apply_release_for_takeover_main_state(
                db,
                task,
                source="task_manager",
                reason="任务取消中但已无可用 runtime owner，保留取消状态并释放 owner",
                status=TASK_STATUS_CANCELLING,
                stage_name=task.current_stage,
                finished_at=None,
                last_error=None,
                record_blocked_event=False,
            )
        observed_owner = str(decision.runtime_lease_owner or "").strip() or None
        if observed_owner:
            self._clear_runtime_lease(db, task.id, owner_instance_id=observed_owner)
        reopen_event_type, reopen_message = self._parent_runtime_reopen_allowed_event(
            decision,
            expired_message="父任务 authoritative runtime lease 已过期，允许释放任务 owner 并重新调度",
            missing_message="父任务 authoritative runtime lease 已缺失，允许释放任务 owner 并重新调度",
        )
        self._record_parent_runtime_lease_decision(
            db,
            task,
            event_type=reopen_event_type,
            message=reopen_message,
            decision=decision,
            reason=reason,
            stage_name=task.current_stage,
            level="warning",
        )
        self._repair_active_operations_for_task(db, task)
        requeue_succeeded = False
        requeue_error: str | None = None
        try:
            requeue_succeeded = self._force_requeue_task_sync(
                task.id,
                context="owned_execution_release_for_takeover",
            )
        except Exception as exc:
            requeue_error = str(exc)
            requeue_succeeded = False
        if not requeue_succeeded and not requeue_error:
            requeue_error = "force_requeue_task_returned_false"
        self._record_event(
            db,
            task,
            "task_runtime_released_without_local_owner",
            "检测到任务已无可用 runtime owner，但当前 Pod 没有本地执行句柄，已释放 owner 并等待重新调度",
            level="warning",
            stage_name=task.current_stage,
            payload={
                "reason": reason,
                "previous_status": previous_status,
                "current_operation_id": current_operation_id,
                "released_by_instance_id": str(self.instance_id or "").strip() or None,
                "operation_runtime": self._operation_runtime_snapshot(active_operation),
                "local_task_runtime_handle_alive": self._has_local_task_execution_owner(task.id),
                "local_streaming_stage_worker_alive": self._task_has_active_streaming_stage_workers(task.id),
                "active_runtime_lease_owner": active_runtime_lease_owner,
                "force_requeue": requeue_succeeded,
                "enqueue_context": "owned_execution_release_for_takeover",
            },
        )
        if requeue_succeeded:
            self._record_event(
                db,
                task,
                "owned_execution_release_reenqueued_for_takeover",
                "检测到父任务 lease 已失效，已释放 owner 并重新加入共享调度队列",
                level="warning",
                stage_name=task.current_stage,
                payload={
                    "previous_status": previous_status,
                    "release_reason": reason,
                    "runtime_lease_owner": active_runtime_lease_owner,
                    "runtime_lease_expires_at": _already_isoformatted_datetime(snapshot.runtime_lease_expires_at),
                    "force_requeue": True,
                    "enqueue_context": "owned_execution_release_for_takeover",
                },
            )
        else:
            self._record_event(
                db,
                task,
                "owned_execution_release_reenqueue_failed",
                "父任务 owner 已释放，但重新加入共享调度队列失败，等待后续补偿修复",
                level="warning",
                stage_name=task.current_stage,
                payload={
                    "previous_status": previous_status,
                    "release_reason": reason,
                    "runtime_lease_owner": active_runtime_lease_owner,
                    "runtime_lease_expires_at": _already_isoformatted_datetime(snapshot.runtime_lease_expires_at),
                    "force_requeue": False,
                    "enqueue_context": "owned_execution_release_for_takeover",
                    "error": requeue_error,
                },
            )
        return True

    def _write_task_heartbeat(self, session: Session, task_id: str, *, now_value: datetime, source: str) -> bool:
        task = session.query(BinarySecurityTask).filter(
            BinarySecurityTask.id == task_id,
        ).first()
        if task is not None:
            self._upsert_runtime_lease(
                session,
                task,
                now_value=now_value,
                owner_instance_id=self.instance_id,
                owner_pod_uid=self.owner_pod_uid,
                owner_boot_id=self.owner_boot_id,
                generation=self._owner_generation,
                owner_started_at=self.owner_started_at,
            )
            task.dispatcher_instance_id = str(self.instance_id or "").strip() or None
            if str(getattr(task, "runtime_phase", "") or "").strip() != TASK_RUNTIME_PHASE_OWNED_EXECUTION:
                task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
            task.tail_reconcile_state = "idle"
            task.updated_at = now_value
            session.commit()
            self._last_task_heartbeat_at[task_id] = now_value
            handle = self._runtime_handle(task_id)
            if handle is not None:
                handle.last_lease_refresh_at = now_value
            observe_heartbeat_update(f"{source}_written")
            return True
        session.rollback()
        observe_heartbeat_update(f"{source}_skipped")
        return False

    def prepare_task_id(self, db: Session, project_id: str) -> str:
        for _ in range(10):
            task_id = uuid.uuid4().hex[:16]
            exists = db.query(BinarySecurityTask.id).filter(
                BinarySecurityTask.project_id == project_id,
                BinarySecurityTask.id == task_id,
            ).first()
            if not exists:
                return task_id
        raise ValidationError("无法生成唯一任务 ID，请重试")

    def _task_type(self, task: BinarySecurityTask | str | None) -> str:
        raw = task if isinstance(task, str) else getattr(task, "task_type", None)
        return raw if raw in TASK_STAGE_SEQUENCES else TASK_TYPE_BINARY

    def _pipeline_profile(self, task: BinarySecurityTask | dict[str, Any] | None) -> str:
        if isinstance(task, dict):
            policy = dict(task.get("policy") or {})
        else:
            policy = dict(getattr(task, "policy", {}) or {})
        raw = str(policy.get("pipeline_profile") or PIPELINE_PROFILE_DEFAULT).strip().lower()
        return raw or PIPELINE_PROFILE_DEFAULT

    def _stage_sequence_for_task(self, task: BinarySecurityTask | str | None) -> list[str]:
        task_type = self._task_type(task)
        if isinstance(task, BinarySecurityTask):
            profile = self._pipeline_profile(task)
        else:
            profile = PIPELINE_PROFILE_DEFAULT
        return list(TASK_PIPELINE_PROFILE_SEQUENCES.get((task_type, profile), TASK_STAGE_SEQUENCES[task_type]))

    def _source_entry_analysis_barrier_enabled(self, task: BinarySecurityTask | dict[str, Any] | None) -> bool:
        return self._task_type(task) == TASK_TYPE_SOURCE and self._pipeline_profile(task) == PIPELINE_PROFILE_DEFAULT

    def _binary_system_analysis_binary_to_source_barrier_enabled(
        self,
        task: BinarySecurityTask | dict[str, Any] | None,
    ) -> bool:
        return self._task_type(task) == TASK_TYPE_BINARY

    def _binary_entry_analysis_barrier_enabled(
        self,
        task: BinarySecurityTask | dict[str, Any] | None,
    ) -> bool:
        return self._task_type(task) in {TASK_TYPE_BINARY, TASK_TYPE_BINARY_MODULE}

    def _stage_handler(self, stage_name: str | None):
        return self._stage_registry.get(stage_name)

    def _validate_task_type(self, task_type: str | None) -> str:
        normalized = str(task_type or TASK_TYPE_BINARY).strip().lower()
        if normalized not in TASK_STAGE_SEQUENCES:
            raise ValidationError(f"不支持的任务类型: {task_type}")
        return normalized

    def _validate_pipeline_profile(self, task_type: str, pipeline_profile: str | None) -> str:
        normalized = str(pipeline_profile or PIPELINE_PROFILE_DEFAULT).strip().lower() or PIPELINE_PROFILE_DEFAULT
        if normalized == PIPELINE_PROFILE_DEFAULT:
            return normalized
        if normalized == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            if task_type != TASK_TYPE_SOURCE:
                raise ValidationError("kg_source_vuln_scan 仅支持源码任务")
            return normalized
        raise ValidationError(f"不支持的流程模式: {pipeline_profile}")

    def _knowledge_graph_policy(self, task: BinarySecurityTask | dict[str, Any] | None) -> dict[str, Any]:
        if isinstance(task, dict):
            policy = dict(task.get("policy") or {})
        else:
            policy = dict(getattr(task, "policy", {}) or {})
        return policy

    def _knowledge_graph_locator(self, task: BinarySecurityTask | dict[str, Any] | None) -> tuple[str | None, str | None]:
        policy = self._knowledge_graph_policy(task)
        upload_id = str(policy.get("knowledge_graph_upload_id") or "").strip() or None
        db_name = str(policy.get("knowledge_graph_db_name") or "").strip() or None
        return upload_id, db_name

    def _knowledge_graph_request_options(self, task: BinarySecurityTask | dict[str, Any] | None) -> dict[str, Any]:
        policy = self._knowledge_graph_policy(task)
        cfg = self.cfg.services.knowledge_graph_audit
        return {
            "status_filter": str(policy.get("knowledge_graph_status_filter") or cfg.default_status_filter or "identified").strip() or "identified",
            "include_excluded": bool(cfg.default_include_excluded if policy.get("knowledge_graph_include_excluded") is None else policy.get("knowledge_graph_include_excluded")),
            "kind": str(policy.get("knowledge_graph_kind") or "").strip() or None,
            "module": policy.get("knowledge_graph_module"),
        }

    def _knowledge_graph_entry_fetch_max_attempts(self) -> int:
        return max(1, int(KNOWLEDGE_GRAPH_ENTRY_FETCH_MAX_ATTEMPTS))

    def _knowledge_graph_entry_fetch_retry_interval_seconds(self) -> int:
        return max(0, int(KNOWLEDGE_GRAPH_ENTRY_FETCH_RETRY_INTERVAL_SECONDS))

    async def complete_uploads(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityUploadCompletePayload,
        updated_by: str,
        authorization_token: str,
    ) -> BinarySecurityTaskDetailResponse:
        del updated_by, authorization_token
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"pending_upload", "uploading", "pending"}:
            raise ValidationError(f"当前状态不允许确认上传完成: {task.status}")
        declared = self._normalize_input_files(
            payload.files or [BinarySecurityInputFile(**item) for item in task.summary.get("input_files") or []],
            task_type=self._task_type(task),
        )
        input_dir = Path(task.workspace_root) / "input"
        self._record_event(db, task, "task_upload_started", "开始校验上传文件")
        if self._task_type(task) == TASK_TYPE_SOURCE:
            source_input_kind = self._source_input_kind(declared)
            if source_input_kind == "source_archives":
                actual_files, total_bytes, extracted_count = await self._materialize_source_archives(task, declared)
                self._record_event(
                    db,
                    task,
                    "source_archives_extracted",
                    "源码压缩包已解压到任务输入目录",
                    payload={"archive_count": len(actual_files), "extracted_file_count": extracted_count},
                )
            else:
                actual_files, total_bytes = await self._materialize_source_tree_files(task, declared)
                extracted_count = len(actual_files)
                self._record_event(
                    db,
                    task,
                    "source_tree_verified",
                    "源码目录文件已校验并纳入任务输入目录",
                    payload={"file_count": len(actual_files)},
                )
        elif self._task_type(task) == TASK_TYPE_BINARY_MODULE:
            actual_files = []
            total_bytes = 0
            for file_info in declared:
                filename = str(file_info["filename"])
                relative_path = str(file_info.get("relative_path") or filename).strip().replace("\\", "/")
                local_path = input_dir / relative_path
                if not await asyncio.to_thread(local_path.is_file):
                    raise ValidationError(f"上传文件缺失: {relative_path}")
                stat = await asyncio.to_thread(local_path.stat)
                self._validate_uploaded_archive_size(filename, stat.st_size, source_task=False)
                self._check_storage_free_space(required_bytes=stat.st_size)
                total_bytes += stat.st_size
                actual_files.append(
                    {
                        **file_info,
                        "size": stat.st_size,
                        "uploaded": True,
                        "path": f"{task.summary.get('input_dir')}/{relative_path}",
                    }
                )
        else:
            actual_files = []
            total_bytes = 0
            for file_info in declared:
                filename = str(file_info["filename"])
                relative_path = str(file_info.get("relative_path") or filename).strip().replace("\\", "/")
                local_path = input_dir / relative_path
                if not await asyncio.to_thread(local_path.is_file):
                    raise ValidationError(f"上传文件缺失: {relative_path}")
                stat = await asyncio.to_thread(local_path.stat)
                self._validate_uploaded_archive_size(filename, stat.st_size, source_task=False)
                self._check_storage_free_space(required_bytes=stat.st_size)
                total_bytes += stat.st_size
                actual_files.append(
                    {
                        **file_info,
                        "size": stat.st_size,
                        "uploaded": True,
                        "path": f"{task.summary.get('input_dir')}/{relative_path}",
                    }
                )
        self._apply_release_for_takeover_main_state(
            db,
            task,
            source="task_manager",
            reason="输入文件上传完成，任务已进入调度队列",
            status="pending",
            stage_name=self._stage_sequence_for_task(task)[0],
        )
        task.summary = {
            **task.summary,
            "input_files": actual_files,
            "input_kind": self._source_input_kind(actual_files) if self._task_type(task) == TASK_TYPE_SOURCE else task.summary.get("input_kind"),
            **(self._build_binary_module_summary(task, actual_files) if self._task_type(task) == TASK_TYPE_BINARY_MODULE else {}),
        }
        task.metrics = {
            **task.metrics,
            "input_file_count": len(actual_files),
            "uploaded_file_count": len(actual_files),
            "input_total_bytes": total_bytes,
            "firmware_item_count": len(actual_files),
            **(
                {
                    "selected_module_count": 1,
                    "candidate_module_count": 1,
                    "high_risk_module_count": 0,
                    "medium_risk_module_count": 0,
                    "low_risk_module_count": 0,
                }
                if self._task_type(task) == TASK_TYPE_BINARY_MODULE
                else {}
            ),
        }
        await self._write_task_metadata_async(task, input_dir / "task-metadata.json", status="pending")
        self._record_event(db, task, "task_upload_completed", "输入文件上传完成", payload={"uploaded_files": len(actual_files)})
        self._record_event(db, task, "task_start_requested", "输入文件已就绪，任务已自动进入调度队列")
        db.commit()
        enqueued = await self._enqueue_task_and_wait(
            task.id,
            context="task_create_initial_enqueue",
            timeout_seconds=self._initial_enqueue_wait_timeout_seconds(),
        )
        if not enqueued:
            refreshed = self._task_or_404(db, project_id, task.id)
            self._record_event(
                db,
                refreshed,
                "task_initial_enqueue_failed",
                "任务首次进入调度队列失败，等待后台补偿自动恢复",
                level="warning",
                stage_name=refreshed.current_stage,
                payload={
                    "reason": "initial_enqueue_failed_after_task_creation",
                    "enqueue_context": "task_create_initial_enqueue",
                    "timeout_seconds": self._initial_enqueue_wait_timeout_seconds(),
                    "runtime_phase": self._task_runtime_phase(refreshed),
                    "current_stage": str(getattr(refreshed, "current_stage", "") or "").strip() or None,
                },
            )
            db.commit()
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def start_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"failed", "partial_success"}:
            if task.status in {"pending", "running"}:
                return self.get_task_detail(db, project_id=project_id, task_id=task_id)
            raise ValidationError(f"当前状态不允许启动任务: {task.status}")
        input_files = task.summary.get("input_files") or []
        if not input_files:
            raise ValidationError("没有可用的输入文件")
        self._apply_release_for_takeover_main_state(
            db,
            task,
            source="task_manager",
            reason="任务启动请求已受理，进入待调度",
            status="pending",
            stage_name=self._stage_sequence_for_task(task)[0],
            finished_at=None,
            last_error=None,
        )
        task.execution_mode = None
        task.target_stage_name = None
        task.started_at = None
        task.finished_at = None
        task.summary = {
            **task.summary,
            "stale_stages": [],
            "stale_reason": None,
            "stale_from_stage": None,
            "stage_retry_context": {},
        }
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
        self._record_event(db, task, "task_start_requested", "任务已进入调度队列")
        observe_task_lifecycle("queued", status=task.status, task_type=self._task_type(task))
        if self._task_type(task) == TASK_TYPE_BINARY:
            self._record_event(db, task, "firmware_items_initialized", f"已初始化 {len(input_files)} 个固件输入")
        else:
            self._record_event(db, task, "source_tree_initialized", f"已初始化源码工程输入，共 {len(input_files)} 个文件")
        db.commit()
        enqueued = self._enqueue_task_and_wait_sync(
            task.id,
            context="task_start_initial_enqueue",
            timeout_seconds=self._initial_enqueue_wait_timeout_seconds(),
        )
        if not enqueued:
            refreshed = self._task_or_404(db, project_id, task.id)
            self._record_event(
                db,
                refreshed,
                "task_initial_enqueue_failed",
                "任务首次进入调度队列失败，等待后台补偿自动恢复",
                level="warning",
                stage_name=refreshed.current_stage,
                payload={
                    "reason": "initial_enqueue_failed_after_manual_start",
                    "enqueue_context": "task_start_initial_enqueue",
                    "timeout_seconds": self._initial_enqueue_wait_timeout_seconds(),
                    "runtime_phase": self._task_runtime_phase(refreshed),
                    "current_stage": str(getattr(refreshed, "current_stage", "") or "").strip() or None,
                },
            )
            db.commit()
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def get_task_abnormal_reason_history(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
    ) -> BinarySecurityAbnormalReasonHistoryResponse:
        task = self._task_or_404(db, project_id, task_id)
        return BinarySecurityAbnormalReasonHistoryResponse(
            task_id=task.id,
            items=self._abnormal_reason_history(db, task),
        )

    def _archive_job_responses(
        self,
        db: Session,
        task: BinarySecurityTask,
        archive_jobs: list[BinarySecurityArchiveJob],
    ) -> list[BinarySecurityArchiveJobResponse]:
        archive_job_responses: list[BinarySecurityArchiveJobResponse] = []
        stage_item_by_id = self._archive_job_stage_item_map(db, task, archive_jobs)
        for job in archive_jobs:
            retry_supported, retry_reason = self._archive_job_retry_support(db, task, job)
            source_refs = self._archive_job_source_refs(job, stage_item_by_id.get(job.item_id))
            archive_sources = self._archive_job_archive_sources(db, task, job)
            archive_job_responses.append(
                BinarySecurityArchiveJobResponse(
                    id=job.id,
                    stage_name=job.stage_name,
                    item_id=job.item_id,
                    item_key=job.item_key,
                    downstream_service=job.downstream_service,
                    downstream_task_id=job.downstream_task_id,
                    archive_source_primary_path=archive_sources[0] if archive_sources else None,
                    archive_source_paths=archive_sources,
                    source_root=source_refs["source_root"],
                    source_root_path=source_refs["source_root_path"],
                    source_dir=source_refs["source_dir"],
                    archive_status=job.archive_status,
                    archive_root=job.archive_root,
                    error_message=job.error_message,
                    abnormal_reason=self._archive_job_abnormal_reason(job),
                    attempts=job.attempts or 0,
                    retry_attempt_count=max(0, int(job.attempts or 0)),
                    created_at=job.created_at,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                    updated_at=job.updated_at,
                    retry_supported=retry_supported,
                    retry_reason=retry_reason,
                    retry_failed_supported=retry_supported,
                    retry_failed_reason=retry_reason,
                    copy_stats=dict((job.payload or {}).get("archive_copy_stats") or {}),
                )
            )
        return archive_job_responses

    def _archive_job_stage_item_map(
        self,
        db: Session,
        task: BinarySecurityTask,
        archive_jobs: list[BinarySecurityArchiveJob],
    ) -> dict[str, BinarySecurityStageItem]:
        item_ids = [str(job.item_id or "").strip() for job in archive_jobs if str(job.item_id or "").strip()]
        if not item_ids:
            return {}
        rows = (
            db.query(BinarySecurityStageItem)
            .filter(
                BinarySecurityStageItem.task_id == task.id,
                BinarySecurityStageItem.id.in_(item_ids),
            )
            .all()
        )
        return {str(row.id): row for row in rows}

    def _archive_job_source_refs(
        self,
        job: BinarySecurityArchiveJob,
        stage_item: BinarySecurityStageItem | None,
    ) -> dict[str, str | None]:
        payload = dict(job.payload or {})
        item_input = dict(getattr(stage_item, "input_ref", {}) or {})
        item_output = dict(getattr(stage_item, "output_ref", {}) or {})
        item_result = dict(getattr(stage_item, "result", {}) or {})
        source_root_path = self._string_or_none(
            payload.get("source_root_path")
            or item_output.get("source_root_path")
            or item_result.get("source_root_path")
            or item_input.get("source_root_path")
        )
        source_root = self._string_or_none(
            payload.get("source_root")
            or item_output.get("source_root")
            or item_result.get("source_root")
            or item_input.get("source_root")
        )
        source_dir = self._string_or_none(
            payload.get("source_dir")
            or item_output.get("source_dir")
            or item_result.get("source_dir")
            or item_input.get("source_dir")
        )
        return {
            "source_root": source_root,
            "source_root_path": source_root_path,
            "source_dir": source_dir,
        }

    def _archive_job_archive_sources(
        self,
        db: Session,
        task: BinarySecurityTask,
        job: BinarySecurityArchiveJob,
    ) -> list[str]:
        payload = dict(job.payload or {})
        payload_sources = payload.get("archive_source_paths")
        if isinstance(payload_sources, list):
            normalized = [str(path).strip() for path in payload_sources if str(path).strip()]
            if normalized:
                return normalized
        fallback_sources = self._archive_job_sources_from_events(db, task, job)
        return fallback_sources

    def _archive_job_sources_from_events(
        self,
        db: Session,
        task: BinarySecurityTask,
        job: BinarySecurityArchiveJob,
    ) -> list[str]:
        rows = (
            db.query(BinarySecurityEvent)
            .filter(
                BinarySecurityEvent.task_id == task.id,
                BinarySecurityEvent.item_id == job.item_id,
                BinarySecurityEvent.event_type.in_(["downstream_output_copied", "downstream_output_copy_partial"]),
            )
            .order_by(BinarySecurityEvent.created_at.desc())
            .all()
        )
        expected_target_dir = str(job.archive_root or "").strip()
        expected_downstream_task_id = self._archive_job_bound_downstream_task_id(job)
        for row in rows:
            payload = dict(getattr(row, "payload", None) or {})
            target_dir = str(payload.get("target_dir") or "").strip()
            if expected_target_dir and target_dir and target_dir != expected_target_dir:
                continue
            event_downstream_task_id = str(payload.get("bound_downstream_task_id") or "").strip()
            if expected_downstream_task_id and event_downstream_task_id and event_downstream_task_id != expected_downstream_task_id:
                continue
            sources = payload.get("sources")
            if isinstance(sources, list):
                normalized = [str(path).strip() for path in sources if str(path).strip()]
                if normalized:
                    return normalized
        return []

    def _current_downstream_task_id(self, item: BinarySecurityStageItem | None) -> str:
        return str(getattr(item, "downstream_task_id", "") or "").strip()

    def _payload_downstream_task_id(self, payload: dict[str, Any] | None) -> str:
        payload = dict(payload or {})
        return str(payload.get("task_id") or payload.get("id") or "").strip()

    def _payload_matches_current_child(
        self,
        item: BinarySecurityStageItem,
        payload: dict[str, Any] | None,
    ) -> bool:
        expected_downstream_task_id = self._current_downstream_task_id(item)
        observed_downstream_task_id = self._payload_downstream_task_id(payload)
        if not expected_downstream_task_id or not observed_downstream_task_id:
            return True
        return expected_downstream_task_id == observed_downstream_task_id

    def _is_recoverable_child_failure_status(self, item: BinarySecurityStageItem | None) -> bool:
        if item is None:
            return False
        result_payload = dict(getattr(item, "result", None) or {})
        sync_observation = dict(result_payload.get("sync_observation") or {})
        raw_values = [
            self._string_or_none(getattr(item, "error_message", None)),
            self._string_or_none(result_payload.get("error_message")),
            self._string_or_none(sync_observation.get("error_message")),
            self._string_or_none(sync_observation.get("error_type")),
            self._string_or_none(result_payload.get("last_sync_error_message")),
            self._string_or_none(result_payload.get("last_sync_error_type")),
        ]
        joined = " ".join(str(value or "").strip().lower() for value in raw_values if str(value or "").strip())
        if not joined:
            return False
        recoverable_tokens = (
            "owner_lost_retry_exhausted",
            "owner changed",
            "owner 已变更",
            "lease expired",
            "lease 已失效",
            "staletaskexecution",
            "当前执行 token 已失效",
            "当前 owned_execution runtime lease owner 已变更",
            "当前 tail 收敛 owner 已变更",
            "当前 tail 收敛 lease 已失效",
            "takeover",
            "requeue",
            "requeued",
            "recovery",
            "transport_error",
            "http_5xx",
            "upstreamerror",
        )
        return any(token in joined for token in recoverable_tokens)

    def _should_apply_current_child_intermediate_recovery(
        self,
        item: BinarySecurityStageItem,
        *,
        mapped_status: str,
        payload: dict[str, Any] | None,
    ) -> bool:
        if mapped_status not in {"pending", "queued", "running", "dispatching"}:
            return False
        if not self._payload_matches_current_child(item, payload):
            return False
        replacement_state = self._replacement_in_progress_state(item)
        if replacement_state["replacement_in_progress"] or replacement_state["binding_cleared"]:
            return False
        current_status = self._normalize_downstream_status(item.status) or self._string_or_none(item.status)
        if current_status not in {"failed", "cancelled", "downstream_missing"}:
            return False
        return self._is_recoverable_child_failure_status(item)

    def _archive_job_bound_downstream_task_id(self, job: BinarySecurityArchiveJob | None) -> str:
        if job is None:
            return ""
        payload = dict(getattr(job, "payload", None) or {})
        return str(payload.get("bound_downstream_task_id") or getattr(job, "downstream_task_id", "") or "").strip()

    def _binding_mismatch_payload(
        self,
        *,
        source: str,
        expected_downstream_task_id: str | None,
        actual_downstream_task_id: str | None,
        current_downstream_task_id: str | None = None,
        archive_job_id: str | None = None,
        payload_downstream_task_id: str | None = None,
        replacement_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        mismatch_payload = {
            "source": source,
            "expected_downstream_task_id": str(expected_downstream_task_id or "").strip() or None,
            "actual_downstream_task_id": str(actual_downstream_task_id or "").strip() or None,
            "current_downstream_task_id": str(current_downstream_task_id or "").strip() or None,
        }
        if archive_job_id:
            mismatch_payload["archive_job_id"] = archive_job_id
        if payload_downstream_task_id:
            mismatch_payload["payload_downstream_task_id"] = str(payload_downstream_task_id or "").strip() or None
        if replacement_state is not None:
            mismatch_payload["replacement_state"] = dict(replacement_state)
        return mismatch_payload

    def _replacement_window_active_for_stale_ignore(self, item: BinarySecurityStageItem) -> bool:
        replacement_state = self._replacement_in_progress_state(item)
        return bool(replacement_state["replacement_in_progress"] or replacement_state["binding_cleared"])

    def _record_binding_mismatch_event(
        self,
        db: Session | None,
        task: BinarySecurityTask | None,
        item: BinarySecurityStageItem | None,
        *,
        event_type: str,
        message: str,
        payload: dict[str, Any],
        level: str = "warning",
    ) -> None:
        if item is None:
            return
        latest = {
            **payload,
            "message": message,
            "recorded_at": _now().isoformat(),
        }
        result = self._load_stage_item_result_payload(item)
        if db is None or task is None:
            item.result = {**result, "latest_binding_mismatch": latest}
            return
        result = self._load_stage_item_result_payload(item)
        self._persist_stage_item_result(
            task,
            item,
            stage_name=item.stage_name,
            result={
                **result,
                "latest_binding_mismatch": {
                    **payload,
                    "message": message,
                    "recorded_at": _now().isoformat(),
                },
            },
        )
        self._record_event(
            db,
            task,
            event_type,
            message,
            stage_name=item.stage_name,
            item=item,
            level=level,
            payload=payload,
        )
        self._record_downstream_sync_event(
            db,
            task=task,
            item=item,
            stage_name=item.stage_name,
            operation=str(payload.get("operation") or "downstream_sync").strip() or "downstream_sync",
            event_type="binding_mismatch",
            sync_status=self._string_or_none(payload.get("sync_status")) or "binding_mismatch",
            outcome="binding_mismatch",
            state_applied=False,
            error_type="binding_mismatch",
            error_message=message,
            payload=payload,
        )

    def _is_payload_bound_to_current_item(
        self,
        item: BinarySecurityStageItem | None,
        payload: dict[str, Any] | None,
        *,
        allow_empty_payload_task_id: bool = True,
    ) -> bool:
        if item is None:
            return False
        current_task_id = self._current_downstream_task_id(item)
        payload_task_id = self._payload_downstream_task_id(payload)
        if not payload_task_id:
            return allow_empty_payload_task_id
        if not current_task_id:
            return True
        return payload_task_id == current_task_id

    def _retry_cleanup_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_names: list[str],
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        direct_refs = self._retry_downstream_refs_for_stages(db, task, stage_names)
        return self._dedupe_downstream_refs(direct_refs), []

    def _parent_linked_downstream_candidates(self) -> list[tuple[str, str, str, str, str | None]]:
        return []

    def _parent_linked_downstream_soft_delete_column(self, service: str) -> str | None:
        normalized_service = str(service or "").strip()
        if normalized_service in {"system_analyse", "entry_analyse", "dataflow_vuln_scan"}:
            return "is_deleted"
        return None

    def _discover_parent_linked_downstream_refs_detailed(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        del db, task
        return [], []

    def update_task_concurrency(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityTaskConcurrencyUpdatePayload,
    ) -> BinarySecurityTaskDetailResponse:
        runtime_payload = BinarySecurityTaskRuntimePolicyUpdatePayload(
            expected_version=0,
            stage_parallelism=dict(payload.stage_parallelism or {}),
        )
        return self.update_task_runtime_policy(
            db,
            project_id=project_id,
            task_id=task_id,
            payload=runtime_payload,
        )

    def _compose_runtime_lease_execution_token(
        self,
        *,
        owner_instance_id: str | None,
        owner_started_at: datetime | None,
        generation: int | None,
        execution_epoch: int | None,
    ) -> str | None:
        normalized_owner = str(owner_instance_id or "").strip() or None
        if normalized_owner is None or owner_started_at is None:
            return None
        return "|".join(
            [
                normalized_owner,
                str(int(execution_epoch or 0)),
                str(int(generation or 0)),
                owner_started_at.isoformat(),
            ]
        )

    def _runtime_lease_execution_token(
        self,
        task: BinarySecurityTask | None,
        runtime_lease: BinarySecurityTaskRuntimeLease | None,
    ) -> str | None:
        if runtime_lease is None:
            return None
        return self._compose_runtime_lease_execution_token(
            owner_instance_id=str(getattr(runtime_lease, "owner_instance_id", "") or "").strip() or None,
            owner_started_at=getattr(runtime_lease, "owner_started_at", None),
            generation=int(getattr(runtime_lease, "generation", 0) or 0),
            execution_epoch=int(
                getattr(runtime_lease, "execution_epoch", 0)
                or getattr(task, "execution_epoch", 0)
                or 0
            ),
        )

    def _dispatch_token_for_task(
        self,
        db: Session,
        task: BinarySecurityTask | None,
    ) -> str | None:
        if task is None:
            return None
        runtime_lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        runtime_token = self._runtime_lease_execution_token(task, runtime_lease)
        return runtime_token

    def _bind_execution_token(
        self,
        db: Session | BinarySecurityTask,
        task: BinarySecurityTask | None = None,
    ) -> str | None:
        if task is None:
            task = db
            setattr(task, "_runtime_lease_owner_started_at", None)
            setattr(task, "_runtime_lease_generation", None)
            setattr(task, "_runtime_lease_execution_epoch", None)
            setattr(task, "_execution_dispatcher_id", None)
            setattr(task, "_execution_token", None)
            return getattr(task, "_execution_token", None)
        assert task is not None
        runtime_lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        runtime_owner = (
            str(getattr(runtime_lease, "owner_instance_id", "") or "").strip() or None
            if runtime_lease is not None
            else None
        )
        setattr(task, "_runtime_lease_owner_started_at", getattr(runtime_lease, "owner_started_at", None) if runtime_lease is not None else None)
        setattr(task, "_runtime_lease_generation", int(getattr(runtime_lease, "generation", 0) or 0) if runtime_lease is not None else None)
        setattr(
            task,
            "_runtime_lease_execution_epoch",
            int(
                getattr(runtime_lease, "execution_epoch", 0)
                or getattr(task, "execution_epoch", 0)
                or 0
            ) if runtime_lease is not None else None,
        )
        setattr(task, "_execution_dispatcher_id", runtime_owner)
        setattr(task, "_execution_token", self._dispatch_token_for_task(db, task))
        return getattr(task, "_execution_token", None)

    def _ensure_owned_execution_current(self, task: BinarySecurityTask) -> None:
        expected_dispatcher_id = getattr(task, "_execution_dispatcher_id", None)
        expected_token = getattr(task, "_execution_token", None)
        if expected_dispatcher_id is None and expected_token is None:
            return
        if not expected_dispatcher_id or not expected_token:
            raise StaleTaskExecution(f"任务 {task.id} 缺少当前执行 token")
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task.id).first()
            ownership_snapshot = (
                self._parent_runtime_ownership_snapshot(session, row)
                if row is not None
                else None
            )
            current_token = self._dispatch_token_for_task(session, row) if row is not None else None
            if (
                row is None
                or (ownership_snapshot is None or ownership_snapshot.runtime_lease_owner != expected_dispatcher_id)
                or current_token != expected_token
                or not (ownership_snapshot and ownership_snapshot.runtime_lease_active)
            ):
                raise StaleTaskExecution(f"任务 {task.id} 当前执行 token 已失效")
        finally:
            session.close()

    def _ensure_task_execution_current(self, task: BinarySecurityTask) -> None:
        self._ensure_owned_execution_current(task)

    async def _ensure_task_execution_current_async(self, task: BinarySecurityTask) -> None:
        await asyncio.to_thread(self._ensure_task_execution_current, task)

    def _task_runtime_workset(self, task: BinarySecurityTask) -> dict[str, Any]:
        summary = dict(getattr(task, "summary", None) or {})
        workset = summary.get("runtime_workset")
        normalized = dict(workset) if isinstance(workset, dict) else {}
        for signal_name in (
            "pending_task_layer_reconcile",
            "pending_downstream_sync",
            "pending_archive_rebuild",
            "pending_cleanup_retry",
            "pending_binding_repair",
            "pending_tail_finalize",
            "pending_operation_repair",
        ):
            value = normalized.get(signal_name)
            if value is None:
                continue
            normalized[signal_name] = dict(value) if isinstance(value, dict) else {}
        return normalized

    def _set_task_runtime_workset(self, task: BinarySecurityTask, workset: dict[str, Any] | None) -> dict[str, Any]:
        summary = dict(getattr(task, "summary", None) or {})
        normalized = dict(workset or {})
        summary["runtime_workset"] = normalized
        task.summary = summary
        return normalized

    def _merge_task_runtime_signal(
        self,
        task: BinarySecurityTask,
        signal_name: str,
        *,
        source: str,
        reason: str,
        stage_name: str | None = None,
        item_ids: list[str] | None = None,
        archive_job_ids: list[str] | None = None,
        force: bool | None = None,
        next_retry_at: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        workset = self._task_runtime_workset(task)
        current = dict(workset.get(signal_name) or {})
        merged = {
            **current,
            **dict(extra or {}),
            "requested_at": current.get("requested_at") or _now().isoformat(),
            "last_requested_at": _now().isoformat(),
            "source": str(source or "").strip() or current.get("source") or "unknown",
            "reason": str(reason or "").strip() or current.get("reason") or "signal_requested",
            "stage_name": str(stage_name or "").strip() or current.get("stage_name") or None,
            "item_ids": sorted(
                {
                    str(value).strip()
                    for value in list(current.get("item_ids") or []) + list(item_ids or [])
                    if str(value).strip()
                }
            ),
            "archive_job_ids": sorted(
                {
                    str(value).strip()
                    for value in list(current.get("archive_job_ids") or []) + list(archive_job_ids or [])
                    if str(value).strip()
                }
            ),
            "attempts": int(current.get("attempts") or 0),
            "last_error": current.get("last_error"),
            "next_retry_at": next_retry_at or current.get("next_retry_at"),
        }
        if force is not None:
            merged["force"] = bool(force)
        workset[signal_name] = merged
        self._set_task_runtime_workset(task, workset)
        return merged

    def _clear_task_runtime_signal(self, task: BinarySecurityTask, signal_name: str) -> None:
        workset = self._task_runtime_workset(task)
        if signal_name in workset:
            workset.pop(signal_name, None)
            self._set_task_runtime_workset(task, workset)

    def _task_has_pending_cross_stage_sync(self, db: Session, task: BinarySecurityTask) -> bool:
        return bool(self._task_has_pending_cross_stage_downstream_sync(db, task))

    def _task_sync_request_dedupe_key(
        self,
        *,
        sync_kind: str,
        stage_name: str | None,
        item_ids: list[str] | None,
        archive_job_ids: list[str] | None,
    ) -> str:
        normalized_kind = str(sync_kind or "downstream_status").strip() or "downstream_status"
        normalized_stage = str(stage_name or "").strip() or "*"
        if normalized_kind in {"downstream_status", "binding_repair", "late_child_terminal_sync"}:
            return f"{normalized_kind}:{normalized_stage}:*:*"
        normalized_item_ids = ",".join(sorted({str(item_id).strip() for item_id in list(item_ids or []) if str(item_id).strip()})) or "*"
        normalized_archive_job_ids = ",".join(sorted({str(job_id).strip() for job_id in list(archive_job_ids or []) if str(job_id).strip()})) or "*"
        return f"{normalized_kind}:{normalized_stage}:{normalized_item_ids}:{normalized_archive_job_ids}"

    async def _enqueue_task_sync_request(
        self,
        task: BinarySecurityTask,
        *,
        db: Session | None = None,
        sync_kind: str,
        source: str,
        reason: str,
        stage_name: str | None = None,
        item_ids: list[str] | None = None,
        archive_job_ids: list[str] | None = None,
        force: bool = False,
        source_event_type: str | None = None,
        payload: dict[str, Any] | None = None,
        priority: int = 100,
    ) -> dict[str, Any]:
        requested_at = _now().isoformat()
        entry = {
            "sync_kind": str(sync_kind or "downstream_status").strip() or "downstream_status",
            "source": str(source or "").strip() or "unknown",
            "reason": str(reason or "").strip() or "sync_requested",
            "source_event_type": str(source_event_type or "").strip() or None,
            "stage_name": str(stage_name or "").strip() or None,
            "item_ids": [str(item_id).strip() for item_id in list(item_ids or []) if str(item_id).strip()],
            "archive_job_ids": [str(job_id).strip() for job_id in list(archive_job_ids or []) if str(job_id).strip()],
            "force": bool(force),
            "requested_at": requested_at,
            "last_requested_at": requested_at,
            "next_retry_at": requested_at,
            "attempts": 0,
            "priority": int(priority or 100),
            "payload": dict(payload or {}),
        }
        dedupe_key = self._task_sync_request_dedupe_key(
            sync_kind=entry["sync_kind"],
            stage_name=entry.get("stage_name"),
            item_ids=entry.get("item_ids"),
            archive_job_ids=entry.get("archive_job_ids"),
        )
        try:
            normalized_entry = await get_task_queue().enqueue_task_sync_request(
                task.id,
                entry,
                dedupe_key=dedupe_key,
                context="task_sync_enqueue",
            )
        except Exception as exc:
            if db is not None:
                self._record_event(
                    db,
                    task,
                    "task_sync_enqueue_failed_but_db_fact_retained",
                    "子任务同步请求入队失败，但 DB 中的同步事实仍保留，后续将自动补偿",
                    level="warning",
                    stage_name=entry.get("stage_name"),
                    payload={
                        "sync_kind": entry["sync_kind"],
                        "reason": entry["reason"],
                        "source": entry["source"],
                        "source_event_type": entry.get("source_event_type"),
                        "item_ids": list(entry.get("item_ids") or []),
                        "archive_job_ids": list(entry.get("archive_job_ids") or []),
                        "dedupe_key": dedupe_key,
                        "error_type": exc.__class__.__name__,
                        "error": str(exc),
                    },
                )
            raise
        if self._should_enqueue_parent_dispatch_for_task_sync(
            db,
            task,
            sync_kind=entry["sync_kind"],
            force=bool(entry["force"]),
        ):
            self._enqueue_task(task.id)
        return normalized_entry

    def _sync_request_entry_due(
        self,
        entry: dict[str, Any],
        *,
        now_value: datetime | None = None,
    ) -> bool:
        next_retry_at = self._parse_comparable_datetime(dict(entry or {}).get("next_retry_at"))
        if next_retry_at is None:
            return True
        return next_retry_at <= (now_value or _now())

    def _sync_request_blocked_by_budget_exhaustion(
        self,
        db: Session,
        task: BinarySecurityTask,
        entry: dict[str, Any],
    ) -> bool:
        item_ids = [str(item_id).strip() for item_id in list(dict(entry or {}).get("item_ids") or []) if str(item_id).strip()]
        if not item_ids:
            return False
        items = (
            db.query(BinarySecurityStageItem)
            .filter(
                BinarySecurityStageItem.task_id == task.id,
                BinarySecurityStageItem.id.in_(item_ids),
            )
            .all()
        )
        if not items:
            return False
        return all(self._stage_item_sync_error_budget_exhausted(item) for item in items)

    async def _reconcile_missing_task_sync_requests(self, db: Session, task: BinarySecurityTask) -> int:
        expected = self._build_expected_sync_requests_from_db(db, task)
        if not expected:
            return 0
        existing = await get_task_queue().list_task_sync_requests(task.id, context="task_sync_reconcile_list")
        existing_dedupe_keys = {
            str(entry.get("dedupe_key") or "").strip()
            for entry in existing
            if str(entry.get("dedupe_key") or "").strip()
        }
        now_value = _now()
        repaired = 0
        for entry in expected:
            dedupe_key = self._task_sync_request_dedupe_key(
                sync_kind=str(entry.get("sync_kind") or "").strip(),
                stage_name=entry.get("stage_name"),
                item_ids=entry.get("item_ids"),
                archive_job_ids=entry.get("archive_job_ids"),
            )
            if dedupe_key in existing_dedupe_keys:
                continue
            if not self._sync_request_entry_due(entry, now_value=now_value):
                continue
            if self._sync_request_blocked_by_budget_exhaustion(db, task, entry):
                continue
            await self._enqueue_task_sync_request(
                task,
                db=db,
                sync_kind=str(entry.get("sync_kind") or "").strip(),
                source="task_sync_reconcile",
                reason=str(entry.get("reason") or "repair_missing_or_stale_sync_queue_entry").strip(),
                stage_name=entry.get("stage_name"),
                item_ids=list(entry.get("item_ids") or []),
                archive_job_ids=list(entry.get("archive_job_ids") or []),
                force=bool(entry.get("force")),
                source_event_type=str(entry.get("source_event_type") or "task_sync_queue_repair").strip(),
                payload={
                    **dict(entry.get("payload") or {}),
                    "repair_source": "task_sync_reconcile",
                },
                priority=int(entry.get("priority") or 100),
            )
            self._record_event(
                db,
                task,
                "task_sync_request_reconcile_requeued",
                "子任务同步请求缺失，已按 DB 事实重新补回队列",
                stage_name=entry.get("stage_name"),
                payload={
                    "sync_kind": entry.get("sync_kind"),
                    "reason": entry.get("reason"),
                    "item_ids": list(entry.get("item_ids") or []),
                    "archive_job_ids": list(entry.get("archive_job_ids") or []),
                    "dedupe_key": dedupe_key,
                },
            )
            repaired += 1
            existing_dedupe_keys.add(dedupe_key)
        return repaired

    def _build_expected_sync_requests_from_db(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> list[dict[str, Any]]:
        expected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in self._task_reconcile_candidate_items(
            db,
            task,
            force=False,
            include_failed_terminal_items=True,
        ):
            normalized_stage = str(normalize_stage_name(item.stage_name) or "").strip() or None
            observed_status = self._latest_observed_downstream_status(item)
            needs_binding_repair = self._item_needs_downstream_binding_reconcile(item)
            needs_sync = self._item_needs_downstream_sync(
                item,
                for_task_status=str(task.status or "").strip().lower() or None,
            )
            missing_recorded_status = self._item_missing_recorded_downstream_status(item)
            if not (needs_binding_repair or needs_sync or missing_recorded_status):
                continue
            sync_kind = "binding_repair" if needs_binding_repair else "late_child_terminal_sync" if (
                observed_status in {"success", "failed", "partial_success", "cancelled", "downstream_missing"}
                and (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower())
                not in {"success", "failed", "partial_success", "cancelled", "downstream_missing"}
            ) else "downstream_status"
            entry = {
                "sync_kind": sync_kind,
                "source": "db_repair",
                "reason": "repair_missing_or_stale_sync_queue_entry",
                "source_event_type": "task_sync_queue_repair",
                "stage_name": normalized_stage,
                "item_ids": [str(item.id or "").strip()] if str(item.id or "").strip() else [],
                "archive_job_ids": [],
                "force": bool(needs_binding_repair or missing_recorded_status),
                "payload": {
                    "item_key": str(item.item_key or "").strip() or None,
                    "downstream_task_id": str(item.downstream_task_id or "").strip() or None,
                    "observed_downstream_status": observed_status,
                    "cross_stage_sync": bool(normalized_stage and normalized_stage != str(normalize_stage_name(task.current_stage) or "").strip()),
                },
                "priority": 10 if needs_binding_repair else 20 if missing_recorded_status else 30,
            }
            dedupe_key = self._task_sync_request_dedupe_key(
                sync_kind=entry["sync_kind"],
                stage_name=entry.get("stage_name"),
                item_ids=entry.get("item_ids"),
                archive_job_ids=entry.get("archive_job_ids"),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            expected.append(entry)
        return expected

    async def _repair_task_sync_queue_on_runtime_start(self, db: Session, task: BinarySecurityTask) -> int:
        owner_token = f"{self.instance_id}:{task.id}:{uuid.uuid4().hex[:12]}"
        acquired = await get_task_queue().acquire_task_sync_repair_lock(
            task.id,
            owner_token,
            ttl_seconds=max(5, int(getattr(self.cfg.queue, "block_timeout_seconds", 5) or 5) * 6),
            context="task_sync_repair_lock",
        )
        if not acquired:
            return 0
        try:
            expected = self._build_expected_sync_requests_from_db(db, task)
            existing = await get_task_queue().list_task_sync_requests(task.id, context="task_sync_repair_list")
            existing_dedupe_keys = {str(entry.get("dedupe_key") or "").strip() for entry in existing if str(entry.get("dedupe_key") or "").strip()}
            repaired = 0
            for entry in expected:
                dedupe_key = self._task_sync_request_dedupe_key(
                    sync_kind=str(entry.get("sync_kind") or "").strip(),
                    stage_name=entry.get("stage_name"),
                    item_ids=entry.get("item_ids"),
                    archive_job_ids=entry.get("archive_job_ids"),
                )
                if dedupe_key in existing_dedupe_keys:
                    continue
                await self._enqueue_task_sync_request(
                    task,
                    db=db,
                    sync_kind=str(entry.get("sync_kind") or "").strip(),
                    source="runtime_start_repair",
                    reason=str(entry.get("reason") or "repair_missing_or_stale_sync_queue_entry").strip(),
                    stage_name=entry.get("stage_name"),
                    item_ids=list(entry.get("item_ids") or []),
                    archive_job_ids=list(entry.get("archive_job_ids") or []),
                    force=bool(entry.get("force")),
                    source_event_type=str(entry.get("source_event_type") or "task_sync_queue_repair").strip(),
                    payload=dict(entry.get("payload") or {}),
                    priority=int(entry.get("priority") or 100),
                )
                repaired += 1
            return repaired
        finally:
            await get_task_queue().release_task_sync_repair_lock(task.id, owner_token, context="task_sync_repair_unlock")

    async def _migrate_legacy_pending_sync_signal_to_redis_queue(
        self,
        task: BinarySecurityTask,
        signal: dict[str, Any],
    ) -> dict[str, Any] | None:
        stage_name = str(signal.get("stage_name") or "").strip() or None
        item_ids = [str(item_id).strip() for item_id in list(signal.get("item_ids") or []) if str(item_id).strip()]
        archive_job_ids = [str(job_id).strip() for job_id in list(signal.get("archive_job_ids") or []) if str(job_id).strip()]
        sync_kind = "binding_repair" if str(signal.get("reason") or "").strip() in {"binding_repair", "stale_binding_repair"} else "downstream_status"
        source_event_type = str(signal.get("source_event_type") or "").strip() or (
            "legacy_pending_binding_repair" if sync_kind == "binding_repair" else "legacy_pending_downstream_sync"
        )
        return await self._enqueue_task_sync_request(
            task,
            db=None,
            sync_kind=sync_kind,
            source=str(signal.get("source") or "legacy_runtime_workset").strip() or "legacy_runtime_workset",
            reason=str(signal.get("reason") or ("legacy_pending_binding_repair" if sync_kind == "binding_repair" else "legacy_pending_downstream_sync")).strip()
            or ("legacy_pending_binding_repair" if sync_kind == "binding_repair" else "legacy_pending_downstream_sync"),
            stage_name=stage_name,
            item_ids=item_ids,
            archive_job_ids=archive_job_ids,
            force=bool(signal.get("force")),
            source_event_type=source_event_type,
            payload={
                "migrated_from_runtime_workset": True,
                "legacy_signal": True,
                "legacy_signal_kind": sync_kind,
            },
            priority=50,
        )

    async def _drain_task_sync_queue(self, db: Session, task: BinarySecurityTask) -> bool:
        await self._repair_task_sync_queue_on_runtime_start(db, task)
        await self._reconcile_missing_task_sync_requests(db, task)
        entry = await get_task_queue().pop_task_sync_request(task.id, context="task_sync_pop")
        if entry is None:
            return False
        queue_item_id = str(entry.get("queue_item_id") or "").strip()
        dedupe_key = str(entry.get("dedupe_key") or "").strip() or None
        stage_name = str(entry.get("stage_name") or "").strip() or None
        item_ids = [str(item_id).strip() for item_id in list(entry.get("item_ids") or []) if str(item_id).strip()]
        force = bool(entry.get("force"))
        sync_kind = str(entry.get("sync_kind") or "downstream_status").strip() or "downstream_status"
        try:
            if sync_kind == "binding_repair":
                repaired = self._repair_replacement_binding_state_for_task(db, task)
                db.commit()
                if repaired:
                    await get_task_queue().ack_task_sync_request(
                        task.id,
                        queue_item_id=queue_item_id,
                        dedupe_key=dedupe_key,
                        context="task_sync_ack",
                    )
                    return True
            sync_db = get_session_factory()()
            try:
                await self.sync_downstream_status(
                    sync_db,
                    project_id=task.project_id,
                    task_id=task.id,
                    stage_name=stage_name,
                    item_ids=item_ids or None,
                    force=force,
                    token=self._service_token(),
                    record_request_event=False,
                    apply_state=True,
                )
            finally:
                sync_db.close()
            await get_task_queue().ack_task_sync_request(
                task.id,
                queue_item_id=queue_item_id,
                dedupe_key=dedupe_key,
                context="task_sync_ack",
            )
            return True
        except Exception as exc:
            missing_item_ids: list[str] = []
            existing_item_ids: list[str] = []
            should_discard_invalid_entry = False
            should_requeue_filtered_entry = False
            should_ack_stale_entry = False
            if isinstance(exc, NotFoundError):
                existing_item_ids, missing_item_ids = self._resolve_task_sync_entry_item_targets(db, task, entry)
                should_discard_invalid_entry = bool(missing_item_ids)
                should_requeue_filtered_entry = bool(existing_item_ids and missing_item_ids)
                should_ack_stale_entry, existing_item_ids, missing_item_ids = self._should_ack_stale_task_sync_entry_without_retry(
                    db,
                    task,
                    exc,
                    entry,
                )
            elif self._should_discard_terminal_task_sync_entry(db, task, exc, entry):
                existing_item_ids, missing_item_ids = self._resolve_task_sync_entry_item_targets(db, task, entry)
                should_discard_invalid_entry = True
            if should_ack_stale_entry:
                stale_stage_items: list[BinarySecurityStageItem] = []
                if existing_item_ids:
                    stale_stage_items = (
                        db.query(BinarySecurityStageItem)
                        .filter(
                            BinarySecurityStageItem.task_id == task.id,
                            BinarySecurityStageItem.id.in_(existing_item_ids),
                        )
                        .all()
                    )
                message = "检测到旧的任务同步消息命中的子任务当前已无需再次同步，已记录并丢弃当前消费"
                for stage_item in stale_stage_items:
                    self._record_downstream_sync_event(
                        db,
                        task=task,
                        item=stage_item,
                        stage_name=str(getattr(stage_item, "stage_name", "") or "").strip() or stage_name,
                        operation=sync_kind,
                        event_type="skipped",
                        sync_status="skipped",
                        outcome="stale_sync_request_discarded",
                        state_applied=False,
                        error_type="stale_sync_request",
                        error_message=message,
                        payload={
                            "operation": sync_kind,
                            "queue_item_id": queue_item_id,
                            "dedupe_key": dedupe_key,
                            "item_ids": item_ids,
                            "existing_item_ids": existing_item_ids,
                            "missing_item_ids": missing_item_ids,
                            "source": str(entry.get("source") or "").strip() or None,
                            "reason": str(entry.get("reason") or "").strip() or None,
                            "source_event_type": str(entry.get("source_event_type") or "").strip() or None,
                            "attempts": int(entry.get("attempts") or 0),
                            "error_type": exc.__class__.__name__,
                            "error": str(exc),
                            "disposition": "acked_as_stale_noop",
                            "item_status": str(getattr(stage_item, "status", "") or "").strip() or None,
                            "downstream_service": str(getattr(stage_item, "downstream_service", "") or "").strip() or None,
                            "downstream_task_id": str(getattr(stage_item, "downstream_task_id", "") or "").strip() or None,
                        },
                    )
                self._record_event(
                    db,
                    task,
                    "task_sync_request_discarded_as_stale_noop",
                    message,
                    level="warning",
                    stage_name=stage_name,
                    payload={
                        "sync_kind": sync_kind,
                        "queue_item_id": queue_item_id,
                        "dedupe_key": dedupe_key,
                        "item_ids": item_ids,
                        "existing_item_ids": existing_item_ids,
                        "missing_item_ids": missing_item_ids,
                        "source": str(entry.get("source") or "").strip() or None,
                        "reason": str(entry.get("reason") or "").strip() or None,
                        "source_event_type": str(entry.get("source_event_type") or "").strip() or None,
                        "attempts": int(entry.get("attempts") or 0),
                        "error_type": exc.__class__.__name__,
                        "error": str(exc),
                        "disposition": "acked_as_stale_noop",
                    },
                )
                db.commit()
                await get_task_queue().ack_task_sync_request(
                    task.id,
                    queue_item_id=queue_item_id,
                    dedupe_key=dedupe_key,
                    context="task_sync_ack_stale_noop",
                )
                logger.warning(
                    "binary-security discarded stale task sync request after recording noop task event: "
                    "task_id=%s queue_item_id=%s stage_name=%s item_ids=%s existing_item_ids=%s error_type=%s error=%s",
                    task.id,
                    queue_item_id,
                    stage_name,
                    item_ids,
                    existing_item_ids,
                    exc.__class__.__name__,
                    str(exc),
                )
                return True
            if should_discard_invalid_entry:
                self._record_event(
                    db,
                    task,
                    "task_sync_request_discarded_after_invalid_item_error",
                    "检测到无效的任务同步消息，已记录并丢弃当前消费，避免持续阻塞后续同步",
                    level="warning",
                    stage_name=stage_name,
                    payload={
                        "sync_kind": sync_kind,
                        "queue_item_id": queue_item_id,
                        "dedupe_key": dedupe_key,
                        "item_ids": item_ids,
                        "existing_item_ids": existing_item_ids,
                        "missing_item_ids": missing_item_ids,
                        "source": str(entry.get("source") or "").strip() or None,
                        "reason": str(entry.get("reason") or "").strip() or None,
                        "source_event_type": str(entry.get("source_event_type") or "").strip() or None,
                        "attempts": int(entry.get("attempts") or 0),
                        "error_type": exc.__class__.__name__,
                        "error": str(exc),
                        "disposition": "acked_and_filtered" if should_requeue_filtered_entry else "acked_and_discarded",
                    },
                )
                db.commit()
                await get_task_queue().ack_task_sync_request(
                    task.id,
                    queue_item_id=queue_item_id,
                    dedupe_key=dedupe_key,
                    context="task_sync_ack_terminal_discard",
                )
                if should_requeue_filtered_entry:
                    await self._enqueue_task_sync_request(
                        task,
                        db=db,
                        sync_kind=sync_kind,
                        source=str(entry.get("source") or "task_sync_invalid_item_filter").strip() or "task_sync_invalid_item_filter",
                        reason=str(entry.get("reason") or "invalid_item_ids_filtered_after_pop").strip() or "invalid_item_ids_filtered_after_pop",
                        stage_name=stage_name,
                        item_ids=existing_item_ids,
                        archive_job_ids=[str(job_id).strip() for job_id in list(entry.get("archive_job_ids") or []) if str(job_id).strip()],
                        force=force,
                        source_event_type=str(entry.get("source_event_type") or "invalid_item_ids_filtered_after_pop").strip() or "invalid_item_ids_filtered_after_pop",
                        payload={
                            **dict(entry.get("payload") or {}),
                            "filtered_missing_item_ids": missing_item_ids,
                            "recovered_existing_item_ids": existing_item_ids,
                            "requeued_from_queue_item_id": queue_item_id,
                            "requeued_from_dedupe_key": dedupe_key,
                        },
                        priority=int(entry.get("priority") or 100),
                    )
                logger.warning(
                    "binary-security discarded invalid task sync request after recording task event: "
                    "task_id=%s queue_item_id=%s stage_name=%s item_ids=%s existing_item_ids=%s missing_item_ids=%s error_type=%s error=%s",
                    task.id,
                    queue_item_id,
                    stage_name,
                    item_ids,
                    existing_item_ids,
                    missing_item_ids,
                    exc.__class__.__name__,
                    str(exc),
                )
                return True
            retry_seconds = max(5, min(60, 5 * (2 ** min(5, int(entry.get("attempts") or 0)))))
            retry_at = _now() + timedelta(seconds=retry_seconds)
            retry_entry = {
                **dict(entry),
                "attempts": int(entry.get("attempts") or 0) + 1,
                "last_error": str(exc),
                "next_retry_at": retry_at.isoformat(),
            }
            try:
                await get_task_queue().retry_task_sync_request(task.id, retry_entry, context="task_sync_retry")
            except Exception as retry_exc:
                item_ids = [str(item_id).strip() for item_id in list(retry_entry.get("item_ids") or []) if str(item_id).strip()]
                stage_items: list[BinarySecurityStageItem] = []
                if item_ids:
                    stage_items = (
                        db.query(BinarySecurityStageItem)
                        .filter(
                            BinarySecurityStageItem.task_id == task.id,
                            BinarySecurityStageItem.id.in_(item_ids),
                        )
                        .all()
                    )
                sync_error_type = self._classify_downstream_sync_error(exc)
                sync_error_message = str(exc)
                for stage_item in stage_items:
                    state = self._build_next_downstream_sync_failure_state(stage_item, observed_at=retry_at)
                    self._persist_child_sync_observation(
                        db,
                        task=task,
                        item=stage_item,
                        change_source="task_sync_retry_enqueue_failed",
                        sync_status="transport_error" if sync_error_type == "UpstreamError" else "observed",
                        synced_at=retry_at,
                        error_message=sync_error_message,
                        error_type=sync_error_type,
                        status_raw=self._stage_item_observed_downstream_status(stage_item),
                        mapped_status=self._normalize_downstream_status(self._stage_item_observed_downstream_status(stage_item)),
                        downstream_status=self._stage_item_observed_downstream_status(stage_item),
                        state_applied=False,
                        consecutive_error_count=state.consecutive_error_count,
                        budget_exhausted=state.budget_exhausted,
                        next_retry_at=state.next_retry_at,
                        last_sync_result="error",
                        extra_payload={
                            "operation": "downstream_sync",
                            "queue_item_id": queue_item_id,
                            "retry_enqueue_error": str(retry_exc),
                            "retry_enqueue_error_type": retry_exc.__class__.__name__,
                            "retry_seconds": retry_seconds,
                        },
                    )
                self._record_event(
                    db,
                    task,
                    "task_sync_retry_enqueue_failed_but_db_retry_persisted",
                    "子任务同步重试入队失败，但重试事实已写入 DB，后续将自动补偿",
                    level="warning",
                    stage_name=stage_name,
                    payload={
                        "sync_kind": sync_kind,
                        "item_ids": item_ids,
                        "queue_item_id": queue_item_id,
                        "dedupe_key": dedupe_key,
                        "next_retry_at": retry_entry.get("next_retry_at"),
                        "error_type": exc.__class__.__name__,
                        "error": str(exc),
                        "retry_enqueue_error_type": retry_exc.__class__.__name__,
                        "retry_enqueue_error": str(retry_exc),
                    },
                )
            raise

    def _resolve_task_sync_entry_item_targets(
        self,
        db: Session,
        task: BinarySecurityTask,
        entry: dict[str, Any],
    ) -> tuple[list[str], list[str]]:
        item_ids = [str(item_id).strip() for item_id in list(entry.get("item_ids") or []) if str(item_id).strip()]
        single_item_id = str(entry.get("item_id") or "").strip()
        if single_item_id:
            item_ids.append(single_item_id)
        if item_ids:
            item_ids = list(dict.fromkeys(item_ids))
        if not item_ids:
            return [], []
        stage_name = str(entry.get("stage_name") or "").strip() or None
        query = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.id.in_(item_ids),
        )
        if stage_name:
            query = query.filter(BinarySecurityStageItem.stage_name == stage_name)
        existing_item_ids = [
            str(getattr(stage_item, "id", "") or "").strip()
            for stage_item in query.all()
            if str(getattr(stage_item, "id", "") or "").strip()
        ]
        existing_set = set(existing_item_ids)
        missing_item_ids = [item_id for item_id in item_ids if item_id not in existing_set]
        return existing_item_ids, missing_item_ids

    def _should_discard_terminal_task_sync_entry(
        self,
        db: Session,
        task: BinarySecurityTask,
        exc: Exception,
        entry: dict[str, Any],
    ) -> bool:
        if not isinstance(exc, NotFoundError):
            return False
        item_ids = [str(item_id).strip() for item_id in list(entry.get("item_ids") or []) if str(item_id).strip()]
        single_item_id = str(entry.get("item_id") or "").strip()
        if single_item_id:
            item_ids.append(single_item_id)
        if item_ids:
            item_ids = list(dict.fromkeys(item_ids))
        if not item_ids:
            return False
        existing_item_ids, _missing_item_ids = self._resolve_task_sync_entry_item_targets(db, task, entry)
        return not existing_item_ids

    def _should_ack_stale_task_sync_entry_without_retry(
        self,
        db: Session,
        task: BinarySecurityTask,
        exc: Exception,
        entry: dict[str, Any],
    ) -> tuple[bool, list[str], list[str]]:
        if not isinstance(exc, NotFoundError):
            return False, [], []
        existing_item_ids, missing_item_ids = self._resolve_task_sync_entry_item_targets(db, task, entry)
        if not existing_item_ids or missing_item_ids:
            return False, existing_item_ids, missing_item_ids
        stage_name = str(entry.get("stage_name") or "").strip() or None
        force = bool(entry.get("force"))
        for item in self._task_reconcile_candidate_items(
            db,
            task,
            stage_name=stage_name,
            force=force,
        ):
            item_id = str(getattr(item, "id", "") or "").strip()
            if item_id and item_id in existing_item_ids:
                return False, existing_item_ids, missing_item_ids
        return True, existing_item_ids, missing_item_ids

    def _has_task_write_ownership(
        self,
        task: BinarySecurityTask,
        db: Session | None = None,
        *,
        allow_dispatching: bool = False,
    ) -> bool:
        del allow_dispatching
        if db is None:
            session = get_session_factory()()
            try:
                db = session
                snapshot = self._parent_runtime_ownership_snapshot(db, task)
            finally:
                session.close()
        else:
            snapshot = self._parent_runtime_ownership_snapshot(db, task)
        if snapshot.runtime_lease_owner != str(self.instance_id or "").strip():
            return False
        if not snapshot.runtime_lease_active:
            return False
        return True

    def _ensure_task_write_ownership(
        self,
        task: BinarySecurityTask,
        db: Session | None = None,
        *,
        allow_dispatching: bool = False,
    ) -> None:
        if not self._has_task_write_ownership(task, db=db, allow_dispatching=allow_dispatching):
            raise StaleTaskExecution(f"任务 {task.id} 当前 owner/lease 已失效，禁止继续写入状态")

    def _has_local_runtime_owner_fast_path(
        self,
        task: BinarySecurityTask,
        db: Session | None = None,
    ) -> bool:
        if not self._has_local_task_execution_owner(str(getattr(task, "id", "") or "").strip()):
            return False
        return self._lease_is_active(task, db=db)

    async def _ensure_task_write_ownership_async(
        self,
        task: BinarySecurityTask,
        db: Session | None = None,
        *,
        allow_dispatching: bool = False,
    ) -> None:
        await asyncio.to_thread(
            self._ensure_task_write_ownership,
            task,
            db,
            allow_dispatching=allow_dispatching,
        )

    def _invalidate_task_execution(self, task: BinarySecurityTask, *, force: bool = False) -> None:
        if not force and str(getattr(task, "current_operation_id", "") or "").strip():
            self._last_task_heartbeat_at.pop(task.id, None)
            return
        setattr(task, "_execution_dispatcher_id", None)
        setattr(task, "_execution_token", None)
        setattr(task, "_runtime_lease_owner_started_at", None)
        setattr(task, "_runtime_lease_generation", None)
        setattr(task, "_runtime_lease_execution_epoch", None)
        self._last_task_heartbeat_at.pop(task.id, None)

    def _task_has_active_streaming_stage_workers(self, task_id: str) -> bool:
        if self._task_execution_owner_count(task_id) > 0:
            with self._task_execution_owner_lock:
                owners = set(self._task_execution_owners.get(task_id) or ())
            if any(owner.startswith("streaming_stage_item:") for owner in owners):
                return True
        active_worker_item_ids = {
            str(item_id or "")
            for item_id, worker in self._stage_item_workers.items()
            if not worker.done() and str(item_id or "").strip()
        }
        if not active_worker_item_ids:
            return False
        session = get_session_factory()()
        try:
            active_item_ids = {
                str(row.id)
                for row in session.query(BinarySecurityStageItem).filter(
                    BinarySecurityStageItem.task_id == task_id,
                    BinarySecurityStageItem.stage_name.in_(list(STREAMING_TAIL_STAGES)),
                    BinarySecurityStageItem.status.in_(list(STREAMING_ACTIVE_ITEM_STATUSES)),
                ).all()
            }
        finally:
            session.close()
        if not active_item_ids:
            return False
        return bool(active_worker_item_ids.intersection(active_item_ids))

    def _streaming_tail_active_context(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[str | None, int, bool]:
        summary = self._tail_stage_work_summary(db, task)
        return (
            summary.get("active_stage_name"),
            int(summary.get("unbound_runnable_item_count", 0) or 0) + int(summary.get("bound_active_item_count", 0) or 0),
            bool(summary.get("has_downstream_refs")),
        )

    def _task_has_active_streaming_tail_state(self, db: Session, task: BinarySecurityTask) -> bool:
        _, active_item_count, _ = self._streaming_tail_active_context(db, task)
        return active_item_count > 0

    def _recover_streaming_parent_running_state_locked(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        record_event: bool = False,
        reason: str | None = None,
    ) -> bool:
        summary = self._tail_stage_work_summary(db, task)
        active_stage_name = summary.get("active_stage_name")
        active_item_count = int(summary.get("unbound_runnable_item_count", 0) or 0) + int(summary.get("bound_active_item_count", 0) or 0)
        has_downstream_refs = bool(summary.get("has_downstream_refs"))
        if active_item_count <= 0:
            return False
        previous_status = str(task.status or "").strip()
        self._apply_active_owned_execution_main_state(
            db,
            task,
            status="running",
            reason="流式尾段存在活跃子项，父任务恢复为运行态",
            source="task_manager",
            stage_name=active_stage_name or task.current_stage,
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            finished_at=None,
            last_error=None,
        )
        task.tail_reconcile_state = "idle"
        self._clear_task_abnormal_reason_snapshot(db, task)
        if record_event:
            self._record_event(
                db,
                task,
                "streaming_parent_state_recovered",
                f"流式尾段存在活跃子项，父任务状态已收敛为 running: {task.current_stage}",
                level="warning",
                stage_name=task.current_stage,
                payload={
                    "from_status": previous_status,
                    "to_status": task.status,
                    "active_stage_name": task.current_stage,
                    "active_item_count": active_item_count,
                    "had_downstream_refs": has_downstream_refs,
                    "tail_control_mode": summary.get("tail_control_mode"),
                    "runtime_lease_established": self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    "reason": reason,
                },
            )
            observe_streaming_parent_recovered(
                stage=str(task.current_stage or "unknown"),
                from_status=previous_status or "unknown",
            )
        return True

    def _release_streaming_parent_for_takeover_locked(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        runtime_lease_owner: str | None,
        runtime_lease_expires_at: datetime | None,
        reason: str,
        signal_takeover: bool = False,
    ) -> bool:
        summary = self._tail_stage_work_summary(db, task)
        active_stage_name = summary.get("active_stage_name")
        active_item_count = int(summary.get("unbound_runnable_item_count", 0) or 0) + int(summary.get("bound_active_item_count", 0) or 0)
        has_downstream_refs = bool(summary.get("has_downstream_refs"))
        if active_item_count <= 0:
            return False
        previous_status = str(task.status or "").strip() or "running"
        self._apply_release_for_takeover_main_state(
            db,
            task,
            source="task_manager",
            reason="运行实例租约失效，父任务释放并重新排队等待接管",
            status="pending",
            stage_name=active_stage_name or task.current_stage,
            finished_at=None,
            last_error=None,
        )
        lease_owner_to_clear = str(runtime_lease_owner or "").strip() or None
        lease_clear_result = (
            self._clear_runtime_lease(
                db,
                task.id,
                owner_instance_id=lease_owner_to_clear,
                swallow_lock_error=True,
            )
            if lease_owner_to_clear
            else RuntimeLeaseClearResult(
                status="lease_missing",
                deleted_count=0,
                owner_instance_id=None,
                task_id=task.id,
            )
        )
        self._clear_task_abnormal_reason_snapshot(db, task)
        release_event_type = "dispatching_execution_released_for_takeover" if previous_status == "dispatching" else "running_execution_released_for_takeover"
        release_message = (
            "调度实例租约已失效，父任务已释放并重新排队，等待新的 worker 继续推进尾段执行"
            if previous_status == "dispatching"
            else "运行实例租约已失效，父任务已释放并重新排队，等待新的 worker 继续推进尾段执行"
        )
        self._record_event(
            db,
            task,
            release_event_type,
            release_message,
            level="warning",
            stage_name=task.current_stage,
            payload={
                "previous_status": previous_status,
                "stage_name": task.current_stage,
                "runtime_lease_owner": runtime_lease_owner,
                "runtime_lease_expires_at": _isoformat_or_none(runtime_lease_expires_at),
                "active_item_count": active_item_count,
                "has_downstream_refs": has_downstream_refs,
                "tail_control_mode": summary.get("tail_control_mode"),
                "requeue_reason": reason,
                "runtime_lease_clear_status": lease_clear_result.status,
            },
        )
        if signal_takeover:
            self._signal_owned_execution_takeover(
                db,
                task,
                stage_name=task.current_stage,
                reason=reason,
                message="检测到 dispatching owner 已失效，已重新排队等待新的 worker 接管尾段执行",
                event_payload={
                    "previous_status": previous_status,
                    "runtime_lease_owner": runtime_lease_owner,
                    "runtime_lease_expires_at": _isoformat_or_none(runtime_lease_expires_at),
                    "active_item_count": active_item_count,
                    "has_downstream_refs": has_downstream_refs,
                    "tail_control_mode": summary.get("tail_control_mode"),
                },
            )
        return True

    def _delete_stage_items_for_stages(
        self,
        db: Session,
        task_id: str,
        stage_names: list[str],
        *,
        batch_size: int = 100,
        max_retries: int = 3,
    ) -> int:
        normalized = self._expand_stage_name_aliases(stage_names)
        if not normalized:
            return 0
        if hasattr(db, "stage_items") and isinstance(getattr(db, "stage_items"), list):
            allowed_stage_names = set(normalized)
            matching = [
                row
                for row in db.stage_items
                if str(getattr(row, "task_id", "") or "").strip() == task_id
                and str(getattr(row, "stage_name", "") or "").strip() in allowed_stage_names
            ]
            if matching:
                db.stage_items = [row for row in db.stage_items if row not in matching]
                return len(matching)
        deleted = 0
        while True:
            item_ids = [
                row[0]
                for row in db.query(BinarySecurityStageItem.id)
                .filter(
                    BinarySecurityStageItem.task_id == task_id,
                    BinarySecurityStageItem.stage_name.in_(normalized),
                )
                .order_by(BinarySecurityStageItem.created_at.asc(), BinarySecurityStageItem.id.asc())
                .limit(max(1, int(batch_size)))
                .all()
            ]
            if not item_ids:
                if hasattr(db, "stage_items") and isinstance(getattr(db, "stage_items"), list):
                    allowed_stage_names = set(normalized)
                    db.stage_items = [
                        row for row in db.stage_items
                        if not (
                            str(getattr(row, "task_id", "") or "").strip() == task_id
                            and str(getattr(row, "stage_name", "") or "").strip() in allowed_stage_names
                        )
                    ]
                return deleted
            for attempt in range(max(1, int(max_retries))):
                try:
                    with self._savepoint(db):
                        deleted += int(
                            db.query(BinarySecurityStageItem)
                            .filter(BinarySecurityStageItem.id.in_(item_ids))
                            .delete(synchronize_session=False)
                            or 0
                        )
                        db.flush()
                    break
                except OperationalError as exc:
                    if not self._is_retryable_lock_error(exc) or attempt >= max(1, int(max_retries)) - 1:
                        raise
                    time.sleep(0.2 * (attempt + 1))
    def _delete_stage_items_by_ids(self, db: Session, item_ids: list[str]) -> int:
        normalized = [str(item_id or "").strip() for item_id in item_ids if str(item_id or "").strip()]
        if not normalized:
            return 0
        return int(
            db.query(BinarySecurityStageItem)
            .filter(BinarySecurityStageItem.id.in_(normalized))
            .delete(synchronize_session=False)
            or 0
        )

    def _stage_enabled(self, task: BinarySecurityTask, stage_name: str) -> bool:
        stage_name = normalize_stage_name(stage_name)
        policy = task.policy or {}
        stage_options = policy.get("stage_options", {})
        option = stage_options.get(stage_name)
        if option is None:
            return True
        return bool(option.get("enabled", True))

    def _b2s_execution_mode(self, task: BinarySecurityTask) -> tuple[str | None, str | None]:
        policy = task.policy or {}
        stage_options = policy.get("stage_options", {}) if isinstance(policy.get("stage_options"), dict) else {}
        option = stage_options.get("binary_to_source") if isinstance(stage_options.get("binary_to_source"), dict) else {}
        raw_mode = option.get("mode") or policy.get("b2s_mode")
        mode = str(raw_mode or "").strip().lower()
        if not mode:
            return None, None
        if mode == "turbo":
            return "turbo", "turbo"
        if mode in {"deep", "agent"}:
            return "deep", "agent"
        if mode in {"fast", "hybrid"}:
            return "fast", "hybrid"
        return None, None

    def _pipeline_mode(self, task: BinarySecurityTask | dict[str, Any] | None) -> str:
        if isinstance(task, dict):
            policy = task
        else:
            policy = (getattr(task, "policy", None) if task is not None else {}) or {}
            if not policy and task is not None:
                raw_policy = getattr(task, "policy_json", None)
                if isinstance(raw_policy, str) and raw_policy.strip():
                    try:
                        parsed_policy = json.loads(raw_policy)
                    except Exception:
                        parsed_policy = {}
                    if isinstance(parsed_policy, dict):
                        policy = parsed_policy
        value = policy.get("pipeline_mode")
        if value is None:
            value = getattr(self.cfg.runtime_policy, "pipeline_mode", PIPELINE_MODE_BARRIER)
        return _normalize_pipeline_mode(value)

    def _streaming_mode_enabled(self, task: BinarySecurityTask | dict[str, Any] | None) -> bool:
        return self._pipeline_mode(task) == PIPELINE_MODE_MIXED_STREAMING

    def _streaming_tail_stage_names(self, task: BinarySecurityTask) -> tuple[str, ...]:
        stage_sequence = self._stage_sequence_for_task(task)
        task_type = self._task_type(task)
        if task_type in {TASK_TYPE_BINARY, TASK_TYPE_BINARY_MODULE}:
            candidate_tail_stages = ("binary_to_source", "entry_analysis", "dataflow_vuln_scan")
        else:
            candidate_tail_stages = STREAMING_TAIL_STAGES
        return tuple(
            stage_name
            for stage_name in candidate_tail_stages
            if stage_name in stage_sequence and self._stage_enabled(task, stage_name)
        )

    def _is_streaming_tail_stage(self, task: BinarySecurityTask, stage_name: str | None) -> bool:
        normalized = str(stage_name or "").strip()
        return bool(normalized) and normalized in self._streaming_tail_stage_names(task)

    def _streaming_has_active_upstream_stage(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_runs: list[BinarySecurityStageRun],
    ) -> tuple[bool, str | None, str | None]:
        if not self._streaming_mode_enabled(task):
            return False, None, None
        active_statuses = {"pending", "queued", "running", "dispatching", "applying"}
        active_candidates: list[tuple[str, str]] = []
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            if self._is_streaming_tail_stage(task, stage_name):
                continue
            stage_start_allowed = bool(self._evaluate_stage_start_gate(db, task, stage_name).get("allowed"))
            stage_items = self._stage_items(db, task.id, stage_name)
            has_real_active_progress = bool(
                self._stage_has_active_items(stage_items)
                or self._stage_has_live_downstream_children(stage_items)
                or self._stage_has_real_runnable_work(db, task, stage_name)
                or self._stage_has_unresolved_expected_outputs(db, task, stage_name, None, stage_items)
            )
            stage_candidates = [
                run
                for run in stage_runs
                if normalize_stage_name(run.stage_name) == normalize_stage_name(stage_name)
            ]
            if not stage_candidates:
                continue
            for run in sorted(stage_candidates, key=lambda row: int(getattr(row, "sequence_no", 0) or 0)):
                normalized_status = self._normalize_downstream_status(run.status) or str(run.status or "").strip()
                if normalized_status in active_statuses and (
                    has_real_active_progress
                    or normalized_status in {"running", "dispatching", "applying"}
                    or stage_start_allowed
                ):
                    active_candidates.append((stage_name, normalized_status))
        if active_candidates:
            stage_name, normalized_status = active_candidates[-1]
            return True, stage_name, normalized_status
        return False, None, None

    def _has_any_active_incomplete_stage(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_runs: list[BinarySecurityStageRun],
    ) -> tuple[bool, str | None, str | None]:
        active_statuses = {"pending", "queued", "running", "dispatching", "applying"}
        task_retry_target_stage = (
            str(task.target_stage_name or "").strip()
            if task.execution_mode in {"task_retry", "task_retry_failed_items"} and str(task.target_stage_name or "").strip()
            else None
        )
        active_candidates: list[tuple[str, str]] = []
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            stage_start_allowed = bool(self._evaluate_stage_start_gate(db, task, stage_name).get("allowed"))
            stage_items = self._stage_items(db, task.id, stage_name)
            has_real_active_progress = bool(
                self._stage_has_active_items(stage_items)
                or self._stage_has_live_downstream_children(stage_items)
                or self._stage_has_real_runnable_work(db, task, stage_name)
            )
            has_unresolved_expected_outputs = self._stage_has_unresolved_expected_outputs(
                db,
                task,
                stage_name,
                None,
                stage_items,
            )
            stage_candidates = [
                run
                for run in stage_runs
                if normalize_stage_name(run.stage_name) == normalize_stage_name(stage_name)
            ]
            if not stage_candidates:
                continue
            for run in sorted(stage_candidates, key=lambda row: int(getattr(row, "sequence_no", 0) or 0)):
                normalized_status = self._normalize_downstream_status(run.status) or str(run.status or "").strip()
                if task_retry_target_stage and stage_name == task_retry_target_stage and normalized_status == "success":
                    continue
                if (
                    normalized_status in {"pending", "queued"}
                    and not has_real_active_progress
                    and not (has_unresolved_expected_outputs and stage_start_allowed)
                ):
                    continue
                if normalized_status in active_statuses:
                    if (
                        has_real_active_progress
                        or normalized_status in {"running", "dispatching", "applying"}
                        or (has_unresolved_expected_outputs and stage_start_allowed)
                    ):
                        active_candidates.append((stage_name, normalized_status))
        if active_candidates:
            stage_name, normalized_status = active_candidates[-1]
            return True, stage_name, normalized_status
        return False, None, None

    def _is_streaming_active_item_status(self, status: str | None) -> bool:
        normalized = self._normalize_downstream_status(status) or str(status or "").strip()
        return normalized in STREAMING_ACTIVE_ITEM_STATUSES

    def _stage_parallelism(self, task: BinarySecurityTask, stage_name: str) -> int:
        policy = self._effective_runtime_policy(task)
        stage_parallelism = policy.get("stage_parallelism") or {}
        if stage_name in stage_parallelism:
            return max(1, int(stage_parallelism[stage_name]))
        return max(1, int(policy.get("max_stage_parallelism") or 1))

    def _module_selection_mode(self, task: BinarySecurityTask) -> str:
        mode = str((task.policy or {}).get("module_selection_mode") or MODULE_SELECTION_MODE_AUTO).strip()
        if mode not in {MODULE_SELECTION_MODE_AUTO, MODULE_SELECTION_MODE_MANUAL_CONFIRM}:
            return MODULE_SELECTION_MODE_AUTO
        return mode

    def _entry_selection_mode(self, task: BinarySecurityTask) -> str:
        mode = str((task.policy or {}).get("entry_selection_mode") or ENTRY_SELECTION_MODE_AUTO).strip()
        if mode not in {ENTRY_SELECTION_MODE_AUTO, ENTRY_SELECTION_MODE_MANUAL_CONFIRM}:
            return ENTRY_SELECTION_MODE_AUTO
        return mode

    def _entry_auto_selection_strategy(self, task: BinarySecurityTask) -> str:
        strategy = str((task.policy or {}).get("entry_auto_selection_strategy") or ENTRY_AUTO_SELECTION_STRATEGY_ALL).strip()
        if strategy not in {
            ENTRY_AUTO_SELECTION_STRATEGY_ALL,
            ENTRY_AUTO_SELECTION_STRATEGY_TOP_N_PER_MODULE_BY_CONFIDENCE,
        }:
            return ENTRY_AUTO_SELECTION_STRATEGY_ALL
        return strategy

    def _entry_auto_selection_top_n(self, task: BinarySecurityTask) -> int:
        if self._entry_auto_selection_strategy(task) != ENTRY_AUTO_SELECTION_STRATEGY_TOP_N_PER_MODULE_BY_CONFIDENCE:
            return 0
        try:
            value = int((task.policy or {}).get("entry_auto_selection_top_n") or DEFAULT_ENTRY_AUTO_SELECTION_TOP_N)
        except (TypeError, ValueError):
            return DEFAULT_ENTRY_AUTO_SELECTION_TOP_N
        return max(1, value)

    def _module_risk_levels(self, task: BinarySecurityTask) -> list[str]:
        return _normalize_module_risk_levels((task.policy or {}).get("module_risk_levels"))

    def _normalize_module_risk_level(self, value: Any, risk_score: Any = None) -> str:
        return _normalize_module_risk_level(value, risk_score)

    def _module_selection_candidate_levels(self, task: BinarySecurityTask) -> list[str]:
        if self._module_selection_mode(task) == MODULE_SELECTION_MODE_MANUAL_CONFIRM:
            return list(ALLOWED_MODULE_RISK_LEVELS)
        return self._module_risk_levels(task)

    def _mark_selected_modules(self, modules: list[dict[str, Any]], *, selected_by: str, selected_at: str | None = None) -> list[dict[str, Any]]:
        timestamp = selected_at or _now().isoformat()
        return [
            {
                **module,
                "selected_by": selected_by,
                "selected_at": timestamp,
            }
            for module in modules
        ]

    def _entry_selection_snapshot(self, task: BinarySecurityTask) -> dict[str, Any]:
        snapshot = (task.summary or {}).get("entry_selection")
        return dict(snapshot) if isinstance(snapshot, dict) else {}

    def _entry_results(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        return [dict(item) for item in (task.summary.get("entry_results") or []) if isinstance(item, dict)]

    def _entry_result_module_kind(self, task: BinarySecurityTask) -> str:
        return "knowledge_graph_module" if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN else "source_module"

    def _entry_result_module_key(self, task: BinarySecurityTask, module: dict[str, Any] | None = None) -> str:
        payload = dict(module or {})
        key = str(payload.get("module_key") or payload.get("source_project_key") or "").strip()
        if key:
            return key
        if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            return "knowledge-graph-source-project"
        return ""

    def _entry_result_module_name(self, task: BinarySecurityTask, module: dict[str, Any] | None = None) -> str:
        payload = dict(module or {})
        name = str(payload.get("module_name") or payload.get("source_project_name") or "").strip()
        if name:
            return name
        if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            return "source-project"
        return ""

    def _entry_result_source_stage(self, task: BinarySecurityTask) -> str:
        return "knowledge_graph_entry_fetch" if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN else "entry_analysis"

    def _entry_result_execution_epoch(self, task: BinarySecurityTask) -> int:
        return int((task.summary or {}).get("execution_epoch") or getattr(task, "execution_epoch", 0) or 0)

    def _normalize_entry_result_module(
        self,
        task: BinarySecurityTask,
        row: dict[str, Any],
    ) -> dict[str, Any]:
        payload = dict(row or {})
        entries = [dict(entry) for entry in list(payload.get("entries") or []) if isinstance(entry, dict)]
        if not entries:
            entries = [dict(entry) for entry in list(payload.get("entries_preview") or []) if isinstance(entry, dict)]
        module_key = self._entry_result_module_key(task, payload)
        module_name = self._entry_result_module_name(task, payload)
        if not module_key and entries:
            first_entry = dict(entries[0])
            module_key = (
                str(first_entry.get("module_key") or "").strip()
                or str(first_entry.get("entry_key") or "").strip()
            )
        if not module_name and entries:
            first_entry = dict(entries[0])
            module_name = (
                str(first_entry.get("module_name") or "").strip()
                or str(first_entry.get("function_name") or "").strip()
            )
        completion_state = str(payload.get("completion_state") or "").strip() or (
            "success" if entries else "pending"
        )
        normalized = {
            **payload,
            "module_key": module_key,
            "module_name": module_name,
            "module_kind": str(payload.get("module_kind") or self._entry_result_module_kind(task)).strip(),
            "source_stage": str(payload.get("source_stage") or self._entry_result_source_stage(task)).strip(),
            "execution_epoch": int(payload.get("execution_epoch") or self._entry_result_execution_epoch(task)),
            "completion_state": completion_state,
            "completion_ready": bool(payload.get("completion_ready")) if "completion_ready" in payload else completion_state in {"success", "failed", "orchestration_failed", "cancelled"},
            "entries": entries,
            "entry_count": int(payload.get("entry_count") or len(entries)),
            "error_message": str(payload.get("error_message") or "").strip() or None,
            "downstream_task_id": str(payload.get("downstream_task_id") or "").strip() or None,
            "artifact_ready": bool(payload.get("artifact_ready")) if "artifact_ready" in payload else bool(entries),
        }
        return normalized

    def _normalized_entry_result_modules(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        modules: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for row in self._entry_results(task):
            normalized = self._normalize_entry_result_module(task, row)
            key = (
                str(normalized.get("module_key") or "").strip(),
                int(normalized.get("execution_epoch") or 0),
            )
            if key in seen:
                continue
            seen.add(key)
            modules.append(normalized)
        return modules

    def _entry_result_modules_for_current_epoch(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        current_epoch = self._entry_result_execution_epoch(task)
        return [
            module
            for module in self._normalized_entry_result_modules(task)
            if int(module.get("execution_epoch") or 0) == current_epoch
        ]

    def _entry_result_success_modules(self, task: BinarySecurityTask, db: Session | None = None) -> list[dict[str, Any]]:
        if db is not None:
            if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                if not self._stage_has_archived_success_progress(db, task, "knowledge_graph_entry_fetch"):
                    return []
            else:
                modules: list[dict[str, Any]] = []
                seen: set[tuple[str, int]] = set()
                for item in self._stage_archived_success_items(db, task, "entry_analysis"):
                    normalized = self._entry_module_result_from_stage_item(task, item)
                    key = (
                        str(normalized.get("module_key") or "").strip(),
                        int(normalized.get("execution_epoch") or 0),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    modules.append(normalized)
                return [
                    module
                    for module in modules
                    if str(module.get("completion_state") or "").strip() == "success"
                    and bool(module.get("completion_ready"))
                ]
        return [
            module
            for module in self._entry_result_modules_for_current_epoch(task)
            if str(module.get("completion_state") or "").strip() == "success"
            and bool(module.get("completion_ready"))
        ]

    def _entry_result_terminal_modules(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        terminal_states = {"success", "failed", "orchestration_failed", "cancelled"}
        return [
            module
            for module in self._entry_result_modules_for_current_epoch(task)
            if str(module.get("completion_state") or "").strip() in terminal_states
            and bool(module.get("completion_ready"))
        ]

    def _expected_entry_modules(self, task: BinarySecurityTask, db: Session) -> list[dict[str, Any]]:
        if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            source_dir = str((task.summary or {}).get("input_dir") or "").strip()
            if not source_dir:
                return []
            kg_state = dict((task.summary or {}).get("knowledge_graph_state") or {})
            return [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": self._entry_result_execution_epoch(task),
                    "completion_expected": bool(kg_state),
                }
            ]
        return [
            {
                "module_key": self._entry_result_module_key(task, module),
                "module_name": self._entry_result_module_name(task, module),
                "module_kind": "source_module",
                "source_stage": "entry_analysis",
                "execution_epoch": self._entry_result_execution_epoch(task),
            }
            for module in self._entry_analysis_inputs(db, task)
            if self._entry_result_module_key(task, module)
        ]

    def _entry_module_completion_state(self, task: BinarySecurityTask, db: Session | None) -> dict[str, Any]:
        expected = self._expected_entry_modules(task, db) if db is not None else (
            [
                {
                    "module_key": self._entry_result_module_key(task, module),
                    "module_name": self._entry_result_module_name(task, module),
                    "module_kind": "source_module",
                    "source_stage": "entry_analysis",
                    "execution_epoch": self._entry_result_execution_epoch(task),
                }
                for module in list((task.summary or {}).get("selected_modules") or [])
                if isinstance(module, dict) and self._entry_result_module_key(task, module)
            ]
            if self._pipeline_profile(task) != PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN
            else (
                [
                    {
                        "module_key": "knowledge-graph-source-project",
                        "module_name": "source-project",
                        "module_kind": "knowledge_graph_module",
                        "source_stage": "knowledge_graph_entry_fetch",
                        "execution_epoch": self._entry_result_execution_epoch(task),
                    }
                ]
                if str((task.summary or {}).get("input_dir") or "").strip()
                else []
            )
        )
        materialized = self._entry_result_terminal_modules(task)
        expected_keys = {str(module.get("module_key") or "").strip() for module in expected if str(module.get("module_key") or "").strip()}
        materialized_keys = {str(module.get("module_key") or "").strip() for module in materialized if str(module.get("module_key") or "").strip()}
        missing = sorted(key for key in expected_keys if key not in materialized_keys)
        legacy_materialized_only = not expected_keys and bool(materialized_keys)
        return {
            "expected_modules": expected,
            "materialized_modules": materialized,
            "expected_module_count": len(expected_keys),
            "materialized_module_count": len(materialized_keys),
            "successful_module_count": len(
                [module for module in materialized if str(module.get("completion_state") or "").strip() == "success"]
            ),
            "failed_module_count": len(
                [module for module in materialized if str(module.get("completion_state") or "").strip() in {"failed", "orchestration_failed", "cancelled"}]
            ),
            "missing_module_keys": missing,
            "complete": legacy_materialized_only or (bool(expected_keys) and len(expected_keys) == len(materialized_keys)),
            "legacy_materialized_only": legacy_materialized_only,
        }

    def _entry_module_completion_gate(self, task: BinarySecurityTask, db: Session) -> bool:
        return bool(self._entry_module_completion_state(task, db).get("complete"))

    def _entry_module_flow_inputs(self, task: BinarySecurityTask, db: Session | None = None) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for module in self._entry_result_success_modules(task, db):
            module_key = str(module.get("module_key") or "").strip()
            module_name = str(module.get("module_name") or "").strip()
            module_kind = str(module.get("module_kind") or "").strip()
            execution_epoch = int(module.get("execution_epoch") or 0)
            for entry in list(module.get("entries") or []):
                if not isinstance(entry, dict):
                    continue
                entries.append(
                    {
                        **dict(entry),
                        "module_key": module_key or str(entry.get("module_key") or "").strip(),
                        "module_name": module_name or str(entry.get("module_name") or "").strip(),
                        "module_kind": module_kind or str(entry.get("module_kind") or "").strip(),
                        "execution_epoch": execution_epoch,
                    }
                )
        return entries

    def _entry_modules_for_selection(self, task: BinarySecurityTask, db: Session | None = None) -> list[dict[str, Any]]:
        return [dict(module) for module in self._entry_result_success_modules(task, db)]

    def _rank_entry_confidence(self, entry: dict[str, Any]) -> float:
        confidence = str(entry.get("confidence") or "").strip().lower()
        if confidence == "high":
            return 3.0
        if confidence == "medium":
            return 2.0
        if confidence == "low":
            return 1.0
        try:
            raw = entry.get("entry_confidence")
            if raw is None:
                return 0.0
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            return 0.0

    def _select_auto_entries_for_kg_task(
        self,
        task: BinarySecurityTask,
        entries: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        strategy = self._entry_auto_selection_strategy(task)
        top_n = self._entry_auto_selection_top_n(task)
        normalized_entries = _deduplicate_entry_keys(
            [dict(entry) for entry in entries if isinstance(entry, dict)]
        )
        if strategy == ENTRY_AUTO_SELECTION_STRATEGY_ALL:
            return normalized_entries, {
                "auto_selection_strategy": strategy,
                "auto_selection_top_n": 0,
                "selection_source": "auto_policy",
                "candidate_entries": normalized_entries,
                "candidate_entries_by_module": [
                    {
                        "module_key": "knowledge-graph-source-project",
                        "module_name": "source-project",
                        "raw_entry_count": len(normalized_entries),
                        "selected_entry_count": len(normalized_entries),
                        "truncated": False,
                    }
                ],
                "truncated_module_count": 0,
            }
        sorted_entries = sorted(
            normalized_entries,
            key=lambda entry: (
                -self._rank_entry_confidence(entry),
                str(entry.get("entry_key") or "").strip(),
                str(entry.get("function_name") or "").strip(),
            ),
        )
        selected = sorted_entries[:top_n]
        return selected, {
            "auto_selection_strategy": strategy,
            "auto_selection_top_n": top_n,
            "selection_source": "auto_policy",
            "candidate_entries": selected,
            "candidate_entries_by_module": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "raw_entry_count": len(sorted_entries),
                    "selected_entry_count": len(selected),
                    "truncated": len(sorted_entries) > len(selected),
                }
            ],
            "truncated_module_count": 1 if len(sorted_entries) > len(selected) else 0,
        }

    def _normalize_module_selection_entries(
        self,
        task: BinarySecurityTask,
        modules: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for module in modules:
            if not isinstance(module, dict):
                continue
            module_key = str(module.get("module_key") or "").strip()
            module_name = str(module.get("module_name") or "").strip()
            module_kind = str(module.get("module_kind") or "").strip()
            execution_epoch = int(module.get("execution_epoch") or self._entry_result_execution_epoch(task))
            for entry in list(module.get("entries") or []):
                if not isinstance(entry, dict):
                    continue
                entries.append(
                    {
                        **dict(entry),
                        "module_key": str(entry.get("module_key") or "").strip() or module_key,
                        "module_name": str(entry.get("module_name") or "").strip() or module_name,
                        "module_kind": str(entry.get("module_kind") or "").strip() or module_kind,
                        "execution_epoch": int(entry.get("execution_epoch") or execution_epoch),
                    }
                )
        return _deduplicate_entry_keys(entries)

    def _select_auto_entries_per_module(
        self,
        task: BinarySecurityTask,
        modules_or_entries: list[dict[str, Any]],
        db: Session | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        del db
        strategy = self._entry_auto_selection_strategy(task)
        top_n = self._entry_auto_selection_top_n(task)
        modules = [
            self._normalize_entry_result_module(task, dict(item))
            for item in modules_or_entries
            if isinstance(item, dict)
        ]
        raw_entries = self._normalize_module_selection_entries(task, modules)
        if strategy == ENTRY_AUTO_SELECTION_STRATEGY_ALL:
            return raw_entries, {
                "auto_selection_strategy": strategy,
                "auto_selection_top_n": 0,
                "selection_source": "auto_policy",
                "candidate_entries": raw_entries,
                "candidate_entries_by_module": [
                    {
                        "module_key": str(module.get("module_key") or "").strip(),
                        "module_name": str(module.get("module_name") or "").strip(),
                        "raw_entry_count": len([entry for entry in list(module.get("entries") or []) if isinstance(entry, dict)]),
                        "selected_entry_count": len([entry for entry in list(module.get("entries") or []) if isinstance(entry, dict)]),
                        "truncated": False,
                    }
                    for module in modules
                ],
                "truncated_module_count": 0,
            }
        selected: list[dict[str, Any]] = []
        candidate_entries_by_module: list[dict[str, Any]] = []
        truncated_module_count = 0
        for module in modules:
            module_entries = [
                {
                    **dict(entry),
                    "module_key": str(entry.get("module_key") or "").strip() or str(module.get("module_key") or "").strip(),
                    "module_name": str(entry.get("module_name") or "").strip() or str(module.get("module_name") or "").strip(),
                    "module_kind": str(entry.get("module_kind") or "").strip() or str(module.get("module_kind") or "").strip(),
                    "execution_epoch": int(entry.get("execution_epoch") or module.get("execution_epoch") or self._entry_result_execution_epoch(task)),
                }
                for entry in list(module.get("entries") or [])
                if isinstance(entry, dict)
            ]
            module_entries = _deduplicate_entry_keys(module_entries)
            sorted_entries = sorted(
                module_entries,
                key=lambda entry: (
                    -self._rank_entry_confidence(entry),
                    str(entry.get("entry_key") or "").strip(),
                    str(entry.get("function_name") or "").strip(),
                ),
            )
            chosen_entries = sorted_entries[:top_n]
            if len(sorted_entries) > len(chosen_entries):
                truncated_module_count += 1
            selected.extend(chosen_entries)
            candidate_entries_by_module.append(
                {
                    "module_key": str(module.get("module_key") or "").strip(),
                    "module_name": str(module.get("module_name") or "").strip(),
                    "raw_entry_count": len(sorted_entries),
                    "selected_entry_count": len(chosen_entries),
                    "truncated": len(sorted_entries) > len(chosen_entries),
                }
            )
        selected = _deduplicate_entry_keys(selected)
        return selected, {
            "auto_selection_strategy": strategy,
            "auto_selection_top_n": top_n,
            "selection_source": "auto_policy",
            "candidate_entries": selected,
            "candidate_entries_by_module": candidate_entries_by_module,
            "truncated_module_count": truncated_module_count,
        }

    def _clear_entry_result_state(self, task: BinarySecurityTask) -> None:
        summary = dict(task.summary or {})
        summary["entry_results"] = []
        summary["entry_selection"] = {}
        task.summary = summary
        metrics = dict(task.metrics or {})
        metrics.update(
            {
                "candidate_entry_count": 0,
                "selected_entry_count": 0,
                "entry_count": 0,
                "expected_entry_module_count": 0,
                "materialized_entry_module_count": 0,
                "successful_entry_module_count": 0,
                "failed_entry_module_count": 0,
            }
        )
        task.metrics = metrics

    def _knowledge_graph_entry_results(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        return [dict(item) for item in (task.summary.get("knowledge_graph_entry_results") or []) if isinstance(item, dict)]

    def _merge_knowledge_graph_entry_results(
        self,
        task: BinarySecurityTask,
        entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for entry in [*self._knowledge_graph_entry_results(task), *entries]:
            if not isinstance(entry, dict):
                continue
            current = dict(entry)
            stable_key = (
                str(current.get("entry_key") or "").strip(),
                str(current.get("source_id") or "").strip(),
                str(current.get("function_id") or "").strip(),
            )
            if stable_key in seen:
                continue
            seen.add(stable_key)
            merged.append(current)
        return merged

    def _compact_knowledge_graph_entry_results(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                **dict(entry),
                "entries": [dict(entry)],
            }
            for entry in entries
            if isinstance(entry, dict)
        ]

    def _entry_candidates(self, task: BinarySecurityTask, db: Session | None = None) -> list[dict[str, Any]]:
        snapshot = self._entry_selection_snapshot(task)
        candidate_entries = snapshot.get("candidate_entries")
        if db is None and isinstance(candidate_entries, list) and candidate_entries:
            return self._materialized_flow_entries(
                task,
                [dict(item) for item in candidate_entries if isinstance(item, dict)],
            )
        if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            entries = self._entry_module_flow_inputs(task, db)
            selected_entries, _snapshot = self._select_auto_entries_for_kg_task(task, entries)
            return selected_entries
        modules = self._entry_modules_for_selection(task, db)
        selected_entries, _snapshot = self._select_auto_entries_per_module(task, modules, db)
        return selected_entries

    def _selected_entry_keys(self, task: BinarySecurityTask) -> list[str]:
        snapshot = self._entry_selection_snapshot(task)
        return [
            str(key).strip()
            for key in (snapshot.get("selected_entry_keys") or [])
            if str(key).strip()
        ]

    def _selected_entries(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        snapshot = self._entry_selection_snapshot(task)
        return self._materialized_flow_entries(
            task,
            [dict(item) for item in (snapshot.get("selected_entries") or []) if isinstance(item, dict)],
        )

    def _legacy_entry_input_rows(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        flattened: list[dict[str, Any]] = []
        for row in self._entry_results(task):
            if not isinstance(row, dict):
                continue
            entry_key = str(row.get("entry_key") or "").strip()
            if entry_key:
                flattened.append(dict(row))
                continue
            for entry in list(row.get("entries") or []):
                if isinstance(entry, dict):
                    flattened.append(dict(entry))
        deduped: dict[str, dict[str, Any]] = {}
        fallback_index = 0
        for entry in flattened:
            key = str(entry.get("entry_key") or "").strip()
            if not key:
                key = f"entry-{fallback_index}"
                fallback_index += 1
            deduped[key] = dict(entry)
        return list(deduped.values())

    def _mark_selected_entries(self, entries: list[dict[str, Any]], *, selected_by: str, selected_at: str | None = None) -> list[dict[str, Any]]:
        timestamp = selected_at or _now().isoformat()
        return [
            {
                **entry,
                "selected_by": selected_by,
                "selected_at": timestamp,
            }
            for entry in entries
        ]

    def _effective_entry_inputs(self, task: BinarySecurityTask, db: Session | None = None) -> list[dict[str, Any]]:
        legacy_rows = self._legacy_entry_input_rows(task)
        if self._entry_selection_mode(task) == ENTRY_SELECTION_MODE_AUTO:
            candidates = self._entry_candidates(task, db)
            return candidates or legacy_rows
        snapshot = self._entry_selection_snapshot(task)
        if str(snapshot.get("status") or "").strip() != "confirmed":
            return []
        selected_entries = self._selected_entries(task)
        if selected_entries:
            return selected_entries
        selected_keys = set(self._selected_entry_keys(task))
        if not selected_keys:
            return []
        selected = [
            entry
            for entry in self._entry_candidates(task, db)
            if str(entry.get("entry_key") or "").strip() in selected_keys
        ]
        return selected

    def _entry_selection_metrics(self, task: BinarySecurityTask, db: Session | None = None) -> dict[str, int]:
        module_state = self._entry_module_completion_state(task, None)
        candidate_count = len(self._entry_candidates(task, db))
        return {
            "candidate_entry_count": candidate_count,
            "selected_entry_count": len(self._effective_entry_inputs(task, db)) if self._entry_selection_mode(task) == ENTRY_SELECTION_MODE_MANUAL_CONFIRM else candidate_count,
            "expected_entry_module_count": int(module_state.get("expected_module_count") or 0),
            "materialized_entry_module_count": int(module_state.get("materialized_module_count") or 0),
            "successful_entry_module_count": int(module_state.get("successful_module_count") or 0),
            "failed_entry_module_count": int(module_state.get("failed_module_count") or 0),
        }

    def _entry_module_result_from_stage_item(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> dict[str, Any]:
        payload = {
            **dict(item.input_ref or {}),
            **dict(item.output_ref or {}),
            **self._load_stage_item_result_payload(item),
        }
        normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
        completion_state = {
            "success": "success",
            "partial_success": "success",
            "failed": "failed",
            "downstream_missing": "failed",
            "cancelled": "cancelled",
        }.get(normalized_status, "orchestration_failed")
        normalized = self._normalize_entry_result_module(
            task,
            {
                **payload,
                "module_key": self._entry_result_module_key(task, payload) or str(item.item_key or "").strip(),
                "module_name": self._entry_result_module_name(task, payload) or str(item.item_name or "").strip(),
                "source_dir": self._resolve_entry_source_dir(payload) or str(task.firmware_path or "").strip() or None,
                "completion_state": completion_state,
                "completion_ready": self._is_terminal_item_status(item.status),
                "downstream_task_id": str(item.downstream_task_id or "").strip() or None,
                "error_message": str(item.error_message or "").strip() or None,
                "artifact_ready": bool(self._stage_item_artifact_root(item)),
            },
        )
        if completion_state == "success":
            module_payload = dict(normalized)
            artifact_root_value = self._stage_item_artifact_root(item)
            entries = [dict(entry) for entry in payload.get("entries") or [] if isinstance(entry, dict)]
            if artifact_root_value:
                artifact_root = Path(str(artifact_root_value))
                parsed_entries = self._parse_entries(artifact_root, module_payload)
                if parsed_entries:
                    entries = parsed_entries
                    normalized["artifact_root"] = str(artifact_root)
            if not entries:
                entries = [dict(entry) for entry in payload.get("entries_preview") or [] if isinstance(entry, dict)]
            normalized_entries: list[dict[str, Any]] = []
            for entry in entries:
                row = dict(entry)
                row["source_dir"] = self._resolve_entry_source_dir({**module_payload, **row}) or module_payload.get("source_dir")
                normalized_entries.append(row)
            normalized["entries"] = _deduplicate_entry_keys(normalized_entries)
            normalized["entry_count"] = len(normalized["entries"])
            normalized["artifact_ready"] = bool(self._stage_item_artifact_root(item))
        else:
            normalized["entries"] = []
            normalized["entry_count"] = 0
        return normalized

    def _materialized_flow_entries(self, task: BinarySecurityTask, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        flattened: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            entry_key = str(row.get("entry_key") or "").strip()
            if entry_key:
                flattened.append(dict(row))
                continue
            module_key = str(row.get("module_key") or "").strip()
            module_name = str(row.get("module_name") or "").strip()
            module_kind = str(row.get("module_kind") or "").strip()
            execution_epoch = int(row.get("execution_epoch") or self._entry_result_execution_epoch(task))
            for entry in list(row.get("entries") or []):
                if not isinstance(entry, dict):
                    continue
                flattened.append(
                    {
                        **dict(entry),
                        "module_key": str(entry.get("module_key") or "").strip() or module_key,
                        "module_name": str(entry.get("module_name") or "").strip() or module_name,
                        "module_kind": str(entry.get("module_kind") or "").strip() or module_kind,
                        "execution_epoch": int(entry.get("execution_epoch") or execution_epoch),
                    }
                )
        return _deduplicate_entry_keys(flattened)

    def _rebuild_entry_result_modules_from_stage_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> list[dict[str, Any]]:
        modules: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in self._stage_items(db, task.id, "entry_analysis"):
            module_key = str(item.item_key or "").strip()
            if not module_key or module_key in seen:
                continue
            seen.add(module_key)
            modules.append(self._entry_module_result_from_stage_item(task, item))
        summary = dict(task.summary or {})
        entry_selection_snapshot = dict(summary.get("entry_selection") or {}) if isinstance(summary.get("entry_selection"), dict) else {}
        if self._pipeline_profile(task) != PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            auto_candidates, auto_snapshot = self._select_auto_entries_per_module(task, modules, db)
            entry_selection_snapshot = {
                **entry_selection_snapshot,
                **auto_snapshot,
            }
            if self._entry_selection_mode(task) != ENTRY_SELECTION_MODE_MANUAL_CONFIRM:
                entry_selection_snapshot.pop("selected_entry_keys", None)
                entry_selection_snapshot.pop("selected_entries", None)
                entry_selection_snapshot.pop("confirmed_at", None)
                entry_selection_snapshot.pop("status", None)
                entry_selection_snapshot["mode"] = ENTRY_SELECTION_MODE_AUTO
                entry_selection_snapshot["selected_entries"] = self._mark_selected_entries(
                    auto_candidates,
                    selected_by=ENTRY_SELECTION_MODE_AUTO,
                )
                entry_selection_snapshot["selected_entry_keys"] = [
                    str(entry.get("entry_key") or "").strip()
                    for entry in auto_candidates
                    if str(entry.get("entry_key") or "").strip()
                ]
        summary["entry_results"] = modules
        summary["entry_selection"] = entry_selection_snapshot
        task.summary = summary
        metrics = dict(task.metrics or {})
        metrics.update(self._entry_selection_metrics(task, db))
        metrics["entry_count"] = sum(int(module.get("entry_count") or 0) for module in modules)
        task.metrics = metrics
        if stage_run is not None:
            self._persist_stage_run_output_summary(
                task,
                stage_run,
                {
                    "items": self._compact_stage_success_items_for_db("entry_results", modules),
                    "entry_count": metrics["entry_count"],
                    "expected_entry_module_count": int(metrics.get("expected_entry_module_count") or 0),
                    "materialized_entry_module_count": int(metrics.get("materialized_entry_module_count") or 0),
                    "successful_entry_module_count": int(metrics.get("successful_entry_module_count") or 0),
                    "failed_entry_module_count": int(metrics.get("failed_entry_module_count") or 0),
                    "status_synced": True,
                    "sync_status": stage_run.status,
                    **(stage_run.counts or {}),
                },
            )
        return modules

    def _build_knowledge_graph_entry_result_module(
        self,
        task: BinarySecurityTask,
        *,
        entries: list[dict[str, Any]],
        completion_state: str,
        completion_ready: bool,
        error_message: str | None = None,
    ) -> dict[str, Any]:
        return self._normalize_entry_result_module(
            task,
            {
                "module_key": "knowledge-graph-source-project",
                "module_name": "source-project",
                "module_kind": "knowledge_graph_module",
                "source_stage": "knowledge_graph_entry_fetch",
                "execution_epoch": self._entry_result_execution_epoch(task),
                "completion_state": completion_state,
                "completion_ready": completion_ready,
                "entries": [dict(entry) for entry in entries if isinstance(entry, dict)] if completion_state == "success" else [],
                "entry_count": len(entries) if completion_state == "success" else 0,
                "error_message": error_message,
                "artifact_ready": completion_state == "success",
            },
        )

    def _knowledge_graph_entry_reason(self, entry: dict[str, Any]) -> str:
        parts: list[str] = []
        channel = str(entry.get("channel") or "").strip()
        subkind = str(entry.get("subkind") or "").strip()
        confidence = str(entry.get("confidence") or "").strip()
        if channel:
            parts.append(f"channel={channel}")
        if subkind:
            parts.append(f"subkind={subkind}")
        if confidence:
            parts.append(f"confidence={confidence}")
        if bool(entry.get("is_promoted_root")):
            parts.append("promoted_root=true")
        if bool(entry.get("enhanced_yes")):
            parts.append("enhanced_yes=true")
        if bool(entry.get("basic_yes")):
            parts.append("basic_yes=true")
        if bool(entry.get("disagreement")):
            parts.append("disagreement=true")
        return "; ".join(parts) or "knowledge_graph_entry"

    def _normalize_knowledge_graph_entry(
        self,
        task: BinarySecurityTask,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        input_dir = str((task.summary or {}).get("input_dir") or "").strip()
        source_file = str(raw.get("file_path") or "").strip().replace("\\", "/")
        source_file_exists = self._knowledge_graph_source_file_exists(input_dir, source_file)
        line_hint = str(raw.get("start_line") or "").strip()
        function_name = str(raw.get("name") or "").strip()
        entry_key = str(raw.get("source_id") or "").strip()
        module_name = str(raw.get("module") or "").strip() or "source-project"
        taint_params = list(raw.get("taint_params") or [])
        return {
            "entry_key": entry_key,
            "firmware_key": SOURCE_TASK_INPUT_KEY,
            "firmware_name": task.name,
            "module_key": "knowledge_graph_source_project",
            "module_name": module_name,
            "module_dir": input_dir,
            "descriptor_root": input_dir,
            "source_dir": input_dir,
            "source_root": input_dir,
            "source_root_path": input_dir,
            "module_input_path": input_dir,
            "source_file": source_file,
            "definition_file": source_file,
            "function_name": function_name,
            "raw_function_name": function_name,
            "line_no": line_hint,
            "definition_line": line_hint,
            "definition_kind": "unknown",
            "is_definition_found": source_file_exists,
            "source_file_exists": source_file_exists,
            "entry_execution_status": "ready" if source_file_exists else "source_file_missing",
            "entry_execution_reason": "source file is accessible" if source_file_exists else "source file is missing under source_root_path",
            "function_description": str(raw.get("function_purpose") or "").strip(),
            "function_description_source": "knowledge_graph_audit_sources",
            "entry_reason": str(raw.get("entry_evidence") or "").strip() or self._knowledge_graph_entry_reason(raw),
            "entry_reason_source": "knowledge_graph_audit_sources",
            "taint_params": taint_params,
            "taint_details": self._build_knowledge_graph_taint_details(raw, taint_params),
            "signature": str(raw.get("signature") or "").strip(),
            "channel": str(raw.get("channel") or "").strip(),
            "subkind": str(raw.get("subkind") or "").strip(),
            "confidence": str(raw.get("confidence") or "").strip(),
            "is_promoted_root": bool(raw.get("is_promoted_root")),
            "covers": list(raw.get("covers") or []),
            "dominated_by": str(raw.get("dominated_by") or "").strip(),
            "source_provider": "knowledge_graph_audit_sources",
            "source_id": entry_key,
            "function_id": str(raw.get("function_id") or "").strip() or None,
            "knowledge_graph_status": str(raw.get("status") or "").strip() or None,
            "review_status": str(raw.get("review_status") or "").strip() or None,
            "judgments": [dict(item) for item in list(raw.get("judgments") or []) if isinstance(item, dict)],
            "taint_locals": list(raw.get("taint_locals") or []),
            "taint_evidence": raw.get("taint_evidence"),
            "callees": [dict(item) for item in list(raw.get("callees") or []) if isinstance(item, dict)],
            "task_type": TASK_TYPE_SOURCE,
        }

    def _knowledge_graph_source_file_exists(self, source_root_path: str, source_file: str) -> bool:
        normalized_root = str(source_root_path or "").strip()
        normalized_file = str(source_file or "").strip().replace("\\", "/")
        if not normalized_root or not normalized_file:
            return False
        try:
            root_path = Path(normalized_root).resolve()
            candidate = (root_path / normalized_file).resolve()
            candidate.relative_to(root_path)
        except Exception:
            return False
        return candidate.is_file()

    def _filter_executable_knowledge_graph_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            dict(entry)
            for entry in entries
            if isinstance(entry, dict) and self._is_executable_knowledge_graph_entry(entry)
        ]

    def _knowledge_graph_entry_execution_metrics(self, entries: list[dict[str, Any]]) -> dict[str, int]:
        total = len([entry for entry in entries if isinstance(entry, dict)])
        executable = len([entry for entry in entries if isinstance(entry, dict) and self._is_executable_knowledge_graph_entry(entry)])
        return {
            "knowledge_graph_executable_entry_count": executable,
            "knowledge_graph_missing_source_file_count": max(0, total - executable),
        }

    def _is_executable_knowledge_graph_entry(self, entry: dict[str, Any] | None) -> bool:
        if not isinstance(entry, dict):
            return False
        if "source_file_exists" not in entry:
            return True
        return bool(entry.get("source_file_exists"))

    def _knowledge_graph_source_endpoint(self, *, upload_id: str | None, db_name: str | None) -> str:
        cfg = self.cfg.services.knowledge_graph_audit
        if upload_id:
            return f"{cfg.base_url.rstrip('/')}{cfg.upload_sources_path_template.format(upload_id=upload_id)}"
        return f"{cfg.base_url.rstrip('/')}{cfg.project_sources_path_template.format(db_name=db_name or '')}"

    def _build_knowledge_graph_taint_details(self, raw: dict[str, Any], taint_params: list[Any]) -> list[dict[str, Any]]:
        details: list[dict[str, Any]] = []
        evidence = raw.get("taint_evidence")
        if isinstance(evidence, str) and evidence.strip():
            try:
                parsed = json.loads(evidence)
            except Exception:
                parsed = []
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        details.append(dict(item))
        if details:
            return details
        return _normalize_entry_taint_details({"taint_details": [], "taint_params": taint_params}, [str(v).strip() for v in taint_params if str(v).strip()])

    def _knowledge_graph_analysis_metrics(self, meta: dict[str, Any]) -> dict[str, int]:
        analysis = dict(meta.get("analysis") or {})
        return {
            "knowledge_graph_analysis_total": int(analysis.get("total") or 0),
            "knowledge_graph_analysis_identified": int(analysis.get("identified") or 0),
            "knowledge_graph_analysis_pending": int(analysis.get("pending") or 0),
            "knowledge_graph_analysis_confirmed": int(analysis.get("confirmed") or 0),
            "knowledge_graph_analysis_rejected": int(analysis.get("rejected") or 0),
        }

    async def _fetch_knowledge_graph_entry_results(
        self,
        task: BinarySecurityTask,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        started = time.perf_counter()
        upload_id, db_name = self._knowledge_graph_locator(task)
        if not upload_id and not db_name:
            raise ValidationError("知识图谱源码任务缺少 upload_id/db_name，无法获取 audit sources")
        request_options = self._knowledge_graph_request_options(task)
        payload = await get_knowledge_graph_audit_client().get_sources(
            upload_id=upload_id,
            db_name=db_name,
            **request_options,
        )
        entries = payload.get("items")
        if not isinstance(entries, list):
            raise ValidationError("知识图谱入口响应格式非法: 缺少 items 列表")
        raw_entries = [dict(item) for item in entries if isinstance(item, dict)]
        selected_raw = [item for item in raw_entries if bool(item.get("is_entry"))]
        normalized_entries = [self._normalize_knowledge_graph_entry(task, item) for item in selected_raw]
        deduped = _deduplicate_entry_keys(normalized_entries)
        analysis = dict(payload.get("analysis") or {})
        graph_status = str(payload.get("graph_status") or "").strip() or None
        identification = dict(payload.get("identification") or {})
        identification_state = str(identification.get("state") or "").strip() or None
        attack_status = str(identification.get("attack_status") or "").strip() or None
        return deduped, {
            "entries_url": self._knowledge_graph_source_endpoint(upload_id=upload_id, db_name=db_name),
            "lookup_mode": "upload_id" if upload_id else "db_name",
            "upload_id": upload_id,
            "db_name": db_name,
            "graph_status": graph_status,
            "identification_state": identification_state,
            "attack_status": attack_status,
            "analysis": analysis,
            "raw_entry_count": int(analysis.get("total") or payload.get("total") or len(raw_entries)),
            "selected_entry_count": len(deduped),
            "filtered_out_count": max(0, int(analysis.get("total") or len(raw_entries)) - len(deduped)),
            "returned_item_count": len(raw_entries),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }

    def _knowledge_graph_poll_state_summary(
        self,
        meta: dict[str, Any],
        *,
        accumulated_selected_entry_count: int,
    ) -> dict[str, Any]:
        analysis_metrics = self._knowledge_graph_analysis_metrics(meta)
        return {
            "graph_status": str(meta.get("graph_status") or "").strip() or None,
            "identification_state": str(meta.get("identification_state") or "").strip() or None,
            "attack_status": str(meta.get("attack_status") or "").strip() or None,
            "last_polled_at": _now().isoformat(),
            "next_poll_after_seconds": max(1, int(self.cfg.scheduler.stage_poll_interval_seconds or 5)),
            "accumulated_selected_entry_count": accumulated_selected_entry_count,
            **analysis_metrics,
        }

    def _filter_candidate_modules(self, modules: list[dict[str, Any]], risk_levels: list[str]) -> list[dict[str, Any]]:
        allowed = set(_normalize_module_risk_levels(risk_levels))
        candidates = [
            dict(module)
            for module in modules
            if self._normalize_module_risk_level(module.get("risk_level"), module.get("risk_score")) in allowed
        ]
        if candidates:
            return candidates
        if not modules:
            return []
        return candidates

    def _module_metrics(self, modules: list[dict[str, Any]], candidate_modules: list[dict[str, Any]], selected_modules: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "high_risk_module_count": sum(1 for module in modules if self._normalize_module_risk_level(module.get("risk_level"), module.get("risk_score")) == "高"),
            "medium_risk_module_count": sum(1 for module in modules if self._normalize_module_risk_level(module.get("risk_level"), module.get("risk_score")) == "中"),
            "low_risk_module_count": sum(1 for module in modules if self._normalize_module_risk_level(module.get("risk_level"), module.get("risk_score")) == "低"),
            "candidate_module_count": len(candidate_modules),
            "selected_module_count": len(selected_modules),
        }

    def _task_or_404(self, db: Session, project_id: str, task_id: str) -> BinarySecurityTask:
        task = db.query(BinarySecurityTask).filter(
            BinarySecurityTask.project_id == project_id,
            BinarySecurityTask.id == task_id,
        ).first()
        if not task:
            raise NotFoundError("任务不存在")
        return task

    async def _readless_reconcile_loop(self) -> None:
        # This loop intentionally remains a TaskManager lifecycle wiring entry.
        # The actual readless reconcile business flow lives in the item/task
        # mixins that are passed into run_readless_sync_loop below.
        interval_seconds = max(300, int(getattr(self.cfg.scheduler, "readless_reconcile_interval_seconds", 300) or 300))
        await run_readless_sync_loop(
            should_stop=lambda: not self._running,
            interval_seconds=interval_seconds,
            before_tick=self._before_readless_reconcile_tick,
            candidate_ids_loader=self._load_readless_reconcile_candidate_ids,
            process_one=self._process_readless_reconcile_task,
            observe=self._observe_readless_reconcile_stats,
            loop_context=observe_scheduler_loop,
            loop_name="readless_reconcile",
        )

    async def _before_readless_reconcile_tick(self) -> bool:
        self._mark_loop_heartbeat("readless_reconcile")
        return True

    def _latest_stage_run(self, db: Session, task_id: str, stage_name: str) -> BinarySecurityStageRun | None:
        normalized_task_id = str(task_id or "").strip()
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_task_id or not normalized_stage_name:
            return None
        return (
            db.query(BinarySecurityStageRun)
            .filter(
                BinarySecurityStageRun.task_id == normalized_task_id,
                BinarySecurityStageRun.stage_name == normalized_stage_name,
            )
            .order_by(
                BinarySecurityStageRun.sequence_no.desc(),
                BinarySecurityStageRun.updated_at.desc(),
                BinarySecurityStageRun.created_at.desc(),
                BinarySecurityStageRun.id.desc(),
            )
            .first()
        )

    def _ensure_stage_run(self, db: Session, task: BinarySecurityTask, stage_name: str) -> BinarySecurityStageRun:
        stage_run = self._latest_stage_run(db, task.id, stage_name)
        if stage_run:
            return stage_run
        stage_run = BinarySecurityStageRun(
            id=f"sr_{uuid.uuid4().hex[:20]}",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_name,
            sequence_no=self._stage_sequence_for_task(task).index(stage_name) + 1,
            status="pending",
        )
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            try:
                with self._savepoint(db):
                    db.add(stage_run)
                    db.flush()
                self._record_event(
                    db,
                    task,
                    "stage_run_created",
                    f"阶段执行记录已创建: {stage_name}",
                    stage_name=stage_name,
                    payload={
                        "stage_run_id": stage_run.id,
                        "sequence_no": stage_run.sequence_no,
                        "status": stage_run.status,
                    },
                )
                return stage_run
            except IntegrityError:
                existing = self._latest_stage_run(db, task.id, stage_name)
                if existing is None:
                    raise
                return existing
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                    raise
                db.rollback()
                self._sleep_after_retryable_lock_error(attempt + 1)

    @staticmethod
    def _preserved_child_result_keys() -> tuple[str, ...]:
        return (
            "first_started_at",
            "sync_status",
            "downstream_status_synced_at",
            "downstream_status",
            "sync_observation",
            "downstream",
            "downstream_binding",
            "archive_copy_stats",
            "archive_root",
            "artifact_root",
            "orchestration_observation",
            "last_orchestration_attempt_at",
            "last_orchestration_success_at",
            "last_orchestration_error_at",
            "last_orchestration_error_type",
            "last_orchestration_error_message",
            "consecutive_orchestration_error_count",
            "orchestration_error_budget_exhausted",
            "next_orchestration_retry_at",
            "last_orchestration_result",
        )

    def _downstream_binding_snapshot(self, item: BinarySecurityStageItem) -> dict[str, Any]:
        result_payload = dict(item.result or {})
        return dict(result_payload.get("downstream_binding") or {})

    def _set_downstream_binding_snapshot(
        self,
        item: BinarySecurityStageItem,
        *,
        state: str | None = None,
        attempts: int | None = None,
        first_attempt_at: datetime | None | object = _UNSET,
        last_attempt_at: datetime | None | object = _UNSET,
        next_retry_at: datetime | None | object = _UNSET,
        last_error: str | None | object = _UNSET,
        last_error_type: str | None | object = _UNSET,
        recoverable: bool | None | object = _UNSET,
        message: str | None | object = _UNSET,
    ) -> dict[str, Any]:
        result_payload = dict(item.result or {})
        binding = dict(result_payload.get("downstream_binding") or {})
        if state is not None:
            binding["state"] = str(state).strip()
        if attempts is not None:
            binding["attempts"] = max(0, int(attempts))
        if first_attempt_at is not _UNSET:
            binding["first_attempt_at"] = _isoformat_or_none(first_attempt_at if isinstance(first_attempt_at, datetime) else None) if first_attempt_at is not None else None
        if last_attempt_at is not _UNSET:
            binding["last_attempt_at"] = _isoformat_or_none(last_attempt_at if isinstance(last_attempt_at, datetime) else None) if last_attempt_at is not None else None
        if next_retry_at is not _UNSET:
            binding["next_retry_at"] = _isoformat_or_none(next_retry_at if isinstance(next_retry_at, datetime) else None) if next_retry_at is not None else None
        if last_error is not _UNSET:
            binding["last_error"] = str(last_error).strip() or None if last_error is not None else None
        if last_error_type is not _UNSET:
            binding["last_error_type"] = str(last_error_type).strip() or None if last_error_type is not None else None
        if recoverable is not _UNSET:
            binding["recoverable"] = bool(recoverable) if recoverable is not None else None
        if message is not _UNSET:
            binding["message"] = str(message).strip() or None if message is not None else None
        result_payload["downstream_binding"] = binding
        item.result = result_payload
        return binding

    def _downstream_binding_state(self, item: BinarySecurityStageItem) -> str:
        binding = self._downstream_binding_snapshot(item)
        task_id = str(item.downstream_task_id or "").strip()
        item_result = self._load_stage_item_result_payload(item)
        downstream_status = (
            self._string_or_none(binding.get("downstream_status"))
            or self._string_or_none(item_result.get("downstream_status"))
            or self._string_or_none(dict(item_result.get("sync_observation") or {}).get("downstream_status"))
            or self._string_or_none(dict(item_result.get("sync_observation") or {}).get("mapped_status"))
            or self._string_or_none(dict(item_result.get("downstream") or {}).get("status"))
        )
        explicit = self._string_or_none(binding.get("state"))
        if task_id:
            return "bound" if downstream_status else "created_pending_sync"
        if explicit:
            return explicit
        return "not_started"

    def _downstream_binding_attempts(self, item: BinarySecurityStageItem) -> int:
        binding = self._downstream_binding_snapshot(item)
        try:
            return max(0, int(binding.get("attempts") or 0))
        except Exception:
            return 0

    def _downstream_binding_time(self, item: BinarySecurityStageItem, key: str) -> datetime | None:
        binding = self._downstream_binding_snapshot(item)
        return self._parse_comparable_datetime(binding.get(key))

    def _downstream_binding_retry_after(self, attempts: int) -> int:
        index = max(0, attempts - 1)
        if index >= len(DOWNSTREAM_CREATE_RETRY_BACKOFF_SECONDS):
            return DOWNSTREAM_CREATE_RETRY_BACKOFF_SECONDS[-1]
        return DOWNSTREAM_CREATE_RETRY_BACKOFF_SECONDS[index]

    def _item_needs_downstream_binding_reconcile(self, item: BinarySecurityStageItem) -> bool:
        if str(item.downstream_service or "").strip() != "dataflow_vuln_scan":
            return False
        if str(item.downstream_task_id or "").strip():
            return False
        if normalize_stage_name(item.stage_name) != "dataflow_vuln_scan":
            return False
        item_status = str(item.status or "").strip().lower()
        if item_status not in {"pending", "queued", "running", "dispatching"}:
            return False
        binding_state = self._downstream_binding_state(item)
        if binding_state in {"creating", "create_retrying", "create_failed"}:
            return True
        sync_status = self._stage_item_sync_status_value(item)
        return sync_status == "transport_error" and binding_state != "not_started"

    def _preserve_child_result_metadata(self, result: dict[str, Any] | None) -> dict[str, Any]:
        current_result = dict(result or {})
        preserved: dict[str, Any] = {}
        for key in self._preserved_child_result_keys():
            if key in current_result:
                preserved[key] = current_result.get(key)
        return preserved

    def _reset_child_runtime_payload(
        self,
        item: BinarySecurityStageItem,
        *,
        payload: dict[str, Any] | None = None,
        keep_error: bool = False,
        reset_started_at: bool = False,
        reset_finished_at: bool = True,
    ) -> list[str]:
        preserved_result = self._preserve_child_result_metadata(item.result)
        preserved_keys = list(preserved_result.keys())
        item.payload = dict(payload or {})
        item.result = preserved_result
        if not keep_error:
            item.error_message = None
        if reset_started_at:
            item.started_at = None
        if reset_finished_at:
            item.finished_at = None
        return preserved_keys

    @staticmethod
    def _stage_item_first_started_at(item: BinarySecurityStageItem) -> datetime | None:
        result_payload = dict(item.result or {})
        raw_value = result_payload.get("first_started_at")
        if isinstance(raw_value, datetime):
            return raw_value
        if isinstance(raw_value, str) and raw_value.strip():
            try:
                return datetime.fromisoformat(raw_value)
            except ValueError:
                return None
        return item.started_at

    def _ensure_stage_item_first_started_at(self, item: BinarySecurityStageItem) -> None:
        if item.started_at is None:
            return
        result_payload = dict(item.result or {})
        current = self._stage_item_first_started_at(item)
        if current is None:
            result_payload["first_started_at"] = item.started_at.isoformat()
            item.result = result_payload

    def _build_child_status_event_payload(
        self,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        change_source: str,
        before_status: str | None,
        after_status: str | None,
        sync_status: str | None = None,
        downstream_status_raw: str | None = None,
        downstream_status_mapped: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
        error_message: str | None = None,
        error_type: str | None = None,
        http_status: int | None = None,
        archive_job_id: str | None = None,
        state_event_id: str | None = None,
        preserved_result_keys: list[str] | None = None,
        task_status_after_reconcile: str | None = None,
        stage_status_after_reconcile: str | None = None,
        extra_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "change_source": change_source,
            "before_status": before_status,
            "after_status": after_status,
            "downstream_service": item.downstream_service,
            "downstream_task_id": item.downstream_task_id,
            "downstream_status_raw": downstream_status_raw,
            "downstream_status_mapped": downstream_status_mapped,
            "downstream_status": downstream_status,
            "state_applied": state_applied,
            "sync_status": sync_status,
            "http_status": http_status,
            "error_type": error_type,
            "error_message": error_message,
            "archive_job_id": archive_job_id,
            "state_event_id": state_event_id,
            "preserved_result_keys": preserved_result_keys or [],
            "task_status_after_reconcile": task_status_after_reconcile or task.status,
            "stage_status_after_reconcile": stage_status_after_reconcile,
        }
        if extra_payload:
            payload.update(extra_payload)
        return payload

    def _child_status_event_message(
        self,
        item: BinarySecurityStageItem,
        *,
        event_type: str,
        before_status: str | None,
        after_status: str | None,
        change_source: str,
    ) -> str:
        item_label = str(item.item_key or item.item_name or item.id or "-")
        stage_label = str(item.stage_name or "unknown")
        if event_type == "child_sync_observed":
            return f"{stage_label} 子任务同步观测完成: {item_label}"
        if event_type == "child_sync_failed":
            return f"{stage_label} 子任务同步失败: {item_label}"
        if event_type == "child_transport_failed":
            return f"{stage_label} 子任务同步通信失败: {item_label}"
        if event_type == "downstream_poll_retry_scheduled":
            return f"{stage_label} 子任务 API 错误，已进入无限重试: {item_label}"
        if event_type == "child_observation_persist_failed":
            return f"{stage_label} 子任务观测快照写入失败: {item_label}"
        if event_type == "child_state_apply_failed":
            return f"{stage_label} 子任务状态推进失败: {item_label}"
        if event_type == "child_archive_status_changed":
            return f"{stage_label} 子任务归档状态推进: {item_label} {before_status or '-'} -> {after_status or '-'}"
        return f"{stage_label} 子任务状态变更: {item_label} {before_status or '-'} -> {after_status or '-'} ({change_source})"

    def _log_child_status_event(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        event_type: str,
        change_source: str,
        before_status: str | None,
        after_status: str | None,
        sync_status: str | None = None,
        downstream_status_raw: str | None = None,
        downstream_status_mapped: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
        error_message: str | None = None,
        error_type: str | None = None,
        http_status: int | None = None,
        archive_job_id: str | None = None,
        state_event_id: str | None = None,
        preserved_result_keys: list[str] | None = None,
        stage_status_after_reconcile: str | None = None,
        extra_payload: dict[str, Any] | None = None,
    ) -> None:
        if event_type == "downstream_http_429_retry_scheduled":
            streak = 0
            if isinstance(extra_payload, dict):
                streak = int(extra_payload.get("retry_attempt_count") or 0)
            if not self._should_emit_http_429_timeline_event(streak):
                return
        if event_type == "downstream_poll_retry_scheduled":
            streak = 0
            retry_delay_seconds = 0
            if isinstance(extra_payload, dict):
                streak = int(extra_payload.get("retry_attempt_count") or 0)
                retry_delay_seconds = int(extra_payload.get("retry_delay_seconds") or 0)
            if not self._should_emit_api_retry_timeline_event(streak, retry_delay_seconds):
                return
        level = "warning" if event_type in {"child_sync_failed", "child_transport_failed", "child_observation_persist_failed", "child_state_apply_failed", "child_archive_status_changed", "downstream_http_429_retry_scheduled"} or str(after_status or "") in {"failed", "cancelled", "downstream_missing"} else "info"
        self._record_event(
            db,
            task,
            event_type,
            self._child_status_event_message(
                item,
                event_type=event_type,
                before_status=before_status,
                after_status=after_status,
                change_source=change_source,
            ),
            level=level,
            stage_name=item.stage_name,
            item=item,
            payload=self._build_child_status_event_payload(
                task=task,
                item=item,
                change_source=change_source,
                before_status=before_status,
                after_status=after_status,
                sync_status=sync_status,
                downstream_status_raw=downstream_status_raw,
                downstream_status_mapped=downstream_status_mapped,
                downstream_status=downstream_status,
                state_applied=state_applied,
                error_message=error_message,
                error_type=error_type,
                http_status=http_status,
                archive_job_id=archive_job_id,
                state_event_id=state_event_id,
                preserved_result_keys=preserved_result_keys,
                stage_status_after_reconcile=stage_status_after_reconcile,
                extra_payload=extra_payload,
            ),
        )

    def _apply_child_task_sync_observation(
        self,
        item: BinarySecurityStageItem,
        *,
        sync_status: str,
        synced_at: datetime | None = None,
        error_message: str | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        downstream_status_raw: str | None = None,
        downstream_status_mapped: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
        downstream_payload: dict[str, Any] | None = None,
        archive_root: str | None = None,
        archive_copy_stats: dict[str, Any] | None = None,
        consecutive_error_count: int | None = None,
        budget_exhausted: bool | None = None,
        next_retry_at: datetime | None = None,
        last_sync_result: str | None = None,
        clear_error_state: bool = False,
    ) -> list[str]:
        current_result = dict(item.result or {})
        preserved_keys = [key for key in self._preserved_child_result_keys() if key in current_result]
        sync_observation = dict(current_result.get("sync_observation") or {})
        control_plane_stale = self._is_tail_control_plane_stale_error(
            error_message=error_message,
            error_type=error_type,
        )
        if control_plane_stale:
            sync_status = "synced" if (downstream_status or downstream_status_mapped or downstream_status_raw or current_result.get("downstream_status")) else (sync_status or "observed")
            error_message = None
            error_type = None
            http_status = None
        observed_at = synced_at or _now()
        observed_at_iso = observed_at.isoformat()
        sync_observation["last_attempt_at"] = observed_at_iso
        if last_sync_result is None:
            last_sync_result = "error" if error_message or error_type else "success"
        sync_observation.update(
            {
                "sync_status": sync_status,
                "error_message": error_message,
                "http_status": http_status,
                "error_type": error_type,
                "status_raw": downstream_status_raw,
                "mapped_status": downstream_status_mapped,
                "downstream_status": downstream_status,
                "state_applied": state_applied,
                "last_result": last_sync_result,
            }
        )
        if consecutive_error_count is not None:
            sync_observation["consecutive_error_count"] = max(0, int(consecutive_error_count))
        if budget_exhausted is not None:
            sync_observation["budget_exhausted"] = bool(budget_exhausted)
        if next_retry_at is not None:
            sync_observation["next_retry_at"] = next_retry_at.isoformat()
        elif error_message or error_type:
            sync_observation["next_retry_at"] = sync_observation.get("next_retry_at")
        else:
            sync_observation["next_retry_at"] = None
        if error_message or error_type:
            sync_observation["last_error_at"] = observed_at_iso
        elif clear_error_state or state_applied or downstream_status or downstream_status_mapped or downstream_status_raw:
            sync_observation["last_success_at"] = observed_at_iso
            sync_observation["last_synced_at"] = observed_at_iso
            sync_observation["last_error_at"] = None
            sync_observation["error_message"] = None
            sync_observation["error_type"] = None
            sync_observation["http_status"] = None
            sync_observation["consecutive_error_count"] = 0
            sync_observation["budget_exhausted"] = False
            sync_observation["next_retry_at"] = None
            sync_observation["last_result"] = "success"
        merged_result = {
            **current_result,
            "sync_status": sync_status,
            "last_sync_attempt_at": observed_at_iso,
            "downstream_status_synced_at": (
                sync_observation.get("last_success_at")
                or sync_observation.get("last_synced_at")
                or observed_at_iso
            ),
            "last_sync_success_at": sync_observation.get("last_success_at") or sync_observation.get("last_synced_at"),
            "last_sync_error_at": sync_observation.get("last_error_at"),
            "last_sync_error_message": sync_observation.get("error_message"),
            "last_sync_error_type": sync_observation.get("error_type"),
            "last_sync_result": sync_observation.get("last_result"),
            "consecutive_sync_error_count": sync_observation.get("consecutive_error_count"),
            "sync_error_budget_exhausted": sync_observation.get("budget_exhausted"),
            "next_sync_retry_at": sync_observation.get("next_retry_at"),
            "downstream_status": downstream_status or current_result.get("downstream_status"),
            "sync_observation": sync_observation,
        }
        if downstream_payload is not None:
            merged_result["downstream"] = self._lightweight_downstream_payload(downstream_payload or {})
        if archive_root is not None:
            merged_result["archive_root"] = archive_root
        if archive_copy_stats is not None:
            merged_result["archive_copy_stats"] = dict(archive_copy_stats or {})
        item.result = merged_result
        return preserved_keys

    def _child_sync_observation_would_change(
        self,
        item: BinarySecurityStageItem,
        *,
        sync_status: str,
        synced_at: datetime | None = None,
        error_message: str | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        status_raw: str | None = None,
        mapped_status: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
    ) -> bool:
        current_result = dict(item.result or {})
        current_observation = dict(current_result.get("sync_observation") or {})
        comparable_synced_at = self._comparable_datetime(synced_at)
        if comparable_synced_at is not None:
            current_synced_candidates = [
                self._parse_comparable_datetime(current_observation.get("last_synced_at")),
                self._parse_comparable_datetime(current_observation.get("last_success_at")),
                self._parse_comparable_datetime(current_result.get("last_sync_attempt_at")),
            ]
            if not any(candidate != comparable_synced_at for candidate in current_synced_candidates if candidate is not None):
                comparable_synced_at = None
        current_sync_status = self._string_or_none(current_result.get("sync_status"))
        current_downstream_status = self._string_or_none(current_result.get("downstream_status"))
        comparable_pairs = (
            (current_sync_status, self._string_or_none(sync_status)),
            (self._string_or_none(current_observation.get("sync_status")), self._string_or_none(sync_status)),
            (self._string_or_none(current_observation.get("error_message")), self._string_or_none(error_message)),
            (self._int_or_none(current_observation.get("http_status")), self._int_or_none(http_status)),
            (self._string_or_none(current_observation.get("error_type")), self._string_or_none(error_type)),
            (self._string_or_none(current_observation.get("status_raw")), self._string_or_none(status_raw)),
            (self._string_or_none(current_observation.get("mapped_status")), self._string_or_none(mapped_status)),
            (self._string_or_none(current_observation.get("downstream_status")), self._string_or_none(downstream_status)),
            (self._bool_or_none(current_observation.get("state_applied")), self._bool_or_none(state_applied)),
            (current_downstream_status, self._string_or_none(downstream_status) or current_downstream_status),
        )
        return comparable_synced_at is not None or any(before != after for before, after in comparable_pairs)

    def _merge_stage_item_output_ref(self, item: BinarySecurityStageItem, **updates: Any) -> list[str]:
        current_output_ref = dict(getattr(item, "output_ref", None) or {})
        preserved_keys = [key for key in updates.keys() if key in current_output_ref]
        merged_output_ref = dict(current_output_ref)
        changed = False
        for key, value in updates.items():
            if value is None:
                continue
            if merged_output_ref.get(key) == value:
                continue
            merged_output_ref[key] = value
            changed = True
        if changed:
            item.output_ref = merged_output_ref
        return preserved_keys

    def _apply_child_task_status_change(
        self,
        db: Session | None,
        *,
        task: BinarySecurityTask | None,
        item: BinarySecurityStageItem,
        change_source: str,
        after_status: str,
        downstream_payload: dict[str, Any] | None = None,
        sync_status: str | None = None,
        downstream_status_raw: str | None = None,
        downstream_status_mapped: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
        error_message: str | None = None,
        error_type: str | None = None,
        http_status: int | None = None,
        archive_job_id: str | None = None,
        state_event_id: str | None = None,
        synced_at: datetime | None = None,
        extra_payload: dict[str, Any] | None = None,
        event_type: str = "child_status_changed",
    ) -> list[str]:
        normalized_status = self._map_downstream_status(after_status) or after_status
        before_status = str(item.status or "").strip().lower() or None
        item.status = normalized_status
        keep_active_error = (
            bool(error_message)
            and normalized_status in {"queued", "running"}
            and (change_source == "transport_error" or sync_status == "transport_error")
        )
        item.error_message = error_message if keep_active_error else (
            None if normalized_status in {"pending", "queued", "dispatching", "running", "success", "partial_success"} else error_message
        )
        if normalized_status in {"running", "success", "failed", "cancelled", "downstream_missing", "partial_success"}:
            item.started_at = item.started_at or _now()
        item.finished_at = None if normalized_status in {"pending", "queued", "dispatching", "running"} else (item.finished_at or _now())
        preserved_keys = self._apply_child_task_sync_observation(
            item,
            sync_status=sync_status or ("synced" if state_applied else "observed"),
            synced_at=synced_at,
            error_message=error_message,
            http_status=http_status,
            error_type=error_type,
            downstream_status_raw=downstream_status_raw,
            downstream_status_mapped=downstream_status_mapped or normalized_status,
            downstream_status=downstream_status,
            state_applied=state_applied,
            downstream_payload=downstream_payload,
        )
        if db is not None and task is not None:
            self._log_child_status_event(
                db,
                task=task,
                item=item,
                event_type=event_type,
                change_source=change_source,
                before_status=before_status,
                after_status=normalized_status,
                sync_status=sync_status or ("synced" if state_applied else "observed"),
                downstream_status_raw=downstream_status_raw,
                downstream_status_mapped=downstream_status_mapped or normalized_status,
                downstream_status=downstream_status,
                state_applied=state_applied,
                error_message=error_message,
                error_type=error_type,
                http_status=http_status,
                archive_job_id=archive_job_id,
                state_event_id=state_event_id,
                preserved_result_keys=preserved_keys,
                extra_payload=extra_payload,
            )
        return preserved_keys

    def _persist_child_sync_observation(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        change_source: str,
        sync_status: str,
        synced_at: datetime | None = None,
        error_message: str | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        status_raw: str | None = None,
        mapped_status: str | None = None,
        downstream_status: str | None = None,
        state_applied: bool | None = None,
        extra_payload: dict[str, Any] | None = None,
        consecutive_error_count: int | None = None,
        budget_exhausted: bool | None = None,
        next_retry_at: datetime | None = None,
        last_sync_result: str | None = None,
        clear_error_state: bool = False,
    ) -> bool:
        before_status = str(item.status or "").strip().lower() or None
        after_status = str(item.status or "").strip().lower() or None
        previous_observation = self._stage_item_sync_observation(item)
        previous_sync_status = self._stage_item_sync_status_value(item)
        previous_error_type = self._string_or_none(previous_observation.get("error_type")) or self._string_or_none(dict(item.result or {}).get("last_sync_error_type"))
        previous_error_message = self._string_or_none(previous_observation.get("error_message")) or self._string_or_none(dict(item.result or {}).get("last_sync_error_message"))
        previous_active_error = self._stage_item_has_active_sync_error(item)
        observation_would_change = self._child_sync_observation_would_change(
            item,
            sync_status=sync_status,
            synced_at=synced_at,
            error_message=error_message,
            http_status=http_status,
            error_type=error_type,
            status_raw=status_raw,
            mapped_status=mapped_status,
            downstream_status=downstream_status,
            state_applied=state_applied,
        )
        sync_event_type = "applied" if state_applied else "observed"
        if sync_status in {"transport_error", "rate_limited", "binding_mismatch", "skipped"}:
            sync_event_type = sync_status
        elif error_message or error_type:
            sync_event_type = "failed"
        elif sync_status == "synced" and (last_sync_result or "").strip().lower() == "success":
            sync_event_type = "succeeded"
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            try:
                with self._savepoint(db):
                    if observation_would_change:
                        self._mark_stage_item_sync_observation(
                            item,
                            sync_status=sync_status,
                            synced_at=synced_at,
                            error_message=error_message,
                            http_status=http_status,
                            error_type=error_type,
                            status_raw=status_raw,
                            mapped_status=mapped_status,
                            downstream_status=downstream_status,
                            state_applied=state_applied,
                            consecutive_error_count=consecutive_error_count,
                            budget_exhausted=budget_exhausted,
                            next_retry_at=next_retry_at,
                            last_sync_result=last_sync_result,
                            clear_error_state=clear_error_state,
                        )
                    self._record_downstream_sync_event(
                        db,
                        task=task,
                        item=item,
                        stage_name=item.stage_name,
                        operation=change_source or "downstream_sync",
                        event_type=sync_event_type,
                        sync_status=sync_status,
                        outcome=last_sync_result or ("error" if error_message or error_type else "success"),
                        state_applied=state_applied,
                        error_type=error_type,
                        error_message=error_message,
                        http_status=http_status,
                        payload={
                            "change_source": change_source,
                            "downstream_status_raw": status_raw,
                            "downstream_status_mapped": mapped_status,
                            "downstream_status": downstream_status,
                            "state_applied": state_applied,
                            "observation_reused": not observation_would_change,
                            "consecutive_error_count": consecutive_error_count,
                            "budget_exhausted": budget_exhausted,
                            "next_retry_at": _isoformat_or_none(next_retry_at),
                            "last_sync_result": last_sync_result,
                            **(extra_payload or {}),
                        },
                    )
                    current_active_error = self._stage_item_has_active_sync_error(item)
                    if (
                        observation_would_change
                        and previous_active_error
                        and not current_active_error
                        and (last_sync_result or "").strip().lower() == "success"
                    ):
                        self._record_downstream_sync_event(
                            db,
                            task=task,
                            item=item,
                            stage_name=item.stage_name,
                            operation=change_source or "downstream_sync",
                            event_type="error_recovered",
                            sync_status=sync_status,
                            outcome="success",
                            state_applied=state_applied,
                            payload={
                                "change_source": change_source,
                                "previous_sync_status": previous_sync_status,
                                "previous_error_type": previous_error_type,
                                "previous_error_message": previous_error_message,
                                "recovered_at": _isoformat_or_none(synced_at),
                                **(extra_payload or {}),
                            },
                        )
                    db.flush()
                return True
            except Exception as exc:
                if self._is_retryable_lock_error(exc) and attempt < max_attempts - 1:
                    self._sleep_after_retryable_lock_error(attempt + 1)
                    continue
                self._log_child_status_event(
                    db,
                    task=task,
                    item=item,
                    event_type="child_observation_persist_failed",
                    change_source=change_source,
                    before_status=before_status,
                    after_status=after_status,
                    sync_status=sync_status,
                    downstream_status_raw=status_raw,
                    downstream_status_mapped=mapped_status,
                    downstream_status=downstream_status,
                    state_applied=state_applied,
                    error_message=str(exc),
                    error_type=exc.__class__.__name__,
                    http_status=http_status,
                    extra_payload={
                        "persist_error": str(exc),
                        "persist_error_type": exc.__class__.__name__,
                        **(extra_payload or {}),
                    },
                )
                return False
        return False

    def _apply_child_state_with_savepoint(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        change_source: str,
        target_status: str,
        sync_status: str,
        downstream_status_raw: str | None,
        downstream_status_mapped: str | None,
        downstream_status: str | None,
        error_message: str | None,
        http_status: int | None,
        error_type: str | None,
        apply_fn,
        extra_payload: dict[str, Any] | None = None,
        clear_error_state: bool = False,
    ) -> bool:
        before_status = str(item.status or "").strip().lower() or None
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            try:
                with self._savepoint(db):
                    apply_fn()
                    db.flush()
                return True
            except Exception as exc:
                if self._is_retryable_lock_error(exc) and attempt < max_attempts - 1:
                    self._sleep_after_retryable_lock_error(attempt + 1)
                    continue
                self._log_child_status_event(
                    db,
                    task=task,
                    item=item,
                    event_type="child_state_apply_failed",
                    change_source=change_source,
                    before_status=before_status,
                    after_status=target_status,
                    sync_status=sync_status,
                    downstream_status_raw=downstream_status_raw,
                    downstream_status_mapped=downstream_status_mapped,
                    downstream_status=downstream_status,
                    state_applied=False,
                    error_message=str(exc),
                    error_type=exc.__class__.__name__,
                    http_status=http_status,
                    extra_payload={
                        "apply_error": str(exc),
                        "apply_error_type": exc.__class__.__name__,
                        **(extra_payload or {}),
                    },
                )
                return False
        return False

    def _enqueue_compat_state_event(
        self,
        db: Session,
        *,
        task_id: str,
        project_id: str,
        event_type: str,
        idempotency_key: str,
        stage_name: str | None = None,
        item_id: str | None = None,
        archive_job_id: str | None = None,
        payload: dict[str, Any] | None = None,
        task: BinarySecurityTask | None = None,
    ) -> BinarySecurityStateEvent | None:
        """Legacy compatibility helper for persisted async state-event records.

        Normal owner-path fact application should prefer `_build_inline_state_event(...)`
        plus direct owner apply/reconcile. This helper is kept only for historical
        compatibility and payload-externalization coverage.
        """
        normalized_payload = dict(payload or {})
        emitted_by = dict(normalized_payload.get("emitted_by") or {})
        emitted_by.update(
            {
                "service": "binary-security",
                "role": self._event_runtime_role(),
                "instance_id": str(self.instance_id or "").strip() or None,
                "hostname": self._event_hostname(),
                "pod_name": self._event_pod_name(),
                "node_name": self._event_node_name(),
            }
        )
        normalized_payload["emitted_by"] = emitted_by
        normalized_payload.setdefault("runtime_role", self._event_runtime_role())
        event = BinarySecurityStateEvent(
            id=f"sev_{uuid.uuid4().hex[:24]}",
            task_id=task_id,
            project_id=project_id,
            stage_name=stage_name,
            item_id=item_id,
            archive_job_id=archive_job_id,
            event_type=event_type,
            idempotency_key=idempotency_key,
            status="pending",
            available_at=_now(),
            updated_at=_now(),
        )
        event.payload = self._prepare_event_payload_for_db(
            db,
            task=task,
            event_id=event.id,
            event_type=event_type,
            stage_name=stage_name,
            payload=normalized_payload,
            state_event=True,
            task_id=task_id,
            project_id=project_id,
        )
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            try:
                with self._savepoint(db):
                    db.add(event)
                    db.flush()
                observe_state_event(event_type, "created")
                return event
            except IntegrityError:
                observe_state_event(event_type, "duplicate")
                return None
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                    raise
                db.rollback()
                self._sleep_after_retryable_lock_error(attempt + 1)

    def _build_inline_state_event(
        self,
        db: Session,
        *,
        task_id: str,
        project_id: str,
        event_type: str,
        idempotency_key: str,
        stage_name: str | None = None,
        item_id: str | None = None,
        archive_job_id: str | None = None,
        payload: dict[str, Any] | None = None,
        task: BinarySecurityTask | None = None,
    ) -> BinarySecurityStateEvent:
        normalized_payload = dict(payload or {})
        emitted_by = dict(normalized_payload.get("emitted_by") or {})
        emitted_by.update(
            {
                "service": "binary-security",
                "role": "owner",
                "instance_id": str(self.instance_id or "").strip() or None,
                "hostname": self._event_hostname(),
                "pod_name": self._event_pod_name(),
                "node_name": self._event_node_name(),
            }
        )
        normalized_payload["emitted_by"] = emitted_by
        normalized_payload.setdefault("runtime_role", "owner")
        event = BinarySecurityStateEvent(
            id=f"owner_sev_{uuid.uuid4().hex[:24]}",
            task_id=task_id,
            project_id=project_id,
            stage_name=stage_name,
            item_id=item_id,
            archive_job_id=archive_job_id,
            event_type=event_type,
            idempotency_key=idempotency_key,
            status="processed",
            available_at=_now(),
            updated_at=_now(),
            processed_at=_now(),
            processing_started_at=_now(),
            processing_finished_at=_now(),
            processing_result="owner_inline",
            processed_by=str(self.instance_id or "").strip() or "owner",
        )
        event.payload = self._prepare_event_payload_for_db(
            db,
            task=task,
            event_id=event.id,
            event_type=event_type,
            stage_name=stage_name,
            payload=normalized_payload,
            state_event=True,
            task_id=task_id,
            project_id=project_id,
        )
        return event

    def _record_missing_stage_terminal_event(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str,
        status: str,
        reason: str,
        summary: dict[str, Any] | None = None,
        execution_token: str | None = None,
    ) -> None:
        self._record_event(
            db,
            task,
            "stage_worker_terminal_event_missing",
            f"检测到阶段终态收口漏执行，已通知 owner 直接补做收口: {stage_name}",
            level="warning",
            stage_name=stage_name,
            payload={
                "reason": reason,
                "status": status,
                "execution_token": execution_token,
                "summary": self._fit_event_payload_for_db(dict(summary or {})),
            },
        )

    def _stage_terminal_generation_key(
        self,
        task: BinarySecurityTask,
        stage_name: str | None,
        *,
        db: Session | None = None,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> str:
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_stage_name:
            return "unknown"
        resolved_stage_run = stage_run
        if resolved_stage_run is None and db is not None:
            resolved_stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == normalized_stage_name,
            ).first()
        if resolved_stage_run is not None and getattr(resolved_stage_run, "sequence_no", None) is not None:
            return f"seq:{int(resolved_stage_run.sequence_no)}"
        if resolved_stage_run is not None and getattr(resolved_stage_run, "started_at", None) is not None:
            return f"started:{resolved_stage_run.started_at.isoformat()}"
        return f"stage:{normalized_stage_name}"

    def _stage_terminal_event_idempotency_key(
        self,
        task: BinarySecurityTask,
        stage_name: str | None,
        stage_status: str | None,
        *,
        db: Session | None = None,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> str:
        normalized_stage_name = str(stage_name or "").strip()
        normalized_status = str(stage_status or "").strip()
        return (
            f"stage_worker_terminal_observed:{task.id}:{normalized_stage_name}:"
            f"{self._stage_terminal_generation_key(task, normalized_stage_name, db=db, stage_run=stage_run)}:{normalized_status}"
        )

    def _stage_has_authoritative_progress_beyond(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str | None,
    ) -> bool:
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_stage_name:
            return False
        stage_sequence = self._stage_sequence_for_task(task)
        if normalized_stage_name not in stage_sequence:
            return False
        current_index = stage_sequence.index(normalized_stage_name)
        for downstream_stage_name in stage_sequence[current_index + 1 :]:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == downstream_stage_name,
            ).first()
            items = self._stage_items(db, task.id, downstream_stage_name)
            if stage_run is not None:
                normalized_status = self._normalize_downstream_status(stage_run.status) or str(stage_run.status or "").strip()
                if normalized_status not in {"pending"}:
                    return True
            if items:
                if any(self._is_active_item_status(item.status) or self._is_terminal_item_status(item.status) for item in items):
                    return True
                if any(str(item.downstream_task_id or "").strip() for item in items):
                    return True
        return False

    def _stage_terminal_already_consumed(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str | None,
    ) -> bool:
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_stage_name:
            return False
        current_stage = str(task.current_stage or "").strip()
        stage_sequence = self._stage_sequence_for_task(task)
        if normalized_stage_name in stage_sequence and current_stage in stage_sequence:
            if stage_sequence.index(current_stage) > stage_sequence.index(normalized_stage_name):
                return True
        return False

    def _is_stage_terminal_event_recovery_candidate(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
    ) -> bool:
        stage_name = str(stage_run.stage_name or "").strip()
        stage_status = str(stage_run.status or "").strip()
        if not stage_name or stage_status not in {"success", "partial_success", "failed", "cancelled", "downstream_missing"}:
            return False
        if self._stage_terminal_already_consumed(db, task, stage_name):
            return False
        if self._stage_has_authoritative_progress_beyond(db, task, stage_name):
            return False
        return True

    def _should_ignore_stage_terminal_event(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str,
        event: BinarySecurityStateEvent,
        payload: dict[str, Any],
        stage_run: BinarySecurityStageRun | None,
    ) -> tuple[bool, str | None]:
        if self._stage_terminal_already_consumed(db, task, stage_name):
            payload_generation = str(payload.get("stage_generation") or "").strip()
            current_generation = self._stage_terminal_generation_key(task, stage_name, db=db, stage_run=stage_run)
            if payload_generation and payload_generation != current_generation:
                return True, "stale_generation"
            return True, "duplicate_consumed"
        return False, None

    def _recover_missing_stage_terminal_events_locked(self, db: Session) -> bool:
        recovered = False
        running_tasks = db.query(BinarySecurityTask).filter(BinarySecurityTask.status == "running").all()
        for task in running_tasks:
            stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
            for stage_run in stage_runs:
                if not self._is_stage_terminal_event_recovery_candidate(db, task, stage_run):
                    continue
                stage_name = str(stage_run.stage_name or "").strip()
                stage_status = str(stage_run.status or "").strip()
                expected_key = self._stage_terminal_event_idempotency_key(
                    task,
                    stage_name,
                    stage_status,
                    db=db,
                    stage_run=stage_run,
                )
                summary = dict(stage_run.output_summary or {})
                self._request_task_layer_reconcile(
                    db,
                    task=task,
                    stage_name=stage_name,
                    source_event_type="stage_worker_terminal_observed",
                    state_event_id=None,
                    reconcile_reason="missing_stage_terminal_recovery",
                    message="检测到阶段终态事实已存在但 owner 收口漏执行，已直接补做任务层收口",
                    event_payload={
                        "stage_status": stage_status,
                        "summary": self._fit_event_payload_for_db(summary),
                        "stage_terminal_event_idempotency_key": expected_key,
                        "recovery_mode": "owner_direct_reconcile",
                    },
                )
                self._record_missing_stage_terminal_event(
                    db,
                    task,
                    stage_name=stage_name,
                    status=stage_status,
                    reason="dispatch_loop_recovery",
                    summary=summary,
                    execution_token=self._dispatch_token_for_task(db, task) or "",
                )
                recovered = True
        if recovered:
            db.flush()
        return recovered

    def _stage_counts(self, db: Session, stage_run: BinarySecurityStageRun) -> dict[str, int]:
        raw_items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.stage_run_id == stage_run.id).all()
        items: list[BinarySecurityStageItem] = []
        seen_item_ids: set[str] = set()
        seen_identity_keys: set[str] = set()
        for item in raw_items:
            item_id = str(item.id or "").strip()
            if item_id and item_id in seen_item_ids:
                continue
            identity_key = str(getattr(item, "item_identity_key", "") or "").strip()
            if not identity_key:
                identity_key = self._stage_item_identity(item.item_key, item.parent_key)
            if identity_key and identity_key in seen_identity_keys:
                continue
            if item_id:
                seen_item_ids.add(item_id)
            if identity_key:
                seen_identity_keys.add(identity_key)
            items.append(item)
        counts = {
            "total_items": len(items),
            "success_items": 0,
            "failed_items": 0,
            "downstream_missing_items": 0,
            "skipped_items": 0,
            "running_items": 0,
            "cancelled_items": 0,
        }
        for item in items:
            normalized_status = self._normalize_downstream_status(item.status) or item.status
            key = f"{normalized_status}_items"
            if key in counts:
                counts[key] += 1
            elif normalized_status in {"pending", "queued", "dispatching"}:
                counts["running_items"] += 1
        return counts

    def _normalize_downstream_status(self, status: str | None) -> str | None:
        return self._map_downstream_status(status or "")

    def _business_stage_status(
        self,
        task: BinarySecurityTask,
        stage_name: str,
        stage_run: BinarySecurityStageRun | None,
        items: list[BinarySecurityStageItem],
        *,
        db: Session | None = None,
    ) -> str:
        if stage_name == "system_analysis":
            if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
                return "waiting_confirmation"
        if stage_run and stage_run.status == "waiting_confirmation":
            return "waiting_confirmation"
        statuses = [self._normalize_downstream_status(item.status) or item.status for item in items]
        aggregated_item_status = self._aggregate_item_statuses(statuses) if statuses else None
        archive_gated = self._stage_archive_success_blocked(task, stage_name, items, db=db)
        if (
            not items
            and stage_run is not None
            and self._stage_requires_materialized_inputs(task, stage_name)
            and not self._is_streaming_tail_stage(task, stage_name)
        ):
            normalized_run_status = self._normalize_downstream_status(stage_run.status) or str(stage_run.status or "")
            if normalized_run_status in {"failed", "downstream_missing", "cancelled", "partial_success"}:
                return "pending"
        if self._is_streaming_tail_stage(task, stage_name) and any(
            self._is_streaming_active_item_status(item.status)
            for item in items
        ):
            return "running"
        if archive_gated and aggregated_item_status in {"success", "partial_success"}:
            return "running"
        if stage_run:
            normalized_run_status = self._normalize_downstream_status(stage_run.status) or str(stage_run.status or "")
            if normalized_run_status in {"pending", "queued", "running", "dispatching"} and aggregated_item_status not in {None, "pending"}:
                return aggregated_item_status
            if normalized_run_status in {"running", "dispatching"} and aggregated_item_status == "pending":
                return "running"
            if archive_gated and normalized_run_status in {"success", "partial_success"}:
                return "running"
            if normalized_run_status in {
                "success",
                "partial_success",
                "failed",
                "downstream_missing",
                "cancelled",
                "waiting_confirmation",
                "running",
                "queued",
                "pending",
                "dispatching",
            }:
                return normalized_run_status
        if aggregated_item_status:
            return aggregated_item_status
        return "pending"

    def _status_label(self, status: str) -> str:
        return {
            "pending": "pending",
            "queued": "queued",
            "running": "running",
            "applying": "applying",
            "success": "success",
            "skipped": "skipped",
            "partial_success": "partial_success",
            "failed": "failed",
            "downstream_missing": "downstream_missing",
            "cancelled": "cancelled",
            "waiting_confirmation": "waiting_confirmation",
        }.get(status, status)

    @staticmethod
    def _abnormal_reason_evidence(key: str, label: str, value: Any) -> BinarySecurityAbnormalEvidence | None:
        text = str(value or "").strip()
        if not text:
            return None
        return BinarySecurityAbnormalEvidence(key=key, label=label, value=text)

    @staticmethod
    def _abnormal_reason_message(raw: Any, fallback: str) -> str:
        text = str(raw or "").strip()
        return text or fallback

    @staticmethod
    def _abnormal_reason_code_from_message(message: str, *, fallback: str) -> str:
        lowered = str(message or "").lower()
        if "lease lost" in lowered or "租约" in lowered:
            return "lease_lost"
        if "cancel" in lowered or "取消" in lowered:
            return "runtime_interrupted"
        if any(token in lowered for token in ("auth", "dependency", "upstream", "503", "502", "connection refused", "timeout")):
            return "dependency_unavailable"
        if "dispatch" in lowered or "调度" in lowered:
            return "dispatch_failed"
        return fallback

    def _build_abnormal_reason(
        self,
        *,
        category: str,
        code: str,
        title: str,
        message: str,
        source_layer: str,
        status: str,
        service: str,
        stage_name: str | None = None,
        item_key: str | None = None,
        downstream_task_id: str | None = None,
        downstream_service: str | None = None,
        first_seen_at: datetime | None = None,
        last_seen_at: datetime | None = None,
        evidence: list[BinarySecurityAbnormalEvidence | None] | None = None,
        recommended_action: str | None = None,
        related_event_ids: list[str] | None = None,
        terminal: bool = True,
    ) -> BinarySecurityAbnormalReason:
        return BinarySecurityAbnormalReason(
            is_abnormal=True,
            category=category,
            code=code,
            title=title,
            message=message,
            terminal=terminal,
            source_layer=source_layer,
            status=status,
            service=service,
            stage_name=stage_name,
            item_key=item_key,
            downstream_task_id=downstream_task_id,
            downstream_service=downstream_service,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            evidence=[item for item in (evidence or []) if item is not None],
            recommended_action=recommended_action,
            related_event_ids=list(related_event_ids or []),
        )

    def _stage_item_abnormal_reason(
        self,
        item: BinarySecurityStageItem,
        *,
        task: BinarySecurityTask | None = None,
    ) -> BinarySecurityAbnormalReason | None:
        status = self._normalize_downstream_status(item.status) or str(item.status or "")
        if status not in {"failed", "cancelled", "downstream_missing", "partial_success"}:
            return None
        error_message = self._abnormal_reason_message(item.error_message, "阶段子任务异常结束")
        if status == "downstream_missing":
            code = "downstream_missing"
            title = "下游任务不存在"
            category = "downstream"
            recommended_action = "检查下游任务是否被提前删除，必要时重新同步状态或重试当前阶段。"
        elif status == "cancelled":
            code = "downstream_cancelled"
            title = "下游任务已取消"
            category = "downstream"
            recommended_action = "检查是否有人为取消、父任务取消或下游运行时中断。"
        elif status == "partial_success":
            code = "result_inconsistent"
            title = "子任务部分成功"
            category = "orchestration"
            recommended_action = "结合时间线和下游详情检查未收敛的失败项。"
        else:
            if self._is_owner_lost_recoverable_failure(
                failure_message=error_message,
                error_type=self._stage_item_sync_error_type_value(item),
                item=item,
            ):
                exhausted = bool(task is not None and self._owner_lost_retry_exhausted(task, item))
                code = "owner_lost_retry_exhausted" if exhausted else "owner_lost_recoverable"
                title = "下游 owner 丢失自动恢复失败" if exhausted else "下游 owner 丢失，等待自动恢复"
                category = "infrastructure"
                recommended_action = "检查 rollout、worker 与 lease 变更，并手工重试或排查下游恢复能力。" if exhausted else "优先等待系统自动接管；若多次恢复后仍失败，再检查 rollout、worker 与 lease 变更。"
            else:
                code = "downstream_failed"
                title = "下游任务失败"
                category = "downstream"
                recommended_action = "优先查看下游任务详情与原始错误信息。"
        return self._build_abnormal_reason(
            category=category,
            code=code,
            title=title,
            message=error_message,
            source_layer="item",
            status=status,
            service=str(item.downstream_service or "binary-security"),
            stage_name=item.stage_name,
            item_key=item.item_key,
            downstream_task_id=item.downstream_task_id,
            downstream_service=item.downstream_service,
            first_seen_at=item.started_at,
            last_seen_at=item.finished_at or item.updated_at,
            evidence=[
                self._abnormal_reason_evidence("stage_name", "阶段", item.stage_name),
                self._abnormal_reason_evidence("item_key", "子任务 Key", item.item_key),
                self._abnormal_reason_evidence("downstream_task_id", "下游任务 ID", item.downstream_task_id),
                self._abnormal_reason_evidence("error_message", "原始错误", item.error_message),
            ],
            recommended_action=recommended_action,
        )

    def _archive_job_abnormal_reason(self, job: BinarySecurityArchiveJob) -> BinarySecurityAbnormalReason | None:
        normalized_status = str(job.archive_status or "").strip()
        if normalized_status == "running" and not job.archive_root and not job.completed_at:
            return self._build_abnormal_reason(
                category="archive",
                code="archive_stale_running",
                title="归档任务长时间运行未收敛",
                message="归档任务处于 running 且长时间未完成，可能发生了 worker 中断或回收延迟。",
                source_layer="archive",
                status=normalized_status,
                service="binary-security",
                stage_name=job.stage_name,
                item_key=job.item_key,
                downstream_task_id=job.downstream_task_id,
                downstream_service=job.downstream_service,
                first_seen_at=job.started_at or job.created_at,
                last_seen_at=job.updated_at,
                evidence=[
                    self._abnormal_reason_evidence("stage_name", "阶段", job.stage_name),
                    self._abnormal_reason_evidence("item_key", "条目", job.item_key),
                    self._abnormal_reason_evidence("downstream_task_id", "下游任务 ID", job.downstream_task_id),
                    self._abnormal_reason_evidence("owner_id", "归档 owner", job.owner_id),
                ],
                recommended_action="优先检查归档 worker 是否中断，以及是否触发了自动回收。",
                terminal=False,
            )
        if normalized_status != "failed":
            return None
        error_text = str(job.error_message or "").lower()
        if "reclaim exhausted" in error_text:
            code = "archive_reclaim_exhausted"
        elif "下游产物归档未完成" in str(job.error_message or "").strip() and int((job.payload or {}).get("copy_retry_attempt") or 0) >= len(self._archive_copy_missing_source_retry_schedule_seconds()):
            code = "archive_source_retry_exhausted"
        else:
            code = "archive_failed"
        return self._build_abnormal_reason(
            category="archive",
            code=code,
            title="归档任务失败",
            message=self._abnormal_reason_message(job.error_message, "阶段产物归档失败"),
            source_layer="archive",
            status=str(job.archive_status or "failed"),
            service="binary-security",
            stage_name=job.stage_name,
            item_key=job.item_key,
            downstream_task_id=job.downstream_task_id,
            downstream_service=job.downstream_service,
            first_seen_at=job.started_at or job.created_at,
            last_seen_at=job.completed_at or job.updated_at,
            evidence=[
                self._abnormal_reason_evidence("stage_name", "阶段", job.stage_name),
                self._abnormal_reason_evidence("item_key", "条目", job.item_key),
                self._abnormal_reason_evidence("downstream_task_id", "下游任务 ID", job.downstream_task_id),
                self._abnormal_reason_evidence("archive_root", "归档目录", job.archive_root),
                self._abnormal_reason_evidence("error_message", "归档错误", job.error_message),
            ],
            recommended_action="检查归档目录、文件系统权限和下游产物是否完整。",
        )

    def _string_or_none(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _bool_or_none(self, value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "y", "on"}:
                return True
            if normalized in {"false", "0", "no", "n", "off"}:
                return False
            return None
        if isinstance(value, (int, float)):
            return bool(value)
        return None

    def _int_or_none(self, value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _stage_abnormal_reason(
        self,
        task: BinarySecurityTask,
        stage_name: str,
        summary: BinarySecurityStageSummary,
        stage_items: list[BinarySecurityStageItem],
    ) -> BinarySecurityAbnormalReason | None:
        if summary.status not in {"failed", "cancelled", "partial_success", "downstream_missing"}:
            return None
        item_reason = next(
            (
                self._stage_item_abnormal_reason(item, task=task)
                for item in reversed(stage_items)
                if self._stage_item_abnormal_reason(item, task=task)
            ),
            None,
        )
        if item_reason is not None:
            return item_reason.model_copy(update={"source_layer": "stage", "service": "binary-security", "stage_name": stage_name})
        message = self._abnormal_reason_message(summary.last_error, f"阶段 {stage_name} 异常结束")
        code = self._abnormal_reason_code_from_message(message, fallback="orchestration_failed")
        category = "runtime" if code in {"lease_lost", "runtime_interrupted", "dispatch_failed", "dependency_unavailable"} else "orchestration"
        return self._build_abnormal_reason(
            category=category,
            code=code if summary.status != "downstream_missing" else "downstream_missing",
            title="阶段异常结束" if summary.status != "partial_success" else "阶段部分成功",
            message=message,
            source_layer="stage",
            status=summary.status,
            service="binary-security",
            stage_name=stage_name,
            first_seen_at=summary.started_at,
            last_seen_at=summary.finished_at,
            evidence=[
                self._abnormal_reason_evidence("stage_name", "阶段", stage_name),
                self._abnormal_reason_evidence("stage_status", "阶段状态", summary.status),
                self._abnormal_reason_evidence("last_error", "原始错误", summary.last_error),
            ],
            recommended_action="查看阶段时间线、下游任务和归档节点，确认是哪一层先出现异常。",
        )

    def _task_success_abnormal_reason(
        self,
        task: BinarySecurityTask,
        stage_summaries: list[BinarySecurityStageSummary],
        items: list[BinarySecurityStageItem],
        archive_jobs: list[BinarySecurityArchiveJob],
    ) -> BinarySecurityAbnormalReason | None:
        del archive_jobs
        dataflow_summary = next(
            (
                summary
                for summary in stage_summaries
                if normalize_stage_name(summary.stage_name) == "dataflow_vuln_scan"
            ),
            None,
        )
        if dataflow_summary is None:
            return None
        dataflow_items = [
            item
            for item in items
            if normalize_stage_name(item.stage_name) == "dataflow_vuln_scan"
        ]
        success_count = sum(
            1
            for item in dataflow_items
            if (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()) in {"success", "partial_success"}
        )
        if success_count <= 0:
            return None
        abnormal_item_count = sum(
            1
            for item in dataflow_items
            if (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower())
            in {"failed", "partial_success", "downstream_missing", "cancelled"}
        )
        if str(dataflow_summary.status or "").strip() != "partial_success" and abnormal_item_count <= 0:
            return None
        latest_item_reason = next(
            (
                self._stage_item_abnormal_reason(item, task=task)
                for item in reversed(dataflow_items)
                if self._stage_item_abnormal_reason(item, task=task) is not None
            ),
            None,
        )
        evidence = [
            self._abnormal_reason_evidence("stage_name", "阶段", "dataflow_vuln_scan"),
            self._abnormal_reason_evidence("stage_status", "阶段状态", dataflow_summary.status),
            self._abnormal_reason_evidence("success_items", "成功子任务数", success_count),
            self._abnormal_reason_evidence("failed_items", "失败子任务数", dataflow_summary.failed_items),
            self._abnormal_reason_evidence("downstream_missing_items", "缺失子任务数", dataflow_summary.downstream_missing_items),
            self._abnormal_reason_evidence("last_error", "原始错误", dataflow_summary.last_error),
        ]
        if latest_item_reason is not None:
            evidence.extend(
                [
                    self._abnormal_reason_evidence("latest_abnormal_item", "最近异常子任务", latest_item_reason.item_key),
                    self._abnormal_reason_evidence("latest_abnormal_message", "最近异常原因", latest_item_reason.message),
                ]
            )
        return self._build_abnormal_reason(
            category="orchestration",
            code="dataflow_partial_success",
            title="数据流阶段部分成功",
            message="数据流漏洞挖掘已成功产出部分结果，但仍存在失败子任务。",
            source_layer="task",
            status="partial_success",
            service="binary-security",
            stage_name="dataflow_vuln_scan",
            first_seen_at=dataflow_summary.started_at,
            last_seen_at=dataflow_summary.finished_at,
            evidence=evidence,
            recommended_action="任务已成功结束；如需补齐剩余结果，请查看失败子任务并按需重试失败项。",
            terminal=False,
        )

    def _abnormal_reason_history(self, db: Session, task: BinarySecurityTask) -> list[BinarySecurityAbnormalReasonEventSummary]:
        rows = (
            db.query(BinarySecurityEvent)
            .filter(
                BinarySecurityEvent.task_id == task.id,
                BinarySecurityEvent.event_type == "abnormal_reason_recorded",
            )
            .order_by(BinarySecurityEvent.created_at.desc())
            .limit(10)
            .all()
        )
        history: list[BinarySecurityAbnormalReasonEventSummary] = []
        for row in rows:
            payload = dict(row.payload or {})
            reason_payload = payload.get("reason") if isinstance(payload.get("reason"), dict) else payload
            if not isinstance(reason_payload, dict):
                continue
            try:
                history.append(
                    BinarySecurityAbnormalReasonEventSummary(
                        event_id=row.id,
                        created_at=row.created_at,
                        reason=BinarySecurityAbnormalReason(**reason_payload),
                    )
                )
            except Exception:
                continue
        return history

    def _sync_task_abnormal_reason_snapshot(
        self,
        db: Session,
        task: BinarySecurityTask,
        reason: BinarySecurityAbnormalReason | None,
    ) -> None:
        previous = task.latest_abnormal_reason or None
        next_payload = reason.model_dump(mode="json") if reason is not None else None
        if previous == next_payload:
            return
        task.latest_abnormal_reason = next_payload
        if reason is None:
            return
        self._record_event(
            db,
            task,
            "abnormal_reason_recorded",
            reason.title,
            level="warning" if reason.status in {"partial_success", "cancelled"} else "error",
            stage_name=reason.stage_name,
            payload={"reason": next_payload},
        )

    def _clear_task_abnormal_reason_snapshot(self, db: Session, task: BinarySecurityTask) -> None:
        self._sync_task_abnormal_reason_snapshot(db, task, None)

    def _aggregate_archive_stage_status(self, statuses: list[str]) -> str:
        if not statuses:
            return "pending"
        normalized = [str(status or "").strip().lower() for status in statuses]
        if any(status == "running" for status in normalized):
            return "running"
        if any(status in {"archived", "applying"} for status in normalized):
            return "applying"
        if any(status == "failed" for status in normalized):
            return "failed"
        terminal = [status for status in normalized if status != "skipped"]
        if terminal and all(status == "success" for status in terminal):
            return "success"
        return "pending"

    def _stage_requires_archive_success_gate(self, task: BinarySecurityTask, stage_name: str) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        if normalized_stage in {"firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis"}:
            return True
        return False

    def _streaming_edges_for_task(self, task: BinarySecurityTask) -> tuple[tuple[str, str], ...]:
        if not self._streaming_mode_enabled(task):
            return ()
        sequence = [stage for stage in self._stage_sequence_for_task(task) if self._stage_enabled(task, stage)]
        if len(sequence) < 2:
            return ()
        return tuple((sequence[index], sequence[index + 1]) for index in range(len(sequence) - 1))

    def _streaming_upstream_stage(self, task: BinarySecurityTask, downstream_stage: str | None) -> str | None:
        normalized_downstream = normalize_stage_name(downstream_stage)
        for upstream_stage, candidate_downstream in self._streaming_edges_for_task(task):
            if normalize_stage_name(candidate_downstream) == normalized_downstream:
                return upstream_stage
        return None

    def _stage_item_has_successful_archive_job(
        self,
        item: BinarySecurityStageItem,
        archive_jobs: list[BinarySecurityArchiveJob] | None = None,
    ) -> bool:
        normalized_status = self._normalize_downstream_status(getattr(item, "status", None)) or str(getattr(item, "status", "") or "").strip().lower()
        if normalized_status not in ARCHIVE_SUCCESS_MAPPED_STATUSES:
            return False
        return self._archive_job_status_value(
            self._canonical_archive_job_for_item(item, archive_jobs=archive_jobs)
        ) == "success"

    def _stage_archived_success_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> list[BinarySecurityStageItem]:
        normalized_stage = normalize_stage_name(stage_name)
        if normalized_stage == "knowledge_graph_entry_fetch":
            return []
        archive_jobs_by_item = self._stage_archive_jobs_by_item(db, task.id, normalized_stage)
        return [
            item
            for item in self._stage_items(db, task.id, normalized_stage)
            if self._stage_item_has_successful_archive_job(item, archive_jobs_by_item.get(str(item.id or ""), []))
        ]

    def _stage_has_archived_success_progress(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        if normalized_stage == "knowledge_graph_entry_fetch":
            return str(self._virtual_archive_stage_status(db, task, normalized_stage) or "").strip().lower() == "success"
        return bool(self._stage_archived_success_items(db, task, normalized_stage))

    def _archived_success_stage_payload_rows(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        archive_jobs_by_item = self._stage_archive_jobs_by_item(db, task.id, stage_name)
        for item in self._stage_archived_success_items(db, task, stage_name):
            resolved_archive_refs = self._resolved_stage_item_archive_refs(
                item,
                archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []),
            )
            rows.append(
                {
                    **dict(item.input_ref or {}),
                    **dict(item.output_ref or {}),
                    **self._load_stage_item_result_payload(item),
                    **resolved_archive_refs,
                }
            )
        return rows

    def _stage_archive_jobs_by_item(self, db: Session, task_id: str, stage_name: str) -> dict[str, list[BinarySecurityArchiveJob]]:
        def _load_grouped() -> dict[str, list[BinarySecurityArchiveJob]]:
            jobs = (
                db.query(BinarySecurityArchiveJob)
                .filter(
                    BinarySecurityArchiveJob.task_id == task_id,
                    BinarySecurityArchiveJob.stage_name == stage_name,
                )
                .order_by(BinarySecurityArchiveJob.created_at.asc(), BinarySecurityArchiveJob.id.asc())
                .all()
            )
            grouped_rows: dict[str, list[BinarySecurityArchiveJob]] = {}
            for job in jobs:
                grouped_rows.setdefault(str(job.item_id or ""), []).append(job)
            return grouped_rows

        grouped = _load_grouped()
        if not grouped:
            return grouped
        task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
        if task is None:
            return grouped
        stage_items = self._stage_items(db, task_id, stage_name)
        items_by_id = {
            str(getattr(item, "id", "") or "").strip(): item
            for item in stage_items
            if str(getattr(item, "id", "") or "").strip()
        }
        pruned = False
        for item_id, item_jobs in list(grouped.items()):
            item = items_by_id.get(str(item_id or "").strip())
            if item is None:
                continue
            if self._prune_nonblocking_archive_jobs_for_item(
                db,
                task,
                item,
                archive_jobs=item_jobs,
                reason="stage_archive_jobs_by_item",
            ):
                pruned = True
        if pruned:
            db.flush()
            grouped = _load_grouped()
        return grouped

    @staticmethod
    def _archive_jobs_by_item_id(archive_jobs: list[BinarySecurityArchiveJob]) -> dict[str, list[BinarySecurityArchiveJob]]:
        grouped: dict[str, list[BinarySecurityArchiveJob]] = {}
        for job in archive_jobs:
            grouped.setdefault(str(getattr(job, "item_id", "") or ""), []).append(job)
        return grouped

    def _resolved_stage_item_archive_refs(
        self,
        item: BinarySecurityStageItem,
        archive_jobs: list[BinarySecurityArchiveJob] | None = None,
    ) -> dict[str, Any]:
        current_output_ref = dict(item.output_ref or {})
        current_result = self._load_stage_item_result_payload(item)
        resolved: dict[str, Any] = {}
        for key in ("artifact_root", "archive_root", "archive_copy_stats"):
            current_value = current_output_ref.get(key)
            if current_value is None:
                current_value = current_result.get(key)
            if current_value is not None:
                resolved[key] = current_value
        if archive_jobs:
            ordered_jobs = sorted(
                archive_jobs,
                key=lambda job: (
                    getattr(job, "updated_at", None) or getattr(job, "completed_at", None) or getattr(job, "created_at", None) or datetime.min,
                    str(getattr(job, "id", "") or ""),
                ),
            )
            for job in reversed(ordered_jobs):
                if "archive_root" not in resolved and getattr(job, "archive_root", None):
                    resolved["archive_root"] = job.archive_root
                payload = dict(getattr(job, "payload", None) or {})
                if "artifact_root" not in resolved and payload.get("artifact_root"):
                    resolved["artifact_root"] = payload.get("artifact_root")
                if "archive_copy_stats" not in resolved and payload.get("archive_copy_stats") is not None:
                    resolved["archive_copy_stats"] = dict(payload.get("archive_copy_stats") or {})
                if "archive_job_id" not in resolved and getattr(job, "id", None):
                    resolved["archive_job_id"] = job.id
                if "archive_status" not in resolved and getattr(job, "archive_status", None):
                    resolved["archive_status"] = job.archive_status
                if all(
                    key in resolved
                    for key in ("archive_root", "artifact_root", "archive_copy_stats", "archive_job_id", "archive_status")
                ):
                    break
        if "artifact_root" not in resolved and resolved.get("archive_root"):
            resolved["artifact_root"] = resolved["archive_root"]
        return resolved

    def _stage_item_archive_root(
        self,
        item: BinarySecurityStageItem,
        archive_jobs: list[BinarySecurityArchiveJob] | None = None,
    ) -> str:
        resolved = self._resolved_stage_item_archive_refs(item, archive_jobs=archive_jobs)
        return str(
            resolved.get("archive_root")
            or resolved.get("artifact_root")
            or dict(item.output_ref or {}).get("unpacked_root")
            or self._load_stage_item_result_payload(item).get("unpacked_root")
            or ""
        ).strip()

    def _stage_item_artifact_root(
        self,
        item: BinarySecurityStageItem,
        archive_jobs: list[BinarySecurityArchiveJob] | None = None,
    ) -> str:
        resolved = self._resolved_stage_item_archive_refs(item, archive_jobs=archive_jobs)
        return str(
            resolved.get("artifact_root")
            or resolved.get("archive_root")
            or ""
        ).strip()

    def _stage_archive_success_blocked(
        self,
        task: BinarySecurityTask,
        stage_name: str,
        items: list[BinarySecurityStageItem],
        *,
        db: Session | None = None,
    ) -> bool:
        if not items or not self._stage_requires_archive_success_gate(task, stage_name):
            return False
        session = db
        owns_session = False
        if session is None:
            session = get_session_factory()()
            owns_session = True
        try:
            jobs_by_item = self._stage_archive_jobs_by_item(session, task.id, stage_name)
            for item in items:
                normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip()
                if normalized_status not in ARCHIVE_SUCCESS_MAPPED_STATUSES:
                    continue
                canonical_job = self._canonical_archive_job_for_item(
                    item,
                    archive_jobs=jobs_by_item.get(str(item.id or ""), []),
                )
                if canonical_job is None:
                    return True
                if self._archive_job_status_value(canonical_job) != "success":
                    return True
            return False
        finally:
            if owns_session:
                session.close()

    def _stage_archive_progress_detail(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        items: list[BinarySecurityStageItem] | None = None,
    ) -> dict[str, Any]:
        normalized_stage = normalize_stage_name(stage_name)
        resolved_items = list(items or self._stage_items(db, task.id, normalized_stage) or [])
        archive_jobs_by_item = self._stage_archive_jobs_by_item(db, task.id, normalized_stage)
        canonical_jobs = self._canonical_archive_jobs_for_stage_items(
            resolved_items,
            archive_jobs_by_item=archive_jobs_by_item,
        )
        success_candidate_items = [
            item
            for item in resolved_items
            if (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower())
            in ARCHIVE_SUCCESS_MAPPED_STATUSES
        ]
        archived_success_items = sum(
            1
            for item in success_candidate_items
            if self._stage_item_has_successful_archive_job(
                item,
                archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []),
            )
        )
        status = self._aggregate_archive_stage_status(
            [str(getattr(job, "archive_status", None) or "").strip() for job in canonical_jobs]
        )
        expected_success_item_count = len(success_candidate_items)
        missing_archive_item_count = max(0, expected_success_item_count - archived_success_items)
        if expected_success_item_count <= 0 and not canonical_jobs:
            status = "pending"
        elif expected_success_item_count > 0 and archived_success_items >= expected_success_item_count and status == "pending":
            status = "success"
        return {
            "status": status,
            "expected_success_item_count": expected_success_item_count,
            "archived_success_item_count": archived_success_items,
            "missing_archive_item_count": missing_archive_item_count,
            "job_count": len(canonical_jobs),
            "success_count": len([job for job in canonical_jobs if str(job.archive_status or "").strip() == "success"]),
            "failed_count": len([job for job in canonical_jobs if str(job.archive_status or "").strip() == "failed"]),
            "running_count": len([job for job in canonical_jobs if str(job.archive_status or "").strip() == "running"]),
            "applying_count": len([job for job in canonical_jobs if str(job.archive_status or "").strip() in {"archived", "applying"}]),
            "pending_count": len([job for job in canonical_jobs if str(job.archive_status or "").strip() == "pending"]),
            "latest_error": next(
                (
                    job.error_message
                    for job in reversed(canonical_jobs)
                    if str(job.archive_status or "").strip() == "failed" and job.error_message
                ),
                None,
            ),
        }

    def _downstream_status_display_value(self, raw_status: str | None) -> str:
        normalized = str(raw_status or "").strip().lower()
        if not normalized:
            return "unknown"
        return normalized

    def _build_project_stats(self, tasks: list[BinarySecurityTask]) -> BinarySecurityProjectStats:
        active_statuses = {
            "pending",
            "dispatching",
            "running",
            "pending_upload",
            "uploading",
            TASK_STATUS_PENDING_MODULE_CONFIRMATION,
        }
        stats = BinarySecurityProjectStats(total=len(tasks))
        for task in tasks:
            status = task.status or ""
            metrics = task.metrics or {}
            if status in active_statuses:
                stats.running += 1
            elif status == "success":
                stats.success += 1
            elif status == "partial_success":
                stats.partial_success += 1
            elif status == "failed":
                stats.failed += 1
            elif status == "cancelled":
                stats.cancelled += 1
            stats.selected_module_count += int(metrics.get("selected_module_count") or 0)
            stats.candidate_module_count += int(metrics.get("candidate_module_count") or 0)
            stats.high_risk_module_count += int(metrics.get("high_risk_module_count") or 0)
            stats.entry_count += int(metrics.get("entry_count") or 0)
            stats.vuln_result_count += int(metrics.get("vuln_result_count") or 0)
            stats.input_count += int(metrics.get("firmware_item_count") or 0)
            stats.unpacked_firmware_count += int(metrics.get("unpacked_firmware_count") or 0)
            stats.failed_firmware_count += int(metrics.get("failed_firmware_count") or 0)
        return stats

    def _build_project_stats_sql(
        self,
        db: Session,
        *,
        project_id: str,
        task_type: str | None = None,
        pipeline_profile: str | None = None,
    ) -> BinarySecurityProjectStats:
        base_query = db.query(BinarySecurityTask).filter(BinarySecurityTask.project_id == project_id)
        normalized_task_type = self._validate_task_type(task_type) if task_type else None
        if normalized_task_type:
            if normalized_task_type == TASK_TYPE_BINARY:
                base_query = base_query.filter(
                    or_(
                        BinarySecurityTask.task_type == TASK_TYPE_BINARY,
                        BinarySecurityTask.task_type.is_(None),
                    )
                )
            else:
                base_query = base_query.filter(BinarySecurityTask.task_type == normalized_task_type)
        if pipeline_profile and normalized_task_type == TASK_TYPE_SOURCE:
            base_query = self._apply_pipeline_profile_filter(base_query, pipeline_profile)
        active_statuses = (
            "pending",
            "dispatching",
            "running",
            "pending_upload",
            "uploading",
            TASK_STATUS_PENDING_MODULE_CONFIRMATION,
        )
        if not hasattr(base_query, "with_entities"):
            tasks = base_query.options(load_only(BinarySecurityTask.status, BinarySecurityTask.metrics_json)).all()
            return self._build_project_stats(tasks)

        def _json_metric_sum(metric_key: str):
            return func.sum(
                cast(
                    func.coalesce(
                        func.json_extract(BinarySecurityTask.metrics_json, f'$.{metric_key}'),
                        0,
                    ),
                    Integer,
                )
            )
        try:
            row = base_query.with_entities(
                func.count(BinarySecurityTask.id),
                func.sum(case((BinarySecurityTask.status.in_(active_statuses), 1), else_=0)),
                func.sum(case((BinarySecurityTask.status == "success", 1), else_=0)),
                func.sum(case((BinarySecurityTask.status == "partial_success", 1), else_=0)),
                func.sum(case((BinarySecurityTask.status == "failed", 1), else_=0)),
                func.sum(case((BinarySecurityTask.status == "cancelled", 1), else_=0)),
                _json_metric_sum("selected_module_count"),
                _json_metric_sum("candidate_module_count"),
                _json_metric_sum("high_risk_module_count"),
                _json_metric_sum("entry_count"),
                _json_metric_sum("vuln_result_count"),
                _json_metric_sum("firmware_item_count"),
                _json_metric_sum("unpacked_firmware_count"),
                _json_metric_sum("failed_firmware_count"),
            ).one()
        except Exception:
            logger.debug(
                "Falling back to in-memory project stats aggregation",
                exc_info=True,
            )
            tasks = base_query.options(load_only(BinarySecurityTask.status, BinarySecurityTask.metrics_json)).all()
            return self._build_project_stats(tasks)

        return BinarySecurityProjectStats(
            total=int(row[0] or 0),
            running=int(row[1] or 0),
            success=int(row[2] or 0),
            partial_success=int(row[3] or 0),
            failed=int(row[4] or 0),
            cancelled=int(row[5] or 0),
            selected_module_count=int(row[6] or 0),
            candidate_module_count=int(row[7] or 0),
            high_risk_module_count=int(row[8] or 0),
            entry_count=int(row[9] or 0),
            vuln_result_count=int(row[10] or 0),
            input_count=int(row[11] or 0),
            unpacked_firmware_count=int(row[12] or 0),
            failed_firmware_count=int(row[13] or 0),
        )

    def _build_project_stage_aggregates(
        self,
        db: Session,
        tasks: list[BinarySecurityTask],
        task_type: str | None = None,
    ) -> list[BinarySecurityProjectStageAggregate]:
        if task_type:
            stage_sequence = list(TASK_STAGE_SEQUENCES.get(task_type, STAGE_SEQUENCE))
        elif tasks and all(self._task_type(task) == TASK_TYPE_SOURCE for task in tasks):
            stage_sequence = list(TASK_STAGE_SEQUENCES[TASK_TYPE_SOURCE])
        else:
            stage_sequence = list(TASK_STAGE_SEQUENCES[TASK_TYPE_BINARY])

        aggregates = {
            stage_name: BinarySecurityProjectStageAggregate(stage_name=stage_name, sequence_no=index)
            for index, stage_name in enumerate(stage_sequence, start=1)
        }
        task_ids = [task.id for task in tasks if task.id]
        if not task_ids:
            return list(aggregates.values())

        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id.in_(task_ids)).all()
        task_counts_by_stage: dict[str, set[str]] = {}
        for run in stage_runs:
            stage_name = getattr(run, "stage_name", None)
            task_id = getattr(run, "task_id", None)
            if not stage_name or not task_id or stage_name not in aggregates:
                continue
            task_counts_by_stage.setdefault(stage_name, set()).add(task_id)
        for stage_name, task_ids_for_stage in task_counts_by_stage.items():
            aggregates[stage_name].business.task_count = len(task_ids_for_stage)

        stage_items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id.in_(task_ids)).all()
        for item in stage_items:
            stage_name = getattr(item, "stage_name", None)
            if not stage_name or stage_name not in aggregates:
                continue
            raw_status = getattr(item, "status", None)
            status = self._normalize_downstream_status(raw_status) or raw_status or "unknown"
            business = aggregates[stage_name].business
            business.total_items += 1
            business.status_counts[status] = business.status_counts.get(status, 0) + 1
            if status == "success":
                business.success_items += 1
            elif status == "failed":
                business.failed_items += 1
            elif status == "cancelled":
                business.cancelled_items += 1
            if status in {"pending", "queued", "running", "dispatching"}:
                business.running_items += 1

        archive_jobs = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.task_id.in_(task_ids)).all()
        for job in archive_jobs:
            stage_name = getattr(job, "stage_name", None)
            if not stage_name or stage_name not in aggregates:
                continue
            status = str(getattr(job, "archive_status", None) or "unknown").strip().lower() or "unknown"
            archive = aggregates[stage_name].archive
            archive.job_count += 1
            archive.status_counts[status] = archive.status_counts.get(status, 0) + 1
            if status == "success":
                archive.success_count += 1
            elif status == "failed":
                archive.failed_count += 1
            elif status == "running":
                archive.running_count += 1
            elif status in {"archived", "applying"}:
                archive.applying_count += 1
            elif status == "pending":
                archive.pending_count += 1

        return list(aggregates.values())

    def _build_project_stage_aggregates_sql(
        self,
        db: Session,
        *,
        project_id: str,
        task_type: str | None = None,
        pipeline_profile: str | None = None,
    ) -> list[BinarySecurityProjectStageAggregate]:
        normalized_task_type = self._validate_task_type(task_type) if task_type else None
        if normalized_task_type == TASK_TYPE_SOURCE and pipeline_profile:
            stage_sequence = list(TASK_PIPELINE_PROFILE_SEQUENCES.get((TASK_TYPE_SOURCE, pipeline_profile), TASK_STAGE_SEQUENCES[TASK_TYPE_SOURCE]))
        elif normalized_task_type:
            stage_sequence = list(TASK_STAGE_SEQUENCES.get(normalized_task_type, STAGE_SEQUENCE))
        else:
            stage_sequence = list(TASK_STAGE_SEQUENCES[TASK_TYPE_BINARY])

        aggregates = {
            stage_name: BinarySecurityProjectStageAggregate(stage_name=stage_name, sequence_no=index)
            for index, stage_name in enumerate(stage_sequence, start=1)
        }

        task_join_filters = [BinarySecurityTask.project_id == project_id]
        if normalized_task_type:
            if normalized_task_type == TASK_TYPE_BINARY:
                task_join_filters.append(
                    or_(
                        BinarySecurityTask.task_type == TASK_TYPE_BINARY,
                        BinarySecurityTask.task_type.is_(None),
                    )
                )
            else:
                task_join_filters.append(BinarySecurityTask.task_type == normalized_task_type)
        if pipeline_profile and normalized_task_type == TASK_TYPE_SOURCE:
            compact_like = f'%"pipeline_profile":"{pipeline_profile}"%'
            spaced_like = f'%"pipeline_profile": "{pipeline_profile}"%'
            if pipeline_profile == PIPELINE_PROFILE_DEFAULT:
                task_join_filters.append(
                    or_(
                        BinarySecurityTask.policy_json.is_(None),
                        BinarySecurityTask.policy_json == "",
                        ~BinarySecurityTask.policy_json.like('%"pipeline_profile"%'),
                        BinarySecurityTask.policy_json.like(compact_like),
                        BinarySecurityTask.policy_json.like(spaced_like),
                    )
                )
            else:
                task_join_filters.append(
                    or_(
                        BinarySecurityTask.policy_json.like(compact_like),
                        BinarySecurityTask.policy_json.like(spaced_like),
                    )
                )

        def _safe_all(query, section: str):
            try:
                return query.all()
            except Exception:
                logger.debug(
                    "Project stage aggregate SQL query failed; leaving section empty",
                    extra={"project_id": project_id, "task_type": normalized_task_type or "all", "section": section},
                    exc_info=True,
                )
                return []

        stage_run_rows = _safe_all(
            db.query(BinarySecurityStageRun.stage_name, func.count(func.distinct(BinarySecurityStageRun.task_id)))
            .join(BinarySecurityTask, BinarySecurityTask.id == BinarySecurityStageRun.task_id)
            .filter(*task_join_filters)
            .group_by(BinarySecurityStageRun.stage_name)
            ,
            "stage_runs",
        )
        for stage_name, task_count in stage_run_rows:
            if stage_name in aggregates:
                aggregates[stage_name].business.task_count = int(task_count or 0)

        stage_item_rows = _safe_all(
            db.query(
                BinarySecurityStageItem.stage_name,
                BinarySecurityStageItem.status,
                func.count(BinarySecurityStageItem.id),
            )
            .join(BinarySecurityTask, BinarySecurityTask.id == BinarySecurityStageItem.task_id)
            .filter(*task_join_filters)
            .group_by(BinarySecurityStageItem.stage_name, BinarySecurityStageItem.status)
            ,
            "stage_items",
        )
        for stage_name, raw_status, count in stage_item_rows:
            aggregate = aggregates.get(stage_name)
            if not aggregate:
                continue
            status = self._normalize_downstream_status(raw_status) or raw_status or "unknown"
            business = aggregate.business
            item_count = int(count or 0)
            business.total_items += item_count
            business.status_counts[status] = business.status_counts.get(status, 0) + item_count
            if status == "success":
                business.success_items += item_count
            elif status == "failed":
                business.failed_items += item_count
            elif status == "cancelled":
                business.cancelled_items += item_count
            if status in {"pending", "queued", "running", "dispatching"}:
                business.running_items += item_count

        archive_job_rows = _safe_all(
            db.query(
                BinarySecurityArchiveJob.stage_name,
                BinarySecurityArchiveJob.archive_status,
                func.count(BinarySecurityArchiveJob.id),
            )
            .join(BinarySecurityTask, BinarySecurityTask.id == BinarySecurityArchiveJob.task_id)
            .filter(*task_join_filters)
            .group_by(BinarySecurityArchiveJob.stage_name, BinarySecurityArchiveJob.archive_status)
            ,
            "archive_jobs",
        )
        for stage_name, raw_status, count in archive_job_rows:
            aggregate = aggregates.get(stage_name)
            if not aggregate:
                continue
            status = str(raw_status or "unknown").strip().lower() or "unknown"
            archive = aggregate.archive
            job_count = int(count or 0)
            archive.job_count += job_count
            archive.status_counts[status] = archive.status_counts.get(status, 0) + job_count
            if status == "success":
                archive.success_count += job_count
            elif status == "failed":
                archive.failed_count += job_count
            elif status == "running":
                archive.running_count += job_count
            elif status in {"archived", "applying"}:
                archive.applying_count += job_count
            elif status == "pending":
                archive.pending_count += job_count

        return list(aggregates.values())

    def _task_sync_status_view(
        self,
        items: list[BinarySecurityStageItem] | None,
    ) -> tuple[datetime | None, datetime | None, datetime | None, str | None, str | None, int, int, int]:
        latest_success: datetime | None = None
        latest_attempt: datetime | None = None
        latest_error_at: datetime | None = None
        latest_error_type: str | None = None
        latest_error_message: str | None = None
        active_sync_error_item_count = 0
        never_synced_item_count = 0
        stale_synced_item_count = 0
        now = _now()
        for item in items or []:
            has_active_sync_error = self._stage_item_has_active_sync_error(item)
            if has_active_sync_error:
                active_sync_error_item_count += 1
            last_synced_at = self._stage_item_last_synced_at_value(item)
            if last_synced_at is not None and (latest_success is None or last_synced_at > latest_success):
                latest_success = last_synced_at
            result = self._load_stage_item_result_payload(item)
            sync_observation = dict(result.get("sync_observation") or {})
            raw_attempt = (
                sync_observation.get("last_attempt_at")
                or sync_observation.get("last_synced_at")
                or result.get("last_sync_attempt_at")
                or result.get("downstream_status_synced_at")
            )
            parsed_attempt: datetime | None = None
            if isinstance(raw_attempt, str) and raw_attempt.strip():
                try:
                    parsed_attempt = datetime.fromisoformat(raw_attempt)
                except ValueError:
                    parsed_attempt = None
            if parsed_attempt is not None and (latest_attempt is None or parsed_attempt > latest_attempt):
                latest_attempt = parsed_attempt
            raw_error_at = sync_observation.get("last_error_at") or result.get("last_sync_error_at")
            parsed_error_at: datetime | None = None
            if isinstance(raw_error_at, str) and raw_error_at.strip():
                try:
                    parsed_error_at = datetime.fromisoformat(raw_error_at)
                except ValueError:
                    parsed_error_at = None
            error_type = self._string_or_none(sync_observation.get("error_type")) or self._string_or_none(result.get("last_sync_error_type"))
            error_message = self._string_or_none(sync_observation.get("error_message")) or self._string_or_none(result.get("last_sync_error_message"))
            if parsed_error_at is not None and has_active_sync_error:
                if latest_error_at is None or parsed_error_at > latest_error_at:
                    latest_error_at = parsed_error_at
                    latest_error_type = error_type
                    latest_error_message = error_message
            elif error_type is not None or error_message is not None:
                latest_error_type = error_type
                latest_error_message = error_message
            if last_synced_at is None and parsed_attempt is not None:
                never_synced_item_count += 1
            if self._stage_item_counts_as_stale_sync(item, now_value=now, last_synced_at=last_synced_at):
                stale_synced_item_count += 1
        return (
            latest_success,
            latest_attempt,
            latest_error_at,
            latest_error_type,
            latest_error_message,
            active_sync_error_item_count,
            never_synced_item_count,
            stale_synced_item_count,
        )

    def _stage_item_has_child_binding(self, item: BinarySecurityStageItem) -> bool:
        if str(getattr(item, "downstream_task_id", "") or "").strip():
            return True
        result = self._load_stage_item_result_payload(item)
        downstream = dict(result.get("downstream") or {})
        return bool(str(downstream.get("task_id") or downstream.get("id") or "").strip())

    def _stage_item_observed_downstream_status(self, item: BinarySecurityStageItem) -> str | None:
        result = self._load_stage_item_result_payload(item)
        sync_observation = self._stage_item_sync_observation(item)
        return (
            self._string_or_none(sync_observation.get("downstream_status"))
            or self._string_or_none(sync_observation.get("mapped_status"))
            or self._string_or_none(result.get("downstream_status"))
        )

    def _stage_item_has_active_sync_error(self, item: BinarySecurityStageItem) -> bool:
        result = self._load_stage_item_result_payload(item)
        sync_observation = self._stage_item_sync_observation(item)
        sync_status = self._stage_item_sync_status_value(item)
        if sync_status in {"binding_mismatch", "binding_missing_during_recreate", "transport_error", "rate_limited"}:
            return True
        if sync_status == "synced" and not self._stage_item_sync_error_budget_exhausted(item):
            return False
        if str(sync_observation.get("last_result") or result.get("last_sync_result") or "").strip().lower() == "success":
            return False
        error_message = self._string_or_none(sync_observation.get("error_message")) or self._string_or_none(result.get("last_sync_error_message"))
        error_type = self._string_or_none(sync_observation.get("error_type")) or self._string_or_none(result.get("last_sync_error_type"))
        if not error_message and not error_type:
            return False
        if not self._stage_item_has_child_binding(item):
            return False
        item_status = self._normalize_downstream_status(item.status)
        observed_status = self._normalize_downstream_status(self._stage_item_observed_downstream_status(item))
        if sync_status == "synced" and observed_status in {"pending", "queued", "running", "dispatching"}:
            return False
        if item_status in {"pending", "queued", "running", "dispatching"}:
            return False
        return True

    def _stage_item_counts_as_stale_sync(
        self,
        item: BinarySecurityStageItem,
        *,
        now_value: datetime,
        last_synced_at: datetime | None,
    ) -> bool:
        if last_synced_at is None:
            return False
        if not self._stage_item_has_child_binding(item):
            return False
        if not self._item_needs_downstream_sync(item, for_task_status="running", now_value=now_value):
            return False
        threshold_seconds = max(60, int(self.cfg.scheduler.downstream_reconcile_interval_seconds or 30) * 3)
        return (now_value - last_synced_at).total_seconds() >= threshold_seconds


    def _retry_plan(self, task: BinarySecurityTask) -> dict[str, Any]:
        summary = dict(task.summary or {})
        plan = summary.get("retry_plan") or {}
        return dict(plan) if isinstance(plan, dict) else {}

    def _retry_cleanup_mode(self, task: BinarySecurityTask) -> str | None:
        plan = self._retry_plan(task)
        mode = str(plan.get("cleanup_mode") or "").strip()
        return mode or None

    def _retry_cleanup_is_hard_reset_verified(self, task: BinarySecurityTask) -> bool:
        plan = self._retry_plan(task)
        verification = plan.get("cleanup_verification") or {}
        if not isinstance(verification, dict):
            return False
        return (
            str(plan.get("cleanup_mode") or "").strip() == "hard_reset"
            and bool(verification.get("validated"))
        )

    def _set_retry_plan(self, task: BinarySecurityTask, plan: dict[str, Any] | None) -> None:
        summary = dict(task.summary or {})
        if plan:
            summary["retry_plan"] = dict(plan)
        else:
            summary.pop("retry_plan", None)
        task.summary = summary

    def _clear_retry_execution_context(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str | None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        had_context = bool(task.execution_mode or task.target_stage_name or self._retry_plan(task))
        task.execution_mode = None
        task.target_stage_name = None
        task_summary = dict(task.summary or {})
        task_summary.pop("stage_retry_context", None)
        task_summary.pop("task_retry_context", None)
        task_summary.pop("retry_plan", None)
        task.summary = task_summary
        if had_context:
            self._record_event(
                db,
                task,
                "stage_retry_context_cleared",
                f"阶段重试上下文已清理: {stage_name or task.current_stage or '-'}",
                stage_name=stage_name,
                payload=dict(payload or {}),
            )

    def _normalize_item_status(self, status: str | None) -> str:
        return (self._normalize_downstream_status(status) or str(status or "").strip().lower() or "unknown")

    def _is_failed_retry_candidate_status(self, status: str | None) -> bool:
        return self._normalize_item_status(status) in FAILED_ITEM_RETRYABLE_STATUSES

    def _stage_retry_candidate_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> list[BinarySecurityStageItem]:
        return [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if self._is_failed_retry_candidate_status(item.status)
            and not self._stage_item_failure_requires_archive_retry_only(db, task, item)
            and (
                str(item.downstream_task_id or "").strip()
                or self._latest_observed_downstream_status(item) in RETRY_CHILD_ABNORMAL_STATUSES
            )
        ]

    def _stage_item_failure_requires_archive_retry_only(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> bool:
        result = self._load_stage_item_result_payload(item)
        sync_observation = dict(result.get("sync_observation") or {})
        last_result = str(
            sync_observation.get("last_result")
            or result.get("last_sync_result")
            or ""
        ).strip()
        if last_result == "downstream_archive_failed_manual_intervention":
            return True
        jobs = self._archive_jobs_for_stage_items(
            db,
            task.id,
            str(item.stage_name or "").strip(),
            [str(item.id or "").strip()],
        )
        for job in jobs:
            if str(getattr(job, "archive_status", "") or "").strip() != "failed":
                continue
            supported, _reason = self._archive_job_retry_support(
                db,
                task,
                job,
                ignore_operation_lock=True,
            )
            if supported:
                return True
        return False

    def _has_retryable_failed_stage_items(self, db: Session, task: BinarySecurityTask) -> bool:
        for stage_name in self._stage_sequence_for_task(task):
            if self._stage_retry_candidate_items(db, task, stage_name):
                return True
        return False

    @staticmethod
    def _comparable_datetime(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is not None:
            return value.astimezone().replace(tzinfo=None)
        return value

    @classmethod
    def _parse_comparable_datetime(cls, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return cls._comparable_datetime(value)
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        normalized = text.replace("Z", "+00:00")
        try:
            return cls._comparable_datetime(datetime.fromisoformat(normalized))
        except ValueError:
            return None

    def _upstream_stage_retried(self, db: Session, task: BinarySecurityTask, stage_name: str) -> tuple[bool, str | None]:
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            return False, None
        target_index = stage_sequence.index(stage_name)
        upstream_stages = stage_sequence[:target_index]
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        runs_by_stage = {run.stage_name: run for run in stage_runs}
        target_items = [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if item.stage_name == stage_name
        ]
        target_created_at = [
            comparable
            for comparable in (self._comparable_datetime(item.created_at) for item in target_items)
            if comparable is not None
        ]
        earliest_target_created_at = min(target_created_at) if target_created_at else None
        retried_upstream_completed_at = [
            comparable
            for comparable in (
                self._comparable_datetime(getattr(run, "finished_at", None) or getattr(run, "started_at", None))
                for run in runs_by_stage.values()
                if run
                and str(run.stage_name or "").strip() in upstream_stages
                and int(getattr(run, "retry_count", 0) or 0) > 0
            )
            if comparable is not None
        ]
        latest_retried_upstream_completed_at = max(retried_upstream_completed_at) if retried_upstream_completed_at else None
        if (
            earliest_target_created_at is not None
            and latest_retried_upstream_completed_at is not None
            and earliest_target_created_at >= latest_retried_upstream_completed_at
        ):
            return False, None
        summary = dict(task.summary or {})
        stale_stages = set(summary.get("stale_stages") or [])
        stale_from_stage = str(summary.get("stale_from_stage") or "").strip()
        stale_reason = str(summary.get("stale_reason") or "").strip()
        if (
            stale_reason == "upstream_stage_retried"
            and stage_name in stale_stages
            and stale_from_stage in upstream_stages
        ):
            return True, stale_from_stage

        for upstream_stage in upstream_stages:
            run = runs_by_stage.get(upstream_stage)
            if not run or int(getattr(run, "retry_count", 0) or 0) <= 0:
                continue
            try:
                stage_index = stage_sequence.index(stage_name)
                upstream_index = stage_sequence.index(upstream_stage)
            except ValueError:
                continue
            if stage_index <= upstream_index:
                continue
            if stage_index == upstream_index + 1 and earliest_target_created_at is None and stage_name not in runs_by_stage:
                continue
            upstream_completed_at = self._comparable_datetime(
                getattr(run, "finished_at", None) or getattr(run, "started_at", None)
            )
            if earliest_target_created_at and upstream_completed_at and earliest_target_created_at >= upstream_completed_at:
                continue
            if run and int(getattr(run, "retry_count", 0) or 0) > 0:
                return True, upstream_stage
        return False, None

    def _first_failed_retry_stage(self, db: Session, task: BinarySecurityTask) -> tuple[str | None, list[BinarySecurityStageItem]]:
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            items = self._stage_retry_candidate_items(db, task, stage_name)
            if items:
                return stage_name, items
        return None, []

    def _retry_snapshot_for_item(self, task: BinarySecurityTask, stage_name: str, item_key: str) -> dict[str, Any] | None:
        summary = task.summary or {}
        stage_context = (summary.get("stage_retry_context") or {}).get(stage_name) or {}
        snapshot = stage_context.get(item_key)
        return dict(snapshot) if isinstance(snapshot, dict) else None

    def _build_hard_restart_cleanup_verification(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> dict[str, Any]:
        cleanup_snapshot = dict(task.cleanup_snapshot or {})
        remaining_refs = [
            dict(row)
            for row in list(cleanup_snapshot.get("remaining_downstream_refs") or [])
            if isinstance(row, dict)
        ]
        cleanup_counts = dict(cleanup_snapshot.get("cleanup_counts") or {})
        try:
            residue_counts = dict(self._validate_hard_restart_cleanup(db, task) or {})
            validated = True
            residue_error = None
        except ValidationError as exc:
            residue_counts = {}
            validated = False
            residue_error = str(exc)
        issues: list[dict[str, Any]] = []
        if bool(cleanup_snapshot.get("cleanup_partial_failed")):
            issues.append(
                {
                    "issue": "remaining_downstream_refs",
                    "remaining_downstream_count": int(cleanup_snapshot.get("remaining_downstream_count") or 0),
                    "remaining_downstream_refs": remaining_refs,
                }
            )
        if residue_error:
            issues.append({"issue": "runtime_residue_detected", "message": residue_error})
        return {
            "validated": validated and not bool(cleanup_snapshot.get("cleanup_partial_failed")),
            "cleanup_mode": "hard_reset",
            "previous_epoch": cleanup_snapshot.get("previous_epoch"),
            "stage_sequence": list(cleanup_snapshot.get("stage_sequence") or []),
            "cleanup_counts": cleanup_counts,
            "remaining_downstream_count": int(cleanup_snapshot.get("remaining_downstream_count") or 0),
            "remaining_downstream_refs": remaining_refs,
            "residue_counts": residue_counts,
            "issues": issues,
        }

    def _stage_result_keys(self, stage_name: str) -> list[str]:
        stage_name = normalize_stage_name(stage_name)
        return list(STAGE_SUMMARY_RESULT_KEYS.get(stage_name, []))

    def _stage_expected_service(self, stage_name: str) -> str | None:
        stage_name = normalize_stage_name(stage_name)
        mapping = STAGE_RETRY_ENDPOINTS.get(stage_name)
        return mapping[0] if mapping else None

    async def _fetch_downstream_task_payload(self, task: BinarySecurityTask, item: BinarySecurityStageItem, token: str) -> dict[str, Any]:
        return await self._downstream_fetch_item_payload(task, item, token)

    async def _refresh_terminal_item_result_from_downstream(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        payload: dict[str, Any],
        *,
        mapped_status: str,
        archived_dir: Path | None,
    ) -> None:
        if item.stage_name != "system_analysis" or item.downstream_service != "system_analyse":
            return
        if mapped_status != "success":
            return
        result_payload: dict[str, Any] = {}
        try:
            result_payload = await self._downstream_fetch_item_result(item)
        except Exception:
            result_payload = {}
        firmware = self._system_analysis_input_for_item(task, item)
        artifact_root = archived_dir or self._service_output_dir(
            task,
            item.downstream_service or item.stage_name,
            item.item_key,
            item.downstream_task_id,
        )
        modules = self._parse_system_analysis_modules(artifact_root, firmware, result_payload)
        self._persist_stage_item_result(
            task,
            item,
            stage_name=item.stage_name,
            result={
                **self._lightweight_system_analysis_input(firmware),
                "modules": self._lightweight_modules_for_storage(modules),
                "module_count": len(modules),
                "downstream": self._lightweight_downstream_payload(payload),
                "system_analysis_result": self._lightweight_system_analysis_result(result_payload),
                "downstream_status_synced_at": _now().isoformat(),
            },
        )
        item.output_ref = {
            **(item.output_ref or {}),
            "artifact_root": str(artifact_root),
            "archive_root": str(artifact_root),
        }

    def _refresh_firmware_unpack_item_result(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        archived_dir: Path | None,
        bound_downstream_task_id: str | None = None,
        downstream_payload: dict[str, Any] | None = None,
    ) -> None:
        input_ref = dict(item.input_ref or {})
        result = self._load_stage_item_result_payload(item)
        firmware_key = str(item.item_key or input_ref.get("firmware_key") or result.get("firmware_key") or "")
        filename = str(input_ref.get("filename") or item.item_name or result.get("filename") or firmware_key)
        effective_downstream_task_id = str(bound_downstream_task_id or item.downstream_task_id or "").strip()
        metadata_sources = self._resolve_downstream_output_sources(
            downstream_payload or result.get("downstream") or {},
            downstream_task_id=effective_downstream_task_id,
            task=task,
            downstream_service=item.downstream_service,
        )
        runtime_output_path = str(metadata_sources[0]) if metadata_sources else ""
        unpacked_root = str(archived_dir) if archived_dir else (
            self._stage_item_archive_root(item)
            or str(result.get("unpacked_root") or runtime_output_path)
        )
        self._persist_stage_item_result(
            task,
            item,
            stage_name=item.stage_name,
            result={
                **result,
                "firmware_key": firmware_key,
                "firmware_name": str(result.get("firmware_name") or Path(filename).stem or firmware_key),
                "filename": filename,
                "input_path": str(input_ref.get("path") or result.get("input_path") or ""),
                "unpacked_root": unpacked_root,
                "source_root": str(result.get("source_root") or unpacked_root),
                "task_type": result.get("task_type", TASK_TYPE_BINARY),
                "downstream": self._lightweight_downstream_payload(downstream_payload or result.get("downstream") or {}),
                "downstream_status_synced_at": _now().isoformat(),
                "bound_downstream_task_id": effective_downstream_task_id or None,
            },
        )
        item.output_ref = {
            **(item.output_ref or {}),
            "runtime_output_path": runtime_output_path,
            "unpacked_root": unpacked_root,
            **({"archive_root": str(archived_dir)} if archived_dir else {}),
        }

    def _system_analysis_input_for_item(self, task: BinarySecurityTask, item: BinarySecurityStageItem) -> dict[str, Any]:
        for candidate in self._system_analysis_inputs(task):
            if str(candidate.get("firmware_key") or "") == str(item.item_key or ""):
                return dict(candidate)
        input_ref = dict(item.input_ref or {})
        return {
            "firmware_key": str(item.item_key or input_ref.get("firmware_key") or SOURCE_TASK_INPUT_KEY),
            "firmware_name": str(item.item_name or task.name),
            "filename": str(item.item_name or input_ref.get("filename") or item.item_key or "source-project"),
            "unpacked_root": str(input_ref.get("input_path") or input_ref.get("unpacked_root") or Path(task.workspace_root) / "input"),
            "source_root": str(input_ref.get("source_root") or input_ref.get("input_path") or Path(task.workspace_root) / "input"),
            "task_type": self._task_type(task),
        }

    def _map_downstream_status(self, status: str) -> str | None:
        normalized = (status or "").lower()
        if normalized in {"downstream_missing", "not_found", "missing", "task_not_found"}:
            return "downstream_missing"
        if normalized in {"pending", "queued", "created", "ready", "awaiting_takeover", "retry_preparing"}:
            return "pending"
        if normalized == "dispatching":
            return "dispatching"
        if normalized in {"running", "processing", "in_progress", "cancelling", "started"}:
            return "running"
        if normalized in {"success", "succeeded", "passed", "completed", "complete", "done", "completed_limited"}:
            return "success"
        if normalized == "partial_success":
            return "partial_success"
        if normalized == "skipped":
            return "failed"
        if normalized == "invalid_input":
            return "failed"
        if normalized in {"failed", "error", "failure"}:
            return "failed"
        if normalized in {"cancelled", "canceled"}:
            return "cancelled"
        return None

    @staticmethod
    def _is_owner_lost_recoverable_message(message: str | None) -> bool:
        normalized = str(message or "").strip().lower()
        if not normalized:
            return False
        if "owner_lost_retry_exhausted" in normalized:
            return False
        tokens = (
            "task owner pod lost",
            "owner pod lost",
            "owner lost",
            "staletaskexecution",
            "当前执行 token 已失效",
            "runtime lease owner 已变更",
            "lease owner 已变更",
            "token 已失效",
            "awaiting_takeover",
            "retry_preparing",
        )
        return any(token.lower() in normalized for token in tokens)

    def _is_owner_lost_recoverable_failure(
        self,
        *,
        failure_message: str | None,
        failure_category: str | None = None,
        error_type: str | None = None,
        item: BinarySecurityStageItem | None = None,
    ) -> bool:
        if str(failure_category or "").strip().lower() == "business":
            return False
        if self._is_owner_lost_recoverable_message(failure_message):
            return True
        if self._is_owner_lost_recoverable_message(error_type):
            return True
        if item is not None:
            if self._is_owner_lost_recoverable_message(item.error_message):
                return True
            observed_error_type = self._stage_item_sync_error_type_value(item)
            if self._is_owner_lost_recoverable_message(observed_error_type):
                return True
            observed_error_message = self._stage_item_sync_error_message_value(item)
            if self._is_owner_lost_recoverable_message(observed_error_message):
                return True
        return False

    def _owner_lost_retry_exhausted(self, task: BinarySecurityTask, item: BinarySecurityStageItem) -> bool:
        error_message = str(item.error_message or "").strip()
        if "owner_lost_retry_exhausted" in error_message.lower():
            return int(item.retry_count or 0) > self._max_retries_per_item(task)
        return self._is_owner_lost_recoverable_failure(
            failure_message=error_message or None,
            error_type=self._stage_item_sync_error_type_value(item),
            item=item,
        ) and int(item.retry_count or 0) > self._max_retries_per_item(task)

    def _aggregate_item_statuses(self, statuses: list[str]) -> str:
        if not statuses:
            return "pending"
        if any(status == "running" for status in statuses):
            return "running"
        if any(status == "dispatching" for status in statuses):
            return "dispatching"
        if any(status in {"pending", "queued"} for status in statuses):
            return "pending"
        if all(status == "success" for status in statuses):
            return "success"
        if any(status == "success" for status in statuses) and any(status in {"failed", "cancelled", "partial_success", "downstream_missing"} for status in statuses):
            return "partial_success"
        if all(status == "cancelled" for status in statuses):
            return "cancelled"
        if all(status == "downstream_missing" for status in statuses):
            return "downstream_missing"
        if any(status == "partial_success" for status in statuses):
            return "partial_success"
        if any(status in {"failed", "partial_success"} for status in statuses):
            return "failed"
        if any(status == "downstream_missing" for status in statuses):
            return "downstream_missing"
        return statuses[0]

    def _is_active_item_status(self, status: str | None) -> bool:
        normalized = self._normalize_downstream_status(status) or str(status or "").strip().lower()
        return normalized in {"pending", "queued", "running", "dispatching"}

    def _is_terminal_item_status(self, status: str | None) -> bool:
        normalized = self._normalize_downstream_status(status) or str(status or "").strip().lower()
        return normalized in {"success", "failed", "cancelled", "downstream_missing", "skipped", "partial_success"}

    def _stage_has_active_items(self, items: list[BinarySecurityStageItem]) -> bool:
        return any(self._is_active_item_status(item.status) for item in items)

    def _stage_has_nonterminal_items(self, items: list[BinarySecurityStageItem]) -> bool:
        return any(not self._is_terminal_item_status(item.status) for item in items)

    def _stage_has_live_downstream_children(
        self,
        items: list[BinarySecurityStageItem],
    ) -> bool:
        return self._stage_has_active_items(items)

    def _stage_has_sync_degraded_items(self, items: list[BinarySecurityStageItem]) -> bool:
        for item in items:
            if not str(item.downstream_task_id or "").strip():
                continue
            if self._stage_item_sync_error_budget_exhausted(item):
                return True
            if self._stage_item_sync_in_retry_backoff(item):
                return True
            if self._item_downstream_sync_stale(item):
                return True
            if self._stage_item_sync_consecutive_error_count(item) > 0:
                return True
        return False

    def _stage_has_orchestration_degraded_items(self, items: list[BinarySecurityStageItem]) -> bool:
        for item in items:
            if self._stage_item_orchestration_error_budget_exhausted(item):
                return True
            if self._stage_item_orchestration_in_retry_backoff(item):
                return True
        return False

    def _stage_has_real_runnable_work(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
        upstream_retried, _ = self._upstream_stage_retried(db, task, stage_name)
        if upstream_retried:
            return False
        stage_run = (
            db.query(BinarySecurityStageRun)
            .filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            )
            .order_by(
                BinarySecurityStageRun.sequence_no.desc(),
                BinarySecurityStageRun.created_at.desc(),
                BinarySecurityStageRun.id.desc(),
            )
            .first()
        )
        normalized_stage_status = self._normalize_downstream_status(getattr(stage_run, "status", None)) or str(getattr(stage_run, "status", "") or "").strip()
        items = self._stage_items(db, task.id, stage_name)
        if items:
            if self._is_streaming_tail_stage(task, stage_name):
                return any(
                    (self._normalize_downstream_status(item.status) or str(item.status or "").strip()) in {"pending", "queued"}
                    and not str(item.downstream_task_id or "").strip()
                    for item in items
                ) or any(self._is_streaming_active_item_status(item.status) for item in items)
            return True
        if self._is_streaming_tail_stage(task, stage_name):
            return False
        if normalized_stage_status in {"success", "partial_success"}:
            return False
        return self._stage_has_materialized_inputs(db, task, stage_name)

    def _stage_start_ready(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        allow_rebuild: bool = False,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        if not normalized_stage:
            return False
        if self._stage_has_real_runnable_work(db, task, normalized_stage):
            return True
        return self._stage_has_materialized_inputs(
            db,
            task,
            normalized_stage,
            allow_rebuild=allow_rebuild,
        )

    def _stage_requires_materialized_inputs(self, task: BinarySecurityTask, stage_name: str) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        return normalized_stage in {"binary_to_source", "entry_analysis", "dataflow_vuln_scan"}

    def _stage_has_materialized_inputs(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        allow_rebuild: bool = True,
    ) -> bool:
        if allow_rebuild:
            self._ensure_stage_inputs_available(db, task, stage_name)
        normalized_stage = normalize_stage_name(stage_name)
        handler = self._stage_handler(normalized_stage)
        if handler is not None and normalized_stage in {"firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "knowledge_graph_entry_fetch", "dataflow_vuln_scan"}:
            return handler.has_runnable_inputs(self, db, task)
        summary = dict(task.summary or {})
        if normalized_stage == "binary_to_source":
            return bool(list(summary.get("selected_modules") or []))
        if normalized_stage == "entry_analysis":
            return bool(self._entry_analysis_inputs(db, task))
        if normalized_stage == "knowledge_graph_entry_fetch":
            return bool(str(summary.get("input_dir") or "").strip())
        if normalized_stage == "dataflow_vuln_scan":
            if not self._entry_analysis_authoritative_items_ready(db, task):
                return False
            return bool(self._effective_entry_inputs(task, db))
        return True

    def _should_hold_task_on_stage_after_requeue(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
        if not stage_name:
            return False
        items = self._stage_items(db, task.id, stage_name)
        if any(self._is_active_item_status(item.status) for item in items):
            return True
        target_stage = str(task.target_stage_name or "").strip()
        return (
            task.execution_mode == TASK_ACTION_RETRY_STAGE_FULL
            and bool(target_stage)
            and target_stage == stage_name
            and self._stage_has_real_runnable_work(db, task, stage_name)
        )

    def _rebuild_entry_results_from_stage_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> list[dict[str, Any]]:
        return self._rebuild_entry_result_modules_from_stage_items(db, task, stage_run)

    def _refresh_system_analysis_stage_from_synced_items(self, db: Session, task: BinarySecurityTask) -> None:
        handler = self._stage_handler("system_analysis")
        if handler is None:
            return
        handler.refresh_summary_from_items(self, db, task)
        self._rebuild_system_analysis_module_selection_from_summary(task)

    def _rebuild_system_analysis_module_selection_from_summary(self, task: BinarySecurityTask) -> None:
        summary = dict(task.summary or {})
        if "system_analysis_modules" not in summary:
            return
        modules = [dict(module) for module in list(summary.get("system_analysis_modules") or []) if isinstance(module, dict)]
        risk_levels = list(self._module_selection_candidate_levels(task) or [])
        candidate_modules = self._filter_candidate_modules(modules, risk_levels)
        high_risk_modules = [
            dict(module)
            for module in modules
            if self._normalize_module_risk_level(module.get("risk_level"), module.get("risk_score")) == "高"
        ]

        if self._module_selection_mode(task) == MODULE_SELECTION_MODE_MANUAL_CONFIRM:
            existing_selected = [
                dict(module)
                for module in list(summary.get("selected_modules") or [])
                if isinstance(module, dict)
            ]
            candidate_by_key = {
                str(module.get("module_key") or "").strip(): dict(module)
                for module in candidate_modules
                if str(module.get("module_key") or "").strip()
            }
            selected_modules: list[dict[str, Any]] = []
            for module in existing_selected:
                module_key = str(module.get("module_key") or "").strip()
                if not module_key:
                    continue
                authoritative = candidate_by_key.get(module_key)
                if authoritative is None:
                    continue
                selected_modules.append(
                    {
                        **authoritative,
                        "selected_by": module.get("selected_by") or MODULE_SELECTION_MODE_MANUAL_CONFIRM,
                        "selected_at": module.get("selected_at"),
                    }
                )
        else:
            selected_modules = self._mark_selected_modules(candidate_modules, selected_by=MODULE_SELECTION_MODE_AUTO) if candidate_modules else []

        task.summary = {
            **summary,
            "candidate_modules": self._lightweight_modules_for_storage(candidate_modules),
            "selected_modules": self._lightweight_modules_for_storage(selected_modules),
            "high_risk_modules": self._lightweight_modules_for_storage(high_risk_modules),
        }
        task.metrics = {
            **dict(task.metrics or {}),
            **self._module_metrics(modules, candidate_modules, selected_modules),
        }

    def _refresh_firmware_unpack_stage_from_synced_items(self, db: Session, task: BinarySecurityTask) -> None:
        handler = self._stage_handler("firmware_unpack")
        if handler is None:
            return
        handler.refresh_summary_from_items(self, db, task)

    def _refresh_knowledge_graph_entry_fetch_summary(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> dict[str, Any]:
        knowledge_graph_entries = self._knowledge_graph_entry_results(task)
        entry_results = self._entry_results(task)
        metrics = dict(task.metrics or {})
        summary = {
            "items": self._compact_stage_success_items_for_db("entry_results", entry_results),
            "failed_items": [],
            "cancelled_items": [],
            "success_count": len(knowledge_graph_entries),
            "failed_count": 0,
            "cancelled_count": 0,
            "running_count": 0,
            "candidate_entry_count": int(metrics.get("candidate_entry_count") or len(knowledge_graph_entries)),
            "selected_entry_count": int(metrics.get("selected_entry_count") or len(knowledge_graph_entries)),
            "entry_count": int(metrics.get("entry_count") or len(knowledge_graph_entries)),
            "knowledge_graph_raw_entry_count": int(metrics.get("knowledge_graph_raw_entry_count") or 0),
            "knowledge_graph_selected_entry_count": int(metrics.get("knowledge_graph_selected_entry_count") or len(knowledge_graph_entries)),
            "knowledge_graph_filtered_out_count": int(metrics.get("knowledge_graph_filtered_out_count") or 0),
            "entries_url": (
                dict(stage_run.output_summary or {}).get("entries_url")
                if stage_run is not None and isinstance(stage_run.output_summary, dict)
                else None
            ),
            "duration_ms": (
                dict(stage_run.output_summary or {}).get("duration_ms")
                if stage_run is not None and isinstance(stage_run.output_summary, dict)
                else None
            ),
        }
        if stage_run is not None:
            self._persist_stage_run_output_summary(
                task,
                stage_run,
                {
                    **summary,
                    "status_synced": True,
                    "sync_status": stage_run.status,
                    **(stage_run.counts or {}),
                },
            )
        return summary

    def _should_skip_readless_reconcile_for_active_task(self, task: BinarySecurityTask) -> bool:
        return self._lease_is_active(task)

    def _should_preserve_task_dispatch_ownership(
        self,
        task: BinarySecurityTask,
        *,
        previous_status: str | None = None,
        db: Session | None = None,
    ) -> bool:
        del previous_status
        return self._lease_is_active(task, db=db)

    def _stage_items(self, db: Session, task_id: str, stage_name: str) -> list[BinarySecurityStageItem]:
        stage_name = normalize_stage_name(stage_name)
        return db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task_id,
            BinarySecurityStageItem.stage_name == stage_name,
        ).order_by(BinarySecurityStageItem.created_at.asc()).all()

    def _stage_item_identity(self, item_key: str, parent_key: str | None) -> str:
        return build_stage_item_identity_key(item_key, parent_key)

    def _stage_item_started_at(self, status: str) -> datetime | None:
        return _now() if status in {"running", "success", "failed", "cancelled", "downstream_missing", "partial_success"} else None

    def _find_stage_item(
        self,
        db: Session,
        *,
        task_id: str,
        stage_name: str,
        item_key: str,
        parent_key: str | None,
    ) -> BinarySecurityStageItem | None:
        stage_name = normalize_stage_name(stage_name)
        identity_key = build_stage_item_identity_key(item_key, parent_key)
        items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task_id,
            BinarySecurityStageItem.stage_name == stage_name,
            BinarySecurityStageItem.item_identity_key == identity_key,
        ).order_by(BinarySecurityStageItem.created_at.asc()).all()
        if not items:
            items = db.query(BinarySecurityStageItem).filter(
                BinarySecurityStageItem.task_id == task_id,
                BinarySecurityStageItem.stage_name == stage_name,
                BinarySecurityStageItem.item_key == item_key,
            ).order_by(BinarySecurityStageItem.created_at.asc()).all()
        matches = [item for item in items if (item.parent_key or None) == (parent_key or None)]
        if len(matches) > 1:
            raise ValidationError(f"阶段 {stage_name} 存在重复历史 item，无法安全重试: {item_key}")
        return matches[0] if matches else None

    def _upsert_stage_item(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        stage_name: str,
        item_key: str,
        item_name: str | None,
        parent_key: str | None,
        downstream_service: str,
        input_ref: dict[str, Any],
        output_ref: dict[str, Any] | None = None,
        retrying: bool,
        auto_retrying: bool = False,
        running_status: str = "running",
        preserve_active_status: bool = False,
    ) -> BinarySecurityStageItem:
        identity_key = build_stage_item_identity_key(item_key, parent_key)
        item = self._find_stage_item(
            db,
            task_id=task.id,
            stage_name=stage_name,
            item_key=item_key,
            parent_key=parent_key,
        )
        if item is None:
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_name,
                item_key=item_key,
                item_name=item_name,
                parent_key=parent_key,
                item_identity_key=identity_key,
                status=running_status,
                downstream_service=downstream_service,
                started_at=self._stage_item_started_at(running_status),
            )
            self._ensure_stage_item_first_started_at(item)
            item.retry_count = int(item.retry_count or 0)
            item.rerun_count = int(item.rerun_count or 0)
            if retrying:
                item.rerun_count = 1
            if auto_retrying:
                item.retry_count = 1
        else:
            item.stage_run_id = stage_run.id
            item.item_name = item_name
            item.parent_key = parent_key
            item.item_identity_key = identity_key
            keep_existing_active = preserve_active_status and self._should_preserve_streaming_item_status(item)
            item.status = item.status if keep_existing_active else running_status
            item.downstream_service = downstream_service
            self._reset_child_runtime_payload(
                item,
                payload={},
                keep_error=False,
                reset_started_at=False,
                reset_finished_at=True,
            )
            if not keep_existing_active:
                item.started_at = self._stage_item_started_at(running_status)
                self._ensure_stage_item_first_started_at(item)
            if retrying:
                item.rerun_count = int(item.rerun_count or 0) + 1
            if auto_retrying:
                item.retry_count = int(item.retry_count or 0) + 1
        item.input_ref = self._sanitize_stage_item_input(stage_name, input_ref)
        if output_ref is not None:
            item.output_ref = output_ref
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            try:
                with self._savepoint(db):
                    db.add(item)
                    db.flush()
                break
            except IntegrityError:
                existing = self._find_stage_item(
                    db,
                    task_id=task.id,
                    stage_name=stage_name,
                    item_key=item_key,
                    parent_key=parent_key,
                )
                if existing is None:
                    raise
                existing.stage_run_id = stage_run.id
                existing.item_name = item_name
                existing.parent_key = parent_key
                existing.item_identity_key = identity_key
                keep_existing_active = preserve_active_status and self._should_preserve_streaming_item_status(existing)
                existing.status = existing.status if keep_existing_active else running_status
                existing.downstream_service = downstream_service
                self._reset_child_runtime_payload(
                    existing,
                    payload={},
                    keep_error=False,
                    reset_started_at=False,
                    reset_finished_at=True,
                )
                if not keep_existing_active:
                    existing.started_at = self._stage_item_started_at(running_status)
                    self._ensure_stage_item_first_started_at(existing)
                existing.input_ref = self._sanitize_stage_item_input(stage_name, input_ref)
                if output_ref is not None:
                    existing.output_ref = output_ref
                if retrying:
                    existing.rerun_count = int(existing.rerun_count or 0) + 1
                if auto_retrying:
                    existing.retry_count = int(existing.retry_count or 0) + 1
                item = existing
                break
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                    raise
                db.rollback()
                self._sleep_after_retryable_lock_error(attempt + 1)
        return item

    def _should_preserve_streaming_item_status(self, item: BinarySecurityStageItem) -> bool:
        status = str(item.status or "").strip().lower()
        if status == "running":
            return True
        if status != "dispatching":
            return False
        worker = self._stage_item_workers.get(str(item.id or ""))
        if worker is not None and not worker.done():
            return True
        reference_time = item.updated_at or item.started_at or item.created_at
        elapsed_seconds = _elapsed_seconds_since(reference_time)
        if elapsed_seconds is None:
            return False
        owns_session = False
        db = Session.object_session(item)
        if db is None:
            db = get_session_factory()()
            owns_session = True
        try:
            service_config = self._load_service_config(db)
        finally:
            if owns_session:
                db.close()
        timeout_seconds = max(int(getattr(service_config, "dispatch_timeout_seconds", 0) or 0), 60)
        return elapsed_seconds < timeout_seconds

    def _retry_item_action_snapshot(
        self,
        item: BinarySecurityStageItem,
        *,
        strategy: str,
        observed_status: str | None,
        old_downstream_task_id: str | None,
        cleanup_performed: bool,
        binding_cleared: bool,
        cleanup_status: str | None = None,
        create_required: bool | None = None,
        create_status: str | None = None,
        verification_status: str | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        return {
            "stage_name": item.stage_name,
            "item_id": item.id,
            "item_key": item.item_key,
            "parent_key": item.parent_key,
            "downstream_service": item.downstream_service,
            "old_downstream_task_id": old_downstream_task_id,
            "current_downstream_task_id": str(item.downstream_task_id or "").strip() or None,
            "new_downstream_task_id": str(item.downstream_task_id or "").strip() or None,
            "strategy": strategy,
            "observed_status": observed_status,
            "cleanup_performed": bool(cleanup_performed),
            "binding_cleared": bool(binding_cleared),
            "cleanup_required": bool(strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL),
            "cleanup_status": cleanup_status or ("pending" if strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL else "not_required"),
            "create_required": bool(create_required if create_required is not None else strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL),
            "create_status": create_status or ("pending" if strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL else "not_required"),
            "verification_status": verification_status or "pending",
            "error": error,
        }

    def _store_retry_item_action(self, task: BinarySecurityTask, action: dict[str, Any] | None) -> None:
        if not isinstance(action, dict):
            return
        plan = self._retry_plan(task)
        actions = [dict(row) for row in list(plan.get("item_actions") or []) if isinstance(row, dict)]
        item_key = str(action.get("item_key") or "").strip()
        parent_key = str(action.get("parent_key") or "").strip()
        normalized: list[dict[str, Any]] = []
        replaced = False
        for row in actions:
            if (
                str(row.get("item_key") or "").strip() == item_key
                and str(row.get("parent_key") or "").strip() == parent_key
            ):
                normalized.append(dict(action))
                replaced = True
            else:
                normalized.append(row)
        if not replaced:
            normalized.append(dict(action))
        plan["item_actions"] = normalized
        self._set_retry_plan(task, plan)

    def _retry_item_actions(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        plan = self._retry_plan(task)
        return [dict(row) for row in list(plan.get("item_actions") or []) if isinstance(row, dict)]

    def _set_retry_item_actions(self, task: BinarySecurityTask, actions: list[dict[str, Any]]) -> None:
        plan = self._retry_plan(task)
        plan["item_actions"] = [dict(row) for row in actions if isinstance(row, dict)]
        self._set_retry_plan(task, plan)

    def _update_retry_item_action(
        self,
        task: BinarySecurityTask,
        *,
        item_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any] | None:
        actions = self._retry_item_actions(task)
        updated: dict[str, Any] | None = None
        normalized: list[dict[str, Any]] = []
        for row in actions:
            if str(row.get("item_id") or "").strip() == str(item_id or "").strip():
                updated = {**row, **dict(updates or {})}
                normalized.append(updated)
            else:
                normalized.append(row)
        self._set_retry_item_actions(task, normalized)
        return updated

    def _validate_retry_prepare_state(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        target_stage: str,
        retry_item_keys: list[str],
        item_actions: list[dict[str, Any]],
        affected_stages: list[str],
        phase: str = "prepare",
    ) -> dict[str, Any]:
        stage_items = self._stage_items(db, task.id, target_stage)
        keyed_items = {
            self._stage_item_identity(item.item_key, item.parent_key): item
            for item in stage_items
        }
        issues: list[dict[str, Any]] = []
        validated_item_count = 0
        failed_item_count = 0
        for item_key in retry_item_keys:
            item = keyed_items.get(item_key)
            if item is None:
                issues.append({"item_key": item_key, "issue": "missing_retry_item"})
                failed_item_count += 1
                continue
            validated_item_count += 1
            action = next((row for row in item_actions if str(row.get("item_key") or "") == item_key), None)
            if action is None:
                action = next(
                    (
                        row
                        for row in item_actions
                        if self._stage_item_identity(str(row.get("item_key") or ""), row.get("parent_key")) == item_key
                    ),
                    None,
                )
            strategy = str((action or {}).get("strategy") or "").strip()
            if strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL:
                old_task_id = str((action or {}).get("old_downstream_task_id") or "").strip()
                current_task_id = str(item.downstream_task_id or "").strip()
                if phase == "prepare":
                    if str(item.status or "").strip() not in {"pending", "queued", "dispatching", "running", "failed", "cancelled", "downstream_missing"}:
                        issues.append({"item_key": item_key, "issue": "status_not_retryable", "status": item.status})
                    continue
                if phase == "verify":
                    if not current_task_id:
                        issues.append({"item_key": item_key, "issue": "replacement_binding_missing"})
                    elif old_task_id and old_task_id == current_task_id:
                        issues.append({"item_key": item_key, "issue": "replacement_reused_old_child", "downstream_task_id": current_task_id})
                    replacement_state = self._replacement_in_progress_state(item)
                    if (
                        replacement_state["replacement_in_progress"]
                        and replacement_state["binding_cleared"]
                        and str(item.status or "").strip() in {"failed", "cancelled", "downstream_missing"}
                    ):
                        issues.append(
                            {
                                "item_key": item_key,
                                "issue": "replacement_terminal_reapplied_from_old_child",
                                "status": item.status,
                                "old_downstream_task_id": replacement_state["old_downstream_task_id"],
                            }
                        )
                elif current_task_id:
                    issues.append({"item_key": item_key, "issue": "binding_not_cleared", "downstream_task_id": item.downstream_task_id})
                if any(
                    [
                        getattr(item, "downstream_status", None),
                        getattr(item, "sync_status", None),
                        getattr(item, "last_synced_at", None),
                        getattr(item, "downstream_raw_status", None),
                        getattr(item, "downstream_mapped_status", None),
                        getattr(item, "sync_observation_error_message", None),
                        getattr(item, "sync_observation_error_type", None),
                        getattr(item, "sync_observation_http_status", None),
                    ]
                ):
                    issues.append({"item_key": item_key, "issue": "stale_sync_snapshot_present"})
                normalized_status = str(item.status or "").strip()
                allowed_statuses = {"pending", "queued", "dispatching", "running"} if phase == "verify" else {"pending"}
                if phase == "verify" and current_task_id and normalized_status == "success":
                    allowed_statuses = allowed_statuses | {"success"}
                if normalized_status not in allowed_statuses:
                    issues.append({"item_key": item_key, "issue": "status_not_reset", "status": item.status})
                if normalized_status != "success" and item.finished_at is not None:
                    issues.append({"item_key": item_key, "issue": "finished_at_not_cleared"})
            elif strategy == RETRY_CHILD_STRATEGY_REUSE_SUCCESS:
                if str(item.status or "").strip() != "success":
                    issues.append({"item_key": item_key, "issue": "success_child_not_preserved", "status": item.status})
            elif strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE:
                if not str(item.downstream_task_id or "").strip():
                    issues.append({"item_key": item_key, "issue": "active_binding_missing"})
                observed_active_status = self._map_downstream_status(str(self._latest_observed_downstream_status(item) or ""))
                if (
                    self._normalize_item_status(item.status) not in {"pending", "queued", "dispatching", "running"}
                    and observed_active_status not in {"pending", "queued", "dispatching", "running"}
                ):
                    issues.append({"item_key": item_key, "issue": "active_status_not_preserved", "status": item.status})
        for stage_name in affected_stages:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            if stage_run is None:
                continue
            if stage_name == target_stage:
                allowed_target_statuses = {"pending", "queued", "running", "dispatching"} if phase == "verify" else {"pending", "queued", "running"}
                if str(stage_run.status or "").strip() not in allowed_target_statuses:
                    issues.append({"stage_name": stage_name, "issue": "target_stage_not_reset", "status": stage_run.status})
            elif str(stage_run.status or "").strip() not in {"pending", "queued"}:
                issues.append({"stage_name": stage_name, "issue": "downstream_stage_not_reset", "status": stage_run.status})
        return {
            "validated": not issues,
            "validated_item_count": validated_item_count,
            "failed_item_count": failed_item_count + len(issues),
            "issues": issues,
        }

    def _classify_retry_downstream_strategy(
        self,
        item: BinarySecurityStageItem,
        *,
        task: BinarySecurityTask | None = None,
        active_payload: dict[str, Any] | None = None,
        observed_payload: dict[str, Any] | None = None,
    ) -> tuple[str, str | None]:
        hard_reset_verified = bool(task is not None and self._retry_cleanup_is_hard_reset_verified(task))
        bound_downstream_task_id = str(item.downstream_task_id or "").strip() or None
        if active_payload is not None:
            status = self._map_downstream_status(str(active_payload.get("status") or ""))
            if status in {"pending", "queued", "dispatching", "running"}:
                if hard_reset_verified or not bound_downstream_task_id:
                    return RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL, status
                return RETRY_CHILD_STRATEGY_ADOPT_ACTIVE, status
        payload = observed_payload if isinstance(observed_payload, dict) else None
        raw_status = None
        if payload is not None:
            raw_status = self._status_from_downstream_payload(payload, success_statuses={"success", "partial_success", "completed", "passed", "succeeded"})
        mapped_status = raw_status or self._latest_observed_downstream_status(item) or str(item.status or "").strip().lower() or None
        mapped_status = self._map_downstream_status(str(mapped_status or "")) or (str(mapped_status or "").strip().lower() or None)
        if not bound_downstream_task_id and mapped_status in {"success", "pending", "queued", "dispatching", "running"}:
            return RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL, mapped_status
        if mapped_status == "success":
            return RETRY_CHILD_STRATEGY_REUSE_SUCCESS, mapped_status
        if mapped_status in {"pending", "queued", "dispatching", "running"}:
            if hard_reset_verified:
                return RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL, mapped_status
            return RETRY_CHILD_STRATEGY_ADOPT_ACTIVE, mapped_status
        if mapped_status in RETRY_CHILD_ABNORMAL_STATUSES:
            return RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL, mapped_status
        return RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL, mapped_status

    async def _prepare_retry_child_for_reuse_or_recreate(
        self,
        session: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        strategy: str,
        observed_status: str | None,
        token: str | None,
    ) -> dict[str, Any]:
        old_task_id = str(item.downstream_task_id or "").strip() or None
        self._record_downstream_item_disposition(
            session,
            task,
            item,
            event_type="retry_item_strategy_selected",
            message=f"重试子任务策略已确定: {strategy}",
            payload={
                "stage_name": item.stage_name,
                "item_id": item.id,
                "item_key": item.item_key,
                "old_downstream_task_id": old_task_id,
                "new_downstream_task_id": None,
                "strategy": strategy,
                "old_downstream_status": observed_status,
            },
        )
        if strategy == RETRY_CHILD_STRATEGY_REUSE_SUCCESS:
            self._record_downstream_item_disposition(
                session,
                task,
                item,
                event_type="retry_item_reuse_success_child",
                message="重试复用已成功的下游子任务",
                payload={
                    "stage_name": item.stage_name,
                    "item_id": item.id,
                    "item_key": item.item_key,
                    "old_downstream_task_id": old_task_id,
                    "new_downstream_task_id": old_task_id,
                    "strategy": strategy,
                    "old_downstream_status": observed_status,
                },
            )
            return self._retry_item_action_snapshot(
                item,
                strategy=strategy,
                observed_status=observed_status,
                old_downstream_task_id=old_task_id,
                cleanup_performed=False,
                binding_cleared=False,
            )
        if strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE:
            self._mark_replacement_in_progress(
                item,
                old_downstream_task_id=old_task_id,
                binding_cleared=False,
                verification_status="pending",
            )
            self._record_downstream_item_disposition(
                session,
                task,
                item,
                event_type="retry_item_observe_existing_child",
                message="重试阶段继续观察已存在的下游子任务",
                payload={
                    "stage_name": item.stage_name,
                    "item_id": item.id,
                    "item_key": item.item_key,
                    "old_downstream_task_id": old_task_id,
                    "new_downstream_task_id": old_task_id,
                    "strategy": strategy,
                    "old_downstream_status": observed_status,
                },
            )
            return self._retry_item_action_snapshot(
                item,
                strategy=strategy,
                observed_status=observed_status,
                old_downstream_task_id=old_task_id,
                cleanup_performed=False,
                binding_cleared=False,
            )
        self._record_downstream_item_disposition(
            session,
            task,
            item,
            event_type="retry_item_recreate_from_abnormal_child",
            message="重试检测到异常下游子任务，准备删旧重建",
            level="warning",
            payload={
                "stage_name": item.stage_name,
                "item_id": item.id,
                "item_key": item.item_key,
                "old_downstream_task_id": old_task_id,
                "new_downstream_task_id": None,
                "strategy": strategy,
                "old_downstream_status": observed_status,
            },
        )
        self._mark_replacement_in_progress(
            item,
            old_downstream_task_id=old_task_id,
            binding_cleared=False,
            verification_status="pending",
        )
        if old_task_id:
            self._record_downstream_item_disposition(
                session,
                task,
                item,
                event_type="retry_item_old_child_cancel_requested",
                message=f"重试前请求取消旧下游子任务: {item.downstream_service}:{old_task_id}",
                level="warning",
                payload={
                    "stage_name": item.stage_name,
                    "item_id": item.id,
                    "item_key": item.item_key,
                    "old_downstream_task_id": old_task_id,
                    "new_downstream_task_id": None,
                    "strategy": strategy,
                    "old_downstream_status": observed_status,
                },
            )
            session.commit()
            try:
                await self._downstream_cancel_refs(
                    session,
                    task,
                    [
                        {
                            "service": item.downstream_service,
                            "task_id": old_task_id,
                            "project_id": task.project_id,
                            "stage_name": item.stage_name,
                            "item_id": item.id,
                            "item_key": item.item_key,
                        }
                    ],
                    token,
                )
            except Exception:
                session.rollback()
            self._record_downstream_item_disposition(
                session,
                task,
                item,
                event_type="retry_item_old_child_delete_requested",
                message=f"重试前请求删除旧下游子任务: {item.downstream_service}:{old_task_id}",
                level="warning",
                payload={
                    "stage_name": item.stage_name,
                    "item_id": item.id,
                    "item_key": item.item_key,
                    "old_downstream_task_id": old_task_id,
                    "new_downstream_task_id": None,
                    "strategy": strategy,
                    "old_downstream_status": observed_status,
                },
            )
            session.commit()
            await self._delete_downstream_refs(
                session,
                task,
                [
                    {
                        "service": item.downstream_service,
                        "task_id": old_task_id,
                        "project_id": task.project_id,
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                    }
                ],
                token,
            )
            self._record_downstream_item_disposition(
                session,
                task,
                item,
                event_type="retry_item_old_child_verified_absent",
                message=f"旧下游子任务已确认不可见: {item.downstream_service}:{old_task_id}",
                payload={
                    "stage_name": item.stage_name,
                    "item_id": item.id,
                    "item_key": item.item_key,
                    "old_downstream_task_id": old_task_id,
                    "new_downstream_task_id": None,
                    "strategy": strategy,
                    "old_downstream_status": observed_status,
                },
            )
        self._clear_item_downstream_runtime_state(item)
        item.finished_at = None
        self._mark_replacement_in_progress(
            item,
            old_downstream_task_id=old_task_id,
            binding_cleared=True,
            verification_status="pending",
        )
        self._record_downstream_item_disposition(
            session,
            task,
            item,
            event_type="retry_item_old_child_cleared",
            message="旧下游绑定与同步快照已清空，准备创建新子任务",
            payload={
                "stage_name": item.stage_name,
                "item_id": item.id,
                "item_key": item.item_key,
                "old_downstream_task_id": old_task_id,
                "new_downstream_task_id": None,
                "strategy": strategy,
                "old_downstream_status": observed_status,
            },
        )
        return self._retry_item_action_snapshot(
            item,
            strategy=strategy,
            observed_status=observed_status,
            old_downstream_task_id=old_task_id,
            cleanup_performed=bool(old_task_id or observed_status == "downstream_missing"),
            binding_cleared=True,
        )

    def _is_vuln_retry_recreate_outcome(self, control: dict[str, Any]) -> bool:
        outcome = str(control.get("retry_outcome") or control.get("outcome") or "").strip()
        if outcome == "not_found":
            return True
        if outcome != "invalid_transition":
            return False
        if control.get("http_status") == 405:
            return True
        error_message = str(control.get("error_message") or "").lower()
        recreate_tokens = (
            "not support",
            "unsupported",
            "not allowed",
            "cannot be retried",
            "cannot retry",
            "retry not supported",
            "invalid status",
            "invalid transition",
            "terminal",
            "终态",
            "重试",
            "不支持重试",
            "无法重试",
            "不能重试",
            "非法状态",
            "状态迁移",
        )
        return any(token in error_message for token in recreate_tokens)

    async def _recreate_vuln_downstream_task(
        self,
        session: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        dataflow_result: dict[str, Any],
        token: str | None,
        *,
        control: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        old_task_id = str(item.downstream_task_id or "").strip() or None
        error_message = str(control.get("error_message") or "").strip() if isinstance(control, dict) else ""
        http_status = control.get("http_status") if isinstance(control, dict) else None
        outcome = str(control.get("outcome") or "").strip() if isinstance(control, dict) else ""

        if old_task_id:
            self._record_downstream_item_disposition(
                session,
                task,
                item,
                event_type="downstream_retry_fallback_delete_requested",
                message=f"下游重试不可复用，准备删除旧下游任务并重建: {item.downstream_service}:{old_task_id}",
                level="warning",
                payload={
                    "stage_name": item.stage_name,
                    "old_downstream_task_id": old_task_id,
                    "new_downstream_task_id": None,
                    "control_outcome": outcome or None,
                    "http_status": http_status,
                    "error": error_message or None,
                },
            )
            session.commit()
            try:
                await self._downstream_tasks().delete_child_task(
                    service="dataflow_vuln_scan",
                    project_id=task.project_id,
                    task_id=old_task_id,
                    token=token,
                )
            except NotFoundError:
                delete_status = 404
            except Exception as exc:
                payload_error = self._extract_downstream_error_text(exc) or str(exc)
                self._record_downstream_item_disposition(
                    session,
                    task,
                    item,
                    event_type="downstream_retry_fallback_delete_failed",
                    message=(
                        f"删除旧下游任务时通信异常，暂不重建: {item.downstream_service}:{old_task_id}"
                        if self._is_retryable_downstream_transport_error(exc)
                        else f"删除旧下游任务失败，无法继续重建: {item.downstream_service}:{old_task_id}"
                    ),
                    level="warning",
                    payload={
                        "stage_name": item.stage_name,
                        "old_downstream_task_id": old_task_id,
                        "new_downstream_task_id": None,
                        "control_outcome": outcome or None,
                        "http_status": self._extract_http_status_from_exception(exc),
                        "error": payload_error,
                    },
                )
                session.commit()
                if self._is_retryable_downstream_transport_error(exc):
                    raise UpstreamError(payload_error)
                raise ValidationError(payload_error)
            else:
                delete_status = 200

            self._record_downstream_item_disposition(
                session,
                task,
                item,
                event_type="downstream_retry_fallback_delete_succeeded",
                message=(
                    f"旧下游任务已删除，继续重建: {item.downstream_service}:{old_task_id}"
                    if delete_status == 200 else
                    f"旧下游任务已不存在，继续重建: {item.downstream_service}:{old_task_id}"
                ),
                payload={
                    "stage_name": item.stage_name,
                    "old_downstream_task_id": old_task_id,
                    "new_downstream_task_id": None,
                    "control_outcome": outcome or None,
                    "http_status": delete_status,
                    "error": error_message or None,
                },
            )
            session.commit()

        dataflow_input_dir = self._resolve_vuln_scan_dataflow_input_dir(dataflow_result)
        source_dir = str(dataflow_result.get("source_root_path") or dataflow_result.get("source_dir") or "")
        if not dataflow_input_dir:
            raise ValidationError("数据流漏洞挖掘输入缺少 data_flow_root/dataflow_dir")
        if not source_dir:
            raise ValidationError("数据流漏洞挖掘输入缺少 source_dir")
        created = await self._downstream_create_task(
            session,
            task,
            item,
            service="dataflow_vuln_scan",
            token=token,
            payload={
                "title": f"{task.name}-{dataflow_result['function_name']}-scan",
                "data_flow_path": dataflow_input_dir,
                "source_dir": source_dir,
                "origin": _downstream_origin_payload(task, item),
            },
        )
        new_task_id = str(created.get("task_id") or created.get("id") or "").strip() or None
        item.downstream_task_id = new_task_id or item.downstream_task_id
        item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
        item.started_at = item.started_at or _now()
        item.finished_at = None
        item.error_message = None
        self._clear_replacement_in_progress(item)
        self._record_downstream_item_disposition(
            session,
            task,
            item,
            event_type="downstream_retry_fallback_recreated",
            message=f"已重建新的下游任务: {item.downstream_service}:{new_task_id or '-'}",
            payload={
                "stage_name": item.stage_name,
                "old_downstream_task_id": old_task_id,
                "new_downstream_task_id": new_task_id,
                "control_outcome": outcome or None,
                "http_status": 200,
                "error": error_message or None,
            },
        )
        session.commit()
        return created

    async def _active_downstream_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None = None,
    ) -> dict[str, Any] | None:
        if not self._has_retryable_downstream_task(item):
            return None
        try:
            payload = await self._fetch_downstream_task_payload(task, item, token or "")
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        mapped_status = self._map_downstream_status(str(payload.get("status") or ""))
        if mapped_status in {"pending", "queued", "dispatching", "running"}:
            return payload
        return None

    def _entry_payload_matches_stage_item(
        self,
        item: BinarySecurityStageItem,
        payload: dict[str, Any] | None,
    ) -> bool:
        if not isinstance(payload, dict):
            return False
        item_id = str(item.id or "").strip()
        item_key = str(item.item_key or "").strip()
        origin_item_id = str(payload.get("parent_stage_item_id") or "").strip()
        origin_item_key = str(payload.get("parent_stage_item_key") or "").strip()
        if item_id:
            return bool(origin_item_id and origin_item_id == item_id)
        if item_key:
            return bool(origin_item_key and origin_item_key == item_key)
        return False

    def _entry_payload_binding_mismatch_payload(
        self,
        item: BinarySecurityStageItem,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "reason_code": "parent_stage_item_mismatch",
            "downstream_service": str(item.downstream_service or "").strip() or None,
            "expected_downstream_task_id": str(item.downstream_task_id or "").strip() or None,
            "observed_downstream_task_id": self._payload_downstream_task_id(payload),
            "current_downstream_task_id": str(item.downstream_task_id or "").strip() or None,
            "payload_downstream_task_id": self._payload_downstream_task_id(payload),
            "expected_parent_stage_item_id": str(item.id or "").strip() or None,
            "expected_parent_stage_item_key": str(item.item_key or "").strip() or None,
            "observed_parent_stage_item_id": str((payload or {}).get("parent_stage_item_id") or "").strip() or None,
            "observed_parent_stage_item_key": str((payload or {}).get("parent_stage_item_key") or "").strip() or None,
        }

    async def _reconcile_entry_payload_binding(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        payload: dict[str, Any],
        token: str | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        del task, token
        if str(item.downstream_service or "").strip() != "entry_analyse":
            return payload, None
        if self._entry_payload_matches_stage_item(item, payload):
            return payload, None
        return None, self._entry_payload_binding_mismatch_payload(item, payload)

    async def _duplicate_downstream_refs_for_item(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
        *,
        keep_task_ids: set[str] | None = None,
    ) -> list[dict[str, str]]:
        del task, item, token, keep_task_ids
        return []

    async def _cleanup_duplicate_downstream_refs_for_item(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
        *,
        keep_task_ids: set[str] | None = None,
    ) -> int:
        del db, task, item, token, keep_task_ids
        return 0

    def _stage_retry_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        require_stage_run: bool = True,
    ) -> tuple[bool, str | None]:
        if stage_name not in self._stage_sequence_for_task(task):
            return False, f"无效阶段: {stage_name}"
        mapping = STAGE_RETRY_ENDPOINTS.get(stage_name)
        if not mapping:
            return False, f"阶段 {stage_name} 未配置安全重试接口"
        self._normalize_cancelled_task_active_children(db, task)
        if task.status in STAGE_RETRY_BLOCKED_TASK_STATUSES:
            return False, f"当前任务状态不允许重试: {task.status}"
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        upstream_supported, upstream_reason = self._stage_full_retry_upstream_support(
            db,
            task,
            stage_name,
            require_stage_run=require_stage_run,
            stage_run=stage_run,
        )
        if not upstream_supported:
            return False, upstream_reason
        items = self._stage_items(db, task.id, stage_name)
        if not items:
            reason = self._continue_stage_input_error(db, task, stage_name)
            if reason:
                return False, reason
            return True, None
        seen: set[str] = set()
        expected_service = mapping[0]
        for item in items:
            logical_key = self._stage_item_identity(item.item_key, item.parent_key)
            if logical_key in seen:
                return False, f"阶段 {stage_name} 存在重复历史 item，无法安全重试: {item.item_key}"
            seen.add(logical_key)
            if item.downstream_service and item.downstream_service != expected_service:
                return False, (
                    f"阶段 {stage_name} 下游服务不匹配，期望 {expected_service}，实际 {item.downstream_service or '-'}"
                )
        return True, None

    def _stage_full_retry_upstream_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        require_stage_run: bool,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> tuple[bool, str | None]:
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            return False, f"无效阶段: {stage_name}"
        target_index = stage_sequence.index(stage_name)
        if target_index == 0:
            return True, None
        for upstream_stage in stage_sequence[:target_index]:
            upstream_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == upstream_stage,
            ).first()
            if upstream_run is None:
                return False, f"上游阶段 {STAGE_TITLES.get(upstream_stage, upstream_stage)} 尚未执行，不能完全重试当前阶段"
            if str(upstream_run.status or "").strip() != "success":
                return False, f"上游阶段 {STAGE_TITLES.get(upstream_stage, upstream_stage)} 尚未成功，不能完全重试当前阶段"
        return True, None

    def _normalize_cancelled_task_active_children(self, db: Session, task: BinarySecurityTask) -> None:
        """Cancelled tasks must not keep stale active stage/item state that blocks retry."""
        if task.status != "cancelled":
            return
        now_value = _now()
        active_items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.status.in_(["pending", "queued", "dispatching", "running"]),
        ).all()
        active_stage_runs = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.status.in_(["pending", "queued", "dispatching", "running"]),
        ).all()
        if not active_items and not active_stage_runs:
            return
        for item in active_items:
            item.status = "cancelled"
            item.finished_at = item.finished_at or now_value
        for stage_run in active_stage_runs:
            stage_run.status = "cancelled"
            stage_run.finished_at = stage_run.finished_at or now_value
        self._record_event(
            db,
            task,
            "cancelled_task_children_normalized",
            "已归一化取消任务中残留的活跃阶段与子任务",
            level="warning",
            stage_name=task.current_stage,
            payload={
                "cancelled_item_count": len(active_items),
                "cancelled_stage_run_count": len(active_stage_runs),
            },
        )

    def _first_retry_stage_name(self, db: Session, task: BinarySecurityTask) -> str | None:
        stage_runs = {
            row.stage_name: row
            for row in db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
            ).all()
        }
        for stage_name in self._stage_sequence_for_task(task):
            run = stage_runs.get(stage_name)
            if not run:
                return None
            if run.status != "success":
                return stage_name
        return None

    def _task_retry_support(self, db: Session, task: BinarySecurityTask) -> tuple[bool, str | None, str | None]:
        if self._streaming_tail_auto_progressing(db, task):
            return False, "当前任务处于 streaming tail 自动推进中，暂不支持任务重试", None
        active_operation = self._active_operation(db, task.id)
        if active_operation is not None:
            return False, f"当前任务已有进行中的操作: {active_operation.operation_type}", None
        if task.status in {"pending_upload", "uploading"}:
            return False, "当前任务尚未完成输入准备，不能重试", None
        blocked_statuses = {"pending", "dispatching", "running"}
        if task.status in blocked_statuses:
            return False, f"当前任务正在执行或排队中，不能重试: {task.status}", None
        stage_sequence = self._stage_sequence_for_task(task)
        if not stage_sequence:
            return False, "当前任务没有可执行阶段", None
        return True, None, stage_sequence[0]

    def _task_retry_failed_items_support(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[bool, str | None, str | None, list[BinarySecurityStageItem]]:
        from app.service.task.state_machine import TaskStateMachineMixin

        return TaskStateMachineMixin._task_retry_failed_items_support(self, db, task)

    def _ensure_stage_inputs_available(self, db: Session, task: BinarySecurityTask, stage_name: str) -> None:
        """Rebuild target-stage inputs from the previous successful stage when possible."""
        summary = dict(task.summary or {})
        if normalize_stage_name(stage_name) == "knowledge_graph_entry_fetch":
            return
        if normalize_stage_name(stage_name) == "firmware_unpack" and not summary.get("input_files"):
            self._repair_firmware_unpack_inputs_from_workspace(task)
            summary = dict(task.summary or {})
        if stage_name in {"binary_to_source", "entry_analysis"} and not summary.get("selected_modules"):
            self._refresh_system_analysis_stage_from_synced_items(db, task)
            summary = dict(task.summary or {})
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan" and not summary.get("entry_results"):
            if self._pipeline_profile(task) != PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                self._refresh_system_analysis_stage_from_synced_items(db, task)
                summary = dict(task.summary or {})
        if stage_name == "entry_analysis" and self._task_type(task) != TASK_TYPE_SOURCE and not summary.get("b2s_results"):
            self._rebuild_summary_results_from_stage_items(db, task, "binary_to_source", "b2s_results")
            summary = dict(task.summary or {})
        if stage_name == "entry_analysis" and self._task_type(task) == TASK_TYPE_BINARY_MODULE and summary.get("b2s_results"):
            normalized = [self._normalize_entry_analysis_module_input(task, module) for module in (summary.get("b2s_results") or []) if isinstance(module, dict)]
            if normalized != list(summary.get("b2s_results") or []):
                task.summary = {**summary, "b2s_results": normalized}
        if normalize_stage_name(stage_name) == "entry_analysis":
            self._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task)
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan" and not summary.get("entry_results"):
            if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                self._refresh_knowledge_graph_entry_fetch_summary(task)
            else:
                self._rebuild_entry_results_from_stage_items(db, task)

    def _entry_analysis_historical_child_count(self, db: Session, task: BinarySecurityTask) -> int:
        if hasattr(db, "ea_tasks") and isinstance(getattr(db, "ea_tasks"), list):
            return len(
                [
                    row
                    for row in list(getattr(db, "ea_tasks") or [])
                    if str(getattr(row, "parent_task_id", "") or "").strip() == str(task.id or "").strip()
                    and str(getattr(row, "parent_stage_name", "") or "").strip() == "entry_analysis"
                ]
            )
        try:
            result = db.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM secflow_app_ea_tasks
                    WHERE parent_task_id = :parent_task_id
                      AND parent_stage_name = :parent_stage_name
                    """
                ),
                {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"},
            )
            scalar = result.scalar() if result is not None else 0
            return max(0, int(scalar or 0))
        except Exception:
            return 0

    def _entry_analysis_authoritative_rebuild_required(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> dict[str, Any]:
        stage_name = "entry_analysis"
        normalized_stage_name = normalize_stage_name(stage_name)
        current_items = self._stage_items(db, task.id, normalized_stage_name)
        current_stage_item_count = len(current_items)
        resolved_stage_run = stage_run
        if resolved_stage_run is None:
            resolved_stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == normalized_stage_name,
            ).first()
        stage_run_status = str(getattr(resolved_stage_run, "status", "") or "").strip() or None
        inputs = self._entry_analysis_inputs(db, task)
        input_count = len(inputs)
        active_operation = self._task_active_operation(db, task)
        historical_child_count = self._entry_analysis_historical_child_count(db, task)
        reason = None
        required = False
        if resolved_stage_run is None:
            reason = "stage_run_missing"
        elif stage_run_status not in {"pending", "queued"}:
            reason = "stage_run_not_pending"
        elif current_stage_item_count > 0:
            reason = "authoritative_items_present"
        elif input_count <= 0:
            reason = "missing_entry_analysis_inputs"
        elif active_operation is not None:
            reason = "active_operation_in_progress"
        elif historical_child_count <= 0:
            reason = "no_historical_entry_analysis_children"
        else:
            reason = "historical_children_exist_but_authoritative_items_missing"
            required = True
        return {
            "required": required,
            "reason": reason,
            "stage_name": normalized_stage_name,
            "input_count": input_count,
            "historical_child_count": historical_child_count,
            "current_stage_item_count": current_stage_item_count,
            "stage_run_status": stage_run_status,
        }

    def _entry_analysis_authoritative_items_ready(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> bool:
        rebuild_state = self._entry_analysis_authoritative_rebuild_required(db, task, stage_run=stage_run)
        if str(rebuild_state.get("reason") or "").strip() == "active_operation_in_progress":
            return False
        return not bool(rebuild_state.get("required"))

    def _stage_has_authoritative_materialization(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        stage_run: BinarySecurityStageRun | None = None,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        resolved_items = stage_items if stage_items is not None else self._stage_items(db, task.id, normalized_stage)
        if resolved_items:
            return True
        if normalized_stage == "entry_analysis":
            rebuild_state = self._entry_analysis_authoritative_rebuild_required(
                db,
                task,
                stage_run=stage_run,
            )
            return bool(
                rebuild_state.get("required")
                and rebuild_state.get("reason") == "historical_children_exist_but_authoritative_items_missing"
                and int(rebuild_state.get("input_count") or 0) > 0
            )
        if normalized_stage == "dataflow_vuln_scan":
            upstream_stage = self._streaming_upstream_stage(task, normalized_stage)
            if upstream_stage and self._stage_requires_archive_success_gate(task, upstream_stage):
                if not self._stage_has_archived_success_progress(db, task, upstream_stage):
                    return False
            return bool(self._effective_entry_inputs(task, db) or self._entry_results(task))
        return False

    def _system_analysis_authoritative_complete(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        """system_analysis 是否已产出权威结果且 summary 已刷新（selected_modules 键存在）。

        用于区分入口分析“未就绪需阻塞”与“就绪但 0 模块应成功收口”。
        """
        stage_run = (
            db.query(BinarySecurityStageRun)
            .filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == "system_analysis",
            )
            .first()
        )
        if stage_run is None:
            return False
        if str(stage_run.status or "").strip() not in {"success", "partial_success"}:
            return False
        # 就绪判据（双路 OR）：
        # ① task.summary 的 _summary_cache 有 selected_modules 键（同 session 内 setter 设过时有效）；
        # ② stage_run.output_summary 有 module_count（DB 直读、由 refresh_summary_from_items 写入，
        #    跨 session 也可靠——archive_dispatch_loop 的 session 写的 output_summary 在 DB 里）。
        # 两条路覆盖：测试场景（cache fresh）和生产场景（cache stale 但 output_summary 在 DB）。
        output_summary = dict(getattr(stage_run, "output_summary", None) or {})
        return "selected_modules" in dict(task.summary or {}) or output_summary.get("module_count") is not None

    def _binary_to_source_authoritative_complete(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        """binary_to_source 是否已收敛（无活跃子项）。

        BINARY / BINARY_MODULE 任务的入口分析输入来自 binary_to_source 的 b2s_results。
        仍在运行（有活跃子项/未终态）时入口分析应阻塞等待，而非提前 fail；
        已收敛（success/failed/cancelled 等终态）后才交由 _missing_entry_analysis_input_reason
        给出具体原因（例如 b2s 失败时传播其错误）。
        """
        items = self._stage_items(db, task.id, "binary_to_source")
        if items:
            active_statuses = {"pending", "queued", "running", "dispatching"}
            return not any(
                (self._normalize_downstream_status(item.status) or str(item.status or "").strip()) in active_statuses
                for item in items
            )
        stage_run = (
            db.query(BinarySecurityStageRun)
            .filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == "binary_to_source",
            )
            .first()
        )
        if stage_run is None:
            return False
        return str(stage_run.status or "").strip() in {
            "success",
            "partial_success",
            "failed",
            "cancelled",
            "downstream_missing",
        }

    def _entry_analysis_pending_requires_materialization(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_run: BinarySecurityStageRun | None = None,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ) -> bool:
        # 系统分析尚未就绪：阻塞等待，不跳过也不收口
        if not self._system_analysis_authoritative_complete(db, task):
            return True
        # 就绪但 0 模块：不阻塞，交给 _should_finalize_without_entries 成功收口
        if int(dict(task.metrics or {}).get("selected_module_count") or 0) == 0:
            return False
        rebuild_state = self._entry_analysis_authoritative_rebuild_required(db, task, stage_run=stage_run)
        if bool(rebuild_state.get("required")):
            return True
        resolved_items = stage_items if stage_items is not None else self._stage_items(db, task.id, "entry_analysis")
        resolved_status = str(getattr(stage_run, "status", "") or "").strip() if stage_run is not None else ""
        return bool(resolved_status in {"pending", "queued"} and not resolved_items)

    def _mark_entry_analysis_authoritative_rebuild_summary(
        self,
        task: BinarySecurityTask,
        rebuild_state: dict[str, Any],
    ) -> None:
        stage_name = "entry_analysis"
        stage_summary = dict(task.stage_summary or {})
        current_summary = dict(stage_summary.get(stage_name) or {})
        current_summary.update(
            {
                "authoritative_items_missing": bool(rebuild_state.get("current_stage_item_count", 0) == 0),
                "authoritative_rebuild_required": bool(rebuild_state.get("required")),
                "authoritative_rebuild_reason": rebuild_state.get("reason"),
                "historical_child_count": int(rebuild_state.get("historical_child_count") or 0),
            }
        )
        if rebuild_state.get("required"):
            current_summary["status_label"] = "待补建"
        stage_summary[stage_name] = current_summary
        task.stage_summary = stage_summary

    def _rebuild_missing_entry_analysis_stage_items_from_inputs(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_run: BinarySecurityStageRun | None = None,
    ) -> dict[str, Any]:
        rebuild_state = self._entry_analysis_authoritative_rebuild_required(db, task, stage_run=stage_run)
        self._mark_entry_analysis_authoritative_rebuild_summary(task, rebuild_state)
        if not rebuild_state.get("required"):
            if rebuild_state.get("reason") not in {
                "authoritative_items_present",
                "missing_entry_analysis_inputs",
                "stage_run_missing",
            }:
                self._record_event(
                    db,
                    task,
                    "entry_analysis_authoritative_items_rebuild_skipped",
                    "入口分析 authoritative item 补建已跳过",
                    stage_name="entry_analysis",
                    payload=dict(rebuild_state),
                )
            return {"rebuilt": False, "rebuilt_item_count": 0, **rebuild_state}
        resolved_stage_run = stage_run or self._ensure_stage_run(db, task, "entry_analysis")
        self._record_event(
            db,
            task,
            "entry_analysis_authoritative_items_missing_detected",
            "检测到入口分析 authoritative item 丢失，准备补建",
            stage_name="entry_analysis",
            level="warning",
            payload=dict(rebuild_state),
        )
        self._record_event(
            db,
            task,
            "entry_analysis_authoritative_items_rebuild_started",
            "入口分析 authoritative item 补建开始",
            stage_name="entry_analysis",
            payload=dict(rebuild_state),
        )
        rebuilt_item_count = 0
        try:
            for module in self._entry_analysis_inputs(db, task):
                item = self._upsert_stage_item(
                    db,
                    task=task,
                    stage_run=resolved_stage_run,
                    stage_name="entry_analysis",
                    item_key=module["module_key"],
                    item_name=module["module_name"],
                    parent_key=module.get("firmware_key"),
                    downstream_service="entry_analyse",
                    input_ref=module,
                    retrying=False,
                    auto_retrying=False,
                )
                item.status = "pending"
                item.downstream_task_id = None
                item.started_at = None
                item.finished_at = None
                item.error_message = None
                rebuilt_item_count += 1
            resolved_stage_run.counts = self._stage_counts(db, resolved_stage_run)
            completed_state = {
                **rebuild_state,
                "required": False,
                "reason": "authoritative_items_rebuilt",
                "current_stage_item_count": rebuilt_item_count,
                "rebuilt_item_count": rebuilt_item_count,
            }
            self._mark_entry_analysis_authoritative_rebuild_summary(task, completed_state)
            self._record_event(
                db,
                task,
                "entry_analysis_authoritative_items_rebuild_finished",
                "入口分析 authoritative item 补建完成",
                stage_name="entry_analysis",
                payload=dict(completed_state),
            )
            return {"rebuilt": True, **completed_state}
        except Exception as exc:
            failed_state = {
                **rebuild_state,
                "rebuilt_item_count": rebuilt_item_count,
                "error": str(exc),
            }
            self._record_event(
                db,
                task,
                "entry_analysis_authoritative_items_rebuild_failed",
                "入口分析 authoritative item 补建失败",
                stage_name="entry_analysis",
                level="error",
                payload=failed_state,
            )
            raise

    def _rebuild_summary_results_from_stage_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        summary_key: str,
    ) -> list[dict[str, Any]]:
        allowed_statuses = {"success"}
        include_partial_success_payloads = summary_key == "dataflow_results" and self._task_type(task) == TASK_TYPE_SOURCE
        if include_partial_success_payloads:
            allowed_statuses.add("partial_success")
        items = [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if item.status in allowed_statuses
        ]
        count_items = list(items)
        if summary_key == "dataflow_results" and not include_partial_success_payloads:
            count_items = [
                item
                for item in self._stage_items(db, task.id, stage_name)
                if item.status in {"success", "partial_success"}
            ]
        rebuilt = self._compact_stage_success_items(
            summary_key,
            [
                {
                    **dict(item.input_ref or {}),
                    **dict(item.output_ref or {}),
                    **self._load_stage_item_result_payload(item),
                }
                for item in items
            ],
        )
        counted_rebuilt = self._compact_stage_success_items(
            summary_key,
            [
                {
                    **dict(item.input_ref or {}),
                    **dict(item.output_ref or {}),
                    **self._load_stage_item_result_payload(item),
                }
                for item in count_items
            ],
        )
        if summary_key == "b2s_results" and self._task_type(task) == TASK_TYPE_BINARY_MODULE:
            rebuilt = [self._normalize_entry_analysis_module_input(task, item) for item in rebuilt]
        next_summary = {**(task.summary or {}), summary_key: rebuilt}
        if summary_key == "dataflow_results":
            next_summary["vuln_results"] = list(rebuilt)
        task.summary = next_summary
        if summary_key == "dataflow_results":
            task.metrics = {**(task.metrics or {}), "vuln_result_count": len(rebuilt)}
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if stage_run is not None:
            failed_items = [
                self._lightweight_stage_failure(
                    {
                        "item": {
                            **dict(item.input_ref or {}),
                            **self._load_stage_item_result_payload(item),
                        },
                        "error": item.error_message,
                    }
                )
                for item in self._stage_items(db, task.id, stage_name)
                if item.status in {"failed", "downstream_missing"}
            ]
            cancelled_items = [
                self._lightweight_stage_failure(
                    {
                        "item": {
                            **dict(item.input_ref or {}),
                            **self._load_stage_item_result_payload(item),
                        },
                        "error": item.error_message,
                    }
                )
                for item in self._stage_items(db, task.id, stage_name)
                if item.status == "cancelled"
            ]
            self._persist_stage_run_output_summary(
                task,
                stage_run,
                {
                    "items": self._compact_stage_success_items_for_db(summary_key, rebuilt),
                    "failed_items": failed_items[:DB_FAILURE_ITEM_LIMIT],
                    "cancelled_items": cancelled_items[:DB_FAILURE_ITEM_LIMIT],
                    "success_count": len(counted_rebuilt),
                    "failed_count": int((stage_run.counts or {}).get("failed_items") or 0),
                    "cancelled_count": int((stage_run.counts or {}).get("cancelled_items") or 0),
                    "running_count": int((stage_run.counts or {}).get("running_items") or 0),
                    "entry_count": self._entry_count_for_summary(summary_key, rebuilt),
                    "vuln_result_count": len(counted_rebuilt) if summary_key == "dataflow_results" else 0,
                    "status_synced": True,
                    "sync_status": stage_run.status,
                    **(stage_run.counts or {}),
                },
            )
        return rebuilt

    def _continue_stage_input_error(self, db: Session, task: BinarySecurityTask, stage_name: str) -> str | None:
        self._ensure_stage_inputs_available(db, task, stage_name)
        summary = dict(task.summary or {})
        handler = self._stage_handler(stage_name)
        if handler is not None and normalize_stage_name(stage_name) in {"firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "knowledge_graph_entry_fetch", "dataflow_vuln_scan"}:
            handler_reason = handler.continue_stage_input_error(self, db, task)
            return handler_reason
        if stage_name == "binary_to_source":
            inputs = list(summary.get("selected_modules") or [])
            if not inputs:
                return "系统分析尚未产出可用模块，不能继续二进制逆向阶段"
            return None
        if normalize_stage_name(stage_name) == "knowledge_graph_entry_fetch":
            source_dir = str(summary.get("input_dir") or "").strip()
            if not source_dir:
                return "源码任务缺少输入目录，不能继续知识图谱入口获取阶段"
            return None
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            inputs = list(self._entry_results(task) or [])
            if not inputs:
                if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                    return "知识图谱入口获取尚未产出可用入口结果，不能继续数据流漏洞挖掘阶段"
                return "入口分析尚未产出可用入口结果，不能继续数据流漏洞挖掘阶段"
            return None
        return None

    def _should_terminalize_blocked_stage_input(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        blocked_reason: str | None,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        reason = str(blocked_reason or "").strip()
        if not normalized_stage or not reason:
            return False
        if normalized_stage == "firmware_unpack":
            self._ensure_stage_inputs_available(db, task, normalized_stage)
            return not bool(list((task.summary or {}).get("input_files") or []))
        return False

    def _repair_firmware_unpack_inputs_from_workspace(self, task: BinarySecurityTask) -> bool:
        if self._task_type(task) != TASK_TYPE_BINARY:
            return False
        summary = dict(task.summary or {})
        if list(summary.get("input_files") or []):
            return False
        input_dir = self._task_input_dir(task)
        metadata_path = Path(str(summary.get("input_manifest_path") or input_dir / "task-metadata.json")).resolve()
        recovered_inputs: list[dict[str, Any]] = []
        metadata_payload: dict[str, Any] = {}
        try:
            if metadata_path.is_file():
                raw = json.loads(metadata_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    metadata_payload = raw
        except Exception:
            metadata_payload = {}
        for current in list(metadata_payload.get("input_files") or []):
            if not isinstance(current, dict):
                continue
            row = dict(current)
            filename = str(row.get("filename") or row.get("relative_path") or "").strip()
            if not filename:
                continue
            relative_path = str(row.get("relative_path") or filename).strip().replace("\\", "/")
            local_path = input_dir / relative_path
            if not local_path.is_file():
                continue
            recovered_inputs.append(
                {
                    **row,
                    "filename": filename,
                    "relative_path": relative_path,
                    "firmware_key": str(row.get("firmware_key") or _slug(Path(filename).stem or filename)).strip(),
                    "uploaded": True if row.get("uploaded") is None else row.get("uploaded"),
                    "size": int(row.get("size") or local_path.stat().st_size),
                    "path": str(row.get("path") or f"{summary.get('input_dir') or str(input_dir)}/{relative_path}"),
                }
            )
        if not recovered_inputs and input_dir.is_dir():
            for local_path in sorted(current for current in input_dir.rglob("*") if current.is_file() and current.name != "task-metadata.json"):
                relative_path = str(local_path.relative_to(input_dir)).replace("\\", "/")
                filename = local_path.name
                recovered_inputs.append(
                    {
                        "filename": filename,
                        "relative_path": relative_path,
                        "firmware_key": _slug(Path(filename).stem or filename),
                        "uploaded": True,
                        "size": int(local_path.stat().st_size),
                        "path": f"{summary.get('input_dir') or str(input_dir)}/{relative_path}",
                    }
                )
        if not recovered_inputs:
            return False
        task.summary = {
            **summary,
            "input_files": recovered_inputs,
            "input_dir": str(summary.get("input_dir") or input_dir),
            "input_manifest_path": str(summary.get("input_manifest_path") or input_dir / "task-metadata.json"),
        }
        task.metrics = {
            **dict(task.metrics or {}),
            "input_file_count": len(recovered_inputs),
            "uploaded_file_count": len(recovered_inputs),
            "firmware_item_count": len(recovered_inputs),
            "input_total_bytes": int(sum(int(item.get("size") or 0) for item in recovered_inputs)),
        }
        return True

    def _streaming_tail_auto_progressing(self, db: Session, task: BinarySecurityTask) -> bool:
        if not self._streaming_mode_enabled(task):
            return False
        if str(task.status or "").strip() not in {"pending", "queued", "running", "dispatching"}:
            return False
        tail_stages = self._streaming_tail_stage_names(task)
        if not tail_stages:
            return False
        for stage_name in tail_stages:
            for item in self._stage_items(db, task.id, stage_name):
                if self._is_streaming_active_item_status(item.status):
                    return True
        return False

    def _clear_stage_outputs_from(self, task: BinarySecurityTask, stage_name: str, *, mark_stale: bool = True) -> None:
        summary = dict(task.summary or {})
        metrics = dict(task.metrics or {})
        stage_summary = dict(task.stage_summary or {})
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            return
        affected = stage_sequence[stage_sequence.index(stage_name):]
        for current_stage in affected:
            for summary_key in self._stage_result_keys(current_stage):
                summary.pop(summary_key, None)
            stage_summary.pop(current_stage, None)
            metrics.update(STAGE_METRIC_RESETTERS.get(current_stage, {}))
        if mark_stale:
            summary["stale_reason"] = "upstream_stage_retried"
            summary["stale_from_stage"] = stage_name
            summary["stale_stages"] = stage_sequence[stage_sequence.index(stage_name) + 1:]
        else:
            summary.pop("stale_reason", None)
            summary.pop("stale_from_stage", None)
            summary.pop("stale_stages", None)
        task.summary = summary
        task.metrics = metrics
        task.stage_summary = stage_summary

    def _clear_task_failure_state(self, task: BinarySecurityTask) -> None:
        task.summary = self._clear_failure_fields_from_summary(task.summary or {})
        task.last_error = None

    def _archive_apply_repaired_stage_refresh(self, db: Session, task: BinarySecurityTask, stage_name: str) -> None:
        normalized_stage = normalize_stage_name(stage_name)
        handler = self._stage_handler(normalized_stage)
        if handler is not None and handler.manages_stage_refresh():
            handler.repair_after_archive_apply(self, db, task)
        elif normalized_stage == "firmware_unpack":
            self._refresh_firmware_unpack_stage_from_synced_items(db, task)
        elif normalized_stage == "binary_to_source":
            self._rebuild_summary_results_from_stage_items(db, task, "binary_to_source", "b2s_results")
        elif normalized_stage == "entry_analysis":
            self._rebuild_entry_results_from_stage_items(db, task)

    def _archive_apply_downstream_input_signature(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> dict[str, Any]:
        normalized_stage = normalize_stage_name(stage_name)
        handler = self._stage_handler(normalized_stage)
        if handler is not None:
            return handler.archive_input_signature(self, db, task)
        summary = dict(task.summary or {})
        if normalized_stage == "binary_to_source":
            entry_inputs = self._entry_analysis_inputs(db, task)
            entry_keys = [
                str(row.get("module_key") or row.get("entry_key") or "").strip()
                for row in entry_inputs
                if isinstance(row, dict)
            ]
            return {
                "stage_name": "binary_to_source",
                "entry_input_count": len(entry_inputs),
                "entry_input_keys": [key for key in entry_keys if key],
            }
        if normalized_stage == "entry_analysis":
            entry_results = self._effective_entry_inputs(task, db)
            entries: list[dict[str, Any]] = []
            for row in entry_results:
                if isinstance(row, dict):
                    entries.extend([dict(entry) for entry in list(row.get("entries") or []) if isinstance(entry, dict)])
            deduped = _deduplicate_entry_keys(entries)
            entry_keys = [str(entry.get("entry_key") or "").strip() for entry in deduped if str(entry.get("entry_key") or "").strip()]
            return {
                "stage_name": "entry_analysis",
                "entry_count": len(deduped),
                "entry_keys": entry_keys,
            }
        if normalized_stage == "firmware_unpack":
            system_inputs = self._system_analysis_inputs(task)
            firmware_keys = [
                str(row.get("firmware_key") or "").strip()
                for row in system_inputs
                if isinstance(row, dict) and str(row.get("firmware_key") or "").strip()
            ]
            return {
                "stage_name": "firmware_unpack",
                "system_input_count": len(system_inputs),
                "firmware_keys": firmware_keys,
            }
        return {"stage_name": normalized_stage}

    def _archive_apply_signature_has_runnable_inputs(self, signature: dict[str, Any] | None) -> bool:
        payload = dict(signature or {})
        stage_name = normalize_stage_name(payload.get("stage_name"))
        handler = self._stage_handler(stage_name)
        if handler is not None:
            return handler.archive_signature_has_runnable_inputs(payload)
        if stage_name == "binary_to_source":
            return int(payload.get("entry_input_count") or 0) > 0
        if stage_name == "entry_analysis":
            return int(payload.get("entry_count") or 0) > 0
        if stage_name == "firmware_unpack":
            return int(payload.get("system_input_count") or 0) > 0
        return False

    def _archive_apply_stage_has_authoritative_success_payload(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        handler = self._stage_handler(normalized_stage)
        if handler is not None:
            return handler.has_authoritative_success_payload(self, db, task)
        return False

    def _virtual_archive_stage_status(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> str | None:
        normalized_stage = normalize_stage_name(stage_name)
        handler = self._stage_handler(normalized_stage)
        if handler is None:
            return None
        return handler.archive_virtual_status(self, db, task)

    def _descendant_stages_for_stage(self, task: BinarySecurityTask, stage_name: str) -> list[str]:
        normalized_stage_name = str(stage_name or "").strip()
        handler = self._stage_handler(normalized_stage_name)
        if handler is not None:
            return [stage for stage in handler.descendant_stages(self, task) if self._stage_enabled(task, stage)]
        stage_sequence = self._stage_sequence_for_task(task)
        if normalized_stage_name not in stage_sequence:
            return []
        index = stage_sequence.index(normalized_stage_name)
        return [stage for stage in stage_sequence[index + 1 :] if self._stage_enabled(task, stage)]

    def _is_archive_repair_sensitive_failure(
        self,
        stage_name: str,
        *,
        failure_code: str | None,
        failure_message: str | None,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        code = str(failure_code or "").strip().lower()
        message = str(failure_message or "").strip()
        lowered = message.lower()
        if normalized_stage == "binary_to_source":
            return code == "missing_selected_modules" or "缺少已选模块列表" in message
        if normalized_stage == "entry_analysis":
            return code == "missing_entry_analysis_input" or "可用于入口分析" in message or "缺少源码模块" in message or "缺少入口分析" in lowered
        if normalized_stage == "dataflow_vuln_scan":
            return code == "missing_dataflow_entries" or "可用于数据流漏洞挖掘的入口" in message
        if normalized_stage == "system_analysis":
            return code == "missing_system_analysis_input" or "可用于系统分析的输入" in message
        return False

    def _archive_apply_descendant_contamination(
        self,
        db: Session,
        task: BinarySecurityTask,
        repaired_stage: str,
    ) -> list[dict[str, Any]]:
        contaminated: list[dict[str, Any]] = []
        descendant_stages = self._descendant_stages_for_stage(task, repaired_stage)
        if not descendant_stages:
            return contaminated
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        runs_by_stage = {str(run.stage_name or "").strip(): run for run in stage_runs}
        for stage_name in descendant_stages:
            stage_run = runs_by_stage.get(stage_name)
            stage_items = self._stage_items(db, task.id, stage_name)
            has_materialized_progress = self._archive_apply_descendant_has_materialized_progress(
                db,
                task,
                stage_name,
                stage_run=stage_run,
                stage_items=stage_items,
            )
            stage_status = self._normalize_downstream_status(getattr(stage_run, "status", None)) or str(getattr(stage_run, "status", "") or "").strip().lower()
            failure_snapshot = self._stage_failure_snapshot(task, stage_run) if stage_run is not None else {}
            failure_code = self._string_or_none(failure_snapshot.get("failure_code"))
            failure_message = (
                self._string_or_none(failure_snapshot.get("failure_message"))
                or self._string_or_none(failure_snapshot.get("error"))
                or self._string_or_none(getattr(stage_run, "last_error", None))
            )
            is_streaming_tail = self._streaming_mode_enabled(task) and self._is_streaming_tail_stage(task, stage_name)
            reason: str | None = None
            if stage_status in {"failed", "cancelled", "downstream_missing"} and self._is_archive_repair_sensitive_failure(
                stage_name,
                failure_code=failure_code,
                failure_message=failure_message,
            ):
                reason = "failed_due_to_missing_repaired_inputs"
            elif (
                not is_streaming_tail
                and stage_status in {"pending", "queued", "running", "dispatching", "success", "partial_success"}
                and stage_items
            ):
                reason = "stale_descendant_items_present"
            elif (
                not is_streaming_tail
                and stage_status in {"pending", "queued", "running", "dispatching", "success", "partial_success"}
                and stage_run is not None
                and has_materialized_progress
            ):
                reason = "stale_descendant_stage_run_present"
            if reason:
                contaminated.append(
                    {
                        "stage_name": stage_name,
                        "reason": reason,
                        "stage_run": stage_run,
                        "stage_items": list(stage_items),
                        "failure_code": failure_code,
                        "failure_message": failure_message,
                    }
                )
        return contaminated

    def _archive_apply_descendant_has_materialized_progress(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        stage_run: BinarySecurityStageRun | None,
        stage_items: list[BinarySecurityStageItem],
    ) -> bool:
        if stage_items:
            return True
        if normalize_stage_name(stage_name) in {"entry_analysis", "dataflow_vuln_scan"}:
            return self._stage_has_authoritative_materialization(
                db,
                task,
                stage_name,
                stage_run=stage_run,
                stage_items=stage_items,
            )
        if self._archive_jobs_for_stages(db, task.id, [stage_name]):
            return True
        stage_summary = dict(task.stage_summary or {})
        if bool(stage_summary.get(stage_name)):
            return True
        summary = dict(task.summary or {})
        if any(summary.get(key) for key in self._stage_result_keys(stage_name)):
            return True
        if stage_run is None:
            return False
        stage_status = self._normalize_downstream_status(getattr(stage_run, "status", None)) or str(getattr(stage_run, "status", "") or "").strip().lower()
        if stage_status in {"success", "partial_success"}:
            return bool(getattr(stage_run, "output_summary", None))
        return False

    def _archive_apply_forced_descendant_contamination(
        self,
        db: Session,
        task: BinarySecurityTask,
        repaired_stage: str,
    ) -> list[dict[str, Any]]:
        normalized_repaired_stage = normalize_stage_name(repaired_stage)
        current_stage = str(task.current_stage or "").strip()
        if normalized_repaired_stage != "system_analysis":
            return []
        descendant_stages = self._descendant_stages_for_stage(task, repaired_stage)
        if not descendant_stages:
            return []
        forced_start_stage: str | None = None
        if current_stage and current_stage in descendant_stages:
            current_stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == current_stage,
            ).first()
            current_failure_message = (
                self._string_or_none(getattr(current_stage_run, "last_error", None))
                or self._string_or_none(task.last_error)
            )
            if self._is_archive_repair_sensitive_failure(
                current_stage,
                failure_code=None,
                failure_message=current_failure_message,
            ):
                forced_start_stage = current_stage
        if forced_start_stage is None:
            for stage_name in descendant_stages:
                stage_run = db.query(BinarySecurityStageRun).filter(
                    BinarySecurityStageRun.task_id == task.id,
                    BinarySecurityStageRun.stage_name == stage_name,
                ).first()
                if stage_run is None:
                    continue
                failure_snapshot = self._stage_failure_snapshot(task, stage_run)
                failure_message = (
                    self._string_or_none(failure_snapshot.get("failure_message"))
                    or self._string_or_none(failure_snapshot.get("error"))
                    or self._string_or_none(getattr(stage_run, "last_error", None))
                )
                if self._is_archive_repair_sensitive_failure(
                    stage_name,
                    failure_code=self._string_or_none(failure_snapshot.get("failure_code")),
                    failure_message=failure_message,
                ):
                    forced_start_stage = stage_name
                    break
        if forced_start_stage is None:
            return []
        contaminated: list[dict[str, Any]] = []
        start_index = descendant_stages.index(forced_start_stage)
        for stage_name in descendant_stages[start_index:]:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            stage_items = self._stage_items(db, task.id, stage_name)
            if stage_run is None and not stage_items:
                continue
            if not stage_items and not self._archive_apply_descendant_has_materialized_progress(
                db,
                task,
                stage_name,
                stage_run=stage_run,
                stage_items=stage_items,
            ):
                continue
            contaminated.append(
                {
                    "stage_name": stage_name,
                    "reason": "forced_missing_input_descendant_repair",
                    "stage_run": stage_run,
                    "stage_items": list(stage_items),
                    "failure_code": None,
                    "failure_message": current_failure_message,
                }
            )
        return contaminated

    def _reset_descendant_stages_after_archive_repair(
        self,
        db: Session,
        task: BinarySecurityTask,
        repaired_stage: str,
        contaminated: list[dict[str, Any]],
    ) -> dict[str, Any]:
        affected_stages = [str(row.get("stage_name") or "").strip() for row in contaminated if str(row.get("stage_name") or "").strip()]
        if not affected_stages:
            return {
                "affected_stages": [],
                "deleted_stage_item_count": 0,
                "deleted_archive_job_count": 0,
                "deleted_state_event_count": 0,
                "deleted_timeline_event_count": 0,
            }
        self._clear_task_failure_state(task)
        self._clear_stage_outputs_from(task, affected_stages[0], mark_stale=False)
        self._clear_stage_output_artifacts(task, affected_stages)
        deleted_archive_job_count = self._delete_archive_children_for_stages(db, task, affected_stages)
        deleted_stage_item_count = self._delete_stage_items_for_stages(db, task.id, affected_stages)
        deleted_state_event_count = self._delete_state_event_rows_for_stages(db, task.id, affected_stages)
        deleted_timeline_event_count = 0
        for stage_name in affected_stages:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            if stage_run is not None:
                self._reset_stage_run_for_retry(task, stage_run, increment_retry=False)
        return {
            "affected_stages": affected_stages,
            "deleted_stage_item_count": deleted_stage_item_count,
            "deleted_archive_job_count": deleted_archive_job_count,
            "deleted_state_event_count": deleted_state_event_count,
            "deleted_timeline_event_count": deleted_timeline_event_count,
        }

    def _base_task_summary(
        self,
        task: BinarySecurityTask,
        *,
        input_files: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        existing_summary = dict(task.summary or {})
        runtime_task_keys = (
            dict(existing_summary.get("runtime_task_keys") or {})
            if isinstance(existing_summary.get("runtime_task_keys"), dict)
            else {}
        )
        normalized_inputs = [dict(item) for item in (input_files if input_files is not None else existing_summary.get("input_files") or [])]
        input_dir = Path(task.workspace_root) / "input"
        run_dir = Path(task.workspace_root) / "run"
        output_root = Path(task.output_root)
        task_type = self._task_type(task)
        summary = {
            "fileserver_project_path": str(task.workspace_root),
            "task_root_path": str(task.workspace_root),
            "input_dir": str(existing_summary.get("input_dir") or input_dir),
            "output_dir": str(output_root),
            "run_dir": str(run_dir),
            "temp_upload_dir": str(run_dir / "upload-tmp") if task_type == TASK_TYPE_SOURCE else None,
            "input_manifest_path": str(input_dir / "task-metadata.json"),
            "input_files": normalized_inputs,
            "input_kind": (
                str(existing_summary.get("input_kind") or "source_archives")
                if task_type == TASK_TYPE_SOURCE
                else "module_elf_files"
                if task_type == TASK_TYPE_BINARY_MODULE
                else "firmware_files"
            ),
            "module_input": (
                {
                    "module_name": str(existing_summary.get("module_input", {}).get("module_name") or task.name or "").strip(),
                    "file_count": len(normalized_inputs),
                }
                if task_type == TASK_TYPE_BINARY_MODULE
                else None
            ),
            "system_analysis_bypassed": task_type == TASK_TYPE_BINARY_MODULE,
            "downstream_task_ids": {},
            "system_analysis_modules": [],
            "candidate_modules": [],
            "selected_modules": [],
            "execution_epoch": int(getattr(task, "execution_epoch", 0) or 0),
            "input_mode": str(existing_summary.get("input_mode") or "uploaded_files"),
            "input_file_path": existing_summary.get("input_file_path"),
            "input_dir_path": existing_summary.get("input_dir_path"),
            "input_file_paths": list(existing_summary.get("input_file_paths") or []),
            "runtime_task_keys": {
                "root_task_key_secret": str(runtime_task_keys.get("root_task_key_secret") or "").strip() or None,
                "root_task_key_id": str(runtime_task_keys.get("root_task_key_id") or "").strip() or None,
                "root_task_key_name": str(runtime_task_keys.get("root_task_key_name") or "").strip() or None,
                "root_task_key_prefix": str(runtime_task_keys.get("root_task_key_prefix") or "").strip() or None,
                "task_key_source": str(runtime_task_keys.get("task_key_source") or "").strip() or None,
            },
        }
        if task_type == TASK_TYPE_BINARY_MODULE:
            summary = {
                **summary,
                **self._build_binary_module_restart_summary(task, normalized_inputs),
            }
        return summary

    def _base_task_metrics(self, task: BinarySecurityTask, *, input_files: list[dict[str, Any]]) -> dict[str, Any]:
        task_type = self._task_type(task)
        total_bytes = int(sum(int(item.get("size") or 0) for item in input_files))
        return {
            "high_risk_module_count": 0,
            "medium_risk_module_count": 0,
            "low_risk_module_count": 0,
            "candidate_module_count": 1 if task_type == TASK_TYPE_BINARY_MODULE else 0,
            "selected_module_count": 1 if task_type == TASK_TYPE_BINARY_MODULE else 0,
            "entry_count": 0,
            "vuln_result_count": 0,
            "input_file_count": len(input_files),
            "uploaded_file_count": len(input_files),
            "input_total_bytes": total_bytes,
            "firmware_item_count": len(input_files),
            "unpacked_firmware_count": 0,
            "failed_firmware_count": 0,
        }

    def _delete_archive_root_path(self, task: BinarySecurityTask, archive_root: str | Path | None) -> bool:
        raw = str(archive_root or "").strip()
        if not raw:
            return False
        try:
            target = Path(raw).resolve()
            output_root = Path(str(task.output_root or "")).resolve()
            workspace_root = Path(str(task.workspace_root or "")).resolve()
        except Exception:
            return False
        if not output_root or not str(output_root).strip():
            return False
        if target == output_root:
            return False
        within_output_root = _is_within_path(output_root, target)
        within_workspace_root = bool(str(task.workspace_root or "").strip()) and _is_within_path(workspace_root, target)
        if not within_output_root and not within_workspace_root:
            return False
        if not target.exists() and not target.is_symlink():
            return False
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target, ignore_errors=True)
            else:
                target.unlink(missing_ok=True)
        except OSError as exc:
            if exc.errno != errno.ESTALE:
                raise
        return True

    def _delete_archive_roots_for_jobs(
        self,
        task: BinarySecurityTask,
        jobs: list[BinarySecurityArchiveJob],
    ) -> list[str]:
        deleted: list[str] = []
        seen: set[str] = set()
        for job in jobs:
            archive_root = str(getattr(job, "archive_root", "") or "").strip()
            if not archive_root or archive_root in seen:
                continue
            if self._delete_archive_root_path(task, archive_root):
                deleted.append(archive_root)
                seen.add(archive_root)
        return deleted

    def _archive_jobs_for_stage_items(
        self,
        db: Session,
        task_id: str,
        stage_name: str,
        item_ids: list[str],
    ) -> list[BinarySecurityArchiveJob]:
        normalized_item_ids = [str(item_id or "").strip() for item_id in item_ids if str(item_id or "").strip()]
        if not normalized_item_ids:
            return []
        jobs = (
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task_id,
                BinarySecurityArchiveJob.stage_name == stage_name,
                BinarySecurityArchiveJob.item_id.in_(normalized_item_ids),
            )
            .all()
        )
        return [job for job in jobs if job is not None]

    def _archive_jobs_for_stages(
        self,
        db: Session,
        task_id: str,
        stage_names: list[str],
    ) -> list[BinarySecurityArchiveJob]:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return []
        jobs = (
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task_id,
                BinarySecurityArchiveJob.stage_name.in_(normalized),
            )
            .all()
        )
        return [job for job in jobs if job is not None]

    def _list_artifact_page(self, root: Path, *, limit: int, offset: int) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        total = 0
        if root.exists():
            for current_root, dirnames, filenames in os.walk(root):
                dirnames.sort()
                filenames.sort()
                current_path = Path(current_root)
                for filename in filenames:
                    path = current_path / filename
                    if total >= offset and len(files) < limit:
                        files.append({"path": str(path.relative_to(root)), "size": path.stat().st_size})
                    total += 1
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(files) < total,
            "files": files,
        }

    def _reset_stage_run_for_retry(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, *, increment_retry: bool) -> None:
        stage_run.status = "pending"
        if increment_retry:
            stage_run.retry_count = int(stage_run.retry_count or 0) + 1
        stage_run.started_at = None
        stage_run.finished_at = None
        stage_run.last_error = None
        stage_run.input_snapshot = {}
        stage_run.output_summary = {}
        stage_run.counts = {}
        stage_run.downstream_refs = {}
        summary_file = self._stage_run_summary_path(task, stage_run)
        try:
            if summary_file.exists():
                summary_file.unlink()
        except Exception:
            pass

    async def _run_with_limits(
        self,
        rows: list[Any],
        worker,
        *,
        concurrency: int,
        timeout_seconds: int | float | None,
    ) -> list[tuple[Any, Any, Exception | None]]:
        if not rows:
            return []
        semaphore = asyncio.Semaphore(max(1, int(concurrency or 1)))

        async def _guarded(row: Any) -> tuple[Any, Any, Exception | None]:
            async with semaphore:
                try:
                    if timeout_seconds and timeout_seconds > 0:
                        result = await asyncio.wait_for(worker(row), timeout=float(timeout_seconds))
                    else:
                        result = await worker(row)
                    return row, result, None
                except Exception as exc:
                    return row, None, exc

        return await asyncio.gather(*(_guarded(row) for row in rows))

    async def _cancel_downstream(self, item: BinarySecurityStageItem, token: str | None) -> None:
        try:
            await self._downstream_cancel_item(item, token)
        except Exception:
            pass

    def _collect_downstream_refs(self, task: BinarySecurityTask, items: list[BinarySecurityStageItem]) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in items:
            downstream_service = str(_stage_item_attr(item, "downstream_service") or "").strip()
            downstream_task_id = str(_stage_item_attr(item, "downstream_task_id") or "").strip()
            if not downstream_service or not downstream_task_id:
                continue
            key = (downstream_service, downstream_task_id)
            if key in seen:
                continue
            seen.add(key)
            refs.append(
                {
                    "service": downstream_service,
                    "task_id": downstream_task_id,
                    "project_id": task.project_id,
                    "stage_name": _stage_item_attr(item, "stage_name"),
                }
            )
        return refs

    def _dedupe_downstream_refs(self, refs: list[dict[str, str]]) -> list[dict[str, str]]:
        unique: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for ref in refs:
            service = str(ref.get("service") or "").strip()
            task_id = str(ref.get("task_id") or "").strip()
            if not service or not task_id:
                continue
            key = (service, task_id)
            if key in seen:
                continue
            seen.add(key)
            unique.append({**ref, "service": service, "task_id": task_id})
        return unique

    def _normalize_downstream_ref_stage_name(self, ref: dict[str, Any]) -> str | None:
        stage_name = normalize_stage_name(ref.get("stage_name"))
        if stage_name:
            return stage_name
        service = str(ref.get("service") or "").strip()
        return SERVICE_STAGE_NAMES.get(service)

    def _event_item_for_downstream_ref(
        self,
        db: Session,
        task: BinarySecurityTask,
        ref: dict[str, Any],
    ) -> dict[str, Any]:
        stage_name = self._normalize_downstream_ref_stage_name(ref)
        downstream_service = str(ref.get("service") or ref.get("downstream_service") or "").strip()
        downstream_task_id = str(ref.get("task_id") or ref.get("downstream_task_id") or "").strip()
        if stage_name and downstream_service and downstream_task_id:
            for candidate in self._stage_items(db, task.id, stage_name):
                if (
                    str(candidate.downstream_service or "").strip() == downstream_service
                    and str(candidate.downstream_task_id or "").strip() == downstream_task_id
                ):
                    return {
                        "id": candidate.id,
                        "item_key": candidate.item_key,
                        "stage_name": candidate.stage_name,
                        "downstream_service": candidate.downstream_service,
                        "downstream_task_id": candidate.downstream_task_id,
                    }
        return {
            "stage_name": stage_name,
            "downstream_service": downstream_service,
            "downstream_task_id": downstream_task_id,
        }

    def _retry_downstream_refs_for_stages(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_names: list[str],
    ) -> list[dict[str, str]]:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return []
        refs = self._downstream_refs_for_stages(db, task, normalized)
        return self._dedupe_downstream_refs(refs)

    def _discover_parent_linked_downstream_refs(self, db: Session, task: BinarySecurityTask) -> list[dict[str, str]]:
        del db, task
        return []

    def _retry_cleanup_refs_for_hard_restart(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_names: list[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        direct_refs = self._downstream_refs_for_stages(db, task, normalized)
        return self._dedupe_downstream_refs(direct_refs), [], []

    def _verify_remaining_parent_linked_downstream_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        attempted_refs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        del db, task, attempted_refs
        return []

    def _downstream_refs_for_stages(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_names: list[str],
    ) -> list[dict[str, str]]:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return []
        rows = db.query(
            BinarySecurityStageItem.stage_name,
            BinarySecurityStageItem.downstream_service,
            BinarySecurityStageItem.downstream_task_id,
        ).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.stage_name.in_(normalized),
        ).all()
        snapshot_items = [
            {
                "stage_name": row[0],
                "downstream_service": row[1],
                "downstream_task_id": row[2],
            }
            for row in rows
        ]
        return self._collect_downstream_refs(task, snapshot_items)

    async def _cancel_local_worker(self, task_id: str) -> None:
        async with self._worker_lock:
            handle = self._workers.get(task_id)
        if handle and not handle.done():
            handle.cancel()
            tasks = [handle.runner_task]
            if handle.heartbeat_task is not None:
                tasks.append(handle.heartbeat_task)
            if handle.sync_maintenance_task is not None:
                tasks.append(handle.sync_maintenance_task)
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _cancel_downstream_refs(self, db: Session, task: BinarySecurityTask, refs: list[dict[str, str]], token: str | None) -> int:
        return await self._downstream_cancel_refs(db, task, refs, token)

    async def _fetch_downstream_ref_payload(self, ref: dict[str, str], token: str | None) -> dict[str, Any]:
        return await self._downstream_fetch_ref_payload(ref, token)

    async def _wait_downstream_ref_inactive(
        self,
        db: Session,
        task: BinarySecurityTask,
        ref: dict[str, str],
        token: str | None,
    ) -> None:
        del db, task
        # Downstream services commonly reject deletion for active work. After a
        # retry/cancel request, always wait until the old child is inactive
        # before deleting local references and creating a replacement. Otherwise
        # stale children can keep consuming downstream concurrency while the
        # parent stage has already moved to a new retry attempt.
        service = str(ref.get("service") or "").strip()
        if not service:
            return
        timeout_seconds = max(
            int(self.cfg.scheduler.downstream_request_timeout_seconds or 120),
            int(self.cfg.scheduler.stage_poll_interval_seconds or 5) * 2,
        )
        deadline = _now() + timedelta(seconds=timeout_seconds)
        while _now() <= deadline:
            try:
                payload = await self._fetch_downstream_ref_payload(ref, token)
            except NotFoundError:
                return
            mapped_status = self._map_downstream_status(str(payload.get("status") or "")) or str(payload.get("status") or "").lower()
            if mapped_status not in {"queued", "running", "dispatching", "pending"}:
                return
            await asyncio.sleep(max(1, int(self.cfg.scheduler.stage_poll_interval_seconds or 5)))
        raise ValidationError(f"旧下游任务仍在运行，不能安全继续: {ref.get('service')}:{ref.get('task_id')}")

    async def _ensure_downstream_refs_inactive(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
    ) -> None:
        normalized_refs = [dict(ref) for ref in list(refs or []) if isinstance(ref, dict)]
        operation_id = str(getattr(task, "current_operation_id", "") or "").strip() or None
        for ref in normalized_refs:
            event_item = self._event_item_for_downstream_ref(db, task, ref)
            self._record_event(
                db,
                task,
                "child_task_inactive_check_requested",
                f"检查下游任务是否已静止: {ref.get('service')}:{ref.get('task_id')}",
                stage_name=ref.get("stage_name"),
                item=event_item,
                payload={**ref, "operation": "inactive_check", "cleanup_phase": "inactive_check"},
                operation_id=operation_id,
            )
        try:
            await self._downstream_ensure_refs_inactive(normalized_refs, token)
        except Exception as exc:
            for ref in normalized_refs:
                event_item = self._event_item_for_downstream_ref(db, task, ref)
                self._record_event(
                    db,
                    task,
                    "child_task_inactive_check_blocked",
                    f"下游任务仍未静止: {ref.get('service')}:{ref.get('task_id')} - {str(exc)}",
                    stage_name=ref.get("stage_name"),
                    item=event_item,
                    level="warning",
                    payload={
                        **ref,
                        "operation": "inactive_check",
                        "cleanup_phase": "inactive_check",
                        "result": "blocked",
                        "error": str(exc),
                    },
                    operation_id=operation_id,
                )
            raise
        for ref in normalized_refs:
            event_item = self._event_item_for_downstream_ref(db, task, ref)
            self._record_event(
                db,
                task,
                "child_task_inactive_check_succeeded",
                f"下游任务已静止，可继续清理: {ref.get('service')}:{ref.get('task_id')}",
                stage_name=ref.get("stage_name"),
                item=event_item,
                payload={
                    **ref,
                    "operation": "inactive_check",
                    "cleanup_phase": "inactive_check",
                    "result": "succeeded",
                },
                operation_id=operation_id,
            )

    async def _delete_downstream_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        refs: list[dict[str, str]],
        token: str | None,
        *,
        force_delete: bool = False,
        best_effort: bool = False,
        cleanup_scope: str = "retry_prepare",
    ) -> int:
        return await self._downstream_delete_refs(
            db,
            task,
            refs,
            token,
            force_delete=force_delete,
            best_effort=best_effort,
            cleanup_scope=cleanup_scope,
        )

    async def _drain_owner_inbox_during_polling(self, task: BinarySecurityTask) -> None:
        operation_passes = 0
        while await self._run_current_task_operation(task.id):
            operation_passes += 1
        if operation_passes <= 0:
            return
        if await self._is_task_cancelled_async(task.id):
            return
        await self._ensure_task_execution_current_async(task)

    async def _poll_until_terminal(self, fetcher, *, success_statuses: set[str], failure_statuses: set[str], task: BinarySecurityTask, item: BinarySecurityStageItem | None = None):
        poll_started_at = _now()
        last_wait_log_at: datetime | None = None
        poll_count = 0
        while True:
            try:
                await self._ensure_task_execution_current_async(task)
                await self._drain_owner_inbox_during_polling(task)
                payload = await fetcher()
                await self._ensure_task_execution_current_async(task)
                poll_count += 1
                status = str(payload.get("status") or "").lower()
                if status in success_statuses:
                    return "success", payload
                if status in failure_statuses:
                    mapped_status = self._map_downstream_status(status)
                    if mapped_status == "cancelled":
                        return "cancelled", payload
                    if mapped_status == "downstream_missing":
                        return "downstream_missing", payload
                    return "failed", payload
                if item is not None:
                    await asyncio.to_thread(
                        self._refresh_polled_child_sync_snapshot,
                        task_id=task.id,
                        item_id=item.id,
                        payload=dict(payload),
                    )
                now_value = _now()
                should_log_wait = (
                    last_wait_log_at is None
                    or (now_value - last_wait_log_at).total_seconds() >= max(30, min(60, self._downstream_child_sync_interval_seconds()))
                )
                if should_log_wait:
                    logger.info(
                        "binary-security downstream poll waiting: task_id=%s stage=%s item_id=%s item_key=%s downstream_task_id=%s downstream_status=%s poll_count=%s waited_seconds=%s",
                        task.id,
                        str(getattr(item, "stage_name", "") or getattr(task, "current_stage", "") or "").strip() or None,
                        str(getattr(item, "id", "") or "").strip() or None,
                        str(getattr(item, "item_key", "") or "").strip() or None,
                        str(
                            payload.get("task_id")
                            or payload.get("id")
                            or getattr(item, "downstream_task_id", None)
                            or ""
                        ).strip()
                        or None,
                        status or None,
                        poll_count,
                        max(0, int((now_value - poll_started_at).total_seconds())),
                    )
                    last_wait_log_at = now_value
                if await self._is_task_cancelled_async(task.id):
                    if item and item.downstream_task_id:
                        await self._cancel_downstream(item, self._service_token())
                    return "cancelled", payload
                await asyncio.sleep(self._downstream_child_sync_interval_seconds())
            except StaleTaskExecution:
                raise
            except NotFoundError:
                return "downstream_missing", {"status": "downstream_missing", "error": "下游子任务不存在"}
            except Exception as exc:
                if self._is_owned_execution_stale_error(
                    error_message=str(exc),
                    error_type=getattr(type(exc), "__name__", None),
                ):
                    raise StaleTaskExecution(str(exc)) from exc
                if item is not None:
                    await asyncio.to_thread(
                        self._record_polled_child_sync_failure,
                        task_id=task.id,
                        item_id=item.id,
                        error_message=str(exc),
                        error_type=self._classify_downstream_sync_error(exc),
                        http_status=self._extract_http_status_from_exception(exc),
                    )
                await asyncio.sleep(self._stage_downstream_sync_backoff_base_seconds())

    def _is_task_cancelled(self, task_id: str) -> bool:
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask.status).filter(BinarySecurityTask.id == task_id).first()
            return row is None or bool(row and row[0] == "cancelled")
        finally:
            session.close()

    async def _is_task_cancelled_async(self, task_id: str) -> bool:
        return await asyncio.to_thread(self._is_task_cancelled, task_id)

    async def _stage_firmware_unpack(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        input_files = [dict(item) for item in (task.summary.get("input_files") or [])]
        if not input_files:
            return "failed", {"error": "缺少输入文件"}
        summary_changed = False
        for input_file in input_files:
            firmware_key = str(input_file.get("firmware_key") or "").strip()
            if firmware_key:
                continue
            filename = str(input_file.get("filename") or input_file.get("relative_path") or "").strip()
            input_file["firmware_key"] = _slug(Path(filename).stem or filename)
            summary_changed = True
        if summary_changed:
            task.summary = {
                **task.summary,
                "input_files": input_files,
            }
            db.commit()
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=input_files,
            downstream_service="firmware_unpacker",
            identity=lambda input_file: (
                input_file["firmware_key"],
                input_file["filename"],
                input_file["firmware_key"],
                {
                    "filename": input_file["filename"],
                    "path": str(input_file.get("path") or Path(task.workspace_root) / "input" / input_file["filename"]),
                },
            ),
            output_ref=lambda input_file: {
                "downstream_service": "firmware_unpacker",
            },
        )
        if executable_inputs is None:
            executable_inputs = input_files
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda input_file, retrying=False, auto_retrying=False: self._run_firmware_item(
                task, stage_run, input_file, token, retrying, auto_retrying
            ),
            retries=self._max_retries_per_item(task),
            initial_retry=retry_existing,
        )
        status, summary = self._aggregate_stage_items(db, task, results, "firmware_unpack_results")
        return status, summary

    async def _stage_system_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        del token
        system_inputs = self._system_analysis_inputs(task, db=db)
        if not system_inputs:
            return "failed", {"error": "缺少可用于系统分析的输入"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=system_inputs,
            downstream_service="system_analyse",
            identity=lambda analysis_input: (
                analysis_input["firmware_key"],
                analysis_input.get("firmware_name") or analysis_input["firmware_key"],
                analysis_input["firmware_key"],
                analysis_input,
            ),
            output_ref=lambda _analysis_input: {},
        )
        if executable_inputs is None:
            executable_inputs = system_inputs
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda analysis_input, retrying=False, auto_retrying=False: self._run_system_analysis_item(
                task, stage_run, analysis_input, retrying, auto_retrying
            ),
            retries=self._max_retries_per_item(task),
            initial_retry=retry_existing,
        )
        status, aggregate_summary = self._aggregate_stage_items(db, task, results, "system_analysis_results")
        success = [result["item"] for result in results if result.get("status") == "success"]
        archive_blocked = [result for result in results if result.get("status") == "archive_blocked" or result.get("archive_blocked")]
        failed_like = [
            result for result in results
            if result.get("status") in {"failed", "downstream_missing"}
        ]
        all_modules: list[dict[str, Any]] = []
        for result in success:
            all_modules.extend(result.get("modules", []))
        task.summary = {
            **self._clear_failure_fields_from_summary(task.summary),
            "system_analysis_results": self._lightweight_system_analysis_items(success),
            "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
            "system_analysis_module_count": len(all_modules),
        }
        self._rebuild_system_analysis_module_selection_from_summary(task)
        self._clear_entry_result_state(task)
        task.last_error = None
        db.commit()
        return status, {
            "items": self._lightweight_system_analysis_items(success),
            "failed_items": aggregate_summary.get("failed_items", []),
            "cancelled_items": aggregate_summary.get("cancelled_items", []),
            "success_count": len(success),
            "failed_count": int(aggregate_summary.get("failed_count") or 0),
            "cancelled_count": int(aggregate_summary.get("cancelled_count") or 0),
            "running_count": int(aggregate_summary.get("running_count") or 0),
            "pending_count": int(aggregate_summary.get("pending_count") or 0),
            "downstream_missing_count": int(aggregate_summary.get("downstream_missing_count") or 0),
            "module_count": len(all_modules),
            "high_risk_module_count": int((task.metrics or {}).get("high_risk_module_count") or 0),
            "medium_risk_module_count": int((task.metrics or {}).get("medium_risk_module_count") or 0),
            "low_risk_module_count": int((task.metrics or {}).get("low_risk_module_count") or 0),
            "candidate_module_count": int((task.metrics or {}).get("candidate_module_count") or 0),
            "selected_module_count": int((task.metrics or {}).get("selected_module_count") or 0),
            "requires_confirmation": False,
            "items_truncated": bool(aggregate_summary.get("items_truncated")),
            "failed_items_truncated": bool(aggregate_summary.get("failed_items_truncated")),
            "cancelled_items_truncated": bool(aggregate_summary.get("cancelled_items_truncated")),
            "archive_blocked": bool(aggregate_summary.get("archive_blocked")) or bool(archive_blocked),
            "error": aggregate_summary.get("error"),
        }

    async def _stage_binary_to_source(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        modules = list(task.summary.get("selected_modules") or [])
        if not modules:
            return "failed", {"error": "缺少已选模块列表"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=modules,
            downstream_service="binary_to_source",
            identity=lambda module: (
                module["module_key"],
                module["module_name"],
                module.get("firmware_key"),
                module,
            ),
            output_ref=lambda _module: {},
        )
        if executable_inputs is None:
            executable_inputs = modules
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module, retrying=False, auto_retrying=False: self._run_b2s_item(
                task, stage_run, module, token, retrying, auto_retrying
            ),
            retries=self._max_retries_per_item(task),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "b2s_results")

    async def _stage_entry_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        self._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=stage_run)
        b2s_success = self._entry_analysis_inputs(db, task)
        if not b2s_success:
            # SOURCE 任务就绪门控：system_analysis 未就绪→阻塞等待（不 fail）；就绪但 0 模块→成功收口
            if self._task_type(task) == TASK_TYPE_SOURCE:
                if not self._system_analysis_authoritative_complete(db, task):
                    return "pending", {"reason": "system_analysis 尚未就绪，入口分析暂不执行，等待上游归档"}
                return "success", {"reason": "system_analysis 已就绪但无入口模块，入口分析直接成功收口"}
            # BINARY / BINARY_MODULE 任务就绪门控：binary_to_source 未就绪→阻塞等待（不 fail）
            if self._task_type(task) in {TASK_TYPE_BINARY, TASK_TYPE_BINARY_MODULE}:
                if not self._binary_to_source_authoritative_complete(db, task):
                    return "pending", {"reason": "binary_to_source 尚未就绪，入口分析暂不执行，等待上游归档"}
            return "failed", {"error": self._missing_entry_analysis_input_reason(db, task)}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=b2s_success,
            downstream_service="entry_analyse",
            identity=lambda module: (
                module["module_key"],
                module["module_name"],
                module.get("firmware_key"),
                module,
            ),
            output_ref=lambda _module: {},
        )
        if executable_inputs is None:
            executable_inputs = b2s_success
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module, retrying=False, auto_retrying=False: self._run_entry_item(
                task, stage_run, module, token, retrying, auto_retrying
            ),
            retries=self._max_retries_per_item(task),
            initial_retry=retry_existing,
        )
        status, summary = self._aggregate_stage_items(db, task, results, "entry_results")
        entry_results = self._rebuild_entry_result_modules_from_stage_items(db, task, stage_run)
        summary = {
            **summary,
            "entry_results": entry_results,
            "candidate_entry_count": int((task.metrics or {}).get("candidate_entry_count") or 0),
            "selected_entry_count": int((task.metrics or {}).get("selected_entry_count") or 0),
            "entry_count": int((task.metrics or {}).get("entry_count") or 0),
            **self._entry_selection_metrics(task, db),
        }
        return status, summary

    async def _stage_knowledge_graph_entry_fetch(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        del token, retry_existing
        upload_id, db_name = self._knowledge_graph_locator(task)
        entries_url = self._knowledge_graph_source_endpoint(upload_id=upload_id, db_name=db_name)
        max_attempts = self._knowledge_graph_entry_fetch_max_attempts()
        retry_interval_seconds = self._knowledge_graph_entry_fetch_retry_interval_seconds()
        self._record_event(
            db,
            task,
            "knowledge_graph_entry_fetch_started",
            "开始拉取知识图谱源码入口",
            stage_name=stage_run.stage_name,
            payload={
                "provider": "knowledge_graph_audit_sources",
                "entries_url": entries_url,
                "lookup_mode": "upload_id" if upload_id else "db_name",
                "upload_id": upload_id,
                "db_name": db_name,
            },
        )
        attempt = 0
        entries: list[dict[str, Any]] = []
        meta: dict[str, Any] = {}
        previous_entries = self._knowledge_graph_entry_results(task)
        try:
            while True:
                attempt += 1
                entries, meta = await self._fetch_knowledge_graph_entry_results(task)
                if entries or previous_entries or attempt >= max_attempts:
                    break
                graph_status = str(meta.get("graph_status") or "").strip().lower()
                if graph_status == "superseded":
                    break
                self._record_event(
                    db,
                    task,
                    "knowledge_graph_entry_fetch_retry_scheduled",
                    "知识图谱入口暂未就绪，等待后重试拉取",
                    stage_name=stage_run.stage_name,
                    payload={
                        "provider": "knowledge_graph_audit_sources",
                        "entries_url": entries_url,
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "retry_interval_seconds": retry_interval_seconds,
                        **meta,
                    },
                )
                if retry_interval_seconds > 0:
                    await asyncio.sleep(retry_interval_seconds)
        except Exception as exc:
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_fetch_failed",
                "知识图谱入口获取失败",
                level="error",
                stage_name=stage_run.stage_name,
                payload={
                    "provider": "knowledge_graph_audit_sources",
                    "entries_url": entries_url,
                    "raw_entry_count": 0,
                    "selected_entry_count": 0,
                    "filtered_out_count": 0,
                    "duration_ms": 0,
                    "error_message": str(exc),
                    "attempt": attempt or 1,
                    "max_attempts": max_attempts,
                },
            )
            failed_module = self._build_knowledge_graph_entry_result_module(
                task,
                entries=[],
                completion_state="failed",
                completion_ready=True,
                error_message=str(exc),
            )
            task.summary = {
                **(task.summary or {}),
                "knowledge_graph_entry_results": [],
                "entry_results": [failed_module],
                "knowledge_graph_state": {},
            }
            task.metrics = {
                **(task.metrics or {}),
                **STAGE_METRIC_RESETTERS["knowledge_graph_entry_fetch"],
                **self._entry_selection_metrics(task),
            }
            failure_summary = {
                "error": str(exc),
                "items": [],
                "success_count": 0,
                "failed_count": 1,
                "candidate_entry_count": 0,
                "selected_entry_count": 0,
                "entry_count": 0,
                "knowledge_graph_raw_entry_count": 0,
                "knowledge_graph_selected_entry_count": 0,
                "knowledge_graph_filtered_out_count": 0,
                "entries_url": entries_url,
                "duration_ms": 0,
                "attempt": attempt or 1,
                "max_attempts": max_attempts,
            }
            self._persist_stage_run_output_summary(task, stage_run, failure_summary)
            return "failed", failure_summary
        graph_status = str(meta.get("graph_status") or "").strip()
        identification_state = str(meta.get("identification_state") or "").strip()
        accumulated_entries = self._merge_knowledge_graph_entry_results(task, entries)
        accumulated_selected_entry_count = len(accumulated_entries)
        executable_entries = self._filter_executable_knowledge_graph_entries(accumulated_entries)
        executable_compact_entries = self._compact_knowledge_graph_entry_results(executable_entries)
        executable_entry_count = len(executable_entries)
        current_poll_selected_entry_count = len(entries)
        state_summary = self._knowledge_graph_poll_state_summary(
            meta,
            accumulated_selected_entry_count=accumulated_selected_entry_count,
        )
        execution_metrics = self._knowledge_graph_entry_execution_metrics(accumulated_entries)
        success_module = self._build_knowledge_graph_entry_result_module(
            task,
            entries=executable_entries,
            completion_state="success",
            completion_ready=True,
        )
        pending_module = self._build_knowledge_graph_entry_result_module(
            task,
            entries=executable_entries,
            completion_state="success",
            completion_ready=False,
        )
        if (graph_status == "failed" or identification_state == "failed" or graph_status == "superseded") and not accumulated_entries:
            reason = "知识图谱入口识别失败"
            if graph_status == "superseded":
                reason = "知识图谱图谱已被替换，当前结果不可用"
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_fetch_failed",
                reason,
                level="error",
                stage_name=stage_run.stage_name,
                payload={
                    "provider": "knowledge_graph_audit_sources",
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    **meta,
                },
            )
            failed_module = self._build_knowledge_graph_entry_result_module(
                task,
                entries=[],
                completion_state="failed",
                completion_ready=True,
                error_message=reason,
            )
            task.summary = {
                **(task.summary or {}),
                "knowledge_graph_entry_results": accumulated_entries,
                "entry_results": [failed_module],
                "knowledge_graph_state": state_summary,
            }
            task.metrics = {
                **(task.metrics or {}),
                **STAGE_METRIC_RESETTERS["knowledge_graph_entry_fetch"],
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                "candidate_entry_count": executable_entry_count,
                "selected_entry_count": executable_entry_count,
                "entry_count": executable_entry_count,
                **execution_metrics,
                **self._knowledge_graph_analysis_metrics(meta),
                **self._entry_selection_metrics(task),
            }
            failure_summary = {
                "error": reason,
                "items": [failed_module],
                "success_count": 0,
                "failed_count": 1,
                "candidate_entry_count": executable_entry_count,
                "selected_entry_count": executable_entry_count,
                "entry_count": executable_entry_count,
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                **execution_metrics,
                "current_poll_selected_entry_count": current_poll_selected_entry_count,
                "accumulated_selected_entry_count": accumulated_selected_entry_count,
                "attempt": attempt,
                "max_attempts": max_attempts,
                **state_summary,
                **meta,
            }
            self._persist_stage_run_output_summary(task, stage_run, failure_summary)
            return "failed", failure_summary
        if identification_state != "done" and graph_status == "building" and not accumulated_entries:
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_fetch_waiting_for_graph",
                "知识图谱图谱仍在构建，等待入口结果就绪",
                stage_name=stage_run.stage_name,
                payload={
                    "provider": "knowledge_graph_audit_sources",
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    **meta,
                },
            )
            task.summary = {
                **(task.summary or {}),
                "knowledge_graph_entry_results": accumulated_entries,
                "entry_results": [pending_module],
                "knowledge_graph_state": state_summary,
            }
            task.metrics = {
                **(task.metrics or {}),
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                "candidate_entry_count": executable_entry_count,
                "selected_entry_count": executable_entry_count,
                "entry_count": executable_entry_count,
                **execution_metrics,
                **self._knowledge_graph_analysis_metrics(meta),
                **self._entry_selection_metrics(task),
            }
            waiting_summary = {
                "status": "waiting_for_graph",
                "items": [pending_module],
                "success_count": 0,
                "failed_count": 0,
                "candidate_entry_count": executable_entry_count,
                "selected_entry_count": executable_entry_count,
                "entry_count": executable_entry_count,
                **execution_metrics,
                "current_poll_selected_entry_count": current_poll_selected_entry_count,
                "accumulated_selected_entry_count": accumulated_selected_entry_count,
                "attempt": attempt,
                "max_attempts": max_attempts,
                **state_summary,
                **meta,
            }
            self._persist_stage_run_output_summary(task, stage_run, waiting_summary)
            return "running", waiting_summary
        if identification_state != "done" and not accumulated_entries:
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_fetch_waiting_for_identification",
                "知识图谱入口识别仍在进行，等待入口结果就绪",
                stage_name=stage_run.stage_name,
                payload={
                    "provider": "knowledge_graph_audit_sources",
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    **meta,
                },
            )
            task.summary = {
                **(task.summary or {}),
                "knowledge_graph_entry_results": accumulated_entries,
                "entry_results": [pending_module],
                "knowledge_graph_state": state_summary,
            }
            task.metrics = {
                **(task.metrics or {}),
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                "candidate_entry_count": executable_entry_count,
                "selected_entry_count": executable_entry_count,
                "entry_count": executable_entry_count,
                **execution_metrics,
                **self._knowledge_graph_analysis_metrics(meta),
                **self._entry_selection_metrics(task),
            }
            waiting_summary = {
                "status": "waiting_for_identification",
                "items": [pending_module],
                "success_count": 0,
                "failed_count": 0,
                "candidate_entry_count": executable_entry_count,
                "selected_entry_count": executable_entry_count,
                "entry_count": executable_entry_count,
                **execution_metrics,
                "current_poll_selected_entry_count": current_poll_selected_entry_count,
                "accumulated_selected_entry_count": accumulated_selected_entry_count,
                "attempt": attempt,
                "max_attempts": max_attempts,
                **state_summary,
                **meta,
            }
            self._persist_stage_run_output_summary(task, stage_run, waiting_summary)
            return "running", waiting_summary
        if not accumulated_entries or not executable_entries:
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                self._record_event(
                    db,
                    task,
                    "knowledge_graph_entry_dispatch_skipped",
                    "知识图谱入口文件不存在，跳过数据流任务创建",
                    stage_name=stage_run.stage_name,
                    payload={
                        "source_id": str(entry.get("source_id") or entry.get("entry_key") or "").strip() or None,
                        "function_id": str(entry.get("function_id") or "").strip() or None,
                        "function_name": str(entry.get("function_name") or "").strip() or None,
                        "source_file": str(entry.get("source_file") or "").strip() or None,
                        "start_line": str(entry.get("definition_line") or entry.get("line_no") or "").strip() or None,
                        "source_file_exists": bool(entry.get("source_file_exists")),
                        "entry_execution_status": str(entry.get("entry_execution_status") or "").strip() or None,
                        "entry_execution_reason": str(entry.get("entry_execution_reason") or "").strip() or None,
                    },
                )
            error_message = "知识图谱入口识别完成，但没有可访问的源码入口文件" if accumulated_entries else "知识图谱入口识别完成，但没有可用入口"
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_fetch_empty_after_done",
                error_message,
                level="warning",
                stage_name=stage_run.stage_name,
                payload={
                    "provider": "knowledge_graph_audit_sources",
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    **meta,
                },
            )
            failed_module = self._build_knowledge_graph_entry_result_module(
                task,
                entries=[],
                completion_state="failed",
                completion_ready=True,
                error_message=error_message,
            )
            task.summary = {
                **(task.summary or {}),
                "knowledge_graph_entry_results": accumulated_entries,
                "entry_results": [failed_module],
                "knowledge_graph_state": state_summary,
            }
            task.metrics = {
                **(task.metrics or {}),
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                **execution_metrics,
                "candidate_entry_count": 0,
                "selected_entry_count": 0,
                "entry_count": 0,
                **self._knowledge_graph_analysis_metrics(meta),
                **self._entry_selection_metrics(task),
            }
            failure_summary = {
                "error": error_message,
                "items": [failed_module],
                "success_count": 0,
                "failed_count": 1,
                "candidate_entry_count": 0,
                "selected_entry_count": 0,
                "entry_count": 0,
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                **execution_metrics,
                "attempt": attempt,
                "max_attempts": max_attempts,
                **state_summary,
                **meta,
            }
            self._persist_stage_run_output_summary(task, stage_run, failure_summary)
            return "failed", failure_summary
        task.summary = {
            **(task.summary or {}),
            "knowledge_graph_entry_results": accumulated_entries,
            "entry_results": [success_module],
            "knowledge_graph_state": state_summary,
        }
        task.metrics = {
            **(task.metrics or {}),
            "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
            "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
            "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
            "candidate_entry_count": executable_entry_count,
            "selected_entry_count": executable_entry_count,
            "entry_count": executable_entry_count,
            **execution_metrics,
            **self._knowledge_graph_analysis_metrics(meta),
            **self._entry_selection_metrics(task),
        }
        self._record_event(
            db,
            task,
            "knowledge_graph_entry_fetch_succeeded",
            "知识图谱入口获取成功",
            stage_name=stage_run.stage_name,
            payload={
                "provider": "knowledge_graph_audit_sources",
                "current_poll_selected_entry_count": current_poll_selected_entry_count,
                "accumulated_selected_entry_count": accumulated_selected_entry_count,
                "knowledge_graph_executable_entry_count": executable_entry_count,
                "attempt": attempt,
                "max_attempts": max_attempts,
                **meta,
            },
        )
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            event_type = "knowledge_graph_entry_dispatch_ready" if bool(entry.get("source_file_exists")) else "knowledge_graph_entry_dispatch_skipped"
            message = "知识图谱入口文件可访问，准备创建数据流任务" if bool(entry.get("source_file_exists")) else "知识图谱入口文件不存在，跳过数据流任务创建"
            self._record_event(
                db,
                task,
                event_type,
                message,
                stage_name=stage_run.stage_name,
                payload={
                    "source_id": str(entry.get("source_id") or entry.get("entry_key") or "").strip() or None,
                    "function_id": str(entry.get("function_id") or "").strip() or None,
                    "function_name": str(entry.get("function_name") or "").strip() or None,
                    "source_file": str(entry.get("source_file") or "").strip() or None,
                    "start_line": str(entry.get("definition_line") or entry.get("line_no") or "").strip() or None,
                    "source_file_exists": bool(entry.get("source_file_exists")),
                    "entry_execution_status": str(entry.get("entry_execution_status") or "").strip() or None,
                    "entry_execution_reason": str(entry.get("entry_execution_reason") or "").strip() or None,
                },
            )
        success_summary = {
            "items": [success_module],
            "success_count": executable_entry_count,
            "failed_count": 0,
            "candidate_entry_count": executable_entry_count,
            "selected_entry_count": executable_entry_count,
            "entry_count": executable_entry_count,
            "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
            "knowledge_graph_selected_entry_count": accumulated_selected_entry_count,
            "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
            **execution_metrics,
            "current_poll_selected_entry_count": current_poll_selected_entry_count,
            "accumulated_selected_entry_count": accumulated_selected_entry_count,
            "entry_results": [success_module],
            "attempt": attempt,
            "max_attempts": max_attempts,
            **state_summary,
            **meta,
        }
        self._persist_stage_run_output_summary(task, stage_run, success_summary)
        return "success", success_summary

    async def _stage_dataflow_vuln_scan(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        if not self._entry_analysis_authoritative_items_ready(db, task):
            rebuild_state = self._entry_analysis_authoritative_rebuild_required(db, task)
            self._mark_entry_analysis_authoritative_rebuild_summary(task, rebuild_state)
            self._record_event(
                db,
                task,
                "dataflow_activation_blocked_until_entry_analysis_materialized",
                "入口分析 authoritative item 尚未 materialize，阻止提前进入数据流漏洞挖掘阶段",
                stage_name=stage_run.stage_name,
                level="warning",
                payload=dict(rebuild_state),
            )
            blocked_summary = {
                "status": "blocked_until_entry_analysis_materialized",
                "items": [],
                "success_count": 0,
                "failed_count": 0,
                "candidate_entry_count": 0,
                "selected_entry_count": 0,
                "entry_count": 0,
                **dict(rebuild_state),
            }
            self._persist_stage_run_output_summary(task, stage_run, blocked_summary)
            return "pending", blocked_summary
        flow_inputs = self._effective_entry_inputs(task, db)
        if not flow_inputs:
            self._rebuild_entry_results_from_stage_items(db, task)
            flow_inputs = self._effective_entry_inputs(task, db)
        entries = _deduplicate_entry_keys(flow_inputs)
        if not entries:
            module_state = self._entry_module_completion_state(task, db)
            if not bool(module_state.get("complete")):
                payload = {
                    "expected_entry_module_count": int(module_state.get("expected_module_count") or 0),
                    "materialized_entry_module_count": int(module_state.get("materialized_module_count") or 0),
                    "missing_module_keys": list(module_state.get("missing_module_keys") or []),
                }
                self._record_event(
                    db,
                    task,
                    "dataflow_waiting_for_entry_modules_complete",
                    "入口模块尚未收敛完成，等待更多模块结果",
                    stage_name=stage_run.stage_name,
                    payload=payload,
                )
                waiting_summary = {
                    "status": "waiting_for_entry_modules_complete",
                    "items": [],
                    "success_count": 0,
                    "failed_count": 0,
                    "candidate_entry_count": 0,
                    "selected_entry_count": 0,
                    "entry_count": 0,
                    **payload,
                }
                self._persist_stage_run_output_summary(task, stage_run, waiting_summary)
                return "running", waiting_summary
            return "success", {"reason": "入口模块已收敛但无可用于数据流漏洞挖掘的入口，直接成功收口"}
        executable_inputs = self._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=stage_run,
            inputs=entries,
            downstream_service="dataflow_vuln_scan",
            identity=lambda entry: (
                entry["entry_key"],
                entry["function_name"],
                entry.get("module_key"),
                entry,
            ),
            output_ref=lambda _entry: {},
        )
        if executable_inputs is None:
            executable_inputs = entries
        results = await self._run_stage_pool(
            task,
            executable_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda entry, retrying=False, auto_retrying=False: self._run_dataflow_item(
                task, stage_run, entry, token, retrying, auto_retrying
            ),
            retries=self._max_retries_per_item(task),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "dataflow_results")

    async def _run_stage_executor(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        *,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        stage_name = normalize_stage_name(stage_run.stage_name)
        if stage_name == "knowledge_graph_entry_fetch":
            return await self._stage_knowledge_graph_entry_fetch(db, task, stage_run, token, retry_existing)
        if stage_name == "firmware_unpack":
            return await self._stage_firmware_unpack(db, task, stage_run, token, retry_existing)
        if stage_name == "system_analysis":
            return await self._stage_system_analysis(db, task, stage_run, token, retry_existing)
        if stage_name == "binary_to_source":
            return await self._stage_binary_to_source(db, task, stage_run, token, retry_existing)
        if stage_name == "entry_analysis":
            return await self._stage_entry_analysis(db, task, stage_run, token, retry_existing)
        if stage_name == "dataflow_vuln_scan":
            return await self._stage_dataflow_vuln_scan(db, task, stage_run, token, retry_existing)
        raise ValidationError(f"不支持的阶段: {stage_name}")

    async def _stage_dataflow_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        return await self._stage_dataflow_vuln_scan(
            db,
            task,
            stage_run,
            token,
            retry_existing,
        )

    def _retry_recreate_payload_for_item(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> tuple[str, str | None, dict[str, Any]]:
        input_ref = dict(item.input_ref or {})
        service = str(item.downstream_service or "").strip()
        token: str | None = self._service_token()
        if service == "firmware_unpacker":
            input_path = str(input_ref.get("path") or "").strip()
            if not input_path:
                raise ValidationError("firmware_unpack retry 缺少输入路径")
            return service, token, {
                "firmware_path": input_path,
                "origin": _downstream_origin_payload(task, item),
            }
        if service == "system_analyse":
            input_path = str(input_ref.get("input_path") or "").strip()
            firmware_name = str(item.item_name or input_ref.get("firmware_key") or "firmware").strip()
            if not input_path:
                raise ValidationError("system_analysis retry 缺少 input_path")
            return service, None, {
                "task_name": f"{task.name}-{firmware_name}-system-analysis",
                "input_path": input_path,
                "origin": _downstream_origin_payload(task, item),
                "analysis_mode": self._task_type(task),
            }
        if service == "binary_to_source":
            elf_tasks = self._build_module_elf_tasks(input_ref)
            b2s_mode, b2s_engine = self._b2s_execution_mode(task)
            return service, token, {
                "name": f"{task.name}-{input_ref['module_name']}",
                "elf_tasks": elf_tasks,
                "origin": _downstream_origin_payload(task, item),
                "mode": b2s_mode,
                "engine": b2s_engine,
            }
        if service == "entry_analyse":
            entry_input = self._normalize_entry_analysis_module_input(task, input_ref)
            input_contract = self._build_entry_analysis_input_contract(entry_input)
            return service, token, {
                "task_name": f"{task.name}-{entry_input['module_name']}-entry",
                "input_path": input_contract["module_dir"],
                "module_name": entry_input["module_name"],
                "source_path": input_contract["source_root"],
                "origin": {
                    **_downstream_origin_payload(task, item),
                    "input_contract": input_contract,
                    "entry_descriptor_root": entry_input.get("entry_descriptor_root"),
                    "entry_files_list": entry_input.get("entry_files_list"),
                },
            }
        if service == "dataflow_analyse":
            raise ValidationError("历史下游服务 dataflow_analyse 已移除，请使用 dataflow_vuln_scan")
        if service == "dataflow_vuln_scan":
            entry_result = self._normalize_entry_analysis_module_input(task, input_ref)
            entry_input_contract = self._build_entry_analysis_input_contract(entry_result)
            source_dir = str(entry_input_contract.get("source_root") or entry_result.get("source_dir") or "").strip()
            dataflow_input_dir = str(entry_input_contract.get("module_dir") or entry_input_contract.get("source_root") or "").strip()
            if not dataflow_input_dir or not source_dir:
                raise ValidationError("dataflow_vuln_scan retry 缺少 entry/source 输入")
            return service, token, {
                "title": f"{task.name}-{str(entry_result.get('function_name') or item.item_name or 'entry').strip()}-scan",
                "data_flow_path": dataflow_input_dir,
                "source_dir": source_dir,
                "origin": _downstream_origin_payload(task, item),
            }
        raise ValidationError(f"不支持的 retry downstream service: {service or '-'}")

    def _resolve_dataflow_directory(self, root: Path) -> Path | None:
        if not root.exists():
            return None
        direct = root / "dataflow"
        if direct.is_dir():
            return direct
        for path in sorted(p for p in root.rglob("dataflow") if p.is_dir()):
            return path
        return None

    def _find_first(self, root: Path, patterns: list[str]) -> Path | None:
        if not root.exists():
            return None
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            for pattern in patterns:
                if re.fullmatch(pattern, path.name):
                    return path
        return None

    def _fileserver_task_path(self, project_id: str, task_id: str, suffix: str | None = None) -> str:
        base = Path(self.cfg.storage.project_root_template.format(project_id=project_id)) / "app" / "secflow-app-binary-security" / task_id
        if suffix:
            return str(base / suffix.strip("/"))
        return str(base)


_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
