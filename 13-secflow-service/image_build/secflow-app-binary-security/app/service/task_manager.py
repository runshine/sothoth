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

from sqlalchemy import Integer, and_, case, cast, func, or_, text
from sqlalchemy.exc import IntegrityError, OperationalError, TimeoutError as SATimeoutError
from sqlalchemy.orm import Session, load_only

from app.copy_utils import safe_copy2
from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import (
    PIPELINE_PROFILE_DEFAULT,
    PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
    TASK_PIPELINE_PROFILE_SEQUENCES,
    STAGE_SEQUENCE,
    TASK_TERMINAL_STATUSES,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_STAGE_SEQUENCES,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
    BinarySecurityEvent,
    BinarySecurityArchiveJob,
    BinarySecurityProjectConfig,
    BinarySecurityServiceConfig,
    BinarySecurityTaskOperation,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityStateEvent,
    BinarySecurityCoordinatorLease,
    BinarySecurityTask,
    BinarySecurityTaskStateLease,
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
    observe_control_operation_duration,
    observe_control_operation_lease_lost,
    observe_control_operation_step_retry,
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
    observe_state_reducer_health,
    observe_state_reducer_event,
    observe_state_reducer_run,
    observe_task_readless_reconcile,
    observe_task_snapshot_lock_retry,
    observe_task_state_lock,
    observe_task_duration,
    observe_task_error,
    observe_task_heartbeat_candidates,
    observe_task_heartbeat_loop_duration,
    observe_task_list_query,
    observe_task_list_query_stage,
    observe_task_lifecycle,
    observe_task_operation,
    observe_tail_reconcile_heartbeat,
    observe_tail_reconcile_owner,
    observe_tail_reconcile_requeue_blocked,
    observe_tail_reconcile_takeover,
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
    BinarySecurityReducerEventPageResponse,
    BinarySecurityReducerEventRecordResponse,
    BinarySecurityReducerEventSummaryResponse,
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
from app.service.reducer_metrics_snapshot import get_reducer_metrics_snapshot_store
from app.service.readless_sync import ReadlessSyncStats, run_readless_sync_loop
from app.service.task.archive import TaskArchiveServiceMixin
from app.service.task.contracts import TaskContractServiceMixin
from app.service.task.control import TaskControlServiceMixin
from app.service.task.downstream import TaskDownstreamServiceMixin
from app.service.task.events import TaskEventServiceMixin
from app.service.task.item_sync import TaskItemSyncServiceMixin
from app.service.task.lifecycle import TaskLifecycleServiceMixin
from app.service.task.operation import TaskOperationServiceMixin
from app.service.task.operation_events import TaskOperationEventServiceMixin
from app.service.task.query import TaskQueryServiceMixin
from app.service.task.read_model import TaskReadModelServiceMixin
from app.service.task.reducer import TaskReducerServiceMixin
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
from app.service.knowledge_graph_entries import get_knowledge_graph_entries_client
from app.time_utils import now_local

logger = logging.getLogger(__name__)



TAIL_RECONCILE_OWNER = "tail_reconcile_worker"

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
class _TaskResumeDecision:
    should_resume: bool = False
    next_stage: str | None = None
    resume_reason: str | None = None
    source: str | None = None
    message: str | None = None
    event_type: str | None = None
    payload: dict[str, Any] | None = None
    owned_execution_requeue_required: bool = False

DB_ENTRY_PREVIEW_LIMIT = 50
DB_ARTIFACT_PREVIEW_LIMIT = 50
DB_EVENT_PAYLOAD_LIMIT_BYTES = 32768
DB_TIMELINE_EVENT_LIMIT = 10_000
DETAIL_STAGE_ITEMS_LIMIT = 100
READONLY_TASK_PROJECTION_CACHE_TTL_SECONDS = 1.0
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
STAGE_RETRY_BLOCKED_TASK_STATUSES = {"pending", "dispatching", "running", "pending_upload", "uploading", "ready_to_start"}
TASK_STATUS_PENDING_MODULE_CONFIRMATION = "pending_module_confirmation"
TASK_STATUS_PENDING_ENTRY_CONFIRMATION = "pending_entry_confirmation"
TASK_STATUS_HARD_RESTART_FAILED = "hard_restart_failed"
TASK_STATUS_CANCELLING = "cancelling"
TASK_STATUS_CANCEL_FAILED = "cancel_failed"
TASK_STATUS_DELETE_FAILED = "delete_failed"
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
TASK_OPERATION_ACTIVE_STATUSES = {"requested", "accepted", "queued", "claimed", "running"}
TASK_OPERATION_TERMINAL_STATUSES = {"succeeded", "failed", "superseded", "cancelled"}
TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN = "collect_cleanup_plan"
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
TASK_OPERATION_STEP_SUCCEEDED = "operation_succeeded"
TASK_CANCEL_BLOCKING_TARGETS_PREVIEW_LIMIT = 20
RETRY_CHILD_STRATEGY_REUSE_SUCCESS = "reuse_success"
RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = "adopt_active"
RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = "recreate_from_abnormal"
RETRY_CHILD_ABNORMAL_STATUSES = {"failed", "cancelled", "downstream_missing"}
TASK_OPERATION_SAGA_STEPS = (
    TASK_OPERATION_STEP_COLLECT_CLEANUP_PLAN,
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
    cancel_requested: bool = False
    last_progress_at: datetime | None = None

    def done(self) -> bool:
        return self.runner_task.done()

    def cancel(self) -> None:
        self.cancel_requested = True
        if self.heartbeat_task is not None and not self.heartbeat_task.done():
            self.heartbeat_task.cancel()
        if not self.runner_task.done():
            self.runner_task.cancel()


class TaskManager(
    TaskQueryServiceMixin,
    TaskReadModelServiceMixin,
    TaskControlServiceMixin,
    TaskDownstreamServiceMixin,
    TaskOperationServiceMixin,
    TaskOperationEventServiceMixin,
    TaskEventServiceMixin,
    TaskRuntimeServiceMixin,
    TaskContractServiceMixin,
    TaskReducerServiceMixin,
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
        self._downstream_reconcile_task: Optional[asyncio.Task] = None
        self._readless_reconcile_task: Optional[asyncio.Task] = None
        self._stage_item_sync_reconcile_task: Optional[asyncio.Task] = None
        self._archive_runtime_reconcile_task: Optional[asyncio.Task] = None
        self._state_repair_reconcile_task: Optional[asyncio.Task] = None
        self._state_reducer_loop_task: Optional[asyncio.Task] = None
        self._reducer_metrics_snapshot_loop_task: Optional[asyncio.Task] = None
        self._task_heartbeat_loop_task: Optional[asyncio.Task] = None
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
        self._state_reducer_consecutive_crash_count = 0
        self._task_list_cache: dict[tuple[str, str, str], tuple[float, Any]] = {}
        self._task_list_cache_lock = threading.Lock()
        self._readonly_projection_cache: dict[tuple[str, str, str], tuple[float, Any]] = {}
        self._readonly_projection_cache_lock = threading.Lock()
        self._loop_heartbeats: dict[str, datetime] = {}
        self._last_stale_operation_requeue_at: datetime | None = None
        self._last_stage_item_sync_reconcile_at: datetime | None = None
        self._tail_reconcile_handoff_reason: dict[str, str] = {}
        self._non_owner_claim_log_state: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._non_owner_claim_log_lock = threading.Lock()
        self._non_owner_claim_event_state: dict[tuple[str, str, str, str], datetime] = {}
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
                runtime_keys = dict((task.summary or {}).get("runtime_task_keys") or {})
                prefix = str(runtime_keys.get("root_task_key_prefix") or "wsk").strip() or "wsk"
                source = str(runtime_keys.get("task_key_source") or "schedule_dispatch").strip() or "schedule_dispatch"
                work_key_name = f"{str(service or 'child').strip() or 'child'}-{str(getattr(item, 'id', '') or 'item').strip() or 'item'}"
                work_key_id = hashlib.sha1(f"{task.id}:{getattr(item, 'id', '')}:{service}:{root_secret}".encode("utf-8")).hexdigest()[:12]
                return {
                    "agent_task_key_id": work_key_id,
                    "agent_task_key_name": work_key_name,
                    "agent_task_key_prefix": prefix,
                    "agent_task_key_source": source,
                    "agent_task_key_secret": root_secret,
                }
            return _derive_downstream_work_key
        if item == "_rebuild_archive_jobs_for_stage":
            def _rebuild_archive_jobs_for_stage(db, task, target_stage, stage_items):
                rebuilt = 0
                for stage_item in list(stage_items or []):
                    payload = dict(self._load_stage_item_result_payload(stage_item).get("downstream") or {})
                    mapped_status = str(payload.get("status") or getattr(stage_item, "status", "") or "").strip().lower() or None
                    job = self._queue_downstream_archive_job(
                        db,
                        task,
                        stage_item,
                        payload=payload,
                        mapped_status=mapped_status,
                        before_status=str(getattr(stage_item, "status", "") or "").strip() or None,
                    )
                    if job is not None:
                        rebuilt += 1
                return rebuilt
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
        if item == "_attempt_vuln_downstream_binding_recovery":
            async def _attempt_vuln_downstream_binding_recovery(db, task, stage_item, *, token=None, force=False):
                del force
                payload = await self._find_reusable_vuln_payload(task, stage_item, token)
                if payload is None:
                    return False, "create_failed"
                stage_item.downstream_task_id = payload.get("task_id") or payload.get("id") or stage_item.downstream_task_id
                stage_item.status = self._map_downstream_status(str(payload.get("status") or "")) or stage_item.status
                self._mark_downstream_binding_created(stage_item, message="已补齐下游绑定，状态待同步")
                db.flush()
                return True, "binding_recovered"
            return _attempt_vuln_downstream_binding_recovery
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
                                BinarySecurityTask.dispatcher_instance_id: self.instance_id,
                                BinarySecurityTask.dispatch_started_at: started_at,
                                BinarySecurityTask.lease_expires_at: started_at + timedelta(seconds=lease_timeout_seconds),
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
                return or_(
                    BinarySecurityTask.lease_expires_at.is_(None),
                    BinarySecurityTask.lease_expires_at < _now(),
                )
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
        return normalized if normalized in {"api", "worker", "reducer"} else "all"

    def _is_worker_role(self) -> bool:
        return self._service_role() in {"all", "worker"}

    def _is_reducer_role(self) -> bool:
        return self._service_role() in {"all", "reducer"}

    def _can_own_runtime_phase(self, phase: str | None) -> bool:
        normalized = str(phase or "").strip().lower()
        if normalized == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
            return self._is_worker_role() or self._is_reducer_role()
        if normalized in {"", TASK_RUNTIME_PHASE_OWNED_EXECUTION}:
            return self._is_worker_role()
        if normalized == TASK_RUNTIME_PHASE_TERMINAL:
            return False
        return self._is_worker_role()

    def _allow_tail_runtime_write(self, task: BinarySecurityTask | None) -> bool:
        return bool(task is not None and self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION and self._is_reducer_role())

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
        task_owner = str(task.dispatcher_instance_id or "").strip() or None
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
                task.dispatcher_instance_id,
                self.instance_id,
                skipped_count,
                ",".join(filter(None, sample_item_ids)),
            )

    def _downstream_tasks(self):
        return get_downstream_task_controller(self)

    def _stage_downstream_sync_max_consecutive_errors(self) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "stage_downstream_sync_max_consecutive_errors", 10) or 10))

    def _stage_downstream_sync_backoff_base_seconds(self) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "stage_downstream_sync_backoff_base_seconds", 2) or 2))

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
        configured = int(getattr(self.cfg.scheduler, "stage_item_sync_reconcile_interval_seconds", 30) or 30)
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
                    "has_root_task_key": True,
                },
            )
        work_key_payload = await self._derive_downstream_work_key(task=task, item=item, service=service)
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
                    "agent_task_key_id": work_key_payload.get("agent_task_key_id"),
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
                    "agent_task_key_id": work_key_payload.get("agent_task_key_id"),
                    "agent_task_key_prefix": work_key_payload.get("agent_task_key_prefix"),
                    "agent_task_key_source": work_key_payload.get("agent_task_key_source"),
                },
            )
        return await self._downstream_tasks().create_child_task(
            db,
            task,
            item,
            service=service,
            token=effective_token,
            payload=effective_payload,
            event_payload=event_payload,
        )

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
            return
        self._running = True
        observe_worker_counts(task_workers=0, operation_workers=0, archive_workers=0, task_heartbeat_workers=0)
        role = str(os.environ.get("SECFLOW_BINARY_SECURITY_ROLE") or "all").strip().lower()
        run_worker_loops = role in {"", "all", "worker"}
        run_reducer_loop = role in {"", "all", "reducer"}
        if run_worker_loops:
            self._loop_task = asyncio.create_task(self._dispatch_loop(), name="binary-security-dispatcher")
            self._archive_loop_task = asyncio.create_task(self._archive_dispatch_loop(), name="binary-security-archive-dispatcher")
            self._stage_item_loop_task = asyncio.create_task(
                self._stage_item_dispatch_loop(),
                name="binary-security-stage-item-dispatcher",
            )
        if run_worker_loops or run_reducer_loop:
            self._task_heartbeat_loop_task = asyncio.create_task(
                self._task_heartbeat_loop(),
                name="binary-security-task-heartbeat",
            )
        if run_reducer_loop:
            self._state_reducer_loop_task = asyncio.create_task(
                self._state_reducer_loop(),
                name="binary-security-state-reducer",
            )
            self._reducer_metrics_snapshot_loop_task = asyncio.create_task(
                self._reducer_metrics_snapshot_loop(),
                name="binary-security-reducer-metrics-snapshot",
            )
        if run_worker_loops:
            await self._seed_work_queues()

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
        await self._cancel_loop_task(self._loop_task)
        await self._cancel_loop_task(self._archive_loop_task)
        await self._cancel_loop_task(self._stage_item_loop_task)
        await self._cancel_loop_task(self._task_heartbeat_loop_task)
        await self._cancel_loop_task(self._state_reducer_loop_task)
        await self._cancel_loop_task(self._reducer_metrics_snapshot_loop_task)
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
        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)
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
        observe_task_heartbeat_candidates(0)
        observe_worker_counts(task_workers=0, operation_workers=0, archive_workers=0, task_heartbeat_workers=0)

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
                    "task_id=%s handle_done=%s cancel_requested=%s heartbeat_done=%s execution_token=%s lease_owner_instance_id=%s",
                    normalized_task_id,
                    existing.done(),
                    existing.cancel_requested,
                    existing.heartbeat_task.done() if existing.heartbeat_task is not None else None,
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
            handle = TaskRuntimeHandle(
                task_id=normalized_task_id,
                runner_task=runner_task,
                heartbeat_task=heartbeat_task,
                claimed_at=_now(),
                execution_token=None,
                lease_owner_instance_id=str(self.instance_id or "").strip() or None,
            )
            self._workers[normalized_task_id] = handle
            task_manager_module.logger.info(
                "binary-security start_task_runtime created new local handle: task_id=%s runner_task=%s heartbeat_task=%s lease_owner_instance_id=%s",
                normalized_task_id,
                runner_task.get_name(),
                heartbeat_task.get_name(),
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
                await asyncio.to_thread(self._touch_task_heartbeat, task_id)
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

    def _acquire_tail_reconcile_owner(self, task_id: str) -> None:
        if not self._is_reducer_role():
            return
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return
        if self._has_tail_reconcile_owner(normalized_task_id):
            return
        self._register_task_execution_owner(normalized_task_id, TAIL_RECONCILE_OWNER)
        observe_tail_reconcile_owner("acquired")

    def _release_tail_reconcile_owner(self, task_id: str) -> None:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return
        had_owner = self._has_tail_reconcile_owner(normalized_task_id)
        self._release_task_execution_owner(normalized_task_id, TAIL_RECONCILE_OWNER)
        if had_owner:
            observe_tail_reconcile_owner("released")

    def _has_tail_reconcile_owner(self, task_id: str) -> bool:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return False
        with self._task_execution_owner_lock:
            owners = self._task_execution_owners.get(normalized_task_id) or set()
            return TAIL_RECONCILE_OWNER in owners

    def _tail_reconcile_owner_token(self) -> dict[str, Any]:
        return {
            "owner_instance_id": self.instance_id,
            "owner_pod_uid": self.owner_pod_uid,
            "owner_boot_id": self.owner_boot_id,
            "generation": self._owner_generation,
            "owner_started_at": self.owner_started_at,
        }

    def _next_tail_reconcile_generation(self, current_generation: int | None = None) -> int:
        base = int(current_generation or self._owner_generation or 0)
        self._owner_generation = max(self._owner_generation, base + 1)
        return self._owner_generation

    def _collect_heartbeat_candidates(self) -> list[str]:
        with self._task_execution_owner_lock:
            return sorted(task_id for task_id, owners in self._task_execution_owners.items() if owners)

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
        _write_json(path, payload)

    async def _write_task_metadata_async(
        self,
        task: BinarySecurityTask,
        path: Path,
        *,
        status: str | None = None,
    ) -> None:
        await asyncio.to_thread(self._write_task_metadata, task, path, status=status)

    def _enqueue_task(self, task_id: str) -> None:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                asyncio.run(get_task_queue().push_task(normalized_task_id))
            except Exception:
                logger.warning("failed to enqueue task without running loop", extra={"task_id": normalized_task_id}, exc_info=True)
            return
        async def _push() -> None:
            try:
                await get_task_queue().push_task(normalized_task_id)
            except Exception:
                logger.warning("failed to enqueue task", extra={"task_id": normalized_task_id}, exc_info=True)

        loop.create_task(_push())

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

    def _clear_runtime_lease(self, db: Session, task_id: str, *, owner_instance_id: str | None = None) -> None:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return
        query = db.query(BinarySecurityTaskRuntimeLease).filter(
            BinarySecurityTaskRuntimeLease.task_id == normalized_task_id
        )
        normalized_owner = str(owner_instance_id or "").strip()
        if normalized_owner:
            query = query.filter(BinarySecurityTaskRuntimeLease.owner_instance_id == normalized_owner)
        query.delete(synchronize_session=False)

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
            db.add(lease)
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
        expires_at = lease.lease_expires_at if lease is not None else task.lease_expires_at
        return lease, owner, expires_at

    def _tail_reconcile_context_active(self, db: Session, task: BinarySecurityTask) -> bool:
        active_stage_name, active_item_count, has_downstream_refs = self._streaming_tail_active_context(db, task)
        return bool(active_stage_name) and (active_item_count > 0 or has_downstream_refs)

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
        if task is None:
            return False
        if not self._task_row_owner_is_supported_locally(task):
            return False
        if str(task.status or "").strip().lower() != "running":
            return False
        if str(task.status or "").strip() == TASK_STATUS_CANCELLING:
            return False
        if task.finished_at is not None:
            return False
        if self._task_has_active_cancel_operation(db, task):
            return False
        if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION and self._has_tail_reconcile_owner(task.id):
            lease = self._runtime_lease_for_task(db, task.id)
            if (
                self._runtime_lease_is_active(lease)
                and str(lease.owner_instance_id or "").strip() == str(self.instance_id or "").strip()
                and self._tail_reconcile_context_active(db, task)
            ):
                return True
        if not self._has_local_task_execution_owner(task.id) and not self._task_has_active_streaming_stage_workers(task.id):
            return False
        return True

    def _local_operation_worker_alive(self, operation_id: str | None) -> bool:
        normalized_operation_id = str(operation_id or "").strip()
        if not normalized_operation_id:
            return False
        worker = self._operation_workers.get(normalized_operation_id)
        return bool(worker is not None and not worker.done())

    def _task_owner_runtime_supported_locally(
        self,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> bool:
        if task is None:
            return False
        task_id = str(getattr(task, "id", "") or "").strip()
        if not task_id:
            return False
        handle = self._runtime_handle(task_id)
        if handle is not None and not handle.done():
            return True
        if self._has_local_task_execution_owner(task_id):
            return True
        if self._task_has_active_streaming_stage_workers(task_id):
            return True
        operation = active_operation
        if operation is None:
            current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
            if current_operation_id:
                session = get_session_factory()()
                try:
                    operation = session.query(BinarySecurityTaskOperation).filter(
                        BinarySecurityTaskOperation.id == current_operation_id
                    ).first()
                finally:
                    session.close()
        if operation is None:
            return False
        operation_status = str(getattr(operation, "status", "") or "").strip().lower()
        if operation_status not in TASK_OPERATION_ACTIVE_STATUSES:
            return False
        return self._local_operation_worker_alive(str(getattr(operation, "id", "") or "").strip())

    def _task_row_owner_is_supported_locally(
        self,
        task: BinarySecurityTask | None,
        *,
        active_operation=None,
    ) -> bool:
        if task is None:
            return False
        dispatcher_instance_id = str(getattr(task, "dispatcher_instance_id", "") or "").strip()
        if dispatcher_instance_id != str(self.instance_id or "").strip():
            return True
        if str(getattr(task, "status", "") or "").strip().lower() not in {"dispatching", "running"}:
            return True
        return self._task_owner_runtime_supported_locally(task, active_operation=active_operation)

    def _task_row_owner_is_runtime_supported(
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
        operation_status = str(getattr(operation, "status", "") or "").strip().lower() if operation is not None else ""
        has_active_operation = operation_status in TASK_OPERATION_ACTIVE_STATUSES
        current_status = str(getattr(task, "status", "") or "").strip().lower()
        if current_status not in {"dispatching", "running"} and not has_active_operation:
            return True
        dispatcher_instance_id = str(getattr(task, "dispatcher_instance_id", "") or "").strip()
        if not dispatcher_instance_id:
            return not has_active_operation
        if dispatcher_instance_id == str(self.instance_id or "").strip():
            return self._task_owner_runtime_supported_locally(task, active_operation=operation)
        if current_status in {"dispatching", "running"}:
            dispatch_started_at = getattr(task, "dispatch_started_at", None)
            dispatch_age_seconds = _elapsed_seconds_since(dispatch_started_at)
            lease_remaining_seconds = _seconds_until(getattr(task, "lease_expires_at", None))
            if (
                dispatch_started_at is not None
                and dispatch_age_seconds is not None
                and dispatch_age_seconds < 15
                and lease_remaining_seconds is not None
                and lease_remaining_seconds > 0
            ):
                return True
        lease = self._runtime_lease_for_task(db, str(getattr(task, "id", "") or "").strip())
        if (
            self._runtime_lease_is_active(lease)
            and str(getattr(lease, "owner_instance_id", "") or "").strip() == dispatcher_instance_id
        ):
            return True
        if current_status == "dispatching" or has_active_operation:
            return False
        if operation_status in TASK_OPERATION_ACTIVE_STATUSES:
            return False
        return True

    def _release_unsupported_task_row_owner(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        active_operation=None,
        reason: str,
    ) -> bool:
        previous_dispatcher_instance_id = str(getattr(task, "dispatcher_instance_id", "") or "").strip() or None
        lease = self._runtime_lease_for_task(db, str(getattr(task, "id", "") or "").strip())
        active_runtime_lease_owner = (
            str(getattr(lease, "owner_instance_id", "") or "").strip() or None
            if self._runtime_lease_is_active(lease)
            else None
        )
        if previous_dispatcher_instance_id is None and active_runtime_lease_owner is None:
            return False
        if self._task_row_owner_is_runtime_supported(db, task, active_operation=active_operation):
            return False
        previous_status = str(getattr(task, "status", "") or "").strip().lower()
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip() or None
        if previous_status == "running":
            task.status = "pending"
        elif previous_status == "dispatching":
            task.status = "pending"
        elif previous_status == TASK_STATUS_CANCELLING:
            task.status = TASK_STATUS_CANCELLING
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        task.finished_at = None
        task.last_error = None
        self._clear_runtime_lease(db, task.id, owner_instance_id=previous_dispatcher_instance_id)
        self._record_event(
            db,
            task,
            "task_row_owner_released_without_local_runtime",
            "检测到任务 owner 元数据漂移，但当前 Pod 没有本地执行句柄，已释放 owner 并等待重新调度",
            level="warning",
            stage_name=task.current_stage,
            payload={
                "reason": reason,
                "previous_status": previous_status,
                "current_operation_id": current_operation_id,
                "previous_dispatcher_instance_id": previous_dispatcher_instance_id,
                "released_by_instance_id": str(self.instance_id or "").strip() or None,
            },
        )
        return True

    def _write_task_heartbeat(self, session: Session, task_id: str, *, now_value: datetime, source: str) -> bool:
        task = session.query(BinarySecurityTask).filter(
            BinarySecurityTask.id == task_id,
            BinarySecurityTask.status == "running",
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
            task.lease_expires_at = self._next_runtime_lease_expiry(now_value=now_value)
            if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                task.tail_reconcile_state = "active"
            task.updated_at = now_value
            session.commit()
            self._last_task_heartbeat_at[task_id] = now_value
            observe_heartbeat_update(f"{source}_written")
            if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                observe_tail_reconcile_heartbeat("written")
                observe_tail_reconcile_owner("handoff_completed")
            return True
        session.rollback()
        observe_heartbeat_update(f"{source}_skipped")
        observe_tail_reconcile_heartbeat("skipped")
        return False

    def _refresh_task_heartbeats_once(self) -> None:
        session = get_session_factory()()
        try:
            candidate_ids = sorted(
                task_id
                for task_id, handle in self._workers.items()
                if handle is not None and not handle.done()
            )
            observe_task_heartbeat_candidates(len(candidate_ids))
            if not candidate_ids:
                return
            rows = session.query(BinarySecurityTask).filter(BinarySecurityTask.id.in_(candidate_ids)).all()
            tasks_by_id = {task.id: task for task in rows}
            for task_id in candidate_ids:
                task = tasks_by_id.get(task_id)
                if not self._should_keep_task_heartbeat(session, task):
                    if not self._has_local_task_execution_owner(task_id):
                        self._last_task_heartbeat_at.pop(task_id, None)
                        self._clear_runtime_lease(session, task_id, owner_instance_id=self.instance_id)
                        session.commit()
                    observe_heartbeat_update("controller_skipped")
                    continue
                try:
                    wrote = False
                    for attempt in range(self._task_lease_write_retry_attempts()):
                        try:
                            wrote = self._write_task_heartbeat(session, task_id, now_value=_now(), source="controller")
                            break
                        except OperationalError as exc:
                            session.rollback()
                            if not self._is_retryable_lock_error(exc) or attempt >= self._task_lease_write_retry_attempts() - 1:
                                raise
                            observe_heartbeat_update("controller_retry")
                            self._sleep_after_retryable_lock_error(attempt + 1)
                    if not wrote:
                        self._last_task_heartbeat_at.pop(task_id, None)
                except Exception:
                    session.rollback()
                    observe_heartbeat_update("controller_failed")
                    logger.exception("binary-security task heartbeat write failed: task_id=%s", task_id)
        finally:
            session.close()

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

    def _knowledge_graph_entries_url(self, task: BinarySecurityTask | dict[str, Any] | None) -> str | None:
        if isinstance(task, dict):
            policy = dict(task.get("policy") or {})
        else:
            policy = dict(getattr(task, "policy", {}) or {})
        value = str(policy.get("knowledge_graph_entries_url") or "").strip()
        return value or None

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
        if task.status not in {"pending_upload", "uploading", "ready_to_start"}:
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
        task.status = "ready_to_start"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
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
        await self._write_task_metadata_async(task, input_dir / "task-metadata.json", status="ready_to_start")
        self._record_event(db, task, "task_upload_completed", "输入文件上传完成", payload={"uploaded_files": len(actual_files)})
        self._record_event(db, task, "task_ready_to_start", "任务已就绪，准备自动启动")
        db.commit()
        return self.start_task(db, project_id=project_id, task_id=task_id)

    def start_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"ready_to_start", "failed", "partial_success"}:
            if task.status in {"pending", "running"}:
                return self.get_task_detail(db, project_id=project_id, task_id=task_id)
            raise ValidationError(f"当前状态不允许启动任务: {task.status}")
        input_files = task.summary.get("input_files") or []
        if not input_files:
            raise ValidationError("没有可用的输入文件")
        task.status = "pending"
        task.current_stage = self._stage_sequence_for_task(task)[0]
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
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
        self._enqueue_task(task.id)
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
        orphan_refs = [
            ref
            for ref in self._discover_parent_linked_downstream_refs(db, task)
            if self._normalize_downstream_ref_stage_name(ref) in set(stage_names)
        ]
        return self._dedupe_downstream_refs(direct_refs + orphan_refs), orphan_refs

    def _parent_linked_downstream_candidates(self) -> list[tuple[str, str, str, str, str | None]]:
        return [
            ("firmware_unpacker", "secflow_app_firmware_unpacker_unpack_tasks", "id", "parent_task_id", "parent_stage_name"),
            ("binary_to_source", "secflow_b2s_task", "id", "parent_task_id", "parent_stage_name"),
            ("system_analyse", "secflow_app_sa_tasks", "task_id", "parent_task_id", "parent_stage_name"),
            ("entry_analyse", "secflow_app_ea_tasks", "task_id", "parent_task_id", "parent_stage_name"),
            ("dataflow_vuln_scan", "secflow_dataflow_vuln_scanner_run_index", "id", "linked_task_id", None),
        ]

    def _discover_parent_linked_downstream_refs_detailed(
        self,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        refs: list[dict[str, Any]] = []
        scan_errors: list[dict[str, Any]] = []
        for service, table_name, task_id_column, parent_column, stage_column in self._parent_linked_downstream_candidates():
            try:
                column_rows = db.execute(
                    text(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema = DATABASE()
                          AND table_name = :table_name
                          AND (
                            column_name = :task_id_column
                            OR column_name = :parent_column
                            OR column_name = :stage_column
                          )
                        """
                    ),
                    {
                        "table_name": table_name,
                        "task_id_column": task_id_column,
                        "parent_column": parent_column,
                        "stage_column": stage_column or "",
                    },
                ).fetchall()
                available_columns = {str(row[0]) for row in column_rows}
                if task_id_column not in available_columns or parent_column not in available_columns:
                    error = {
                        "service": service,
                        "table_name": table_name,
                        "reason": "required_columns_missing",
                        "task_id_column": task_id_column,
                        "parent_column": parent_column,
                    }
                    scan_errors.append(error)
                    logger.warning(
                        "parent-linked downstream scan unavailable: service=%s table=%s task_id=%s reason=%s",
                        service,
                        table_name,
                        task.id,
                        error["reason"],
                    )
                    continue
                select_stage = f"`{stage_column}`" if stage_column and stage_column in available_columns else "NULL"
                rows = db.execute(
                    text(
                        f"""
                        SELECT `{task_id_column}` AS task_id, {select_stage} AS stage_name
                        FROM `{table_name}`
                        WHERE `{parent_column}` = :parent_task_id
                        """
                    ),
                    {"parent_task_id": task.id},
                ).fetchall()
            except Exception as exc:
                error = {
                    "service": service,
                    "table_name": table_name,
                    "reason": "scan_failed",
                    "error": str(exc),
                }
                scan_errors.append(error)
                logger.warning(
                    "failed to discover parent-linked downstream refs: service=%s table=%s task_id=%s error=%s",
                    service,
                    table_name,
                    task.id,
                    exc,
                )
                continue
            for row in rows:
                downstream_task_id = str(row[0] or "").strip()
                if not downstream_task_id:
                    continue
                parent_stage_name = str(row[1] or "").strip() or None
                inferred_stage_name = SERVICE_STAGE_NAMES.get(service)
                refs.append(
                    {
                        "service": service,
                        "task_id": downstream_task_id,
                        "project_id": task.project_id,
                        "stage_name": parent_stage_name or inferred_stage_name,
                        "parent_stage_name": parent_stage_name,
                        "stage_name_inferred": not bool(parent_stage_name) and bool(inferred_stage_name),
                        "inferred_stage_name": inferred_stage_name if not parent_stage_name else None,
                        "collect_source": "parent_linked_scan",
                    }
                )
        return refs, scan_errors

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

    def _stage_item_claim_token(self, item: BinarySecurityStageItem | None) -> str | None:
        token = str(getattr(item, "claim_execution_token", "") or "").strip()
        return token or None

    def _bind_stage_item_claim(self, item: BinarySecurityStageItem, *, task: BinarySecurityTask, owner_instance_id: str | None = None) -> str | None:
        token = self._dispatch_token(task)
        item.claim_owner_instance_id = str(owner_instance_id or self.instance_id or "").strip() or None
        item.claim_execution_token = token
        item.claim_started_at = _now()
        return token

    def _clear_stage_item_claim(self, item: BinarySecurityStageItem) -> None:
        item.claim_owner_instance_id = None
        item.claim_execution_token = None
        item.claim_started_at = None

    def _stage_item_claim_matches_task_execution(self, item: BinarySecurityStageItem, task: BinarySecurityTask) -> bool:
        claim_owner = str(getattr(item, "claim_owner_instance_id", "") or "").strip()
        claim_token = self._stage_item_claim_token(item)
        task_owner = str(getattr(task, "dispatcher_instance_id", "") or "").strip()
        task_token = self._dispatch_token(task)
        if not claim_owner or not claim_token or not task_owner or not task_token:
            return False
        return (
            claim_owner == task_owner
            and claim_token == task_token
            and self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_OWNED_EXECUTION
            and self._lease_is_active(task)
        )

    def _bind_execution_token(self, task: BinarySecurityTask) -> None:
        setattr(task, "_execution_dispatcher_id", task.dispatcher_instance_id)
        setattr(task, "_execution_token", self._dispatch_token(task))

    def _ensure_owned_execution_current(self, task: BinarySecurityTask) -> None:
        expected_dispatcher_id = getattr(task, "_execution_dispatcher_id", None)
        expected_token = getattr(task, "_execution_token", None)
        if expected_dispatcher_id is None and expected_token is None and not task.dispatcher_instance_id and not task.dispatch_started_at:
            return
        expected_dispatcher_id = expected_dispatcher_id or task.dispatcher_instance_id
        expected_token = expected_token or self._dispatch_token(task)
        if not expected_dispatcher_id or not expected_token:
            raise StaleTaskExecution(f"任务 {task.id} 缺少当前执行 token")
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task.id).first()
            current_token = row.dispatch_started_at.isoformat() if row and row.dispatch_started_at else None
            if (
                row is None
                or row.status not in {"dispatching", "running"}
                or row.dispatcher_instance_id != expected_dispatcher_id
                or current_token != expected_token
                or not self._lease_is_active(row)
            ):
                raise StaleTaskExecution(f"任务 {task.id} 当前执行 token 已失效")
        finally:
            session.close()

    def _ensure_tail_reconciliation_current(self, task: BinarySecurityTask) -> None:
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task.id).first()
            if row is None:
                raise StaleTaskExecution(f"任务 {task.id} 不存在")
            if self._task_runtime_phase(row) != TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                raise StaleTaskExecution(f"任务 {task.id} 当前 tail 收敛上下文已失效")
            if str(row.status or "").strip().lower() in TASK_TERMINAL_STATUSES:
                raise StaleTaskExecution(f"任务 {task.id} 已进入终态")
            lease = self._runtime_lease_for_task(session, task.id)
            if not self._runtime_lease_is_active(lease):
                raise StaleTaskExecution(f"任务 {task.id} 当前 tail 收敛 lease 已失效")
            if str(lease.owner_instance_id or "").strip() != str(self.instance_id or "").strip():
                self._release_tail_reconcile_owner(task.id)
                raise StaleTaskExecution(f"任务 {task.id} 当前 tail 收敛 owner 已变更")
            active_stage_name, active_item_count, has_downstream_refs = self._streaming_tail_active_context(session, row)
            if active_item_count <= 0 and not has_downstream_refs:
                raise StaleTaskExecution(f"任务 {task.id} 当前 tail 收敛上下文已结束")
        finally:
            session.close()

    def _ensure_task_execution_current(self, task: BinarySecurityTask) -> None:
        phase = self._task_runtime_phase(task)
        if phase == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
            self._ensure_tail_reconciliation_current(task)
            return
        self._ensure_owned_execution_current(task)

    async def _ensure_task_execution_current_async(self, task: BinarySecurityTask) -> None:
        await asyncio.to_thread(self._ensure_task_execution_current, task)

    def _task_runtime_workset(self, task: BinarySecurityTask) -> dict[str, Any]:
        summary = dict(getattr(task, "summary", None) or {})
        workset = summary.get("runtime_workset")
        normalized = dict(workset) if isinstance(workset, dict) else {}
        for signal_name in (
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

    def _has_task_write_ownership(
        self,
        task: BinarySecurityTask,
        db: Session | None = None,
        *,
        allow_dispatching: bool = False,
    ) -> bool:
        expected_statuses = {"running", "dispatching"} if allow_dispatching else {"running"}
        if str(getattr(task, "status", "") or "").strip() not in expected_statuses:
            return False
        if str(getattr(task, "dispatcher_instance_id", "") or "").strip() != str(self.instance_id or "").strip():
            return False
        if not self._lease_is_active(task, db=db):
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

    def _invalidate_task_execution(self, task: BinarySecurityTask) -> None:
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
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
        previous_dispatcher = str(task.dispatcher_instance_id or "").strip() or None
        task.status = "running"
        task.current_stage = active_stage_name or task.current_stage
        task.finished_at = None
        task.last_error = None
        if self._tail_requires_execution_takeover(db, task):
            self._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            task.tail_reconcile_state = "idle"
            if not self._should_preserve_task_dispatch_ownership(task, previous_status=previous_status):
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
        else:
            self._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_TAIL_RECONCILIATION)
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            lease = self._activate_tail_reconciliation(
                db,
                task,
                now_value=_now(),
                fallback_status="pending",
                takeover_result="recovered",
            )
            if not self._runtime_lease_is_active(lease):
                task.status = "running"
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
                    "previous_dispatcher_instance_id": previous_dispatcher,
                    "tail_control_mode": summary.get("tail_control_mode"),
                    "runtime_lease_established": self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
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
    ) -> bool:
        summary = self._tail_stage_work_summary(db, task)
        active_stage_name = summary.get("active_stage_name")
        active_item_count = int(summary.get("unbound_runnable_item_count", 0) or 0) + int(summary.get("bound_active_item_count", 0) or 0)
        has_downstream_refs = bool(summary.get("has_downstream_refs"))
        if active_item_count <= 0:
            return False
        previous_dispatcher = str(task.dispatcher_instance_id or "").strip() or None
        task.status = "pending"
        task.current_stage = active_stage_name or task.current_stage
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        task.finished_at = None
        task.last_error = None
        self._clear_runtime_lease(db, task.id)
        self._clear_task_abnormal_reason_snapshot(db, task)
        self._record_event(
            db,
            task,
            "running_execution_released_for_takeover",
            "运行实例租约已失效，父任务已释放并重新排队，等待新的 worker 继续推进尾段执行",
            level="warning",
            stage_name=task.current_stage,
            payload={
                "stage_name": task.current_stage,
                "previous_dispatcher_instance_id": previous_dispatcher,
                "runtime_lease_owner": runtime_lease_owner,
                "runtime_lease_expires_at": _isoformat_or_none(runtime_lease_expires_at),
                "active_item_count": active_item_count,
                "has_downstream_refs": has_downstream_refs,
                "tail_control_mode": summary.get("tail_control_mode"),
                "requeue_reason": reason,
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
        return tuple(
            stage_name
            for stage_name in STREAMING_TAIL_STAGES
            if stage_name in self._stage_sequence_for_task(task) and self._stage_enabled(task, stage_name)
        )

    def _is_streaming_tail_stage(self, task: BinarySecurityTask, stage_name: str | None) -> bool:
        normalized = str(stage_name or "").strip()
        return bool(normalized) and normalized in self._streaming_tail_stage_names(task)

    def _streaming_has_active_upstream_stage(
        self,
        task: BinarySecurityTask,
        stage_runs: list[BinarySecurityStageRun],
    ) -> tuple[bool, str | None, str | None]:
        if not self._streaming_mode_enabled(task):
            return False, None, None
        active_statuses = {"pending", "queued", "running", "dispatching", "applying"}
        runs_by_stage = {run.stage_name: run for run in stage_runs}
        active_candidates: list[tuple[str, str]] = []
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            if self._is_streaming_tail_stage(task, stage_name):
                continue
            run = runs_by_stage.get(stage_name)
            if run is None:
                active_candidates.append((stage_name, "pending"))
                continue
            normalized_status = self._normalize_downstream_status(run.status) or str(run.status or "").strip()
            if normalized_status in active_statuses:
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
        runs_by_stage = {run.stage_name: run for run in stage_runs}
        task_retry_target_stage = (
            str(task.target_stage_name or "").strip()
            if task.execution_mode in {"task_retry", "task_retry_failed_items"} and str(task.target_stage_name or "").strip()
            else None
        )
        active_candidates: list[tuple[str, str]] = []
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            run = runs_by_stage.get(stage_name)
            if run is None:
                continue
            normalized_status = self._normalize_downstream_status(run.status) or str(run.status or "").strip()
            if task_retry_target_stage and stage_name == task_retry_target_stage and normalized_status == "success":
                continue
            if normalized_status in {"pending", "queued"} and not self._stage_has_real_runnable_work(db, task, stage_name):
                continue
            if normalized_status in active_statuses:
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

    def _module_risk_levels(self, task: BinarySecurityTask) -> list[str]:
        return _normalize_module_risk_levels((task.policy or {}).get("module_risk_levels"))

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

    def _knowledge_graph_entry_results(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        return [dict(item) for item in (task.summary.get("knowledge_graph_entry_results") or []) if isinstance(item, dict)]

    def _entry_candidates(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        snapshot = self._entry_selection_snapshot(task)
        candidate_entries = snapshot.get("candidate_entries")
        if isinstance(candidate_entries, list) and candidate_entries:
            return [dict(item) for item in candidate_entries if isinstance(item, dict)]
        return self._entry_results(task)

    def _selected_entry_keys(self, task: BinarySecurityTask) -> list[str]:
        snapshot = self._entry_selection_snapshot(task)
        return [
            str(key).strip()
            for key in (snapshot.get("selected_entry_keys") or [])
            if str(key).strip()
        ]

    def _selected_entries(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        snapshot = self._entry_selection_snapshot(task)
        return [dict(item) for item in (snapshot.get("selected_entries") or []) if isinstance(item, dict)]

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

    def _effective_entry_inputs(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        if self._entry_selection_mode(task) == ENTRY_SELECTION_MODE_AUTO:
            return self._entry_candidates(task)
        selected_entries = self._selected_entries(task)
        if selected_entries:
            return selected_entries
        selected_keys = set(self._selected_entry_keys(task))
        if not selected_keys:
            return []
        return [
            entry
            for entry in self._entry_candidates(task)
            if str(entry.get("entry_key") or "").strip() in selected_keys
        ]

    def _entry_selection_metrics(self, task: BinarySecurityTask) -> dict[str, int]:
        return {
            "candidate_entry_count": len(self._entry_candidates(task)),
            "selected_entry_count": len(self._effective_entry_inputs(task)) if self._entry_selection_mode(task) == ENTRY_SELECTION_MODE_MANUAL_CONFIRM else len(self._entry_candidates(task)),
        }

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
        line_hint = str(raw.get("start_line") or "").strip()
        function_name = str(raw.get("name") or "").strip()
        entry_key = str(raw.get("source_id") or "").strip()
        return {
            "entry_key": entry_key,
            "firmware_key": SOURCE_TASK_INPUT_KEY,
            "firmware_name": task.name,
            "module_key": "knowledge_graph_source_project",
            "module_name": "source-project",
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
            "function_description": str(raw.get("function_purpose") or "").strip(),
            "function_description_source": "knowledge_graph",
            "entry_reason": self._knowledge_graph_entry_reason(raw),
            "entry_reason_source": "knowledge_graph",
            "taint_params": [],
            "taint_details": [],
            "signature": str(raw.get("signature") or "").strip(),
            "channel": str(raw.get("channel") or "").strip(),
            "subkind": str(raw.get("subkind") or "").strip(),
            "confidence": str(raw.get("confidence") or "").strip(),
            "is_promoted_root": bool(raw.get("is_promoted_root")),
            "covers": list(raw.get("covers") or []),
            "dominated_by": str(raw.get("dominated_by") or "").strip(),
            "source_provider": "knowledge_graph",
            "source_id": entry_key,
            "task_type": TASK_TYPE_SOURCE,
        }

    async def _fetch_knowledge_graph_entry_results(
        self,
        task: BinarySecurityTask,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        started = time.perf_counter()
        payload = await get_knowledge_graph_entries_client().list_entries(
            override_url=self._knowledge_graph_entries_url(task),
        )
        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise ValidationError("知识图谱入口响应格式非法: 缺少 entries 列表")
        raw_entries = [dict(item) for item in entries if isinstance(item, dict)]
        selected_raw = [item for item in raw_entries if bool(item.get("is_entry"))]
        normalized_entries = [self._normalize_knowledge_graph_entry(task, item) for item in selected_raw]
        deduped = _deduplicate_entry_keys(normalized_entries)
        return deduped, {
            "entries_url": self._knowledge_graph_entries_url(task)
            or f"{self.cfg.services.knowledge_graph_entries.base_url.rstrip('/')}{self.cfg.services.knowledge_graph_entries.entries_path}",
            "raw_entry_count": len(raw_entries),
            "selected_entry_count": len(deduped),
            "filtered_out_count": max(0, len(raw_entries) - len(selected_raw)),
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }

    def _filter_candidate_modules(self, modules: list[dict[str, Any]], risk_levels: list[str]) -> list[dict[str, Any]]:
        allowed = set(_normalize_module_risk_levels(risk_levels))
        candidates = [dict(module) for module in modules if str(module.get("risk_level") or "").strip() in allowed]
        if candidates:
            return candidates
        if not modules:
            return []
        return candidates

    def _module_metrics(self, modules: list[dict[str, Any]], candidate_modules: list[dict[str, Any]], selected_modules: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "high_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "高"),
            "medium_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "中"),
            "low_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "低"),
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

    def _ensure_stage_run(self, db: Session, task: BinarySecurityTask, stage_name: str) -> BinarySecurityStageRun:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
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
                return stage_run
            except IntegrityError:
                existing = db.query(BinarySecurityStageRun).filter(
                    BinarySecurityStageRun.task_id == task.id,
                    BinarySecurityStageRun.stage_name == stage_name,
                ).first()
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
        return sync_status == "transport_error"

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
        if not self._child_sync_observation_would_change(
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
        ):
            return True
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            try:
                with self._savepoint(db):
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

    def _enqueue_state_event(
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
            payload=payload or {},
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
            f"检测到阶段终态事件漏信，已补投 reducer 事件: {stage_name}",
            level="warning",
            stage_name=stage_name,
            payload={
                "reason": reason,
                "status": status,
                "execution_token": execution_token,
                "summary": self._fit_event_payload_for_db(dict(summary or {})),
            },
        )

    def _emit_stage_terminal_event_safely(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        stage_name: str,
        status: str,
        summary: dict[str, Any],
        stage_retry_mode: bool,
        task_retry_mode: bool,
        target_stage_name: str | None,
        execution_token: str | None,
    ) -> BinarySecurityStateEvent | None:
        stage_generation = self._stage_terminal_generation_key(task, stage_name, db=db)
        return self._enqueue_state_event(
            db,
            task=task,
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_name,
            event_type="stage_worker_terminal_observed",
            idempotency_key=(
                f"stage_worker_terminal_observed:{task.id}:{stage_name}:"
                f"{stage_generation}:{status}"
            ),
            payload={
                "stage_name": stage_name,
                "status": status,
                "summary": summary,
                "stage_retry_mode": bool(stage_retry_mode),
                "task_retry_mode": bool(task_retry_mode),
                "target_stage_name": target_stage_name,
                "execution_token": execution_token,
                "stage_generation": stage_generation,
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

    def _enqueue_downstream_status_event(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        mapped_status: str,
        before_status: str | None,
        downstream_status: str,
        payload: dict[str, Any],
        error_message: str | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        status_raw: str | None = None,
        force: bool = False,
        event_type: str = "downstream_status_observed",
    ) -> BinarySecurityStateEvent | None:
        downstream_payload = self._lightweight_downstream_payload(payload or {})
        fingerprint_payload = {
            "item_id": item.id,
            "downstream_task_id": item.downstream_task_id,
            "mapped_status": mapped_status,
            "downstream_status": downstream_status,
            "error_message": error_message,
            "downstream_payload": downstream_payload,
        }
        fingerprint = hashlib.sha1(json.dumps(fingerprint_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        return self._enqueue_state_event(
            db,
            task_id=task.id,
            project_id=task.project_id,
            stage_name=item.stage_name,
            item_id=item.id,
            event_type=event_type,
            idempotency_key=f"{event_type}:{item.id}:{fingerprint}",
            payload={
                "mapped_status": mapped_status,
                "before_status": before_status,
                "downstream_status": downstream_status,
                "downstream_payload": downstream_payload,
                "error_message": error_message,
                "http_status": http_status,
                "error_type": error_type,
                "status_raw": status_raw or downstream_status,
                "force": bool(force),
            },
        )

    def _enqueue_downstream_terminal_event(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        mapped_status: str,
        before_status: str | None,
        downstream_status: str,
        payload: dict[str, Any],
        error_message: str | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        status_raw: str | None = None,
        force: bool = False,
    ) -> BinarySecurityStateEvent | None:
        return self._enqueue_downstream_status_event(
            db,
            task=task,
            item=item,
            mapped_status=mapped_status,
            before_status=before_status,
            downstream_status=downstream_status,
            payload=payload,
            error_message=error_message,
            http_status=http_status,
            error_type=error_type,
            status_raw=status_raw,
            force=force,
            event_type="downstream_terminal_observed",
        )

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
                existing = db.query(BinarySecurityStateEvent).filter(
                    BinarySecurityStateEvent.idempotency_key == expected_key
                ).first()
                if existing is not None:
                    continue
                summary = dict(stage_run.output_summary or {})
                emitted = self._emit_stage_terminal_event_safely(
                    db,
                    task=task,
                    stage_name=stage_name,
                    status=stage_status,
                    summary=summary,
                    stage_retry_mode=False,
                    task_retry_mode=False,
                    target_stage_name=None,
                    execution_token=task.dispatch_started_at.isoformat() if task.dispatch_started_at else "",
                )
                if emitted is None:
                    continue
                self._record_missing_stage_terminal_event(
                    db,
                    task,
                    stage_name=stage_name,
                    status=stage_status,
                    reason="dispatch_loop_recovery",
                    summary=summary,
                    execution_token=task.dispatch_started_at.isoformat() if task.dispatch_started_at else "",
                )
                recovered = True
        if recovered:
            db.flush()
        return recovered

    def _enqueue_archive_state_event_by_job_id(self, job_id: str, *, event_type: str, payload: dict[str, Any] | None = None) -> None:
        db = get_session_factory()()
        try:
            job = db.query(BinarySecurityArchiveJob).filter(BinarySecurityArchiveJob.id == job_id).first()
            if job is None:
                observe_state_event(event_type, "missing_archive_job")
                return
            merged_payload = {**(payload or {})}
            if job.archive_root and "archive_root" not in merged_payload:
                merged_payload["archive_root"] = job.archive_root
            self._enqueue_state_event(
                db,
                task_id=job.task_id,
                project_id=job.project_id,
                stage_name=job.stage_name,
                item_id=job.item_id,
                archive_job_id=job.id,
                event_type=event_type,
                idempotency_key=f"{event_type}:{job.id}:{job.archive_status}:{job.updated_at.isoformat() if job.updated_at else ''}",
                payload=merged_payload,
            )
            db.commit()
        except Exception:
            db.rollback()
            observe_state_event(event_type, "error")
            logger.exception("binary-security failed to enqueue archive state event: job=%s type=%s", job_id, event_type)
        finally:
            db.close()

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
        return self._is_streaming_tail_stage(task, stage_name) and normalize_stage_name(stage_name) == "dataflow_vuln_scan"

    def _stage_archive_jobs_by_item(self, db: Session, task_id: str, stage_name: str) -> dict[str, list[BinarySecurityArchiveJob]]:
        jobs = (
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task_id,
                BinarySecurityArchiveJob.stage_name == stage_name,
            )
            .order_by(BinarySecurityArchiveJob.created_at.asc(), BinarySecurityArchiveJob.id.asc())
            .all()
        )
        grouped: dict[str, list[BinarySecurityArchiveJob]] = {}
        for job in jobs:
            grouped.setdefault(str(job.item_id or ""), []).append(job)
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
                item_jobs = jobs_by_item.get(str(item.id or ""), [])
                if item_jobs and any(str(job.archive_status or "").strip() != "success" for job in item_jobs):
                    return True
            return False
        finally:
            if owns_session:
                session.close()

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
            "ready_to_start",
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
            "ready_to_start",
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
            and (
                str(item.downstream_task_id or "").strip()
                or self._latest_observed_downstream_status(item) in RETRY_CHILD_ABNORMAL_STATUSES
            )
        ]

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
                self._comparable_datetime(run.finished_at or run.started_at)
                for run in runs_by_stage.values()
                if run
                and str(run.stage_name or "").strip() in upstream_stages
                and int(run.retry_count or 0) > 0
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
            if not run or int(run.retry_count or 0) <= 0:
                continue
            upstream_completed_at = self._comparable_datetime(run.finished_at or run.started_at)
            if earliest_target_created_at and upstream_completed_at and earliest_target_created_at >= upstream_completed_at:
                continue
            if run and int(run.retry_count or 0) > 0:
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
        if normalized in {"pending", "queued", "created", "ready", "ready_to_start", "awaiting_takeover", "retry_preparing"}:
            return "pending"
        if normalized == "dispatching":
            return "dispatching"
        if normalized in {"running", "processing", "in_progress", "cancelling", "started"}:
            return "running"
        if normalized in {"success", "succeeded", "passed", "completed", "complete", "done"}:
            return "success"
        if normalized == "partial_success":
            return "partial_success"
        if normalized == "skipped":
            return "failed"
        if normalized in {"invalid_input", "completed_limited"}:
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
        return self._stage_has_materialized_inputs(db, task, stage_name)

    def _stage_requires_materialized_inputs(self, task: BinarySecurityTask, stage_name: str) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        return normalized_stage in {"binary_to_source", "entry_analysis", "dataflow_vuln_scan"}

    def _stage_has_materialized_inputs(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
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
            return bool(self._effective_entry_inputs(task))
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
        """Rebuild full entry_results after downstream sync only updated stage items.

        Stage item result_json intentionally stores only entries_preview to keep DB rows
        small, so the authoritative source for full entries is the archived artifact.
        """
        items = [
            item
            for item in self._stage_items(db, task.id, "entry_analysis")
            if item.status == "success"
        ]
        rebuilt: list[dict[str, Any]] = []
        for item in items:
            result = self._load_stage_item_result_payload(item)
            input_ref = dict(item.input_ref or {})
            output_ref = dict(item.output_ref or {})
            module = {
                **input_ref,
                **result,
                "module_key": str(result.get("module_key") or input_ref.get("module_key") or item.item_key or ""),
                "module_name": str(result.get("module_name") or input_ref.get("module_name") or item.item_name or ""),
                "source_dir": self._resolve_entry_source_dir({**input_ref, **result}) or str(task.firmware_path or ""),
            }
            if not module["module_key"] or not module["module_name"]:
                continue
            artifact_root_value = self._stage_item_artifact_root(item)
            entries = [dict(entry) for entry in result.get("entries") or [] if isinstance(entry, dict)]
            if artifact_root_value:
                artifact_root = Path(str(artifact_root_value))
                parsed_entries = self._parse_entries(artifact_root, module)
                if parsed_entries:
                    entries = parsed_entries
                    module["artifact_root"] = str(artifact_root)
            if not entries:
                entries = [dict(entry) for entry in result.get("entries_preview") or [] if isinstance(entry, dict)]
            if not entries:
                continue
            normalized_entries = []
            for entry in entries:
                row = dict(entry)
                row["source_dir"] = self._resolve_entry_source_dir({**module, **row}) or module["source_dir"]
                normalized_entries.append(row)
            rebuilt.append(self._compact_entry_summary_item({**module, "entries": normalized_entries}))

        summary = {**(task.summary or {}), "entry_results": rebuilt}
        task.summary = summary
        entry_count = self._entry_count_for_summary("entry_results", rebuilt)
        task.metrics = {**(task.metrics or {}), "entry_count": entry_count}
        if stage_run is not None:
            stage_summary = {
                "items": self._compact_stage_success_items_for_db("entry_results", rebuilt),
                "failed_items": [
                    self._lightweight_stage_failure(
                        {
                            "item": {
                                **dict(item.input_ref or {}),
                                **self._load_stage_item_result_payload(item),
                            },
                            "error": item.error_message,
                        }
                    )
                    for item in self._stage_items(db, task.id, "entry_analysis")
                    if item.status in {"failed", "cancelled", "downstream_missing"}
                ],
                "success_count": len(rebuilt),
                "failed_count": int((stage_run.counts or {}).get("failed_items") or 0),
                "cancelled_count": int((stage_run.counts or {}).get("cancelled_items") or 0),
                "entry_count": entry_count,
                "status_synced": True,
                "sync_status": stage_run.status,
                **(stage_run.counts or {}),
            }
            self._persist_stage_run_output_summary(task, stage_run, stage_summary)
        return rebuilt

    def _refresh_system_analysis_stage_from_synced_items(self, db: Session, task: BinarySecurityTask) -> None:
        handler = self._stage_handler("system_analysis")
        if handler is None:
            return
        handler.refresh_summary_from_items(self, db, task)

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
        status = str(task.status or "").strip()
        active_statuses = {"running", "dispatching"}
        if status not in active_statuses:
            return False
        if not str(task.dispatcher_instance_id or "").strip():
            return False
        if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_OWNED_EXECUTION:
            return False
        return self._lease_is_active(task)

    def _should_preserve_task_dispatch_ownership(self, task: BinarySecurityTask, *, previous_status: str | None = None) -> bool:
        status = str(previous_status if previous_status is not None else task.status or "").strip()
        if status not in {"running", "dispatching"}:
            return False
        if not str(task.dispatcher_instance_id or "").strip():
            return False
        return self._lease_is_active(task)

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
            self._clear_stage_item_claim(item)
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
            if not keep_existing_active:
                self._clear_stage_item_claim(item)
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
        item.input_ref = input_ref
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
                if not keep_existing_active:
                    self._clear_stage_item_claim(existing)
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
                existing.input_ref = input_ref
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
        active_payload: dict[str, Any] | None = None,
        observed_payload: dict[str, Any] | None = None,
    ) -> tuple[str, str | None]:
        if active_payload is not None:
            status = self._map_downstream_status(str(active_payload.get("status") or ""))
            if status in {"pending", "queued", "dispatching", "running"}:
                return RETRY_CHILD_STRATEGY_ADOPT_ACTIVE, status
        payload = observed_payload if isinstance(observed_payload, dict) else None
        raw_status = None
        if payload is not None:
            raw_status = self._status_from_downstream_payload(payload, success_statuses={"success", "partial_success", "completed", "passed", "succeeded"})
        mapped_status = raw_status or self._latest_observed_downstream_status(item) or str(item.status or "").strip().lower() or None
        mapped_status = self._map_downstream_status(str(mapped_status or "")) or (str(mapped_status or "").strip().lower() or None)
        if mapped_status == "success":
            return RETRY_CHILD_STRATEGY_REUSE_SUCCESS, mapped_status
        if mapped_status in {"pending", "queued", "dispatching", "running"}:
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
                event_type="retry_item_adopt_active_child",
                message="重试接管仍在运行中的下游子任务",
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

    def _sort_downstream_payload_priority(self, payload: dict[str, Any]) -> tuple[int, float, str]:
        status = str(payload.get("status") or "").strip().lower()
        mapped = self._map_downstream_status(status)
        if mapped == "running":
            priority = 0
        elif mapped == "success":
            priority = 1
        elif mapped == "queued":
            priority = 2
        elif mapped in {"failed", "cancelled"}:
            priority = 3
        else:
            priority = 4
        comparable = (
            self._parse_comparable_datetime(payload.get("updated_at"))
            or self._parse_comparable_datetime(payload.get("finished_at"))
            or self._parse_comparable_datetime(payload.get("started_at"))
            or self._parse_comparable_datetime(payload.get("created_at"))
            or datetime.min
        )
        timestamp = comparable.timestamp() if comparable != datetime.min else float("-inf")
        return (priority, -timestamp, str(payload.get("task_id") or payload.get("id") or ""))

    async def _find_reusable_dataflow_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        allow_rebind: bool = True,
    ) -> dict[str, Any] | None:
        item_id = str(item.id or "").strip()
        if not item_id:
            return None
        try:
            listed = await self._downstream_list_tasks(
                service="dataflow_vuln_scan",
                project_id=task.project_id,
                token=self._resolve_downstream_token(),
                parent_task_id=task.id,
                parent_stage_item_id=item_id,
                per_page=100,
                sort_by="updated_at",
                sort_order="desc",
            )
        except Exception:
            return None
        rows = listed.get("items") if isinstance(listed, dict) else None
        if not isinstance(rows, list):
            return None
        candidates = [row for row in rows if isinstance(row, dict)]
        if not candidates:
            return None
        candidates.sort(key=self._sort_downstream_payload_priority)
        selected = candidates[0]
        selected_task_id = str(selected.get("task_id") or selected.get("id") or "").strip()
        current_task_id = str(item.downstream_task_id or "").strip()
        if allow_rebind and selected_task_id and selected_task_id != current_task_id:
            item.downstream_task_id = selected_task_id
        return selected

    async def _find_reusable_entry_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None = None,
    ) -> dict[str, Any] | None:
        item_id = str(item.id or "").strip()
        item_key = str(item.item_key or "").strip()
        if not item_id and not item_key:
            return None
        try:
            listed = await self._downstream_list_tasks(
                service="entry_analyse",
                project_id=task.project_id,
                token=token,
                parent_task_id=task.id,
                parent_stage_name=item.stage_name,
                parent_stage_item_id=item_id or None,
                parent_stage_item_key=None if item_id else (item_key or None),
                per_page=100,
                sort_by="updated_at",
                sort_order="desc",
            )
        except Exception:
            return None
        rows = listed.get("items") if isinstance(listed, dict) else None
        if not isinstance(rows, list):
            return None
        candidates = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            origin_item_id = str(row.get("parent_stage_item_id") or "").strip()
            origin_item_key = str(row.get("parent_stage_item_key") or "").strip()
            if item_id and origin_item_id == item_id:
                candidates.append(row)
                continue
            if not item_id and item_key and origin_item_key == item_key:
                candidates.append(row)
        if not candidates:
            return None
        candidates.sort(key=self._sort_downstream_payload_priority)
        selected = candidates[0]
        selected_task_id = str(selected.get("task_id") or selected.get("id") or "").strip()
        current_task_id = str(item.downstream_task_id or "").strip()
        if selected_task_id and selected_task_id != current_task_id:
            item.downstream_task_id = selected_task_id
        return selected

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

    async def _reconcile_entry_payload_binding(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        payload: dict[str, Any],
        token: str | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if str(item.downstream_service or "").strip() != "entry_analyse":
            return payload, None
        if self._entry_payload_matches_stage_item(item, payload):
            return payload, None
        mismatch_payload = {
            "downstream_service": item.downstream_service,
            "downstream_task_id": str(item.downstream_task_id or "").strip() or None,
            "expected_parent_stage_item_id": str(item.id or "").strip() or None,
            "expected_parent_stage_item_key": str(item.item_key or "").strip() or None,
            "observed_parent_stage_item_id": str(payload.get("parent_stage_item_id") or "").strip() or None,
            "observed_parent_stage_item_key": str(payload.get("parent_stage_item_key") or "").strip() or None,
        }
        rebound = await self._find_reusable_entry_payload(task, item, token)
        if rebound is not None and self._entry_payload_matches_stage_item(item, rebound):
            mismatch_payload["rebound_downstream_task_id"] = str(rebound.get("task_id") or rebound.get("id") or "").strip() or None
            return rebound, mismatch_payload
        return None, mismatch_payload

    async def _find_reusable_firmware_unpack_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None = None,
    ) -> dict[str, Any] | None:
        item_id = str(item.id or "").strip()
        item_key = str(item.item_key or "").strip()
        if not item_id and not item_key:
            return None
        try:
            listed = await self._downstream_list_tasks(
                service="firmware_unpacker",
                project_id=task.project_id,
                token=token,
                origin_mode="linked",
                limit=100,
                offset=0,
            )
        except Exception:
            return None
        rows = listed.get("items") if isinstance(listed, dict) else None
        if not isinstance(rows, list):
            return None
        candidates = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            origin_parent_task_id = str(row.get("parent_task_id") or "").strip()
            origin_item_id = str(row.get("parent_stage_item_id") or "").strip()
            origin_item_key = str(row.get("parent_stage_item_key") or "").strip()
            if origin_parent_task_id and origin_parent_task_id != str(task.id or "").strip():
                continue
            if item_id and origin_item_id == item_id:
                candidates.append(row)
                continue
            if item_key and origin_item_key == item_key:
                candidates.append(row)
        if not candidates:
            return None
        candidates.sort(key=self._sort_downstream_payload_priority)
        selected = candidates[0]
        selected_task_id = str(selected.get("task_id") or selected.get("id") or "").strip()
        current_task_id = str(item.downstream_task_id or "").strip()
        if selected_task_id and selected_task_id != current_task_id:
            item.downstream_task_id = selected_task_id
        return selected

    async def _find_reusable_vuln_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None = None,
    ) -> dict[str, Any] | None:
        item_id = str(item.id or "").strip()
        item_key = str(item.item_key or "").strip()
        if not item_id and not item_key:
            return None
        try:
            listed = await self._downstream_list_tasks(
                service="dataflow_vuln_scan",
                project_id=task.project_id,
                token=token,
                limit=100,
                offset=0,
            )
        except Exception:
            return None
        rows = listed if isinstance(listed, list) else listed.get("items") if isinstance(listed, dict) else None
        if not isinstance(rows, list):
            return None
        candidates = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            origin_parent_task_id = str(row.get("parent_task_id") or row.get("linked_task_id") or "").strip()
            origin_item_id = str(row.get("parent_stage_item_id") or "").strip()
            origin_item_key = str(row.get("parent_stage_item_key") or "").strip()
            if origin_parent_task_id and origin_parent_task_id != str(task.id or "").strip():
                continue
            if item_id and origin_item_id == item_id:
                candidates.append(row)
                continue
            if item_key and origin_item_key == item_key:
                candidates.append(row)
        if not candidates:
            return None
        candidates.sort(key=self._sort_downstream_payload_priority)
        selected = candidates[0]
        selected_task_id = str(selected.get("task_id") or selected.get("id") or "").strip()
        current_task_id = str(item.downstream_task_id or "").strip()
        if selected_task_id and selected_task_id != current_task_id:
            item.downstream_task_id = selected_task_id
        return selected

    async def _find_reusable_system_analysis_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None = None,
    ) -> dict[str, Any] | None:
        item_key = str(item.item_key or "").strip()
        if not item_key:
            return None
        try:
            listed = await self._downstream_list_tasks(
                service="system_analyse",
                project_id=task.project_id,
                token=self._resolve_downstream_token(token),
                parent_task_id=task.id,
                per_page=100,
                sort_by="updated_at",
                sort_order="desc",
            )
        except Exception:
            return None
        rows = listed.get("items") if isinstance(listed, dict) else None
        if not isinstance(rows, list):
            return None
        candidates = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            origin_item_id = str(row.get("parent_stage_item_id") or "").strip()
            row_item_key = str(row.get("item_key") or row.get("firmware_key") or "").strip()
            if origin_item_id and origin_item_id == str(item.id or "").strip():
                candidates.append(row)
                continue
            if row_item_key and row_item_key == item_key:
                candidates.append(row)
        if not candidates:
            return None
        candidates.sort(key=self._sort_downstream_payload_priority)
        selected = candidates[0]
        selected_task_id = str(selected.get("task_id") or selected.get("id") or "").strip()
        current_task_id = str(item.downstream_task_id or "").strip()
        if selected_task_id and selected_task_id != current_task_id:
            item.downstream_task_id = selected_task_id
        return selected

    async def _find_reusable_b2s_payload(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None = None,
    ) -> dict[str, Any] | None:
        item_id = str(item.id or "").strip()
        item_key = str(item.item_key or "").strip()
        if not item_id and not item_key:
            return None
        try:
            listed = await self._downstream_list_tasks(
                service="binary_to_source",
                project_id=task.project_id,
                token=token,
                parent_task_id=task.id,
                parent_stage_item_id=item_id or None,
                limit=100,
                offset=0,
            )
        except Exception:
            return None
        rows = listed.get("items") if isinstance(listed, dict) else None
        if not isinstance(rows, list):
            return None
        candidates = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            origin_item_id = str(row.get("parent_stage_item_id") or "").strip()
            origin_item_key = str(row.get("parent_stage_item_key") or "").strip()
            if item_id and origin_item_id == item_id:
                candidates.append(row)
                continue
            if item_key and origin_item_key == item_key:
                candidates.append(row)
        if not candidates:
            return None
        candidates.sort(key=self._sort_downstream_payload_priority)
        selected = candidates[0]
        selected_task_id = str(selected.get("task_id") or selected.get("id") or "").strip()
        current_task_id = str(item.downstream_task_id or "").strip()
        if selected_task_id and selected_task_id != current_task_id:
            item.downstream_task_id = selected_task_id
        return selected

    async def _duplicate_downstream_refs_for_item(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
        *,
        keep_task_ids: set[str] | None = None,
    ) -> list[dict[str, str]]:
        service = str(item.downstream_service or "").strip()
        item_id = str(item.id or "").strip()
        item_key = str(item.item_key or "").strip()
        if not service or (not item_id and not item_key):
            return []
        keep = {str(value or "").strip() for value in (keep_task_ids or set()) if str(value or "").strip()}
        rows: list[dict[str, Any]] = []
        try:
            if service == "system_analyse":
                listed = await self._downstream_list_tasks(
                    service="system_analyse",
                    project_id=task.project_id,
                    token=self._resolve_downstream_token(token),
                    parent_task_id=task.id,
                    per_page=100,
                    sort_by="updated_at",
                    sort_order="desc",
                )
                rows = listed.get("items") if isinstance(listed, dict) else []
            elif service == "binary_to_source":
                listed = await self._downstream_list_tasks(
                    service="binary_to_source",
                    project_id=task.project_id,
                    token=token,
                    parent_task_id=task.id,
                    parent_stage_item_id=item_id or None,
                    limit=100,
                    offset=0,
                )
                rows = listed.get("items") if isinstance(listed, dict) else []
            elif service == "entry_analyse":
                listed = await self._downstream_list_tasks(
                    service="entry_analyse",
                    project_id=task.project_id,
                    token=token,
                    parent_task_id=task.id,
                    parent_stage_item_id=item_id or None,
                    per_page=100,
                    sort_by="updated_at",
                    sort_order="desc",
                )
                rows = listed.get("items") if isinstance(listed, dict) else []
            elif service == "dataflow_analyse":
                rows = []
            elif service == "firmware_unpacker":
                listed = await self._downstream_list_tasks(
                    service="firmware_unpacker",
                    project_id=task.project_id,
                    token=token,
                    origin_mode="linked",
                    limit=100,
                    offset=0,
                )
                rows = listed.get("items") if isinstance(listed, dict) else []
            elif service == "dataflow_vuln_scan":
                listed = await self._downstream_list_tasks(
                    service="dataflow_vuln_scan",
                    project_id=task.project_id,
                    token=token,
                    limit=100,
                    offset=0,
                )
                rows = listed if isinstance(listed, list) else listed.get("items") if isinstance(listed, dict) else []
        except Exception:
            return []
        if not isinstance(rows, list):
            return []

        refs: list[dict[str, str]] = []
        current_task_id = str(item.downstream_task_id or "").strip()
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_task_id = str(row.get("task_id") or row.get("id") or "").strip()
            if not row_task_id or row_task_id == current_task_id or row_task_id in keep:
                continue
            origin_parent_task_id = str(row.get("parent_task_id") or row.get("linked_task_id") or "").strip()
            if origin_parent_task_id and origin_parent_task_id != str(task.id or "").strip():
                continue
            origin_item_id = str(row.get("parent_stage_item_id") or "").strip()
            origin_item_key = str(row.get("parent_stage_item_key") or row.get("item_key") or row.get("firmware_key") or "").strip()
            matched = bool(item_id and origin_item_id == item_id) or bool(item_key and origin_item_key == item_key)
            if not matched:
                continue
            refs.append(
                {
                    "service": service,
                    "task_id": row_task_id,
                    "project_id": task.project_id,
                    "stage_name": item.stage_name,
                }
            )
        return self._dedupe_downstream_refs(refs)

    async def _cleanup_duplicate_downstream_refs_for_item(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
        *,
        keep_task_ids: set[str] | None = None,
    ) -> int:
        refs = await self._duplicate_downstream_refs_for_item(task, item, token, keep_task_ids=keep_task_ids)
        if not refs:
            return 0
        self._record_downstream_item_disposition(
            db,
            task,
            item,
            event_type="downstream_orphan_cleanup_started",
            message=f"开始被动清理重复下游子任务 {item.downstream_service}:{len(refs)} 个",
            payload={"cleanup_refs": refs},
        )
        try:
            await self._cleanup_downstream_refs(db, task, refs, token)
        except Exception as exc:
            self._record_downstream_item_disposition(
                db,
                task,
                item,
                event_type="downstream_orphan_cleanup_failed",
                message=f"被动清理重复下游子任务失败: {item.downstream_service}:{exc}",
                level="warning",
                payload={"cleanup_refs": refs, "error": str(exc)},
            )
            return 0
        self._record_downstream_item_disposition(
            db,
            task,
            item,
            event_type="downstream_orphan_cleanup_completed",
            message=f"已被动清理重复下游子任务 {item.downstream_service}:{len(refs)} 个",
            payload={"cleanup_refs": refs},
        )
        return len(refs)

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
        if task.status in {"pending_upload", "uploading", "ready_to_start"}:
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
        if self._streaming_tail_auto_progressing(db, task):
            return False, "当前任务处于 streaming tail 自动推进中，暂不支持失败项重试", None, []
        active_operation = self._active_operation(db, task.id)
        if active_operation is not None:
            return False, f"当前任务已有进行中的操作: {active_operation.operation_type}", None, []
        if task.status in {"pending_upload", "uploading", "ready_to_start"}:
            return False, "当前任务尚未完成输入准备，不能重试失败项", None, []
        blocked_statuses = {"pending", "dispatching", "running"}
        if task.status in blocked_statuses:
            return False, f"当前任务正在执行或排队中，不能重试失败项: {task.status}", None, []
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            return False, "当前任务等待模块确认，请先确认模块后再重试失败项", None, []
        stage_name, items = self._first_failed_retry_stage(db, task)
        if not stage_name or not items:
            return False, "当前任务没有可重试的失败项", None, []
        upstream_retried, upstream_stage = self._upstream_stage_retried(db, task, stage_name)
        if upstream_retried:
            return False, f"阶段 {STAGE_TITLES.get(stage_name, stage_name)} 的上游阶段 {STAGE_TITLES.get(upstream_stage or '', upstream_stage or '')} 已发生重试，不能只重试失败项", None, []
        reason = self._continue_stage_input_error(db, task, stage_name)
        if reason:
            return False, reason, stage_name, []
        return True, None, stage_name, items

    def _ensure_stage_inputs_available(self, db: Session, task: BinarySecurityTask, stage_name: str) -> None:
        """Rebuild target-stage inputs from the previous successful stage when possible."""
        summary = dict(task.summary or {})
        if normalize_stage_name(stage_name) == "knowledge_graph_entry_fetch":
            return
        if stage_name in {"binary_to_source", "entry_analysis"} and not summary.get("selected_modules"):
            self._refresh_system_analysis_stage_from_synced_items(db, task)
            summary = dict(task.summary or {})
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan" and not summary.get("entry_results"):
            if self._pipeline_profile(task) != PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                self._refresh_system_analysis_stage_from_synced_items(db, task)
                summary = dict(task.summary or {})
                if summary.get("selected_modules") and not self._stage_items(db, task.id, "entry_analysis"):
                    task.current_stage = "entry_analysis"
                    stage_name = "entry_analysis"
        if stage_name == "entry_analysis" and self._task_type(task) != TASK_TYPE_SOURCE and not summary.get("b2s_results"):
            self._rebuild_summary_results_from_stage_items(db, task, "binary_to_source", "b2s_results")
            summary = dict(task.summary or {})
        if stage_name == "entry_analysis" and self._task_type(task) == TASK_TYPE_BINARY_MODULE and summary.get("b2s_results"):
            normalized = [self._normalize_entry_analysis_module_input(task, module) for module in (summary.get("b2s_results") or []) if isinstance(module, dict)]
            if normalized != list(summary.get("b2s_results") or []):
                task.summary = {**summary, "b2s_results": normalized}
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan" and not summary.get("entry_results"):
            if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                self._refresh_knowledge_graph_entry_fetch_summary(task)
            else:
                self._rebuild_entry_results_from_stage_items(db, task)

    def _rebuild_summary_results_from_stage_items(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        summary_key: str,
    ) -> list[dict[str, Any]]:
        items = [
            item
            for item in self._stage_items(db, task.id, stage_name)
            if item.status == "success"
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
                    "success_count": len(rebuilt),
                    "failed_count": int((stage_run.counts or {}).get("failed_items") or 0),
                    "cancelled_count": int((stage_run.counts or {}).get("cancelled_items") or 0),
                    "running_count": int((stage_run.counts or {}).get("running_items") or 0),
                    "entry_count": self._entry_count_for_summary(summary_key, rebuilt),
                    "vuln_result_count": len(rebuilt) if summary_key == "dataflow_results" else 0,
                    "status_synced": True,
                    "sync_status": stage_run.status,
                    **(stage_run.counts or {}),
                },
            )
        return rebuilt

    def _continue_stage_input_error(self, db: Session, task: BinarySecurityTask, stage_name: str) -> str | None:
        self._ensure_stage_inputs_available(db, task, stage_name)
        handler = self._stage_handler(stage_name)
        if handler is not None and normalize_stage_name(stage_name) in {"firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "knowledge_graph_entry_fetch", "dataflow_vuln_scan"}:
            handler_reason = handler.continue_stage_input_error(self, db, task)
            return handler_reason
        summary = dict(task.summary or {})
        if stage_name == "binary_to_source":
            inputs = list(summary.get("selected_modules") or [])
            if not inputs:
                return "系统分析尚未产出可用模块，不能继续二进制逆向阶段"
            return None
        if stage_name == "entry_analysis":
            if self._task_type(task) == TASK_TYPE_BINARY_MODULE:
                inputs = [dict(item) for item in (summary.get("b2s_results") or []) if isinstance(item, dict)]
                if not inputs:
                    return "binary-to-source 尚未产出可用结果，不能继续入口分析阶段"
                ready_inputs = [item for item in inputs if item.get("entry_descriptor_ready")]
                if not ready_inputs:
                    return "binary-to-source 已成功，但未生成入口分析所需模块描述文件"
                if not any(str(item.get("entry_files_list") or "").strip() for item in ready_inputs):
                    return "入口分析模块描述文件已生成但文件列表为空"
                return None
            inputs = list(summary.get("selected_modules") or [])
            if not inputs:
                return "系统分析尚未产出可用模块，不能继续入口分析阶段"
            return None
        if normalize_stage_name(stage_name) == "knowledge_graph_entry_fetch":
            source_dir = str(summary.get("input_dir") or "").strip()
            if not source_dir:
                return "源码任务缺少输入目录，不能继续知识图谱入口获取阶段"
            return None
        if normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            inputs = list(summary.get("entry_results") or [])
            if not inputs:
                if self._pipeline_profile(task) == PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
                    return "知识图谱入口获取尚未产出可用入口结果，不能继续数据流漏洞挖掘阶段"
                return "入口分析尚未产出可用入口结果，不能继续数据流漏洞挖掘阶段"
            return None
        return None

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
            entry_results = self._effective_entry_inputs(task)
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
            stage_status = self._normalize_downstream_status(getattr(stage_run, "status", None)) or str(getattr(stage_run, "status", "") or "").strip().lower()
            failure_snapshot = self._stage_failure_snapshot(task, stage_run) if stage_run is not None else {}
            failure_code = self._string_or_none(failure_snapshot.get("failure_code"))
            failure_message = (
                self._string_or_none(failure_snapshot.get("failure_message"))
                or self._string_or_none(failure_snapshot.get("error"))
                or self._string_or_none(getattr(stage_run, "last_error", None))
            )
            reason: str | None = None
            if stage_status in {"failed", "cancelled", "downstream_missing"} and self._is_archive_repair_sensitive_failure(
                stage_name,
                failure_code=failure_code,
                failure_message=failure_message,
            ):
                reason = "failed_due_to_missing_repaired_inputs"
            elif stage_status in {"pending", "queued", "running", "dispatching", "success", "partial_success"} and stage_items:
                reason = "stale_descendant_items_present"
            elif stage_status in {"pending", "queued", "running", "dispatching"} and stage_run is not None:
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

    def _should_reopen_failed_stage_after_archive_input_repair(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None,
    ) -> bool:
        if stage_run is None or str(stage_run.status or "").strip() != "failed":
            return False
        summary = dict(task.summary or {})
        if str(summary.get("stale_reason") or "").strip() != "archive_input_repaired":
            return False
        stage_name = str(stage_run.stage_name or "").strip()
        if not stage_name:
            return False
        failure_snapshot = self._stage_failure_snapshot(task, stage_run)
        failure_message = (
            self._string_or_none(failure_snapshot.get("failure_message"))
            or self._string_or_none(failure_snapshot.get("error"))
            or self._string_or_none(getattr(stage_run, "last_error", None))
        )
        if not self._is_archive_repair_sensitive_failure(
            stage_name,
            failure_code=self._string_or_none(failure_snapshot.get("failure_code")),
            failure_message=failure_message,
        ):
            return False
        return self._stage_has_materialized_inputs(db, task, stage_name)

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
        deleted_timeline_event_count = self._delete_timeline_rows_for_stages(db, task.id, affected_stages)
        for stage_name in affected_stages:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            if stage_run is not None:
                self._reset_stage_run_for_retry(task, stage_run, increment_retry=False)
        summary = dict(task.summary or {})
        summary["stale_reason"] = "archive_input_repaired"
        summary["stale_from_stage"] = repaired_stage
        summary["stale_stages"] = affected_stages
        task.summary = summary
        return {
            "affected_stages": affected_stages,
            "deleted_stage_item_count": deleted_stage_item_count,
            "deleted_archive_job_count": deleted_archive_job_count,
            "deleted_state_event_count": deleted_state_event_count,
            "deleted_timeline_event_count": deleted_timeline_event_count,
        }

    def _requeue_after_archive_input_repair(
        self,
        db: Session,
        task: BinarySecurityTask,
        *,
        repaired_stage: str,
        affected_stages: list[str],
        state_event_id: str | None,
        before_signature: dict[str, Any],
        after_signature: dict[str, Any],
    ) -> bool:
        next_stage = self._next_incomplete_stage(db, task)
        if not next_stage:
            return False
        decision = self._decide_task_resume_after_stage_reset(
            db,
            task,
            next_stage=next_stage,
            resume_reason="archive_input_repaired",
            source="archive_apply",
            message=f"归档修复后任务重新进入下一阶段: {next_stage}",
            payload={
                "state_event_id": state_event_id,
                "repaired_stage": repaired_stage,
                "affected_stages": affected_stages,
                "input_semantics_before": before_signature,
                "input_semantics_after": after_signature,
            },
        )
        if not decision.should_resume:
            blocked_reason = self._continue_stage_input_error(db, task, next_stage)
            self._record_event(
                db,
                task,
                "archive_apply_input_repair_blocked",
                "归档晚到修复后仍无法自动推进到下一阶段",
                level="warning",
                stage_name=next_stage,
                payload={
                    "state_event_id": state_event_id,
                    "repaired_stage": repaired_stage,
                    "blocked_reason": blocked_reason,
                    "affected_stages": affected_stages,
                    "input_semantics_before": before_signature,
                    "input_semantics_after": after_signature,
                },
            )
            return False
        self._record_event(
            db,
            task,
            "archive_apply_triggered_input_repair",
            "上游阶段归档晚到修复了后续输入，已失效化污染阶段并重新排队",
            stage_name=repaired_stage,
            level="warning",
            payload={
                "state_event_id": state_event_id,
                "repaired_stage": repaired_stage,
                "next_stage": next_stage,
                "affected_stages": affected_stages,
                "input_semantics_before": before_signature,
                "input_semantics_after": after_signature,
            },
        )
        decision.event_type = "task_requeued_after_archive_input_repair"
        return self._apply_task_resume_decision(db, task, decision)

    def _base_task_summary(
        self,
        task: BinarySecurityTask,
        *,
        input_files: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        existing_summary = dict(task.summary or {})
        normalized_inputs = [dict(item) for item in (input_files if input_files is not None else existing_summary.get("input_files") or [])]
        input_dir = Path(task.workspace_root) / "input"
        run_dir = Path(task.workspace_root) / "run"
        output_root = Path(task.output_root)
        task_type = self._task_type(task)
        summary = {
            "fileserver_project_path": str(task.workspace_root),
            "task_root_path": str(task.workspace_root),
            "input_dir": str(input_dir),
            "output_dir": str(output_root),
            "run_dir": str(run_dir),
            "temp_upload_dir": str(run_dir / "upload-tmp") if task_type == TASK_TYPE_SOURCE else None,
            "input_manifest_path": str(input_dir / "task-metadata.json"),
            "input_files": normalized_inputs,
            "input_kind": (
                "source_archives"
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
        allowed = set(normalized)
        refs = self._downstream_refs_for_stages(db, task, normalized)
        orphan_refs = [
            ref
            for ref in self._discover_parent_linked_downstream_refs(db, task)
            if self._normalize_downstream_ref_stage_name(ref) in allowed
        ]
        return self._dedupe_downstream_refs(refs + orphan_refs)

    def _discover_parent_linked_downstream_refs(self, db: Session, task: BinarySecurityTask) -> list[dict[str, str]]:
        """Find old child tasks that are no longer referenced by current stage items."""
        refs, _scan_errors = self._discover_parent_linked_downstream_refs_detailed(db, task)
        return refs

    def _retry_cleanup_refs_for_hard_restart(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_names: list[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        direct_refs = self._downstream_refs_for_stages(db, task, normalized)
        parent_linked_refs, scan_errors = self._discover_parent_linked_downstream_refs_detailed(db, task)
        return self._dedupe_downstream_refs(direct_refs + parent_linked_refs), parent_linked_refs, scan_errors

    def _verify_remaining_parent_linked_downstream_refs(
        self,
        db: Session,
        task: BinarySecurityTask,
        attempted_refs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        current_refs, _scan_errors = self._discover_parent_linked_downstream_refs_detailed(db, task)
        attempted_keys = {
            (str(ref.get("service") or "").strip(), str(ref.get("task_id") or "").strip())
            for ref in attempted_refs
            if str(ref.get("service") or "").strip() and str(ref.get("task_id") or "").strip()
        }
        last_results = [
            dict(result)
            for result in list(getattr(self, "_last_downstream_cleanup_results", []) or [])
            if isinstance(result, dict)
        ]
        result_map = {
            (str(result.get("service") or "").strip(), str(result.get("task_id") or "").strip()): result
            for result in last_results
            if str(result.get("service") or "").strip() and str(result.get("task_id") or "").strip()
        }
        remaining: list[dict[str, Any]] = []
        for ref in current_refs:
            key = (str(ref.get("service") or "").strip(), str(ref.get("task_id") or "").strip())
            if key not in attempted_keys:
                remaining.append({**ref, "deferred": True, "deferred_reason": "collect_missed"})
                continue
            cleanup_result = result_map.get(key) or {}
            if bool(cleanup_result.get("deferred")):
                remaining.append({**ref, **cleanup_result})
                continue
            remaining.append({**ref, **cleanup_result, "deferred": True, "deferred_reason": "verify_remaining"})
        return remaining

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
        del db, task
        await self._downstream_ensure_refs_inactive(refs, token)

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

    async def _poll_until_terminal(self, fetcher, *, success_statuses: set[str], failure_statuses: set[str], task: BinarySecurityTask, item: BinarySecurityStageItem | None = None):
        while True:
            try:
                await self._ensure_task_execution_current_async(task)
                await self._touch_task_heartbeat_async(task.id)
                payload = await fetcher()
                await self._ensure_task_execution_current_async(task)
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
                if await self._is_task_cancelled_async(task.id):
                    if item and item.downstream_task_id:
                        await self._cancel_downstream(item, self._service_token())
                    return "cancelled", payload
                await asyncio.sleep(self.cfg.scheduler.stage_poll_interval_seconds)
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
                await asyncio.sleep(
                    min(
                        self._stage_downstream_sync_backoff_max_seconds(),
                        self._stage_downstream_sync_backoff_base_seconds(),
                    )
                )

    def _touch_task_heartbeat(self, task_id: str) -> None:
        now = _now()
        last_heartbeat_at = self._last_task_heartbeat_at.get(task_id)
        interval_seconds = max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15))
        if last_heartbeat_at and (now - last_heartbeat_at).total_seconds() < interval_seconds:
            observe_heartbeat_update("fallback_skipped")
            return
        has_owner = self._has_local_task_execution_owner(task_id)
        has_tail_owner = self._has_tail_reconcile_owner(task_id)
        has_streaming_worker = self._task_has_active_streaming_stage_workers(task_id)
        if not has_owner and not has_tail_owner and not has_streaming_worker:
            observe_heartbeat_update("fallback_skipped")
            return
        session = get_session_factory()()
        try:
            task = session.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if not self._should_keep_task_heartbeat(session, task):
                observe_heartbeat_update("fallback_skipped")
                return
            self._write_task_heartbeat(session, task_id, now_value=now, source="fallback")
        finally:
            session.close()

    async def _touch_task_heartbeat_async(self, task_id: str) -> None:
        await asyncio.to_thread(self._touch_task_heartbeat, task_id)

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
        input_files = list(task.summary.get("input_files") or [])
        if not input_files:
            return "failed", {"error": "缺少输入文件"}
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
                {"filename": input_file["filename"], "path": str(Path(task.workspace_root) / "input" / input_file["filename"])},
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
            retries=int(task.policy.get("max_retries_per_item") or 0),
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
            retries=int(task.policy.get("max_retries_per_item") or 0),
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
        candidate_modules = self._filter_candidate_modules(all_modules, self._module_selection_candidate_levels(task))
        if status in {"success", "partial_success"} and success and not failed_like and not candidate_modules:
            failure = _no_candidate_modules_failure()
            task.summary = {
                **task.summary,
                "system_analysis_results": self._lightweight_system_analysis_items(success),
                "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
                "system_analysis_module_count": len(all_modules),
                "candidate_modules": [],
                "selected_modules": [],
                "high_risk_modules": [],
                **failure,
            }
            task.metrics = {
                **task.metrics,
                **self._module_metrics(all_modules, [], []),
            }
            task.last_error = failure["failure_message"]
            self._record_event(
                db,
                task,
                "system_analysis_no_candidate_modules",
                failure["failure_message"],
                level="error",
                stage_name=stage_run.stage_name,
                payload=failure,
            )
            db.commit()
            return "failed", {
                "items": self._lightweight_system_analysis_items(success),
                "failed_items": aggregate_summary.get("failed_items", []),
                "success_count": len(success),
                "failed_count": int(aggregate_summary.get("failed_count") or 0),
                "module_count": len(all_modules),
                "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
                "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
                "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
                "candidate_module_count": 0,
                "selected_module_count": 0,
                **failure,
            }
        selection_mode = self._module_selection_mode(task)
        selected_modules = self._mark_selected_modules(candidate_modules, selected_by=MODULE_SELECTION_MODE_AUTO) if selection_mode == MODULE_SELECTION_MODE_AUTO else []
        task.summary = {
            **self._clear_failure_fields_from_summary(task.summary),
            "system_analysis_results": self._lightweight_system_analysis_items(success),
            "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
            "system_analysis_module_count": len(all_modules),
            "candidate_modules": candidate_modules,
            "selected_modules": selected_modules,
            "high_risk_modules": selected_modules,
        }
        task.metrics = {
            **task.metrics,
            **self._module_metrics(all_modules, candidate_modules, selected_modules),
        }
        task.last_error = None
        db.commit()
        if status in {"success", "partial_success"} and selection_mode == MODULE_SELECTION_MODE_MANUAL_CONFIRM:
            task.status = TASK_STATUS_PENDING_MODULE_CONFIRMATION
            self._record_event(
                db,
                task,
                "module_selection_required",
                "系统分析已完成，等待人工确认模块",
                stage_name=stage_run.stage_name,
                payload={"candidate_module_count": len(candidate_modules)},
            )
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
            "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
            "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
            "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
            "candidate_module_count": len(candidate_modules),
            "selected_module_count": len(selected_modules),
            "requires_confirmation": selection_mode == MODULE_SELECTION_MODE_MANUAL_CONFIRM,
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
            retries=int(task.policy.get("max_retries_per_item") or 0),
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
        b2s_success = self._entry_analysis_inputs(db, task)
        if not b2s_success:
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
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        status, summary = self._aggregate_stage_items(db, task, results, "entry_results")
        entry_mode = self._entry_selection_mode(task)
        entry_results = self._entry_results(task)
        candidate_entries = self._entry_candidates(task)
        selected_entries = candidate_entries if entry_mode == ENTRY_SELECTION_MODE_AUTO else self._effective_entry_inputs(task)
        if entry_mode == ENTRY_SELECTION_MODE_MANUAL_CONFIRM and status in {"success", "partial_success"}:
            task.summary = {
                **(task.summary or {}),
                "entry_selection": {
                    "mode": entry_mode,
                    "status": "waiting_confirmation",
                    "candidate_entries": candidate_entries,
                    "selected_entry_keys": [],
                    "selected_entries": [],
                    "confirmed_at": None,
                },
            }
            task.metrics = {
                **(task.metrics or {}),
                "candidate_entry_count": len(candidate_entries),
                "selected_entry_count": 0,
                "entry_count": 0,
            }
            task.status = TASK_STATUS_PENDING_ENTRY_CONFIRMATION
            stage_run.status = "waiting_confirmation"
            stage_run.finished_at = None
            stage_run.counts = self._stage_counts(db, stage_run)
            self._record_event(
                db,
                task,
                "entry_selection_required",
                "入口分析已完成，等待人工确认入口",
                stage_name=stage_run.stage_name,
                payload={"candidate_entry_count": len(candidate_entries)},
            )
            db.commit()
            return "success", {
                **summary,
                "entry_results": entry_results,
                "candidate_entry_count": len(candidate_entries),
                "selected_entry_count": 0,
                "requires_confirmation": True,
                "entry_selection": {
                    "mode": entry_mode,
                    "status": "waiting_confirmation",
                    "candidate_entries": candidate_entries,
                    "selected_entry_keys": [],
                    "selected_entries": [],
                    "confirmed_at": None,
                },
            }
        if entry_mode == ENTRY_SELECTION_MODE_AUTO:
            task.summary = {
                **(task.summary or {}),
                "entry_selection": {
                    "mode": entry_mode,
                    "status": "auto_selected",
                    "candidate_entries": candidate_entries,
                    "selected_entry_keys": [str(entry.get("entry_key") or "").strip() for entry in selected_entries if str(entry.get("entry_key") or "").strip()],
                    "selected_entries": self._mark_selected_entries(selected_entries, selected_by=ENTRY_SELECTION_MODE_AUTO),
                    "confirmed_at": _now().isoformat(),
                },
            }
            task.metrics = {
                **(task.metrics or {}),
                "candidate_entry_count": len(candidate_entries),
                "selected_entry_count": len(selected_entries),
                "entry_count": sum(len(entry.get("entries") or []) for entry in selected_entries if isinstance(entry, dict)),
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
        entries_url = self._knowledge_graph_entries_url(task) or (
            f"{self.cfg.services.knowledge_graph_entries.base_url.rstrip('/')}"
            f"{self.cfg.services.knowledge_graph_entries.entries_path}"
        )
        self._record_event(
            db,
            task,
            "knowledge_graph_entry_fetch_started",
            "开始拉取知识图谱源码入口",
            stage_name=stage_run.stage_name,
            payload={
                "provider": "knowledge_graph",
                "entries_url": entries_url,
            },
        )
        try:
            entries, meta = await self._fetch_knowledge_graph_entry_results(task)
        except Exception as exc:
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_fetch_failed",
                "知识图谱入口获取失败",
                level="error",
                stage_name=stage_run.stage_name,
                payload={
                    "provider": "knowledge_graph",
                    "entries_url": entries_url,
                    "raw_entry_count": 0,
                    "selected_entry_count": 0,
                    "filtered_out_count": 0,
                    "duration_ms": 0,
                    "error_message": str(exc),
                },
            )
            task.summary = {
                **(task.summary or {}),
                "knowledge_graph_entry_results": [],
                "entry_results": [],
            }
            task.metrics = {
                **(task.metrics or {}),
                **STAGE_METRIC_RESETTERS["knowledge_graph_entry_fetch"],
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
            }
            self._persist_stage_run_output_summary(task, stage_run, failure_summary)
            return "failed", failure_summary
        if not entries:
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_fetch_empty",
                "知识图谱入口结果为空",
                level="warning",
                stage_name=stage_run.stage_name,
                payload={
                    "provider": "knowledge_graph",
                    **meta,
                },
            )
            task.summary = {
                **(task.summary or {}),
                "knowledge_graph_entry_results": [],
                "entry_results": [],
            }
            task.metrics = {
                **(task.metrics or {}),
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": 0,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                "candidate_entry_count": 0,
                "selected_entry_count": 0,
                "entry_count": 0,
            }
            failure_summary = {
                "error": "知识图谱入口结果为空",
                "items": [],
                "success_count": 0,
                "failed_count": 1,
                "candidate_entry_count": 0,
                "selected_entry_count": 0,
                "entry_count": 0,
                "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
                "knowledge_graph_selected_entry_count": 0,
                "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
                **meta,
            }
            self._persist_stage_run_output_summary(task, stage_run, failure_summary)
            return "failed", failure_summary
        compact_entries = [
            {
                **entry,
                "entries": [dict(entry)],
            }
            for entry in entries
        ]
        task.summary = {
            **(task.summary or {}),
            "knowledge_graph_entry_results": entries,
            "entry_results": compact_entries,
        }
        task.metrics = {
            **(task.metrics or {}),
            "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
            "knowledge_graph_selected_entry_count": int(meta.get("selected_entry_count") or 0),
            "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
            "candidate_entry_count": int(meta.get("selected_entry_count") or 0),
            "selected_entry_count": int(meta.get("selected_entry_count") or 0),
            "entry_count": int(meta.get("selected_entry_count") or 0),
        }
        self._record_event(
            db,
            task,
            "knowledge_graph_entry_fetch_succeeded",
            "知识图谱入口获取成功",
            stage_name=stage_run.stage_name,
            payload={
                "provider": "knowledge_graph",
                **meta,
            },
        )
        success_summary = {
            "items": compact_entries,
            "success_count": len(entries),
            "failed_count": 0,
            "candidate_entry_count": len(entries),
            "selected_entry_count": len(entries),
            "entry_count": len(entries),
            "knowledge_graph_raw_entry_count": int(meta.get("raw_entry_count") or 0),
            "knowledge_graph_selected_entry_count": int(meta.get("selected_entry_count") or 0),
            "knowledge_graph_filtered_out_count": int(meta.get("filtered_out_count") or 0),
            "entry_results": compact_entries,
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
        entry_results = self._effective_entry_inputs(task)
        if not entry_results:
            self._rebuild_entry_results_from_stage_items(db, task)
            entry_results = self._effective_entry_inputs(task)
        entries: list[dict[str, Any]] = []
        for result in entry_results:
            entries.extend(result.get("entries", []))
        entries = _deduplicate_entry_keys(entries)
        if not entries:
            return "failed", {"error": "没有可用于数据流漏洞挖掘的入口"}
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
            retries=int(task.policy.get("max_retries_per_item") or 0),
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
