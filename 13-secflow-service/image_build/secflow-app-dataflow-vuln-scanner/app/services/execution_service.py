from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import posixpath
import re
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi.encoders import jsonable_encoder
from fastapi import HTTPException, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.artifacts.io import abs_path, ensure_dir, sanitize_name, write_json, write_task_manifest, write_text
from app.config import get_config
from app.models.contracts import TaskItem, TaskManifest
from app.models.database import (
    DfvsTaskListProjection,
    RunIndex,
    RunIndexCycle,
    RunIndexFile,
    RunIndexGlobalReview,
    RunIndexRemovedResult,
    RunIndexResult,
    RunIndexResultReview,
    RunIndexSession,
    SchedulerWorkerSlotReservation,
    TriggerTask,
    VulnReportSubmission,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.observability.service_ops import observe_service_operation
from app.pi_vuln_core.review.profile import apply_profile_runtime_policy_to_config
from app.pi_vuln_core.runner import build_runtime_framework_config, run_framework_config
from app.pi_vuln_core.utils.logger import attach_log_file, detach_log_file
from app.pi_vuln_core.utils.win_compat import ensure_event_loop_policy
from app.schemas import (
    ActiveTaskReconcileResponse,
    ArtifactRef,
    CreateEvolutionTaskRequest,
    DataflowAgentStateDirResponse,
    DataflowInputRef,
    DataflowTaskTimelineActionResponse,
    DataflowTaskTimelineEvent,
    DataflowTaskTimelineResponse,
    ReplayReadyResponse,
    RunRetryRequest,
    ScanTaskAttemptResponse,
    ScanTaskCreateRequest,
    ScanTaskDetailResponse,
    ScanTaskListItemResponse,
    ScanTaskListResponse,
    ScanTaskProjectionRepairResponse,
    ScanTaskResponse,
    ScanTaskStatsResponse,
    TriggerTaskInputTask,
)
from app.services.fileserver_client import get_fileserver_client
from app.services.llm_provider_sync import sync_providers_to_pi
from app.services.run_index_service import (
    _load_externalized_json_payload,
    _load_externalized_mapping_payload,
    get_run_index_service,
)
from app.services.run_state import is_run_active, is_run_queued, is_run_terminal
from app.services.task_state import (
    derive_task_control_state,
    is_canonical_task_active,
    normalize_canonical_task_status,
    normalize_public_task_status,
    public_task_status_matches_filter,
    resolve_public_task_state,
)
from app.services.dataflow_worker_client import DataflowWorkerError, get_dataflow_worker_client
from app.services.pi_vuln_adapter import (
    DbExecutionObserver,
    DbExecutionRecorder,
    build_core_tasks,
    write_final_task_manifest,
)
from app.services.vuln_reporter import get_task_vuln_report_status, get_vuln_report_service
from app.services.workflow_service import get_workflow_service
from app.time_utils import UTC_PLUS_8, isoformat_local, now_local


logger = logging.getLogger("dataflow_vuln.execution")


def _perf_elapsed_ms(started_at: float) -> float:
    return round((time.perf_counter() - started_at) * 1000, 2)


def _log_api_timing(endpoint: str, **fields: Any) -> None:
    parts = []
    for key, value in fields.items():
        if isinstance(value, float):
            parts.append(f"{key}={value:.2f}")
        else:
            parts.append(f"{key}={value}")
    logger.info("api_timing endpoint=%s %s", endpoint, " ".join(parts))


_TASK_PURPOSE_LABELS = {
    "normal": "正常任务",
    "evolution": "进化任务",
}

_RUNTIME_RECONCILED_FAILURE_MESSAGES = {
    "stale active runtime assumed failed",
    "runtime heartbeat lost; assumed failed",
}


def _is_runtime_reconciled_failure_message(message: str | None) -> bool:
    return str(message or "").strip().lower() in _RUNTIME_RECONCILED_FAILURE_MESSAGES
_CANONICAL_TASK_STATUSES = {"pending", "running", "succeeded", "failed", "cancelled"}

_TASK_LIST_SORT_COLUMNS = {
    "created_at": DfvsTaskListProjection.created_at,
    "updated_at": DfvsTaskListProjection.updated_at,
    "started_at": DfvsTaskListProjection.started_at,
    "finished_at": DfvsTaskListProjection.finished_at,
    "priority": DfvsTaskListProjection.priority,
    "public_status": DfvsTaskListProjection.public_status,
    "status": DfvsTaskListProjection.public_status,
}

_ACTIVE_RECONCILE_TRIGGER_STATUSES = {"running", "cancel_requested", "delete_requested", "dispatching"}
_ACTIVE_RECONCILE_EXECUTION_STATUSES = {"running", "cancel_requested", "delete_requested", "dispatching", "starting", "pending"}
_ACTIVE_RECONCILE_RUN_INDEX_STATUSES = {"running", "pending", "queued", "dispatching", "starting", "cancel_requested", "delete_requested"}

_TIMELINE_STAGE_LABELS = {
    "dispatch": "调度/分发",
    "worker_dispatch": "调度/分发",
    "worker_dispatch_prepare": "调度/分发",
    "worker_dispatch_result": "调度/分发",
    "prepare": "运行准备",
    "bootstrap": "运行准备",
    "initialization": "运行准备",
    "atomic_cycle": "原子分析循环",
    "cycle": "原子分析循环",
    "summary": "Summary",
    "plugin": "Plugin",
    "global_review": "Global Review",
    "result_review": "Result Review",
    "completion": "完成/收尾",
    "cancel": "取消",
    "abnormal": "异常",
}

def _normalize_timeline_stage_name(stage_key: str | None, payload: dict[str, Any] | None = None) -> str | None:
    raw_stage = str(stage_key or "").strip()
    payload_dict = payload if isinstance(payload, dict) else {}
    payload_stage = (
        str(payload_dict.get("stage_name") or payload_dict.get("stage") or payload_dict.get("stage_id") or "").strip()
    )
    if payload_stage:
        return payload_stage
    if not raw_stage:
        return None
    lowered = raw_stage.lower()
    for prefix, label in _TIMELINE_STAGE_LABELS.items():
        if lowered == prefix or lowered.startswith(f"{prefix}_"):
            return label
    return raw_stage


def _abnormal_evidence(key: str, label: str, value: object) -> dict | None:
    text = str(value or "").strip()
    if not text:
        return None
    return {"key": key, "label": label, "value": text}


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _sanitize_dataflow_run_name(value: str) -> str:
    cleaned = re.sub(r"\s+", "-", str(value or "").strip())
    cleaned = re.sub(r"[\\/:\0]+", "-", cleaned)
    cleaned = re.sub(r"[^\w.-]+", "-", cleaned, flags=re.UNICODE).strip("-.")
    if cleaned in {"", ".", ".."}:
        return "item"
    return cleaned


def _principal_id(principal: dict) -> str:
    return principal.get("user_id") or principal.get("subject") or principal.get("client_id") or "system"


def _project_ids(principal: dict) -> set[str]:
    return set(principal.get("project_ids") or [])


_RETRYABLE_RUN_INDEX_STATUSES = {
    "cancelled",
    "failed",
    "interrupted",
    "stopped",
    "review_error",
    "review_plateau",
    "summary_incomplete",
    "runtime_output_limit",
    "runtime_timeout",
    "blocked_context_window",
    "blocked_quota",
    "provider_rate_limited",
    "model_contract_violation",
    "blocked_external_source",
    "error",
}


def _canonical_task_status(value: str | None) -> str:
    return normalize_canonical_task_status(value)


def _public_task_status(value: str | None) -> str:
    return normalize_public_task_status(value)


def _is_control_message(message: str | None) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    return text in {
        "cancel requested",
        "run cancel requested",
        "delete requested",
        "delete requested; stopping run_vuln_scan.py",
        "run delete requested; worker unreachable",
        "run_vuln_scan.py running",
        "execution running",
        "running",
    } or text.endswith("before dispatch")


def _preferred_abnormal_message(
    *,
    trigger_message: str | None,
    execution_message: str | None,
    dispatch_error: str | None,
    run_error: str | None,
) -> str:
    for candidate in (
        dispatch_error,
        run_error,
        execution_message,
        trigger_message,
    ):
        text = str(candidate or "").strip()
        if not text:
            continue
        if _is_control_message(text):
            continue
        return text
    return ""


def _canonical_task_status(value: str | None) -> str:
    return normalize_canonical_task_status(value)


def _public_task_status(value: str | None) -> str:
    return normalize_public_task_status(value)


def _is_control_message(message: str | None) -> bool:
    text = str(message or "").strip().lower()
    if not text:
        return False
    return text in {
        "cancel requested",
        "run cancel requested",
        "delete requested",
        "delete requested; stopping run_vuln_scan.py",
        "run delete requested; worker unreachable",
        "run_vuln_scan.py running",
        "execution running",
        "running",
    } or text.endswith("before dispatch")


def _preferred_abnormal_message(
    *,
    trigger_message: str | None,
    execution_message: str | None,
    dispatch_error: str | None,
    run_error: str | None,
) -> str:
    for candidate in (
        dispatch_error,
        run_error,
        execution_message,
        trigger_message,
    ):
        text = str(candidate or "").strip()
        if not text:
            continue
        if _is_control_message(text):
            continue
        return text
    return ""


def _command_display(args: list[str]) -> str:
    return " ".join(shlex.quote(str(item)) for item in args)


class ExecutionService:
    def __init__(self) -> None:
        self._process_lock = threading.RLock()
        self._active_cli_processes: dict[str, subprocess.Popen] = {}

    def _ensure_project_access(self, principal: dict, project_id: str) -> None:
        project_ids = _project_ids(principal)
        if project_ids and project_id not in project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project access denied")

    def _definition_or_404(self, db: Session, definition_id: str) -> WorkflowDefinition:
        definition = db.get(WorkflowDefinition, definition_id)
        if definition is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition not found")
        return definition

    def _definition_version_or_404(self, db: Session, version_id: str | None) -> WorkflowDefinitionVersion:
        if not version_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition version not found")
        version = db.get(WorkflowDefinitionVersion, version_id)
        if version is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition version not found")
        return version

    def _trigger_or_404(self, db: Session, trigger_task_id: str) -> TriggerTask:
        trigger = db.get(TriggerTask, trigger_task_id)
        if trigger is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="trigger task not found")
        return trigger

    def _execution_or_404(self, db: Session, execution_id: str) -> WorkflowExecution:
        execution = db.get(WorkflowExecution, execution_id)
        if execution is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution not found")
        return execution

    def _latest_execution_for_trigger(self, db: Session, trigger_id: str) -> WorkflowExecution | None:
        return (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger_id)
            .order_by(WorkflowExecution.attempt_no.desc(), WorkflowExecution.created_at.desc())
            .first()
        )

    def _list_executions_for_trigger(self, db: Session, trigger_id: str) -> list[WorkflowExecution]:
        return (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger_id)
            .order_by(WorkflowExecution.attempt_no.asc(), WorkflowExecution.created_at.asc())
            .all()
        )

    def _trigger_title(self, trigger: TriggerTask) -> str:
        try:
            manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        except Exception:
            return trigger.id
        first_task = manifest.tasks[0] if manifest.tasks else None
        return str(first_task.title or trigger.id) if first_task else trigger.id

    def _trigger_task_metadata(self, trigger: TriggerTask | None) -> dict[str, Any]:
        if trigger is None:
            return {}
        try:
            manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        except Exception:
            return {}
        first_task = manifest.tasks[0] if manifest.tasks else None
        return dict(first_task.metadata or {}) if first_task else {}

    def _task_abnormal_reason(self, trigger: TriggerTask, execution: WorkflowExecution | None, run_summary: dict[str, Any] | None = None) -> dict[str, Any] | None:
        status_value = str(trigger.status or "").strip().lower()
        if status_value not in {"failed", "cancelled", "interrupted", "error"}:
            return None
        if isinstance(trigger.latest_abnormal_reason_json, dict):
            return dict(trigger.latest_abnormal_reason_json)
        run_summary = run_summary or {}
        run_status = str(run_summary.get("status") or "").strip()
        run_error = str(run_summary.get("error") or "").strip()
        trigger_message = str(trigger.message or "").strip()
        execution_message = str(execution.message or "").strip() if execution is not None else ""
        dispatch_error = str(execution.dispatch_error or "").strip() if execution is not None else ""
        message = _preferred_abnormal_message(
            trigger_message=trigger_message,
            execution_message=execution_message,
            dispatch_error=dispatch_error,
            run_error=run_error,
        )
        if status_value == "cancelled":
            code, category, title = "user_cancelled", "cancel", "任务已取消"
        elif execution is not None and str(execution.dispatch_status or "").strip().lower() == "failed":
            code, category, title = "dispatch_failed", "runtime", "调度失败"
        elif execution is not None and str(execution.process_status or "").strip().lower() in {"cancelled", "interrupted", "killed"}:
            code, category, title = "runtime_interrupted", "runtime", "运行时中断"
        elif run_status in {"failed", "error", "runtime_timeout", "provider_rate_limited", "blocked_quota"}:
            code, category, title = "downstream_failed", "downstream", "扫描执行失败"
        else:
            code, category, title = "unknown_abnormal", "orchestration", "任务异常结束"
        return {
            "is_abnormal": True,
            "category": category,
            "code": code,
            "title": title,
            "message": message or "任务以非正常状态结束。",
            "terminal": True,
            "source_layer": "task",
            "status": status_value,
            "service": "dataflow-vuln-scanner",
            "stage_name": str(execution.current_stage_id if execution is not None else "").strip() or None,
            "item_key": None,
            "downstream_task_id": execution.id if execution is not None else None,
            "downstream_service": "workflow_execution" if execution is not None else None,
            "first_seen_at": isoformat_local(trigger.started_at),
            "last_seen_at": isoformat_local(trigger.finished_at or trigger.updated_at),
            "evidence": [
                item for item in [
                    _abnormal_evidence("task_status", "任务状态", trigger.status),
                    _abnormal_evidence("dispatch_status", "调度状态", execution.dispatch_status if execution is not None else None),
                    _abnormal_evidence("process_status", "进程状态", execution.process_status if execution is not None else None),
                    _abnormal_evidence("run_status", "运行摘要状态", run_status),
                    _abnormal_evidence("error", "原始错误", message or dispatch_error or run_error),
                ] if item is not None
            ],
            "recommended_action": "查看最近一次 execution、run summary 和 dispatch_error，确认是调度失败、运行时中断还是扫描执行本身失败。",
            "related_event_ids": [],
        }

    def _abnormal_reason_history(self, db: Session, trigger: TriggerTask) -> list[dict[str, Any]]:
        execution_ids = [item.id for item in self._list_executions_for_trigger(db, trigger.id)]
        if not execution_ids:
            return []
        rows = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id.in_(execution_ids),
                WorkflowExecutionEvent.event_type == "abnormal_reason_recorded",
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .limit(10)
            .all()
        )
        history: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row.payload_json or {})
            reason = payload.get("reason") if isinstance(payload.get("reason"), dict) else None
            if not isinstance(reason, dict):
                continue
            history.append(
                {
                    "event_id": row.id,
                    "created_at": row.created_at,
                    "reason": reason,
                }
            )
        return history

    def _sync_trigger_abnormal_reason(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        execution: WorkflowExecution | None,
        run_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        reason = self._task_abnormal_reason(trigger, execution, run_summary)
        next_payload = dict(reason) if isinstance(reason, dict) else None
        previous_payload = trigger.latest_abnormal_reason_json if isinstance(trigger.latest_abnormal_reason_json, dict) else None
        trigger.latest_abnormal_reason_json = next_payload
        if reason is None or previous_payload == next_payload or execution is None:
            return next_payload
        db.add(
            WorkflowExecutionEvent(
                id=_new_id("evt"),
                execution_id=execution.id,
                event_type="abnormal_reason_recorded",
                level="warning" if reason.get("status") == "cancelled" else "error",
                message=str(reason.get("title") or "任务异常结束"),
                payload_json={"reason": next_payload},
            )
        )
        return next_payload

    def _normalize_task_purpose(self, value: str | None) -> str:
        normalized = str(value or "").strip().lower()
        return normalized if normalized in {"normal", "evolution"} else "normal"

    def _task_derivation_metadata(self, metadata: dict[str, Any] | None) -> dict[str, Any]:
        payload = metadata.get("derivation") if isinstance(metadata, dict) else None
        return dict(payload) if isinstance(payload, dict) else {}

    def _first_manifest_task_payload(self, trigger: TriggerTask | None) -> dict[str, Any]:
        if trigger is None:
            return {}
        payload = trigger.input_tasks_json
        if not isinstance(payload, dict):
            return {}
        tasks = payload.get("tasks")
        if not isinstance(tasks, list):
            return {}
        first_task = next((item for item in tasks if isinstance(item, dict)), None)
        return dict(first_task or {})

    @staticmethod
    def _task_metadata_from_manifest_payload(first_task: dict[str, Any] | None) -> dict[str, Any]:
        metadata = first_task.get("metadata") if isinstance(first_task, dict) else None
        return dict(metadata) if isinstance(metadata, dict) else {}

    @staticmethod
    def _task_title_from_manifest_payload(first_task: dict[str, Any] | None, fallback: str) -> str:
        if isinstance(first_task, dict):
            title = str(first_task.get("title") or "").strip()
            if title:
                return title
        return fallback

    @staticmethod
    def _task_origin_label(task_origin_type: str | None, parent_task_type: str | None) -> str:
        normalized_origin = str(task_origin_type or "").strip() or "manual"
        normalized_parent_type = str(parent_task_type or "").strip() or None
        if normalized_origin == "binary_security" and normalized_parent_type == "source":
            return "二进制安全-源码扫描"
        if normalized_origin == "binary_security":
            return "二进制安全-二进制类扫描"
        return "手动任务"

    @staticmethod
    def _extract_review_profile_from_config(config: dict[str, Any] | None) -> str:
        payload = config if isinstance(config, dict) else {}
        for workflow in ((payload.get("workflows") or {}).get("atomic") or []):
            if not isinstance(workflow, dict):
                continue
            engine = workflow.get("engine")
            if isinstance(engine, dict) and (engine.get("review_profile") or workflow.get("id") == "vuln_scan"):
                return str(engine.get("review_profile") or "").strip()
        return ""

    @staticmethod
    def _extract_worker_runtime_defaults(config: dict[str, Any] | None) -> tuple[str, str]:
        payload = config if isinstance(config, dict) else {}
        for agent in payload.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            if str(agent.get("id") or "").strip() != "pi-worker":
                continue
            runtime_config = agent.get("runtime_config") if isinstance(agent.get("runtime_config"), dict) else {}
            sdk_specific = runtime_config.get("sdk_specific") if isinstance(runtime_config.get("sdk_specific"), dict) else {}
            return (
                str(runtime_config.get("model") or "").strip(),
                str(sdk_specific.get("thinking") or "").strip(),
            )
        return "", ""

    @staticmethod
    def _extract_max_review_cycles_from_config(config: dict[str, Any] | None) -> int:
        payload = config if isinstance(config, dict) else {}
        global_cycles = (payload.get("global") or {}).get("max_review_cycles")
        try:
            parsed = int(global_cycles)
        except (TypeError, ValueError):
            parsed = 0
        return parsed if parsed > 0 else 0

    def _planned_run_root_from_task_metadata(self, *, project_id: str, metadata: dict[str, Any] | None) -> Path | None:
        payload = metadata if isinstance(metadata, dict) else {}
        plan = payload.get("dataflow_cli") if isinstance(payload.get("dataflow_cli"), dict) else {}
        raw_run_dir = str(plan.get("run_dir") or "").strip()
        if not raw_run_dir:
            request = payload.get("dataflow_scan_request") if isinstance(payload.get("dataflow_scan_request"), dict) else {}
            raw_run_dir = str(request.get("resume_run_dir") or "").strip()
        if not raw_run_dir:
            return None
        candidate = Path(raw_run_dir)
        if not candidate.is_absolute():
            return None
        try:
            return self._ensure_path_within(path=candidate, root=self._project_files_root(project_id), label="run_dir")
        except Exception:
            return None

    def _run_locator_from_task_context(
        self,
        *,
        project_id: str,
        metadata: dict[str, Any] | None,
        execution: WorkflowExecution | None,
        run_index: RunIndex | None,
    ) -> dict[str, str | None]:
        if run_index is not None:
            run_path = str(run_index.run_root_path or "").strip()
            if run_path:
                return {
                    "run_name": str(run_index.run_name or Path(run_path).name),
                    "runs_root": str(Path(run_path).parent),
                    "run_path": run_path,
                }
        if execution is not None and execution.workspace_root:
            run_root = Path(execution.workspace_root).resolve()
        else:
            run_root = self._planned_run_root_from_task_metadata(project_id=project_id, metadata=metadata)
        if run_root is None:
            return {"run_name": None, "runs_root": None, "run_path": None}
        return {
            "run_name": run_root.name,
            "runs_root": str(run_root.parent),
            "run_path": str(run_root),
        }

    @staticmethod
    def _vuln_report_status_from_counts(*, enabled: bool, counts: dict[str, int] | None) -> dict[str, Any]:
        if not enabled:
            return {"status": "disabled", "enabled": False, "total": 0, "reported": 0, "failed": 0, "pending": 0, "items": []}
        bucket = counts or {}
        total = int(bucket.get("total") or 0)
        reported = int(bucket.get("reported") or 0)
        failed = int(bucket.get("failed") or 0)
        pending = int(bucket.get("pending") or 0)
        if total == 0:
            status_text = "not_started"
        elif failed and reported:
            status_text = "partial_failed"
        elif failed:
            status_text = "failed"
        elif reported == total:
            status_text = "reported"
        else:
            status_text = "pending"
        return {
            "enabled": True,
            "status": status_text,
            "total": total,
            "reported": reported,
            "failed": failed,
            "pending": pending,
            "items": [],
        }

    def _task_effective_profile_id(self, trigger: TriggerTask) -> str:
        return str(trigger.profile_id or trigger.workflow_definition_id or "").strip()

    def _task_origin_mode(self, trigger: TriggerTask) -> str:
        task_origin_type = str(trigger.task_origin_type or "").strip().lower()
        parent_task_type = str(trigger.parent_task_type or "").strip().lower()
        if task_origin_type == "binary_security" and parent_task_type == "source":
            return "source"
        if task_origin_type == "binary_security":
            return "binary"
        return "manual"

    def _task_origin_label(self, trigger: TriggerTask) -> str:
        origin_mode = self._task_origin_mode(trigger)
        if origin_mode == "source":
            return "二进制安全-源码扫描"
        if origin_mode == "binary":
            return "二进制安全-二进制类扫描"
        return "手动任务"

    def _projection_run_summary(self, row: DfvsTaskListProjection) -> dict[str, Any]:
        if not row.latest_run_id and not row.run_name and not row.latest_run_status:
            return {}
        return {
            "run_id": row.latest_run_id,
            "status": row.latest_run_status,
            "model": row.run_model,
            "provider": row.run_provider,
            "thinking": row.run_thinking,
            "max_cycles": row.run_max_cycles,
            "cycles_used": row.run_cycles_used,
            "result_count": row.run_result_count,
            "passed_count": row.run_passed_count,
            "failed_count": row.run_failed_count,
            "workflow_mode": row.run_workflow_mode,
            "review_profile": "",
            "duration_seconds": row.run_duration_seconds,
            "start_epoch": row.run_start_epoch,
            "name": row.run_name,
            "root_path": row.runs_root,
            "path": row.run_path,
            "linked_task_id": row.task_id,
            "linked_execution_id": row.latest_execution_id,
        }

    def _projection_vuln_report_status(self, row: DfvsTaskListProjection) -> dict[str, Any]:
        return {
            "enabled": bool(row.vuln_report_enabled),
            "status": row.vuln_report_status,
            "total": int(row.vuln_report_total or 0),
            "reported": int(row.vuln_report_reported or 0),
            "failed": int(row.vuln_report_failed or 0),
            "pending": int(row.vuln_report_pending or 0),
            "items": [],
        }

    def _projection_to_task_list_item(self, row: DfvsTaskListProjection) -> ScanTaskListItemResponse:
        run_summary = self._projection_run_summary(row)
        return ScanTaskListItemResponse(
            task_id=row.task_id,
            project_id=row.project_id,
            task_purpose=self._normalize_task_purpose(row.task_purpose),
            task_origin_type=row.task_origin_type,
            parent_task_id=row.parent_task_id,
            parent_task_type=row.parent_task_type,
            parent_stage_name=row.parent_stage_name,
            parent_stage_item_id=row.parent_stage_item_id,
            parent_stage_item_key=row.parent_stage_item_key,
            origin_mode=row.origin_mode if row.origin_mode in {"manual", "binary", "source"} else "manual",
            origin_label=row.origin_label,
            parent_task_display=row.parent_task_display,
            profile_id=row.profile_id,
            profile_version=int(row.profile_version or 0),
            title=row.title or "",
            status=row.public_status,
            control_state=row.control_state or "none",
            latest_attempt_no=int(row.latest_attempt_no or 0),
            priority=int(row.priority or 0),
            created_by=row.created_by or "",
            created_at=row.created_at,
            started_at=row.started_at,
            finished_at=row.finished_at,
            updated_at=row.updated_at,
            message=row.message,
            latest_execution_id=row.latest_execution_id,
            owner_pod_id=row.owner_pod_id,
            dispatch_status=row.dispatch_status,
            slot_binding_state=row.slot_binding_state,
            slot_binding_reason=row.slot_binding_reason,
            latest_run_id=row.latest_run_id,
            latest_run_status=row.latest_run_status,
            run_name=row.run_name,
            runs_root=row.runs_root,
            run_path=row.run_path,
            run=run_summary,
            latest_run=run_summary,
            auto_report_vulnerabilities=bool(row.auto_report_vulnerabilities),
            vuln_report_status=self._projection_vuln_report_status(row),
            abnormal_reason_title=row.abnormal_reason_title,
            abnormal_reason_code=row.abnormal_reason_code,
            abnormal_reason_category=row.abnormal_reason_category,
        )

    def _run_summary_snapshot(
        self,
        *,
        run_index: RunIndex | None,
        latest_execution: WorkflowExecution | None,
    ) -> dict[str, Any]:
        if run_index is None:
            return {}
        return {
            "run_id": run_index.id,
            "status": get_run_index_service().normalized_run_status(run_index),
            "model": run_index.model,
            "provider": run_index.provider,
            "thinking": run_index.thinking,
            "max_cycles": run_index.max_cycles,
            "cycles_used": run_index.cycles_used,
            "result_count": run_index.result_count,
            "passed_count": run_index.passed_count,
            "failed_count": run_index.failed_count,
            "workflow_mode": run_index.workflow_mode,
            "duration_seconds": run_index.duration_seconds,
            "start_epoch": int(run_index.started_at.timestamp()) if run_index.started_at else None,
            "started_at": run_index.started_at,
            "finished_at": run_index.finished_at,
            "linked_execution_id": str(latest_execution.id) if latest_execution is not None else None,
        }

    def _vuln_report_counts_for_task_ids(self, db: Session, task_ids: list[str]) -> dict[str, dict[str, int]]:
        normalized_ids = [str(task_id or "").strip() for task_id in task_ids if str(task_id or "").strip()]
        if not normalized_ids:
            return {}
        rows = (
            db.query(
                VulnReportSubmission.task_id,
                VulnReportSubmission.status,
                func.count(VulnReportSubmission.id),
            )
            .filter(VulnReportSubmission.task_id.in_(normalized_ids))
            .group_by(VulnReportSubmission.task_id, VulnReportSubmission.status)
            .all()
        )
        counts_by_task: dict[str, dict[str, int]] = {task_id: {"total": 0, "reported": 0, "failed": 0, "pending": 0} for task_id in normalized_ids}
        for task_id, status, count in rows:
            bucket = counts_by_task.setdefault(str(task_id), {"total": 0, "reported": 0, "failed": 0, "pending": 0})
            bucket["total"] += int(count or 0)
            status_value = str(status or "").strip().lower()
            if status_value == "reported":
                bucket["reported"] += int(count or 0)
            elif status_value == "failed":
                bucket["failed"] += int(count or 0)
            else:
                bucket["pending"] += int(count or 0)
        return counts_by_task

    def _rebuild_task_list_projections(self, db: Session, triggers: list[TriggerTask]) -> None:
        if not triggers:
            return
        latest_execution_map = self._build_latest_execution_map(db, triggers)
        run_index_map = self._build_lightweight_run_index_map(db, triggers, latest_execution_map)
        report_counts_by_task = self._vuln_report_counts_for_task_ids(db, [str(item.id) for item in triggers])

        version_by_id: dict[str, WorkflowDefinitionVersion] = {}
        explicit_version_ids = [str(item.workflow_definition_version_id) for item in triggers if item.workflow_definition_version_id]
        if explicit_version_ids:
            version_rows = (
                db.query(WorkflowDefinitionVersion)
                .filter(WorkflowDefinitionVersion.id.in_(explicit_version_ids))
                .all()
            )
            version_by_id = {str(item.id): item for item in version_rows}

        fallback_version_no_by_definition: dict[str, int] = {}
        for trigger in triggers:
            if trigger.workflow_definition_version_id:
                continue
            definition_id = str(trigger.workflow_definition_id or "").strip()
            if not definition_id or definition_id in fallback_version_no_by_definition:
                continue
            latest_version = (
                db.query(WorkflowDefinitionVersion)
                .filter(WorkflowDefinitionVersion.workflow_definition_id == definition_id)
                .order_by(WorkflowDefinitionVersion.version_no.desc(), WorkflowDefinitionVersion.created_at.desc())
                .first()
            )
            fallback_version_no_by_definition[definition_id] = int(latest_version.version_no if latest_version is not None else 0)

        for trigger in triggers:
            latest_execution = latest_execution_map.get(str(trigger.id))
            run_index = run_index_map.get(str(trigger.id))
            run_summary = self._run_summary_snapshot(run_index=run_index, latest_execution=latest_execution)
            run_locator = self._run_locator_for_execution(latest_execution, trigger)
            effective_status, effective_message, effective_started_at, effective_finished_at = self._effective_scan_task_runtime_state(
                trigger=trigger,
                execution=latest_execution,
                run_summary=run_summary,
            )
            control_state = derive_task_control_state(
                dispatch_status=latest_execution.dispatch_status if latest_execution is not None else None,
                process_status=latest_execution.process_status if latest_execution is not None else None,
                trigger_message=trigger.message,
                execution_message=latest_execution.message if latest_execution is not None else None,
            )
            slot_binding_state, slot_binding_reason = self._slot_binding_state(
                execution=latest_execution,
                effective_status=effective_status,
            )
            abnormal_reason = self._task_abnormal_reason(trigger, latest_execution, run_summary)
            report_status = self._vuln_report_status_from_counts(
                enabled=bool(self._trigger_task_metadata(trigger).get("auto_report_vulnerabilities", True)),
                counts=report_counts_by_task.get(str(trigger.id)),
            )
            row = db.get(DfvsTaskListProjection, trigger.id)
            if row is None:
                row = DfvsTaskListProjection(task_id=trigger.id)
            row.project_id = trigger.project_id
            row.title = self._trigger_title(trigger)
            row.profile_id = self._task_effective_profile_id(trigger)
            if trigger.workflow_definition_version_id:
                version = version_by_id.get(str(trigger.workflow_definition_version_id))
                row.profile_version = int(version.version_no if version is not None else 0)
            else:
                row.profile_version = int(fallback_version_no_by_definition.get(str(trigger.workflow_definition_id or "").strip(), 0))
            row.priority = int(trigger.priority or 0)
            row.created_by = str(trigger.submitted_by or "").strip()
            row.task_purpose = self._normalize_task_purpose(getattr(trigger, "task_purpose", None))
            row.task_origin_type = str(trigger.task_origin_type or "").strip() or "manual"
            row.parent_task_id = trigger.parent_task_id
            row.parent_task_type = trigger.parent_task_type
            row.parent_stage_name = trigger.parent_stage_name
            row.parent_stage_item_id = trigger.parent_stage_item_id
            row.parent_stage_item_key = trigger.parent_stage_item_key
            row.origin_mode = self._task_origin_mode(trigger)
            row.origin_label = self._task_origin_label(trigger)
            row.parent_task_display = trigger.parent_task_id
            row.public_status = effective_status
            row.control_state = control_state
            row.message = effective_message
            row.abnormal_reason_title = str(abnormal_reason.get("title") or "").strip() or None if abnormal_reason else None
            row.abnormal_reason_code = str(abnormal_reason.get("code") or "").strip() or None if abnormal_reason else None
            row.abnormal_reason_category = str(abnormal_reason.get("category") or "").strip() or None if abnormal_reason else None
            row.latest_execution_id = latest_execution.id if latest_execution is not None else trigger.latest_execution_id
            row.latest_attempt_no = int(latest_execution.attempt_no if latest_execution is not None else 0)
            row.owner_pod_id = latest_execution.owner_pod_id if latest_execution is not None else None
            row.dispatch_status = latest_execution.dispatch_status if latest_execution is not None else None
            row.slot_binding_state = slot_binding_state
            row.slot_binding_reason = slot_binding_reason
            row.latest_run_id = run_index.id if run_index is not None else None
            row.latest_run_status = str(run_summary.get("status") or "").strip() or None
            row.run_name = (str(run_index.run_name or "").strip() if run_index is not None else "") or run_locator.get("run_name")
            row.run_path = (str(run_index.run_root_path or "").strip() if run_index is not None else "") or run_locator.get("run_path")
            row.runs_root = (
                str(Path(run_index.run_root_path).parent) if run_index is not None and run_index.run_root_path
                else run_locator.get("runs_root")
            )
            row.run_model = str(run_index.model or "").strip() or None if run_index is not None else None
            row.run_provider = str(run_index.provider or "").strip() or None if run_index is not None else None
            row.run_thinking = str(run_index.thinking or "").strip() or None if run_index is not None else None
            row.run_workflow_mode = str(run_index.workflow_mode or "").strip() or None if run_index is not None else None
            row.run_max_cycles = int(run_index.max_cycles) if run_index is not None and run_index.max_cycles is not None else None
            row.run_cycles_used = int(run_index.cycles_used) if run_index is not None and run_index.cycles_used is not None else None
            row.run_result_count = int(run_index.result_count) if run_index is not None and run_index.result_count is not None else None
            row.run_passed_count = int(run_index.passed_count) if run_index is not None and run_index.passed_count is not None else None
            row.run_failed_count = int(run_index.failed_count) if run_index is not None and run_index.failed_count is not None else None
            row.run_duration_seconds = float(run_index.duration_seconds) if run_index is not None and run_index.duration_seconds is not None else None
            row.run_start_epoch = int(run_index.started_at.timestamp()) if run_index is not None and run_index.started_at else None
            row.auto_report_vulnerabilities = bool(report_status.get("enabled"))
            row.vuln_report_enabled = bool(report_status.get("enabled"))
            row.vuln_report_status = str(report_status.get("status") or "not_started")
            row.vuln_report_total = int(report_status.get("total") or 0)
            row.vuln_report_reported = int(report_status.get("reported") or 0)
            row.vuln_report_failed = int(report_status.get("failed") or 0)
            row.vuln_report_pending = int(report_status.get("pending") or 0)
            row.started_at = effective_started_at
            row.finished_at = effective_finished_at
            row.created_at = trigger.created_at
            row.updated_at = trigger.updated_at
            db.add(row)
        db.flush()

    def _backfill_missing_task_list_projections(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
        batch_size: int = 200,
    ) -> None:
        project_ids = _project_ids(principal)
        while True:
            query = (
                db.query(TriggerTask.id)
                .outerjoin(DfvsTaskListProjection, DfvsTaskListProjection.task_id == TriggerTask.id)
                .filter(DfvsTaskListProjection.task_id.is_(None))
            )
            if project_id:
                self._ensure_project_access(principal, project_id)
                query = query.filter(TriggerTask.project_id == project_id)
            elif project_ids:
                query = query.filter(TriggerTask.project_id.in_(project_ids))
            missing_ids = [str(task_id) for task_id, in query.order_by(TriggerTask.created_at.desc(), TriggerTask.id.desc()).limit(batch_size).all()]
            if not missing_ids:
                return
            triggers = (
                db.query(TriggerTask)
                .filter(TriggerTask.id.in_(missing_ids))
                .all()
            )
            self._rebuild_task_list_projections(db, triggers)
            db.commit()

    def _refresh_task_list_projection_for_task_id(self, db: Session, task_id: str | None) -> None:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return
        if not hasattr(db, "get"):
            return
        trigger = db.get(TriggerTask, normalized_task_id)
        if trigger is None:
            db.query(DfvsTaskListProjection).filter(DfvsTaskListProjection.task_id == normalized_task_id).delete()
            db.flush()
            return
        self._rebuild_task_list_projections(db, [trigger])

    def _refresh_task_list_projection_for_execution(self, db: Session, execution: WorkflowExecution | None) -> None:
        if execution is None:
            return
        self._refresh_task_list_projection_for_task_id(db, execution.trigger_task_id)

    def _active_reconcile_statuses(self, statuses: list[str] | None = None) -> tuple[set[str], set[str]]:
        normalized = {normalize_canonical_task_status(item) for item in (statuses or []) if str(item or "").strip()}
        if not normalized:
            return set(_ACTIVE_RECONCILE_TRIGGER_STATUSES), set(_ACTIVE_RECONCILE_EXECUTION_STATUSES)
        trigger_statuses = {item for item in normalized if item in _ACTIVE_RECONCILE_TRIGGER_STATUSES}
        execution_statuses = {item for item in normalized if item in _ACTIVE_RECONCILE_EXECUTION_STATUSES}
        return (
            trigger_statuses or set(_ACTIVE_RECONCILE_TRIGGER_STATUSES),
            execution_statuses or set(_ACTIVE_RECONCILE_EXECUTION_STATUSES),
        )

    def _active_reconcile_candidates(
        self,
        db: Session,
        *,
        project_id: str | None = None,
        statuses: list[str] | None = None,
        limit: int = 100,
    ) -> list[TriggerTask]:
        trigger_statuses, execution_statuses = self._active_reconcile_statuses(statuses)
        query = (
            db.query(TriggerTask)
            .outerjoin(DfvsTaskListProjection, DfvsTaskListProjection.task_id == TriggerTask.id)
            .outerjoin(WorkflowExecution, WorkflowExecution.id == TriggerTask.latest_execution_id)
            .outerjoin(RunIndex, RunIndex.linked_task_id == TriggerTask.id)
            .filter(
                or_(
                    TriggerTask.status.in_(tuple(trigger_statuses)),
                    WorkflowExecution.status.in_(tuple(execution_statuses)),
                    DfvsTaskListProjection.public_status.in_(tuple(trigger_statuses)),
                    RunIndex.status.in_(tuple(_ACTIVE_RECONCILE_RUN_INDEX_STATUSES)),
                )
            )
            .order_by(TriggerTask.updated_at.asc(), TriggerTask.created_at.asc(), TriggerTask.id.asc())
        )
        if project_id:
            query = query.filter(TriggerTask.project_id == project_id)
        return query.limit(max(1, int(limit or 100))).all()

    def _active_runtime_truth(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        execution: WorkflowExecution | None,
        run_index: RunIndex | None,
    ) -> dict[str, Any]:
        run_summary = self._run_summary_snapshot(run_index=run_index, latest_execution=execution)
        effective_status, _, _, _ = self._effective_scan_task_runtime_state(
            trigger=trigger,
            execution=execution,
            run_summary=run_summary,
        )
        process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution) if run_index is not None else {}
        local_process = self._local_cli_process(execution.id) if execution is not None else None
        orphaned_resolution = self._orphaned_control_request_resolution(
            trigger=trigger,
            execution=execution,
            local_process=local_process,
        )
        active_runtime = self._has_active_execution_runtime(execution=execution, local_process=local_process)
        if orphaned_resolution is not None:
            classification = "orphaned_delete_requested" if str(orphaned_resolution.get("event_type")) == "task_delete_reconciled" else "orphaned_cancel_requested"
        elif active_runtime or process_state.get("is_running"):
            classification = "actually_running"
        elif process_state.get("is_queued"):
            classification = "actually_queued"
        elif effective_status in {"failed", "cancelled", "success"}:
            classification = "actually_terminal"
        else:
            classification = "runtime_lost"
        return {
            "classification": classification,
            "effective_status": effective_status,
            "process_state": process_state,
            "orphaned_resolution": orphaned_resolution,
            "run_summary": run_summary,
        }

    def reconcile_active_tasks(
        self,
        db: Session,
        *,
        principal: dict | None = None,
        project_id: str | None = None,
        statuses: list[str] | None = None,
        limit: int = 100,
        dry_run: bool = False,
    ) -> ActiveTaskReconcileResponse:
        if principal is not None and project_id:
            self._ensure_project_access(principal, project_id)
        triggers = self._active_reconcile_candidates(db, project_id=project_id, statuses=statuses, limit=limit)
        reconciled_count = 0
        requeued_count = 0
        terminalized_count = 0
        projection_refreshed_count = 0
        sample_task_ids: list[str] = []
        for trigger in triggers:
            latest_execution = self._latest_execution_for_trigger(db, trigger.id)
            run_index = self._source_run_index_for_trigger(db, trigger, latest_execution)
            truth = self._active_runtime_truth(db, trigger=trigger, execution=latest_execution, run_index=run_index)
            classification = str(truth["classification"])
            effective_status = str(truth["effective_status"])
            process_state = truth["process_state"] if isinstance(truth["process_state"], dict) else {}
            projection_before = db.get(DfvsTaskListProjection, trigger.id)
            projection_status_before = str(projection_before.public_status or "") if projection_before is not None else ""
            projection_dispatch_before = str(projection_before.dispatch_status or "") if projection_before is not None else ""
            latest_dispatch = str(latest_execution.dispatch_status or "") if latest_execution is not None else ""
            effective_public_status = normalize_public_task_status(effective_status)
            projection_drift = (
                projection_before is None
                or projection_status_before != effective_public_status
                or projection_dispatch_before != latest_dispatch
            )
            needs_state_reconcile = classification in {
                "actually_terminal",
                "runtime_lost",
                "orphaned_cancel_requested",
                "orphaned_delete_requested",
            }
            run_index_drift = (
                run_index is not None
                and trigger is not None
                and _public_task_status(trigger.status) in {"success", "failed", "cancelled"}
                and _public_task_status(run_index.status) in _ACTIVE_RECONCILE_RUN_INDEX_STATUSES
            )
            if not needs_state_reconcile and not projection_drift and not run_index_drift:
                continue
            if dry_run:
                reconciled_count += 1
                if needs_state_reconcile:
                    terminalized_count += 1
                if projection_drift or run_index_drift:
                    projection_refreshed_count += 1
                if len(sample_task_ids) < 20:
                    sample_task_ids.append(trigger.id)
                continue
            changed = False
            if self._reconcile_stale_runtime(db, run_index=run_index, trigger=trigger, execution=latest_execution):
                changed = True
                terminalized_count += 1
            elif classification in {"orphaned_cancel_requested", "orphaned_delete_requested"} and truth.get("orphaned_resolution") is not None:
                self._finalize_orphaned_control_request(
                    db,
                    trigger=trigger,
                    execution=latest_execution,
                    resolution=truth["orphaned_resolution"],
                )
                changed = True
                terminalized_count += 1
            elif classification == "runtime_lost":
                self._mark_stale_runtime_exited(
                    db,
                    trigger=trigger,
                    execution=latest_execution,
                    message="stale active runtime assumed failed",
                )
                changed = True
                terminalized_count += 1
            if self._reconcile_stale_run_index_to_terminal_task(
                db,
                run_index=run_index,
                trigger=trigger,
                execution=latest_execution,
            ):
                changed = True
                run_index_drift = True
            if changed or projection_drift or run_index_drift:
                self._refresh_task_list_projection_for_task_id(db, trigger.id)
                projection_refreshed_count += 1
                reconciled_count += 1
                if len(sample_task_ids) < 20:
                    sample_task_ids.append(trigger.id)
                logger.warning(
                    "active_task_reconciled task_id=%s execution_id=%s projection_status_before=%s effective_status_after=%s dispatch_status_before=%s owner_pod_id_before=%s worker_job_id_before=%s process_state_source=%s resolution_reason=%s",
                    trigger.id,
                    latest_execution.id if latest_execution is not None else "",
                    projection_status_before,
                    effective_status,
                    latest_dispatch,
                    latest_execution.owner_pod_id if latest_execution is not None else "",
                    latest_execution.worker_job_id if latest_execution is not None else "",
                    process_state.get("source"),
                    classification,
                )
                db.commit()
            else:
                db.rollback()
        return ActiveTaskReconcileResponse(
            scanned_count=len(triggers),
            reconciled_count=reconciled_count,
            requeued_count=requeued_count,
            terminalized_count=terminalized_count,
            projection_refreshed_count=projection_refreshed_count,
            sample_task_ids=sample_task_ids,
            dry_run=bool(dry_run),
            message="active task reconcile completed",
        )

    def _resolve_task_timeline_execution(
        self,
        db: Session,
        *,
        task_id: str | None = None,
        trigger: TriggerTask | None = None,
        execution: WorkflowExecution | None = None,
    ) -> tuple[TriggerTask | None, WorkflowExecution | None]:
        resolved_execution = execution
        resolved_trigger = trigger
        if resolved_trigger is None and resolved_execution is not None and resolved_execution.trigger_task_id:
            resolved_trigger = db.get(TriggerTask, resolved_execution.trigger_task_id)
        if resolved_trigger is None and str(task_id or "").strip():
            resolved_trigger = db.get(TriggerTask, str(task_id).strip())
        if resolved_execution is None and resolved_trigger is not None:
            resolved_execution = self._latest_execution_for_trigger(db, resolved_trigger.id)
        return resolved_trigger, resolved_execution

    def _record_task_mutation_event(
        self,
        db: Session,
        *,
        event_type: str,
        message: str,
        payload_json: dict[str, Any] | None = None,
        level: str = "info",
        task_id: str | None = None,
        trigger: TriggerTask | None = None,
        execution: WorkflowExecution | None = None,
        stage_id: str | None = None,
        round_no: int | None = None,
    ) -> WorkflowExecutionEvent | None:
        resolved_trigger, resolved_execution = self._resolve_task_timeline_execution(
            db,
            task_id=task_id,
            trigger=trigger,
            execution=execution,
        )
        if resolved_execution is None:
            logger.warning(
                "skip timeline mutation event event_type=%s task_id=%s trigger_id=%s message=%s",
                event_type,
                str(task_id or ""),
                resolved_trigger.id if resolved_trigger is not None else "",
                message,
            )
            return None
        return self.record_event(
            db,
            execution_id=resolved_execution.id,
            event_type=event_type,
            message=message,
            stage_id=stage_id,
            round_no=round_no,
            level=level,
            payload_json=payload_json,
        )

    def _log_task_mutation(
        self,
        *,
        action: str,
        principal: dict | None = None,
        level: str = "info",
        **fields: Any,
    ) -> None:
        log_fn = logger.warning if str(level).lower() == "warning" else logger.info
        safe_fields = {key: jsonable_encoder(value) for key, value in fields.items()}
        safe_fields["action"] = action
        principal_id = _principal_id(principal or {})
        if principal_id:
            safe_fields["principal_id"] = principal_id
        rendered = " ".join(f"{key}={safe_fields[key]!r}" for key in sorted(safe_fields))
        log_fn("task mutation log %s", rendered)

    def rebuild_single_scan_task_projection(
        self,
        db: Session,
        task_id: str,
        principal: dict,
    ) -> ScanTaskProjectionRepairResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        self._rebuild_task_list_projections(db, [trigger])
        db.commit()
        self._record_task_mutation_event(
            db,
            event_type="task_projection_rebuilt",
            message="task list projection rebuilt",
            trigger=trigger,
            payload_json={
                "task_id": trigger.id,
                "project_id": trigger.project_id,
            },
        )
        return ScanTaskProjectionRepairResponse(
            task_id=trigger.id,
            project_id=trigger.project_id,
            repaired_count=1,
            message="task list projection rebuilt",
        )

    def rebuild_scan_task_projections(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
    ) -> ScanTaskProjectionRepairResponse:
        query = db.query(TriggerTask)
        if project_id:
            self._ensure_project_access(principal, project_id)
            query = query.filter(TriggerTask.project_id == project_id)
        else:
            project_ids = _project_ids(principal)
            if project_ids:
                query = query.filter(TriggerTask.project_id.in_(project_ids))
        triggers = query.order_by(TriggerTask.created_at.desc(), TriggerTask.id.desc()).all()
        self._rebuild_task_list_projections(db, triggers)
        db.commit()
        self._log_task_mutation(
            action="task_projection_batch_rebuilt",
            principal=principal,
            project_id=project_id,
            repaired_count=len(triggers),
        )
        return ScanTaskProjectionRepairResponse(
            project_id=project_id,
            repaired_count=len(triggers),
            message="task list projections rebuilt",
        )

    def _list_task_projection_query(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
        status_filter: str | None = None,
        profile_id: str | None = None,
        search: str | None = None,
        slot_binding_state: str | None = None,
        report_status: str | None = None,
        model: str | None = None,
        mode: str | None = None,
        parent_task_id: str | None = None,
        sort_by: str | None = None,
        sort_order: str | None = None,
    ):
        project_ids = _project_ids(principal)
        query = db.query(DfvsTaskListProjection)
        if project_id:
            self._ensure_project_access(principal, project_id)
            query = query.filter(DfvsTaskListProjection.project_id == project_id)
        elif project_ids:
            query = query.filter(DfvsTaskListProjection.project_id.in_(project_ids))
        if status_filter:
            query = query.filter(DfvsTaskListProjection.public_status == normalize_public_task_status(status_filter))
        if profile_id:
            query = query.filter(DfvsTaskListProjection.profile_id == profile_id)
        normalized_search = str(search or "").strip()
        if normalized_search:
            escaped = normalized_search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped}%"
            query = query.filter(or_(
                DfvsTaskListProjection.task_id.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.title.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.public_status.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.message.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.latest_execution_id.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.profile_id.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.run_name.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.run_path.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.runs_root.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.run_model.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.run_provider.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.run_workflow_mode.ilike(pattern, escape="\\"),
                DfvsTaskListProjection.parent_task_id.ilike(pattern, escape="\\"),
            ))
        normalized_slot_binding_state = str(slot_binding_state or "").strip()
        if normalized_slot_binding_state:
            query = query.filter(DfvsTaskListProjection.slot_binding_state == normalized_slot_binding_state)
        normalized_report_status = str(report_status or "").strip()
        if normalized_report_status:
            query = query.filter(DfvsTaskListProjection.vuln_report_status == normalized_report_status)
        normalized_model = str(model or "").strip()
        if normalized_model:
            query = query.filter(DfvsTaskListProjection.run_model == normalized_model)
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode in {"manual", "binary", "source"}:
            query = query.filter(DfvsTaskListProjection.origin_mode == normalized_mode)
        normalized_parent_task_id = str(parent_task_id or "").strip()
        if normalized_parent_task_id:
            query = query.filter(DfvsTaskListProjection.parent_task_id == normalized_parent_task_id)
        normalized_sort_by = str(sort_by or "created_at").strip()
        sort_column = _TASK_LIST_SORT_COLUMNS.get(normalized_sort_by)
        if sort_column is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unsupported sort_by: {normalized_sort_by}",
            )
        order_expr = sort_column.asc() if str(sort_order or "").lower() == "asc" else sort_column.desc()
        return query.order_by(order_expr, DfvsTaskListProjection.task_id.desc())

    def _source_run_index_for_trigger(self, db: Session, trigger: TriggerTask, execution: WorkflowExecution | None) -> RunIndex | None:
        if execution is not None:
            run_index = self._ensure_run_index_for_execution(db, execution, trigger)
            if run_index is not None:
                return run_index
        return (
            db.query(RunIndex)
            .filter(RunIndex.linked_task_id == trigger.id)
            .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
            .first()
        )

    def _default_evolution_title(self, source_title: str) -> str:
        title = f"Evolution of {str(source_title or '').strip()}".strip()
        title = title[:128].rstrip()
        return title or "Evolution Task"

    def _input_ref_or_none(self, value: Any, *, label: str) -> DataflowInputRef | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} ref is invalid")
        try:
            return DataflowInputRef.model_validate(value)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} ref is invalid") from exc

    def _artifact_refs_from_metadata(self, metadata: dict[str, Any]) -> list[ArtifactRef]:
        items: list[ArtifactRef] = []
        for item in metadata.get("artifact_refs") or []:
            if not isinstance(item, dict):
                continue
            try:
                items.append(ArtifactRef.model_validate(item))
            except Exception as exc:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="artifact_refs in source task metadata is invalid") from exc
        return items

    def _merged_scan_options_for_evolution(self, source_request: dict[str, Any], payload: CreateEvolutionTaskRequest) -> dict[str, Any]:
        merged = dict(source_request.get("options") or {})
        merged.pop("run_name", None)
        merged.update(dict(payload.scan_options or {}))
        return merged

    def _build_evolution_create_payload(
        self,
        *,
        db: Session,
        source_trigger: TriggerTask,
        source_execution: WorkflowExecution | None,
        payload: CreateEvolutionTaskRequest,
    ) -> tuple[ScanTaskCreateRequest, dict[str, Any]]:
        task_metadata = self._trigger_task_metadata(source_trigger)
        if self._normalize_task_purpose(getattr(source_trigger, "task_purpose", None) or task_metadata.get("task_purpose")) != "normal":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="only normal tasks can create evolution tasks")
        if not self._is_dataflow_cli_task_metadata(task_metadata):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="source task is not a run_vuln_scan.py launcher task")
        source_request = task_metadata.get("dataflow_scan_request") if isinstance(task_metadata.get("dataflow_scan_request"), dict) else {}
        if not isinstance(source_request.get("data_flow"), dict) or not isinstance(source_request.get("source_dir"), dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="source task is missing reusable data_flow/source_dir inputs")

        if source_trigger.workflow_definition_version_id:
            version = self._definition_version_or_404(db, source_trigger.workflow_definition_version_id)
        else:
            version = get_workflow_service().get_profile_version_model(db, source_trigger.workflow_definition_id)
        source_config_payload = dict(version.config_payload_json or {})
        source_run_index = self._source_run_index_for_trigger(db, source_trigger, source_execution)
        source_run_id = source_run_index.id if source_run_index is not None else None
        source_title = self._trigger_title(source_trigger)
        source_profile_id = self._task_effective_profile_id(source_trigger)
        source_origin_type = str(source_trigger.task_origin_type or task_metadata.get("task_origin_type") or "manual").strip() or "manual"
        source_runtime_overrides = dict(task_metadata.get("runtime_overrides") or {})
        merged_runtime_overrides = {**source_runtime_overrides, **dict(payload.runtime_overrides or {})}
        derivation = {
            "kind": "evolution_replay",
            "source_task_id": source_trigger.id,
            "source_execution_id": source_execution.id if source_execution is not None else None,
            "source_run_id": source_run_id,
            "source_task_purpose": "normal",
            "evolution_task_id": payload.evolution_task_id,
            "evolution_round": payload.evolution_round,
            "evolution_source_task_id": payload.evolution_source_task_id or source_trigger.id,
            "evolution_source_execution_id": payload.evolution_source_execution_id or (source_execution.id if source_execution is not None else None),
        }

        create_payload = ScanTaskCreateRequest(
            project_id=source_trigger.project_id,
            profile_id=payload.profile_id or source_profile_id,
            title=(payload.title.strip() if isinstance(payload.title, str) else "") or self._default_evolution_title(source_title),
            workspace_dir=self._input_ref_or_none(source_request.get("workspace_dir"), label="workspace_dir"),
            data_flow=self._input_ref_or_none(source_request.get("data_flow"), label="data_flow"),
            source_dir=self._input_ref_or_none(source_request.get("source_dir"), label="source_dir"),
            output_dir=self._input_ref_or_none(source_request.get("output_dir"), label="output_dir"),
            model=payload.model if payload.model is not None else source_request.get("model") or source_config_payload.get("model"),
            provider=payload.provider if payload.provider is not None else source_request.get("provider"),
            review_profile=payload.review_profile if payload.review_profile is not None else source_request.get("review_profile") or source_config_payload.get("review_profile"),
            max_review_cycles=payload.max_review_cycles if payload.max_review_cycles is not None else source_request.get("max_review_cycles") or source_config_payload.get("max_review_cycles"),
            agent_run_timeout_seconds=payload.agent_run_timeout_seconds if payload.agent_run_timeout_seconds is not None else source_request.get("agent_run_timeout_seconds") if source_request.get("agent_run_timeout_seconds") is not None else source_config_payload.get("agent_run_timeout_seconds"),
            agent_timeout_retry_enabled=payload.agent_timeout_retry_enabled if payload.agent_timeout_retry_enabled is not None else source_request.get("agent_timeout_retry_enabled") if source_request.get("agent_timeout_retry_enabled") is not None else source_config_payload.get("agent_timeout_retry_enabled"),
            agent_timeout_max_retries=payload.agent_timeout_max_retries if payload.agent_timeout_max_retries is not None else source_request.get("agent_timeout_max_retries") if source_request.get("agent_timeout_max_retries") is not None else source_config_payload.get("agent_timeout_max_retries"),
            worker_timeout=source_request.get("worker_timeout") if source_request.get("worker_timeout") is not None else source_config_payload.get("worker_timeout"),
            advisor_timeout=source_request.get("advisor_timeout") if source_request.get("advisor_timeout") is not None else source_config_payload.get("advisor_timeout"),
            timeout_max_retries=payload.timeout_max_retries if payload.timeout_max_retries is not None else source_request.get("timeout_max_retries") if source_request.get("timeout_max_retries") is not None else source_config_payload.get("timeout_max_retries"),
            timeout_retry_interval_seconds=payload.timeout_retry_interval_seconds if payload.timeout_retry_interval_seconds is not None else source_request.get("timeout_retry_interval_seconds") if source_request.get("timeout_retry_interval_seconds") is not None else source_config_payload.get("timeout_retry_interval_seconds"),
            result_review_concurrency=payload.result_review_concurrency if payload.result_review_concurrency is not None else source_request.get("result_review_concurrency") if source_request.get("result_review_concurrency") is not None else source_config_payload.get("result_review_concurrency"),
            scan_options=self._merged_scan_options_for_evolution(source_request, payload),
            artifact_refs=self._artifact_refs_from_metadata(task_metadata),
            priority=payload.priority if payload.priority is not None else source_trigger.priority,
            runtime_overrides=merged_runtime_overrides,
            task_purpose="evolution",
            agent_state_roots=dict(payload.agent_state_roots or {}),
            task_origin_type=source_origin_type,
            auto_report_vulnerabilities=bool(task_metadata.get("auto_report_vulnerabilities", True)) if payload.auto_report_vulnerabilities is None else bool(payload.auto_report_vulnerabilities),
        )
        return create_payload, {"derivation": derivation}

    def _agent_ids_from_compiled_config(self, compiled_config: dict[str, Any] | None) -> list[str]:
        agent_ids: list[str] = []
        for agent in (compiled_config or {}).get("agents") or []:
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("id") or "").strip()
            if agent_id and agent_id not in agent_ids:
                agent_ids.append(agent_id)
        return agent_ids

    def _default_agent_state_root(self, *, project_id: str, agent_id: str) -> Path:
        config = get_config()
        return (
            self._project_files_root(project_id)
            / sanitize_name(config.fileserver_service.dataflow_subproject_name)
            / "agent-state"
            / "shared"
            / sanitize_name(agent_id)
        )

    def _resolve_directory_ref(
        self,
        *,
        project_id: str,
        ref: dict[str, Any],
        expected: str,
        require_exists: bool,
    ) -> Path:
        source = str(ref.get("source") or "project_filesystem").strip()
        if source in {"project_filesystem", "project_path", "project"}:
            project_root = self._project_files_root(project_id)
            normalized = self._normalize_project_path(str(ref.get("path") or ""))
            resolved = self._ensure_path_within(path=project_root / normalized.lstrip("/"), root=project_root, label=expected)
        elif source in {"fileserver_storage", "storage_key", "managed_file"}:
            storage_key = str(ref.get("storage_key") or ref.get("path") or "").strip()
            if not storage_key:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} storage_key is required")
            resolved = self._resolve_project_storage_key(project_id=project_id, storage_key=storage_key, label=expected)
        elif source in {"absolute", "absolute_path", "local_path"}:
            if not get_config().service.allow_absolute_input_refs:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute_path input is disabled")
            raw = str(ref.get("path") or "").strip()
            if not raw:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} path is required")
            candidate = Path(raw)
            if not candidate.is_absolute():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute path is required")
            resolved = self._ensure_path_within(path=candidate, root=self._project_files_root(project_id), label=expected)
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"unsupported {expected} source: {source}")
        if require_exists and not resolved.exists():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} not found: {resolved}")
        if resolved.exists() and not resolved.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} must be a directory: {resolved}")
        return resolved

    def _agent_state_dirs_from_metadata(
        self,
        *,
        project_id: str,
        compiled_config: dict[str, Any] | None,
        metadata: dict[str, Any] | None,
    ) -> dict[str, dict[str, str]]:
        metadata = metadata or {}
        configured_roots = metadata.get("agent_state_roots") if isinstance(metadata.get("agent_state_roots"), dict) else {}
        response: dict[str, dict[str, str]] = {}
        for agent_id in self._agent_ids_from_compiled_config(compiled_config):
            root_path: Path
            source = "shared_default"
            root_payload = configured_roots.get(agent_id) if isinstance(configured_roots.get(agent_id), dict) else {}
            root_ref = root_payload.get("root_dir") if isinstance(root_payload.get("root_dir"), dict) else None
            if root_ref is not None:
                root_path = self._resolve_directory_ref(
                    project_id=project_id,
                    ref=root_ref,
                    expected=f"{agent_id} root_dir",
                    require_exists=False,
                )
                source = "task_override"
            else:
                root_path = self._default_agent_state_root(project_id=project_id, agent_id=agent_id)
            response[agent_id] = {
                "agent_id": agent_id,
                "root_dir": abs_path(root_path),
                "skills_dir": abs_path(root_path / "skills"),
                "memory_dir": abs_path(root_path / "memory"),
                "source": source,
            }
        return response

    def _ensure_agent_state_dirs(self, agent_state_dirs: dict[str, dict[str, str]]) -> None:
        models_source = self._pi_models_json_path()
        for item in agent_state_dirs.values():
            root_dir = ensure_dir(item["root_dir"])
            skills_dir = ensure_dir(item["skills_dir"])
            memory_dir = ensure_dir(item["memory_dir"])
            home_skills = root_dir / "skills"
            home_memory = root_dir / "memory"
            if home_skills != skills_dir:
                ensure_dir(home_skills)
            if home_memory != memory_dir:
                ensure_dir(home_memory)
            self._copy_pi_models_json(models_source, root_dir / "models.json")

    def _pi_models_json_path(self) -> Path | None:
        explicit_path = str(os.environ.get("PI_MODELS_JSON") or "").strip()
        candidates = []
        if explicit_path:
            candidates.append(Path(explicit_path).expanduser())
        candidates.append(Path(os.environ.get("PI_CODING_AGENT_DIR", "/root/.pi/agent")).expanduser() / "models.json")
        candidates.append(Path("/root/.pi/agent/models.json"))
        for candidate in candidates:
            try:
                if candidate.is_file():
                    return candidate
            except OSError:
                logger.debug("skip unreadable pi models.json candidate: %s", candidate, exc_info=True)
        return None

    def _copy_pi_models_json(self, source: Path | None, target: Path) -> None:
        if source is None:
            return
        try:
            source = source.resolve()
            target_parent = ensure_dir(target.parent)
            target = target_parent / target.name
            if target.exists() and target.resolve() == source:
                return
            tmp_path = target.with_name(f".{target.name}.tmp")
            shutil.copyfile(source, tmp_path)
            tmp_path.replace(target)
        except Exception:
            logger.warning("failed to copy pi models.json to agent state dir: source=%s target=%s", source, target, exc_info=True)

    def _apply_agent_state_dirs_to_compiled_config(
        self,
        *,
        compiled_config: dict[str, Any],
        agent_state_dirs: dict[str, dict[str, str]],
    ) -> dict[str, Any]:
        payload = copy.deepcopy(compiled_config or {})
        for agent in payload.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("id") or "").strip()
            state_dirs = agent_state_dirs.get(agent_id)
            if not state_dirs:
                continue
            runtime_config = agent.setdefault("runtime_config", {})
            env_payload = runtime_config.setdefault("env", {})
            env_payload["PI_CODING_AGENT_DIR"] = state_dirs["root_dir"]
            env_payload["SECFLOW_PI_AGENT_HOME"] = state_dirs["root_dir"]
            env_payload["SECFLOW_PI_SKILLS_DIR"] = state_dirs["skills_dir"]
            env_payload["SECFLOW_PI_MEMORY_DIR"] = state_dirs["memory_dir"]
            runtime_config["agent_home_dir"] = state_dirs["root_dir"]
            runtime_config["skills_dir"] = state_dirs["skills_dir"]
            runtime_config["memory_dir"] = state_dirs["memory_dir"]
        return payload

    def _trigger_uses_run_directory(self, trigger: TriggerTask | None) -> bool:
        metadata = self._trigger_task_metadata(trigger)
        return (
            self._is_dataflow_cli_task_metadata(metadata)
            or isinstance(metadata.get("run_adoption"), dict)
            or isinstance(metadata.get("run_retry"), dict)
        )

    def _planned_run_root_for_trigger(self, trigger: TriggerTask | None) -> Path | None:
        metadata = self._trigger_task_metadata(trigger)
        plan = metadata.get("dataflow_cli") if isinstance(metadata.get("dataflow_cli"), dict) else {}
        raw_run_dir = str(plan.get("run_dir") or "").strip()
        if not raw_run_dir:
            request = metadata.get("dataflow_scan_request") if isinstance(metadata.get("dataflow_scan_request"), dict) else {}
            raw_run_dir = str(request.get("resume_run_dir") or "").strip()
        if not raw_run_dir:
            return None
        candidate = Path(raw_run_dir)
        if not candidate.is_absolute():
            return None
        try:
            project_id = trigger.project_id if trigger is not None else ""
            return self._ensure_path_within(path=candidate, root=self._project_files_root(project_id), label="run_dir")
        except Exception:
            return None

    def _run_root_for_execution_or_trigger(
        self,
        execution: WorkflowExecution | None,
        trigger: TriggerTask | None = None,
    ) -> Path | None:
        if execution is not None and execution.workspace_root:
            return Path(execution.workspace_root).resolve()
        return self._planned_run_root_for_trigger(trigger)

    def _run_locator_for_execution(self, execution: WorkflowExecution | None, trigger: TriggerTask | None = None) -> dict[str, str | None]:
        run_root = self._run_root_for_execution_or_trigger(execution, trigger)
        if run_root is None:
            return {"run_name": None, "runs_root": None, "run_path": None}
        return {
            "run_name": run_root.name,
            "runs_root": str(run_root.parent),
            "run_path": str(run_root),
        }

    def _latest_run_summary_for_execution(self, db: Session, execution: WorkflowExecution | None, trigger: TriggerTask | None = None) -> dict[str, Any]:
        if execution is None:
            return {}
        try:
            run_index = get_run_index_service().get_run_index_by_execution(db, execution) if execution.workspace_root else None
            if run_index is None:
                run_index = self._ensure_run_index_for_execution(db, execution, trigger)
            if run_index is None:
                return {}
            return get_run_index_service().get_run_summary(db, run_index)
        except Exception:
            db.rollback()
            return {}

    def _ensure_run_index_for_execution(
        self,
        db: Session,
        execution: WorkflowExecution | None,
        trigger: TriggerTask | None = None,
        *,
        include_runtime_assets: bool = False,
    ) -> RunIndex | None:
        if execution is None:
            return None
        run_root = self._run_root_for_execution_or_trigger(execution, trigger)
        if run_root is None:
            return None
        if not execution.workspace_root:
            execution.workspace_root = abs_path(run_root)
            db.add(execution)
            db.flush()
        if not run_root.is_dir() and trigger is not None and self._trigger_uses_run_directory(trigger):
            metadata = self._trigger_task_metadata(trigger)
            plan = metadata.get("dataflow_cli") if isinstance(metadata.get("dataflow_cli"), dict) else {}
            planned_run_dir = str(plan.get("run_dir") or "").strip()
            if planned_run_dir:
                try:
                    if Path(planned_run_dir).resolve() == run_root.resolve():
                        self._write_dataflow_cli_task_preview(plan)
                except Exception:
                    # Resolver paths should be best-effort; the caller will
                    # still return 404 if the run directory cannot be prepared.
                    pass
        if not run_root.is_dir():
            return None
        existing_run_index = (
            get_run_index_service().get_run_index_by_execution(db, execution)
            or (
                db.query(RunIndex)
                .filter(RunIndex.linked_execution_id == execution.id)
                .order_by(RunIndex.last_synced_at.desc(), RunIndex.created_at.desc(), RunIndex.id.desc())
                .first()
            )
        )
        if existing_run_index is not None:
            if str(get_config().scheduler.role or "standalone").strip().lower() == "manager":
                return existing_run_index
            return get_run_index_service().refresh_run_index(
                db,
                existing_run_index,
                include_runtime_assets=False,
            )
        return get_run_index_service().sync_run_path(
            db,
            project_id=execution.project_id,
            run_root=run_root,
            source_type="execution_workspace",
            linked_execution=execution,
            linked_task=trigger or db.get(TriggerTask, execution.trigger_task_id),
            profile_id=(trigger.profile_id if trigger else None),
            include_runtime_assets=include_runtime_assets,
        )

    def _scan_task_response(self, db: Session, trigger: TriggerTask, *, include_run_summary: bool = True) -> ScanTaskResponse:
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        if trigger.workflow_definition_version_id:
            version = self._definition_version_or_404(db, trigger.workflow_definition_version_id)
        else:
            version = get_workflow_service().get_profile_version_model(db, trigger.workflow_definition_id)
        compiled_config = version.compiled_config_json or version.definition_json or {}
        task_metadata = self._trigger_task_metadata(trigger)
        task_origin_type = str(trigger.task_origin_type or "").strip() or "manual"
        task_purpose = self._normalize_task_purpose(getattr(trigger, "task_purpose", None) or task_metadata.get("task_purpose"))
        derivation = self._task_derivation_metadata(task_metadata)
        parent_task_type = str(trigger.parent_task_type or "").strip() or None
        origin_label = (
            "二进制安全-源码扫描"
            if task_origin_type == "binary_security" and parent_task_type == "source"
            else "二进制安全-二进制类扫描"
            if task_origin_type == "binary_security"
            else "手动任务"
        )
        def _version_review_profile() -> str:
            version_config = version.compiled_config_json or version.definition_json or {}
            for workflow in ((version_config.get("workflows") or {}).get("atomic") or []):
                if not isinstance(workflow, dict):
                    continue
                engine = workflow.get("engine")
                if isinstance(engine, dict) and (engine.get("review_profile") or workflow.get("id") == "vuln_scan"):
                    return str(engine.get("review_profile") or "")
            return ""

        run_locator = self._run_locator_for_execution(latest_execution, trigger)
        if include_run_summary:
            run_summary = self._latest_run_summary_for_execution(db, latest_execution, trigger)
        else:
            run_summary = {}
            if latest_execution is not None:
                lightweight_run_index = (
                    db.query(RunIndex)
                    .filter(RunIndex.linked_execution_id == latest_execution.id)
                    .first()
                )
                if lightweight_run_index is None:
                    lightweight_run_index = (
                        db.query(RunIndex)
                        .filter(RunIndex.linked_task_id == trigger.id)
                        .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
                        .first()
                    )
                if lightweight_run_index is not None:
                    config_json = _load_externalized_mapping_payload(
                        lightweight_run_index.run_root_path,
                        lightweight_run_index.config_json,
                    )
                    review_profile = str(config_json.get("review_profile") or "")
                    for workflow in ((config_json.get("workflows") or {}).get("atomic") or []):
                        if not isinstance(workflow, dict):
                            continue
                        engine = workflow.get("engine")
                        if isinstance(engine, dict) and (engine.get("review_profile") or workflow.get("id") == "vuln_scan"):
                            review_profile = str(engine.get("review_profile") or "")
                            break
                    if not review_profile:
                        review_profile = _version_review_profile()
                    normalized_run_status = get_run_index_service().normalized_run_status(lightweight_run_index)
                    run_summary.update({
                        "run_id": lightweight_run_index.id,
                        "status": normalized_run_status,
                        "model": lightweight_run_index.model,
                        "provider": lightweight_run_index.provider,
                        "thinking": lightweight_run_index.thinking,
                        "max_cycles": lightweight_run_index.max_cycles,
                        "cycles_used": lightweight_run_index.cycles_used,
                        "result_count": lightweight_run_index.result_count,
                        "passed_count": lightweight_run_index.passed_count,
                        "failed_count": lightweight_run_index.failed_count,
                        "workflow_mode": lightweight_run_index.workflow_mode,
                        "review_profile": review_profile,
                        "process_state": self._run_process_state(
                            db,
                            lightweight_run_index,
                            trigger=trigger,
                            execution=latest_execution,
                        ),
                    })
        if run_summary and "process_state" not in run_summary:
            run_index_for_state = None
            run_index_id = str(run_summary.get("run_id") or "").strip()
            if run_index_id:
                run_index_for_state = db.get(RunIndex, run_index_id)
            if run_index_for_state is None and latest_execution is not None:
                run_index_for_state = (
                    db.query(RunIndex)
                    .filter(RunIndex.linked_execution_id == latest_execution.id)
                    .first()
                )
            if run_index_for_state is None:
                run_index_for_state = (
                    db.query(RunIndex)
                    .filter(RunIndex.linked_task_id == trigger.id)
                    .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
                    .first()
                )
            if run_index_for_state is not None:
                run_summary["process_state"] = self._run_process_state(
                    db,
                    run_index_for_state,
                    trigger=trigger,
                    execution=latest_execution,
                )
        if run_locator["run_name"] and run_locator["runs_root"]:
            run_summary = {
                "name": run_locator["run_name"],
                "root_path": run_locator["runs_root"],
                "path": run_locator["run_path"],
                "linked_task_id": trigger.id,
                "linked_execution_id": latest_execution.id if latest_execution else None,
                **run_summary,
            }
        run_index_for_unbound = None
        run_index_id = str(run_summary.get("run_id") or "").strip()
        if run_index_id:
            run_index_for_unbound = db.get(RunIndex, run_index_id)
        if run_index_for_unbound is None and latest_execution is not None:
            run_index_for_unbound = (
                db.query(RunIndex)
                .filter(RunIndex.linked_execution_id == latest_execution.id)
                .first()
            )
        if run_index_for_unbound is None:
            run_index_for_unbound = (
                db.query(RunIndex)
                .filter(RunIndex.linked_task_id == trigger.id)
                .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
                .first()
            )
        if latest_execution is not None and self._requeue_unbound_active_execution_if_safe(
            db,
            trigger=trigger,
            execution=latest_execution,
            run_index=run_index_for_unbound,
            reason="scan_task_response",
        ):
            db.flush()
            latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        abnormal_reason = self._task_abnormal_reason(trigger, latest_execution, run_summary)
        effective_task_status, effective_task_message, effective_started_at, effective_finished_at = self._effective_scan_task_runtime_state(
            trigger=trigger,
            execution=latest_execution,
            run_summary=run_summary,
        )
        slot_binding_state, slot_binding_reason = self._slot_binding_state(
            execution=latest_execution,
            effective_status=effective_task_status,
        )
        control_state = derive_task_control_state(
            dispatch_status=latest_execution.dispatch_status if latest_execution is not None else None,
            process_status=latest_execution.process_status if latest_execution is not None else None,
            trigger_message=trigger.message,
            execution_message=latest_execution.message if latest_execution is not None else None,
        )
        return ScanTaskResponse(
            task_id=trigger.id,
            project_id=trigger.project_id,
            derived_from_task_id=str(derivation.get("source_task_id") or "").strip() or None,
            derived_from_execution_id=str(derivation.get("source_execution_id") or "").strip() or None,
            derived_from_run_id=str(derivation.get("source_run_id") or "").strip() or None,
            derivation_kind="evolution_replay" if str(derivation.get("kind") or "").strip() == "evolution_replay" else None,
            task_origin_type=task_origin_type,
            parent_project_id=trigger.parent_project_id,
            parent_task_id=trigger.parent_task_id,
            parent_task_type=parent_task_type,
            parent_stage_name=trigger.parent_stage_name,
            parent_stage_item_id=trigger.parent_stage_item_id,
            parent_stage_item_key=trigger.parent_stage_item_key,
            origin_label=origin_label,
            parent_task_display=trigger.parent_task_id,
            profile_id=trigger.profile_id or trigger.workflow_definition_id,
            profile_version=version.version_no,
            task_purpose=task_purpose,
            agent_state_dirs={
                key: DataflowAgentStateDirResponse.model_validate(value)
                for key, value in self._agent_state_dirs_from_metadata(
                    project_id=trigger.project_id,
                    compiled_config=compiled_config,
                    metadata=task_metadata,
                ).items()
            },
            title=self._trigger_title(trigger),
            status=normalize_canonical_task_status(effective_task_status),
            control_state=control_state,
            latest_attempt_no=latest_execution.attempt_no if latest_execution else 0,
            retry_count=trigger.retry_count,
            max_retry_count=trigger.max_retry_count,
            priority=trigger.priority,
            created_by=trigger.submitted_by,
            created_at=trigger.created_at,
            started_at=effective_started_at,
            finished_at=effective_finished_at,
            message=effective_task_message,
            latest_execution_id=trigger.latest_execution_id,
            owner_pod_id=latest_execution.owner_pod_id if latest_execution is not None else None,
            dispatch_status=latest_execution.dispatch_status if latest_execution is not None else None,
            slot_binding_state=slot_binding_state,
            slot_binding_reason=slot_binding_reason,
            run_name=run_locator["run_name"],
            runs_root=run_locator["runs_root"],
            run_path=run_locator["run_path"],
            run=run_summary,
            latest_run=run_summary,
            auto_report_vulnerabilities=bool(
                task_metadata.get("auto_report_vulnerabilities", True)
            ),
            vuln_report_status=get_task_vuln_report_status(
                db,
                trigger,
                latest_execution.id if latest_execution else None,
            ),
            abnormal_reason_title=abnormal_reason.get("title") if abnormal_reason else None,
            abnormal_reason_code=abnormal_reason.get("code") if abnormal_reason else None,
            abnormal_reason_category=abnormal_reason.get("category") if abnormal_reason else None,
            abnormal_reason=abnormal_reason,
        )

    def _build_profile_version_map(
        self,
        db: Session,
        triggers: list[TriggerTask],
    ) -> dict[str, int]:
        version_ids = {str(item.workflow_definition_version_id) for item in triggers if item.workflow_definition_version_id}
        version_rows = {}
        if version_ids:
            version_rows = {
                str(item.id): int(item.version_no or 0)
                for item in db.query(WorkflowDefinitionVersion).filter(WorkflowDefinitionVersion.id.in_(version_ids)).all()
            }
        definition_ids = {str(item.workflow_definition_id) for item in triggers if item.workflow_definition_id}
        latest_versions: dict[str, int] = {}
        if definition_ids:
            rows = (
                db.query(WorkflowDefinitionVersion.workflow_definition_id, WorkflowDefinitionVersion.version_no)
                .filter(WorkflowDefinitionVersion.workflow_definition_id.in_(definition_ids))
                .all()
            )
            for workflow_definition_id, version_no in rows:
                key = str(workflow_definition_id)
                latest_versions[key] = max(latest_versions.get(key, 0), int(version_no or 0))
        profile_versions: dict[str, int] = {}
        for trigger in triggers:
            trigger_id = str(trigger.id)
            if trigger.workflow_definition_version_id and str(trigger.workflow_definition_version_id) in version_rows:
                profile_versions[trigger_id] = version_rows[str(trigger.workflow_definition_version_id)]
            else:
                profile_versions[trigger_id] = latest_versions.get(str(trigger.workflow_definition_id), 0)
        return profile_versions

    def _build_latest_execution_map(
        self,
        db: Session,
        triggers: list[TriggerTask],
    ) -> dict[str, WorkflowExecution]:
        trigger_ids = [str(item.id) for item in triggers if item.id]
        if not trigger_ids:
            return {}
        executions = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id.in_(trigger_ids))
            .order_by(WorkflowExecution.trigger_task_id.asc(), WorkflowExecution.attempt_no.desc(), WorkflowExecution.created_at.desc())
            .all()
        )
        latest: dict[str, WorkflowExecution] = {}
        for execution in executions:
            key = str(execution.trigger_task_id)
            if key not in latest:
                latest[key] = execution
        return latest

    def _build_lightweight_run_index_map(
        self,
        db: Session,
        triggers: list[TriggerTask],
        latest_execution_map: dict[str, WorkflowExecution],
    ) -> dict[str, RunIndex]:
        trigger_ids = [str(item.id) for item in triggers if item.id]
        execution_ids = [str(item.id) for item in latest_execution_map.values() if item.id]
        run_indexes = (
            db.query(RunIndex)
            .filter(
                (RunIndex.linked_execution_id.in_(execution_ids) if execution_ids else False)
                | (RunIndex.linked_task_id.in_(trigger_ids) if trigger_ids else False)
            )
            .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
            .all()
        )
        by_execution: dict[str, RunIndex] = {}
        by_task: dict[str, RunIndex] = {}
        for item in run_indexes:
            execution_id = str(item.linked_execution_id or "").strip()
            task_id = str(item.linked_task_id or "").strip()
            if execution_id and execution_id not in by_execution:
                by_execution[execution_id] = item
            if task_id and task_id not in by_task:
                by_task[task_id] = item
        resolved: dict[str, RunIndex] = {}
        for trigger in triggers:
            trigger_id = str(trigger.id)
            latest_execution = latest_execution_map.get(trigger_id)
            if latest_execution is not None:
                run_index = by_execution.get(str(latest_execution.id))
                if run_index is not None:
                    resolved[trigger_id] = run_index
                    continue
            run_index = by_task.get(trigger_id)
            if run_index is not None:
                resolved[trigger_id] = run_index
        return resolved

    def _scan_task_list_response(
        self,
        *,
        trigger: TriggerTask,
        latest_execution: WorkflowExecution | None,
        profile_version: int,
        run_index: RunIndex | None,
    ) -> ScanTaskListItemResponse:
        task_metadata = self._trigger_task_metadata(trigger)
        task_origin_type = str(trigger.task_origin_type or "").strip() or "manual"
        derivation = self._task_derivation_metadata(task_metadata)
        parent_task_type = str(trigger.parent_task_type or "").strip() or None
        request_payload = task_metadata.get("dataflow_scan_request") if isinstance(task_metadata.get("dataflow_scan_request"), dict) else {}
        execution_metadata = getattr(latest_execution, "metadata_json", None) if latest_execution is not None else None
        run_index_config = dict(getattr(run_index, "config_json", {}) or {}) if run_index is not None else {}
        review_profile = str(
            run_index_config.get("review_profile")
            or ((execution_metadata or {}).get("review_profile") if isinstance(execution_metadata, dict) else None)
            or request_payload.get("review_profile")
            or task_metadata.get("review_profile")
            or "balanced"
        ).strip() or "balanced"
        origin_label = (
            "二进制安全-源码扫描"
            if task_origin_type == "binary_security" and parent_task_type == "source"
            else "二进制安全-二进制类扫描"
            if task_origin_type == "binary_security"
            else "手动任务"
        )
        run_locator = self._run_locator_for_execution(latest_execution, trigger)
        latest_run: dict[str, Any] = {}
        if run_index is not None:
            latest_run = {
                "run_id": run_index.id,
                "status": get_run_index_service().normalized_run_status(run_index),
                "model": run_index.model,
                "provider": run_index.provider,
                "thinking": run_index.thinking,
                "max_cycles": run_index.max_cycles,
                "cycles_used": run_index.cycles_used,
                "result_count": run_index.result_count,
                "passed_count": run_index.passed_count,
                "failed_count": run_index.failed_count,
                "workflow_mode": run_index.workflow_mode,
                "duration_seconds": run_index.duration_seconds,
                "start_epoch": int(run_index.started_at.timestamp()) if run_index.started_at else None,
                "linked_execution_id": str(latest_execution.id) if latest_execution is not None else None,
                "review_profile": review_profile,
            }
        if run_locator["run_name"] and run_locator["runs_root"]:
            latest_run = {
                "name": run_locator["run_name"],
                "root_path": run_locator["runs_root"],
                "path": run_locator["run_path"],
                "linked_task_id": trigger.id,
                "linked_execution_id": str(latest_execution.id) if latest_execution is not None else None,
                "review_profile": review_profile,
                **latest_run,
            }
        effective_status, effective_message, effective_started_at, effective_finished_at = self._effective_scan_task_runtime_state(
            trigger=trigger,
            execution=latest_execution,
            run_summary=latest_run,
        )
        slot_binding_state, slot_binding_reason = self._slot_binding_state(
            execution=latest_execution,
            effective_status=effective_status,
        )
        auto_report_enabled = bool(task_metadata.get("auto_report_vulnerabilities", True))
        report_status = {"status": "disabled" if not auto_report_enabled else "not_started", "enabled": auto_report_enabled}
        return ScanTaskListItemResponse(
            task_id=trigger.id,
            project_id=trigger.project_id,
            task_purpose=self._normalize_task_purpose(getattr(trigger, "task_purpose", None) or task_metadata.get("task_purpose")),
            task_origin_type=task_origin_type,
            parent_project_id=trigger.parent_project_id,
            parent_task_id=trigger.parent_task_id,
            parent_task_type=parent_task_type,
            parent_stage_name=trigger.parent_stage_name,
            parent_stage_item_id=trigger.parent_stage_item_id,
            parent_stage_item_key=trigger.parent_stage_item_key,
            origin_label=origin_label,
            parent_task_display=trigger.parent_task_id,
            profile_id=trigger.profile_id or trigger.workflow_definition_id,
            profile_version=profile_version,
            title=self._trigger_title(trigger),
            status=effective_status,
            latest_attempt_no=latest_execution.attempt_no if latest_execution else 0,
            retry_count=trigger.retry_count,
            max_retry_count=trigger.max_retry_count,
            priority=trigger.priority,
            created_by=trigger.submitted_by,
            created_at=trigger.created_at,
            started_at=effective_started_at,
            finished_at=effective_finished_at,
            message=effective_message,
            latest_execution_id=trigger.latest_execution_id or (str(latest_execution.id) if latest_execution is not None else None),
            owner_pod_id=latest_execution.owner_pod_id if latest_execution is not None else None,
            dispatch_status=latest_execution.dispatch_status if latest_execution is not None else None,
            slot_binding_state=slot_binding_state,
            slot_binding_reason=slot_binding_reason,
            run_name=run_locator["run_name"],
            runs_root=run_locator["runs_root"],
            run_path=run_locator["run_path"],
            run=latest_run,
            latest_run=latest_run,
            auto_report_vulnerabilities=auto_report_enabled,
            vuln_report_status=report_status,
        )

    def _effective_scan_task_runtime_state(
        self,
        *,
        trigger: TriggerTask,
        execution: WorkflowExecution | None,
        run_summary: dict[str, Any] | None,
    ) -> tuple[str, str | None, datetime | None, datetime | None]:
        trigger_message = str(trigger.message or "").strip() or None
        trigger_started_at = trigger.started_at
        trigger_finished_at = trigger.finished_at

        dispatch_status = str(execution.dispatch_status or "").strip().lower() if execution is not None else ""
        execution_message = str(execution.message or "").strip() if execution is not None else ""
        dispatch_error = str(execution.dispatch_error or "").strip() if execution is not None else ""
        execution_started_at = execution.started_at if execution is not None else None
        execution_finished_at = execution.finished_at if execution is not None else None

        run_summary = run_summary or {}
        run_error = str(run_summary.get("error") or "").strip()

        preferred_error_message = _preferred_abnormal_message(
            trigger_message=trigger_message,
            execution_message=execution_message,
            dispatch_error=dispatch_error,
            run_error=run_error,
        ) or execution_message or trigger_message or None

        resolved = resolve_public_task_state(
            trigger_status=trigger.status,
            trigger_message=trigger_message,
            trigger_started_at=trigger_started_at,
            trigger_finished_at=trigger_finished_at,
            execution_status=execution.status if execution is not None else None,
            execution_message=execution_message or dispatch_error or trigger_message,
            execution_started_at=execution_started_at,
            execution_finished_at=execution_finished_at,
            dispatch_status=dispatch_status,
            preferred_error_message=preferred_error_message,
            run_status=run_summary.get("status"),
            run_message=run_error or execution_message or trigger_message,
            run_started_at=run_summary.get("started_at"),
            run_finished_at=run_summary.get("finished_at"),
        )
        return (
            resolved.status,
            resolved.message,
            resolved.started_at,
            resolved.finished_at,
        )

    def _unbound_active_runtime_evidence(
        self,
        db: Session,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        run_index: RunIndex | None,
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "has_owner_pod_id": False,
            "has_worker_job_id": False,
            "has_process_pid": False,
            "has_process_started_at": False,
            "has_local_process": False,
            "has_active_worker_job": False,
            "has_process_file_running": False,
            "has_recent_run_activity": False,
            "run_index_id": run_index.id if run_index is not None else None,
        }
        if execution is None:
            return evidence

        evidence["has_owner_pod_id"] = bool(str(execution.owner_pod_id or "").strip())
        evidence["has_worker_job_id"] = bool(str(execution.worker_job_id or "").strip())
        evidence["has_process_pid"] = bool(execution.process_pid)
        evidence["has_process_started_at"] = bool(execution.process_started_at)
        evidence["has_local_process"] = self._local_cli_process(execution.id) is not None

        if run_index is not None:
            process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
            source = str(process_state.get("source") or "").strip().lower()
            evidence["has_process_file_running"] = bool(
                process_state.get("process_file_status") in {"running", "timeout_requested", "stop_requested", "delete_requested"}
                and not bool(process_state.get("stale"))
            )
            evidence["has_recent_run_activity"] = bool(
                process_state.get("is_running")
                and source in {"local_process", "process_file_heartbeat"}
            )

        if evidence["has_worker_job_id"] and evidence["has_owner_pod_id"]:
            try:
                from app.services.scheduler import get_scheduler_service

                worker_jobs = get_scheduler_service().list_local_jobs() if str(execution.owner_pod_id or "").strip() == get_config().scheduler.pod_id else []
                evidence["has_active_worker_job"] = any(
                    str(job.get("execution_id") or "").strip() == execution.id
                    and str(job.get("status") or "").strip().lower() in ACTIVE_JOB_STATUSES
                    for job in worker_jobs
                )
            except Exception:
                evidence["has_active_worker_job"] = False

        return evidence

    def _can_requeue_unbound_active_execution(
        self,
        db: Session,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        run_index: RunIndex | None,
    ) -> tuple[bool, dict[str, Any]]:
        evidence = self._unbound_active_runtime_evidence(
            db,
            trigger=trigger,
            execution=execution,
            run_index=run_index,
        )
        should_requeue = not any(
            bool(evidence.get(key))
            for key in (
                "has_owner_pod_id",
                "has_process_pid",
                "has_process_started_at",
                "has_local_process",
                "has_active_worker_job",
                "has_process_file_running",
                "has_recent_run_activity",
            )
        )
        return should_requeue, evidence

    def _requeue_unbound_active_execution_if_safe(
        self,
        db: Session,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        run_index: RunIndex | None,
        reason: str,
    ) -> bool:
        if execution is None:
            return False
        if str(execution.owner_pod_id or "").strip():
            return False

        execution_status = _canonical_task_status(execution.status)
        trigger_status = _canonical_task_status(trigger.status) if trigger is not None else ""
        if execution_status not in {"dispatching", "running"} and trigger_status not in {"dispatching", "running"}:
            return False

        should_requeue, evidence = self._can_requeue_unbound_active_execution(
            db,
            trigger=trigger,
            execution=execution,
            run_index=run_index,
        )
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="unbound_active_execution_detected",
            message="detected active execution without owner pod binding",
            level="warning",
            payload_json={
                "trigger_task_id": trigger.id if trigger is not None else None,
                "owner_pod_id_before": str(execution.owner_pod_id or "").strip() or None,
                "worker_job_id_before": str(execution.worker_job_id or "").strip() or None,
                "process_pid": execution.process_pid,
                "process_started_at": isoformat_local(execution.process_started_at),
                "dispatch_status": str(execution.dispatch_status or "").strip() or None,
                "run_index_id": run_index.id if run_index is not None else None,
                "runtime_evidence": evidence,
                "requeue_applied": should_requeue,
                "reason": reason,
            },
        )
        if not should_requeue:
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="unbound_active_execution_preserved_due_to_runtime_evidence",
                message="preserved unbound active execution because runtime evidence still exists",
                level="warning",
                payload_json={
                    "trigger_task_id": trigger.id if trigger is not None else None,
                    "runtime_evidence": evidence,
                    "reason": reason,
                },
            )
            return False

        message = "unbound active execution requeued after no-runtime confirmation"
        execution.worker_url = None
        execution.worker_job_id = None
        execution.owner_pod_id = None
        execution.status = "pending"
        execution.public_status = "pending"
        execution.control_state = "none"
        execution.dispatch_status = None
        execution.dispatch_error = message
        execution.process_status = "not_started"
        execution.process_pid = None
        execution.process_started_at = None
        execution.process_finished_at = None
        execution.started_at = None
        execution.finished_at = None
        execution.message = message
        if trigger is not None:
            trigger.status = "pending"
            trigger.public_status = "pending"
            trigger.control_state = "none"
            trigger.started_at = None
            trigger.finished_at = None
            trigger.message = message
            db.add(trigger)
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="pending", control_state="none")
        db.add(execution)
        self._refresh_task_list_projection_for_execution(db, execution)
        db.flush()
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="unbound_active_execution_requeued",
            message=message,
            level="warning",
            payload_json={
                "trigger_task_id": trigger.id if trigger is not None else None,
                "run_index_id": run_index.id if run_index is not None else None,
                "runtime_evidence": evidence,
                "reason": reason,
            },
        )
        return True

    def _slot_binding_state(
        self,
        *,
        execution: WorkflowExecution | None,
        effective_status: str,
    ) -> tuple[str | None, str | None]:
        normalized_status = _canonical_task_status(effective_status)
        if normalized_status in {"succeeded", "failed", "cancelled"}:
            return "released", None
        if execution is None:
            return ("unbound", "no execution record") if normalized_status else (None, None)

        owner_pod_id = str(execution.owner_pod_id or "").strip()
        dispatch_status = str(execution.dispatch_status or "").strip().lower()
        execution_status = _canonical_task_status(execution.status)

        if owner_pod_id:
            return "bound", None
        if dispatch_status in {"queued", "dispatching"}:
            return "queued", f"dispatch_status={dispatch_status}"
        if execution_status == "running":
            return "unbound", "active execution without owner_pod_id"
        return "unbound", None

    def _sync_runtime_state_snapshots(
        self,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        public_status: str | None = None,
        control_state: str | None = None,
    ) -> None:
        resolved_public_status = normalize_public_task_status(public_status)
        resolved_control_state = control_state or derive_task_control_state(
            dispatch_status=execution.dispatch_status if execution is not None else None,
            process_status=execution.process_status if execution is not None else None,
            trigger_message=trigger.message if trigger is not None else None,
            execution_message=execution.message if execution is not None else None,
        )
        if trigger is not None:
            trigger.public_status = resolved_public_status
            trigger.control_state = resolved_control_state
        if execution is not None:
            execution.public_status = resolved_public_status
            execution.control_state = resolved_control_state

    def _scan_task_detail(self, db: Session, trigger: TriggerTask) -> ScanTaskDetailResponse:
        response = self._scan_task_response(db, trigger)
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        first_task = manifest.tasks[0] if manifest.tasks else None
        task_markdown = ""
        artifact_refs: list[ArtifactRef] = []
        runtime_overrides: dict[str, Any] = {}
        task_metadata: dict[str, Any] = {}
        input_summary: dict[str, Any] = {}
        output_summary: dict[str, Any] = {}
        effective_config_summary: dict[str, Any] = {}
        task_root: str | None = None
        run_root: str | None = None
        workspace_root: str | None = None
        title = first_task.title if first_task else trigger.id
        if first_task:
            task_metadata = dict(first_task.metadata or {})
            dataflow_cli = task_metadata.get("dataflow_cli") if isinstance(task_metadata.get("dataflow_cli"), dict) else {}
            request_payload = task_metadata.get("dataflow_scan_request") if isinstance(task_metadata.get("dataflow_scan_request"), dict) else {}
            candidate_task_paths = [
                str(first_task.task_md_path or "").strip(),
                str(dataflow_cli.get("task_md_path") or "").strip(),
            ]
            for candidate in candidate_task_paths:
                if not candidate:
                    continue
                try:
                    task_markdown = Path(candidate).read_text(encoding="utf-8")
                    if task_markdown:
                        break
                except FileNotFoundError:
                    continue
            for item in task_metadata.get("artifact_refs") or []:
                if isinstance(item, dict):
                    artifact_refs.append(ArtifactRef.model_validate(item))
            runtime_overrides = dict(task_metadata.get("runtime_overrides") or {})
            input_summary = {
                "workspace_dir": request_payload.get("workspace_dir"),
                "data_flow": request_payload.get("data_flow"),
                "source_dir": request_payload.get("source_dir"),
                "output_dir": request_payload.get("output_dir"),
                "task_markdown_path": dataflow_cli.get("task_md_path"),
                "data_flow_dir": dataflow_cli.get("data_flow_dir"),
                "data_flow_files": dataflow_cli.get("data_flow_files") or [],
            }
        attempts = []
        run_service = get_run_index_service()
        for item in self._list_executions_for_trigger(db, trigger.id):
            try:
                run_index = run_service.get_run_index_by_execution(db, item) if item.workspace_root else None
            except Exception:
                db.rollback()
                run_index = None
            if not task_markdown and run_index is not None:
                try:
                    task_path = Path(run_index.run_root_path) / "run" / "input" / "task.md"
                    if not task_path.exists():
                        task_path = Path(run_index.run_root_path) / "input" / "task.md"
                    task_markdown = task_path.read_text(encoding="utf-8")
                except (FileNotFoundError, TypeError):
                    task_markdown = ""
            if run_index is not None:
                task_root = str(Path(run_index.run_root_path))
                run_root = str(Path(run_index.run_root_path) / "run")
                workspace_root = str(item.workspace_root or "") or str(Path(run_index.run_root_path) / "workspace")
                output_summary = {
                    "run_root": run_root,
                    "workspace_root": workspace_root,
                    "output_root": str(Path(run_index.run_root_path) / "output"),
                    "atomic_work_path": str(run_index.atomic_work_path or ""),
                    "run_name": str(run_index.run_name or ""),
                }
            attempts.append(self._attempt_response(item, run_id=run_index.id if run_index else None))
        if not effective_config_summary:
            effective_config_summary = {
                "profile_id": response.profile_id,
                "profile_version": response.profile_version,
                "runtime_overrides": runtime_overrides,
                "review_profile": task_metadata.get("dataflow_scan_request", {}).get("review_profile") if isinstance(task_metadata.get("dataflow_scan_request"), dict) else None,
                "compiled_profile": task_metadata.get("compiled_profile") if isinstance(task_metadata.get("compiled_profile"), dict) else {},
            }
        payload = response.model_dump()
        payload["title"] = title
        return ScanTaskDetailResponse(
            **payload,
            task_markdown=task_markdown,
            artifact_refs=artifact_refs,
            runtime_overrides=runtime_overrides,
            task_metadata=task_metadata,
            input_summary=input_summary,
            output_summary=output_summary,
            effective_config_summary=effective_config_summary,
            task_root=task_root,
            run_root=run_root,
            workspace_root=workspace_root,
            attempts=attempts,
            abnormal_reason_history=self._abnormal_reason_history(db, trigger),
        )

    def _attempt_response(self, execution: WorkflowExecution, run_id: str | None = None) -> ScanTaskAttemptResponse:
        slot_binding_state, slot_binding_reason = self._slot_binding_state(
            execution=execution,
            effective_status=execution.status,
        )
        return ScanTaskAttemptResponse(
            execution_id=execution.id,
            task_id=execution.trigger_task_id,
            attempt_no=execution.attempt_no,
            status=execution.status,
            run_id=run_id,
            owner_pod_id=execution.owner_pod_id,
            worker_url=execution.worker_url,
            worker_job_id=execution.worker_job_id,
            dispatch_status=execution.dispatch_status,
            slot_binding_state=slot_binding_state,
            slot_binding_reason=slot_binding_reason,
            dispatch_error=execution.dispatch_error,
            process_pid=execution.process_pid,
            process_host=execution.process_host,
            process_status=execution.process_status,
            process_started_at=execution.process_started_at,
            process_finished_at=execution.process_finished_at,
            started_at=execution.started_at,
            finished_at=execution.finished_at,
            recovery_reason=execution.recovery_reason,
            message=execution.message,
            workspace_root=execution.workspace_root,
            output_manifest_path=execution.output_manifest_path,
            output_task_count=execution.output_task_count,
            created_at=execution.created_at,
            updated_at=execution.updated_at,
        )

    def _execution_command_payload(self, db: Session, execution_id: str) -> dict[str, Any]:
        event = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == execution_id,
                WorkflowExecutionEvent.event_type == "execution_started",
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .first()
        )
        payload = dict(event.payload_json or {}) if event else {}
        command = payload.get("command") if isinstance(payload.get("command"), list) else []
        return {
            "command": [str(item) for item in command],
            "command_display": str(payload.get("command_display") or ""),
        }

    def _register_cli_process(self, execution_id: str, process: subprocess.Popen) -> None:
        with self._process_lock:
            self._active_cli_processes[execution_id] = process

    def _forget_cli_process(self, execution_id: str, process: subprocess.Popen | None = None) -> None:
        with self._process_lock:
            current = self._active_cli_processes.get(execution_id)
            if process is None or current is process:
                self._active_cli_processes.pop(execution_id, None)

    def _local_cli_process(self, execution_id: str) -> subprocess.Popen | None:
        with self._process_lock:
            process = self._active_cli_processes.get(execution_id)
        if process is not None and process.poll() is None:
            return process
        if process is not None:
            self._forget_cli_process(execution_id, process)
        return None

    def _process_heartbeat_stale_after_seconds(self) -> int:
        cfg = get_config()
        configured_seconds = max(int(getattr(cfg.service, "process_heartbeat_stale_after_seconds", 0) or 0), 0)
        scheduler_seconds = max(int(getattr(cfg.scheduler, "heartbeat_interval_seconds", 0) or 0) * 3, 0)
        cancel_poll_seconds = max(int(getattr(cfg.service, "execution_cancel_check_interval_seconds", 0) or 0) * 5, 0)
        return max(configured_seconds, scheduler_seconds, cancel_poll_seconds, 30)

    def _process_start_grace_seconds(self) -> int:
        cfg = get_config()
        scheduler_seconds = max(int(getattr(cfg.scheduler, "poll_interval_seconds", 0) or 0) * 5, 0)
        cancel_poll_seconds = max(int(getattr(cfg.service, "execution_cancel_check_interval_seconds", 0) or 0) * 5, 0)
        return max(scheduler_seconds, cancel_poll_seconds, 30)

    def _parse_process_timestamp(self, value: Any) -> datetime | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed.astimezone(UTC_PLUS_8).replace(tzinfo=None)
            return parsed
        except ValueError:
            return None

    def _read_run_process_file(self, run_root: str | Path | None) -> dict[str, Any]:
        if not run_root:
            return {}
        root = Path(run_root)
        path = root / "run" / "_meta" / "process.json"
        if not path.is_file():
            path = root / "_meta" / "process.json"
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"read_error": f"failed to read {path}"}
        return payload if isinstance(payload, dict) else {}

    def _write_cli_process_file(
        self,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        cmd: list[str],
        process: subprocess.Popen,
        status_text: str,
        return_code: int | None = None,
    ) -> None:
        if not execution.workspace_root:
            return
        current = now_local()
        payload: dict[str, Any] = {
            "execution_id": execution.id,
            "trigger_task_id": trigger.id,
            "pid": process.pid,
            "pod_id": get_config().scheduler.pod_id,
            "host_name": get_config().scheduler.host_name,
            "command": cmd,
            "command_display": _command_display(cmd),
            "started_at": isoformat_local(execution.process_started_at or current) or "",
            "status": status_text,
            "updated_at": isoformat_local(current) or "",
        }
        if status_text in {"running", "timeout_requested", "stop_requested", "delete_requested"}:
            payload["heartbeat_at"] = isoformat_local(current) or ""
        if execution.process_finished_at:
            payload["finished_at"] = isoformat_local(execution.process_finished_at) or ""
        if return_code is not None:
            payload["return_code"] = return_code
        write_json(Path(execution.workspace_root) / "run" / "_meta" / "process.json", payload)

    def _try_write_cli_process_file(
        self,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        cmd: list[str],
        process: subprocess.Popen,
        status_text: str,
        return_code: int | None = None,
    ) -> bool:
        try:
            self._write_cli_process_file(
                execution=execution,
                trigger=trigger,
                cmd=cmd,
                process=process,
                status_text=status_text,
                return_code=return_code,
            )
            return True
        except OSError as exc:
            logger.warning(
                "run process metadata write failed; child process will continue: execution_id=%s status=%s error=%s",
                execution.id,
                status_text,
                exc,
            )
            return False

    def _resume_command_payload_from_plan(self, *, plan: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
        argv, _ = self._build_dataflow_cli_argv(
            plan=plan,
            config_payload={},
            request=request,
            compiled_config={},
            runtime_overrides={},
            agent_state_dirs={},
        )
        command = [sys.executable, str(Path(__file__).resolve().parents[2] / "run_vuln_scan.py"), *argv]
        return {
            "argv": argv,
            "command": command,
            "command_display": _command_display(command),
        }

    def _task_dataflow_cli_metadata(self, trigger: TriggerTask | None) -> dict[str, Any]:
        if trigger is None:
            return {}
        try:
            manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        except Exception:
            return {}
        for task in manifest.tasks:
            metadata = dict(task.metadata or {})
            cli_payload = metadata.get("dataflow_cli")
            if isinstance(cli_payload, dict):
                return dict(cli_payload)
        return {}

    def _command_payload_is_resume(self, payload: dict[str, Any]) -> bool:
        command_items = payload.get("command") if isinstance(payload.get("command"), list) else []
        argv_items = payload.get("argv") if isinstance(payload.get("argv"), list) else []
        text = " ".join(str(item) for item in [*command_items, *argv_items, payload.get("command_display") or ""])
        return "--resume-run-dir" in text or str(payload.get("mode") or "").lower() == "resume"

    def _retry_command_display(
        self,
        db: Session,
        *,
        run_index,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
    ) -> str:
        candidates: list[dict[str, Any]] = []
        task_payload = self._task_dataflow_cli_metadata(trigger)
        if task_payload:
            candidates.append(task_payload)
        if execution is not None:
            event_payload = self._execution_command_payload(db, execution.id)
            if event_payload:
                candidates.append(event_payload)
        process_payload = self._read_run_process_file(run_index.run_root_path)
        if process_payload:
            candidates.append(process_payload)
        raw_summary = dict(_load_externalized_json_payload(run_index.run_root_path, run_index.raw_summary_json) or {})
        raw_cli = raw_summary.get("dataflow_cli") if isinstance(raw_summary.get("dataflow_cli"), dict) else {}
        if raw_cli:
            candidates.append(dict(raw_cli))
        for payload in candidates:
            if not self._command_payload_is_resume(payload):
                continue
            display = str(payload.get("command_display") or "").strip()
            if display:
                return display
            command = payload.get("command") if isinstance(payload.get("command"), list) else payload.get("argv")
            if isinstance(command, list) and command:
                return _command_display([str(item) for item in command])
        return ""

    def _signal_local_cli_process(
        self,
        execution_id: str,
        *,
        wait: bool,
        graceful_timeout: float = 5.0,
        terminate_timeout: float = 5.0,
    ) -> dict[str, Any]:
        process = self._local_cli_process(execution_id)
        if process is None:
            return {"found": False, "signal": "db_flag_only"}
        payload: dict[str, Any] = {"found": True, "pid": process.pid, "signal": "sigint"}
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
            except ProcessLookupError:
                payload["signal"] = "already_exited"
                return payload
        if not wait:
            return payload
        try:
            payload["exit_code"] = process.wait(timeout=graceful_timeout)
            payload["signal"] = "sigint"
            return payload
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                process.terminate()
            payload["signal"] = "terminate"
        try:
            payload["exit_code"] = process.wait(timeout=terminate_timeout)
            return payload
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                process.kill()
            payload["signal"] = "kill"
            payload["exit_code"] = process.wait()
            return payload

    def _cancel_worker_job(self, execution: WorkflowExecution | None) -> dict[str, Any]:
        if execution is None or not execution.worker_url or not execution.worker_job_id:
            return {"found": False, "signal": None}
        try:
            payload = get_dataflow_worker_client(execution.worker_url).cancel_job(execution.worker_job_id)
            return {
                "found": True,
                "signal": "worker_cancel",
                "worker_url": execution.worker_url,
                "worker_job_id": execution.worker_job_id,
                "worker_response": payload,
            }
        except DataflowWorkerError as exc:
            return {
                "found": False,
                "signal": "worker_unreachable",
                "worker_url": execution.worker_url,
                "worker_job_id": execution.worker_job_id,
                "error": str(exc),
            }

    def _record_worker_control_result(
        self,
        db: Session,
        *,
        execution: WorkflowExecution | None,
        action: str,
        payload: dict[str, Any],
    ) -> None:
        if execution is None or not execution.id or not payload.get("signal"):
            return
        signal_name = str(payload.get("signal") or "")
        level = "warning" if signal_name == "worker_unreachable" else "info"
        event_type = f"worker_{action}_{'deferred' if signal_name == 'worker_unreachable' else 'requested'}"
        message = (
            f"worker {action} requested but worker is unreachable"
            if signal_name == "worker_unreachable"
            else f"worker {action} requested"
        )
        self.record_event(
            db,
            execution_id=execution.id,
            event_type=event_type,
            message=message,
            level=level,
            payload_json=payload,
        )

    def _write_run_control_state(self, run_root: str | Path | None, *, status_text: str, message: str) -> None:
        if not run_root:
            return
        try:
            root = Path(run_root)
            if not root.exists():
                return
            timestamp_path = root / "run" / "_meta" / "run_timestamps.json"
            if not timestamp_path.exists() and (root / "_meta").exists():
                timestamp_path = root / "_meta" / "run_timestamps.json"
            payload: dict[str, Any] = {}
            if timestamp_path.is_file():
                try:
                    import json

                    payload = json.loads(timestamp_path.read_text(encoding="utf-8"))
                except Exception:
                    payload = {}
            current = now_local()
            normalized_status = str(status_text or "").strip().lower()
            payload.update(
                {
                    "status": normalized_status or status_text,
                    "control_message": message,
                    "last_updated_at": isoformat_local(current),
                }
            )
            if is_run_terminal(normalized_status) and not payload.get("finished_at"):
                payload["finished_at"] = isoformat_local(current)
            write_json(
                timestamp_path,
                payload,
            )
        except OSError:
            pass

    def _build_workspace_root(self, execution_id: str, definition: WorkflowDefinition) -> Path:
        base_dir = definition.workspace_base_dir or get_config().service.workspace_base_dir
        return ensure_dir(Path(base_dir) / execution_id)

    def _copy_uploaded_inputs_to_task_dir(self, *, project_id: str, task_input_dir: Path, metadata: Dict[str, Any]) -> List[Dict[str, str]]:
        uploads = metadata.get("task_input_uploads")
        if not isinstance(uploads, list) or not uploads:
            return []
        copied: List[Dict[str, str]] = []
        assets_dir = ensure_dir(task_input_dir / get_config().service.default_artifact_subdir)

        for item in uploads:
            if not isinstance(item, dict):
                continue
            storage_key = str(item.get("storage_key") or "").strip()
            if not storage_key:
                continue
            relative_path_raw = str(item.get("relative_path") or item.get("filename") or "").strip()
            if not relative_path_raw:
                continue
            relative_path = Path(relative_path_raw)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"invalid uploaded relative path: {relative_path_raw}",
                )
            storage_path = Path(storage_key)
            if storage_path.is_absolute() or ".." in storage_path.parts:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"invalid uploaded storage key: {storage_key}",
                )
            source_path = self._resolve_project_storage_key(project_id=project_id, storage_key=storage_key, label="uploaded file")
            if not source_path.exists() or not source_path.is_file():
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"uploaded file not found in project storage: {storage_key}",
                )
            target_path = assets_dir / relative_path
            ensure_dir(target_path.parent)
            shutil.copy2(source_path, target_path)
            copied.append(
                {
                    "relative_path": relative_path.as_posix(),
                    "target_path": abs_path(target_path),
                    "source_storage_key": storage_key,
                }
            )
        if copied:
            write_json(task_input_dir / "uploaded_assets_manifest.json", {"items": copied})
        return copied

    def _normalize_project_path(self, raw_path: str) -> str:
        raw = str(raw_path or "").strip() or "/"
        if any(part == ".." for part in raw.split("/")):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="project path escapes project root")
        normalized = posixpath.normpath(raw)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if normalized.startswith("/../") or normalized == "/..":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="project path escapes project root")
        return normalized

    def _ensure_path_within(self, *, path: Path, root: Path, label: str) -> Path:
        resolved = path.resolve()
        root_resolved = root.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} escapes allowed root") from exc
        return resolved

    def _project_files_root(self, project_id: str) -> Path:
        config = get_config()
        data_mount_path = Path(config.fileserver_service.data_mount_path).resolve()
        project_root = data_mount_path / config.fileserver_service.project_files_dirname / sanitize_name(project_id)
        return self._ensure_path_within(path=project_root, root=data_mount_path, label="project_root")

    def _build_project_filesystem_entry(self, *, project_root: Path, candidate: Path) -> dict[str, Any]:
        resolved = self._ensure_path_within(path=candidate, root=project_root, label="project filesystem path")
        stat = resolved.stat()
        relative = resolved.relative_to(project_root).as_posix()
        depth = 0 if not relative else len(relative.split("/"))
        is_dir = resolved.is_dir()
        node_type = "file"
        if is_dir:
            node_type = "subproject" if depth == 1 else "directory"
        has_children = False
        if is_dir:
            try:
                next(resolved.iterdir())
                has_children = True
            except StopIteration:
                has_children = False
        return {
            "node_type": node_type,
            "name": resolved.name,
            "path": f"/{relative}" if relative else "/",
            "content_type": None,
            "size": stat.st_size if resolved.is_file() else None,
            "updated_at": datetime.fromtimestamp(stat.st_mtime, tz=UTC_PLUS_8).isoformat(),
            "has_children": has_children,
            "special_badge": None,
        }

    def _list_project_filesystem_entries(self, *, project_root: Path, current_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        directories: list[dict[str, Any]] = []
        files: list[dict[str, Any]] = []
        if not current_dir.exists():
            return directories, files
        for child in sorted(current_dir.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
            entry = self._build_project_filesystem_entry(project_root=project_root, candidate=child)
            if entry["node_type"] == "file":
                files.append(entry)
            else:
                directories.append(entry)
        return directories, files

    def get_project_filesystem_root(self, principal: dict, project_id: str) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        project_root = self._project_files_root(project_id)
        directories, files = self._list_project_filesystem_entries(project_root=project_root, current_dir=project_root)
        items = directories + files
        return {
            "project_id": project_id,
            "root_name": project_id,
            "total": len(items),
            "items": items,
        }

    def get_project_filesystem_children(self, principal: dict, project_id: str, path: str) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        project_root = self._project_files_root(project_id)
        normalized = self._normalize_project_path(path)
        current_dir = project_root if normalized == "/" else self._ensure_path_within(
            path=project_root / normalized.lstrip("/"),
            root=project_root,
            label="project filesystem path",
        )
        if not current_dir.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"path not found: {normalized}")
        if not current_dir.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="path must be a directory")

        directories, files = self._list_project_filesystem_entries(project_root=project_root, current_dir=current_dir)
        breadcrumbs = [{"node_type": "project", "name": project_id, "path": "/"}]
        if normalized != "/":
            parts = [part for part in normalized.split("/") if part]
            assembled: list[str] = []
            for index, part in enumerate(parts):
                assembled.append(part)
                breadcrumbs.append(
                    {
                        "node_type": "subproject" if index == 0 else "directory",
                        "name": part,
                        "path": f"/{'/'.join(assembled)}",
                    }
                )

        return {
            "project_id": project_id,
            "current_path": normalized,
            "current_name": project_id if normalized == "/" else current_dir.name,
            "breadcrumbs": breadcrumbs,
            "directories": directories,
            "files": files,
        }

    def _resolve_project_storage_key(self, *, project_id: str, storage_key: str, label: str) -> Path:
        storage_path = Path(str(storage_key or "").strip())
        if not storage_path.parts or storage_path.is_absolute() or ".." in storage_path.parts:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"invalid {label} storage_key")
        config = get_config()
        parts = storage_path.parts
        project_component = sanitize_name(project_id)
        if parts and parts[0] == config.fileserver_service.project_files_dirname:
            if len(parts) < 2 or parts[1] != project_component:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} escapes project root")
        data_mount_path = Path(config.fileserver_service.data_mount_path).resolve()
        project_root = self._project_files_root(project_id)
        candidates = [
            data_mount_path / storage_path,
            project_root / storage_path,
        ]
        for candidate in candidates:
            try:
                return self._ensure_path_within(path=candidate, root=project_root, label=label)
            except HTTPException:
                continue
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} escapes project root")

    def _resolve_dataflow_input_ref(self, *, project_id: str, ref: dict[str, Any], expected: str) -> Path:
        source = str(ref.get("source") or "project_filesystem").strip()
        if source in {"project_filesystem", "project_path", "project"}:
            project_root = self._project_files_root(project_id)
            normalized = self._normalize_project_path(str(ref.get("path") or ""))
            candidate = project_root / normalized.lstrip("/")
            resolved = self._ensure_path_within(path=candidate, root=project_root, label=expected)
        elif source in {"fileserver_storage", "storage_key", "managed_file"}:
            storage_key = str(ref.get("storage_key") or ref.get("path") or "").strip()
            if not storage_key:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} storage_key is required")
            resolved = self._resolve_project_storage_key(project_id=project_id, storage_key=storage_key, label=expected)
        elif source in {"absolute", "absolute_path", "local_path"}:
            if not get_config().service.allow_absolute_input_refs:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute_path input is disabled")
            raw = str(ref.get("path") or "").strip()
            if not raw:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} path is required")
            candidate = Path(raw)
            if not candidate.is_absolute():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute path is required")
            resolved = self._ensure_path_within(path=candidate, root=self._project_files_root(project_id), label=expected)
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"unsupported {expected} source: {source}")
        if not resolved.exists():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} not found: {resolved}")
        return resolved

    def _copy_ref_to_target(self, *, source_path: Path, target_path: Path, expected: str) -> None:
        if expected == "file":
            if not source_path.is_file():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected file but got: {source_path}")
            ensure_dir(target_path.parent)
            shutil.copy2(source_path, target_path)
            return
        if not source_path.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {source_path}")
        ensure_dir(target_path)
        shutil.copytree(source_path, target_path, dirs_exist_ok=True)

    def _resolve_custom_execution_paths(
        self,
        *,
        project_id: str,
        metadata: Dict[str, Any],
        execution_id: str,
    ) -> tuple[Path | None, Path | None]:
        request = metadata.get("dataflow_scan_request")
        if not isinstance(request, dict):
            return None, None
        # Dataflow vulnerability scan tasks use the standard task-root layout:
        # <project>/app/secflow-app-dataflow-vuln-scanner/<run_name>/{input,output,run}.
        # User-provided workspace/output refs are treated as input metadata only
        # and must not move runtime or final artifacts outside the task root.
        return None, None

    def _default_dataflow_cli_runs_root(self, project_id: str) -> Path:
        config = get_config()
        return (
            Path(config.fileserver_service.data_mount_path)
            / config.fileserver_service.project_files_dirname
            / sanitize_name(project_id)
            / "app"
            / "secflow-app-dataflow-vuln-scanner"
        ).resolve()

    def _normalize_model_override(self, *, model: str | None, provider: str | None) -> str | None:
        model_text = str(model or "").strip()
        provider_text = str(provider or "").strip()
        if not model_text:
            return None
        if provider_text and "/" not in model_text:
            return f"{provider_text}/{model_text}"
        return model_text

    def _is_dataflow_cli_resume_request(self, request: dict[str, Any]) -> bool:
        return bool(str(request.get("resume_run_dir") or "").strip())

    def _resolve_dataflow_cli_runs_root(self, *, project_id: str, request: dict[str, Any]) -> Path:
        # Keep every dataflow-vuln task under the service task root. A
        # workspace_dir request may still be stored in input metadata, but it
        # must not redirect the task directory outside app/<service>/<run_name>.
        return ensure_dir(self._default_dataflow_cli_runs_root(project_id)).resolve()

    def _build_dataflow_cli_run_name(
        self,
        *,
        trigger_id: str,
        request: dict[str, Any],
        runs_root: Path,
    ) -> str:
        options = request.get("options") if isinstance(request.get("options"), dict) else {}
        requested_run_name = str(options.get("run_name") or "").strip()
        base_name = _sanitize_dataflow_run_name(requested_run_name or trigger_id)
        if not base_name:
            base_name = sanitize_name(trigger_id)
        if not base_name:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="invalid trigger task id")

        candidate = runs_root / base_name
        if not candidate.exists():
            return base_name
        if not candidate.is_dir():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"task directory path is occupied by a non-directory: {candidate}",
            )

        suffix = sanitize_name(trigger_id)[-8:] or uuid.uuid4().hex[:8]
        fallback = f"{base_name}_{suffix}"
        fallback_candidate = runs_root / fallback
        if not fallback_candidate.exists():
            return fallback
        if not fallback_candidate.is_dir():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"task directory path is occupied by a non-directory: {fallback_candidate}",
            )
        return f"{fallback}_{uuid.uuid4().hex[:6]}"

    def _build_dataflow_cli_resume_plan(
        self,
        *,
        project_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        raw_run_dir = str(request.get("resume_run_dir") or "").strip()
        if not raw_run_dir:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="resume_run_dir is required")
        candidate = Path(raw_run_dir)
        if not candidate.is_absolute():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="resume_run_dir must be an absolute path")
        run_dir = self._ensure_path_within(
            path=candidate,
            root=self._project_files_root(project_id),
            label="resume_run_dir",
        )
        if not run_dir.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"resume_run_dir not found: {run_dir}")
        task_md_path = run_dir / "run" / "input" / "task.md"
        if not task_md_path.exists():
            task_md_path = run_dir / "input" / "task.md"
        return {
            "launcher": "run_vuln_scan.py",
            "mode": "resume",
            "run_name": run_dir.name,
            "runs_root": abs_path(run_dir.parent),
            "run_dir": abs_path(run_dir),
            "task_md_path": abs_path(task_md_path),
            "resume_run_dir": abs_path(run_dir),
            "extra_cycles": max(int(request.get("resume_extra_cycles") or 5), 1),
        }

    def _build_dataflow_cli_plan(
        self,
        *,
        project_id: str,
        trigger_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        if self._is_dataflow_cli_resume_request(request):
            return self._build_dataflow_cli_resume_plan(project_id=project_id, request=request)
        data_flow_ref = request.get("data_flow")
        source_dir_ref = request.get("source_dir")
        if not isinstance(data_flow_ref, dict) or not isinstance(source_dir_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow scan request is incomplete")
        if request.get("output_dir") is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="output_dir is not supported by run_vuln_scan.py launcher; final outputs are written to the task output directory",
            )
        data_flow_path = self._resolve_dataflow_input_ref(project_id=project_id, ref=data_flow_ref, expected="data_flow")
        if not data_flow_path.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {data_flow_path}")
        source_dir_path = self._resolve_dataflow_input_ref(project_id=project_id, ref=source_dir_ref, expected="source_dir")
        if not source_dir_path.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {source_dir_path}")
        from run_vuln_scan import data_flow_manifest_input
        data_flow_manifest = data_flow_manifest_input(data_flow_path)
        runs_root = self._resolve_dataflow_cli_runs_root(project_id=project_id, request=request)
        run_name = self._build_dataflow_cli_run_name(
            trigger_id=trigger_id,
            request=request,
            runs_root=runs_root,
        )
        run_dir = runs_root / run_name
        task_md_path = run_dir / "run" / "input" / "task.md"
        return {
            "launcher": "run_vuln_scan.py",
            "run_name": run_name,
            "runs_root": abs_path(runs_root),
            "run_dir": abs_path(run_dir),
            "task_md_path": abs_path(task_md_path),
            "data_flow_input": abs_path(data_flow_path),
            "data_flow_dir": data_flow_manifest["data_flow_dir"],
            "data_flow_files": data_flow_manifest["data_flow_files"],
            "source_dir": abs_path(source_dir_path),
        }

    def _write_dataflow_cli_task_preview(self, plan: dict[str, Any]) -> None:
        run_dir = Path(plan["run_dir"])
        task_md_path = Path(plan["task_md_path"])
        ensure_dir(task_md_path.parent)
        input_manifest = {
            "schema_version": 1,
            "generated_at": isoformat_local(now_local()),
            "task": {
                "task_id": plan.get("run_name"),
                "launcher": plan.get("launcher"),
                "mode": plan.get("mode") or "fresh",
            },
            "input": {},
            "prompt": {"task_md_path": abs_path(task_md_path)},
        }
        if plan.get("mode") == "resume":
            if not task_md_path.exists():
                write_text(
                    task_md_path,
                    (
                        "# Resume Existing Dataflow Vulnerability Scan\n\n"
                        f"- Run directory: `{plan['run_dir']}`\n"
                        f"- Extra cycles: `{plan.get('extra_cycles', 5)}`\n"
                    ),
                )
            input_manifest["task"]["task_id"] = plan.get("run_name")
            input_manifest["input"] = {"resume_run_dir": plan.get("resume_run_dir")}
        else:
            from run_vuln_scan import generate_task_md
            task_content = generate_task_md(plan["data_flow_input"], plan["source_dir"]).strip() + "\n"
            write_text(
                task_md_path,
                task_content,
            )
            import hashlib
            input_manifest["task"]["task_id"] = plan.get("run_name")
            input_manifest["input"] = {
                "data_flow_dir": plan.get("data_flow_dir"),
                "data_flow_files": plan.get("data_flow_files") or [],
                "source_dir": plan.get("source_dir"),
            }
            input_manifest["prompt"].update({
                "content_length": len(task_content),
                "content_sha256": hashlib.sha256(task_content.encode("utf-8")).hexdigest(),
            })
        write_json(run_dir / "input" / "input_manifest.json", input_manifest)
        ensure_dir(run_dir / "output")

    def _dataflow_cli_config_requires_file(self, *, request: dict[str, Any], runtime_overrides: dict[str, Any]) -> bool:
        # worker_timeout/advisor_timeout are deprecated compatibility fields and
        # do not control RPC prompt timeout, so they must not force the launcher
        # onto a stale compiled -c config path. Only real runtime_overrides need
        # a temporary config file.
        return bool(runtime_overrides)

    def _build_dataflow_cli_argv(
        self,
        *,
        plan: dict[str, Any],
        config_payload: dict[str, Any],
        request: dict[str, Any],
        compiled_config: dict[str, Any],
        runtime_overrides: dict[str, Any],
        agent_state_dirs: dict[str, dict[str, str]],
    ) -> tuple[list[str], str | None]:
        if plan.get("mode") == "resume" or self._is_dataflow_cli_resume_request(request):
            argv = [
                "--resume-run-dir",
                plan["resume_run_dir"],
                "--extra-cycles",
                str(max(int(request.get("resume_extra_cycles") or plan.get("extra_cycles") or 5), 1)),
            ]
            model = self._normalize_model_override(
                model=str(request.get("model") or "").strip() or None,
                provider=str(request.get("provider") or "").strip() or None,
            )
            if model:
                argv.extend(["--model", model])
            if bool(request.get("clean_workspace")):
                argv.append("--clean")
            return argv, None

        argv = [
            "--data-flow",
            plan["data_flow_input"],
            "--source-dir",
            plan["source_dir"],
            "--runs-root",
            plan["runs_root"],
            "--run-name",
            plan["run_name"],
        ]
        temp_config_path: str | None = None

        def first_present_int(*values: Any, default: int) -> int:
            for value in values:
                if value is None or value == "":
                    continue
                return int(value)
            return default

        model = str(config_payload.get("model") or request.get("model") or "").strip()
        review_profile = str(config_payload.get("review_profile") or request.get("review_profile") or "balanced").strip() or "balanced"
        max_cycles = first_present_int(config_payload.get("max_review_cycles"), request.get("max_review_cycles"), default=0)
        agent_timeout_retry_enabled = request.get("agent_timeout_retry_enabled")
        if agent_timeout_retry_enabled is None:
            agent_timeout_retry_enabled = config_payload.get("agent_timeout_retry_enabled", True)
        agent_timeout_retry_enabled = bool(agent_timeout_retry_enabled)
        configured_timeout_max_retries = first_present_int(
            request.get("timeout_max_retries"),
            config_payload.get("timeout_max_retries"),
            request.get("agent_timeout_max_retries"),
            config_payload.get("agent_timeout_max_retries"),
            default=3,
        )
        timeout_max_retries = max(configured_timeout_max_retries, 1) if agent_timeout_retry_enabled else 1
        timeout_retry_interval_seconds = first_present_int(config_payload.get("timeout_retry_interval_seconds"), request.get("timeout_retry_interval_seconds"), default=30)
        result_review_concurrency = first_present_int(config_payload.get("result_review_concurrency"), request.get("result_review_concurrency"), default=3)

        if agent_state_dirs or self._dataflow_cli_config_requires_file(request=request, runtime_overrides=runtime_overrides):
            fd, temp_config_path = tempfile.mkstemp(prefix="secflow-dataflow-cli-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json_payload = self._apply_agent_state_dirs_to_compiled_config(
                    compiled_config=compiled_config or {},
                    agent_state_dirs=agent_state_dirs,
                )
                apply_profile_runtime_policy_to_config(json_payload, review_profile)
                import json

                json.dump(json_payload, handle, ensure_ascii=False, indent=2)
            argv.extend(["--config", temp_config_path])
            argv.extend(["--timeout-max-retries", str(max(timeout_max_retries, 1))])
            argv.extend(["--timeout-retry-interval-seconds", str(max(timeout_retry_interval_seconds, 0))])
            return argv, temp_config_path

        if model:
            argv.extend(["--model", model])
        if max_cycles > 0:
            argv.extend(["--max-cycles", str(max_cycles)])
        argv.extend(["--timeout-max-retries", str(max(timeout_max_retries, 1))])
        argv.extend(["--timeout-retry-interval-seconds", str(max(timeout_retry_interval_seconds, 0))])
        argv.extend(["--result-review-concurrency", str(max(result_review_concurrency, 1))])
        argv.extend(["--review-profile", review_profile])
        return argv, temp_config_path

    def _is_dataflow_cli_task_metadata(self, metadata: dict[str, Any]) -> bool:
        request = metadata.get("dataflow_scan_request")
        return isinstance(request, dict) and request.get("launcher") == "run_vuln_scan.py"

    def _update_trigger_cli_task(
        self,
        *,
        trigger: TriggerTask,
        metadata: dict[str, Any],
        task_md_path: str,
    ) -> None:
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        if not manifest.tasks:
            return
        task = manifest.tasks[0]
        task.metadata = metadata
        task.task_md_path = task_md_path
        trigger.input_tasks_json = TaskManifest(tasks=[task, *manifest.tasks[1:]]).model_dump(mode="json")

    def _materialize_dataflow_scan_inputs(self, *, materialized_input_dir: Path, metadata: Dict[str, Any]) -> tuple[str | None, Dict[str, Any]]:
        request = metadata.get("dataflow_scan_request")
        if not isinstance(request, dict):
            return None, {}
        project_id = str(request.get("project_id") or "").strip()
        data_flow_ref = request.get("data_flow")
        source_dir_ref = request.get("source_dir")
        workspace_ref = request.get("workspace_dir")
        output_ref = request.get("output_dir")
        if not project_id or not isinstance(data_flow_ref, dict) or not isinstance(source_dir_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow scan request is incomplete")

        source_data_flow = self._resolve_dataflow_input_ref(project_id=project_id, ref=data_flow_ref, expected="data_flow")
        if not source_data_flow.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {source_data_flow}")
        source_source_dir = self._resolve_dataflow_input_ref(project_id=project_id, ref=source_dir_ref, expected="source_dir")
        workspace_base = None
        output_base = None
        if workspace_ref is not None:
            if not isinstance(workspace_ref, dict):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="workspace_dir ref is invalid")
            workspace_base = self._resolve_dataflow_input_ref(project_id=project_id, ref=workspace_ref, expected="workspace_dir")
            if not workspace_base.is_dir():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {workspace_base}")
        if output_ref is not None:
            if not isinstance(output_ref, dict):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="output_dir ref is invalid")
            output_base = self._resolve_dataflow_input_ref(project_id=project_id, ref=output_ref, expected="output_dir")
            if not output_base.is_dir():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {output_base}")
        if workspace_base is not None and output_base is not None:
            self._ensure_path_within(path=output_base, root=workspace_base, label="output_dir")
        effective_output_base = output_base
        if workspace_base is not None and effective_output_base is None:
            effective_output_base = workspace_base / "output"
        scan_input_dir = ensure_dir(materialized_input_dir / "dataflow_scan")
        data_flow_target = scan_input_dir / "data_flow"
        source_target = scan_input_dir / "source"
        self._copy_ref_to_target(source_path=source_data_flow, target_path=data_flow_target, expected="directory")
        self._copy_ref_to_target(source_path=source_source_dir, target_path=source_target, expected="directory")

        from run_vuln_scan import data_flow_manifest_input, generate_task_md

        generated_markdown = generate_task_md(abs_path(data_flow_target), abs_path(source_target))
        materialized_data_flow = data_flow_manifest_input(data_flow_target)
        materialized = {
            "data_flow_dir": materialized_data_flow["data_flow_dir"],
            "data_flow_files": materialized_data_flow["data_flow_files"],
            "source_dir": abs_path(source_target),
            "original_data_flow": data_flow_ref,
            "original_source_dir": source_dir_ref,
            "options": request.get("options") or {},
        }
        if workspace_base is not None:
            materialized["workspace_dir"] = abs_path(workspace_base)
            materialized["original_workspace_dir"] = workspace_ref
        if effective_output_base is not None:
            materialized["output_dir"] = abs_path(effective_output_base)
        if output_base is not None:
            materialized["original_output_dir"] = output_ref
        elif workspace_base is not None:
            materialized["output_dir_mode"] = "auto_workspace_output"
        write_json(scan_input_dir / "input_manifest.json", materialized)
        return generated_markdown, materialized

    def _normalize_trigger_tasks(
        self,
        *,
        project_id: str,
        input_tasks: List[TriggerTaskInputTask],
        workspace_root: Path,
        entry_input_task_type: str,
    ) -> List[TaskItem]:
        metadata_tasks_root = ensure_dir(workspace_root / "input" / "tasks")
        runtime_tasks_root = ensure_dir(workspace_root / "run" / "input" / "tasks")
        materialized_tasks_root = ensure_dir(workspace_root / "run" / "materialized_inputs" / "tasks")
        normalized: List[TaskItem] = []
        if not input_tasks:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="input_tasks must not be empty")
        for index, raw_task in enumerate(input_tasks, start=1):
            provided_task_type = (raw_task.task_type or "").strip()
            if provided_task_type and provided_task_type != entry_input_task_type:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=(
                        f"task {raw_task.task_id or index} task_type '{provided_task_type}' "
                        f"does not match entry_input_task_type '{entry_input_task_type}'"
                    ),
                )
            task_id = raw_task.task_id or _new_id(f"task{index}")
            task_slug = sanitize_name(task_id)
            metadata_dir = ensure_dir(metadata_tasks_root / task_slug)
            runtime_input_dir = ensure_dir(runtime_tasks_root / task_slug)
            materialized_input_dir = ensure_dir(materialized_tasks_root / task_slug)
            metadata = dict(raw_task.metadata or {})
            markdown = raw_task.task_markdown
            if markdown is None and raw_task.task_md_path:
                markdown = Path(raw_task.task_md_path).read_text(encoding="utf-8")
            generated_markdown, materialized_inputs = self._materialize_dataflow_scan_inputs(
                materialized_input_dir=materialized_input_dir,
                metadata=metadata,
            )
            if generated_markdown:
                markdown = generated_markdown
                metadata["dataflow_scan_materialized"] = materialized_inputs
            if markdown is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"task {task_id} missing task_markdown",
                )
            task_content = markdown.strip() + "\n"
            task_md_path = write_text(runtime_input_dir / "task.md", task_content)
            copied_inputs = self._copy_uploaded_inputs_to_task_dir(
                project_id=project_id,
                task_input_dir=materialized_input_dir,
                metadata=metadata,
            )
            import hashlib

            write_json(
                metadata_dir / "task.json",
                {
                    "schema_version": 1,
                    "task_id": task_id,
                    "task_type": entry_input_task_type,
                    "title": raw_task.title,
                    "metadata": metadata,
                    "upstream_refs": raw_task.upstream_refs,
                    "task_md_path": abs_path(task_md_path),
                    "task_md_content_length": len(task_content),
                    "task_md_sha256": hashlib.sha256(task_content.encode("utf-8")).hexdigest(),
                    "copied_input_files": copied_inputs,
                },
            )
            normalized.append(
                TaskItem(
                    task_id=task_id,
                    task_type=entry_input_task_type,
                    title=raw_task.title,
                    task_md_path=abs_path(task_md_path),
                    metadata=metadata,
                    upstream_refs=list(raw_task.upstream_refs),
                )
            )
        return normalized

    def _prepare_single_task_entry_file(self, *, workspace_root: Path, manifest: TaskManifest) -> str | None:
        if len(manifest.tasks) != 1:
            return None
        task = manifest.tasks[0]
        markdown_path = str(task.task_md_path or "").strip()
        if not markdown_path:
            return None
        try:
            markdown = Path(markdown_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        if not markdown.strip():
            return None
        task_file = write_text(workspace_root / "run" / "input" / "task.md", markdown.strip() + "\n")
        return abs_path(task_file)

    def _build_project_workspace_root(
        self,
        *,
        definition: WorkflowDefinition,
        trigger_id: str,
        execution_id: str,
        authorization_token: str | None,
        created_by: str,
    ) -> Path:
        subproject = get_fileserver_client().ensure_subproject(
            project_id=definition.project_id,
            authorization_token=authorization_token,
            created_by=created_by,
        )
        base_root = Path(subproject["root_dir"])
        return ensure_dir(
            base_root
            / "app"
            / "secflow-app-dataflow-vuln-scanner"
            / sanitize_name(trigger_id)
        )

    def _artifact_uploads_from_refs(self, artifact_refs: list[ArtifactRef]) -> list[dict[str, Any]]:
        return [
            {
                "storage_key": item.storage_key,
                "relative_path": item.relative_path,
                "filename": item.filename,
                "metadata": item.metadata,
            }
            for item in artifact_refs
        ]

    def _input_tasks_from_manifest(self, manifest: TaskManifest) -> list[TriggerTaskInputTask]:
        items: list[TriggerTaskInputTask] = []
        for item in manifest.tasks:
            items.append(
                TriggerTaskInputTask(
                    task_id=item.task_id,
                    task_type=item.task_type,
                    title=item.title,
                    task_md_path=item.task_md_path,
                    metadata=dict(item.metadata),
                    upstream_refs=list(item.upstream_refs),
                )
            )
        return items

    def _sync_runtime_state_snapshots(
        self,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        public_status: str | None = None,
        control_state: str | None = None,
    ) -> None:
        resolved_public_status = normalize_public_task_status(public_status)
        resolved_control_state = control_state or derive_task_control_state(
            dispatch_status=execution.dispatch_status if execution is not None else None,
            process_status=execution.process_status if execution is not None else None,
            trigger_message=trigger.message if trigger is not None else None,
            execution_message=execution.message if execution is not None else None,
        )
        if trigger is not None:
            trigger.public_status = resolved_public_status
            trigger.control_state = resolved_control_state
        if execution is not None:
            execution.public_status = resolved_public_status
            execution.control_state = resolved_control_state

    def _set_terminal_state(
        self,
        db: Session,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        execution_status: str,
        message: str,
        output_manifest_path: str | None = None,
        output_task_count: int = 0,
    ) -> None:
        now = now_local()
        execution.status = normalize_canonical_task_status(execution_status)
        execution.message = message
        execution.finished_at = now
        execution.output_manifest_path = output_manifest_path
        execution.output_task_count = output_task_count
        execution.current_stage_id = None
        execution.dispatch_status = str(execution.status or execution_status or "").strip().lower()
        execution.dispatch_error = None if execution.status in {"succeeded", "cancelled"} else message
        if execution.process_status in {"running", "stop_requested", "delete_requested"}:
            execution.process_status = "exited"
            execution.process_finished_at = now
        trigger.status = execution.status
        trigger.message = message
        trigger.finished_at = now
        if trigger.started_at is None:
            trigger.started_at = execution.started_at or now
        trigger.latest_abnormal_reason_json = None
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status=execution.status, control_state="none")
        self._sync_trigger_abnormal_reason(db, trigger=trigger, execution=execution)
        db.add(execution)
        db.add(trigger)
        self._refresh_task_list_projection_for_task_id(db, trigger.id)

    def _apply_terminal_state_mutation(
        self,
        db: Session,
        *,
        execution: WorkflowExecution | None,
        trigger: TriggerTask | None,
        terminal_status: str,
        message: str,
        process_status: str = "exited",
        sync_abnormal_reason: bool = True,
    ) -> None:
        now = now_local()
        resolved_terminal_status = normalize_canonical_task_status(terminal_status)
        if execution is not None:
            execution.status = resolved_terminal_status
            execution.dispatch_status = resolved_terminal_status
            execution.dispatch_error = None if resolved_terminal_status in {"succeeded", "cancelled"} else message
            execution.message = message
            execution.finished_at = now
            if process_status:
                execution.process_status = process_status
                execution.process_finished_at = now
            db.add(execution)
        if trigger is not None:
            trigger.status = resolved_terminal_status
            trigger.message = message
            trigger.finished_at = now if execution is None else execution.finished_at
            self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status=resolved_terminal_status, control_state="none")
            if sync_abnormal_reason:
                self._sync_trigger_abnormal_reason(db, trigger=trigger, execution=execution)
            db.add(trigger)
            self._refresh_task_list_projection_for_task_id(db, trigger.id)
        elif execution is not None:
            self._refresh_task_list_projection_for_execution(db, execution)
        db.flush()

    def _has_active_execution_runtime(
        self,
        *,
        execution: WorkflowExecution | None,
        local_process: subprocess.Popen | None = None,
    ) -> bool:
        if execution is None:
            return False
        if local_process is not None:
            return True
        if bool(execution.worker_url and execution.worker_job_id):
            return True
        if _canonical_task_status(execution.status) in {"dispatching", "running"}:
            return True
        if str(execution.process_status or "").strip().lower() in {
            "running",
            "starting",
            "stop_requested",
            "delete_requested",
        }:
            return True
        return False

    def _orphaned_control_request_resolution(
        self,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        local_process: subprocess.Popen | None = None,
    ) -> dict[str, Any] | None:
        control_state = str(
            (trigger.control_state if trigger is not None else None)
            or (execution.control_state if execution is not None else None)
            or derive_task_control_state(
                dispatch_status=execution.dispatch_status if execution is not None else None,
                process_status=execution.process_status if execution is not None else None,
                trigger_message=trigger.message if trigger is not None else None,
                execution_message=execution.message if execution is not None else None,
            )
            or ""
        ).strip().lower()
        if control_state not in {"cancel_requested", "delete_requested"}:
            return None
        if trigger is not None and _canonical_task_status(trigger.status) not in {"pending", "running"}:
            return None
        if execution is None:
            return None
        if _canonical_task_status(execution.status) != "pending":
            return None
        if self._has_active_execution_runtime(execution=execution, local_process=local_process):
            return None
        if execution.owner_pod_id or execution.worker_job_id:
            return None
        if str(execution.process_status or "").strip().lower() not in {"", "not_started", "exited"}:
            return None
        if control_state == "delete_requested":
            return {
                "terminal_status": "cancelled",
                "message": "deleted after dispatch requeue",
                "event_type": "task_delete_reconciled",
                "resolution_reason": "dispatch_requeued_no_active_worker_delete_requested",
                "process_status": "not_started",
            }
        return {
            "terminal_status": "cancelled",
            "message": "cancelled after dispatch requeue",
            "event_type": "task_cancel_reconciled",
            "resolution_reason": "dispatch_requeued_no_active_worker_cancel_requested",
            "process_status": "not_started",
        }

    def _finalize_orphaned_control_request(
        self,
        db: Session,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        resolution: dict[str, Any],
    ) -> None:
        self._apply_terminal_state_mutation(
            db,
            execution=execution,
            trigger=trigger,
            terminal_status=str(resolution.get("terminal_status") or "cancelled"),
            message=str(resolution.get("message") or "cancelled"),
            process_status=str(resolution.get("process_status") or "not_started"),
        )
        if execution is not None:
            payload_json = {
                "task_id": trigger.id if trigger is not None else execution.trigger_task_id,
                "execution_id": execution.id,
                "status_before": "pending" if execution is not None else None,
                "dispatch_status_before": execution.dispatch_status,
                "process_status_before": execution.process_status,
                "worker_url": execution.worker_url,
                "worker_job_id": execution.worker_job_id,
                "owner_pod_id": execution.owner_pod_id,
                "resolution_reason": resolution.get("resolution_reason"),
            }
            self.record_event(
                db,
                execution_id=execution.id,
                event_type=str(resolution.get("event_type") or "task_cancel_reconciled"),
                message=str(resolution.get("message") or "cancelled"),
                level="warning",
                payload_json=payload_json,
            )

    def mark_dispatch_failure_terminal(
        self,
        db: Session,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask | None,
        error: str,
    ) -> None:
        now = now_local()
        message = f"worker dispatch failed: {error}"
        execution.status = "failed"
        execution.message = message
        execution.finished_at = now
        execution.dispatch_status = "failed"
        execution.dispatch_error = error
        execution.process_status = "not_started"
        execution.process_finished_at = now
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="failed", control_state="none")
        db.add(execution)
        if trigger is not None:
            trigger.status = "failed"
            trigger.message = message
            trigger.finished_at = now
            trigger.latest_abnormal_reason_json = None
            self._sync_trigger_abnormal_reason(db, trigger=trigger, execution=execution)
            db.add(trigger)
            self._refresh_task_list_projection_for_task_id(db, trigger.id)
        else:
            self._refresh_task_list_projection_for_execution(db, execution)
        db.flush()

    def _legacy_dispatch_failure_reconcile_threshold(self) -> datetime:
        cfg = get_config()
        dispatch_window = max(
            10,
            int(cfg.scheduler.requeue_stuck_dispatch_after_seconds or 60),
            int(cfg.dataflow_worker.dispatch_max_retries or 1) * max(1, int(cfg.dataflow_worker.dispatch_retry_interval_seconds or 0)),
        )
        return now_local() - timedelta(seconds=dispatch_window)

    def _reconcile_legacy_dispatch_failure(
        self,
        db: Session,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
    ) -> bool:
        if execution is None:
            return False
        if _public_task_status(execution.status) != "pending":
            return False
        if trigger is not None and _public_task_status(trigger.status) != "pending":
            return False
        dispatch_status = str(execution.dispatch_status or "").strip().lower()
        updated_at = execution.updated_at or (trigger.updated_at if trigger is not None else None)
        threshold = self._legacy_dispatch_failure_reconcile_threshold()
        if updated_at is None or updated_at > threshold:
            return False
        if dispatch_status == "running":
            return False
        if dispatch_status in {"queued", "dispatching"}:
            if dispatch_status != "dispatching":
                return False
            message = str(execution.message or "").strip() or "stale dispatching execution assumed failed"
            self.mark_dispatch_failure_terminal(
                db,
                execution=execution,
                trigger=trigger,
                error=message,
            )
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="stale_dispatching_reconciled",
                message=message,
                level="warning",
                payload_json={
                    "reason": "stale_dispatching",
                    "updated_at": isoformat_local(updated_at) if updated_at else None,
                },
            )
            return True
        trigger_message = str(trigger.message or "").strip() if trigger is not None else ""
        message = str(execution.message or trigger_message or "").strip()
        if not message.lower().startswith("worker dispatch failed:"):
            return False

        error = message.split(":", 1)[1].strip() if ":" in message else message
        self.mark_dispatch_failure_terminal(
            db,
            execution=execution,
            trigger=trigger,
            error=error or message,
        )
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="legacy_dispatch_failure_reconciled",
            message=message,
            level="warning",
            payload_json={
                "reason": "legacy_dispatch_failure",
                "updated_at": isoformat_local(updated_at) if updated_at else None,
            },
        )
        return True

    def _create_execution_attempt(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        actor: str,
        authorization_token: str | None,
        recovery_reason: str | None = None,
    ) -> WorkflowExecution:
        compiled_config = definition_version.compiled_config_json or definition_version.definition_json or definition.definition_json
        validated_definition = get_workflow_service().validate_definition_payload(compiled_config)
        next_attempt_no = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger.id)
            .count()
        ) + 1
        execution_id = _new_id("exec")
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        raw_input_tasks = self._input_tasks_from_manifest(manifest)
        primary_metadata = dict(raw_input_tasks[0].metadata or {}) if raw_input_tasks else {}
        workspace_root, _ = self._resolve_custom_execution_paths(
            project_id=definition.project_id,
            metadata=primary_metadata,
            execution_id=execution_id,
        )
        if workspace_root is None:
            workspace_root = self._build_project_workspace_root(
                definition=definition,
                trigger_id=trigger.id,
                execution_id=execution_id,
                authorization_token=authorization_token,
                created_by=actor,
            )
        normalized_tasks = self._normalize_trigger_tasks(
            project_id=definition.project_id,
            input_tasks=raw_input_tasks,
            workspace_root=workspace_root,
            entry_input_task_type=validated_definition.resolve_entry_input_task_type(),
        )
        input_manifest_path = write_task_manifest(workspace_root / "input" / "tasks.json", normalized_tasks)
        write_json(
            workspace_root / "run" / "execution_meta.json",
            {
                "workflow_definition_id": definition.id,
                "workflow_definition_version_id": definition_version.id,
                "project_id": definition.project_id,
                "trigger_id": trigger.id,
                "execution_id": execution_id,
                "attempt_no": next_attempt_no,
                "trigger_type": trigger.trigger_type,
                "entry_input_task_type": validated_definition.resolve_entry_input_task_type(),
                "workspace_root": abs_path(workspace_root),
                "input_manifest_path": abs_path(input_manifest_path),
                "recovery_reason": recovery_reason,
            },
        )
        trigger.input_tasks_json = TaskManifest(tasks=normalized_tasks).model_dump(mode="json")
        trigger.status = "pending"
        trigger.latest_execution_id = execution_id
        trigger.workflow_definition_version_id = definition_version.id
        trigger.profile_id = definition.id
        trigger.finished_at = None
        trigger.message = "pending start" if not recovery_reason else f"pending start: {recovery_reason}"
        trigger.latest_abnormal_reason_json = None
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            project_id=definition.project_id,
            attempt_no=next_attempt_no,
            status="pending",
            recovery_reason=recovery_reason,
            workspace_root=abs_path(workspace_root),
            message="pending start" if not recovery_reason else f"pending start: {recovery_reason}",
        )
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="pending", control_state="none")
        db.add(trigger)
        db.add(execution)
        db.flush()
        return execution

    def _create_task_record(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        input_tasks: List[TriggerTaskInputTask],
        priority: int,
        trigger_type: str,
        actor: str,
        authorization_token: str | None,
    ) -> tuple[TriggerTask, WorkflowExecution]:
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            profile_id=definition.id,
            project_id=definition.project_id,
            trigger_type=trigger_type,
            task_origin_type=str(trigger_type if trigger_type == "binary_security" else "manual"),
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=priority,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message="pending start",
        )
        db.add(trigger)
        db.flush()
        compiled_config = definition_version.compiled_config_json or definition_version.definition_json or definition.definition_json
        validated_definition = get_workflow_service().validate_definition_payload(compiled_config)
        workspace_root = self._build_project_workspace_root(
            definition=definition,
            trigger_id=trigger.id,
            execution_id="bootstrap",
            authorization_token=authorization_token,
            created_by=actor,
        )
        normalized_tasks = self._normalize_trigger_tasks(
            project_id=definition.project_id,
            input_tasks=input_tasks,
            workspace_root=workspace_root,
            entry_input_task_type=validated_definition.resolve_entry_input_task_type(),
        )
        trigger.input_tasks_json = TaskManifest(tasks=normalized_tasks).model_dump(mode="json")
        db.add(trigger)
        execution = self._create_execution_attempt(
            db,
            trigger=trigger,
            definition=definition,
            definition_version=definition_version,
            actor=actor,
            authorization_token=authorization_token,
        )
        return trigger, execution

    def _create_dataflow_cli_execution_attempt(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        actor: str,
        recovery_reason: str | None = None,
    ) -> WorkflowExecution:
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        if not manifest.tasks:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="input_tasks must not be empty")
        task = manifest.tasks[0]
        metadata = dict(task.metadata or {})
        request = metadata.get("dataflow_scan_request")
        if not isinstance(request, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow scan request is incomplete")
        execution_id = _new_id("exec")
        next_attempt_no = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger.id)
            .count()
        ) + 1
        request = {**request, "task_id": trigger.id}
        plan = self._build_dataflow_cli_plan(
            project_id=definition.project_id,
            trigger_id=trigger.id,
            request=request,
        )
        if plan.get("mode") == "resume" or self._is_dataflow_cli_resume_request(request):
            plan = {
                **plan,
                **self._resume_command_payload_from_plan(plan=plan, request=request),
            }
        metadata["dataflow_cli"] = plan
        self._write_dataflow_cli_task_preview(plan)
        if not str(metadata.get("task_title") or "").strip():
            metadata["task_title"] = plan["run_name"]
            task.title = plan["run_name"]
        task.task_md_path = plan["task_md_path"]
        task.metadata = metadata
        trigger.input_tasks_json = TaskManifest(tasks=[task, *manifest.tasks[1:]]).model_dump(mode="json")
        trigger.status = "pending"
        trigger.latest_execution_id = execution_id
        trigger.workflow_definition_version_id = definition_version.id
        trigger.profile_id = definition.id
        trigger.finished_at = None
        trigger.message = "pending start" if not recovery_reason else f"pending start: {recovery_reason}"
        trigger.latest_abnormal_reason_json = None
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            project_id=definition.project_id,
            attempt_no=next_attempt_no,
            status="pending",
            recovery_reason=recovery_reason,
            workspace_root=plan["run_dir"],
            message="pending start" if not recovery_reason else f"pending start: {recovery_reason}",
        )
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="pending", control_state="none")
        db.add(trigger)
        db.add(execution)
        db.flush()
        return execution

    def _create_dataflow_cli_task_record(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        payload: ScanTaskCreateRequest,
        metadata: dict[str, Any],
        priority: int,
        actor: str,
    ) -> tuple[TriggerTask, WorkflowExecution]:
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            profile_id=definition.id,
            project_id=definition.project_id,
            trigger_type="manual",
            task_purpose=self._normalize_task_purpose(payload.task_purpose),
            task_origin_type=str(payload.task_origin_type or "").strip() or "manual",
            parent_project_id=payload.parent_project_id,
            parent_task_id=payload.parent_task_id,
            parent_task_type=payload.parent_task_type,
            parent_stage_name=payload.parent_stage_name,
            parent_stage_item_id=payload.parent_stage_item_id,
            parent_stage_item_key=payload.parent_stage_item_key,
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=priority,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message="pending start",
        )
        db.add(trigger)
        db.flush()
        trigger.input_tasks_json = TaskManifest(
            tasks=[
                TaskItem(
                    task_id=_new_id("task"),
                    task_type="dataflow_vuln_scan_cli",
                    title=str(payload.title or "").strip() or trigger.id,
                    task_md_path=abs_path(self._default_dataflow_cli_runs_root(definition.project_id) / "_pending" / trigger.id / "task.md"),
                    metadata=metadata,
                    upstream_refs=[],
                )
            ]
        ).model_dump(mode="json")
        execution = self._create_dataflow_cli_execution_attempt(
            db,
            trigger=trigger,
            definition=definition,
            definition_version=definition_version,
            actor=actor,
        )
        return trigger, execution

    def _run_mutation_response(
        self,
        *,
        run_id: str,
        project_id: str,
        status_text: str,
        message: str,
        linked_task_id: str | None,
        linked_execution_id: str | None,
        process_pid: int | None = None,
        process_host: str | None = None,
        process_signal: str | None = None,
        control_state: str | None = None,
    ) -> dict[str, Any]:
        return {
            "success": True,
            "run_id": run_id,
            "project_id": project_id,
            "status": "deleted" if str(status_text or "").strip().lower() == "deleted" else normalize_public_task_status(status_text),
            "message": message,
            "linked_task_id": linked_task_id,
            "linked_execution_id": linked_execution_id,
            "process_pid": process_pid,
            "process_host": process_host,
            "process_signal": process_signal,
            "control_state": control_state or "none",
        }

    def _run_index_status_is_active(self, status_text: str | None) -> bool:
        return is_run_active(status_text)

    def _adopted_run_index_task_status(self, status_text: str | None) -> str:
        return _canonical_task_status(status_text or "succeeded")

    def _run_index_output_manifest_path(self, run_index) -> str | None:
        atomic_work_path = str(run_index.atomic_work_path or "").strip()
        if not atomic_work_path:
            return None
        candidate = Path(atomic_work_path) / "_meta" / "results_manifest.json"
        return abs_path(candidate) if candidate.exists() else None

    def _run_index_task_md_path(self, run_index) -> str:
        candidate = Path(run_index.run_root_path) / "run" / "input" / "task.md"
        if not candidate.exists():
            candidate = Path(run_index.run_root_path) / "input" / "task.md"
        return abs_path(candidate)

    def _run_index_adoption_manifest(self, run_index) -> dict[str, Any]:
        return TaskManifest(
            tasks=[
                TaskItem(
                    task_id=_new_id("task"),
                    task_type="dataflow_vuln_scan_cli",
                    title=f"Run {run_index.run_name}",
                    task_md_path=self._run_index_task_md_path(run_index),
                    metadata={
                        "run_adoption": {
                            "run_id": run_index.id,
                            "source_type": run_index.source_type,
                            "run_root_path": run_index.run_root_path,
                            "adopted_at": isoformat_local(now_local()),
                        },
                        "runtime_overrides": {},
                        "task_title": f"Run {run_index.run_name}",
                    },
                    upstream_refs=[],
                )
            ]
        ).model_dump(mode="json")

    def _select_run_index_definition(self, db: Session, run_index, principal: dict) -> WorkflowDefinition:
        workflow_service = get_workflow_service()
        candidate_ids: list[str] = []
        if run_index.linked_task_id:
            try:
                trigger = self._trigger_or_404(db, run_index.linked_task_id)
                candidate_ids.append(trigger.workflow_definition_id)
            except HTTPException:
                pass
        if run_index.profile_id:
            candidate_ids.append(run_index.profile_id)
        for definition_id in candidate_ids:
            try:
                definition = workflow_service._get_definition_or_404(db, definition_id)
            except HTTPException:
                continue
            self._ensure_project_access(principal, definition.project_id)
            return definition
        return workflow_service.get_or_create_default_profile_model(db, run_index.project_id, principal)

    def _build_run_index_resume_request(self, *, run_index, payload: RunRetryRequest) -> dict[str, Any]:
        return {
            "launcher": "run_vuln_scan.py",
            "project_id": run_index.project_id,
            "resume_run_dir": run_index.run_root_path,
            "resume_extra_cycles": payload.extra_cycles,
            "model": self._normalize_model_override(model=payload.model, provider=payload.provider),
            "provider": None,
            "clean_workspace": payload.clean_workspace,
            "options": {
                "run_id": run_index.id,
                "resume": True,
            },
        }

    def _update_trigger_for_run_index_resume(
        self,
        *,
        trigger: TriggerTask,
        run_index,
        request: dict[str, Any],
    ) -> None:
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        if manifest.tasks:
            first_task = manifest.tasks[0]
            remaining_tasks = list(manifest.tasks[1:])
        else:
            first_task = TaskItem(
                task_id=_new_id("task"),
                task_type="dataflow_vuln_scan_cli",
                title=f"Resume {run_index.run_name}",
                task_md_path="",
                metadata={},
                upstream_refs=[],
            )
            remaining_tasks = []
        extra_cycles = int(request.get("resume_extra_cycles") or 5)
        metadata = dict(first_task.metadata or {})
        metadata["dataflow_scan_request"] = request
        metadata["run_retry"] = {
            "run_id": run_index.id,
            "source_type": run_index.source_type,
            "requested_at": isoformat_local(now_local()),
            "extra_cycles": extra_cycles,
        }
        metadata["task_title"] = f"Resume {run_index.run_name}"
        first_task.task_type = "dataflow_vuln_scan_cli"
        first_task.title = f"Resume {run_index.run_name}"
        first_task.metadata = metadata
        trigger.input_tasks_json = TaskManifest(tasks=[first_task, *remaining_tasks]).model_dump(mode="json")
        trigger.message = f"pending start: resume requested (+{extra_cycles} cycles)"

    def _create_run_index_resume_task_record(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        run_index,
        request: dict[str, Any],
        actor: str,
    ) -> tuple[TriggerTask, WorkflowExecution]:
        extra_cycles = int(request.get("resume_extra_cycles") or 5)
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            profile_id=definition.id,
            project_id=definition.project_id,
            trigger_type="manual",
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=definition.priority_default,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message=f"pending start: resume requested (+{extra_cycles} cycles)",
        )
        db.add(trigger)
        db.flush()
        trigger.input_tasks_json = TaskManifest(
            tasks=[
                TaskItem(
                    task_id=_new_id("task"),
                    task_type="dataflow_vuln_scan_cli",
                    title=f"Resume {run_index.run_name}",
                    task_md_path=self._run_index_task_md_path(run_index),
                    metadata={
                        "dataflow_scan_request": request,
                        "run_retry": {
                            "run_id": run_index.id,
                            "source_type": run_index.source_type,
                            "requested_at": isoformat_local(now_local()),
                            "extra_cycles": extra_cycles,
                        },
                        "runtime_overrides": {},
                        "task_title": f"Resume {run_index.run_name}",
                    },
                    upstream_refs=[],
                )
            ]
        ).model_dump(mode="json")
        execution = self._create_dataflow_cli_execution_attempt(
            db,
            trigger=trigger,
            definition=definition,
            definition_version=definition_version,
            actor=actor,
                recovery_reason="manual run resume requested",
        )
        return trigger, execution

    def create_scan_task(
        self,
        db: Session,
        payload: ScanTaskCreateRequest,
        principal: dict,
        *,
        authorization_token: str | None = None,
        extra_task_metadata: dict[str, Any] | None = None,
    ) -> ScanTaskResponse:
        self._ensure_project_access(principal, payload.project_id)
        workflow_service = get_workflow_service()
        definition = (
            workflow_service.get_or_create_default_profile_model(db, payload.project_id, principal)
            if not payload.profile_id
            else workflow_service._get_definition_or_404(db, payload.profile_id)
        )
        self._ensure_project_access(principal, definition.project_id)
        if definition.project_id != payload.project_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="profile_id belongs to a different project",
            )
        actor = _principal_id(principal)
        config_payload_overrides = {
            "model": payload.model,
            "review_profile": payload.review_profile,
            "max_review_cycles": payload.max_review_cycles,
            "agent_run_timeout_seconds": payload.agent_run_timeout_seconds,
            "agent_timeout_retry_enabled": payload.agent_timeout_retry_enabled,
            "agent_timeout_max_retries": payload.agent_timeout_max_retries,
            "worker_timeout": payload.worker_timeout,
            "advisor_timeout": payload.advisor_timeout,
            "timeout_max_retries": payload.timeout_max_retries,
            "timeout_retry_interval_seconds": payload.timeout_retry_interval_seconds,
            "result_review_concurrency": payload.result_review_concurrency,
        }
        if payload.provider and payload.model and "/" not in payload.model:
            config_payload_overrides["model"] = f"{payload.provider}/{payload.model}"
        definition_version = workflow_service.build_task_bound_version(
            db,
            definition=definition,
            principal=principal,
            runtime_overrides=payload.runtime_overrides,
            config_payload_overrides={key: value for key, value in config_payload_overrides.items() if value is not None},
        )
        requested_title = str(payload.title or "").strip()
        metadata = {
            "artifact_refs": [item.model_dump(mode="json") for item in payload.artifact_refs],
            "task_input_uploads": self._artifact_uploads_from_refs(payload.artifact_refs),
            "runtime_overrides": payload.runtime_overrides,
            "task_purpose": self._normalize_task_purpose(payload.task_purpose),
            "agent_state_roots": {
                agent_id: item.model_dump(mode="json")
                for agent_id, item in (payload.agent_state_roots or {}).items()
            },
            "task_title": requested_title,
            "task_origin_type": str(payload.task_origin_type or "").strip() or "manual",
            "parent_project_id": payload.parent_project_id,
            "parent_task_id": payload.parent_task_id,
            "parent_task_type": payload.parent_task_type,
            "parent_stage_name": payload.parent_stage_name,
            "parent_stage_item_id": payload.parent_stage_item_id,
            "parent_stage_item_key": payload.parent_stage_item_key,
            "auto_report_vulnerabilities": bool(payload.auto_report_vulnerabilities),
        }
        if extra_task_metadata:
            metadata.update(dict(extra_task_metadata))
        if payload.data_flow and payload.source_dir:
            scan_options = dict(payload.scan_options or {})
            if requested_title:
                scan_options.setdefault("run_name", requested_title)
            metadata["dataflow_scan_request"] = {
                "launcher": "run_vuln_scan.py",
                "project_id": payload.project_id,
                "workspace_dir": payload.workspace_dir.model_dump(mode="json") if payload.workspace_dir else None,
                "data_flow": payload.data_flow.model_dump(mode="json"),
                "source_dir": payload.source_dir.model_dump(mode="json"),
                "output_dir": payload.output_dir.model_dump(mode="json") if payload.output_dir else None,
                "model": payload.model,
                "provider": payload.provider,
                "review_profile": payload.review_profile,
                "max_review_cycles": payload.max_review_cycles,
                "agent_run_timeout_seconds": payload.agent_run_timeout_seconds,
                "agent_timeout_retry_enabled": payload.agent_timeout_retry_enabled,
                "agent_timeout_max_retries": payload.agent_timeout_max_retries,
                "worker_timeout": payload.worker_timeout,
                "advisor_timeout": payload.advisor_timeout,
                "timeout_max_retries": payload.timeout_max_retries,
                "timeout_retry_interval_seconds": payload.timeout_retry_interval_seconds,
                "result_review_concurrency": payload.result_review_concurrency,
                "options": scan_options,
            }
        self._agent_state_dirs_from_metadata(
            project_id=payload.project_id,
            compiled_config=definition_version.compiled_config_json or definition_version.definition_json or definition.definition_json or {},
            metadata=metadata,
        )
        if payload.data_flow and payload.source_dir:
            trigger, _ = self._create_dataflow_cli_task_record(
                db,
                definition=definition,
                definition_version=definition_version,
                payload=payload,
                metadata=metadata,
                priority=payload.priority if payload.priority is not None else definition.priority_default,
                actor=actor,
            )
        else:
            trigger, _ = self._create_task_record(
                db,
                definition=definition,
                definition_version=definition_version,
                input_tasks=[
                    TriggerTaskInputTask(
                        task_id=_new_id("task"),
                        title=requested_title or f"Task {datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        task_markdown=payload.task_markdown,
                        metadata=metadata,
                        upstream_refs=[],
                    )
                ],
                priority=payload.priority if payload.priority is not None else definition.priority_default,
                trigger_type="manual",
                actor=actor,
                authorization_token=authorization_token,
            )
            trigger.task_origin_type = str(payload.task_origin_type or "").strip() or "manual"
            trigger.task_purpose = self._normalize_task_purpose(payload.task_purpose)
            trigger.parent_project_id = payload.parent_project_id
            trigger.parent_task_id = payload.parent_task_id
            trigger.parent_task_type = payload.parent_task_type
            trigger.parent_stage_name = payload.parent_stage_name
            trigger.parent_stage_item_id = payload.parent_stage_item_id
            trigger.parent_stage_item_key = payload.parent_stage_item_key
        db.commit()
        db.refresh(trigger)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        if latest_execution is not None and self._trigger_uses_run_directory(trigger):
            self._ensure_run_index_for_execution(db, latest_execution, trigger)
            db.commit()
            db.refresh(trigger)
        if latest_execution is not None:
            self._record_task_mutation_event(
                db,
                event_type="task_created",
                message="scan task created",
                trigger=trigger,
                execution=latest_execution,
                payload_json={
                    "task_id": trigger.id,
                    "project_id": trigger.project_id,
                    "task_origin_type": str(trigger.task_origin_type or "").strip() or "manual",
                    "task_purpose": self._normalize_task_purpose(trigger.task_purpose),
                    "priority": trigger.priority,
                    "attempt_no": latest_execution.attempt_no,
                    "dataflow_cli_task": self._is_dataflow_cli_task_metadata(self._trigger_task_metadata(trigger)),
                },
            )
            self.record_event(
                db,
                execution_id=latest_execution.id,
                event_type="execution_queued",
                message="task start requested",
                payload_json={"task_id": trigger.id, "attempt_no": latest_execution.attempt_no},
            )
        self._refresh_task_list_projection_for_task_id(db, trigger.id)
        db.commit()
        return self._scan_task_response(db, trigger)

    def create_evolution_task(
        self,
        db: Session,
        *,
        source_task_id: str,
        payload: CreateEvolutionTaskRequest,
        principal: dict,
        authorization_token: str | None = None,
    ) -> ScanTaskResponse:
        source_trigger = self._trigger_or_404(db, source_task_id)
        self._ensure_project_access(principal, source_trigger.project_id)
        source_execution = self._latest_execution_for_trigger(db, source_trigger.id)
        create_payload, extra_metadata = self._build_evolution_create_payload(
            db=db,
            source_trigger=source_trigger,
            source_execution=source_execution,
            payload=payload,
        )
        created = self.create_scan_task(
            db,
            create_payload,
            principal,
            authorization_token=authorization_token,
            extra_task_metadata=extra_metadata,
        )
        if created.latest_execution_id:
            self.record_event(
                db,
                execution_id=created.latest_execution_id,
                event_type="task_evolution_created",
                message="evolution task created from normal source task",
                payload_json={
                    "source_task_id": source_trigger.id,
                    "source_execution_id": source_execution.id if source_execution is not None else None,
                    "source_run_id": extra_metadata.get("derivation", {}).get("source_run_id"),
                    "created_task_id": created.task_id,
                    "task_purpose": created.task_purpose,
                },
            )
        return created

    def get_task_replay_ready(self, db: Session, task_id: str, principal: dict) -> ReplayReadyResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        metadata = self._trigger_task_metadata(trigger)
        task_purpose = self._normalize_task_purpose(getattr(trigger, "task_purpose", None) or metadata.get("task_purpose"))
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        latest_run = self._source_run_index_for_trigger(db, trigger, latest_execution)
        reason = None
        replay_ready = True
        if task_purpose != "normal":
            replay_ready = False
            reason = "only normal tasks can create evolution tasks"
        elif not self._is_dataflow_cli_task_metadata(metadata):
            replay_ready = False
            reason = "source task is not a run_vuln_scan.py launcher task"
        else:
            source_request = metadata.get("dataflow_scan_request") if isinstance(metadata.get("dataflow_scan_request"), dict) else {}
            if not isinstance(source_request.get("data_flow"), dict) or not isinstance(source_request.get("source_dir"), dict):
                replay_ready = False
                reason = "source task is missing reusable data_flow/source_dir inputs"
        task_payload = self._scan_task_response(db, trigger, include_run_summary=False)
        return ReplayReadyResponse(
            task_id=trigger.id,
            project_id=trigger.project_id,
            task_purpose=task_purpose,
            replay_ready=replay_ready,
            reason=reason,
            latest_execution_id=latest_execution.id if latest_execution is not None else None,
            latest_run_id=latest_run.id if latest_run is not None else None,
            agent_state_dirs=task_payload.agent_state_dirs,
        )

    def _list_scan_tasks_query(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
        status_filter: str | None = None,
        profile_id: str | None = None,
        mode: str | None = None,
        parent_task_id: str | None = None,
        sort_by: str | None = None,
        sort_order: str | None = None,
    ):
        project_ids = _project_ids(principal)
        query = db.query(TriggerTask)
        if project_id:
            self._ensure_project_access(principal, project_id)
            query = query.filter(TriggerTask.project_id == project_id)
        elif project_ids:
            query = query.filter(TriggerTask.project_id.in_(project_ids))
        if status_filter:
            normalized_status = normalize_public_task_status(status_filter)
            query = query.filter(TriggerTask.public_status == normalized_status)
        if profile_id:
            query = query.filter(TriggerTask.profile_id == profile_id)
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode == "manual":
            query = query.filter(
                (TriggerTask.task_origin_type.is_(None)) | (TriggerTask.task_origin_type != "binary_security")
            )
        elif normalized_mode == "binary":
            query = query.filter(
                TriggerTask.task_origin_type == "binary_security",
                (TriggerTask.parent_task_type.is_(None)) | (TriggerTask.parent_task_type != "source"),
            )
        elif normalized_mode == "source":
            query = query.filter(
                TriggerTask.task_origin_type == "binary_security",
                TriggerTask.parent_task_type == "source",
            )
        normalized_parent_task_id = str(parent_task_id or "").strip()
        if normalized_parent_task_id:
            query = query.filter(TriggerTask.parent_task_id == normalized_parent_task_id)
        sort_column = _TASK_LIST_SORT_COLUMNS.get(str(sort_by or "").strip(), TriggerTask.created_at)
        order_expr = sort_column.asc() if str(sort_order or "").lower() == "asc" else sort_column.desc()
        return query.order_by(order_expr, TriggerTask.id.desc())

    def _filter_task_responses_by_status(
        self,
        items: list[ScanTaskResponse],
        status_filter: str | None,
    ) -> list[ScanTaskResponse]:
        if not status_filter:
            return items
        return [
            item for item in items
            if public_task_status_matches_filter(item.status, status_filter)
        ]

    def _build_light_scan_task_responses(self, db: Session, triggers: list[TriggerTask]) -> list[ScanTaskResponse]:
        if not triggers:
            return []

        trigger_ids = [str(item.id) for item in triggers]
        first_task_payload_by_trigger: dict[str, dict[str, Any]] = {}
        task_metadata_by_trigger: dict[str, dict[str, Any]] = {}
        for trigger in triggers:
            first_task_payload = self._first_manifest_task_payload(trigger)
            first_task_payload_by_trigger[trigger.id] = first_task_payload
            task_metadata_by_trigger[trigger.id] = self._task_metadata_from_manifest_payload(first_task_payload)

        version_by_id: dict[str, WorkflowDefinitionVersion] = {}
        explicit_version_ids = [
            str(item.workflow_definition_version_id)
            for item in triggers
            if item.workflow_definition_version_id
        ]
        if explicit_version_ids:
            rows = (
                db.query(WorkflowDefinitionVersion)
                .filter(WorkflowDefinitionVersion.id.in_(explicit_version_ids))
                .all()
            )
            version_by_id = {str(row.id): row for row in rows}

        latest_version_by_definition: dict[str, WorkflowDefinitionVersion] = {}
        fallback_definition_ids = {
            str(item.workflow_definition_id)
            for item in triggers
            if not item.workflow_definition_version_id and item.workflow_definition_id
        }
        if fallback_definition_ids:
            rows = (
                db.query(WorkflowDefinitionVersion)
                .filter(WorkflowDefinitionVersion.workflow_definition_id.in_(fallback_definition_ids))
                .order_by(
                    WorkflowDefinitionVersion.workflow_definition_id.asc(),
                    WorkflowDefinitionVersion.version_no.desc(),
                )
                .all()
            )
            for row in rows:
                latest_version_by_definition.setdefault(str(row.workflow_definition_id), row)

        execution_by_id: dict[str, WorkflowExecution] = {}
        latest_execution_ids = {
            str(item.latest_execution_id)
            for item in triggers
            if item.latest_execution_id
        }
        if latest_execution_ids:
            rows = db.query(WorkflowExecution).filter(WorkflowExecution.id.in_(latest_execution_ids)).all()
            execution_by_id = {str(row.id): row for row in rows}

        latest_execution_by_trigger: dict[str, WorkflowExecution] = {}
        fallback_trigger_ids: list[str] = []
        for trigger in triggers:
            execution = execution_by_id.get(str(trigger.latest_execution_id or ""))
            if execution is not None:
                latest_execution_by_trigger[trigger.id] = execution
            else:
                fallback_trigger_ids.append(trigger.id)
        if fallback_trigger_ids:
            rows = (
                db.query(WorkflowExecution)
                .filter(WorkflowExecution.trigger_task_id.in_(fallback_trigger_ids))
                .order_by(
                    WorkflowExecution.trigger_task_id.asc(),
                    WorkflowExecution.attempt_no.desc(),
                    WorkflowExecution.created_at.desc(),
                )
                .all()
            )
            for row in rows:
                latest_execution_by_trigger.setdefault(str(row.trigger_task_id), row)

        run_index_by_execution: dict[str, RunIndex] = {}
        execution_ids = [str(item.id) for item in latest_execution_by_trigger.values() if item.id]
        if execution_ids:
            rows = (
                db.query(RunIndex)
                .filter(RunIndex.linked_execution_id.in_(execution_ids))
                .order_by(
                    RunIndex.linked_execution_id.asc(),
                    RunIndex.started_at.desc(),
                    RunIndex.created_at.desc(),
                )
                .all()
            )
            for row in rows:
                if row.linked_execution_id is not None:
                    run_index_by_execution.setdefault(str(row.linked_execution_id), row)

        run_index_by_task: dict[str, RunIndex] = {}
        rows = (
            db.query(RunIndex)
            .filter(RunIndex.linked_task_id.in_(trigger_ids))
            .order_by(
                RunIndex.linked_task_id.asc(),
                RunIndex.started_at.desc(),
                RunIndex.created_at.desc(),
            )
            .all()
        )
        for row in rows:
            if row.linked_task_id is not None:
                run_index_by_task.setdefault(str(row.linked_task_id), row)

        latest_execution_id_by_task = {
            task_id: str(execution.id)
            for task_id, execution in latest_execution_by_trigger.items()
            if execution is not None and execution.id
        }
        report_counts_by_task: dict[str, dict[str, int]] = {task_id: {"total": 0, "reported": 0, "failed": 0, "pending": 0} for task_id in trigger_ids}
        if latest_execution_id_by_task:
            report_rows = (
                db.query(
                    VulnReportSubmission.task_id,
                    VulnReportSubmission.execution_id,
                    VulnReportSubmission.status,
                    func.count(VulnReportSubmission.id),
                )
                .filter(VulnReportSubmission.execution_id.in_(list(latest_execution_id_by_task.values())))
                .group_by(VulnReportSubmission.task_id, VulnReportSubmission.execution_id, VulnReportSubmission.status)
                .all()
            )
            for task_id, execution_id, status_value, count_value in report_rows:
                task_key = str(task_id)
                if latest_execution_id_by_task.get(task_key) != str(execution_id):
                    continue
                bucket = report_counts_by_task.setdefault(task_key, {"total": 0, "reported": 0, "failed": 0, "pending": 0})
                normalized_status = str(status_value or "").strip().lower()
                count_int = int(count_value or 0)
                bucket["total"] = int(bucket.get("total") or 0) + count_int
                if normalized_status in {"reported", "failed", "pending"}:
                    bucket[normalized_status] = int(bucket.get(normalized_status) or 0) + count_int

        responses: list[ScanTaskResponse] = []
        for trigger in triggers:
            first_task_payload = first_task_payload_by_trigger.get(trigger.id, {})
            task_metadata = task_metadata_by_trigger.get(trigger.id, {})
            derivation = self._task_derivation_metadata(task_metadata)
            task_origin_type = str(trigger.task_origin_type or "").strip() or "manual"
            parent_task_type = str(trigger.parent_task_type or "").strip() or None
            origin_label = self._task_origin_label(task_origin_type, parent_task_type)
            task_purpose = self._normalize_task_purpose(getattr(trigger, "task_purpose", None) or task_metadata.get("task_purpose"))
            version = (
                version_by_id.get(str(trigger.workflow_definition_version_id or ""))
                if trigger.workflow_definition_version_id
                else latest_version_by_definition.get(str(trigger.workflow_definition_id or ""))
            )
            compiled_config = (
                version.compiled_config_json or version.definition_json or {}
                if version is not None
                else {}
            )
            request_payload = task_metadata.get("dataflow_scan_request") if isinstance(task_metadata.get("dataflow_scan_request"), dict) else {}
            default_model, default_thinking = self._extract_worker_runtime_defaults(compiled_config)
            review_profile = str(request_payload.get("review_profile") or self._extract_review_profile_from_config(compiled_config) or "").strip()
            max_review_cycles = request_payload.get("max_review_cycles")
            try:
                max_review_cycles_value = int(max_review_cycles)
            except (TypeError, ValueError):
                max_review_cycles_value = self._extract_max_review_cycles_from_config(compiled_config)
            latest_execution = latest_execution_by_trigger.get(trigger.id)
            run_index = run_index_by_execution.get(str(latest_execution.id)) if latest_execution is not None else None
            if run_index is None:
                run_index = run_index_by_task.get(trigger.id)
            run_locator = self._run_locator_from_task_context(
                project_id=trigger.project_id,
                metadata=task_metadata,
                execution=latest_execution,
                run_index=run_index,
            )
            effective_model = str((run_index.model if run_index is not None else None) or request_payload.get("model") or default_model or "").strip()
            effective_provider = str((run_index.provider if run_index is not None else None) or request_payload.get("provider") or "").strip()
            effective_thinking = str((run_index.thinking if run_index is not None else None) or default_thinking or "").strip()
            run_summary: dict[str, Any] = {
                "status": get_run_index_service().normalized_run_status(run_index) if run_index is not None else "",
                "model": effective_model,
                "provider": effective_provider,
                "thinking": effective_thinking,
                "review_profile": review_profile,
                "max_cycles": int(run_index.max_cycles or 0) if run_index is not None else max(max_review_cycles_value, 0),
                "cycles_used": int(run_index.cycles_used or 0) if run_index is not None else 0,
                "result_count": int(run_index.result_count or 0) if run_index is not None else 0,
                "passed_count": int(run_index.passed_count or 0) if run_index is not None else 0,
                "failed_count": int(run_index.failed_count or 0) if run_index is not None else 0,
                "workflow_mode": str(run_index.workflow_mode or "") if run_index is not None else "",
                "start_time": isoformat_local(run_index.started_at) if run_index is not None and run_index.started_at else "",
                "start_epoch": int(run_index.started_at.replace(tzinfo=UTC_PLUS_8).timestamp()) if run_index is not None and run_index.started_at else 0,
                "duration_seconds": int(run_index.duration_seconds or 0) if run_index is not None else 0,
                "last_activity": isoformat_local(run_index.last_activity_at) if run_index is not None else "",
                "updated_at": isoformat_local(run_index.last_synced_at) if run_index is not None else None,
            }
            if run_locator.get("run_name") and run_locator.get("runs_root"):
                run_summary.update(
                    {
                        "name": run_locator.get("run_name"),
                        "root_path": run_locator.get("runs_root"),
                        "path": run_locator.get("run_path"),
                        "linked_task_id": trigger.id,
                        "linked_execution_id": latest_execution.id if latest_execution is not None else None,
                        "run_id": run_index.id if run_index is not None else None,
                    }
                )

            auto_report_enabled = bool(task_metadata.get("auto_report_vulnerabilities", True))
            abnormal_reason = dict(trigger.latest_abnormal_reason_json) if isinstance(trigger.latest_abnormal_reason_json, dict) else None
            effective_status, effective_message, effective_started_at, effective_finished_at = self._effective_scan_task_runtime_state(
                trigger=trigger,
                execution=latest_execution,
                run_summary=run_summary,
            )
            control_state = derive_task_control_state(
                dispatch_status=latest_execution.dispatch_status if latest_execution is not None else None,
                process_status=latest_execution.process_status if latest_execution is not None else None,
                trigger_message=trigger.message,
                execution_message=latest_execution.message if latest_execution is not None else None,
            )
            slot_binding_state, slot_binding_reason = self._slot_binding_state(
                execution=latest_execution,
                effective_status=effective_status,
            )
            responses.append(
                ScanTaskResponse(
                    task_id=trigger.id,
                    project_id=trigger.project_id,
                    task_purpose=task_purpose,
                    agent_state_dirs={
                        key: DataflowAgentStateDirResponse.model_validate(value)
                        for key, value in self._agent_state_dirs_from_metadata(
                            project_id=trigger.project_id,
                            compiled_config=compiled_config,
                            metadata=task_metadata,
                        ).items()
                    },
                    derived_from_task_id=str(derivation.get("source_task_id") or "").strip() or None,
                    derived_from_execution_id=str(derivation.get("source_execution_id") or "").strip() or None,
                    derived_from_run_id=str(derivation.get("source_run_id") or "").strip() or None,
                    derivation_kind="evolution_replay" if str(derivation.get("kind") or "").strip() == "evolution_replay" else None,
                    task_origin_type=task_origin_type,
                    parent_project_id=trigger.parent_project_id,
                    parent_task_id=trigger.parent_task_id,
                    parent_task_type=parent_task_type,
                    parent_stage_name=trigger.parent_stage_name,
                    parent_stage_item_id=trigger.parent_stage_item_id,
                    parent_stage_item_key=trigger.parent_stage_item_key,
                    origin_label=origin_label,
                    parent_task_display=trigger.parent_task_id,
                    profile_id=self._task_effective_profile_id(trigger),
                    profile_version=int(version.version_no if version is not None else 0),
                    title=self._task_title_from_manifest_payload(first_task_payload, trigger.id),
                    status=effective_status,
                    control_state=control_state,
                    latest_attempt_no=latest_execution.attempt_no if latest_execution is not None else 0,
                    retry_count=trigger.retry_count,
                    max_retry_count=trigger.max_retry_count,
                    priority=trigger.priority,
                    created_by=trigger.submitted_by,
                    created_at=trigger.created_at,
                    started_at=effective_started_at,
                    finished_at=effective_finished_at,
                    message=effective_message,
                    latest_execution_id=(latest_execution.id if latest_execution is not None else trigger.latest_execution_id),
                    owner_pod_id=latest_execution.owner_pod_id if latest_execution is not None else None,
                    dispatch_status=latest_execution.dispatch_status if latest_execution is not None else None,
                    slot_binding_state=slot_binding_state,
                    slot_binding_reason=slot_binding_reason,
                    run_name=run_locator.get("run_name"),
                    runs_root=run_locator.get("runs_root"),
                    run_path=run_locator.get("run_path"),
                    run=run_summary,
                    latest_run=run_summary,
                    auto_report_vulnerabilities=auto_report_enabled,
                    vuln_report_status=self._vuln_report_status_from_counts(
                        enabled=auto_report_enabled,
                        counts=report_counts_by_task.get(trigger.id),
                    ),
                    abnormal_reason_title=str(abnormal_reason.get("title") or "").strip() or None if abnormal_reason else None,
                    abnormal_reason_code=str(abnormal_reason.get("code") or "").strip() or None if abnormal_reason else None,
                    abnormal_reason_category=str(abnormal_reason.get("category") or "").strip() or None if abnormal_reason else None,
                    abnormal_reason=abnormal_reason,
                )
            )
        return responses

    def list_scan_tasks(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
        status_filter: str | None = None,
        profile_id: str | None = None,
        search: str | None = None,
        slot_binding_state: str | None = None,
        report_status: str | None = None,
        model: str | None = None,
        page: int | None = None,
        per_page: int | None = None,
        mode: str | None = None,
        parent_task_id: str | None = None,
        sort_by: str | None = None,
        sort_order: str | None = None,
    ) -> ScanTaskListResponse:
        self._backfill_missing_task_list_projections(db, principal, project_id=project_id)
        query = self._list_task_projection_query(
            db,
            principal,
            project_id=project_id,
            status_filter=status_filter,
            profile_id=profile_id,
            search=search,
            slot_binding_state=slot_binding_state,
            report_status=report_status,
            model=model,
            mode=mode,
            parent_task_id=parent_task_id,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        safe_page = max(1, int(page or 1))
        safe_per_page = max(1, min(int(per_page or 100), 500))
        total = query.order_by(None).count()
        rows = query.offset((safe_page - 1) * safe_per_page).limit(safe_per_page).all()
        items = [self._projection_to_task_list_item(row) for row in rows]
        return ScanTaskListResponse(
            items=items,
            total=total,
            page=safe_page,
            per_page=safe_per_page,
            page_size=safe_per_page,
        )

    def get_scan_task_stats(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
        status_filter: str | None = None,
        profile_id: str | None = None,
        search: str | None = None,
        slot_binding_state: str | None = None,
        report_status: str | None = None,
        model: str | None = None,
        mode: str | None = None,
        parent_task_id: str | None = None,
    ) -> ScanTaskStatsResponse:
        self._backfill_missing_task_list_projections(db, principal, project_id=project_id)
        query = self._list_task_projection_query(
            db,
            principal,
            project_id=project_id,
            status_filter=status_filter,
            profile_id=profile_id,
            search=search,
            slot_binding_state=slot_binding_state,
            report_status=report_status,
            model=model,
            mode=mode,
            parent_task_id=parent_task_id,
            sort_by="created_at",
            sort_order="desc",
        )
        rows = (
            query.order_by(None)
            .with_entities(DfvsTaskListProjection.public_status, func.count(DfvsTaskListProjection.task_id))
            .group_by(DfvsTaskListProjection.public_status)
            .all()
        )
        counts = {
            "pending": 0,
            "running": 0,
            "succeeded": 0,
            "failed": 0,
            "cancelled": 0,
        }
        total = 0
        for public_status, count in rows:
            normalized = normalize_public_task_status(public_status)
            counts[normalized] = counts.get(normalized, 0) + int(count or 0)
            total += int(count or 0)
        return ScanTaskStatsResponse(
            total=total,
            pending=counts.get("pending", 0),
            running=counts.get("running", 0),
            succeeded=counts.get("succeeded", 0),
            failed=counts.get("failed", 0),
            cancelled=counts.get("cancelled", 0),
        )

    def get_scan_task(self, db: Session, task_id: str, principal: dict) -> ScanTaskDetailResponse:
        request_started = time.perf_counter()
        trigger_lookup_started = time.perf_counter()
        trigger = self._trigger_or_404(db, task_id)
        trigger_lookup_ms = _perf_elapsed_ms(trigger_lookup_started)
        self._ensure_project_access(principal, trigger.project_id)

        latest_execution_started = time.perf_counter()
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        latest_execution_ms = _perf_elapsed_ms(latest_execution_started)

        ensure_run_index_ms = 0.0
        run_index = None
        if latest_execution is not None:
            ensure_run_index_started = time.perf_counter()
            run_index = self._ensure_run_index_for_execution(db, latest_execution, trigger)
            ensure_run_index_ms = _perf_elapsed_ms(ensure_run_index_started)

        reconcile_started = time.perf_counter()
        if self._reconcile_stale_runtime(db, run_index=run_index, trigger=trigger, execution=latest_execution):
            db.commit()
            db.refresh(trigger)
        reconcile_ms = _perf_elapsed_ms(reconcile_started)

        build_detail_started = time.perf_counter()
        payload = self._scan_task_detail(db, trigger)
        build_detail_ms = _perf_elapsed_ms(build_detail_started)
        _log_api_timing(
            "GET /tasks/{task_id}",
            task_id=task_id,
            project_id=trigger.project_id,
            trigger_lookup_ms=trigger_lookup_ms,
            latest_execution_ms=latest_execution_ms,
            ensure_run_index_ms=ensure_run_index_ms,
            reconcile_ms=reconcile_ms,
            build_detail_ms=build_detail_ms,
            total_ms=_perf_elapsed_ms(request_started),
        )
        return payload

    def get_scan_task_timeline(self, db: Session, task_id: str, principal: dict) -> DataflowTaskTimelineResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        executions = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger.id)
            .order_by(WorkflowExecution.attempt_no.asc(), WorkflowExecution.created_at.asc(), WorkflowExecution.id.asc())
            .all()
        )
        execution_ids = [row.id for row in executions]
        if not execution_ids:
            return DataflowTaskTimelineResponse(task_id=trigger.id, items=[])
        attempt_by_execution = {row.id: row.attempt_no for row in executions}
        events = (
            db.query(WorkflowExecutionEvent)
            .filter(WorkflowExecutionEvent.execution_id.in_(execution_ids))
            .order_by(WorkflowExecutionEvent.created_at.asc(), WorkflowExecutionEvent.id.asc())
            .all()
        )
        items = [
            DataflowTaskTimelineEvent(
                id=event.id,
                task_id=trigger.id,
                project_id=trigger.project_id,
                execution_id=event.execution_id,
                attempt_no=attempt_by_execution.get(event.execution_id),
                stage_key=str(event.stage_id or "").strip() or None,
                stage_name=_normalize_timeline_stage_name(event.stage_id, event.payload_json if isinstance(event.payload_json, dict) else None),
                event_type=event.event_type,
                level=str(event.level or "info").strip() or "info",
                message=event.message,
                payload=event.payload_json if isinstance(event.payload_json, dict) else {},
                created_at=event.created_at,
            )
            for event in events
        ]
        return DataflowTaskTimelineResponse(task_id=trigger.id, items=items)

    def clear_scan_task_timeline(self, db: Session, task_id: str, principal: dict) -> DataflowTaskTimelineActionResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        execution_ids = [
            row[0]
            for row in db.query(WorkflowExecution.id).filter(WorkflowExecution.trigger_task_id == trigger.id).all()
        ]
        deleted = 0
        if execution_ids:
            deleted = (
                db.query(WorkflowExecutionEvent)
                .filter(WorkflowExecutionEvent.execution_id.in_(execution_ids))
                .delete(synchronize_session=False)
            ) or 0
            db.commit()
        self._log_task_mutation(
            action="timeline_cleared",
            principal=principal,
            task_id=trigger.id,
            deleted_event_count=int(deleted or 0),
        )
        return DataflowTaskTimelineActionResponse(
            task_id=trigger.id,
            message="task timeline cleared",
            deleted_event_count=int(deleted or 0),
        )

    def delete_scan_task_timeline_event(self, db: Session, task_id: str, event_id: str, principal: dict) -> DataflowTaskTimelineActionResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        event = (
            db.query(WorkflowExecutionEvent)
            .join(WorkflowExecution, WorkflowExecution.id == WorkflowExecutionEvent.execution_id)
            .filter(
                WorkflowExecutionEvent.id == event_id,
                WorkflowExecution.trigger_task_id == trigger.id,
            )
            .first()
        )
        if event is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="timeline event not found")
        db.delete(event)
        db.commit()
        self._log_task_mutation(
            action="timeline_event_deleted",
            principal=principal,
            task_id=trigger.id,
            event_id=event_id,
        )
        return DataflowTaskTimelineActionResponse(
            task_id=trigger.id,
            message="task timeline event deleted",
            deleted_event_count=1,
        )

    def get_scan_task_summary(self, db: Session, task_id: str, principal: dict) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        run_index = self._ensure_run_index_for_execution(db, latest_execution, trigger) if latest_execution is not None else None
        if self._reconcile_stale_runtime(db, run_index=run_index, trigger=trigger, execution=latest_execution):
            db.commit()
            db.refresh(trigger)
        return self._scan_task_response(db, trigger)

    def get_scan_task_artifacts(self, db: Session, task_id: str, principal: dict) -> dict[str, Any]:
        """Compatibility artifact view for upstream orchestrators.

        The canonical UI uses the Run APIs.  Binary-security historically called
        ``/tasks/{task_id}/artifacts`` after polling a downstream dataflow-vuln
        task, so keep a lightweight task-level envelope that points at the same
        run directory and indexed files.
        """
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        run_index: RunIndex | None = None
        if latest_execution is not None:
            run_index = get_run_index_service().get_run_index_by_execution(db, latest_execution)
            if run_index is None:
                run_index = self._ensure_run_index_for_execution(db, latest_execution, trigger)
        if run_index is None:
            run_index = (
                db.query(RunIndex)
                .filter(RunIndex.linked_task_id == trigger.id, RunIndex.source_type == "execution_workspace")
                .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
                .first()
            )
        workspace_root = latest_execution.workspace_root if latest_execution is not None else None
        run_payload: dict[str, Any] = {}
        files: list[dict[str, Any]] = []
        if run_index is not None:
            workspace_root = run_index.run_root_path
            run_payload = get_run_index_service().get_run_summary(db, run_index)
            files = get_run_index_service().list_run_files(db, run_index, limit=20000)
        output_root = str(Path(workspace_root) / "output") if str(workspace_root or "").strip() else ""
        return {
            "task_id": trigger.id,
            "project_id": trigger.project_id,
            "status": trigger.status,
            "execution_id": latest_execution.id if latest_execution is not None else None,
            "workspace_root": workspace_root or "",
            "output_root": output_root,
            "run_id": run_index.id if run_index is not None else None,
            "run": run_payload,
            "files": files,
        }

    def retry_scan_task(self, db: Session, task_id: str, principal: dict, payload: RunRetryRequest | None = None) -> dict[str, Any]:
        """Compatibility task-level retry used by upstream orchestrators.

        Run-level retry is a resume operation and can fail preflight when older
        runs do not have a complete session tree.  The historical task retry
        contract means "submit this scanner task again", so create a fresh
        execution attempt from the original task request instead.
        """
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        if is_canonical_task_active(trigger.status):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task is still active and cannot be retried")
        definition = db.get(WorkflowDefinition, trigger.workflow_definition_id)
        if definition is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition not found")
        definition_version = (
            self._definition_version_or_404(db, trigger.workflow_definition_version_id)
            if trigger.workflow_definition_version_id
            else get_workflow_service().get_profile_version_model(db, definition.id)
        )
        actor = _principal_id(principal)
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        first_task = manifest.tasks[0] if manifest.tasks else None
        metadata = dict(first_task.metadata or {}) if first_task is not None else {}
        if isinstance(metadata.get("dataflow_scan_request"), dict):
            execution = self._create_dataflow_cli_execution_attempt(
                db,
                trigger=trigger,
                definition=definition,
                definition_version=definition_version,
                actor=actor,
                recovery_reason="manual task retry requested",
            )
        else:
            execution = self._create_execution_attempt(
                db,
                trigger=trigger,
                definition=definition,
                definition_version=definition_version,
                actor=actor,
                authorization_token=None,
                recovery_reason="manual task retry requested",
            )
        trigger.retry_count = int(trigger.retry_count or 0) + 1
        trigger.latest_abnormal_reason_json = None
        db.add(trigger)
        self._refresh_task_list_projection_for_task_id(db, trigger.id)
        db.commit()
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="task_retry_queued",
            message="manual task retry requested",
            payload_json={"task_id": trigger.id, "attempt_no": execution.attempt_no, "request": (payload.model_dump(mode="json") if payload else {})},
        )
        return {"linked_execution_id": execution.id, "task_id": trigger.id}

    def _run_index_or_404(self, db: Session, run_index_id: str, principal: dict) -> Any:
        run_index = get_run_index_service()._run_index_or_404(db, run_index_id)
        self._ensure_project_access(principal, run_index.project_id)
        return run_index

    def list_runs(self, db: Session, principal: dict, *, project_id: str) -> list[dict[str, Any]]:
        self._ensure_project_access(principal, project_id)
        payloads = get_run_index_service().list_runs(db, project_id)
        enriched: list[dict[str, Any]] = []
        for payload in payloads:
            run_index = db.get(RunIndex, payload.get("run_id"))
            enriched.append(self._enrich_run_payload(db, run_index, payload) if run_index is not None else payload)
        return enriched

    def _run_index_resolve_response(self, run_index: RunIndex) -> dict[str, Any]:
        return {
            "run_id": run_index.id,
            "project_id": run_index.project_id,
            "run_name": run_index.run_name,
            "root_path": str(Path(run_index.run_root_path).resolve().parent),
            "source_type": run_index.source_type,
            "linked_task_id": run_index.linked_task_id,
            "linked_execution_id": run_index.linked_execution_id,
        }

    def resolve_run(self, db: Session, principal: dict, *, project_id: str, run_name: str, root_path: str) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        run_index = get_run_index_service().resolve_run(db, project_id=project_id, run_name=run_name, root_path=root_path)
        return self._run_index_resolve_response(run_index)

    def resolve_run_by_task(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str,
        task_id: str,
        execution_id: str | None = None,
    ) -> dict[str, Any]:
        request_started = time.perf_counter()
        self._ensure_project_access(principal, project_id)

        trigger_lookup_started = time.perf_counter()
        trigger = db.get(TriggerTask, task_id)
        trigger_lookup_ms = _perf_elapsed_ms(trigger_lookup_started)
        if trigger is None or trigger.project_id != project_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
        execution: WorkflowExecution | None = None

        execution_lookup_started = time.perf_counter()
        if execution_id:
            execution = db.get(WorkflowExecution, execution_id)
            if (
                execution is None
                or execution.project_id != project_id
                or execution.trigger_task_id != task_id
            ):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution not found for task")
        else:
            execution = self._latest_execution_for_trigger(db, task_id)
        execution_lookup_ms = _perf_elapsed_ms(execution_lookup_started)

        run_query_started = time.perf_counter()
        query = db.query(RunIndex).filter(
            RunIndex.project_id == project_id,
            RunIndex.source_type == "execution_workspace",
            RunIndex.linked_task_id == task_id,
        )
        if execution_id:
            query = query.filter(RunIndex.linked_execution_id == execution_id)
        run_index = query.order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc()).first()
        run_index_query_ms = _perf_elapsed_ms(run_query_started)
        if run_index is not None and not Path(run_index.run_root_path).is_dir():
            run_index = None

        ensure_run_index_ms = 0.0
        if run_index is None and execution is not None:
            ensure_started = time.perf_counter()
            run_index = self._ensure_run_index_for_execution(
                db,
                execution,
                trigger,
                include_runtime_assets=False,
            )
            ensure_run_index_ms = _perf_elapsed_ms(ensure_started)
            if run_index is not None:
                db.commit()

        fallback_sync_project_runs_ms = 0.0
        fallback_query_ms = 0.0
        if run_index is None:
            fallback_sync_started = time.perf_counter()
            get_run_index_service().sync_project_runs(db, project_id)
            fallback_sync_project_runs_ms = _perf_elapsed_ms(fallback_sync_started)
            fallback_query_started = time.perf_counter()
            query = db.query(RunIndex).filter(
                RunIndex.project_id == project_id,
                RunIndex.source_type == "execution_workspace",
                RunIndex.linked_task_id == task_id,
            )
            if execution_id:
                query = query.filter(RunIndex.linked_execution_id == execution_id)
            run_index = query.order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc()).first()
            fallback_query_ms = _perf_elapsed_ms(fallback_query_started)
            if run_index is not None and not Path(run_index.run_root_path).is_dir():
                run_index = None

        if run_index is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found for task")

        payload = self._run_index_resolve_response(run_index)
        _log_api_timing(
            "GET /runs/by-task",
            project_id=project_id,
            task_id=task_id,
            execution_id=execution_id or "",
            trigger_lookup_ms=trigger_lookup_ms,
            execution_lookup_ms=execution_lookup_ms,
            run_index_query_ms=run_index_query_ms,
            ensure_run_index_ms=ensure_run_index_ms,
            fallback_sync_project_runs_ms=fallback_sync_project_runs_ms,
            fallback_query_ms=fallback_query_ms,
            total_ms=_perf_elapsed_ms(request_started),
        )
        return payload

    def get_run_overview(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        request_started = time.perf_counter()
        lookup_started = time.perf_counter()
        run_index = self._run_index_or_404(db, run_index_id, principal)
        lookup_ms = _perf_elapsed_ms(lookup_started)
        build_started = time.perf_counter()
        payload = get_run_index_service().get_run_overview(db, run_index)
        build_ms = _perf_elapsed_ms(build_started)
        enrich_started = time.perf_counter()
        enriched = self._enrich_run_payload(db, run_index, payload, include_linked_task_detail=False)
        enrich_ms = _perf_elapsed_ms(enrich_started)
        _log_api_timing(
            "GET /runs/{run_id}/overview",
            run_id=run_index_id,
            project_id=run_index.project_id,
            run_index_lookup_ms=lookup_ms,
            build_overview_ms=build_ms,
            enrich_ms=enrich_ms,
            total_ms=_perf_elapsed_ms(request_started),
        )
        return enriched

    def get_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        return self.get_run_overview(db, run_index_id, principal)

    def get_run_detail_full(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        request_started = time.perf_counter()
        lookup_started = time.perf_counter()
        run_index = self._run_index_or_404(db, run_index_id, principal)
        lookup_ms = _perf_elapsed_ms(lookup_started)
        build_started = time.perf_counter()
        payload = get_run_index_service().get_run_detail(
            db,
            run_index,
            include_runtime_assets=True,
            force_runtime_assets=True,
        )
        build_ms = _perf_elapsed_ms(build_started)
        enrich_started = time.perf_counter()
        db.refresh(run_index)
        enriched = self._enrich_run_payload(db, run_index, payload, include_linked_task_detail=False)
        enrich_ms = _perf_elapsed_ms(enrich_started)
        _log_api_timing(
            "GET /runs/{run_id}/detail",
            run_id=run_index_id,
            project_id=run_index.project_id,
            run_index_lookup_ms=lookup_ms,
            build_detail_ms=build_ms,
            enrich_ms=enrich_ms,
            total_ms=_perf_elapsed_ms(request_started),
        )
        return enriched

    def report_run_vulnerabilities(
        self,
        db: Session,
        run_index_id: str,
        principal: dict,
        result_files: list[str],
    ) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        trigger, execution = self._linked_run_index_runtime(db, run_index)
        if trigger is None or execution is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="run is not linked to a managed scan task")
        selected = [str(item or "").strip() for item in result_files if str(item or "").strip()]
        if not selected:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="result_files must not be empty")
        try:
            report_status = get_vuln_report_service().report_run_results(
                db,
                trigger=trigger,
                execution=execution,
                run_index=run_index,
                result_files=selected,
            )
        except Exception as exc:
            db.rollback()
            report_status = {"status": "failed", "enabled": True, "error": str(exc), "items": []}
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="vuln_report_manual",
            message=f"manual vulnerability suspicion report {report_status.get('status', 'unknown')}",
            level="warning" if report_status.get("status") in {"failed", "partial_failed"} else "info",
            payload_json={**report_status, "result_files": selected},
        )
        self._refresh_task_list_projection_for_task_id(db, trigger.id)
        db.commit()
        return report_status

    def get_run_cycle(self, db: Session, run_index_id: str, cycle: int, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_cycle(db, run_index, cycle)

    def list_run_sessions(self, db: Session, run_index_id: str, principal: dict) -> list[dict[str, Any]]:
        request_started = time.perf_counter()
        lookup_started = time.perf_counter()
        run_index = self._run_index_or_404(db, run_index_id, principal)
        lookup_ms = _perf_elapsed_ms(lookup_started)
        fetch_started = time.perf_counter()
        payload = get_run_index_service().list_run_sessions(db, run_index)
        fetch_ms = _perf_elapsed_ms(fetch_started)
        _log_api_timing(
            "GET /runs/{run_id}/sessions",
            run_id=run_index_id,
            project_id=run_index.project_id,
            run_index_lookup_ms=lookup_ms,
            fetch_sessions_ms=fetch_ms,
            total_ms=_perf_elapsed_ms(request_started),
        )
        return payload

    def list_run_files(self, db: Session, run_index_id: str, principal: dict, limit: int = 1200) -> list[dict[str, Any]]:
        request_started = time.perf_counter()
        lookup_started = time.perf_counter()
        run_index = self._run_index_or_404(db, run_index_id, principal)
        lookup_ms = _perf_elapsed_ms(lookup_started)
        fetch_started = time.perf_counter()
        payload = get_run_index_service().list_run_files(db, run_index, limit=limit)
        fetch_ms = _perf_elapsed_ms(fetch_started)
        _log_api_timing(
            "GET /runs/{run_id}/files",
            run_id=run_index_id,
            project_id=run_index.project_id,
            limit=limit,
            run_index_lookup_ms=lookup_ms,
            fetch_files_ms=fetch_ms,
            total_ms=_perf_elapsed_ms(request_started),
        )
        return payload

    def get_run_file(self, db: Session, run_index_id: str, principal: dict, path: str) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_file(db, run_index, path)

    def get_run_session_file(self, db: Session, run_index_id: str, principal: dict, path: str) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_session_file(db, run_index, path)

    def get_run_log(self, db: Session, run_index_id: str, principal: dict, lines: int = 300) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_log(db, run_index, lines=lines)

    def _linked_run_index_runtime(self, db: Session, run_index) -> tuple[TriggerTask | None, WorkflowExecution | None]:
        trigger = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
        execution = db.get(WorkflowExecution, run_index.linked_execution_id) if run_index.linked_execution_id else None
        if trigger is None and execution is not None:
            trigger = db.get(TriggerTask, execution.trigger_task_id)
        if trigger is not None and (execution is None or execution.trigger_task_id != trigger.id):
            execution = self._latest_execution_for_trigger(db, trigger.id)
        return trigger, execution

    def _run_process_state(
        self,
        db: Session,
        run_index,
        *,
        trigger: TriggerTask | None = None,
        execution: WorkflowExecution | None = None,
    ) -> dict[str, Any]:
        trigger, execution = (trigger, execution) if (trigger is not None or execution is not None) else self._linked_run_index_runtime(db, run_index)
        checked_at = now_local()
        stale_after = self._process_heartbeat_stale_after_seconds()
        base: dict[str, Any] = {
            "checked_at": isoformat_local(checked_at) or "",
            "stale_after_seconds": stale_after,
            "run_status": str(run_index.status or ""),
            "trigger_task_id": trigger.id if trigger is not None else run_index.linked_task_id,
            "trigger_status": str(trigger.status or "") if trigger is not None else "",
            "execution_id": execution.id if execution is not None else run_index.linked_execution_id,
            "execution_status": str(execution.status or "") if execution is not None else "",
            "process_status": str(execution.process_status or "") if execution is not None else "",
            "can_retry": True,
            "is_running": False,
            "is_queued": False,
            "reason": "未发现活跃 run_vuln_scan.py 进程，可以重试",
            "source": "terminal_or_no_process",
        }

        run_status = str(run_index.status or "").strip().lower()
        trigger_status = str(trigger.status or "").strip().lower() if trigger is not None else ""
        execution_status = str(execution.status or "").strip().lower() if execution is not None else ""
        local_process = self._local_cli_process(execution.id) if execution is not None else None
        orphaned_resolution = self._orphaned_control_request_resolution(
            trigger=trigger,
            execution=execution,
            local_process=local_process,
        )
        if orphaned_resolution is not None:
            base.update(
                {
                    "can_retry": False,
                    "is_queued": False,
                    "reason": str(orphaned_resolution.get("message") or "control request reconciliable"),
                    "source": "orphaned_control_requested",
                    "display_status": "cancel_requested",
                    "display_label": "取消收敛中",
                    "resolution_reason": orphaned_resolution.get("resolution_reason"),
                }
            )
            return base
        if _public_task_status(trigger_status) in {"success", "failed", "cancelled"} or _public_task_status(execution_status) in {"success", "failed", "cancelled"}:
            base.update(
                {
                    "can_retry": True,
                    "is_running": False,
                    "is_queued": False,
                    "reason": "任务已进入终态，无活跃 run_vuln_scan.py 进程",
                    "source": "terminal_linked_status",
                }
            )
            return base
        if is_run_queued(run_status) or is_run_queued(trigger_status) or is_run_queued(execution_status):
            base.update(
                {
                    "can_retry": False,
                    "is_queued": True,
                    "reason": "该 Run 已有 pending/queued 的执行或 resume 请求，不能重复重试",
                    "source": "queued_execution",
                }
            )
            return base

        if execution is not None:
            if local_process is not None:
                base.update(
                    {
                        "can_retry": False,
                        "is_running": True,
                        "pid": local_process.pid,
                        "pod_id": get_config().scheduler.pod_id,
                        "reason": "当前 Pod 仍持有 run_vuln_scan.py 进程，不能重试；如需停止请先取消 Run",
                        "source": "local_process",
                    }
                )
                return base

        startup_grace = self._process_start_grace_seconds()
        base["startup_grace_seconds"] = startup_grace
        process_payload = self._read_run_process_file(run_index.run_root_path)
        if process_payload:
            heartbeat_at = self._parse_process_timestamp(
                process_payload.get("heartbeat_at")
                or process_payload.get("updated_at")
                or process_payload.get("started_at")
            )
            heartbeat_age = int(max((checked_at - heartbeat_at).total_seconds(), 0)) if heartbeat_at else None
            file_status = str(process_payload.get("status") or "").strip().lower()
            base.update(
                {
                    "pid": process_payload.get("pid"),
                    "pod_id": process_payload.get("pod_id") or "",
                    "process_file_status": file_status,
                    "process_file_execution_id": process_payload.get("execution_id") or "",
                    "heartbeat_at": process_payload.get("heartbeat_at") or process_payload.get("updated_at") or "",
                    "heartbeat_age_seconds": heartbeat_age,
                }
            )
            if file_status in {"running", "timeout_requested", "stop_requested", "delete_requested"}:
                if heartbeat_age is not None and heartbeat_age <= stale_after:
                    base.update(
                        {
                            "can_retry": False,
                            "is_running": True,
                            "reason": "共享心跳显示 run_vuln_scan.py 仍在运行，不能重试；如需停止请先取消 Run",
                            "source": "process_file_heartbeat",
                        }
                    )
                    return base
                base.update(
                    {
                        "can_retry": True,
                        "is_running": False,
                        "stale": True,
                        "display_status": "runtime_lost",
                        "display_label": "运行失联",
                        "severity": "warning",
                        "reason": "旧运行记录仍标记 active，但进程心跳已过期，可以通过 resume 重试",
                        "source": "stale_process_heartbeat",
                    }
                )
                return base

        if is_run_active(run_status) or is_run_active(trigger_status) or is_run_active(execution_status):
            started_at = None
            if execution is not None:
                started_at = execution.process_started_at or execution.started_at or started_at
            if started_at is None and trigger is not None:
                started_at = trigger.started_at
            if started_at is not None:
                started_age = int(max((checked_at - started_at).total_seconds(), 0))
                base["started_age_seconds"] = started_age
                if started_age <= startup_grace:
                    base.update(
                        {
                            "can_retry": False,
                            "is_running": True,
                            "display_status": "starting",
                            "display_label": "启动中",
                            "severity": "info",
                            "reason": "Run 刚进入运行态，等待进程注册或心跳落盘",
                            "source": "startup_grace",
                        }
                    )
                    return base

        if is_run_active(run_status) or is_run_active(trigger_status) or is_run_active(execution_status):
            base.update(
                {
                    "can_retry": True,
                    "is_running": False,
                    "stale": True,
                    "display_status": "runtime_lost",
                    "display_label": "运行失联",
                    "severity": "warning",
                    "reason": "旧运行记录仍标记 active，但未发现本地进程或有效心跳，可以通过 resume 重试",
                    "source": "stale_active_record",
                }
            )
            return base

        return base

    def _effective_run_payload_status(
        self,
        current_status: str | None,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        process_state: dict[str, Any],
    ) -> str:
        current = str(current_status or "").strip().lower()
        orphaned_resolution = self._orphaned_control_request_resolution(trigger=trigger, execution=execution)
        if orphaned_resolution is not None:
            return str(orphaned_resolution.get("terminal_status") or "cancelled")
        linked_statuses = [
            str(execution.status or "").strip().lower() if execution is not None else "",
            str(trigger.status or "").strip().lower() if trigger is not None else "",
        ]
        current_canonical = _canonical_task_status(current)
        linked_canonical_statuses = [_canonical_task_status(candidate) for candidate in linked_statuses if candidate]
        if any(status in {"pending", "running"} for status in linked_canonical_statuses):
            return "running" if "running" in linked_canonical_statuses else "pending"
        if is_run_active(current) or not current:
            terminal_linked_statuses = [candidate for candidate in linked_statuses if is_run_terminal(candidate)]
            for candidate in terminal_linked_statuses:
                if candidate not in {"succeeded", "completed"}:
                    return candidate
            if (
                not terminal_linked_statuses
                and bool(process_state.get("stale"))
                and process_state.get("is_running") is False
            ):
                stale_resolution = self._stale_runtime_terminal_resolution(
                    process_status=str(execution.process_status or "").strip().lower() if execution is not None else "",
                    process_state=process_state,
                )
                if stale_resolution is not None:
                    return stale_resolution["terminal_status"]
        return current or current_canonical or str(current_status or "")

    def _stale_runtime_terminal_resolution(
        self,
        *,
        process_status: str | None,
        process_state: dict[str, Any],
    ) -> dict[str, str] | None:
        if not bool(process_state.get("stale")):
            return None
        normalized_process_status = str(process_status or "").strip().lower()
        if normalized_process_status in {"stop_requested", "delete_requested"}:
            delete_requested = normalized_process_status == "delete_requested"
            return {
                "terminal_status": "cancelled",
                "control_status": "cancelled",
                "message": "stale delete_requested runtime assumed stopped" if delete_requested else "stale cancel_requested runtime assumed cancelled",
                "event_type": "execution_cancelled",
            }
        return {
            "terminal_status": "queued",
            "control_status": "pending",
            "message": "stale active runtime awaiting recovery",
            "event_type": "stale_runtime_recovery_pending",
        }

    def _enrich_run_payload(
        self,
        db: Session,
        run_index,
        payload: dict[str, Any],
        *,
        include_linked_task_detail: bool = False,
    ) -> dict[str, Any]:
        trigger, execution = self._linked_run_index_runtime(db, run_index)
        enriched = dict(payload)
        process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
        enriched["process_state"] = process_state
        effective_status = self._effective_run_payload_status(
            enriched.get("status"),
            trigger=trigger,
            execution=execution,
            process_state=process_state,
        )
        if effective_status and effective_status != str(enriched.get("status") or "").strip().lower():
            enriched["status"] = effective_status
        retry_command = self._retry_command_display(db, run_index=run_index, trigger=trigger, execution=execution)
        enriched["retry_command_display"] = retry_command or None
        if trigger is not None:
            task_payload = self._scan_task_response(db, trigger, include_run_summary=False)
            enriched["linked_task_purpose"] = task_payload.task_purpose
            enriched["linked_task_agent_state_dirs"] = {
                key: value.model_dump(mode="json")
                for key, value in task_payload.agent_state_dirs.items()
            }
            if include_linked_task_detail:
                task_detail_payload = self._scan_task_detail(db, trigger)
                enriched["linked_task_detail"] = task_detail_payload.model_dump(mode="json")
        return enriched

    def _mark_stale_runtime_exited(
        self,
        db: Session,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        message: str,
    ) -> None:
        trigger_before = {
            "status": str(trigger.status or "").strip() if trigger is not None else None,
            "public_status": str(trigger.public_status or "").strip() if trigger is not None else None,
            "message": str(trigger.message or "").strip() if trigger is not None else None,
        }
        execution_before = {
            "status": str(execution.status or "").strip() if execution is not None else None,
            "public_status": str(execution.public_status or "").strip() if execution is not None else None,
            "message": str(execution.message or "").strip() if execution is not None else None,
        }
        self._apply_terminal_state_mutation(
            db,
            execution=execution,
            trigger=trigger,
            terminal_status="failed",
            message=message,
            process_status="exited",
        )
        if execution is not None:
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="task_public_state_reconciled",
                message="task public state reconciled to terminal failure",
                level="warning",
                payload_json={
                    "reason": "stale_runtime_terminal_reconciled",
                    "trigger_status_before": trigger_before["status"],
                    "trigger_public_status_before": trigger_before["public_status"],
                    "trigger_message_before": trigger_before["message"],
                    "execution_status_before": execution_before["status"],
                    "execution_public_status_before": execution_before["public_status"],
                    "execution_message_before": execution_before["message"],
                    "trigger_status_after": str(trigger.status or "").strip() if trigger is not None else None,
                    "trigger_public_status_after": str(trigger.public_status or "").strip() if trigger is not None else None,
                    "trigger_message_after": str(trigger.message or "").strip() if trigger is not None else None,
                    "execution_status_after": str(execution.status or "").strip(),
                    "execution_public_status_after": str(execution.public_status or "").strip(),
                    "execution_message_after": str(execution.message or "").strip(),
                },
            )

    def _reconcile_stale_run_index_to_terminal_task(
        self,
        db: Session,
        *,
        run_index: RunIndex | None,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
    ) -> bool:
        if run_index is None or trigger is None:
            return False
        task_status = _public_task_status(trigger.status)
        if task_status not in {"success", "failed", "cancelled"}:
            return False
        run_status = _public_task_status(run_index.status)
        if run_status not in {"running", "pending", "queued", "dispatching", "starting", "cancel_requested", "delete_requested"}:
            return False

        now = now_local()
        run_index.status = "completed" if task_status == "success" else task_status
        run_index.finished_at = run_index.finished_at or trigger.finished_at or (execution.finished_at if execution is not None else None) or now
        if run_index.started_at and run_index.duration_seconds is None:
            run_index.duration_seconds = max((run_index.finished_at - run_index.started_at).total_seconds(), 0)
        if task_status in {"failed", "cancelled"} and not str(run_index.error or "").strip():
            run_index.error = str(trigger.message or (execution.message if execution is not None else "") or f"task {task_status}").strip()
        run_index.last_synced_at = now
        db.add(run_index)
        if execution is not None:
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="run_index_status_reconciled",
                message=f"run index reconciled to terminal task status: {task_status}",
                level="warning",
                payload_json={
                    "reason": "terminal_task_reconciled_stale_run_index",
                    "run_index_id": run_index.id,
                    "run_status_before": run_status,
                    "run_status_after": run_index.status,
                    "task_status": task_status,
                },
            )
        return True

    def _reconcile_terminal_run_state(
        self,
        db: Session,
        *,
        run_index: RunIndex | None,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
    ) -> bool:
        if run_index is None or (trigger is None and execution is None):
            return False
        run_status = _public_task_status(run_index.status)
        if run_status not in {"success", "failed", "cancelled"}:
            return False

        trigger_status = _public_task_status(trigger.status) if trigger is not None else ""
        execution_status = _public_task_status(execution.status) if execution is not None else ""
        trigger_runtime_reconciled_failure = (
            trigger is not None
            and trigger_status == "failed"
            and _is_runtime_reconciled_failure_message(trigger.message)
        )
        execution_runtime_reconciled_failure = (
            execution is not None
            and execution_status == "failed"
            and _is_runtime_reconciled_failure_message(execution.message)
        )
        allow_success_override = (
            run_status == "success"
            and (trigger_runtime_reconciled_failure or execution_runtime_reconciled_failure)
        )
        if (
            not allow_success_override
            and trigger_status in {"success", "failed", "cancelled"}
            and execution_status in {"", "success", "failed", "cancelled"}
        ):
            return False

        terminal_status = "succeeded" if run_status == "success" else run_status
        message = (
            ("run index reconciled to success" if terminal_status == "succeeded" else "")
            or str(run_index.error or "").strip()
            or (str(execution.message or "").strip() if execution is not None else "")
            or (str(trigger.message or "").strip() if trigger is not None else "")
            or f"run index reconciled to {run_status}"
        )
        if execution is not None and trigger is not None:
            self._set_terminal_state(
                db,
                execution=execution,
                trigger=trigger,
                execution_status=terminal_status,
                message=message,
                output_manifest_path=execution.output_manifest_path,
                output_task_count=int(execution.output_task_count or run_index.result_count or 0),
            )
        else:
            self._apply_terminal_state_mutation(
                db,
                execution=execution,
                trigger=trigger,
                terminal_status=terminal_status,
                message=message,
                process_status="exited",
                sync_abnormal_reason=terminal_status != "succeeded",
            )
        db.flush()
        if execution is not None:
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="run_index_terminal_state_reconciled",
                message=message,
                level="warning" if terminal_status in {"failed", "cancelled"} else "info",
                payload_json={
                    "reason": "run_index_terminal_reconciled",
                    "run_index_id": run_index.id,
                    "run_status": run_status,
                },
            )
        return True

    def _reconcile_stale_runtime(
        self,
        db: Session,
        *,
        run_index: RunIndex | None,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
    ) -> bool:
        if run_index is None or (trigger is None and execution is None):
            return False
        if self._requeue_unbound_active_execution_if_safe(
            db,
            trigger=trigger,
            execution=execution,
            run_index=run_index,
            reason="stale_runtime_reconcile",
        ):
            return True
        if self._reconcile_terminal_run_state(
            db,
            run_index=run_index,
            trigger=trigger,
            execution=execution,
        ):
            return True
        process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
        if self._requeue_stale_starting_without_process(
            db,
            run_index=run_index,
            trigger=trigger,
            execution=execution,
            process_state=process_state,
        ):
            return True
        if not bool(process_state.get("stale")):
            return False

        execution_status = _canonical_task_status(execution.status) if execution is not None else ""
        trigger_status = _canonical_task_status(trigger.status) if trigger is not None else ""
        process_status = str(execution.process_status or "").strip().lower() if execution is not None else ""
        if not is_run_active(execution_status) and not is_run_active(trigger_status):
            return False
        resolution = self._stale_runtime_terminal_resolution(
            process_status=process_status,
            process_state=process_state,
        )
        if resolution is None:
            return False

        if self._requeue_stale_runtime_without_process(
            db,
            run_index=run_index,
            trigger=trigger,
            execution=execution,
            message=resolution["message"],
            process_state=process_state,
        ):
            return True

        terminal_status = resolution["terminal_status"]
        message = resolution["message"]
        event_type = resolution["event_type"]
        control_status = resolution["control_status"]
        if terminal_status == "cancelled":
            if execution is not None and trigger is not None:
                self._set_terminal_state(
                    db,
                    execution=execution,
                    trigger=trigger,
                    execution_status=terminal_status,
                    message=message,
                    output_manifest_path=execution.output_manifest_path,
                    output_task_count=int(execution.output_task_count or run_index.result_count or 0),
                )
            else:
                self._apply_terminal_state_mutation(
                    db,
                    execution=execution,
                    trigger=trigger,
                    terminal_status=terminal_status,
                    message=message,
                    process_status="exited",
                    sync_abnormal_reason=False,
                )
            self._write_run_control_state(run_index.run_root_path, status_text=control_status, message=message)
            get_run_index_service().sync_execution_run(db, execution)
            self._refresh_task_list_projection_for_execution(db, execution)
            db.flush()
            if execution is not None:
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type=event_type,
                    message=message,
                    level="warning",
                    payload_json={"reason": "stale_runtime_reconciled", "process_state": process_state},
                )
            return True

        if terminal_status == "queued":
            if self._requeue_stale_runtime_without_process(
                db,
                run_index=run_index,
                trigger=trigger,
                execution=execution,
                message=message,
                process_state={**process_state, "source": "stale_runtime_recovery_pending"},
            ):
                if execution is not None:
                    self.record_event(
                        db,
                        execution_id=execution.id,
                        event_type=event_type,
                        message=message,
                        level="warning",
                        payload_json={"reason": "stale_runtime_recovery_pending", "process_state": process_state},
                    )
                return True
            if execution is not None:
                execution.message = "stale active runtime kept running by run evidence"
                db.add(execution)
            if trigger is not None:
                trigger.message = "stale active runtime kept running by run evidence"
                db.add(trigger)
            if run_index is not None:
                self._write_run_control_state(
                    run_index.run_root_path,
                    status_text="running",
                    message="stale active runtime kept running by run evidence",
                )
                get_run_index_service().sync_execution_run(db, execution)
            if execution is not None:
                self._refresh_task_list_projection_for_execution(db, execution)
                db.flush()
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type="stale_runtime_kept_running",
                    message="stale active runtime kept running by run evidence",
                    level="warning",
                    payload_json={"reason": "stale_runtime_kept_running", "process_state": process_state},
                )
            return True

        self._mark_stale_runtime_exited(
            db,
            trigger=trigger,
            execution=execution,
            message=message,
        )
        self._write_run_control_state(run_index.run_root_path, status_text=control_status, message=message)
        get_run_index_service().sync_execution_run(db, execution)
        self._refresh_task_list_projection_for_execution(db, execution)
        db.flush()
        if execution is not None:
            self.record_event(
                db,
                execution_id=execution.id,
                event_type=event_type,
                message=message,
                level="warning",
                payload_json={"reason": "stale_runtime_reconciled", "process_state": process_state},
            )
        return True

    def _requeue_stale_starting_without_process(
        self,
        db: Session,
        *,
        run_index: RunIndex | None,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        process_state: dict[str, Any],
    ) -> bool:
        if execution is None:
            return False
        if execution.process_pid or execution.process_started_at:
            return False
        execution_status = str(execution.status or "").strip().lower()
        dispatch_status = str(execution.dispatch_status or "").strip().lower()
        if "starting" not in {execution_status, dispatch_status}:
            return False
        started_at = execution.started_at or (trigger.started_at if trigger is not None else None)
        if started_at is None:
            return False
        startup_grace = self._process_start_grace_seconds()
        if int(max((now_local() - started_at).total_seconds(), 0)) <= startup_grace:
            return False
        return self._requeue_stale_runtime_without_process(
            db,
            run_index=run_index,
            trigger=trigger,
            execution=execution,
            message="starting runtime exceeded startup grace without process registration",
            process_state={**process_state, "source": "stale_starting_without_process"},
        )

    def _requeue_stale_runtime_without_process(
        self,
        db: Session,
        *,
        run_index: RunIndex | None,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        message: str,
        process_state: dict[str, Any],
    ) -> bool:
        if execution is None:
            return False
        if execution.process_pid or execution.process_started_at:
            return False
        execution_status = _canonical_task_status(execution.status)
        trigger_status = _canonical_task_status(trigger.status) if trigger is not None else ""
        if execution_status not in {"dispatching", "running"} and trigger_status not in {"dispatching", "running"}:
            return False

        worker_url = execution.worker_url
        owner_pod_id = execution.owner_pod_id
        worker_job_id = execution.worker_job_id
        requeue_message = f"stale runtime had no process registration, requeued: {message}"
        (
            db.query(SchedulerWorkerSlotReservation)
            .filter(SchedulerWorkerSlotReservation.execution_id == execution.id)
            .delete(synchronize_session=False)
        )
        execution.worker_url = None
        execution.worker_job_id = None
        execution.owner_pod_id = None
        execution.status = "queued"
        execution.public_status = "queued"
        execution.control_state = "none"
        execution.dispatch_status = "queued"
        execution.dispatch_error = message
        execution.process_status = "not_started"
        execution.process_pid = None
        execution.process_started_at = None
        execution.process_finished_at = None
        execution.started_at = None
        execution.finished_at = None
        execution.message = requeue_message
        if trigger is not None:
            trigger.status = "queued"
            trigger.public_status = "queued"
            trigger.control_state = "none"
            trigger.started_at = None
            trigger.finished_at = None
            trigger.message = requeue_message
            db.add(trigger)
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="queued", control_state="none")
        db.add(execution)
        self._refresh_task_list_projection_for_execution(db, execution)
        db.flush()
        if run_index is not None:
            self._write_run_control_state(run_index.run_root_path, status_text="queued", message=requeue_message)
            get_run_index_service().sync_execution_run(db, execution)
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="worker_job_requeued_before_process_start",
            message=requeue_message,
            level="warning",
            payload_json={
                "reason": "stale_runtime_without_process",
                "process_state": process_state,
                "worker_url": worker_url,
                "owner_pod_id": owner_pod_id,
                "worker_job_id": worker_job_id,
                "process_pid": None,
            },
        )
        try:
            from app.services.scheduler import get_scheduler_service

            get_scheduler_service()._record_execution_health_sample(  # type: ignore[attr-defined]
                "stale_without_pid",
                reason=message,
                payload={
                    "execution_id": execution.id,
                    "owner_pod_id": owner_pod_id,
                    "worker_job_id": worker_job_id,
                },
            )
        except Exception:
            logger.exception("failed to record stale-without-pid execution health sample execution=%s", execution.id)
        return True

    def reconcile_stale_active_executions(self, db: Session, *, limit: int = 200) -> int:
        reconciled = 0
        rows = (
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.status.in_(
                    (
                        "pending",
                        "queued",
                        "dispatching",
                        "running",
                        "cancel_requested",
                        "delete_requested",
                    )
                )
            )
            .order_by(WorkflowExecution.updated_at.asc())
            .limit(limit)
            .all()
        )
        for execution in rows:
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            orphaned_resolution = self._orphaned_control_request_resolution(
                trigger=trigger,
                execution=execution,
            )
            if orphaned_resolution is not None:
                self._finalize_orphaned_control_request(
                    db,
                    trigger=trigger,
                    execution=execution,
                    resolution=orphaned_resolution,
                )
                reconciled += 1
                db.commit()
                continue
            if self._reconcile_legacy_dispatch_failure(
                db,
                trigger=trigger,
                execution=execution,
            ):
                reconciled += 1
                db.commit()
                continue
            run_index = self._ensure_run_index_for_execution(db, execution, trigger)
            if self._requeue_unbound_active_execution_if_safe(
                db,
                trigger=trigger,
                execution=execution,
                run_index=run_index,
                reason="reconcile_stale_active_executions",
            ):
                reconciled += 1
                db.commit()
                continue
            if self._reconcile_stale_runtime(
                db,
                run_index=run_index,
                trigger=trigger,
                execution=execution,
            ):
                reconciled += 1
                db.commit()
        return reconciled

    def _preflight_run_resume(self, *, run_index, payload: RunRetryRequest) -> dict[str, Any]:
        run_dir = Path(run_index.run_root_path)
        if not run_dir.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run directory not found")
        try:
            import run_vuln_scan as launcher
            from app.pi_vuln_core.resume import build_resume_plan, rebuild_review_state

            config_obj, plan = build_resume_plan(run_dir)
            review_state = rebuild_review_state(plan.atomic_work_dir)
            diagnostics = launcher._collect_resume_diagnostics(  # type: ignore[attr-defined]
                plan.atomic_work_dir,
                review_state=review_state,
            )
            current_model, current_thinking = launcher._extract_worker_runtime(config_obj)  # type: ignore[attr-defined]
            display_model = self._normalize_model_override(model=payload.model, provider=payload.provider) if payload.model else current_model
            display_thinking = launcher.resolve_profile_thinking(  # type: ignore[attr-defined]
                display_model,
                launcher._extract_review_profile_from_config_obj(config_obj),  # type: ignore[attr-defined]
            ) or current_thinking
            preview_path = launcher._write_resume_preview_file(  # type: ignore[attr-defined]
                run_dir=str(run_dir.resolve()),
                atomic_work_dir=plan.atomic_work_dir,
                current_status=plan.current_status or "unknown",
                completed_cycles=plan.completed_cycles,
                extra_cycles=payload.extra_cycles,
                worker_session_id=plan.worker_session_id,
                timeout_detected=plan.timeout_detected,
                timeout_call_dir=plan.timeout_call_dir,
                timeout_agent_id=plan.timeout_agent_id,
                timeout_error=plan.timeout_error,
                resume_state=plan.resume_state,
                checkpoint_cycle=plan.checkpoint_cycle,
                checkpoint_phase=plan.checkpoint_phase,
                checkpoint_step_key=plan.checkpoint_step_key,
                checkpoint_status=plan.checkpoint_status,
                resume_cursor=plan.resume_cursor,
                resume_start_cycle=plan.resume_start_cycle,
                resume_target_node={
                    "cycle": int((plan.resume_cursor or {}).get("cycle") or 0),
                    "phase": plan.resume_target_phase,
                    "step_key": plan.resume_target_step_key,
                    "node_id": str((plan.resume_cursor or {}).get("node_id") or ""),
                    "node_kind": str((plan.resume_cursor or {}).get("node_kind") or ""),
                } if plan.resume_target_phase else None,
                node_resume_policy=plan.node_resume_policy,
                model_display=launcher._format_model_display(display_model),  # type: ignore[attr-defined]
                thinking=display_thinking,
                task_file=plan.task_file,
                diagnostics=diagnostics,
            )
            return {
                "preview_path": preview_path,
                "atomic_work_dir": plan.atomic_work_dir,
                "current_status": plan.current_status,
                "completed_cycles": plan.completed_cycles,
                "extra_cycles": payload.extra_cycles,
                "resume_start_cycle": plan.resume_start_cycle,
                "resume_total_cycle_limit": max(plan.completed_cycles, plan.resume_start_cycle) + payload.extra_cycles,
                "resume_cursor": plan.resume_cursor,
                "resume_target_node": {
                    "cycle": int((plan.resume_cursor or {}).get("cycle") or 0),
                    "phase": plan.resume_target_phase,
                    "step_key": plan.resume_target_step_key,
                    "node_id": str((plan.resume_cursor or {}).get("node_id") or ""),
                    "node_kind": str((plan.resume_cursor or {}).get("node_kind") or ""),
                } if plan.resume_target_phase else None,
                "node_resume_policy": plan.node_resume_policy,
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail=f"resume preflight failed: {exc}",
            ) from exc

    def _wait_until_execution_inactive(self, db: Session, execution_id: str, *, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + max(timeout_seconds, 0.0)
        while True:
            db.expire_all()
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return True
            if not self._run_index_status_is_active(execution.status):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.5)

    @staticmethod
    def _expunge_loaded_records(db: Session, model: type, record_ids: list[str] | None) -> None:
        id_set = {str(item).strip() for item in (record_ids or []) if str(item).strip()}
        if not id_set:
            return
        for instance in list(db.identity_map.values()):
            if isinstance(instance, model) and str(getattr(instance, "id", "") or "") in id_set:
                try:
                    db.expunge(instance)
                except Exception:
                    pass

    def _delete_linked_runtime_records(self, db: Session, *, linked_task_id: str | None, linked_execution_id: str | None) -> None:
        execution_ids: list[str] = []
        if linked_task_id:
            execution_ids = [
                item[0]
                for item in db.query(WorkflowExecution.id)
                .filter(WorkflowExecution.trigger_task_id == linked_task_id)
                .all()
            ]
        elif linked_execution_id:
            execution_ids = [linked_execution_id]

        self._expunge_loaded_records(db, WorkflowExecution, execution_ids)
        self._expunge_loaded_records(db, TriggerTask, [linked_task_id] if linked_task_id else [])
        self._expunge_loaded_records(db, DfvsTaskListProjection, [linked_task_id] if linked_task_id else [])

        if execution_ids:
            db.query(WorkflowExecutionEvent).filter(WorkflowExecutionEvent.execution_id.in_(execution_ids)).delete(synchronize_session=False)
            db.query(WorkflowExecution).filter(WorkflowExecution.id.in_(execution_ids)).delete(synchronize_session=False)
        if linked_task_id:
            db.query(TriggerTask).filter(TriggerTask.id == linked_task_id).delete(synchronize_session=False)
            db.query(DfvsTaskListProjection).filter(DfvsTaskListProjection.task_id == linked_task_id).delete(synchronize_session=False)

    def delete_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        project_id = run_index.project_id
        run_name = run_index.run_name
        linked_task_id = run_index.linked_task_id
        linked_execution_id = run_index.linked_execution_id
        trigger, execution = self._linked_run_index_runtime(db, run_index)
        stop_payload: dict[str, Any] = {"signal": None}
        process_pid = execution.process_pid if execution is not None else None
        process_host = execution.process_host if execution is not None else None
        if execution is None and self._run_index_status_is_active(run_index.status):
            process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
            if process_state.get("is_running"):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="active run is not linked to a managed execution and still appears to be running; retry delete after it stops",
                )
        self._record_task_mutation_event(
            db,
            event_type="run_delete_requested",
            message="run delete requested",
            trigger=trigger,
            execution=execution,
            task_id=linked_task_id,
            payload_json={
                "run_id": run_index.id,
                "linked_task_id": linked_task_id,
                "linked_execution_id": linked_execution_id,
                "workspace_roots": [path for path in {run_index.run_root_path, *(([execution.workspace_root] if execution and execution.workspace_root else []))} if str(path or "").strip()],
                "run_index_ids": [run_index.id],
            },
        )
        if execution is not None and execution.status == "pending":
            self._apply_terminal_state_mutation(
                db,
                execution=execution,
                trigger=trigger,
                terminal_status="cancelled",
                message="deleted before dispatch",
                process_status="not_started",
                sync_abnormal_reason=False,
            )
        elif execution is not None and self._run_index_status_is_active(execution.status):
            execution.status = "running"
            execution.message = "delete requested; stopping run_vuln_scan.py"
            execution.process_status = "delete_requested"
            self._sync_runtime_state_snapshots(
                trigger=trigger,
                execution=execution,
                public_status="running",
                control_state="delete_requested",
            )
            db.add(execution)
            if trigger is not None:
                trigger.status = "running"
                trigger.message = "delete requested; stopping run_vuln_scan.py"
                db.add(trigger)
            run_index = get_run_index_service().bind_runtime_state(
                db,
                run_index,
                linked_execution=execution,
                linked_task=trigger,
                profile_id=run_index.profile_id,
                status_text="delete_requested",
            )
            self._write_run_control_state(run_index.run_root_path, status_text="delete_requested", message="delete requested")
            db.commit()
            stop_payload = (
                self._cancel_worker_job(execution)
                if execution.worker_url and execution.worker_job_id
                else self._signal_local_cli_process(execution.id, wait=True)
            )
            process_pid = stop_payload.get("pid") or process_pid
            if execution.worker_url and execution.worker_job_id:
                self._record_worker_control_result(
                    db,
                    execution=execution,
                    action="delete",
                    payload=stop_payload,
                )
                if stop_payload.get("signal") == "worker_unreachable":
                    return self._run_mutation_response(
                        run_id=run_index_id,
                        project_id=project_id,
                        status_text="running",
                        message="Run delete requested; worker unreachable",
                        linked_task_id=linked_task_id,
                        linked_execution_id=linked_execution_id,
                        process_pid=process_pid,
                        process_host=process_host,
                        process_signal=stop_payload.get("signal"),
                        control_state="delete_requested",
                    )
            if stop_payload.get("exit_code") is not None or stop_payload.get("signal") == "already_exited":
                if trigger is not None:
                    self._set_terminal_state(
                        db,
                        execution=execution,
                        trigger=trigger,
                        execution_status="cancelled",
                        message="run_vuln_scan.py stopped for delete",
                    )
                else:
                    execution.status = "cancelled"
                    execution.message = "run_vuln_scan.py stopped for delete"
                    execution.finished_at = now_local()
                    execution.process_status = "exited"
                    execution.process_finished_at = now_local()
                    self._sync_runtime_state_snapshots(
                        trigger=trigger,
                        execution=execution,
                        public_status="cancelled",
                        control_state="none",
                    )
                    db.add(execution)
                db.commit()
            else:
                stopped = self._wait_until_execution_inactive(db, execution.id, timeout_seconds=45)
                if not stopped:
                    db.expire_all()
                    run_index = db.get(type(run_index), run_index_id)
                    if run_index is None:
                        return self._run_mutation_response(
                            run_id=run_index_id,
                            project_id=project_id,
                            status_text="deleted",
                            message=f"Run {run_name} deleted",
                            linked_task_id=linked_task_id,
                            linked_execution_id=linked_execution_id,
                            process_pid=process_pid,
                            process_host=process_host,
                            process_signal=stop_payload.get("signal"),
                            control_state="none",
                        )
                    trigger, execution = self._linked_run_index_runtime(db, run_index)
                    process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
                    if process_state.get("is_running"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="run deletion requested but run_vuln_scan.py is still stopping; retry delete shortly",
                        )
                    self._mark_stale_runtime_exited(
                        db,
                        trigger=trigger,
                        execution=execution,
                        message="stale delete_requested run assumed stopped during delete",
                    )
                    db.commit()
            db.expire_all()
            run_index = db.get(type(run_index), run_index_id)
            if run_index is None:
                return self._run_mutation_response(
                    run_id=run_index_id,
                    project_id=project_id,
                    status_text="deleted",
                    message=f"Run {run_name} deleted",
                    linked_task_id=linked_task_id,
                    linked_execution_id=linked_execution_id,
                    process_pid=process_pid,
                    process_host=process_host,
                    process_signal=stop_payload.get("signal"),
                    control_state="none",
                )
        self._delete_linked_runtime_records(db, linked_task_id=linked_task_id, linked_execution_id=linked_execution_id)
        get_run_index_service().delete_run_index(db, run_index, allow_active=True)
        db.commit()
        self._log_task_mutation(
            action="run_deleted",
            principal=principal,
            run_id=run_index_id,
            project_id=project_id,
            linked_task_id=linked_task_id,
            linked_execution_id=linked_execution_id,
        )
        return self._run_mutation_response(
            run_id=run_index_id,
            project_id=project_id,
            status_text="deleted",
            message=f"Run {run_name} deleted",
            linked_task_id=linked_task_id,
            linked_execution_id=linked_execution_id,
            process_pid=process_pid,
            process_host=process_host,
            process_signal=stop_payload.get("signal"),
            control_state="none",
        )

    def adopt_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        run_root = Path(run_index.run_root_path)
        if not run_root.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run directory not found")

        trigger = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
        execution = db.get(WorkflowExecution, run_index.linked_execution_id) if run_index.linked_execution_id else None
        if trigger is None and execution is not None:
            trigger = db.get(TriggerTask, execution.trigger_task_id)
        if trigger is not None and execution is not None and execution.trigger_task_id != trigger.id:
            execution = None
        if trigger is not None and execution is None:
            execution = self._latest_execution_for_trigger(db, trigger.id)

        definition = self._select_run_index_definition(db, run_index, principal)
        definition_version = get_workflow_service().get_profile_version_model(db, definition.id)
        actor = _principal_id(principal)
        task_status = self._adopted_run_index_task_status(run_index.status)
        active = self._run_index_status_is_active(run_index.status)
        started_at = run_index.started_at
        finished_at = None if active else (run_index.finished_at or run_index.last_activity_at)
        adoption_message = f"adopted Run {run_index.run_name}"

        if trigger is None:
            trigger = TriggerTask(
                id=_new_id("tt"),
                workflow_definition_id=definition.id,
                workflow_definition_version_id=definition_version.id,
                profile_id=definition.id,
                project_id=run_index.project_id,
                trigger_type="manual",
                input_tasks_json=self._run_index_adoption_manifest(run_index),
                priority=definition.priority_default,
                status=task_status,
                submitted_by=actor,
                retry_count=0,
                max_retry_count=definition.max_retry_count,
                latest_execution_id=None,
                started_at=started_at,
                finished_at=finished_at,
                message=adoption_message,
            )
        else:
            self._ensure_project_access(principal, trigger.project_id)
            trigger.workflow_definition_id = definition.id
            trigger.workflow_definition_version_id = definition_version.id
            trigger.profile_id = definition.id
            trigger.project_id = run_index.project_id
            trigger.input_tasks_json = self._run_index_adoption_manifest(run_index)
            trigger.status = task_status
            trigger.started_at = started_at
            trigger.finished_at = finished_at
            trigger.message = adoption_message
        if task_status in {"failed", "cancelled", "error", "interrupted"}:
            self._sync_trigger_abnormal_reason(db, trigger=trigger, execution=execution)
        else:
            trigger.latest_abnormal_reason_json = None
        db.add(trigger)
        db.flush()

        if execution is None:
            execution = WorkflowExecution(
                id=_new_id("exec"),
                trigger_task_id=trigger.id,
                workflow_definition_id=definition.id,
                workflow_definition_version_id=definition_version.id,
                project_id=run_index.project_id,
                attempt_no=(
                    db.query(WorkflowExecution)
                    .filter(WorkflowExecution.trigger_task_id == trigger.id)
                    .count()
                ) + 1,
                status=task_status,
                recovery_reason="run adopted",
                workspace_root=abs_path(run_root),
                output_manifest_path=self._run_index_output_manifest_path(run_index),
                output_task_count=run_index.result_count,
                started_at=started_at,
                finished_at=finished_at,
                message=adoption_message,
            )
        else:
            self._ensure_project_access(principal, execution.project_id)
            execution.trigger_task_id = trigger.id
            execution.workflow_definition_id = definition.id
            execution.workflow_definition_version_id = definition_version.id
            execution.project_id = run_index.project_id
            execution.status = task_status
            execution.recovery_reason = execution.recovery_reason or "run adopted"
            execution.workspace_root = abs_path(run_root)
            execution.output_manifest_path = self._run_index_output_manifest_path(run_index)
            execution.output_task_count = run_index.result_count
            execution.started_at = started_at
            execution.finished_at = finished_at
            execution.message = adoption_message
        self._sync_runtime_state_snapshots(
            trigger=trigger,
            execution=execution,
            public_status=task_status,
            control_state="none",
        )
        db.add(execution)
        db.flush()

        trigger.latest_execution_id = execution.id
        db.add(trigger)
        run_index = get_run_index_service().bind_runtime_state(
            db,
            run_index,
            linked_execution=execution,
            linked_task=trigger,
            profile_id=definition.id,
            status_text=run_index.status,
        )
        db.commit()
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="run_adopted",
            message=adoption_message,
            payload_json={
                "run_id": run_index.id,
                "project_id": run_index.project_id,
                "run_root_path": run_index.run_root_path,
            },
        )
        return self._run_mutation_response(
            run_id=run_index.id,
            project_id=run_index.project_id,
            status_text=_canonical_task_status(run_index.status),
            message=adoption_message,
            linked_task_id=trigger.id,
            linked_execution_id=execution.id,
            control_state="none",
        )

    def cancel_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        if run_index.linked_task_id:
            linked_execution = db.get(WorkflowExecution, run_index.linked_execution_id) if run_index.linked_execution_id else None
            self._record_task_mutation_event(
                db,
                event_type="run_cancel_requested",
                message="run cancel requested",
                task_id=run_index.linked_task_id,
                execution=linked_execution,
                payload_json={
                    "run_id": run_index.id,
                    "linked_task_id": run_index.linked_task_id,
                    "linked_execution_id": run_index.linked_execution_id,
                    "process_signal": None,
                    "worker_job_id": linked_execution.worker_job_id if linked_execution is not None else None,
                    "status_before": _canonical_task_status(run_index.status),
                },
            )
            self.cancel_scan_task(db, run_index.linked_task_id, principal, signal_process=False)
            trigger = self._trigger_or_404(db, run_index.linked_task_id)
            latest_execution = self._latest_execution_for_trigger(db, trigger.id)
            stop_payload = (
                self._cancel_worker_job(latest_execution)
                if latest_execution is not None and latest_execution.worker_url and latest_execution.worker_job_id
                else self._signal_local_cli_process(latest_execution.id, wait=False)
                if latest_execution is not None and _canonical_task_status(latest_execution.status) in {"dispatching", "running"}
                else {"signal": None}
            )
            if latest_execution is not None and latest_execution.worker_url and latest_execution.worker_job_id:
                self._record_worker_control_result(
                    db,
                    execution=latest_execution,
                    action="cancel",
                    payload=stop_payload,
                )
            status_text = "running"
            message = "Run cancel requested"
            effective_trigger_status = _canonical_task_status(trigger.status) if trigger is not None else ""
            effective_execution_status = _canonical_task_status(latest_execution.status) if latest_execution is not None else ""
            if effective_trigger_status == "cancelled" or effective_execution_status == "cancelled" or latest_execution is None:
                status_text = "cancelled"
                message = str(trigger.message or (latest_execution.message if latest_execution is not None else "") or "cancelled before dispatch")
            self._write_run_control_state(run_index.run_root_path, status_text=status_text, message=message)
            run_index = get_run_index_service().bind_runtime_state(
                db,
                run_index,
                linked_execution=latest_execution,
                linked_task=trigger,
                profile_id=run_index.profile_id,
                status_text=status_text,
            )
            db.commit()
            return self._run_mutation_response(
                run_id=run_index.id,
                project_id=run_index.project_id,
                status_text=_canonical_task_status(run_index.status),
                message=message,
                linked_task_id=run_index.linked_task_id,
                linked_execution_id=run_index.linked_execution_id,
                process_pid=stop_payload.get("pid") or (latest_execution.process_pid if latest_execution else None),
                process_host=latest_execution.process_host if latest_execution else None,
                process_signal=stop_payload.get("signal"),
                control_state="none" if status_text == "cancelled" else "cancel_requested",
            )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="run is not managed by a cancellable execution")

    def _resume_command_preview_payload(self, *, run_index, payload: RunRetryRequest) -> dict[str, Any]:
        request = self._build_run_index_resume_request(run_index=run_index, payload=payload)
        plan = self._build_dataflow_cli_resume_plan(
            project_id=run_index.project_id,
            request=request,
        )
        return self._resume_command_payload_from_plan(plan=plan, request=request)

    def preview_run_retry(
        self,
        db: Session,
        run_index_id: str,
        principal: dict,
        payload: RunRetryRequest,
    ) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        run_index = get_run_index_service().refresh_run_index(db, run_index)
        run_root = Path(run_index.run_root_path)
        if not run_root.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run directory not found")

        trigger, latest_execution = self._linked_run_index_runtime(db, run_index)
        process_state = self._run_process_state(db, run_index, trigger=trigger, execution=latest_execution)
        can_retry = bool(process_state.get("can_retry"))
        reason = str(process_state.get("reason") or "")
        resume_preflight: dict[str, Any] = {}
        if can_retry:
            resume_preflight = self._preflight_run_resume(run_index=run_index, payload=payload)
            try:
                command_payload = self._resume_command_preview_payload(run_index=run_index, payload=payload)
                resume_preflight.update(
                    {
                        "argv": command_payload.get("argv") or [],
                        "command": command_payload.get("command") or [],
                        "command_display": command_payload.get("command_display") or "",
                    }
                )
            except Exception as exc:
                resume_preflight["command_preview_error"] = str(exc)
            resume_preflight.update(
                {
                    "can_retry": True,
                    "reason": reason,
                    "process_state": process_state,
                }
            )

        return {
            "success": True,
            "run_id": run_index.id,
            "project_id": run_index.project_id,
            "can_retry": can_retry,
            "reason": reason,
            "process_state": process_state,
            "resume_preflight": resume_preflight,
        }

    def retry_run(
        self,
        db: Session,
        run_index_id: str,
        principal: dict,
        payload: RunRetryRequest,
    ) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        run_index = get_run_index_service().refresh_run_index(db, run_index)
        run_root = Path(run_index.run_root_path)
        if not run_root.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run directory not found")

        trigger, latest_execution = self._linked_run_index_runtime(db, run_index)
        process_state = self._run_process_state(db, run_index, trigger=trigger, execution=latest_execution)
        if not bool(process_state.get("can_retry")):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(process_state.get("reason") or "run_vuln_scan.py is still active; cannot retry"),
            )
        preflight = self._preflight_run_resume(run_index=run_index, payload=payload)
        preflight.update(
            {
                "can_retry": True,
                "reason": str(process_state.get("reason") or ""),
                "process_state": process_state,
            }
        )
        try:
            command_payload = self._resume_command_preview_payload(run_index=run_index, payload=payload)
            preflight.update(
                {
                    "argv": command_payload.get("argv") or [],
                    "command": command_payload.get("command") or [],
                    "command_display": command_payload.get("command_display") or "",
                }
            )
        except Exception as exc:
            preflight["command_preview_error"] = str(exc)
        self._mark_stale_runtime_exited(
            db,
            trigger=trigger,
            execution=latest_execution,
            message="previous run_vuln_scan.py process is no longer active; retrying via resume",
        )

        definition = self._select_run_index_definition(db, run_index, principal)
        workflow_service = get_workflow_service()
        definition_version = workflow_service.get_profile_version_model(db, definition.id)
        request = self._build_run_index_resume_request(run_index=run_index, payload=payload)
        actor = _principal_id(principal)

        trigger = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
        if trigger is not None:
            self._ensure_project_access(principal, trigger.project_id)
            self._update_trigger_for_run_index_resume(trigger=trigger, run_index=run_index, request=request)
            db.add(trigger)
            execution = self._create_dataflow_cli_execution_attempt(
                db,
                trigger=trigger,
                definition=definition,
                definition_version=definition_version,
                actor=actor,
                recovery_reason="manual run resume requested",
            )
        else:
            trigger, execution = self._create_run_index_resume_task_record(
                db,
                definition=definition,
                definition_version=definition_version,
                run_index=run_index,
                request=request,
                actor=actor,
            )

        run_index = get_run_index_service().bind_runtime_state(
            db,
            run_index,
            linked_execution=execution,
            linked_task=trigger,
            profile_id=definition.id,
            status_text="queued",
        )
        if trigger is not None:
            self._refresh_task_list_projection_for_task_id(db, trigger.id)
        else:
            self._refresh_task_list_projection_for_execution(db, execution)
        db.commit()
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="run_resume_queued",
            message="manual run resume requested",
            payload_json={
                "run_id": run_index.id,
                "project_id": run_index.project_id,
                "run_root_path": run_index.run_root_path,
                "extra_cycles": payload.extra_cycles,
                "resume_preflight": preflight,
            },
        )
        response = self._run_mutation_response(
            run_id=run_index.id,
            project_id=run_index.project_id,
            status_text=_canonical_task_status(run_index.status),
            message="Run resume started",
            linked_task_id=trigger.id,
            linked_execution_id=execution.id,
            control_state="none",
        )
        response["resume_preflight"] = preflight
        return response

    def cancel_scan_task(self, db: Session, task_id: str, principal: dict, *, signal_process: bool = True) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        status_before = _canonical_task_status(trigger.status)
        worker_bound_execution = (
            latest_execution
            if latest_execution is not None and latest_execution.worker_url and latest_execution.worker_job_id
            else None
        )
        if trigger.status == "pending":
            self._apply_terminal_state_mutation(
                db,
                execution=latest_execution if latest_execution is not None and latest_execution.status == "pending" else None,
                trigger=trigger,
                terminal_status="cancelled",
                message="cancelled before dispatch",
                process_status="not_started",
            )
        elif _canonical_task_status(trigger.status) in {"dispatching", "running"}:
            local_process = self._local_cli_process(latest_execution.id) if latest_execution is not None else None
            orphaned_resolution = self._orphaned_control_request_resolution(
                trigger=trigger,
                execution=latest_execution,
                local_process=local_process,
            )
            if orphaned_resolution is not None:
                self._finalize_orphaned_control_request(
                    db,
                    trigger=trigger,
                    execution=latest_execution,
                    resolution=orphaned_resolution,
                )
            else:
                trigger.status = "running"
                trigger.message = "cancel requested"
                trigger.latest_abnormal_reason_json = None
                if latest_execution is not None and self._has_active_execution_runtime(execution=latest_execution, local_process=local_process):
                    latest_execution.status = "running"
                    latest_execution.message = "cancel requested"
                    latest_execution.process_status = "stop_requested"
                    self._sync_runtime_state_snapshots(
                        trigger=trigger,
                        execution=latest_execution,
                        public_status="running",
                        control_state="cancel_requested",
                    )
                    db.add(latest_execution)
                else:
                    self._sync_runtime_state_snapshots(
                        trigger=trigger,
                        execution=latest_execution,
                        public_status="running",
                        control_state="cancel_requested",
                    )
        else:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task is not cancelable")
        db.add(trigger)
        db.commit()
        self._record_task_mutation_event(
            db,
            event_type="task_cancel_requested",
            message="task cancel requested",
            trigger=trigger,
            execution=latest_execution,
            payload_json={
                "task_id": trigger.id,
                "execution_id": latest_execution.id if latest_execution is not None else None,
                "signal_process": bool(signal_process),
                "worker_job_id": worker_bound_execution.worker_job_id if worker_bound_execution is not None else None,
                "worker_url": worker_bound_execution.worker_url if worker_bound_execution is not None else None,
                "status_before": status_before,
            },
        )
        if signal_process and latest_execution is not None:
            self._write_run_control_state(latest_execution.workspace_root, status_text=trigger.status, message=trigger.message or "cancel requested")
            if worker_bound_execution is not None:
                stop_payload = self._cancel_worker_job(latest_execution)
                self._record_worker_control_result(
                    db,
                    execution=latest_execution,
                    action="cancel",
                    payload=stop_payload,
                )
            elif self._has_active_execution_runtime(execution=latest_execution):
                self._signal_local_cli_process(latest_execution.id, wait=False)
        db.refresh(trigger)
        return self._scan_task_response(db, trigger)

    def delete_scan_task(self, db: Session, task_id: str, principal: dict) -> dict[str, Any]:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        if is_canonical_task_active(trigger.status):
            latest_execution = self._latest_execution_for_trigger(db, trigger.id)
            orphaned_resolution = self._orphaned_control_request_resolution(
                trigger=trigger,
                execution=latest_execution,
            )
            if orphaned_resolution is None:
                try:
                    self.cancel_scan_task(db, task_id, principal)
                    trigger = self._trigger_or_404(db, task_id)
                except Exception:
                    db.rollback()
                    trigger = self._trigger_or_404(db, task_id)
            else:
                self._finalize_orphaned_control_request(
                    db,
                    trigger=trigger,
                    execution=latest_execution,
                    resolution={
                        **orphaned_resolution,
                        "message": "deleted after dispatch requeue",
                        "event_type": "task_delete_reconciled",
                        "resolution_reason": "dispatch_requeued_no_active_worker_delete_requested",
                    },
                )
                db.commit()

        executions = self._list_executions_for_trigger(db, trigger.id)
        run_index_ids: set[str] = set()
        workspace_roots: set[str] = set()
        for execution in executions:
            if execution.workspace_root:
                workspace_roots.add(execution.workspace_root)
            run_index = get_run_index_service().get_run_index_by_execution(db, execution) if execution.workspace_root else None
            if run_index:
                run_index_ids.add(run_index.id)
                if run_index.run_root_path:
                    workspace_roots.add(run_index.run_root_path)

        if run_index_ids:
            db.query(RunIndexFile).filter(RunIndexFile.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexSession).filter(RunIndexSession.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexRemovedResult).filter(RunIndexRemovedResult.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexResultReview).filter(RunIndexResultReview.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexResult).filter(RunIndexResult.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexGlobalReview).filter(RunIndexGlobalReview.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexCycle).filter(RunIndexCycle.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndex).filter(RunIndex.id.in_(list(run_index_ids))).delete(synchronize_session=False)

        self._delete_linked_runtime_records(db, linked_task_id=trigger.id, linked_execution_id=None)
        db.commit()
        self._log_task_mutation(
            action="task_deleted",
            principal=principal,
            task_id=trigger.id,
            project_id=trigger.project_id,
            execution_count=len(executions),
            run_index_count=len(run_index_ids),
        )

        for path in workspace_roots:
            if path:
                shutil.rmtree(path, ignore_errors=True)
        return {"success": True, "message": "task deleted"}

    def update_scan_task_priority(self, db: Session, task_id: str, principal: dict, priority: int) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        if trigger.status in {"succeeded", "failed", "cancelled"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="finished task priority cannot be updated")
        old_priority = trigger.priority
        trigger.priority = priority
        trigger.message = f"priority updated to {priority}"
        db.add(trigger)
        self._refresh_task_list_projection_for_task_id(db, trigger.id)
        db.commit()
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        self._record_task_mutation_event(
            db,
            event_type="task_priority_updated",
            message="task priority updated",
            trigger=trigger,
            execution=latest_execution,
            payload_json={
                "task_id": trigger.id,
                "old_priority": old_priority,
                "new_priority": priority,
            },
        )
        db.refresh(trigger)
        return self._scan_task_response(db, trigger)

    def record_event(
        self,
        db: Session,
        *,
        execution_id: str,
        event_type: str,
        message: str,
        stage_id: str | None = None,
        round_no: int | None = None,
        level: str = "info",
        payload_json: dict[str, Any] | None = None,
    ) -> WorkflowExecutionEvent:
        safe_payload = jsonable_encoder(payload_json or {})
        event = WorkflowExecutionEvent(
            id=_new_id("evt"),
            execution_id=execution_id,
            event_type=event_type,
            stage_id=stage_id,
            round_no=round_no,
            level=level,
            message=message,
            payload_json=safe_payload,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    def _invoke_run_vuln_scan_cli(
        self,
        *,
        argv: list[str],
        db: Session,
        execution: WorkflowExecution,
        trigger: TriggerTask,
    ) -> int:
        if os.environ.get("SECFLOW_DATAFLOW_CLI_IN_PROCESS") == "1":
            now = now_local()
            execution.status = "running"
            execution.started_at = now
            execution.process_pid = os.getpid()
            execution.process_host = get_config().scheduler.pod_id
            execution.process_status = "running"
            execution.process_started_at = now
            execution.process_finished_at = None
            execution.dispatch_status = "running"
            trigger.status = "running"
            trigger.message = "run_vuln_scan.py running"
            self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="running", control_state="none")
            db.add(execution)
            db.add(trigger)
            self._refresh_task_list_projection_for_execution(db, execution)
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="run_vuln_scan_process_started",
                message=f"run_vuln_scan.py in-process started pid={os.getpid()}",
                payload_json={
                    "pid": os.getpid(),
                    "pod_id": get_config().scheduler.pod_id,
                    "host_name": get_config().scheduler.host_name,
                    "in_process": True,
                },
            )
            import run_vuln_scan

            try:
                run_vuln_scan.main(argv)
                return 0
            except SystemExit as exc:
                code = exc.code
                if code is None:
                    return 0
                if isinstance(code, int):
                    return code
                return 1

        script_path = Path(__file__).resolve().parents[2] / "run_vuln_scan.py"
        cmd = [sys.executable, str(script_path), *argv]
        process = subprocess.Popen(cmd, cwd=str(script_path.parent))
        self._register_cli_process(execution.id, process)
        now = now_local()
        execution.status = "running"
        execution.started_at = now
        execution.process_pid = int(process.pid)
        execution.process_host = get_config().scheduler.pod_id
        execution.process_status = "running"
        execution.process_started_at = now
        execution.process_finished_at = None
        execution.dispatch_status = "running"
        trigger.status = "running"
        trigger.message = "run_vuln_scan.py running"
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="running", control_state="none")
        db.add(execution)
        db.add(trigger)
        self._refresh_task_list_projection_for_execution(db, execution)
        db.commit()
        self._try_write_cli_process_file(
            execution=execution,
            trigger=trigger,
            cmd=cmd,
            process=process,
            status_text="running",
        )
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="run_vuln_scan_process_started",
            message=f"run_vuln_scan.py process started pid={process.pid}",
            payload_json={
                "pid": process.pid,
                "pod_id": get_config().scheduler.pod_id,
                "host_name": get_config().scheduler.host_name,
                "command": cmd,
            },
        )
        try:
            while process.poll() is None:
                time.sleep(max(1, int(get_config().service.execution_cancel_check_interval_seconds)))
                self._try_write_cli_process_file(
                    execution=execution,
                    trigger=trigger,
                    cmd=cmd,
                    process=process,
                    status_text="running",
                )
                db.expire(execution)
                db.expire(trigger)
                if str(execution.process_status or "").strip().lower() in {"stop_requested", "delete_requested"}:
                    db.add(execution)
                    db.commit()
                    self._try_write_cli_process_file(
                        execution=execution,
                        trigger=trigger,
                        cmd=cmd,
                        process=process,
                        status_text=execution.process_status,
                    )
                    try:
                        process.send_signal(signal.SIGINT)
                    except ProcessLookupError:
                        return int(process.returncode or 0)
                    try:
                        return process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            return process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            return process.wait()
            return int(process.returncode or 0)
        finally:
            if process.poll() is None:
                process.terminate()
            self._forget_cli_process(execution.id, process)
            try:
                execution.process_status = "exited"
                execution.process_finished_at = now_local()
                db.add(execution)
                db.commit()
                self._try_write_cli_process_file(
                    execution=execution,
                    trigger=trigger,
                    cmd=cmd,
                    process=process,
                    status_text="exited",
                    return_code=process.returncode,
                )
            except Exception:
                db.rollback()

    def _run_claimed_dataflow_cli_execution(
        self,
        *,
        db: Session,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        definition: WorkflowDefinition,
        version: WorkflowDefinitionVersion,
        metadata: dict[str, Any],
    ) -> None:
        launcher_mode = "run_vuln_scan_cli"
        request = metadata.get("dataflow_scan_request")
        plan = metadata.get("dataflow_cli")
        if not isinstance(request, dict) or not isinstance(plan, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow CLI task metadata is incomplete")
        run_dir = Path(plan["run_dir"])
        self._write_dataflow_cli_task_preview(plan)
        execution.workspace_root = abs_path(run_dir)
        if str(execution.status or "").strip().lower() not in {"starting", "dispatching"}:
            execution.status = "starting"
        execution.message = "run_vuln_scan.py starting"
        if execution.started_at is None:
            execution.started_at = now_local()
        if trigger.started_at is None:
            trigger.started_at = execution.started_at
        trigger.status = "dispatching"
        trigger.message = "run_vuln_scan.py starting"
        execution.dispatch_status = "starting"
        execution.process_status = "not_started"
        self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="dispatching", control_state="none")
        db.add(execution)
        db.add(trigger)
        self._refresh_task_list_projection_for_task_id(db, trigger.id)
        db.commit()

        runtime_overrides = dict(metadata.get("runtime_overrides") or {})
        config_payload = version.config_payload_json or definition.config_payload_json or {}
        compiled_config = version.compiled_config_json or version.definition_json or definition.definition_json
        agent_state_dirs = self._agent_state_dirs_from_metadata(
            project_id=trigger.project_id,
            compiled_config=compiled_config,
            metadata=metadata,
        )
        self._ensure_agent_state_dirs(agent_state_dirs)
        temp_config_path: str | None = None
        argv: list[str] = []
        try:
            argv, temp_config_path = self._build_dataflow_cli_argv(
                plan=plan,
                config_payload=config_payload,
                request=request,
                compiled_config=compiled_config,
                runtime_overrides=runtime_overrides,
                agent_state_dirs=agent_state_dirs,
            )
            command = [sys.executable, str(Path(__file__).resolve().parents[2] / "run_vuln_scan.py"), *argv]
            metadata["dataflow_cli"] = {
                **plan,
                "agent_state_dirs": agent_state_dirs,
                "argv": argv,
                "command": command,
                "command_display": _command_display(command),
                "launch_mode": launcher_mode,
            }
            self._update_trigger_cli_task(trigger=trigger, metadata=metadata, task_md_path=plan["task_md_path"])
            db.add(trigger)
            db.commit()
            get_run_index_service().sync_execution_run(db, execution)
            self._refresh_task_list_projection_for_execution(db, execution)
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_started",
                message="run_vuln_scan.py launch requested",
                payload_json={
                    "workspace_root": abs_path(run_dir),
                    "owner_pod_id": execution.owner_pod_id,
                    "launch_mode": launcher_mode,
                    "command": command,
                    "command_display": _command_display(command),
                    "run_name": plan["run_name"],
                    "runs_root": plan["runs_root"],
                },
            )
            invoke_kwargs: dict[str, Any] = {
                "argv": argv,
                "db": db,
                "execution": execution,
                "trigger": trigger,
            }
            exit_code = self._invoke_run_vuln_scan_cli(**invoke_kwargs)
            db.refresh(execution)
            db.refresh(trigger)
            run_index = get_run_index_service().sync_execution_run(db, execution)
            self._refresh_task_list_projection_for_execution(db, execution)
            output_summary = run_dir / "output" / "execution_summary.json"
            output_manifest = run_dir / "output" / "tasks.json"
            output_manifest_path = output_manifest if output_manifest.is_file() else output_summary if output_summary.is_file() else None
            if exit_code == 0:
                terminal_status = "succeeded"
                message = "run_vuln_scan.py completed"
            elif (
                exit_code in {130, -signal.SIGINT, -signal.SIGTERM, -signal.SIGKILL}
                or str(execution.process_status or "").strip().lower() in {"stop_requested", "delete_requested"}
            ):
                terminal_status = "cancelled"
                message = "run_vuln_scan.py stopped for delete" if str(execution.process_status or "").strip().lower() == "delete_requested" else "run_vuln_scan.py cancelled"
            elif exit_code == 124:
                terminal_status = "failed"
                message = "run_vuln_scan.py exited with timeout code 124"
            else:
                terminal_status = "failed"
                message = f"run_vuln_scan.py failed with exit code {exit_code}"
            self._set_terminal_state(
                db,
                execution=execution,
                trigger=trigger,
                execution_status=terminal_status,
                message=message,
                output_manifest_path=abs_path(output_manifest_path) if output_manifest_path else None,
                output_task_count=int(run_index.result_count if run_index else 0),
            )
            db.commit()
            get_run_index_service().sync_execution_run(db, execution)
            self._refresh_task_list_projection_for_execution(db, execution)
            db.commit()
            report_status = {}
            if terminal_status == "succeeded":
                try:
                    run_index = get_run_index_service().get_run_index_by_execution(db, execution)
                    report_status = get_vuln_report_service().report_execution_results(
                        db,
                        trigger=trigger,
                        execution=execution,
                        run_index=run_index,
                    )
                except Exception as exc:
                    db.rollback()
                    report_status = {"status": "failed", "enabled": True, "error": str(exc)}
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type="vuln_report_finished",
                    message=f"vulnerability suspicion auto-report {report_status.get('status', 'unknown')}",
                    level="warning" if report_status.get("status") in {"failed", "partial_failed"} else "info",
                    payload_json=report_status,
                )
            event_type = "execution_finished"
            if terminal_status == "cancelled":
                event_type = "execution_cancelled"
            elif terminal_status != "succeeded":
                event_type = "execution_failed"
            self.record_event(
                db,
                execution_id=execution.id,
                event_type=event_type,
                message=message,
                level="info" if terminal_status == "succeeded" else "warning",
                payload_json={
                    "status": execution.status,
                    "exit_code": exit_code,
                    "launch_mode": launcher_mode,
                    "run_dir": abs_path(run_dir),
                    "output_manifest_path": execution.output_manifest_path,
                    "output_task_count": execution.output_task_count,
                    "vuln_report_status": report_status,
                },
            )
        finally:
            if temp_config_path:
                try:
                    Path(temp_config_path).unlink(missing_ok=True)
                except OSError:
                    pass

    def run_claimed_execution(self, execution_id: str) -> None:
        db = get_db_session()
        execution: WorkflowExecution | None = None
        trigger: TriggerTask | None = None
        launcher_mode = "rest_service"
        try:
            execution = self._execution_or_404(db, execution_id)
            trigger = self._trigger_or_404(db, execution.trigger_task_id)
            definition = self._definition_or_404(db, execution.workflow_definition_id)
            version = self._definition_version_or_404(db, execution.workflow_definition_version_id or trigger.workflow_definition_version_id)
            service_manifest = TaskManifest.model_validate(trigger.input_tasks_json)
            task_metadata = dict(service_manifest.tasks[0].metadata or {}) if service_manifest.tasks else {}
            if self._is_dataflow_cli_task_metadata(task_metadata):
                self._run_claimed_dataflow_cli_execution(
                    db=db,
                    execution=execution,
                    trigger=trigger,
                    definition=definition,
                    version=version,
                    metadata=task_metadata,
                )
                return
            compiled_config = version.compiled_config_json or version.definition_json or definition.definition_json
            agent_state_dirs = self._agent_state_dirs_from_metadata(
                project_id=trigger.project_id,
                compiled_config=compiled_config,
                metadata=task_metadata,
            )
            self._ensure_agent_state_dirs(agent_state_dirs)
            compiled_config = self._apply_agent_state_dirs_to_compiled_config(
                compiled_config=compiled_config,
                agent_state_dirs=agent_state_dirs,
            )
            workspace_root = Path(execution.workspace_root) if execution.workspace_root else self._build_workspace_root(execution.id, definition)
            input_manifest_path = workspace_root / "input" / "tasks.json"
            if not input_manifest_path.exists():
                input_manifest_path = write_task_manifest(input_manifest_path, TaskManifest.model_validate(trigger.input_tasks_json).tasks)

            execution.workspace_root = abs_path(workspace_root)
            execution.status = "running"
            execution.message = "execution running"
            if execution.started_at is None:
                execution.started_at = now_local()
            if trigger.started_at is None:
                trigger.started_at = execution.started_at
            trigger.status = "running"
            trigger.message = "execution running"
            self._sync_runtime_state_snapshots(trigger=trigger, execution=execution, public_status="running", control_state="none")
            db.add(execution)
            db.add(trigger)
            self._refresh_task_list_projection_for_task_id(db, trigger.id)
            db.commit()
            custom_workspace_root, custom_output_dir = self._resolve_custom_execution_paths(
                project_id=definition.project_id,
                metadata=task_metadata,
                execution_id=execution.id,
            )
            if custom_workspace_root is not None:
                workspace_root = custom_workspace_root
                execution.workspace_root = abs_path(workspace_root)
                db.add(execution)
                db.commit()
            single_task_entry_file = self._prepare_single_task_entry_file(
                workspace_root=workspace_root,
                manifest=service_manifest,
            )
            entry_task_file = single_task_entry_file or service_manifest.tasks[0].task_md_path
            launcher_mode = "rest_service_cli" if single_task_entry_file else "rest_service"
            runtime_root = ensure_dir(workspace_root / "run")
            runtime_workspace_root = ensure_dir(runtime_root / "workspace")
            runtime_config = build_runtime_framework_config(
                compiled_config,
                workspace_root=abs_path(runtime_workspace_root),
                execution_id=execution.id,
                input_task_file=entry_task_file,
                input_task_id=service_manifest.tasks[0].task_id,
                output_dir=abs_path(custom_output_dir or (workspace_root / "output")),
                summary_file=abs_path((custom_output_dir or (workspace_root / "output")) / "execution_summary.json"),
                runtime_mode=launcher_mode,
            )
            write_json(runtime_root / "config.json", runtime_config.model_dump(mode="json"))
            write_json(
                runtime_root / "_meta" / "run_timestamps.json",
                {
                    "started_at": isoformat_local(now_local()),
                    "status": "running",
                    "last_mode": launcher_mode,
                    "last_updated_at": isoformat_local(now_local()),
                },
            )
            get_run_index_service().sync_execution_run(db, execution)
            self._refresh_task_list_projection_for_execution(db, execution)
            db.commit()
            log_path = attach_log_file(abs_path(runtime_root / "run.log"))
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_started",
                message="execution claimed and started",
                payload_json={
                    "workspace_root": str(workspace_root),
                    "owner_pod_id": execution.owner_pod_id,
                    "launch_mode": launcher_mode,
                    "entry_task_file": entry_task_file,
                    "log_path": log_path,
                },
            )
            observer = DbExecutionObserver(execution.id)
            recorder = DbExecutionRecorder(abs_path(runtime_workspace_root), execution.id)
            ensure_event_loop_policy()
            try:
                sync_providers_to_pi()
                artifacts = asyncio.run(
                    run_framework_config(
                        runtime_config,
                        initial_tasks=None if single_task_entry_file else build_core_tasks(service_manifest),
                        observer=observer,
                        recorder=recorder,
                    )
                )
            finally:
                detach_log_file()
            output_manifest_path = write_final_task_manifest(
                workspace_root=workspace_root,
                final_tasks=artifacts.result.final_tasks,
                final_output_task_type=runtime_config.resolve_final_output_task_type(),
            )

            db.refresh(execution)
            db.refresh(trigger)
            self._set_terminal_state(
                db,
                execution=execution,
                trigger=trigger,
                execution_status="succeeded" if artifacts.result.success else "failed",
                message="execution completed" if artifacts.result.success else (artifacts.result.error or "execution failed"),
                output_manifest_path=abs_path(output_manifest_path),
                output_task_count=len(artifacts.result.final_tasks),
            )
            db.commit()
            write_json(
                workspace_root / "run" / "_meta" / "run_timestamps.json",
                {
                    "started_at": isoformat_local(execution.started_at or trigger.started_at or now_local()),
                    "finished_at": isoformat_local(now_local()),
                    "status": execution.status,
                    "exit_code": 0 if artifacts.result.success else 1,
                    "last_mode": launcher_mode,
                    "last_updated_at": isoformat_local(now_local()),
                },
            )
            get_run_index_service().sync_execution_run(db, execution)
            self._refresh_task_list_projection_for_execution(db, execution)
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_finished",
                message="execution finished",
                payload_json={
                    "status": execution.status,
                    "output_manifest_path": execution.output_manifest_path,
                    "output_task_count": execution.output_task_count,
                    "launch_mode": launcher_mode,
                },
            )
        except Exception as exc:
            from app.pi_vuln_core.observer import ExecutionCancelledError

            if isinstance(exc, ExecutionCancelledError):
                if execution is None or trigger is None:
                    return
                db.refresh(execution)
                db.refresh(trigger)
                self._set_terminal_state(db, execution=execution, trigger=trigger, execution_status="cancelled", message=str(exc))
                db.commit()
                workspace_root = Path(execution.workspace_root) if execution.workspace_root else None
                if workspace_root:
                    write_json(
                        workspace_root / "run" / "_meta" / "run_timestamps.json",
                        {
                            "started_at": isoformat_local(execution.started_at or trigger.started_at or now_local()),
                            "finished_at": isoformat_local(now_local()),
                            "status": "cancelled",
                            "exit_code": 130,
                            "last_mode": launcher_mode,
                            "last_updated_at": isoformat_local(now_local()),
                        },
                    )
                    get_run_index_service().sync_execution_run(db, execution)
                    self._refresh_task_list_projection_for_execution(db, execution)
                    db.commit()
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type="execution_cancelled",
                    message=str(exc),
                    level="warning",
                )
                return
            if execution is None or trigger is None:
                raise
            db.refresh(execution)
            db.refresh(trigger)
            self._set_terminal_state(db, execution=execution, trigger=trigger, execution_status="failed", message=str(exc))
            db.commit()
            workspace_root = Path(execution.workspace_root) if execution.workspace_root else None
            if workspace_root:
                write_json(
                    workspace_root / "run" / "_meta" / "run_timestamps.json",
                    {
                        "started_at": isoformat_local(execution.started_at or trigger.started_at or now_local()),
                        "finished_at": isoformat_local(now_local()),
                        "status": "failed",
                        "exit_code": 1,
                        "last_mode": launcher_mode,
                        "last_updated_at": isoformat_local(now_local()),
                    },
                )
                get_run_index_service().sync_execution_run(db, execution)
                self._refresh_task_list_projection_for_execution(db, execution)
                db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_failed",
                message=str(exc),
                level="error",
            )
            raise
        finally:
            db.close()


_execution_service: ExecutionService | None = None


def get_execution_service() -> ExecutionService:
    global _execution_service
    if _execution_service is None:
        _execution_service = ExecutionService()
    return _execution_service
