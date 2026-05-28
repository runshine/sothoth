from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.services.run_state import (
    RUN_CONTROL_REQUEST_STATES,
    RUN_QUEUE_STATES,
    RUN_TERMINAL_STATES,
    RUN_WORKFLOW_PROGRESS_STATES,
    normalize_run_status,
)

PUBLIC_TASK_STATUSES = {
    "pending",
    "dispatching",
    "running",
    "success",
    "failed",
    "cancelled",
}

PUBLIC_TASK_TERMINAL_STATUSES = {"success", "failed", "cancelled"}
CANONICAL_ACTIVE_TASK_STATUSES = {"pending", "dispatching", "running"}
TASK_CONTROL_STATES = {"none", "cancel_requested", "delete_requested"}

_RUN_FAILURE_STATUSES = {
    "failed",
    "error",
    "failure",
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
    "no_workspace",
}

_RUN_CANCELLED_STATUSES = {"cancelled", "canceled", "interrupted", "stopped", "deleted"}
_RUN_SUCCESS_STATUSES = {"success", "succeeded", "completed", "passed"}
_DISPATCH_ACTIVE_STATUSES = {"queued", "dispatching", "accepted"}
_RUNNING_ALIASES = {"running", "processing", "in_progress", "started"}
_PENDING_ALIASES = {"pending", "ready", "ready_to_start", "not_started", "unassigned"}
_RUNTIME_RECONCILED_FAILURE_MESSAGES = {
    "stale active runtime assumed failed",
    "runtime heartbeat lost; assumed failed",
}


@dataclass(frozen=True)
class ResolvedPublicTaskState:
    status: str
    message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    source: str


def normalize_public_task_status(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "pending"

    normalized_run = normalize_run_status(text)
    if normalized_run in _RUN_SUCCESS_STATUSES:
        return "success"
    if normalized_run in _RUN_CANCELLED_STATUSES:
        return "cancelled"
    if normalized_run in _RUN_FAILURE_STATUSES:
        return "failed"
    if normalized_run in _DISPATCH_ACTIVE_STATUSES:
        return "dispatching"
    if normalized_run in RUN_CONTROL_REQUEST_STATES:
        return "running"
    if normalized_run in RUN_WORKFLOW_PROGRESS_STATES or normalized_run in _RUNNING_ALIASES:
        return "running"
    if normalized_run in RUN_QUEUE_STATES:
        return "dispatching" if normalized_run != "pending" else "pending"
    if normalized_run in RUN_TERMINAL_STATES:
        return "failed"
    if normalized_run in _PENDING_ALIASES:
        return "pending"
    return "pending"


def normalize_canonical_task_status(value: str | None) -> str:
    public_status = normalize_public_task_status(value)
    if public_status == "success":
        return "succeeded"
    return public_status


def is_public_task_terminal(status: str | None) -> bool:
    return normalize_public_task_status(status) in PUBLIC_TASK_TERMINAL_STATUSES


def is_canonical_task_active(status: str | None) -> bool:
    return normalize_canonical_task_status(status) in CANONICAL_ACTIVE_TASK_STATUSES


def derive_task_control_state(
    *,
    dispatch_status: str | None = None,
    process_status: str | None = None,
    trigger_message: str | None = None,
    execution_message: str | None = None,
) -> str:
    for candidate in (
        str(dispatch_status or "").strip().lower(),
        str(process_status or "").strip().lower(),
    ):
        if candidate == "delete_requested":
            return "delete_requested"
        if candidate in {"cancel_requested", "stop_requested"}:
            return "cancel_requested"

    merged_message = " ".join(
        part.strip().lower()
        for part in (trigger_message or "", execution_message or "")
        if str(part or "").strip()
    )
    if "delete requested" in merged_message:
        return "delete_requested"
    if "cancel requested" in merged_message:
        return "cancel_requested"
    return "none"


def public_task_status_matches_filter(status: str | None, status_filter: str | None) -> bool:
    normalized_filter = normalize_public_task_status(status_filter)
    if normalized_filter not in PUBLIC_TASK_STATUSES:
        return True
    return normalize_public_task_status(status) == normalized_filter


def _is_runtime_reconciled_failure_message(message: str | None) -> bool:
    return str(message or "").strip().lower() in _RUNTIME_RECONCILED_FAILURE_MESSAGES


def resolve_public_task_state(
    *,
    trigger_status: str | None,
    trigger_message: str | None,
    trigger_started_at: datetime | None,
    trigger_finished_at: datetime | None,
    execution_status: str | None,
    execution_message: str | None,
    execution_started_at: datetime | None,
    execution_finished_at: datetime | None,
    dispatch_status: str | None,
    preferred_error_message: str | None,
    run_status: str | None,
    run_message: str | None,
    run_started_at: datetime | None = None,
    run_finished_at: datetime | None = None,
) -> ResolvedPublicTaskState:
    trigger_public = normalize_public_task_status(trigger_status)
    execution_public = normalize_public_task_status(execution_status)
    run_public = normalize_public_task_status(run_status)
    dispatch_public = normalize_public_task_status(dispatch_status)
    effective_started_at = execution_started_at or trigger_started_at

    trigger_runtime_reconciled_failure = (
        trigger_public == "failed" and _is_runtime_reconciled_failure_message(trigger_message)
    )
    execution_runtime_reconciled_failure = (
        execution_public == "failed" and _is_runtime_reconciled_failure_message(execution_message)
    )
    if run_public == "success" and (trigger_runtime_reconciled_failure or execution_runtime_reconciled_failure):
        return ResolvedPublicTaskState(
            status="success",
            message=run_message or "run index reconciled to success",
            started_at=run_started_at or effective_started_at,
            finished_at=run_finished_at or execution_finished_at or trigger_finished_at,
            source="run_reconciled_success",
        )

    for source, status, message, started_at, finished_at in (
        ("trigger", trigger_public, trigger_message, trigger_started_at, trigger_finished_at),
        ("execution", execution_public, execution_message, execution_started_at or trigger_started_at, execution_finished_at or trigger_finished_at),
        ("run", run_public, run_message, run_started_at or execution_started_at or trigger_started_at, run_finished_at or execution_finished_at or trigger_finished_at),
    ):
        if status in PUBLIC_TASK_TERMINAL_STATUSES:
            return ResolvedPublicTaskState(
                status=status,
                message=message or preferred_error_message,
                started_at=started_at,
                finished_at=finished_at,
                source=source,
            )

    if str(dispatch_status or "").strip().lower() == "failed":
        return ResolvedPublicTaskState(
            status="failed",
            message=preferred_error_message,
            started_at=effective_started_at,
            finished_at=execution_finished_at or trigger_finished_at,
            source="dispatch",
        )

    if dispatch_public == "dispatching":
        return ResolvedPublicTaskState(
            status="dispatching",
            message=execution_message or trigger_message,
            started_at=effective_started_at,
            finished_at=None,
            source="dispatch",
        )

    if "running" in {trigger_public, execution_public, run_public}:
        return ResolvedPublicTaskState(
            status="running",
            message=execution_message or trigger_message,
            started_at=effective_started_at,
            finished_at=None,
            source="runtime",
        )

    if "dispatching" in {trigger_public, execution_public, run_public}:
        return ResolvedPublicTaskState(
            status="dispatching",
            message=execution_message or trigger_message,
            started_at=effective_started_at,
            finished_at=None,
            source="runtime",
        )

    return ResolvedPublicTaskState(
        status="pending",
        message=execution_message or trigger_message,
        started_at=effective_started_at,
        finished_at=None,
        source="fallback",
    )
