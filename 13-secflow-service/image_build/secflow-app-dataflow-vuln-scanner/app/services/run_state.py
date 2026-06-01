from __future__ import annotations

from typing import Any

RUN_WORKFLOW_PROGRESS_STATES = {
    "created",
    "start_plugins",
    "worker",
    "reflect",
    "summary",
    "global_review",
    "result_review",
    "end_plugins",
    "running",
    "in_progress",
}

RUN_QUEUE_STATES = {
    "pending",
    "queued",
    "dispatching",
    "starting",
}

RUN_CONTROL_REQUEST_STATES = {
    "cancel_requested",
    "delete_requested",
    "stop_requested",
    "timeout_requested",
}

RUN_TERMINAL_STATES = {
    "completed",
    "succeeded",
    "failed",
    "interrupted",
    "cancelled",
    "stopped",
    "deleted",
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
    "error",
}

RUN_GENERIC_TERMINAL_STATES = {"failed", "error"}


def normalize_run_status(raw_status: str | None, run_meta: dict[str, Any] | None = None) -> str:
    run_meta = run_meta or {}
    text = str(raw_status or "").strip().lower()
    meta_status = str(run_meta.get("status") or "").strip().lower()
    if meta_status in RUN_TERMINAL_STATES:
        if meta_status in RUN_GENERIC_TERMINAL_STATES and text in (RUN_TERMINAL_STATES - RUN_GENERIC_TERMINAL_STATES):
            return text
        return meta_status
    if not run_meta.get("finished_at"):
        if meta_status in RUN_WORKFLOW_PROGRESS_STATES:
            return "running"
        if meta_status in RUN_QUEUE_STATES | RUN_CONTROL_REQUEST_STATES:
            return meta_status
    if text in RUN_TERMINAL_STATES:
        return text
    if text in RUN_WORKFLOW_PROGRESS_STATES:
        return "running"
    if text in RUN_QUEUE_STATES | RUN_CONTROL_REQUEST_STATES:
        return text
    return text or "pending"


def is_run_terminal(status: str | None) -> bool:
    return str(status or "").strip().lower() in RUN_TERMINAL_STATES


def is_run_queued(status: str | None) -> bool:
    return str(status or "").strip().lower() in RUN_QUEUE_STATES


def is_run_control_requested(status: str | None) -> bool:
    return str(status or "").strip().lower() in RUN_CONTROL_REQUEST_STATES


def is_run_running(status: str | None) -> bool:
    return normalize_run_status(status) == "running"


def is_run_active(status: str | None) -> bool:
    normalized = normalize_run_status(status)
    return normalized == "running" or is_run_queued(normalized) or is_run_control_requested(normalized)
