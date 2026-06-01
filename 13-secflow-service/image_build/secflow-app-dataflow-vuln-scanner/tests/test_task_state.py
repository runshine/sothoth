from __future__ import annotations

from datetime import datetime

from app.services.task_state import (
    derive_task_control_state,
    is_canonical_task_active,
    normalize_canonical_task_status,
    normalize_public_task_status,
    public_task_status_matches_filter,
    resolve_public_task_state,
)


def test_normalize_public_task_status_maps_run_failure_states() -> None:
    assert normalize_public_task_status("review_error") == "failed"
    assert normalize_public_task_status("runtime_timeout") == "failed"
    assert normalize_public_task_status("blocked_quota") == "failed"


def test_normalize_public_task_status_maps_queue_and_progress_states() -> None:
    assert normalize_public_task_status("queued") == "dispatching"
    assert normalize_public_task_status("dispatching") == "dispatching"
    assert normalize_public_task_status("created") == "running"
    assert normalize_public_task_status("global_review") == "running"


def test_normalize_canonical_task_status_preserves_internal_shape() -> None:
    assert normalize_canonical_task_status("success") == "succeeded"
    assert normalize_canonical_task_status("dispatching") == "dispatching"
    assert normalize_canonical_task_status("review_error") == "failed"


def test_is_canonical_task_active_includes_dispatching() -> None:
    assert is_canonical_task_active("pending")
    assert is_canonical_task_active("dispatching")
    assert is_canonical_task_active("running")
    assert not is_canonical_task_active("failed")


def test_resolve_public_task_state_prefers_terminal_run_state() -> None:
    resolved = resolve_public_task_state(
        trigger_status="pending",
        trigger_message="pending",
        trigger_started_at=None,
        trigger_finished_at=None,
        execution_status="pending",
        execution_message="queued",
        execution_started_at=None,
        execution_finished_at=None,
        dispatch_status="queued",
        preferred_error_message="runtime timeout",
        run_status="runtime_timeout",
        run_message="runtime timeout",
    )
    assert resolved.status == "failed"
    assert resolved.message == "runtime timeout"
    assert resolved.source == "run"


def test_resolve_public_task_state_returns_dispatching_for_queued_dispatch() -> None:
    started_at = datetime(2026, 1, 1, 0, 0, 0)
    resolved = resolve_public_task_state(
        trigger_status="pending",
        trigger_message="pending",
        trigger_started_at=started_at,
        trigger_finished_at=None,
        execution_status="pending",
        execution_message="queued on worker pod-a",
        execution_started_at=started_at,
        execution_finished_at=None,
        dispatch_status="queued",
        preferred_error_message=None,
        run_status="",
        run_message=None,
    )
    assert resolved.status == "dispatching"
    assert resolved.started_at == started_at


def test_resolve_public_task_state_prefers_completed_run_over_stale_runtime_failure() -> None:
    run_started_at = datetime(2026, 1, 1, 0, 0, 0)
    run_finished_at = datetime(2026, 1, 1, 0, 10, 0)
    resolved = resolve_public_task_state(
        trigger_status="failed",
        trigger_message="stale active runtime assumed failed",
        trigger_started_at=run_started_at,
        trigger_finished_at=run_finished_at,
        execution_status="failed",
        execution_message="stale active runtime assumed failed",
        execution_started_at=run_started_at,
        execution_finished_at=run_finished_at,
        dispatch_status="failed",
        preferred_error_message="stale active runtime assumed failed",
        run_status="completed",
        run_message=None,
        run_started_at=run_started_at,
        run_finished_at=run_finished_at,
    )
    assert resolved.status == "success"
    assert resolved.source == "run_reconciled_success"
    assert resolved.finished_at == run_finished_at


def test_resolve_public_task_state_prefers_terminal_trigger_over_stale_running_message() -> None:
    finished_at = datetime(2026, 1, 1, 0, 10, 0)
    resolved = resolve_public_task_state(
        trigger_status="failed",
        trigger_message="run_vuln_scan.py running",
        trigger_started_at=datetime(2026, 1, 1, 0, 0, 0),
        trigger_finished_at=finished_at,
        execution_status="failed",
        execution_message="run_vuln_scan.py running",
        execution_started_at=datetime(2026, 1, 1, 0, 0, 0),
        execution_finished_at=finished_at,
        dispatch_status="failed",
        preferred_error_message="stale active runtime assumed failed",
        run_status="failed",
        run_message="stale active runtime assumed failed",
        run_started_at=datetime(2026, 1, 1, 0, 0, 0),
        run_finished_at=finished_at,
    )
    assert resolved.status == "failed"
    assert resolved.source == "trigger"


def test_public_task_status_matches_filter_uses_public_status() -> None:
    assert public_task_status_matches_filter("review_error", "failed")
    assert public_task_status_matches_filter("queued", "dispatching")
    assert not public_task_status_matches_filter("pending", "dispatching")


def test_derive_task_control_state_prefers_delete_request() -> None:
    assert derive_task_control_state(dispatch_status="delete_requested") == "delete_requested"
    assert derive_task_control_state(process_status="delete_requested") == "delete_requested"


def test_derive_task_control_state_detects_cancel_request() -> None:
    assert derive_task_control_state(dispatch_status="cancel_requested") == "cancel_requested"
    assert derive_task_control_state(process_status="stop_requested") == "cancel_requested"
    assert derive_task_control_state(trigger_message="cancel requested") == "cancel_requested"
