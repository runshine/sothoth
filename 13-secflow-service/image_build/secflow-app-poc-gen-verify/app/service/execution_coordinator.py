"""Execution-coordination primitives: CAS claim/commit for Celery workers.

Simplified for run-ONCE semantics: no lease, no heartbeat, no re-claim.
- `claim_specific_task`: only claims pending tasks. Running → None (no re-claim).
- `begin_execution_if_owner`: CAS pending→running.
- `commit_terminal_state_if_owner`: CAS running→terminal, clears owner.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from app.db.models import AppPocTask
from app.time_utils import now_local


@dataclass
class ClaimedTask:
    task_id: str
    epoch: int
    control_version: int
    dispatch_status: Optional[str] = None


def claim_specific_task(db: Session, owner_id: str, task_id: str) -> ClaimedTask | None:
    """Claim a specific task_id. Only claims pending tasks (no re-claim of running).

    Returns ClaimedTask or None (if not pending / already terminal / already running).
    """
    candidate = (
        db.query(AppPocTask)
        .filter(
            AppPocTask.task_id == task_id,
            AppPocTask.is_deleted.is_(False),
        )
        .first()
    )
    if candidate is None:
        return None
    status = str(candidate.status or "pending")
    if status != "pending":
        return None  # running or terminal → skip (no re-claim)
    new_epoch = int(candidate.execution_epoch or 0) + 1
    now = now_local()
    updated = (
        db.query(AppPocTask)
        .filter(
            AppPocTask.id == candidate.id,
            AppPocTask.is_deleted.is_(False),
            AppPocTask.status == "pending",
        )
        .update(
            {
                AppPocTask.execution_owner_id: owner_id,
                AppPocTask.execution_lease_until: None,
                AppPocTask.execution_heartbeat_at: now,
                AppPocTask.execution_epoch: new_epoch,
                AppPocTask.dispatch_status: "leased",
                AppPocTask.started_at: now,
                AppPocTask.finished_at: None,
                AppPocTask.error: None,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    if not updated:
        return None
    return ClaimedTask(
        task_id=str(candidate.task_id),
        epoch=new_epoch,
        control_version=int(candidate.control_version or 0),
        dispatch_status="leased",
    )


def still_owner(db: Session, task_id: str, owner_id: str, epoch: int, control_version: int) -> bool:
    """Check if this worker still owns the task (no lease expiry — just ownership)."""
    row = (
        db.query(AppPocTask)
        .filter(
            AppPocTask.task_id == task_id,
            AppPocTask.is_deleted.is_(False),
        )
        .first()
    )
    if row is None:
        return False
    return (
        row.execution_owner_id == owner_id
        and int(row.execution_epoch or 0) == int(epoch)
        and int(row.control_version or 0) == int(control_version)
        and row.status in {"pending", "running"}
    )


def begin_execution_if_owner(
    db: Session, task_id: str, owner_id: str, epoch: int, control_version: int, *, started_at
) -> bool:
    updated = (
        db.query(AppPocTask)
        .filter(
            AppPocTask.task_id == task_id,
            AppPocTask.execution_owner_id == owner_id,
            AppPocTask.execution_epoch == epoch,
            AppPocTask.control_version == control_version,
            AppPocTask.is_deleted.is_(False),
            AppPocTask.status.in_(["pending", "running"]),
        )
        .update(
            {
                AppPocTask.status: "running",
                AppPocTask.dispatch_status: "running",
                AppPocTask.started_at: started_at,
                AppPocTask.finished_at: None,
                AppPocTask.error: None,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def commit_terminal_state_if_owner(
    db: Session,
    task_id: str,
    owner_id: str,
    epoch: int,
    control_version: int,
    *,
    status: str,
    finished_at,
    returncode: Optional[int],
    artifacts_json,
    stages_json: dict,
    result_json: dict | None,
    error: str | None,
    entry_function: Optional[str] = None,
) -> bool:
    values = {
        AppPocTask.status: status,
        AppPocTask.finished_at: finished_at,
        AppPocTask.returncode: returncode,
        AppPocTask.artifacts_json: artifacts_json,
        AppPocTask.stages_json: stages_json,
        AppPocTask.result_json: result_json,
        AppPocTask.error: error,
        AppPocTask.execution_owner_id: None,
        AppPocTask.execution_lease_until: None,
        AppPocTask.execution_heartbeat_at: None,
        AppPocTask.dispatch_status: None,
    }
    if entry_function:
        values[AppPocTask.entry_function] = entry_function
    updated = (
        db.query(AppPocTask)
        .filter(
            AppPocTask.task_id == task_id,
            AppPocTask.execution_owner_id == owner_id,
            AppPocTask.execution_epoch == epoch,
            AppPocTask.control_version == control_version,
            AppPocTask.is_deleted.is_(False),
            AppPocTask.status == "running",
        )
        .update(
            values,
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)
