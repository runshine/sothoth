"""Execution-coordination primitives: DB-lease CAS claim/commit for Celery workers.

Lifted from dataflow-vuln-scan's execution_coordinator (trimmed: poc-gen-verify has
no parent/binary-security orchestration). DB is the source of truth; these CAS
UPDATEs make a Celery worker the unique owner of a task for one execution epoch.

- `claim_specific_task`: worker claims a specific task_id (non-competitive). Only
  claims pending, or running-with-expired-lease (acks_late re-deliver / orphan).
  Returns ClaimedTask(task_id, epoch, control_version) or None.
- `begin_execution_if_owner`: CAS pending→running, filtered by owner/epoch/cv.
- `commit_terminal_state_if_owner`: CAS running→terminal, clears owner/lease.
- `renew_lease` / `still_owner`: heartbeat + ownership guard.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.db.models import AppPocTask
from app.runtime_context import LEASE_TTL_SECONDS
from app.time_utils import now_local


@dataclass
class ClaimedTask:
    task_id: str
    epoch: int
    control_version: int
    dispatch_status: Optional[str] = None


def _lease_deadline():
    return now_local() + timedelta(seconds=LEASE_TTL_SECONDS)


def claim_specific_task(db: Session, owner_id: str, task_id: str) -> ClaimedTask | None:
    """Celery worker claims a specific task_id (non-competitive, by dispatcher routing).

    Only claims pending (normal) or running-with-expired-lease (acks_late re-deliver /
    orphan). Running with a fresh lease → None (another live worker owns it; this
    message is acked away without execution).
    """
    now = now_local()
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
    if status == "pending":
        expected_status = "pending"
    elif status == "running" and (
        candidate.execution_lease_until is None or candidate.execution_lease_until < now
    ):
        expected_status = "running"  # orphan / lease-expired → re-claim
    else:
        return None  # running+fresh-lease or terminal → skip
    new_epoch = int(candidate.execution_epoch or 0) + 1
    update_fields = {
        AppPocTask.execution_owner_id: owner_id,
        AppPocTask.execution_lease_until: _lease_deadline(),
        AppPocTask.execution_heartbeat_at: now,
        AppPocTask.execution_epoch: new_epoch,
        AppPocTask.dispatch_status: "leased",
        AppPocTask.started_at: now,
        AppPocTask.finished_at: None,
        AppPocTask.error: None,
    }
    if expected_status == "running":
        update_fields[AppPocTask.status] = "pending"  # orphan → back to pending first
    updated = (
        db.query(AppPocTask)
        .filter(
            AppPocTask.id == candidate.id,
            AppPocTask.is_deleted.is_(False),
            AppPocTask.status == expected_status,
            ((AppPocTask.execution_lease_until.is_(None)) | (AppPocTask.execution_lease_until < now))
            if expected_status == "running" else AppPocTask.status.is_not(None),
        )
        .update(update_fields, synchronize_session=False)
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


def renew_lease(db: Session, task_id: str, owner_id: str, epoch: int) -> bool:
    now = now_local()
    updated = (
        db.query(AppPocTask)
        .filter(
            AppPocTask.task_id == task_id,
            AppPocTask.execution_owner_id == owner_id,
            AppPocTask.execution_epoch == epoch,
            AppPocTask.is_deleted.is_(False),
            AppPocTask.status == "running",
        )
        .update(
            {
                AppPocTask.execution_lease_until: _lease_deadline(),
                AppPocTask.execution_heartbeat_at: now,
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def still_owner(db: Session, task_id: str, owner_id: str, epoch: int, control_version: int) -> bool:
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
) -> bool:
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
            {
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
            },
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)
