from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TERMINAL_STATUSES,
)
from app.schemas import BinarySecurityServiceConfigPayload, BinarySecurityServiceConfigResponse
from . import shared as task_shared

if TYPE_CHECKING:
    from app.model import BinarySecurityTask
    from app.service.task_manager import TaskManager


@dataclass
class LeaseClearDecision:
    allowed: bool
    reason_code: str
    lease_state: str
    owner_matches_current_instance: bool
    task_terminal: bool
    task_status: str | None
    runtime_phase: str | None
    active_operation_type: str | None
    active_operation_status: str | None
    runtime_lease_owner: str | None = None
    runtime_lease_expires_at: str | None = None


@dataclass
class TaskLayerReconcileDeliveryDecision:
    delivery_channel: str
    observe_only: bool
    decision_reason: str
    target_owner_instance_id: str | None
    runtime_lease_owner: str | None
    task_status: str | None
    runtime_phase: str | None


@dataclass
class ParentRuntimeOwnershipSnapshot:
    runtime_lease_present: bool
    runtime_lease_active: bool
    runtime_lease_owner: str | None
    runtime_lease_expires_at: str | None
    local_handle_alive: bool
    local_streaming_worker_alive: bool
    runtime_phase: str | None
    transition_guard_active: bool
    supported_control_operation_active: bool
    task_status: str | None
    active_operation_type: str | None
    active_operation_status: str | None
    current_operation_id: str | None


@dataclass
class ParentRuntimeOwnershipGuardDecision:
    preserve: bool
    decision_reason: str
    snapshot: ParentRuntimeOwnershipSnapshot


@dataclass
class DeleteQueueConsumeDecision:
    allowed: bool
    reason_code: str
    blocker_kind: str
    lease_state: str
    task_status: str | None
    runtime_phase: str | None
    runtime_lease_owner: str | None
    runtime_lease_expires_at: str | None
    active_operation_id: str | None
    active_operation_type: str | None
    active_operation_status: str | None


class TaskRuntimeStateServiceMixin:
    _STATE_TRANSITION_GUARD_TTL_SECONDS = 30
    _MAIN_STATE_UNSET = object()

    def _task_layer_reconcile_requires_execution(
        self: TaskManager,
        *,
        source_event_type: str | None,
        reconcile_reason: str | None,
    ) -> bool:
        normalized_source = str(source_event_type or "").strip()
        normalized_reason = str(reconcile_reason or "").strip()
        if normalized_reason == "missing_stage_terminal_recovery":
            return True
        return normalized_source in {
            "stage_worker_terminal_observed",
            "downstream_terminal_observed",
            "task_execution_failed",
            "archive_job_copy_failed",
        }

    def _parent_task_state_snapshot(self: TaskManager, task) -> dict[str, Any]:
        return {
            "status": str(getattr(task, "status", "") or "").strip() or None,
            "current_stage": str(getattr(task, "current_stage", "") or "").strip() or None,
            "runtime_phase": str(getattr(task, "runtime_phase", "") or "").strip() or None,
            "finished_at": task_shared._isoformat_or_none(getattr(task, "finished_at", None)),
            "last_error": str(getattr(task, "last_error", "") or "").strip() or None,
            "current_operation_id": str(getattr(task, "current_operation_id", "") or "").strip() or None,
        }

    def _record_parent_task_state_transition(
        self: TaskManager,
        db: Session,
        task,
        *,
        before_state: dict[str, Any],
        reason: str,
        source: str,
        stage_name: str | None = None,
    ) -> None:
        after_state = self._parent_task_state_snapshot(task)
        changed_fields = [
            field_name
            for field_name in before_state.keys()
            if before_state.get(field_name) != after_state.get(field_name)
        ]
        if not changed_fields:
            return
        self._record_event(
            db,
            task,
            "parent_task_state_transition",
            "父任务主状态已更新",
            level="info",
            stage_name=stage_name or after_state.get("current_stage") or before_state.get("current_stage"),
            payload={
                "source": str(source or "").strip() or None,
                "reason": str(reason or "").strip() or None,
                "changed_fields": changed_fields,
                "before": {key: before_state.get(key) for key in changed_fields},
                "after": {key: after_state.get(key) for key in changed_fields},
            },
        )

    def _task_runtime_transition_guard(self: TaskManager, task) -> dict[str, Any]:
        summary = dict(getattr(task, "summary", None) or {})
        guard = summary.get("runtime_transition_guard")
        return dict(guard) if isinstance(guard, dict) else {}

    def _set_task_runtime_transition_guard(
        self: TaskManager,
        task,
        *,
        from_stage: str | None,
        to_stage: str | None,
        reason: str,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        now_value = task_manager_module._now()
        ttl_seconds = max(5, int(self._STATE_TRANSITION_GUARD_TTL_SECONDS or 30))
        guard = {
            "guard_id": f"rtg_{task_manager_module.uuid.uuid4().hex[:16]}",
            "owner_instance_id": str(self.instance_id or "").strip() or None,
            "from_stage": str(from_stage or "").strip() or None,
            "to_stage": str(to_stage or "").strip() or None,
            "reason": str(reason or "").strip() or None,
            "created_at": task_shared._isoformat_or_none(now_value),
            "expires_at": task_shared._isoformat_or_none(now_value + task_manager_module.timedelta(seconds=ttl_seconds)),
        }
        summary = dict(getattr(task, "summary", None) or {})
        summary["runtime_transition_guard"] = guard
        task.summary = summary
        return guard

    def _clear_task_runtime_transition_guard(self: TaskManager, task) -> None:
        summary = dict(getattr(task, "summary", None) or {})
        if "runtime_transition_guard" not in summary:
            return
        summary.pop("runtime_transition_guard", None)
        task.summary = summary

    def _task_runtime_transition_guard_active(self: TaskManager, task) -> bool:
        guard = self._task_runtime_transition_guard(task)
        expires_at = task_shared._parse_iso_datetime(guard.get("expires_at"))
        if expires_at is None:
            return False
        remaining = task_shared._seconds_until(expires_at)
        return remaining is not None and remaining > 0

    def _task_runtime_transition_guard_owned_by_current_instance(self: TaskManager, task) -> bool:
        if not self._task_runtime_transition_guard_active(task):
            return False
        guard = self._task_runtime_transition_guard(task)
        return str(guard.get("owner_instance_id") or "").strip() == str(self.instance_id or "").strip()

    def _task_runtime_owner_matches_current_instance(
        self: TaskManager,
        db: Session,
        task,
    ) -> bool:
        lease = self._runtime_lease_for_task(db, task.id)
        return bool(
            lease is not None
            and self._runtime_lease_is_active(lease)
            and str(getattr(lease, "owner_instance_id", "") or "").strip() == str(self.instance_id or "").strip()
        )

    def _is_retry_like_operation_type(self: TaskManager, operation_type: str | None) -> bool:
        from app.service import task_manager as task_manager_module

        normalized = str(operation_type or "").strip()
        return normalized in task_manager_module.TASK_OPERATION_REQUEUE_APPLIED_TYPES

    def _parent_runtime_lease_decision_payload(
        self: TaskManager,
        decision: LeaseClearDecision,
        *,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "reason": str(reason or "").strip() or None,
            "reason_code": decision.reason_code,
            "lease_state": decision.lease_state,
            "owner_matches_current_instance": decision.owner_matches_current_instance,
            "task_terminal": decision.task_terminal,
            "task_status": decision.task_status,
            "runtime_phase": decision.runtime_phase,
            "active_operation_type": decision.active_operation_type,
            "active_operation_status": decision.active_operation_status,
            "runtime_lease_owner": decision.runtime_lease_owner,
            "runtime_lease_expires_at": decision.runtime_lease_expires_at,
            "decision": "allowed" if decision.allowed else "suppressed",
        }

    def _parent_runtime_ownership_snapshot(
        self: TaskManager,
        db: Session,
        task,
        *,
        active_operation=None,
    ) -> ParentRuntimeOwnershipSnapshot:
        operation = active_operation if active_operation is not None else self._task_active_operation(db, task)
        runtime_lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        runtime_lease_active = bool(self._runtime_lease_is_active(runtime_lease))
        runtime_lease_owner = (
            str(getattr(runtime_lease, "owner_instance_id", "") or "").strip() or None
            if runtime_lease is not None
            else None
        )
        runtime_lease_expires_at = (
            task_shared._isoformat_or_none(getattr(runtime_lease, "lease_expires_at", None))
            if runtime_lease is not None
            else None
        )
        runtime_phase = str(self._task_runtime_phase(task) or "").strip() or None
        task_status = str(getattr(task, "status", "") or "").strip().lower() or None
        active_operation_type = str(getattr(operation, "operation_type", "") or "").strip() or None
        active_operation_status = str(getattr(operation, "status", "") or "").strip().lower() or None
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip() or None
        return ParentRuntimeOwnershipSnapshot(
            runtime_lease_present=runtime_lease is not None,
            runtime_lease_active=runtime_lease_active,
            runtime_lease_owner=runtime_lease_owner,
            runtime_lease_expires_at=runtime_lease_expires_at,
            local_handle_alive=bool(self._has_local_task_execution_owner(str(getattr(task, "id", "") or "").strip())),
            local_streaming_worker_alive=bool(
                self._task_has_active_streaming_stage_workers(str(getattr(task, "id", "") or "").strip())
            ),
            runtime_phase=runtime_phase,
            transition_guard_active=bool(self._task_runtime_transition_guard_active(task)),
            supported_control_operation_active=bool(
                self._task_has_supported_control_operation_runtime(db, task, active_operation=operation)
            ),
            task_status=task_status,
            active_operation_type=active_operation_type,
            active_operation_status=active_operation_status,
            current_operation_id=current_operation_id,
        )

    def _parent_runtime_ownership_snapshot_payload(
        self: TaskManager,
        snapshot: ParentRuntimeOwnershipSnapshot,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "reason": str(reason or "").strip() or None,
            "runtime_lease_present": snapshot.runtime_lease_present,
            "runtime_lease_active": snapshot.runtime_lease_active,
            "runtime_lease_owner": snapshot.runtime_lease_owner,
            "runtime_lease_expires_at": snapshot.runtime_lease_expires_at,
            "local_handle_alive": snapshot.local_handle_alive,
            "local_streaming_worker_alive": snapshot.local_streaming_worker_alive,
            "runtime_phase": snapshot.runtime_phase,
            "transition_guard_active": snapshot.transition_guard_active,
            "supported_control_operation_active": snapshot.supported_control_operation_active,
            "task_status": snapshot.task_status,
            "active_operation_type": snapshot.active_operation_type,
            "active_operation_status": snapshot.active_operation_status,
            "current_operation_id": snapshot.current_operation_id,
        }

    def _should_preserve_parent_runtime_ownership(
        self: TaskManager,
        snapshot: ParentRuntimeOwnershipSnapshot,
        *,
        reason: str,
    ) -> ParentRuntimeOwnershipGuardDecision:
        if snapshot.runtime_lease_active:
            return ParentRuntimeOwnershipGuardDecision(
                preserve=True,
                decision_reason="runtime_lease_active",
                snapshot=snapshot,
            )
        return ParentRuntimeOwnershipGuardDecision(
            preserve=False,
            decision_reason=str(reason or "").strip() or "no_authoritative_runtime_owner",
            snapshot=snapshot,
        )

    def _can_reclaim_parent_after_lease_loss(
        self: TaskManager,
        snapshot: ParentRuntimeOwnershipSnapshot,
        *,
        reason: str,
    ) -> ParentRuntimeOwnershipGuardDecision:
        guard = self._should_preserve_parent_runtime_ownership(snapshot, reason=reason)
        if guard.preserve:
            return guard
        return ParentRuntimeOwnershipGuardDecision(
            preserve=False,
            decision_reason=str(reason or "").strip() or "authoritative_owner_missing_reclaim_allowed",
            snapshot=snapshot,
        )

    def _delete_queue_consume_decision_payload(
        self: TaskManager,
        decision: DeleteQueueConsumeDecision,
    ) -> dict[str, Any]:
        return {
            "reason_code": decision.reason_code,
            "blocker_kind": decision.blocker_kind,
            "lease_state": decision.lease_state,
            "task_status": decision.task_status,
            "runtime_phase": decision.runtime_phase,
            "runtime_lease_owner": decision.runtime_lease_owner,
            "runtime_lease_expires_at": decision.runtime_lease_expires_at,
            "active_operation_id": decision.active_operation_id,
            "active_operation_type": decision.active_operation_type,
            "active_operation_status": decision.active_operation_status,
            "decision": "allowed" if decision.allowed else "suppressed",
        }

    def _can_clear_parent_runtime_ownership(
        self: TaskManager,
        db: Session,
        task,
        *,
        reason: str,
    ) -> LeaseClearDecision:
        active_operation = self._task_active_operation(db, task)
        snapshot = self._parent_runtime_ownership_snapshot(db, task, active_operation=active_operation)
        active_operation_type = snapshot.active_operation_type
        active_operation_status = snapshot.active_operation_status
        runtime_lease_owner = snapshot.runtime_lease_owner
        runtime_lease_expires_at = snapshot.runtime_lease_expires_at
        task_status = snapshot.task_status
        runtime_phase = snapshot.runtime_phase
        task_terminal = bool(task_status in TASK_TERMINAL_STATUSES)
        owner_matches_current_instance = bool(
            runtime_lease_owner and runtime_lease_owner == str(self.instance_id or "").strip()
        )
        lease_state = (
            "active"
            if snapshot.runtime_lease_active
            else "expired"
            if snapshot.runtime_lease_present
            else "missing"
        )
        if task_terminal and owner_matches_current_instance:
            return LeaseClearDecision(
                allowed=True,
                reason_code="terminal_owner_cleanup",
                lease_state=lease_state,
                owner_matches_current_instance=owner_matches_current_instance,
                task_terminal=task_terminal,
                task_status=task_status,
                runtime_phase=runtime_phase,
                active_operation_type=active_operation_type,
                active_operation_status=active_operation_status,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
            )
        if lease_state in {"expired", "missing"}:
            return LeaseClearDecision(
                allowed=True,
                reason_code="runtime_lease_expired" if lease_state == "expired" else "runtime_lease_missing",
                lease_state=lease_state,
                owner_matches_current_instance=owner_matches_current_instance,
                task_terminal=task_terminal,
                task_status=task_status,
                runtime_phase=runtime_phase,
                active_operation_type=active_operation_type,
                active_operation_status=active_operation_status,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
            )
        preserve = self._should_preserve_parent_runtime_ownership(snapshot, reason=reason)
        if preserve.preserve:
            reason_code = f"{preserve.decision_reason}_blocks_owner_clear"
        elif lease_state == "active":
            reason_code = "active_runtime_lease_non_owner" if not owner_matches_current_instance else "active_runtime_lease_owner_nonterminal"
        else:
            reason_code = "runtime_lease_missing_nonterminal"
        return LeaseClearDecision(
            allowed=False,
            reason_code=reason_code,
            lease_state=lease_state,
            owner_matches_current_instance=owner_matches_current_instance,
            task_terminal=task_terminal,
            task_status=task_status,
            runtime_phase=runtime_phase,
            active_operation_type=active_operation_type,
            active_operation_status=active_operation_status,
            runtime_lease_owner=runtime_lease_owner,
            runtime_lease_expires_at=runtime_lease_expires_at,
        )

    def _can_reopen_parent_task_after_lease_loss(
        self: TaskManager,
        db: Session,
        task,
        *,
        reason: str,
    ) -> LeaseClearDecision:
        decision = self._can_clear_parent_runtime_ownership(db, task, reason=reason)
        if decision.allowed and decision.reason_code == "terminal_owner_cleanup":
            return LeaseClearDecision(
                allowed=False,
                reason_code="terminal_cleanup_not_reopen",
                lease_state=decision.lease_state,
                owner_matches_current_instance=decision.owner_matches_current_instance,
                task_terminal=decision.task_terminal,
                task_status=decision.task_status,
                runtime_phase=decision.runtime_phase,
                active_operation_type=decision.active_operation_type,
                active_operation_status=decision.active_operation_status,
                runtime_lease_owner=decision.runtime_lease_owner,
                runtime_lease_expires_at=decision.runtime_lease_expires_at,
            )
        return decision

    def _can_take_over_parent_control_operation(
        self: TaskManager,
        db: Session,
        task,
        *,
        reason: str,
    ) -> LeaseClearDecision:
        return self._can_reopen_parent_task_after_lease_loss(db, task, reason=reason)

    def _can_consume_delete_queue_task(
        self: TaskManager,
        db: Session,
        task,
        *,
        active_operation=None,
    ) -> DeleteQueueConsumeDecision:
        operation = active_operation or self._active_delete_queue_operation(db, task)
        active_operation_id = str(getattr(operation, "id", "") or "").strip() or None
        active_operation_type = str(getattr(operation, "operation_type", "") or "").strip() or None
        active_operation_status = str(getattr(operation, "status", "") or "").strip().lower() or None
        task_status = str(getattr(task, "status", "") or "").strip().lower() or None
        runtime_phase = str(self._task_runtime_phase(task) or "").strip() or None
        lease = self._runtime_lease_for_task(db, task.id)
        runtime_lease_owner = str(getattr(lease, "owner_instance_id", "") or "").strip() or None
        runtime_lease_expires_at = task_shared._isoformat_or_none(getattr(lease, "lease_expires_at", None)) if lease is not None else None
        lease_active = bool(lease is not None and self._runtime_lease_is_active(lease))
        lease_state = (
            "active"
            if lease_active
            else "expired"
            if lease is not None
            else "missing"
        )
        if active_operation_type != "delete" or active_operation_status not in {"accepted", "queued", "running", "pending"}:
            return DeleteQueueConsumeDecision(
                allowed=False,
                reason_code="delete_operation_missing_or_inactive",
                blocker_kind="none",
                lease_state=lease_state,
                task_status=task_status,
                runtime_phase=runtime_phase,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
                active_operation_id=active_operation_id,
                active_operation_type=active_operation_type,
                active_operation_status=active_operation_status,
            )
        if self._task_has_supported_control_operation_runtime(db, task, active_operation=operation):
            return DeleteQueueConsumeDecision(
                allowed=False,
                reason_code="delete_control_runtime_active",
                blocker_kind="supported_control_runtime",
                lease_state=lease_state,
                task_status=task_status,
                runtime_phase=runtime_phase,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
                active_operation_id=active_operation_id,
                active_operation_type=active_operation_type,
                active_operation_status=active_operation_status,
            )
        if lease_active:
            return DeleteQueueConsumeDecision(
                allowed=False,
                reason_code="active_runtime_lease_blocks_delete_consume",
                blocker_kind="active_runtime_lease",
                lease_state=lease_state,
                task_status=task_status,
                runtime_phase=runtime_phase,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
                active_operation_id=active_operation_id,
                active_operation_type=active_operation_type,
                active_operation_status=active_operation_status,
            )
        if task_status in TASK_TERMINAL_STATUSES:
            return DeleteQueueConsumeDecision(
                allowed=True,
                reason_code="terminal_delete_takeover_without_runtime_lease",
                blocker_kind="runtime_lease_missing",
                lease_state=lease_state,
                task_status=task_status,
                runtime_phase=runtime_phase,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
                active_operation_id=active_operation_id,
                active_operation_type=active_operation_type,
                active_operation_status=active_operation_status,
            )
        if lease_state == "expired":
            reason_code = "non_terminal_delete_waiting_for_owner_recovery_after_runtime_lease_expired"
        else:
            reason_code = "non_terminal_delete_waiting_for_owner_recovery_without_runtime_lease"
        return DeleteQueueConsumeDecision(
            allowed=False,
            reason_code=reason_code,
            blocker_kind="waiting_for_runtime_owner_recovery",
            lease_state=lease_state,
            task_status=task_status,
            runtime_phase=runtime_phase,
            runtime_lease_owner=runtime_lease_owner,
            runtime_lease_expires_at=runtime_lease_expires_at,
            active_operation_id=active_operation_id,
            active_operation_type=active_operation_type,
            active_operation_status=active_operation_status,
        )

    def _can_owner_release_parent_runtime_for_retry_requeue(
        self: TaskManager,
        db: Session,
        task,
        *,
        operation,
        reason: str,
    ) -> LeaseClearDecision:
        lease = self._runtime_lease_for_task(db, task.id)
        runtime_lease_owner = str(getattr(lease, "owner_instance_id", "") or "").strip() or None
        runtime_lease_expires_at = task_shared._isoformat_or_none(getattr(lease, "lease_expires_at", None)) if lease is not None else None
        task_status = str(getattr(task, "status", "") or "").strip().lower() or None
        runtime_phase = str(self._task_runtime_phase(task) or "").strip() or None
        operation_type = str(getattr(operation, "operation_type", "") or "").strip() or None
        operation_status = str(getattr(operation, "status", "") or "").strip().lower() or None
        task_terminal = bool(task_status in TASK_TERMINAL_STATUSES)
        current_instance_id = str(self.instance_id or "").strip()
        owner_matches_current_instance = bool(runtime_lease_owner and runtime_lease_owner == current_instance_id)
        lease_active = bool(lease is not None and self._runtime_lease_is_active(lease))
        lease_state = (
            "active"
            if lease_active
            else "expired"
            if lease is not None
            else "missing"
        )
        if not self._is_retry_like_operation_type(operation_type):
            return LeaseClearDecision(
                allowed=False,
                reason_code="operation_not_retry_like",
                lease_state=lease_state,
                owner_matches_current_instance=owner_matches_current_instance,
                task_terminal=task_terminal,
                task_status=task_status,
                runtime_phase=runtime_phase,
                active_operation_type=operation_type,
                active_operation_status=operation_status,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
            )
        if not owner_matches_current_instance:
            return LeaseClearDecision(
                allowed=False,
                reason_code="retry_requeue_owner_mismatch",
                lease_state=lease_state,
                owner_matches_current_instance=False,
                task_terminal=task_terminal,
                task_status=task_status,
                runtime_phase=runtime_phase,
                active_operation_type=operation_type,
                active_operation_status=operation_status,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
            )
        if lease_state != "active":
            return LeaseClearDecision(
                allowed=False,
                reason_code="retry_requeue_active_lease_required",
                lease_state=lease_state,
                owner_matches_current_instance=owner_matches_current_instance,
                task_terminal=task_terminal,
                task_status=task_status,
                runtime_phase=runtime_phase,
                active_operation_type=operation_type,
                active_operation_status=operation_status,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
            )
        return LeaseClearDecision(
            allowed=True,
            reason_code="retry_owner_release_requeue",
            lease_state=lease_state,
            owner_matches_current_instance=owner_matches_current_instance,
            task_terminal=task_terminal,
            task_status=task_status,
            runtime_phase=runtime_phase,
            active_operation_type=operation_type,
            active_operation_status=operation_status,
            runtime_lease_owner=runtime_lease_owner,
            runtime_lease_expires_at=runtime_lease_expires_at,
        )

    def _record_parent_runtime_lease_decision(
        self: TaskManager,
        db: Session,
        task,
        *,
        event_type: str,
        message: str,
        decision: LeaseClearDecision,
        reason: str,
        stage_name: str | None = None,
        level: str = "warning",
    ) -> None:
        self._record_event(
            db,
            task,
            event_type,
            message,
            level=level,
            stage_name=stage_name or str(getattr(task, "current_stage", "") or "").strip() or None,
            payload=self._parent_runtime_lease_decision_payload(decision, reason=reason),
        )

    def _parent_runtime_reopen_allowed_event(
        self: TaskManager,
        decision: LeaseClearDecision,
        *,
        expired_message: str,
        missing_message: str,
    ) -> tuple[str, str]:
        lease_state = str(getattr(decision, "lease_state", "") or "").strip().lower()
        if lease_state == "missing":
            return "parent_runtime_reopen_allowed_after_lease_missing", missing_message
        return "parent_runtime_reopen_allowed_after_lease_expiry", expired_message

    def _task_main_state_write_allowed(
        self: TaskManager,
        db: Session,
        task,
        *,
        source: str,
        allow_reclaim_write: bool = False,
    ) -> bool:
        normalized_source = str(source or "").strip().lower()
        guarded_sources = {
            "state_event_inbox",
            "runtime_state",
            "runtime_worker",
            "state_machine",
            "task_operation",
            "archive_apply",
            "downstream_sync",
            "item_sync",
        }
        if normalized_source not in guarded_sources:
            return True
        if allow_reclaim_write and self._stale_reclaim_write_allowed(db, task, source=source):
            return True
        return self._task_runtime_owner_matches_current_instance(db, task) or self._task_runtime_transition_guard_owned_by_current_instance(task)

    def _stale_reclaim_write_allowed(
        self: TaskManager,
        db: Session,
        task,
        *,
        source: str,
    ) -> bool:
        normalized_source = str(source or "").strip().lower()
        if normalized_source not in {"runtime_worker", "runtime_reclaim", "task_manager"}:
            return False
        if task is None:
            return False
        if self._task_runtime_owner_matches_current_instance(db, task):
            return True
        if self._task_runtime_transition_guard_owned_by_current_instance(task):
            return True
        lease = self._runtime_lease_for_task(db, getattr(task, "id", None))
        if self._runtime_lease_is_active(lease):
            return False
        return True

    def _infer_running_to_pending_reason_category(
        self: TaskManager,
        *,
        source: str,
        reason: str,
        clear_runtime_owner: bool,
    ) -> str | None:
        normalized_source = str(source or "").strip().lower()
        normalized_reason = str(reason or "").strip().lower()
        if normalized_source == "runtime_reclaim":
            return "lease_loss_requeue"
        if normalized_source == "task_manager":
            return "stale_reclaim"
        if normalized_source == "archive_worker":
            return "retry_requeue"
        if normalized_source == "task_operation":
            return "control_operation_requeue"
        if normalized_source == "runtime_worker" and clear_runtime_owner:
            return "stale_reclaim"
        return None

    def _running_state_preservation_context(
        self: TaskManager,
        db: Session,
        task,
    ) -> dict[str, Any]:
        transition_guard = self._task_runtime_transition_guard(task)
        return {
            "runtime_owner_valid": bool(self._running_task_has_valid_runtime_ownership(db, task)),
            "transition_guard_active": bool(self._task_runtime_transition_guard_active(task)),
            "transition_guard": transition_guard if transition_guard else None,
            "runtime_phase": str(self._task_runtime_phase(task) or "").strip() or None,
            "current_stage": str(getattr(task, "current_stage", "") or "").strip() or None,
        }

    def _task_should_preserve_running_during_owned_execution(
        self: TaskManager,
        db: Session,
        task,
        *,
        attempted_status: str,
        runtime_phase: str | None = None,
        downgrade_reason_category: str | None = None,
        clear_runtime_owner: bool = False,
    ) -> tuple[bool, str | None]:
        attempted = str(attempted_status or "").strip().lower()
        if attempted != "pending":
            return False, None
        current_status = str(getattr(task, "status", "") or "").strip().lower()
        if current_status != "running":
            return False, None
        effective_runtime_phase = str(runtime_phase or self._task_runtime_phase(task) or "").strip().lower()
        if effective_runtime_phase != TASK_RUNTIME_PHASE_OWNED_EXECUTION:
            return False, None
        if downgrade_reason_category:
            return False, None
        if clear_runtime_owner:
            return False, None
        if self._task_runtime_transition_guard_active(task):
            return True, "transition_guard_active"
        if self._running_task_has_valid_runtime_ownership(db, task):
            return True, "runtime_owner_still_valid"
        if self._task_runtime_owner_matches_current_instance(db, task):
            return True, "current_instance_still_owner"
        return False, None

    def _apply_task_main_state_update(
        self: TaskManager,
        db: Session,
        task,
        *,
        source: str,
        reason: str,
        status: str | None = None,
        stage_name: str | None = None,
        runtime_phase: str | None = None,
        finished_at: Any = _MAIN_STATE_UNSET,
        last_error: Any = _MAIN_STATE_UNSET,
        clear_runtime_owner: bool = False,
        status_event_type: str = "task_status_changed",
        status_message: str | None = None,
        status_level: str = "info",
        status_payload: dict[str, Any] | None = None,
        record_blocked_event: bool = True,
        allow_reclaim_write: bool = False,
        downgrade_reason_category: str | None = None,
        preserve_running_event_type: str | None = None,
        preserve_running_message: str | None = None,
    ) -> bool:
        if not self._task_main_state_write_allowed(db, task, source=source, allow_reclaim_write=allow_reclaim_write):
            if record_blocked_event:
                self._record_main_state_write_blocked(
                    db,
                    task,
                    source=source,
                    attempted_stage_name=stage_name,
                    attempted_status=status,
                    reason=reason,
                )
            return False
        before_state = self._parent_task_state_snapshot(task)
        attempted_status = str(status or "").strip() or None
        effective_runtime_phase = runtime_phase if runtime_phase is not None else self._task_runtime_phase(task)
        normalized_downgrade_reason_category = (
            str(downgrade_reason_category or "").strip()
            or self._infer_running_to_pending_reason_category(
                source=source,
                reason=reason,
                clear_runtime_owner=clear_runtime_owner,
            )
        )
        preserve_running, preserve_reason = self._task_should_preserve_running_during_owned_execution(
            db,
            task,
            attempted_status=attempted_status or "",
            runtime_phase=effective_runtime_phase,
            downgrade_reason_category=normalized_downgrade_reason_category or None,
            clear_runtime_owner=clear_runtime_owner,
        )
        state_context = self._running_state_preservation_context(db, task)
        merged_status_payload = dict(status_payload or {})
        if attempted_status:
            merged_status_payload.setdefault("attempted_status", attempted_status)
        merged_status_payload.setdefault("final_status", "running" if preserve_running else attempted_status)
        merged_status_payload.setdefault("runtime_owner_valid", state_context.get("runtime_owner_valid"))
        merged_status_payload.setdefault("transition_guard_active", state_context.get("transition_guard_active"))
        merged_status_payload.setdefault("runtime_phase", state_context.get("runtime_phase"))
        if normalized_downgrade_reason_category:
            merged_status_payload.setdefault("downgrade_reason_category", normalized_downgrade_reason_category)
        if preserve_running:
            merged_status_payload.setdefault("preserve_running_rejected_reason", preserve_reason)
            self._record_event(
                db,
                task,
                preserve_running_event_type or "task_running_downgrade_to_pending_blocked",
                preserve_running_message or "任务仍处于 owned execution 连续执行窗口，已阻止 running -> pending 降级",
                level="warning",
                stage_name=stage_name or str(getattr(task, "current_stage", "") or "").strip() or None,
                payload={
                    "task_id": str(getattr(task, "id", "") or "").strip() or None,
                    "previous_status": str(before_state.get("status") or "").strip() or None,
                    "attempted_status": attempted_status,
                    "final_status": "running",
                    "next_stage": str(stage_name or "").strip() or None,
                    "source": str(source or "").strip() or None,
                    "preserve_running_rejected_reason": preserve_reason,
                    **state_context,
                    **merged_status_payload,
                },
            )
            status = "running"
            clear_runtime_owner = False
        elif attempted_status == "pending" and str(before_state.get("status") or "").strip() == "running":
            self._record_event(
                db,
                task,
                "task_running_downgrade_to_pending_allowed",
                "任务已满足回收到待调度队列的条件，允许 running -> pending",
                level="warning",
                stage_name=stage_name or str(getattr(task, "current_stage", "") or "").strip() or None,
                payload={
                    "task_id": str(getattr(task, "id", "") or "").strip() or None,
                    "previous_status": str(before_state.get("status") or "").strip() or None,
                    "attempted_status": attempted_status,
                    "final_status": "pending",
                    "next_stage": str(stage_name or "").strip() or None,
                    "source": str(source or "").strip() or None,
                    "downgrade_reason_category": normalized_downgrade_reason_category or "unspecified",
                    **state_context,
                    **merged_status_payload,
                },
            )
        if status is not None:
            self._set_task_status(
                db,
                task,
                status,
                reason=reason,
                source=source,
                event_type=status_event_type,
                message=status_message,
                level=status_level,
                stage_name=stage_name,
                payload=merged_status_payload,
            )
        if stage_name is not None:
            task.current_stage = stage_name
        if runtime_phase is not None:
            self._set_task_runtime_phase(task, runtime_phase)
        if finished_at is not self._MAIN_STATE_UNSET:
            task.finished_at = finished_at
        if last_error is not self._MAIN_STATE_UNSET:
            task.last_error = last_error
        if clear_runtime_owner:
            effective_status = str(getattr(task, "status", "") or "").strip()
            effective_runtime_phase = str(self._task_runtime_phase(task) or "").strip()
            _runtime_lease = self._runtime_lease_for_task(db, task.id)
            if (
                effective_status == "running"
                and effective_runtime_phase == TASK_RUNTIME_PHASE_OWNED_EXECUTION
                and self._runtime_lease_is_active(_runtime_lease)
            ):
                _suppress_message = "任务保持 running+owned_execution，不清理 authoritative runtime lease"
                if not self._has_recent_matching_task_event(
                    db,
                    task,
                    event_type="runtime_owner_clear_suppressed_for_running_owned",
                    stage_name=str(getattr(task, "current_stage", "") or "").strip() or None,
                    message=_suppress_message,
                    payload_keys={"source": str(source or "").strip() or None},
                    within_seconds=60,
                ):
                    self._record_event(
                        db,
                        task,
                        "runtime_owner_clear_suppressed_for_running_owned",
                        _suppress_message,
                        level="warning",
                        stage_name=str(getattr(task, "current_stage", "") or "").strip() or None,
                        payload={
                            "source": str(source or "").strip() or None,
                            "reason": str(reason or "").strip() or None,
                        },
                    )
        self._record_parent_task_state_transition(
            db,
            task,
            before_state=before_state,
            reason=reason,
            source=source,
            stage_name=stage_name,
        )
        return True

    def _apply_task_status_only_update(
        self: TaskManager,
        db: Session,
        task,
        *,
        status: str,
        reason: str,
        source: str,
        stage_name: str | None = None,
        runtime_phase: str | None = None,
        finished_at: Any = _MAIN_STATE_UNSET,
        last_error: Any = _MAIN_STATE_UNSET,
        clear_runtime_owner: bool = False,
        status_event_type: str = "task_status_changed",
        status_message: str | None = None,
        status_level: str = "info",
        status_payload: dict[str, Any] | None = None,
        record_blocked_event: bool = True,
    ) -> bool:
        return self._apply_task_main_state_update(
            db,
            task,
            source=source,
            reason=reason,
            status=status,
            stage_name=stage_name,
            runtime_phase=runtime_phase,
            finished_at=finished_at,
            last_error=last_error,
            clear_runtime_owner=clear_runtime_owner,
            status_event_type=status_event_type,
            status_message=status_message,
            status_level=status_level,
            status_payload=status_payload,
            record_blocked_event=record_blocked_event,
        )

    def _apply_terminal_main_state(
        self: TaskManager,
        db: Session,
        task,
        *,
        source: str,
        reason: str,
        status: str | None = None,
        stage_name: str | None = None,
        runtime_phase: str | None = TASK_RUNTIME_PHASE_TERMINAL,
        finished_at: Any = None,
        last_error: Any = None,
        record_blocked_event: bool = True,
    ) -> bool:
        return self._apply_task_main_state_update(
            db,
            task,
            source=source,
            reason=reason,
            status=status,
            stage_name=stage_name,
            runtime_phase=runtime_phase,
            finished_at=finished_at,
            last_error=self._MAIN_STATE_UNSET if last_error is None else last_error,
            clear_runtime_owner=True,
            record_blocked_event=record_blocked_event,
            allow_reclaim_write=True,
        )

    def _apply_active_owned_execution_main_state(
        self: TaskManager,
        db: Session,
        task,
        *,
        source: str,
        reason: str,
        status: str | None = None,
        stage_name: str | None = None,
        runtime_phase: str | None = TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        finished_at: Any = None,
        last_error: Any = None,
        record_blocked_event: bool = True,
    ) -> bool:
        return self._apply_task_main_state_update(
            db,
            task,
            source=source,
            reason=reason,
            status=status,
            stage_name=stage_name,
            runtime_phase=runtime_phase,
            finished_at=finished_at,
            last_error=self._MAIN_STATE_UNSET if last_error is None else last_error,
            clear_runtime_owner=False,
            record_blocked_event=record_blocked_event,
        )

    def _apply_release_for_takeover_main_state(
        self: TaskManager,
        db: Session,
        task,
        *,
        source: str,
        reason: str,
        status: str | None = None,
        stage_name: str | None = None,
        runtime_phase: str | None = TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        finished_at: Any = None,
        last_error: Any = None,
        record_blocked_event: bool = True,
    ) -> bool:
        return self._apply_task_main_state_update(
            db,
            task,
            source=source,
            reason=reason,
            status=status,
            stage_name=stage_name,
            runtime_phase=runtime_phase,
            finished_at=finished_at,
            last_error=self._MAIN_STATE_UNSET if last_error is None else last_error,
            clear_runtime_owner=True,
            record_blocked_event=record_blocked_event,
            allow_reclaim_write=True,
        )

    def _record_main_state_write_blocked(
        self: TaskManager,
        db: Session,
        task,
        *,
        source: str,
        attempted_stage_name: str | None = None,
        attempted_status: str | None = None,
        reason: str,
    ) -> None:
        self._record_event(
            db,
            task,
            "main_state_write_blocked",
            "非 owner 路径试图推进任务主状态，已降级为事实更新",
            level="warning",
            stage_name=attempted_stage_name or str(getattr(task, "current_stage", "") or "").strip() or None,
            payload={
                "source": str(source or "").strip() or None,
                "attempted_stage_name": str(attempted_stage_name or "").strip() or None,
                "attempted_status": str(attempted_status or "").strip() or None,
                "reason": str(reason or "").strip() or None,
            },
        )

    def _operation_allows_owner_claim(self: TaskManager, operation: BinarySecurityTaskOperation | None) -> bool:
        from app.service import task_manager as task_manager_module

        if operation is None:
            return False
        status = str(getattr(operation, "status", "") or "").strip().lower()
        return status in task_manager_module.TASK_OPERATION_ACTIVE_STATUSES

    def _operation_allows_runtime_resume(self: TaskManager, operation: BinarySecurityTaskOperation | None) -> bool:
        return not self._operation_blocks_runtime_resume(operation)

    def _operation_blocks_runtime_resume(self: TaskManager, operation: BinarySecurityTaskOperation | None) -> bool:
        from app.service import task_manager as task_manager_module

        if operation is None:
            return False
        status = str(getattr(operation, "status", "") or "").strip().lower()
        if status not in task_manager_module.TASK_OPERATION_ACTIVE_STATUSES:
            return False
        operation_type = str(getattr(operation, "operation_type", "") or "").strip()
        return operation_type in task_manager_module.TASK_OPERATION_CONTROL_SERIAL_ONLY_TYPES

    def _task_active_operation(
        self: TaskManager,
        db: Session,
        task,
    ) -> BinarySecurityTaskOperation | None:
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
        if not current_operation_id:
            return None
        return (
            db.query(BinarySecurityTaskOperation)
            .filter(BinarySecurityTaskOperation.id == current_operation_id)
            .first()
        )

    def _task_blocks_runtime_resume(
        self: TaskManager,
        db: Session,
        task,
        *,
        active_operation: BinarySecurityTaskOperation | None = None,
    ) -> bool:
        operation = active_operation if active_operation is not None else self._task_active_operation(db, task)
        return self._operation_blocks_runtime_resume(operation)

    def _load_service_config(self: TaskManager, db: Session) -> Any:
        from app.service import task_manager as task_manager_module

        service_cfg = getattr(self.cfg, "service", None)
        scheduler_cfg = getattr(self.cfg, "scheduler", None)
        default_max_concurrent = max(
            1,
            int(
                getattr(service_cfg, "max_concurrent_tasks", None)
                or getattr(scheduler_cfg, "max_concurrent_tasks", None)
                or 20
            ),
        )
        default_dispatch_timeout = max(
            10,
            int(
                getattr(service_cfg, "dispatch_timeout_seconds", None)
                or getattr(scheduler_cfg, "dispatch_timeout_seconds", None)
                or 60
            ),
        )
        default_worker_task_concurrency = max(
            1,
            int(
                getattr(scheduler_cfg, "task_concurrency", None)
                or 40
            ),
        )
        default_lease_timeout = max(
            15,
            int(
                getattr(service_cfg, "lease_timeout_seconds", None)
                or getattr(scheduler_cfg, "task_lease_ttl_seconds", None)
                or 90
            ),
        )
        payload: dict[str, Any] = {}
        try:
            row = (
                db.query(task_manager_module.BinarySecurityServiceConfig)
                .order_by(task_manager_module.BinarySecurityServiceConfig.updated_at.desc())
                .first()
            )
            payload = dict(getattr(row, "config", {}) or {}) if row is not None else {}
        except Exception:
            payload = {}
        return SimpleNamespace(
            worker_task_concurrency=max(1, int(payload.get("worker_task_concurrency") or default_worker_task_concurrency)),
            max_concurrent_tasks=max(1, int(payload.get("max_concurrent_tasks") or default_max_concurrent)),
            dispatch_timeout_seconds=max(10, int(payload.get("dispatch_timeout_seconds") or default_dispatch_timeout)),
            lease_timeout_seconds=max(15, int(payload.get("lease_timeout_seconds") or default_lease_timeout)),
        )

    def get_service_config(self: TaskManager, db: Session) -> BinarySecurityServiceConfigResponse:
        config = self._load_service_config(db)
        payload = BinarySecurityServiceConfigPayload(
            worker_task_concurrency=int(getattr(config, "worker_task_concurrency", 40)),
            max_concurrent_tasks=int(config.max_concurrent_tasks),
            dispatch_timeout_seconds=int(config.dispatch_timeout_seconds),
            lease_timeout_seconds=int(getattr(config, "lease_timeout_seconds", 90)),
        )
        return BinarySecurityServiceConfigResponse(config=payload)

    def _active_operation(self: TaskManager, db: Session, task_id: str) -> BinarySecurityTaskOperation | None:
        from app.service import task_manager as task_manager_module

        now_value = task_manager_module._now()
        operations = (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(
                task_manager_module.BinarySecurityTaskOperation.task_id == task_id,
                task_manager_module.BinarySecurityTaskOperation.status.in_(list(task_manager_module.TASK_OPERATION_ACTIVE_STATUSES)),
            )
            .order_by(
                task_manager_module.BinarySecurityTaskOperation.created_at.desc(),
                task_manager_module.BinarySecurityTaskOperation.id.desc(),
            )
            .all()
        )
        for operation in operations:
            return operation
        return None

    def _task_runtime_policy_update_support(
        self: TaskManager,
        task: BinarySecurityTask,
        db: Session | None = None,
    ) -> tuple[bool, str | None]:
        from app.service import task_manager as task_manager_module

        owns_session = db is None
        if db is None:
            db = task_manager_module.get_session_factory()()
        try:
            active_operation = self._active_operation(db, task.id)
        finally:
            if owns_session:
                db.close()
        if active_operation is not None and str(active_operation.operation_type or "").strip() not in {
            "update_runtime_policy",
            "update_concurrency",
        }:
            return False, f"当前任务正在执行 {active_operation.operation_type}，暂不允许运行时修改任务策略"
        if str(task.status or "").strip() == "cancelled":
            return False, "已取消任务不允许运行时修改任务策略"
        if str(task.status or "").strip() not in {
            "pending",
            "dispatching",
            "running",
            task_manager_module.TASK_STATUS_PENDING_ENTRY_CONFIRMATION,
            task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION,
            "failed",
            "success",
            "partial_success",
            "cancel_failed",
        }:
            return False, f"当前任务状态不支持运行时修改任务策略: {task.status}"
        return True, None

    def _task_policy_update_support(
        self: TaskManager,
        task: BinarySecurityTask,
        db: Session | None = None,
    ) -> tuple[bool, str | None]:
        from app.service import task_manager as task_manager_module

        owns_session = db is None
        if db is None:
            db = task_manager_module.get_session_factory()()
        try:
            active_operation = self._active_operation(db, task.id)
        finally:
            if owns_session:
                db.close()
        if active_operation is not None:
            return False, f"当前任务正在执行 {active_operation.operation_type}，暂不允许修改任务策略"
        blocked_statuses = {"dispatching", "running"}
        if task.status in blocked_statuses:
            return False, f"任务运行中，当前状态不允许修改任务策略: {task.status}"
        return True, None

    def _runtime_lease_capable(self: TaskManager) -> bool:
        return str(self._service_role() or "").strip() == "worker"

    def _task_base_policy(self: TaskManager, task: BinarySecurityTask) -> dict[str, Any]:
        return dict(task.policy or {})

    def _task_runtime_override(self: TaskManager, task: BinarySecurityTask) -> dict[str, Any]:
        return dict(getattr(task, "runtime_override", {}) or {})

    def _effective_runtime_policy(self: TaskManager, task: BinarySecurityTask) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        base = json.loads(json.dumps(self._task_base_policy(task)))
        override = self._task_runtime_override(task)

        if override.get("stage_parallelism"):
            merged = dict(base.get("stage_parallelism") or {})
            for stage_name, value in dict(override.get("stage_parallelism") or {}).items():
                if stage_name in self._stage_sequence_for_task(task) and value is not None:
                    merged[stage_name] = max(1, int(value))
            base["stage_parallelism"] = merged
            if merged:
                base["max_stage_parallelism"] = max(int(v) for v in merged.values())

        if override.get("dispatch_throttle"):
            base["dispatch_throttle"] = {
                **dict(base.get("dispatch_throttle") or {}),
                **dict(override.get("dispatch_throttle") or {}),
            }
        if override.get("max_retries_per_item") is not None:
            base["max_retries_per_item"] = int(override["max_retries_per_item"])
        if override.get("continue_on_item_failure") is not None:
            base["continue_on_item_failure"] = bool(override["continue_on_item_failure"])
        if override.get("tail_reconcile_poll_interval_seconds") is not None:
            base["tail_reconcile_poll_interval_seconds"] = int(override["tail_reconcile_poll_interval_seconds"])
        base["module_risk_levels"] = task_manager_module._normalize_module_risk_levels(base.get("module_risk_levels"))
        # Child-task automatic retry is globally disabled. Explicit retry/reset operations
        # remain available, but runtime execution ignores task-supplied retry counts.
        base["max_retries_per_item"] = 0
        base["automatic_child_retry_enabled"] = False
        return base

    def _max_retries_per_item(self: TaskManager, task: BinarySecurityTask) -> int:
        del task
        return 0

    def _runtime_policy_effect_scope(self: TaskManager, task: BinarySecurityTask) -> dict[str, str]:
        from app.service import task_manager as task_manager_module

        effective = self._effective_runtime_policy(task)
        stage_scope: dict[str, str] = {}
        for stage_name in self._stage_sequence_for_task(task):
            if stage_name in task_manager_module.STREAMING_TAIL_STAGES:
                stage_scope[stage_name] = "tail_claim_immediate"
            elif stage_name == str(task.current_stage or "").strip():
                stage_scope[stage_name] = "next_dispatch_batch"
            else:
                stage_scope[stage_name] = "future_stage_only"
        if effective.get("tail_reconcile_poll_interval_seconds") is not None:
            stage_scope["_tail_reconcile_poll_interval_seconds"] = "tail_claim_immediate"
        if effective.get("dispatch_throttle"):
            stage_scope["_dispatch_throttle"] = "tail_claim_immediate"
        return stage_scope

    def _service_token(self: TaskManager) -> str | None:
        return self.cfg.auth_service.service_machine_token

    def _resolve_downstream_token(self: TaskManager, preferred_token: str | None = None) -> str | None:
        token = str(preferred_token or "").strip()
        if token:
            return token
        service_token = str(self._service_token() or "").strip()
        return service_token or None

    def _root_task_key_secret(self: TaskManager, task: BinarySecurityTask) -> str | None:
        summary = task.summary if isinstance(task.summary, dict) else {}
        runtime_keys = summary.get("runtime_task_keys") if isinstance(summary.get("runtime_task_keys"), dict) else {}
        secret = str(runtime_keys.get("root_task_key_secret") or "").strip()
        return secret or None

    def _lease_is_active(self: TaskManager, task: BinarySecurityTask, db: Session | None = None) -> bool:
        from app.service import task_manager as task_manager_module

        task_id = str(getattr(task, "id", "") or "").strip()
        if not task_id:
            return False
        lease: BinarySecurityTaskRuntimeLease | None = None
        if db is not None:
            lease = self._runtime_lease_for_task(db, task_id)
        else:
            session = task_manager_module.get_session_factory()()
            try:
                lease = self._runtime_lease_for_task(session, task_id)
            finally:
                session.close()
        return bool(lease is not None and self._runtime_lease_is_active(lease))

    def _next_lease_expiry(
        self: TaskManager,
        db: Session | None = None,
        *,
        now_value: Any | None = None,
    ):
        del db
        return self._next_runtime_lease_expiry(now_value=now_value)

    def _classify_orchestration_error(self: TaskManager, exc: Exception) -> str:
        sync_error = self._classify_downstream_sync_error(exc)
        if sync_error in {
            "db_connection_refused",
            "db_connection_lost",
            "db_session_invalid",
            "downstream_http_timeout",
            "downstream_http_error",
            "downstream_payload_invalid",
        }:
            return sync_error
        lowered = str(exc or "").strip().lower()
        if isinstance(exc, FileNotFoundError):
            return "workspace_transient_missing"
        if isinstance(exc, OSError):
            return "archive_copy_io_error"
        if any(token in lowered for token in {"metadata", "task-metadata.json"}):
            return "task_metadata_write_failed"
        if any(token in lowered for token in {"state event", "state_event_inbox"}):
            return "state_event_persist_failed"
        if self._is_retryable_lock_error(exc):
            return "retryable_lock_conflict"
        return sync_error

    def _task_runtime_lease_view(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[str | None, Any | None, str | None, str | None, str | None, int | None]:
        lease = self._runtime_lease_for_task(db, task.id)
        if lease is not None:
            return (
                lease.owner_instance_id,
                lease.lease_expires_at,
                "runtime_lease",
                lease.owner_pod_uid,
                lease.owner_boot_id,
                lease.generation,
            )
        return (None, None, None, None, None, None)

    def _is_terminal_tail_item_with_only_residual_binding(self: TaskManager, item) -> bool:
        normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
        if normalized_status not in {"success", "failed", "cancelled", "downstream_missing", "partial_success"}:
            return False
        if not str(item.downstream_task_id or "").strip():
            return False
        replacement_state = self._replacement_in_progress_state(item)
        if replacement_state["replacement_in_progress"]:
            return False
        if replacement_state["binding_cleared"] and replacement_state["verification_status"] != "succeeded":
            return False
        sync_status = self._stage_item_sync_status_value(item)
        if sync_status in {"transport_error", "binding_mismatch", "binding_missing_during_recreate"}:
            return False
        if self._stage_item_sync_in_retry_backoff(item):
            return False
        observed_status = self._normalize_downstream_status(self._latest_observed_downstream_status(item))
        if observed_status in {"pending", "queued", "dispatching", "running"}:
            return False
        return True

    def _stage_item_has_unresolved_downstream_ref(self: TaskManager, item) -> bool:
        if not str(item.downstream_task_id or "").strip():
            return False
        normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
        if normalized_status in {"pending", "queued", "dispatching", "running"}:
            return True
        if self._item_has_pending_replacement_or_stale_child(item):
            return True
        if self._stage_item_sync_in_retry_backoff(item):
            return True
        sync_status = self._stage_item_sync_status_value(item)
        if sync_status in {"transport_error", "binding_mismatch", "binding_missing_during_recreate"}:
            return True
        if self._item_missing_recorded_downstream_status(item):
            return True
        if self._is_terminal_tail_item_with_only_residual_binding(item):
            return False
        return False

    def _tail_stage_work_summary(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> dict[str, Any]:
        if not self._streaming_mode_enabled(task):
            return {
                "active_stage_name": None,
                "tail_control_mode": "idle",
                "has_runnable_unbound_items": False,
                "unbound_runnable_item_count": 0,
                "bound_active_item_count": 0,
                "has_downstream_refs": False,
                "takeover_required": False,
                "takeover_reason": None,
            }
        active_stage_name: str | None = None
        unbound_runnable_item_count = 0
        bound_active_item_count = 0
        has_downstream_refs = False
        has_incomplete_stage = False
        terminal_residual_binding_count = 0
        for stage_name in self._streaming_tail_stage_names(task):
            items = self._stage_items(db, task.id, stage_name)
            stage_bound_active_item_count = 0
            stage_has_downstream_refs = False
            stage_has_runnable_unbound_items = False
            stage_has_real_runnable_work = self._stage_has_real_runnable_work(db, task, stage_name)
            stage_run = (
                db.query(BinarySecurityStageRun)
                .filter(
                    BinarySecurityStageRun.task_id == task.id,
                    BinarySecurityStageRun.stage_name == stage_name,
                )
                .first()
            )
            normalized_stage_status = self._normalize_downstream_status(getattr(stage_run, "status", None)) or str(getattr(stage_run, "status", "") or "").strip()
            stage_has_unresolved_tail_work = False
            for item in items:
                normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip()
                unresolved_downstream_ref = self._stage_item_has_unresolved_downstream_ref(item)
                if self._is_terminal_tail_item_with_only_residual_binding(item):
                    terminal_residual_binding_count += 1
                if normalized_status in {"pending", "queued"}:
                    unbound_runnable_item_count += 1
                    stage_has_runnable_unbound_items = True
                    stage_has_unresolved_tail_work = True
                    if unresolved_downstream_ref:
                        has_downstream_refs = True
                        stage_has_downstream_refs = True
                elif unresolved_downstream_ref and self._is_streaming_active_item_status(normalized_status):
                    bound_active_item_count += 1
                    stage_bound_active_item_count += 1
                    has_downstream_refs = True
                    stage_has_downstream_refs = True
                    stage_has_unresolved_tail_work = True
                elif unresolved_downstream_ref:
                    has_downstream_refs = True
                    stage_has_downstream_refs = True
                    stage_has_unresolved_tail_work = True
            if normalized_stage_status in {"pending", "queued"} and stage_has_real_runnable_work:
                has_incomplete_stage = True
            elif normalized_stage_status in {"dispatching", "running", "applying"} and not (
                stage_bound_active_item_count > 0 or stage_has_downstream_refs or stage_has_runnable_unbound_items
            ):
                has_incomplete_stage = True
            if active_stage_name is None and (
                stage_has_runnable_unbound_items
                or stage_bound_active_item_count > 0
                or stage_has_downstream_refs
                or (normalized_stage_status in {"pending", "queued", "dispatching", "running", "applying"} and stage_has_unresolved_tail_work)
            ):
                active_stage_name = stage_name
        has_runnable_unbound_items = unbound_runnable_item_count > 0
        if has_runnable_unbound_items or has_incomplete_stage:
            tail_control_mode = "execution_takeover"
            takeover_required = True
            takeover_reason = "runnable_unbound_tail_items" if has_runnable_unbound_items else "incomplete_tail_stage"
        elif bound_active_item_count > 0 or has_downstream_refs:
            tail_control_mode = "reconciliation"
            takeover_required = False
            takeover_reason = None
        else:
            tail_control_mode = "idle"
            takeover_required = False
            takeover_reason = None
        return {
            "active_stage_name": active_stage_name,
            "tail_control_mode": tail_control_mode,
            "has_runnable_unbound_items": has_runnable_unbound_items,
            "unbound_runnable_item_count": unbound_runnable_item_count,
            "bound_active_item_count": bound_active_item_count,
            "has_downstream_refs": has_downstream_refs,
            "has_incomplete_stage": has_incomplete_stage,
            "terminal_residual_binding_count": terminal_residual_binding_count,
            "takeover_required": takeover_required,
            "takeover_reason": takeover_reason,
        }

    def _tail_has_runnable_unbound_work(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        return bool(self._tail_stage_work_summary(db, task).get("has_runnable_unbound_items"))

    def _tail_requires_execution_takeover(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        summary = self._tail_stage_work_summary(db, task)
        return bool(summary.get("tail_control_mode") == "execution_takeover" and summary.get("takeover_required"))

    def _should_preserve_tail_runtime_lease(self: TaskManager, db: Session, task: BinarySecurityTask | None) -> bool:
        del db, task
        return False

    def _tail_reconcile_state(self: TaskManager, task: BinarySecurityTask | None) -> str:
        del task
        return "idle"

    def _has_active_owned_execution_holder(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        if self._task_runtime_phase(task) != TASK_RUNTIME_PHASE_OWNED_EXECUTION:
            return False
        lease_owner, lease_expires_at, lease_source, _lease_pod_uid, _lease_boot_id, _lease_generation = self._task_runtime_lease_view(db, task)
        if lease_source == "runtime_lease" and lease_owner and ((task_manager_module._seconds_until(lease_expires_at) or 0) > 0):
            return True
        return False

    def _should_requeue_for_owned_execution(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        next_stage: str | None = None,
        next_stage_status: str | None = None,
    ) -> bool:
        if self._task_runtime_phase(task) != TASK_RUNTIME_PHASE_OWNED_EXECUTION:
            return False
        if self._has_active_owned_execution_holder(db, task):
            return False
        if str(task.status or "").strip() not in {"running", "dispatching", "pending"}:
            return False
        stage_name = str(next_stage or task.current_stage or "").strip()
        if not stage_name:
            return False
        normalized_stage_status = str(next_stage_status or "").strip()
        if normalized_stage_status and normalized_stage_status not in {"pending", "queued", "running", "dispatching", "applying"}:
            return False
        has_authoritative_active_stage = normalized_stage_status in {"pending", "queued", "running", "dispatching", "applying"}
        has_runnable_work = self._stage_has_real_runnable_work(db, task, stage_name)
        if self._stage_terminal_already_consumed(db, task, stage_name) and not has_runnable_work and not has_authoritative_active_stage:
            return False
        return has_runnable_work or has_authoritative_active_stage

    def _task_has_authoritative_active_stage_context(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str | None = None,
    ) -> bool:
        normalized_stage_name = str(stage_name or getattr(task, "current_stage", "") or "").strip()
        if not normalized_stage_name:
            return False
        stage_run = self._latest_stage_run(db, task.id, normalized_stage_name)
        normalized_stage_status = (
            self._normalize_downstream_status(getattr(stage_run, "status", None))
            or str(getattr(stage_run, "status", "") or "").strip().lower()
        ) if stage_run is not None else ""
        if normalized_stage_status in {"pending", "queued", "running", "dispatching", "applying"}:
            return True
        items = self._stage_items(db, task.id, normalized_stage_name)
        if any(self._is_active_item_status(getattr(item, "status", None)) for item in items):
            return True
        if any(str(getattr(item, "downstream_task_id", "") or "").strip() for item in items):
            return True
        return self._stage_has_real_runnable_work(db, task, normalized_stage_name)

    def _requeue_owned_execution_takeover(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str | None,
        reason: str,
        event_type: str,
        message: str,
        event_level: str = "warning",
        event_payload: dict[str, Any] | None = None,
        preserve_active_state: bool = False,
    ) -> bool:
        if bool(getattr(task, "_owned_execution_requeue_emitted", False)):
            return False
        if self._task_has_common_terminal_status(task):
            self._record_event(
                db,
                task,
                "runtime_recovery_skipped_for_common_terminal_task",
                "任务已进入常见终态，跳过 owned execution 接管重排队以避免重新打开主任务状态",
                level="info",
                stage_name=stage_name or task.current_stage,
                payload={
                    "reason": reason,
                    "task_status": str(getattr(task, "status", "") or "").strip() or None,
                    "runtime_phase": self._task_runtime_phase(task),
                    "current_operation_id": str(getattr(task, "current_operation_id", "") or "").strip() or None,
                    "recovery_action": "requeue_owned_execution_takeover",
                },
            )
            return False
        from app.service import task_manager as task_manager_module

        task_query = db.query(task_manager_module.BinarySecurityTask).filter(
            task_manager_module.BinarySecurityTask.id == str(getattr(task, "id", "") or "").strip()
        )
        with_for_update = getattr(task_query, "with_for_update", None)
        if callable(with_for_update):
            task_query = with_for_update()
        locked_task = task_query.first()
        if locked_task is not None:
            task = locked_task
        snapshot = self._parent_runtime_ownership_snapshot(db, task)
        preserve_guard = self._should_preserve_parent_runtime_ownership(snapshot, reason=reason)
        decision = self._can_reopen_parent_task_after_lease_loss(db, task, reason=reason)
        if not decision.allowed:
            if preserve_guard.preserve and preserve_guard.decision_reason == "transition_guard_active":
                preferred_stage_name = (
                    str(getattr(task, "_preferred_requeue_event_stage_name", "") or "").strip()
                    or (stage_name or task.current_stage)
                )
                self._apply_active_owned_execution_main_state(
                    db,
                    task,
                    source="runtime_state",
                    reason="owned execution 接管重排队被 transition guard 抑制，保持运行态",
                    status="running",
                    stage_name=str(preferred_stage_name or task.current_stage or "").strip() or None,
                    runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                    last_error=None,
                    record_blocked_event=False,
                )
                self._record_parent_runtime_lease_decision(
                    db,
                    task,
                    event_type=(
                        "cancel_takeover_suppressed_active_lease"
                        if decision.active_operation_type == "cancel"
                        else "delete_takeover_suppressed_active_lease"
                        if decision.active_operation_type == "delete"
                        else "retry_takeover_suppressed_active_lease"
                        if str(decision.active_operation_type or "").startswith("retry")
                        or decision.active_operation_type in {"continue", "force_reset_to_pending", task_manager_module.TASK_ACTION_FINISH_SUCCESS}
                        else "parent_runtime_reopen_suppressed_active_lease"
                    ),
                    message="父任务 row mirror 仍在保护窗口内，当前不允许重新排队接管",
                    decision=decision,
                    reason=reason,
                    stage_name=stage_name,
                )
                return False
            self._record_parent_runtime_lease_decision(
                db,
                task,
                event_type=(
                    "cancel_takeover_suppressed_active_lease"
                    if decision.active_operation_type == "cancel"
                    else "delete_takeover_suppressed_active_lease"
                    if decision.active_operation_type == "delete"
                    else "retry_takeover_suppressed_active_lease"
                    if str(decision.active_operation_type or "").startswith("retry")
                    or decision.active_operation_type in {"continue", "force_reset_to_pending", task_manager_module.TASK_ACTION_FINISH_SUCCESS}
                    else "parent_runtime_reopen_suppressed_active_lease"
                ),
                message="父任务租约仍有效，当前不允许重新排队接管",
                decision=decision,
                reason=reason,
                stage_name=stage_name,
            )
            return False
        setattr(task, "_owned_execution_requeue_emitted", True)
        event_stage_name = str(getattr(task, "_preferred_requeue_event_stage_name", "") or "").strip() or (stage_name or task.current_stage)
        if hasattr(task, "_preferred_requeue_event_stage_name"):
            setattr(task, "_preferred_requeue_event_stage_name", None)
        next_stage_name = str(stage_name or task.current_stage or "").strip() or None
        observed_owner = str(decision.runtime_lease_owner or "").strip() or None
        if observed_owner:
            clear_result = self._clear_runtime_lease(
                db,
                task.id,
                owner_instance_id=observed_owner,
                swallow_lock_error=True,
            )
            if clear_result.status == "lease_locked_retry_later":
                setattr(task, "_owned_execution_requeue_emitted", False)
                self._record_event(
                    db,
                    task,
                    "runtime_lease_clear_deferred_by_lock",
                    "runtime lease 清理遇到可重试锁冲突，当前轮延后接管重排队",
                    level="warning",
                    stage_name=event_stage_name,
                    payload={
                        "next_stage": next_stage_name,
                        "reason": reason,
                        "takeover_action": "requeue_owned_execution",
                        "runtime_lease_owner": observed_owner,
                        "clear_status": clear_result.status,
                        "clear_error_message": clear_result.error_message,
                    },
                )
                self._record_event(
                    db,
                    task,
                    "owned_execution_reclaim_deferred_by_lock",
                    "owned execution 接管修复遇到可重试锁冲突，当前轮延后重试",
                    level="warning",
                    stage_name=event_stage_name,
                    payload={
                        "next_stage": next_stage_name,
                        "reason": reason,
                        "runtime_lease_owner": observed_owner,
                        "takeover_action": "defer_requeue_owned_execution",
                    },
                )
                return False
        self._apply_release_for_takeover_main_state(
            db,
            task,
            source="runtime_state",
            reason="owned execution 接管重排队",
            status="running" if preserve_active_state else "pending",
            stage_name=next_stage_name,
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            finished_at=None,
            last_error=None,
        )
        task.tail_reconcile_state = "idle"
        self._last_task_heartbeat_at.pop(task.id, None)
        reopen_event_type, reopen_message = self._parent_runtime_reopen_allowed_event(
            decision,
            expired_message="父任务租约已过期，允许重新排队等待新的 owner 接管",
            missing_message="父任务租约已缺失，允许重新排队等待新的 owner 接管",
        )
        self._record_parent_runtime_lease_decision(
            db,
            task,
            event_type=reopen_event_type,
            message=reopen_message,
            decision=decision,
            reason=reason,
            stage_name=event_stage_name,
            level="warning",
        )
        self._record_event(
            db,
            task,
            event_type,
            message,
            level=event_level,
            stage_name=event_stage_name,
            payload={
                "next_stage": task.current_stage,
                "reason": reason,
                "takeover_reason": reason,
                "takeover_action": "requeue_owned_execution",
                **(event_payload or {}),
            },
        )
        self._sync_task_abnormal_reason_snapshot(db, task, None)
        signal_payload = self._remember_shared_dispatch_signal(
            task,
            signal_type="owned_execution_takeover",
            enqueue_context="shared_dispatch_owned_execution_takeover_enqueue",
            source="runtime_state._requeue_owned_execution_takeover",
            reason=reason,
            stage_name=event_stage_name,
            extra={
                "takeover_action": "requeue_owned_execution",
                "event_type": event_type,
            },
        )
        self._record_event(
            db,
            task,
            "shared_dispatch_signal_enqueued",
            "已向共享 dispatch 队列投递 owned execution 接管信号",
            level="info",
            stage_name=event_stage_name,
            payload={
                **signal_payload,
                "task_id": str(getattr(task, "id", "") or "").strip() or None,
                "signal_channel": "shared_dispatch",
            },
        )
        self._enqueue_task_with_context(task.id, context="shared_dispatch_owned_execution_takeover_enqueue")
        return True

    def _signal_owned_execution_takeover(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str | None,
        reason: str,
        message: str,
        event_type: str = "owned_execution_takeover_requeued",
        event_level: str = "warning",
        event_payload: dict[str, Any] | None = None,
    ) -> None:
        signal_stage_name = str(stage_name or task.current_stage or "").strip() or None
        self._record_event(
            db,
            task,
            event_type,
            message,
            level=event_level,
            stage_name=signal_stage_name,
            payload={
                "next_stage": signal_stage_name,
                "reason": reason,
                "takeover_reason": reason,
                "takeover_action": "signal_owned_execution",
                **(event_payload or {}),
            },
        )
        signal_payload = self._remember_shared_dispatch_signal(
            task,
            signal_type="owned_execution_signal",
            enqueue_context="shared_dispatch_owned_execution_signal_enqueue",
            source="runtime_state._signal_owned_execution_takeover",
            reason=reason,
            stage_name=signal_stage_name,
            extra={
                "takeover_action": "signal_owned_execution",
                "event_type": event_type,
            },
        )
        self._record_event(
            db,
            task,
            "shared_dispatch_signal_enqueued",
            "已向共享 dispatch 队列投递 owned execution 唤醒信号",
            level="info",
            stage_name=signal_stage_name,
            payload={
                **signal_payload,
                "task_id": str(getattr(task, "id", "") or "").strip() or None,
                "signal_channel": "shared_dispatch",
            },
        )
        self._enqueue_task_with_context(task.id, context="shared_dispatch_owned_execution_signal_enqueue")

    def _request_task_layer_reconcile(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str | None,
        source_event_type: str,
        state_event_id: str | None,
        reconcile_reason: str,
        message: str,
        event_type: str = "owned_execution_takeover_requeued",
        event_level: str = "warning",
        event_payload: dict[str, Any] | None = None,
    ) -> None:
        signal_stage_name = str(stage_name or task.current_stage or "").strip() or None
        delivery_decision = self._task_layer_reconcile_delivery_decision(
            db,
            task,
            source_event_type=source_event_type,
            reconcile_reason=reconcile_reason,
        )
        target_owner_instance_id = delivery_decision.target_owner_instance_id
        observe_only = delivery_decision.observe_only
        effective_event_type = str(event_type or "").strip() or "owned_execution_takeover_requeued"
        if observe_only and effective_event_type == "owned_execution_takeover_requeued":
            effective_event_type = (
                "owned_execution_owner_reconcile_requested"
                if delivery_decision.delivery_channel == "owner_inbox"
                else "task_layer_reconcile_shared_dispatch_requested"
            )
        self._merge_task_runtime_signal(
            task,
            "pending_task_layer_reconcile",
            source="owner_fact_apply",
            reason=reconcile_reason,
            stage_name=signal_stage_name,
            extra={
                "reconcile_mode": "observe_only" if observe_only else "allow_execution",
                "state_event_id": str(state_event_id or "").strip() or None,
                "source_event_type": str(source_event_type or "").strip() or None,
                "fact_applied": True,
                "reconcile_reason": reconcile_reason,
                **dict(event_payload or {}),
            },
        )
        self._record_event(
            db,
            task,
            effective_event_type,
            message,
            level=event_level,
            stage_name=signal_stage_name,
            payload={
                "next_stage": signal_stage_name,
                "reason": reconcile_reason,
                "takeover_reason": reconcile_reason,
                "takeover_action": (
                    "request_task_layer_reconcile"
                    if not observe_only
                    else "notify_owner_reconcile"
                    if delivery_decision.delivery_channel == "owner_inbox"
                    else "request_shared_dispatch_reconcile"
                ),
                "reconcile_mode": "observe_only" if observe_only else "allow_execution",
                "source_event_type": str(source_event_type or "").strip() or None,
                "state_event_id": str(state_event_id or "").strip() or None,
                "fact_applied": True,
                "reconcile_reason": reconcile_reason,
                "signal_channel": delivery_decision.delivery_channel,
                "delivery_channel": delivery_decision.delivery_channel,
                "decision_reason": delivery_decision.decision_reason,
                "target_owner_instance_id": target_owner_instance_id,
                "runtime_lease_owner": delivery_decision.runtime_lease_owner,
                "task_status": delivery_decision.task_status,
                "runtime_phase": delivery_decision.runtime_phase,
                **dict(event_payload or {}),
            },
        )
        self._record_event(
            db,
            task,
            "task_layer_reconcile_delivery_decided",
            "任务层 reconcile 唤醒投递决策已确定",
            level="info",
            stage_name=signal_stage_name,
            payload={
                "task_id": str(getattr(task, "id", "") or "").strip() or None,
                "source_event_type": str(source_event_type or "").strip() or None,
                "reconcile_reason": reconcile_reason,
                "delivery_channel": delivery_decision.delivery_channel,
                "decision_reason": delivery_decision.decision_reason,
                "target_owner_instance_id": target_owner_instance_id,
                "runtime_lease_owner": delivery_decision.runtime_lease_owner,
                "task_status": delivery_decision.task_status,
                "runtime_phase": delivery_decision.runtime_phase,
                "state_event_id": str(state_event_id or "").strip() or None,
            },
        )
        if delivery_decision.delivery_channel == "owner_inbox" and target_owner_instance_id:
            self._record_event(
                db,
                task,
                "owner_reconcile_signal_enqueued",
                "已向当前 owner worker 投递任务层收口唤醒信号"
                if observe_only
                else "已向当前 owner worker 投递可执行的任务层收口信号",
                level="info",
                stage_name=signal_stage_name,
                payload={
                    "task_id": str(getattr(task, "id", "") or "").strip() or None,
                    "target_owner_instance_id": target_owner_instance_id,
                    "local_instance_id": str(self.instance_id or "").strip() or None,
                    "signal_channel": delivery_decision.delivery_channel,
                    "reconcile_reason": reconcile_reason,
                    "decision_reason": delivery_decision.decision_reason,
                    "source_event_type": str(source_event_type or "").strip() or None,
                    "reconcile_mode": "observe_only" if observe_only else "allow_execution",
                },
            )
            self._enqueue_owner_signal(
                target_owner_instance_id,
                task.id,
                context="owner_reconcile_signal_enqueue",
            )
            return
        signal_payload = self._remember_shared_dispatch_signal(
            task,
            signal_type="task_layer_reconcile",
            enqueue_context="shared_dispatch_task_layer_reconcile_enqueue",
            source="runtime_state._request_task_layer_reconcile",
            reason=reconcile_reason,
            stage_name=signal_stage_name,
            extra={
                "source_event_type": str(source_event_type or "").strip() or None,
                "state_event_id": str(state_event_id or "").strip() or None,
                "decision_reason": delivery_decision.decision_reason,
                "delivery_channel": delivery_decision.delivery_channel,
                "reconcile_mode": "observe_only" if observe_only else "allow_execution",
            },
        )
        self._record_event(
            db,
            task,
            "shared_dispatch_signal_enqueued",
            "已向共享 dispatch 队列投递任务层 reconcile 信号",
            level="info",
            stage_name=signal_stage_name,
            payload={
                **signal_payload,
                "task_id": str(getattr(task, "id", "") or "").strip() or None,
                "signal_channel": "shared_dispatch",
            },
        )
        self._enqueue_task_with_context(task.id, context="shared_dispatch_task_layer_reconcile_enqueue")

    def _task_layer_reconcile_delivery_decision(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        source_event_type: str,
        reconcile_reason: str,
    ) -> TaskLayerReconcileDeliveryDecision:
        task_status = str(getattr(task, "status", "") or "").strip().lower() or None
        runtime_phase = str(self._task_runtime_phase(task) or "").strip() or None
        lease = self._runtime_lease_for_task(db, task.id)
        runtime_lease_owner = (
            str(getattr(lease, "owner_instance_id", "") or "").strip() or None
            if lease is not None and self._runtime_lease_is_active(lease)
            else None
        )
        source_event_type_normalized = str(source_event_type or "").strip() or None
        observe_only = not self._task_layer_reconcile_requires_execution(
            source_event_type=source_event_type_normalized,
            reconcile_reason=reconcile_reason,
        )

        target_owner_instance_id = runtime_lease_owner
        if runtime_lease_owner:
            return TaskLayerReconcileDeliveryDecision(
                delivery_channel="owner_inbox",
                observe_only=observe_only,
                decision_reason="active_runtime_lease_owner_present",
                target_owner_instance_id=target_owner_instance_id,
                runtime_lease_owner=runtime_lease_owner,
                task_status=task_status,
                runtime_phase=runtime_phase,
            )
        return TaskLayerReconcileDeliveryDecision(
            delivery_channel="shared_dispatch",
            observe_only=observe_only,
            decision_reason="runtime_lease_owner_missing_requires_shared_dispatch",
            target_owner_instance_id=target_owner_instance_id,
            runtime_lease_owner=runtime_lease_owner,
            task_status=task_status,
            runtime_phase=runtime_phase,
        )

    def _reconcile_lease_view(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[str | None, Any | None, str | None, str | None, int | None]:
        lease = self._runtime_lease_for_task(db, task.id)
        if lease is None:
            return None, None, None, None, None
        return (
            str(lease.owner_instance_id or "").strip() or None,
            lease.lease_expires_at,
            str(lease.owner_pod_uid or "").strip() or None,
            str(lease.owner_boot_id or "").strip() or None,
            lease.generation,
        )

    def _task_runtime_phase(self: TaskManager, task: BinarySecurityTask) -> str:
        value = str(getattr(task, "runtime_phase", "") or "").strip()
        if value in {
            TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            TASK_RUNTIME_PHASE_TERMINAL,
        }:
            return value
        status = str(getattr(task, "status", "") or "").strip().lower()
        if status in TASK_TERMINAL_STATUSES:
            return TASK_RUNTIME_PHASE_TERMINAL
        return TASK_RUNTIME_PHASE_OWNED_EXECUTION

    def _set_task_runtime_phase(self: TaskManager, task: BinarySecurityTask, phase: str) -> None:
        normalized = str(phase or "").strip() or TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.runtime_phase = normalized

    def _task_control_mode(self: TaskManager, task: BinarySecurityTask) -> str:
        if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TERMINAL:
            return TASK_RUNTIME_PHASE_TERMINAL
        return TASK_RUNTIME_PHASE_OWNED_EXECUTION

    def _task_has_live_runtime_lease(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        lease = self._runtime_lease_for_task(db, task.id)
        if not self._runtime_lease_is_active(lease):
            return False
        return True

    def _running_task_requires_live_runtime_lease(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        if str(getattr(task, "status", "") or "").strip().lower() != "running":
            return False
        phase = self._task_runtime_phase(task)
        if phase != TASK_RUNTIME_PHASE_OWNED_EXECUTION:
            return False
        return True

    def _running_task_has_valid_runtime_ownership(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        if not self._running_task_requires_live_runtime_lease(db, task):
            return True
        return self._task_has_live_runtime_lease(db, task)

    def _repair_running_lease_invariant(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        reason: str,
        stage_name: str | None = None,
        event_type: str = "running_without_active_lease_requeued",
        event_level: str = "warning",
        event_payload: dict[str, Any] | None = None,
    ) -> bool:
        if not self._running_task_requires_live_runtime_lease(db, task):
            return False
        snapshot = self._parent_runtime_ownership_snapshot(db, task)
        if snapshot.runtime_lease_active:
            return False
        guard = self._can_reclaim_parent_after_lease_loss(snapshot, reason=reason)
        if guard.preserve:
            self._record_event(
                db,
                task,
                "running_without_active_lease_repair_suppressed",
                "检测到 authoritative runtime ownership 仍需保留，暂不执行 lease invariant 修复",
                level="warning",
                stage_name=stage_name or str(task.current_stage or "").strip() or None,
                payload={
                    "decision_reason": guard.decision_reason,
                    **self._parent_runtime_ownership_snapshot_payload(snapshot, reason=reason),
                    **(event_payload or {}),
                },
            )
            return False
        decision = self._can_reopen_parent_task_after_lease_loss(db, task, reason=reason)
        if not decision.allowed:
            self._record_parent_runtime_lease_decision(
                db,
                task,
                event_type="parent_runtime_reopen_suppressed_active_lease",
                message="父任务租约仍有效，当前不允许因 lease invariant 修复而重新排队",
                decision=decision,
                reason=reason,
                stage_name=stage_name,
            )
            return False
        released = self._release_task_without_supported_runtime_owner(
            db,
            task,
            active_operation=None,
            reason=reason,
        )
        if not released:
            return False
        self._record_event(
            db,
            task,
            event_type,
            "检测到 running 任务缺少有效租约，已完成 stale owner 纠偏并同步补回共享调度队列",
            level=event_level,
            stage_name=str(stage_name or task.current_stage or "").strip() or None,
            payload={
                "reason": reason,
                "repair_action": "release_for_takeover_and_requeue",
                "enqueue_context": "owned_execution_release_for_takeover",
                **(event_payload or {}),
            },
        )
        return True
