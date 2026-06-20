from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.model import (
    BinarySecurityStageRun,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TERMINAL_STATUSES,
)
from app.schemas import BinarySecurityServiceConfigPayload, BinarySecurityServiceConfigResponse
from app.observability import (
    observe_tail_reconcile_heartbeat,
    observe_tail_reconcile_owner,
    observe_tail_reconcile_takeover,
)

if TYPE_CHECKING:
    from app.model import BinarySecurityTask
    from app.service.task_manager import TaskManager


class TaskRuntimeStateServiceMixin:
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
            max_concurrent_tasks=max(1, int(payload.get("max_concurrent_tasks") or default_max_concurrent)),
            dispatch_timeout_seconds=max(10, int(payload.get("dispatch_timeout_seconds") or default_dispatch_timeout)),
            lease_timeout_seconds=max(15, int(payload.get("lease_timeout_seconds") or default_lease_timeout)),
        )

    def get_service_config(self: TaskManager, db: Session) -> BinarySecurityServiceConfigResponse:
        config = self._load_service_config(db)
        payload = BinarySecurityServiceConfigPayload(
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
        if not self._is_reducer_role():
            return False
        return bool(
            self._state_reducer_loop_task
            and not self._state_reducer_loop_task.done()
            and self._reducer_metrics_snapshot_loop_task
            and not self._reducer_metrics_snapshot_loop_task.done()
        )

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
        return base

    def _max_retries_per_item(self: TaskManager, task: BinarySecurityTask) -> int:
        effective = self._effective_runtime_policy(task)
        value = effective.get("max_retries_per_item")
        try:
            return max(1, int(value if value is not None else 1))
        except Exception:
            return 1

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

        lease: BinarySecurityTaskRuntimeLease | None = None
        if db is not None:
            lease = self._runtime_lease_for_task(db, task.id)
        elif getattr(task, "lease_expires_at", None) is None:
            session = task_manager_module.get_session_factory()()
            try:
                lease = self._runtime_lease_for_task(session, task.id)
            finally:
                session.close()
        if lease is not None:
            return self._runtime_lease_is_active(lease)
        remaining = task_manager_module._seconds_until(task.lease_expires_at)
        return remaining is not None and remaining > 0

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
        if any(token in lowered for token in {"state event", "state reducer"}):
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
            if self._task_runtime_phase(task) == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                return (
                    lease.owner_instance_id,
                    lease.lease_expires_at,
                    "tail_runtime_lease",
                    lease.owner_pod_uid,
                    lease.owner_boot_id,
                    lease.generation,
                )
            return (
                lease.owner_instance_id,
                lease.lease_expires_at,
                "runtime_lease",
                lease.owner_pod_uid,
                lease.owner_boot_id,
                lease.generation,
            )
        return (
            str(task.dispatcher_instance_id or "").strip() or None,
            task.lease_expires_at,
            "legacy_task_row" if task.lease_expires_at is not None else None,
            None,
            None,
            None,
        )

    def _is_terminal_tail_item_with_only_residual_binding(self: TaskManager, item) -> bool:
        normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
        if normalized_status not in {"success", "failed", "cancelled", "downstream_missing", "partial_success"}:
            return False
        if not str(item.downstream_task_id or "").strip():
            return False
        if str(getattr(item, "claim_owner_instance_id", "") or "").strip():
            return False
        if str(getattr(item, "claim_execution_token", "") or "").strip():
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

    def _should_enter_tail_reconciliation(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        summary = self._tail_stage_work_summary(db, task)
        if summary.get("tail_control_mode") == "reconciliation":
            return True
        return bool(
            not summary.get("has_runnable_unbound_items")
            and int(summary.get("bound_active_item_count", 0) or 0) > 0
            and bool(summary.get("has_downstream_refs"))
        )

    def _activate_tail_reconciliation(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        now_value: Any | None = None,
        fallback_status: str | None = None,
        takeover_result: str | None = None,
    ) -> BinarySecurityTaskRuntimeLease | None:
        from app.service import task_manager as task_manager_module

        if not self._should_enter_tail_reconciliation(db, task):
            current_stage_name = str(task.current_stage or "").strip()
            if not self._is_streaming_tail_stage(task, current_stage_name):
                return None
            current_stage_items = self._stage_items(db, task.id, current_stage_name)
            has_active_tail_items = any(
                (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower())
                in {"pending", "queued", "dispatching", "running"}
                or str(item.downstream_task_id or "").strip()
                for item in current_stage_items
            )
            if not has_active_tail_items:
                return None
        current_now = now_value or task_manager_module._now()
        self._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_TAIL_RECONCILIATION)
        task.tail_reconcile_state = "handoff_waiting"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        lease = self._maybe_upsert_runtime_lease(
            db,
            task,
            now_value=current_now,
            owner_instance_id=self.instance_id,
            owner_pod_uid=self.owner_pod_uid,
            owner_boot_id=self.owner_boot_id,
            generation=self._owner_generation,
            owner_started_at=self.owner_started_at,
        )
        lease_owner = str(lease.owner_instance_id or "").strip() if lease is not None else ""
        if self._runtime_lease_is_active(lease) and lease_owner == str(self.instance_id or "").strip():
            if self._is_reducer_role():
                task.tail_reconcile_state = "active"
                self._acquire_tail_reconcile_owner(task.id)
            if takeover_result:
                observe_tail_reconcile_takeover(takeover_result)
            self._tail_reconcile_handoff_reason.pop(task.id, None)
            self._record_event(
                db,
                task,
                "tail_reconcile_handoff_completed",
                f"tail 收口接管完成: {task.id}",
                level="info",
                payload={
                    "lease_owner": lease_owner,
                    "lease_generation": int(getattr(lease, "generation", 0) or 0),
                    "owner_pod_uid": getattr(lease, "owner_pod_uid", None),
                    "owner_boot_id": getattr(lease, "owner_boot_id", None),
                },
            )
            return lease
        self._release_tail_reconcile_owner(task.id)
        self._tail_reconcile_handoff_reason[task.id] = "owner_conflict"
        conflict_payload = {
            "lease_owner": lease_owner or None,
            "lease_generation": int(getattr(lease, "generation", 0) or 0) if lease is not None else None,
            "owner_pod_uid": getattr(lease, "owner_pod_uid", None) if lease is not None else None,
            "owner_boot_id": getattr(lease, "owner_boot_id", None) if lease is not None else None,
        }
        conflict_message = f"tail 收口 owner 冲突: {task.id}"
        if not self._has_recent_matching_task_event(
            db,
            task,
            event_type="tail_reconcile_owner_conflict",
            stage_name=task.current_stage,
            message=conflict_message,
            payload_keys=conflict_payload,
            within_seconds=60,
        ):
            self._record_event(
                db,
                task,
                "tail_reconcile_owner_conflict",
                conflict_message,
                level="warning",
                payload=conflict_payload,
            )
        if fallback_status is not None:
            if self._is_streaming_tail_stage(task, task.current_stage):
                task.status = "running"
            else:
                task.status = fallback_status
        task.tail_reconcile_state = "handoff_waiting"
        observe_tail_reconcile_heartbeat("handoff")
        observe_tail_reconcile_owner("handoff_started")
        handoff_message = f"tail 收口 handoff 开始: {task.id}"
        if not self._has_recent_matching_task_event(
            db,
            task,
            event_type="tail_reconcile_handoff_started",
            stage_name=task.current_stage,
            message=handoff_message,
            payload_keys=conflict_payload,
            within_seconds=60,
        ):
            self._record_event(
                db,
                task,
                "tail_reconcile_handoff_started",
                handoff_message,
                level="info",
                payload=conflict_payload,
            )
        if takeover_result:
            observe_tail_reconcile_takeover("conflict")
        return lease

    def _should_preserve_tail_runtime_lease(self: TaskManager, db: Session, task: BinarySecurityTask | None) -> bool:
        if task is None:
            return False
        if self._task_runtime_phase(task) != TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
            return False
        if str(task.status or "").strip().lower() in TASK_TERMINAL_STATUSES:
            return False
        lease = self._runtime_lease_for_task(db, task.id)
        if (
            self._runtime_lease_is_active(lease)
            and str(lease.owner_instance_id or "").strip() == str(self.instance_id or "").strip()
        ):
            return True
        return self._has_tail_reconcile_owner(task.id)

    def _tail_reconcile_state(self: TaskManager, task: BinarySecurityTask | None) -> str:
        if task is None:
            return "idle"
        raw = str(getattr(task, "tail_reconcile_state", "") or "").strip().lower()
        if raw in {"active", "handoff_waiting", "idle"}:
            return raw
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
    ) -> None:
        if bool(getattr(task, "_owned_execution_requeue_emitted", False)):
            return
        setattr(task, "_owned_execution_requeue_emitted", True)
        event_stage_name = str(getattr(task, "_preferred_requeue_event_stage_name", "") or "").strip() or (stage_name or task.current_stage)
        if hasattr(task, "_preferred_requeue_event_stage_name"):
            setattr(task, "_preferred_requeue_event_stage_name", None)
        task.current_stage = stage_name or task.current_stage
        task.status = "pending"
        self._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_OWNED_EXECUTION)
        task.tail_reconcile_state = "idle"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        task.finished_at = None
        task.last_error = None
        self._clear_runtime_lease(db, task.id)
        self._release_tail_reconcile_owner(task.id)
        self._last_task_heartbeat_at.pop(task.id, None)
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
        self._enqueue_task(task.id)

    def _reconcile_lease_view(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[str | None, Any | None, str | None, str | None, int | None]:
        if self._task_runtime_phase(task) != TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
            return None, None, None, None, None
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
            TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
            TASK_RUNTIME_PHASE_TERMINAL,
        }:
            return value
        status = str(getattr(task, "status", "") or "").strip().lower()
        if status in TASK_TERMINAL_STATUSES:
            return TASK_RUNTIME_PHASE_TERMINAL
        return TASK_RUNTIME_PHASE_OWNED_EXECUTION

    def _set_task_runtime_phase(self: TaskManager, task: BinarySecurityTask, phase: str) -> None:
        task.runtime_phase = str(phase or "").strip() or TASK_RUNTIME_PHASE_OWNED_EXECUTION

    def _task_control_mode(self: TaskManager, task: BinarySecurityTask) -> str:
        phase = self._task_runtime_phase(task)
        if phase == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
            return TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
        if phase == TASK_RUNTIME_PHASE_TERMINAL:
            return TASK_RUNTIME_PHASE_TERMINAL
        return TASK_RUNTIME_PHASE_OWNED_EXECUTION
