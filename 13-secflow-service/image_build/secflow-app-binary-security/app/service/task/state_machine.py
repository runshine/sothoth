from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    normalize_stage_name,
)

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskStateMachineMixin:
    def _partial_success_advancement_enabled(
        self: TaskManager,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
        policy: dict[str, Any] = {}
        if isinstance(getattr(task, "policy", None), dict):
            policy = dict(task.policy or {})
        elif isinstance(getattr(task, "policy_json", None), str) and str(task.policy_json or "").strip():
            try:
                import json

                loaded = json.loads(task.policy_json)
                if isinstance(loaded, dict):
                    policy = loaded
            except Exception:
                policy = {}
        partial_success = dict(policy.get("partial_success_stage_advancement") or {})
        normalized_stage = normalize_stage_name(stage_name)
        if normalized_stage in partial_success:
            return bool(partial_success.get(normalized_stage))
        return False

    def _ensure_task_remains_cancelling(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        active_cancel_operation: BinarySecurityTaskOperation | None = None,
    ) -> BinarySecurityTaskOperation | None:
        from app.service import task_manager as task_manager_module

        operation = active_cancel_operation or self._active_cancel_operation(db, task.id)
        if operation is None:
            return None
        task.status = task_manager_module.TASK_STATUS_CANCELLING
        task.finished_at = None
        task.last_error = None
        task.current_operation_id = operation.id
        self._invalidate_task_execution(task)
        return operation

    def _recover_failed_cancelled_task_state(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        if str(task.status or "").strip() != task_manager_module.TASK_STATUS_CANCELLING:
            return False
        operation = self._latest_cancel_operation(db, task.id)
        if operation is None:
            return False
        if str(operation.operation_type or "").strip() != task_manager_module.TASK_ACTION_CANCEL:
            return False
        if str(operation.status or "").strip() in task_manager_module.TASK_OPERATION_ACTIVE_STATUSES:
            return False
        if str(operation.status or "").strip() != "failed":
            return False
        task.status = task_manager_module.TASK_STATUS_CANCEL_FAILED
        task.finished_at = task.finished_at or task_manager_module._now()
        task.last_error = str(operation.error_message or task.last_error or "cancel operation failed")
        task.current_operation_id = operation.id
        self._invalidate_task_execution(task)
        return True

    @staticmethod
    def _clear_failure_fields_from_summary(summary: dict[str, Any]) -> dict[str, Any]:
        cleaned = dict(summary or {})
        for key in ("failure_code", "failure_category", "failure_message", "error"):
            cleaned.pop(key, None)
        return cleaned

    @staticmethod
    def _task_status_is_terminal(status: str | None) -> bool:
        return str(status or "").strip() in {"success", "failed", "downstream_missing", "partial_success", "cancelled"}

    def _stage_failure_snapshot(
        self: TaskManager,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        candidates: list[dict[str, Any]] = []
        if stage_run is not None:
            candidates.append(task_manager_module._failure_shape(stage_run.output_summary))
        summary = task_manager_module._failure_shape(task.summary)
        stage_name = str(getattr(stage_run, "stage_name", "") or "").strip()
        if stage_name:
            candidates.append(task_manager_module._failure_shape(summary.get(stage_name)))
        candidates.append(summary)

        merged: dict[str, Any] = {}
        for payload in candidates:
            for key in ("failure_code", "failure_category", "failure_message", "error", "sync_status", "status_synced"):
                value = payload.get(key)
                if value is not None and value != "":
                    merged.setdefault(key, value)
        return merged

    def _is_terminal_business_stage_failure(
        self: TaskManager,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None,
    ) -> bool:
        snapshot = self._stage_failure_snapshot(task, stage_run)
        return str(snapshot.get("failure_category") or "").strip() == "business"

    def _record_business_failure_terminalization(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None,
    ) -> None:
        from app.service import task_manager as task_manager_module

        snapshot = self._stage_failure_snapshot(task, stage_run)
        stage_name = str(getattr(stage_run, "stage_name", "") or task.current_stage or "").strip() or None
        payload = {
            "stage_name": stage_name,
            "failure_code": snapshot.get("failure_code"),
            "failure_category": snapshot.get("failure_category"),
            "failure_message": snapshot.get("failure_message") or snapshot.get("error"),
            "requeue_suppressed": True,
        }
        existing = (
            db.query(task_manager_module.BinarySecurityEvent)
            .filter(
                task_manager_module.BinarySecurityEvent.task_id == task.id,
                task_manager_module.BinarySecurityEvent.event_type == "task_finalized_after_business_failure",
                task_manager_module.BinarySecurityEvent.stage_name == stage_name,
            )
            .order_by(task_manager_module.BinarySecurityEvent.created_at.desc())
            .first()
        )
        existing_payload = dict(getattr(existing, "payload", None) or {}) if existing is not None else {}
        if (
            existing is not None
            and str(existing_payload.get("failure_code") or "").strip() == str(payload.get("failure_code") or "").strip()
            and str(existing_payload.get("failure_category") or "").strip() == str(payload.get("failure_category") or "").strip()
        ):
            return
        self._record_event(
            db,
            task,
            "task_finalized_after_business_failure",
            "业务终态失败已直接收口，不再进入补偿重排",
            level="warning",
            stage_name=stage_name,
            payload=payload,
        )
        task_manager_module.logger.info(
            "binary-security business failure requeue suppressed task_id=%s stage_name=%s failure_code=%s failure_category=%s decision=terminal_failed requeue_suppressed=true",
            task.id,
            stage_name or "-",
            payload.get("failure_code") or "-",
            payload.get("failure_category") or "-",
        )

    def _should_terminalize_parent_for_failed_stage(
        self: TaskManager,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun | None,
    ) -> bool:
        if stage_run is None or str(stage_run.status or "").strip() != "failed":
            return False
        error_text = " ".join(
            str(part or "").strip()
            for part in (
                stage_run.last_error,
                getattr(stage_run, "error_message", None),
                getattr(stage_run, "reason", None),
            )
            if str(part or "").strip()
        )
        if self._is_owner_lost_recoverable_failure(
            failure_message=error_text,
            failure_category=self._stage_failure_snapshot(task, stage_run).get("failure_category"),
        ):
            return False
        if "task owner pod lost" in error_text.lower() or "owner pod lost" in error_text.lower():
            return True
        return False

    def _current_stage_authoritative_failure_context(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
    ) -> dict[str, Any] | None:
        stage_name = str(task.current_stage or "").strip()
        if not stage_name:
            return None
        if stage_runs is None:
            stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        stage_run = next((run for run in stage_runs if str(run.stage_name or "").strip() == stage_name), None)
        if str(task.status or "").strip() == "failed":
            failure_message = str(task.last_error or "").strip()
            if failure_message and ("总任务产物归档失败" in failure_message or "archive" in failure_message.lower()):
                return {
                    "stage_name": stage_name,
                    "stage_run": stage_run,
                    "failure_code": "stage_archive_blocked",
                    "failure_category": "archive_blocked",
                    "failure_message": failure_message,
                    "reason": "authoritative_archive_blocked",
                }
        if stage_run is not None and self._should_terminalize_parent_for_failed_stage(task, stage_run):
            snapshot = self._stage_failure_snapshot(task, stage_run)
            return {
                "stage_name": stage_name,
                "stage_run": stage_run,
                "failure_code": snapshot.get("failure_code"),
                "failure_category": snapshot.get("failure_category"),
                "failure_message": snapshot.get("failure_message") or snapshot.get("error") or stage_run.last_error,
                "reason": "stage_run_failed",
            }
        items = self._stage_items(db, task.id, stage_name)
        if not items:
            return None
        normalized_statuses = [
            self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
            for item in items
        ]
        if any(status in {"pending", "queued", "running", "dispatching"} for status in normalized_statuses):
            return None
        aggregate_status = self._aggregate_item_statuses(normalized_statuses)
        if aggregate_status not in {"failed", "cancelled", "downstream_missing", "partial_success"}:
            return None
        snapshot = self._stage_failure_snapshot(task, stage_run)
        if aggregate_status == "failed":
            exhausted_owner_lost_items = [item for item in items if self._owner_lost_retry_exhausted(task, item)]
            if exhausted_owner_lost_items:
                exhausted_item = exhausted_owner_lost_items[0]
                return {
                    "stage_name": stage_name,
                    "stage_run": stage_run,
                    "failure_code": "owner_lost_retry_exhausted",
                    "failure_category": "infrastructure",
                    "failure_message": str(exhausted_item.error_message or "").strip() or "owner_lost_retry_exhausted",
                    "reason": "owner_lost_retry_exhausted",
                }
            for item in items:
                if self._is_owner_lost_recoverable_failure(
                    failure_message=str(item.error_message or "").strip() or None,
                    failure_category=snapshot.get("failure_category"),
                    error_type=self._stage_item_sync_error_type_value(item),
                    item=item,
                ):
                    return None
        failure_message = next((str(item.error_message or "").strip() for item in items if str(item.error_message or "").strip()), None)
        return {
            "stage_name": stage_name,
            "stage_run": stage_run,
            "failure_code": snapshot.get("failure_code"),
            "failure_category": snapshot.get("failure_category"),
            "failure_message": snapshot.get("failure_message") or snapshot.get("error") or failure_message or getattr(stage_run, "last_error", None),
            "reason": "authoritative_stage_items_terminal",
        }

    def _earlier_stage_authoritative_failure_context(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
    ) -> dict[str, Any] | None:
        current_stage = str(task.current_stage or "").strip()
        if not current_stage:
            return None
        if stage_runs is None:
            stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        ordered_stage_names = [
            str(name or "").strip()
            for name in self._stage_sequence_for_task(task)
            if str(name or "").strip()
        ]
        try:
            current_index = ordered_stage_names.index(current_stage)
        except ValueError:
            return None
        for stage_name in reversed(ordered_stage_names[:current_index]):
            stage_run = next((run for run in stage_runs if str(run.stage_name or "").strip() == stage_name), None)
            if stage_run is not None and self._should_terminalize_parent_for_failed_stage(task, stage_run):
                snapshot = self._stage_failure_snapshot(task, stage_run)
                return {
                    "stage_name": stage_name,
                    "stage_run": stage_run,
                    "failure_code": snapshot.get("failure_code"),
                    "failure_category": snapshot.get("failure_category"),
                    "failure_message": snapshot.get("failure_message") or snapshot.get("error") or stage_run.last_error,
                    "reason": "earlier_stage_run_failed",
                }
            items = self._stage_items(db, task.id, stage_name)
            if not items:
                continue
            normalized_statuses = [
                self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
                for item in items
            ]
            if any(status in {"pending", "queued", "running", "dispatching"} for status in normalized_statuses):
                continue
            aggregate_status = self._aggregate_item_statuses(normalized_statuses)
            if aggregate_status not in {"failed", "cancelled", "downstream_missing", "partial_success"}:
                continue
            if aggregate_status == "failed":
                snapshot = self._stage_failure_snapshot(task, stage_run)
                exhausted_owner_lost_items = [item for item in items if self._owner_lost_retry_exhausted(task, item)]
                if exhausted_owner_lost_items:
                    exhausted_item = exhausted_owner_lost_items[0]
                    return {
                        "stage_name": stage_name,
                        "stage_run": stage_run,
                        "failure_code": "owner_lost_retry_exhausted",
                        "failure_category": "infrastructure",
                        "failure_message": str(exhausted_item.error_message or "").strip() or "owner_lost_retry_exhausted",
                        "reason": "owner_lost_retry_exhausted",
                    }
                recoverable_items = [
                    item for item in items
                    if self._is_owner_lost_recoverable_failure(
                        failure_message=str(item.error_message or "").strip() or None,
                        failure_category=snapshot.get("failure_category"),
                        error_type=self._stage_item_sync_error_type_value(item),
                        item=item,
                    )
                ]
                if recoverable_items:
                    continue
            snapshot = self._stage_failure_snapshot(task, stage_run)
            failure_message = next((str(item.error_message or "").strip() for item in items if str(item.error_message or "").strip()), None)
            return {
                "stage_name": stage_name,
                "stage_run": stage_run,
                "failure_code": snapshot.get("failure_code"),
                "failure_category": snapshot.get("failure_category"),
                "failure_message": snapshot.get("failure_message") or snapshot.get("error") or failure_message or getattr(stage_run, "last_error", None),
                "reason": "earlier_stage_items_terminal",
            }
        return None

    def _later_stage_names(self: TaskManager, task: BinarySecurityTask, stage_name: str | None) -> list[str]:
        current_stage = str(stage_name or "").strip()
        if not current_stage:
            return []
        sequence = [str(name or "").strip() for name in self._stage_sequence_for_task(task) if str(name or "").strip()]
        try:
            current_index = sequence.index(current_stage)
        except ValueError:
            return []
        return sequence[current_index + 1 :]

    def _suppress_later_stage_items_after_archive_blocked(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str,
        error_message: str,
        archive_job_id: str | None = None,
        downstream_task_id: str | None = None,
    ) -> list[str]:
        from app.service import task_manager as task_manager_module

        blocked_item_ids: list[str] = []
        blocked_stages = self._later_stage_names(task, stage_name)
        if not blocked_stages:
            return blocked_item_ids
        blocked_at = task_manager_module._now()
        for blocked_stage_name in blocked_stages:
            touched_stage = False
            for item in self._stage_items(db, task.id, blocked_stage_name):
                if not self._is_active_item_status(item.status):
                    continue
                touched_stage = True
                item.status = "skipped"
                item.error_message = error_message
                item.finished_at = blocked_at
                result_payload = self._merge_stage_item_result(
                    item,
                    {
                        "blocked_by_upstream_archive_failure": True,
                        "blocked_from_stage": stage_name,
                        "blocked_reason": error_message,
                        "blocked_at": task_manager_module._isoformat_or_none(blocked_at),
                        "blocking_archive_job_id": archive_job_id,
                        "blocking_downstream_task_id": downstream_task_id,
                    },
                )
                self._clear_stage_item_sync_observation_errors(
                    item,
                    result_payload=result_payload,
                    touched=False,
                )
                blocked_item_ids.append(str(item.id or ""))
                self._record_event(
                    db,
                    task,
                    "downstream_stage_item_blocked_after_archive_failure",
                    f"上游阶段归档失败，已阻断后续阶段项: {blocked_stage_name}:{item.item_key}",
                    level="warning",
                    stage_name=blocked_stage_name,
                    item=item,
                    payload={
                        "blocked_from_stage": stage_name,
                        "blocking_archive_job_id": archive_job_id,
                        "blocking_downstream_task_id": downstream_task_id,
                        "blocked_reason": error_message,
                    },
                )
            if touched_stage:
                self._refresh_stage_from_authoritative_items(db, task, blocked_stage_name)
        return blocked_item_ids

    def _finalize_task_after_authoritative_failure(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        failure_ctx: dict[str, Any],
        previous_status: str | None = None,
        event_type: str = "dispatching_state_force_terminalized",
    ) -> None:
        from app.service import task_manager as task_manager_module

        stage_name = str(failure_ctx.get("stage_name") or task.current_stage or "").strip() or None
        failure_code = self._string_or_none(failure_ctx.get("failure_code"))
        failure_category = self._string_or_none(failure_ctx.get("failure_category"))
        failure_message = self._string_or_none(failure_ctx.get("failure_message")) or task.last_error
        stage_run = failure_ctx.get("stage_run")
        task.status = "failed"
        if stage_name:
            task.current_stage = stage_name
        task.finished_at = task.finished_at or task_manager_module._now()
        task.last_error = failure_message
        self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        self._record_event(
            db,
            task,
            event_type,
            "检测到当前阶段已进入终态失败，父任务已自动结束 dispatching 收口",
            level="warning",
            stage_name=stage_name,
            payload={
                "stage_name": stage_name,
                "failure_code": failure_code,
                "failure_category": failure_category,
                "failure_message": failure_message,
                "previous_status": previous_status,
                "reason": self._string_or_none(failure_ctx.get("reason")),
            },
        )
        if str(failure_category or "").strip() == "business":
            self._record_business_failure_terminalization(db, task, stage_run)
        else:
            self._record_event(
                db,
                task,
                "task_finalized_after_child_failure",
                "下游子任务已终态失败，父任务已直接收口为 failed",
                level="warning",
                stage_name=stage_name,
                payload={
                    "stage_name": stage_name,
                    "failure_code": failure_code,
                    "failure_category": failure_category,
                    "failure_message": failure_message,
                    "requeue_suppressed": True,
                },
            )
        if failure_code == "owner_lost_retry_exhausted":
            self._sync_task_abnormal_reason_snapshot(
                db,
                task,
                self._build_abnormal_reason(
                    category="infrastructure",
                    code="owner_lost_retry_exhausted",
                    title="下游 owner 丢失自动恢复失败",
                    message=failure_message or "下游 owner 丢失自动恢复次数耗尽",
                    source_layer="task",
                    status="failed",
                    service="binary-security",
                    stage_name=stage_name,
                    evidence=[
                        self._abnormal_reason_evidence("current_stage", "当前阶段", stage_name),
                        self._abnormal_reason_evidence("last_error", "原始错误", failure_message),
                    ],
                    recommended_action="检查 rollout、worker 与 lease 变更，并手工重试或排查下游恢复能力。",
                    terminal=True,
                ),
            )
        else:
            self._clear_task_abnormal_reason_snapshot(db, task)
    def _next_incomplete_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> str | None:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        runs_by_stage = {run.stage_name: run for run in stage_runs}
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            upstream_retried, _ = self._upstream_stage_retried(db, task, stage_name)
            if upstream_retried:
                continue
            run = runs_by_stage.get(stage_name)
            if run is None:
                if self._should_finalize_without_entries(db, task, stage_name):
                    continue
                if self._should_skip_stage_without_runnable_work(db, task, stage_name):
                    continue
                return stage_name
            items = self._stage_items(db, task.id, stage_name)
            if items:
                item_status = self._aggregate_item_statuses([item.status for item in items])
                if item_status in {"pending", "queued", "running", "dispatching"}:
                    return stage_name
                if self._stage_has_nonterminal_items(items):
                    return stage_name
                if self._stage_archive_success_blocked(task, stage_name, items, db=db):
                    return stage_name
            elif self._should_skip_stage_without_runnable_work(db, task, stage_name):
                continue
            if self._should_finalize_without_entries(db, task, stage_name):
                continue
            if run.status == "partial_success":
                if not self._partial_success_advancement_enabled(task, stage_name):
                    return stage_name
                continue
            normalized_status = self._normalize_downstream_status(run.status) or str(run.status or "").strip()
            if (
                normalized_status in {"pending", "queued", "running", "dispatching"}
                and self._is_streaming_tail_stage(task, stage_name)
                and not items
            ):
                if str(task.status or "").strip() in {"pending", "queued", "running", "dispatching"}:
                    continue
                return stage_name
            if normalized_status in {"pending", "queued", "running", "dispatching"}:
                return stage_name
            if normalized_status not in {"success", "failed", "cancelled", "downstream_missing", "partial_success", "skipped"}:
                return stage_name
        return None

    def _should_skip_stage_without_runnable_work(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        handler = self._stage_handler(normalized_stage)
        if handler is not None and handler.should_skip_without_runnable_work(self, db, task):
            return True
        if normalized_stage not in {"entry_analysis", "dataflow_vuln_scan"}:
            return False
        if self._stage_items(db, task.id, stage_name):
            return False
        return bool(self._continue_stage_input_error(db, task, stage_name))

    def _should_finalize_without_entries(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        if normalized_stage == "entry_analysis":
            return not bool(self._effective_entry_inputs(task))
        if normalized_stage == "dataflow_vuln_scan":
            return not bool(self._entry_results(task))
        return False

    def _first_failed_terminal_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> str | None:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        runs_by_stage = {str(run.stage_name or "").strip(): run for run in stage_runs}
        failure_statuses = {"failed", "downstream_missing", "cancelled", "partial_success"}
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            items = self._stage_items(db, task.id, stage_name)
            if any(self._normalize_item_status(item.status) in {"failed", "cancelled", "downstream_missing"} for item in items):
                return stage_name
            run = runs_by_stage.get(stage_name)
            if run is None:
                continue
            normalized_status = self._normalize_downstream_status(run.status) or str(run.status or "").strip()
            if normalized_status not in failure_statuses:
                continue
            if items and self._stage_has_nonterminal_items(items):
                continue
            return stage_name
        return None

    def _reconcile_task_summary_in_session(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ):
        self._refresh_task_status_after_sync(db, task)
        return self._task_state_snapshot(task)

    def _reconcile_after_item_layer_update_in_session(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str,
        preferred_stage_name: str | None = None,
        reason: str,
        message: str,
        payload: dict[str, Any] | None = None,
        event_type: str = "owned_execution_takeover_requeued",
    ):
        stage_run = self._reconcile_stage_domain_in_session(db, task, stage_name)
        snapshot = self._reconcile_task_summary_in_session(db, task)
        decision = self._decide_owned_execution_requeue(
            db,
            task,
            preferred_stage_name=preferred_stage_name,
            reason=reason,
            message=message,
            payload=payload,
        )
        self._apply_task_layer_decision(db, task, decision, event_type=event_type)
        return stage_run, snapshot, decision

    def _next_active_owned_execution_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        exclude_stage: str | None = None,
    ) -> BinarySecurityStageRun | None:
        return self._next_authoritative_active_stage(db, task, exclude_stage=exclude_stage)

    def _has_authoritative_active_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        exclude_stage: str | None = None,
    ) -> bool:
        return self._next_authoritative_active_stage(db, task, exclude_stage=exclude_stage) is not None

    def _next_authoritative_active_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        exclude_stage: str | None = None,
    ) -> BinarySecurityStageRun | None:
        excluded = str(exclude_stage or "").strip()
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        for run in stage_runs:
            current_stage_name = str(run.stage_name or "").strip()
            if excluded and current_stage_name == excluded:
                continue
            current_status = str(run.status or "").strip()
            if current_status not in {"pending", "queued", "running", "dispatching"}:
                continue
            return run
        return None

    def _decide_owned_execution_requeue(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        preferred_stage_name: str | None = None,
        reason: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ):
        from app.service import task_manager as task_manager_module

        decision = task_manager_module._TaskLayerDecision()
        if self._task_runtime_phase(task) != TASK_RUNTIME_PHASE_OWNED_EXECUTION:
            return decision
        if self._has_active_owned_execution_holder(db, task):
            return decision
        active_stage = self._next_active_owned_execution_stage(
            db,
            task,
            exclude_stage=preferred_stage_name,
        )
        if active_stage is None:
            return decision
        active_stage_name = str(active_stage.stage_name or "").strip() or None
        active_stage_status = str(active_stage.status or "").strip() or None
        if not self._should_requeue_for_owned_execution(
            db,
            task,
            next_stage=active_stage_name,
            next_stage_status=active_stage_status,
        ):
            return decision
        decision.owned_execution_requeue_required = True
        decision.owned_execution_requeue_stage_name = active_stage_name
        decision.owned_execution_requeue_reason = reason
        decision.owned_execution_requeue_message = message
        decision.owned_execution_requeue_payload = {
            **(payload or {}),
            "next_stage_status": active_stage_status,
        }
        return decision

    def _apply_task_layer_decision(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        decision,
        *,
        event_type: str = "owned_execution_takeover_requeued",
    ):
        if decision.owned_execution_requeue_required:
            self._requeue_owned_execution_takeover(
                db,
                task,
                stage_name=decision.owned_execution_requeue_stage_name,
                reason=str(decision.owned_execution_requeue_reason or "").strip() or "owned_execution_without_active_holder",
                event_type=event_type,
                message=str(decision.owned_execution_requeue_message or "").strip() or "检测到执行接管悬空，已重新排队等待 worker 接管",
                event_payload=decision.owned_execution_requeue_payload,
            )
            decision.changed = True
        return decision

    def _decide_task_resume_after_stage_reset(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        next_stage: str | None,
        resume_reason: str,
        source: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ):
        from app.service import task_manager as task_manager_module

        decision = task_manager_module._TaskResumeDecision(
            resume_reason=resume_reason,
            source=source,
            message=message,
            event_type="task_requeued",
            payload=dict(payload or {}),
        )
        normalized_next_stage = str(next_stage or "").strip() or None
        if not normalized_next_stage:
            return decision
        if not self._should_auto_advance_to_stage(db, task, normalized_next_stage):
            blocked_reason = self._continue_stage_input_error(db, task, normalized_next_stage)
            decision.event_type = "task_resume_blocked"
            decision.payload = {
                **dict(payload or {}),
                "next_stage": normalized_next_stage,
                "resume_reason": resume_reason,
                "source": source,
                "authoritative_active_progress": False,
                "blocked_reason": blocked_reason,
            }
            return decision
        decision.should_resume = True
        decision.next_stage = normalized_next_stage
        has_authoritative_progress = self._has_authoritative_active_stage(
            db,
            task,
            exclude_stage=normalized_next_stage,
        )
        decision.owned_execution_requeue_required = bool(has_authoritative_progress)
        decision.payload = {
            **dict(payload or {}),
            "next_stage": normalized_next_stage,
            "resume_reason": resume_reason,
            "source": source,
            "authoritative_active_progress": has_authoritative_progress,
        }
        return decision

    def _apply_task_resume_decision(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        decision,
        *,
        operation: BinarySecurityTaskOperation | None = None,
    ) -> bool:
        if not decision.should_resume or not decision.next_stage:
            return False
        task.status = "pending"
        task.current_stage = decision.next_stage
        task.last_error = None
        task.finished_at = None
        task.summary = self._clear_failure_fields_from_summary(dict(task.summary or {}))
        self._clear_task_abnormal_reason_snapshot(db, task)
        self._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_OWNED_EXECUTION)
        self._invalidate_task_execution(task)
        if operation is not None:
            self._update_operation_result_payload(
                operation,
                {
                    "requeue": {
                        "requested": True,
                        "task_status_before": "retry_operation_succeeded",
                        "task_status_after": task.status,
                        "resume_reason": decision.resume_reason,
                        "source": decision.source,
                    },
                },
                workspace_root=task.workspace_root,
            )
            self._record_operation_event(
                db,
                task,
                operation,
                decision.event_type or "task_requeued",
                decision.message or f"任务已重新排队: {operation.operation_type}",
                stage_name=decision.next_stage,
                payload=dict(decision.payload or {}),
            )
        else:
            self._record_event(
                db,
                task,
                decision.event_type or "task_requeued",
                decision.message or f"任务已重新排队: {decision.next_stage}",
                stage_name=decision.next_stage,
                payload=dict(decision.payload or {}),
            )
        self._enqueue_task(task.id)
        return True

    def _should_auto_advance_to_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        next_stage: str | None,
    ) -> bool:
        normalized_stage = str(next_stage or "").strip()
        if not normalized_stage:
            return False
        existing_items = self._stage_items(db, task.id, normalized_stage)
        if existing_items:
            return True
        existing_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == normalized_stage,
        ).first()
        if existing_run is not None:
            normalized_status = self._normalize_downstream_status(existing_run.status) or str(existing_run.status or "").strip()
            if normalized_status in {"pending", "queued", "running", "dispatching", "applying"}:
                return True
        if self._should_skip_stage_without_runnable_work(db, task, normalized_stage):
            return False
        return self._stage_has_real_runnable_work(db, task, normalized_stage) or self._stage_has_materialized_inputs(db, task, normalized_stage)

    def _stage_retry_failed_items_support(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> tuple[bool, str | None, list[BinarySecurityStageItem]]:
        from app.service import task_manager as task_manager_module

        if self._streaming_tail_auto_progressing(db, task):
            return False, "当前任务处于 streaming tail 自动推进中，暂不支持阶段失败项重试", []
        items = self._stage_retry_candidate_items(db, task, stage_name)
        if not items:
            return False, "当前阶段没有可重试的失败项", []
        supported, reason = self._stage_retry_support(db, task, stage_name)
        if not supported:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            blocked_by_task_status = bool(task.status in task_manager_module.STAGE_RETRY_BLOCKED_TASK_STATUSES)
            blocked_by_stage_status = bool(stage_run and stage_run.status not in task_manager_module.STAGE_RETRY_ALLOWED_STATUSES)
            if not blocked_by_task_status and not blocked_by_stage_status:
                return False, reason, []
        upstream_retried, upstream_stage = self._upstream_stage_retried(db, task, stage_name)
        if upstream_retried:
            return False, f"上游阶段 {task_manager_module.STAGE_TITLES.get(upstream_stage or '', upstream_stage or '')} 已发生重试，当前阶段不能只重试失败项", []
        reason = self._continue_stage_input_error(db, task, stage_name)
        if reason:
            return False, reason, []
        return True, None, items

    def _task_continue_support(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[bool, str | None, str | None]:
        from app.service import task_manager as task_manager_module

        if self._streaming_tail_auto_progressing(db, task):
            return False, "当前任务处于 streaming tail 自动推进中，无需手动继续", None
        active_operation = self._active_operation(db, task.id)
        if active_operation is not None:
            return False, f"当前任务已有进行中的操作: {active_operation.operation_type}", None
        if task.status in {"pending_upload", "uploading", "ready_to_start"}:
            return False, f"当前任务状态不允许继续: {task.status}", None
        blocked_statuses = {"pending", "dispatching", "running"}
        if task.status in blocked_statuses:
            return False, f"当前任务正在执行或排队中，不能手动继续: {task.status}", None
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            return False, "当前任务等待模块确认，请先确认模块后继续", None
        stage_sequence = self._stage_sequence_for_task(task)
        if not stage_sequence:
            return False, "当前任务没有可执行阶段", None
        target_stage = self._first_failed_terminal_stage(db, task) or self._next_incomplete_stage(db, task)
        if target_stage is None:
            return False, "当前任务所有阶段都已成功，没有可继续的后续阶段", None
        reason = self._continue_stage_input_error(db, task, target_stage)
        if reason:
            return False, reason, target_stage
        return True, None, target_stage

    def _reconcile_task_summary(self: TaskManager, task_id: str):
        def _run():
            from app.service import task_manager as task_manager_module

            session = task_manager_module.get_session_factory()()
            try:
                task = session.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == task_id).first()
                if task is None:
                    return None
                self._refresh_task_status_after_sync(session, task)
                snapshot = self._task_state_snapshot(task)
                session.commit()
                return snapshot
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        return self._run_retryable_layer(_run)

    def _readless_reconcile_task_layer(self: TaskManager, task_id: str):
        return self._reconcile_task_summary(task_id)

    def _decide_task_action_after_stage_terminal(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str,
        status: str,
        summary: dict[str, Any],
        payload: dict[str, Any],
        state_event_id: str | None,
    ):
        from app.service import task_manager as task_manager_module

        del payload
        decision = task_manager_module._StageTerminalTaskDecision()
        if summary.get("archive_blocked"):
            decision.action = "archive_blocked"
            decision.event_type = "stage_archive_blocked"
            decision.message = f"阶段业务执行已完成，但总任务产物归档失败，停止后续推进: {stage_name}"
            decision.level = "error"
            return decision
        if status == "failed":
            decision.action = "finalize_failed"
            decision.event_type = "stage_failed"
            decision.message = f"阶段失败，停止后续推进: {stage_name}"
            decision.level = "error"
            return decision
        next_stage = self._next_incomplete_stage(db, task)
        if (
            next_stage is None
            and normalize_stage_name(stage_name) == "system_analysis"
            and status == "success"
            and self._entry_analysis_inputs(db, task)
        ):
            next_stage = "entry_analysis"
        if next_stage and not self._should_auto_advance_to_stage(db, task, next_stage):
            blocked_reason = self._continue_stage_input_error(db, task, next_stage)
            decision.action = "advance_blocked"
            decision.next_stage = None
            decision.event_type = "next_stage_auto_advance_blocked"
            decision.message = f"阶段完成后未自动推进到下一阶段: {next_stage}"
            decision.level = "warning"
            decision.payload = {
                "state_event_id": state_event_id,
                "completed_stage": stage_name,
                "blocked_reason": blocked_reason,
            }
            return decision
        if (
            task.status in {"running", "dispatching"}
            and next_stage
            and self._streaming_mode_enabled(task)
            and self._is_streaming_tail_stage(task, next_stage)
        ):
            decision.action = "activate_streaming_tail"
            decision.next_stage = next_stage
            decision.event_type = "streaming_tail_activated"
            decision.message = f"阶段完成后切换为流式尾段推进: {next_stage}"
            decision.payload = {"state_event_id": state_event_id, "completed_stage": stage_name}
            return decision
        if task.status in {"running", "dispatching"} and next_stage:
            decision.action = "requeue_next_stage"
            decision.next_stage = next_stage
            decision.event_type = "task_requeued_after_stage_completion"
            decision.message = f"阶段完成后任务继续进入下一阶段: {next_stage}"
            decision.payload = {"state_event_id": state_event_id, "completed_stage": stage_name}
            return decision
        decision.action = "finalize_success"
        return decision

    async def _apply_task_action_after_stage_terminal(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str,
        status: str,
        summary: dict[str, Any],
        payload: dict[str, Any],
        state_event_id: str | None,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        decision = self._decide_task_action_after_stage_terminal(
            db,
            task,
            stage_name=stage_name,
            status=status,
            summary=summary,
            payload=payload,
            state_event_id=state_event_id,
        )
        metadata_path = Path(task.workspace_root) / "input" / "task-metadata.json"
        if decision.action == "archive_blocked":
            task.status = "failed"
            task.last_error = summary.get("error") or "总任务产物归档失败"
            self._invalidate_task_execution(task)
            task.finished_at = task_manager_module._now()
            blocked_item_ids = self._suppress_later_stage_items_after_archive_blocked(
                db,
                task,
                stage_name=stage_name,
                error_message=task.last_error,
            )
            task_manager_module.observe_task_error("downstream_error", stage=stage_name, result="archive_blocked")
            task_manager_module.observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
            task_manager_module.observe_task_duration(
                phase="execution",
                duration_seconds=task_manager_module._elapsed_seconds_since(task.started_at),
                status=task.status,
                task_type=self._task_type(task),
            )
            task_manager_module.observe_task_duration(
                phase="total",
                duration_seconds=task_manager_module._elapsed_seconds_since(task.created_at),
                status=task.status,
                task_type=self._task_type(task),
            )
            self._record_event(
                db,
                task,
                decision.event_type or "stage_archive_blocked",
                decision.message or f"阶段业务执行已完成，但总任务产物归档失败，停止后续推进: {stage_name}",
                level=decision.level,
                stage_name=stage_name,
                payload={
                    "stage_status": status,
                    "error": task.last_error,
                    "state_event_id": state_event_id,
                    "blocked_item_ids": blocked_item_ids,
                },
            )
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        if decision.action == "finalize_failed":
            self._record_event(
                db,
                task,
                decision.event_type or "stage_failed",
                decision.message or f"阶段失败，停止后续推进: {stage_name}",
                level=decision.level,
                stage_name=stage_name,
                payload={
                    "error": task.last_error,
                    "state_event_id": state_event_id,
                    **(
                        {
                            "failure_code": summary.get("failure_code"),
                            "failure_category": summary.get("failure_category"),
                            "failure_message": summary.get("failure_message"),
                        }
                        if summary.get("failure_code")
                        else {}
                    ),
                },
            )
            self._finalize_task(db, task)
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        if decision.action == "advance_blocked":
            self._record_event(
                db,
                task,
                decision.event_type or "next_stage_auto_advance_blocked",
                decision.message or "",
                level=decision.level,
                stage_name=stage_name if decision.next_stage is None else decision.next_stage,
                payload=dict(decision.payload or {}),
            )
            self._finalize_task(db, task)
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        if decision.action == "activate_streaming_tail":
            task.status = "running"
            task.current_stage = decision.next_stage
            task.finished_at = None
            task.last_error = None
            self._record_event(
                db,
                task,
                decision.event_type or "streaming_tail_activated",
                decision.message or "",
                stage_name=decision.next_stage,
                payload=dict(decision.payload or {}),
            )
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        if decision.action == "requeue_next_stage":
            resume_decision = self._decide_task_resume_after_stage_reset(
                db,
                task,
                next_stage=decision.next_stage,
                resume_reason="stage_terminal_requeue",
                source="stage_terminal",
                message=decision.message or "",
                payload=dict(decision.payload or {}),
            )
            resume_decision.event_type = decision.event_type or "task_requeued_after_stage_completion"
            if decision.next_stage and not resume_decision.should_resume:
                # Stage-terminal decision has already chosen the next runnable stage; keep
                # the shared apply path from vetoing that explicit resume handoff here.
                resume_decision.should_resume = True
                resume_decision.next_stage = decision.next_stage
                resume_decision.payload = {
                    **dict(resume_decision.payload or {}),
                    **dict(decision.payload or {}),
                    "next_stage": decision.next_stage,
                    "resume_reason": resume_decision.resume_reason or "stage_terminal_requeue",
                    "source": resume_decision.source or "stage_terminal",
                    "authoritative_active_progress": bool(
                        self._has_authoritative_active_stage(db, task, exclude_stage=decision.next_stage)
                    ),
                }
            if not resume_decision.should_resume:
                self._record_event(
                    db,
                    task,
                    resume_decision.event_type or "task_resume_blocked",
                    "阶段完成，但当前仍不满足重新排队条件",
                    level="warning",
                    stage_name=decision.next_stage,
                    payload=dict(resume_decision.payload or {}),
                )
                self._finalize_task(db, task)
            else:
                self._apply_task_resume_decision(db, task, resume_decision)
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        if decision.action == "finalize_success":
            self._finalize_task(db, task)
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        return False

    def _refresh_task_status_after_sync(self: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        current_status = str(task.status or "").strip()
        early_outcome = self._refresh_task_status_after_sync_early_return(db, task)
        if early_outcome:
            return
        stage_runs = self._refresh_task_status_after_sync_refresh_authoritative_stages(db, task)
        if any(
            str(run.status or "").strip() == "failed"
            and str(getattr(run, "stage_name", "") or "").strip() == str(task.current_stage or "").strip()
            and self._is_terminal_business_stage_failure(task, run)
            for run in stage_runs
        ):
            task.status = "pending"
            task.last_error = None
            task.finished_at = None
            self._clear_task_abnormal_reason_snapshot(db, task)
            return
        if any(str(run.status or "").strip() == "running" for run in stage_runs):
            task.summary = self._clear_failure_fields_from_summary(dict(task.summary or {}))
        authoritative_failure = self._current_stage_authoritative_failure_context(db, task, stage_runs=stage_runs)
        if authoritative_failure is None:
            authoritative_failure = self._earlier_stage_authoritative_failure_context(db, task, stage_runs=stage_runs)
        if authoritative_failure is None:
            failure_run = next(
                (
                    run for run in stage_runs
                    if str(run.status or "").strip() in {"failed", "downstream_missing", "cancelled"}
                    and "owner_lost_retry_exhausted" in str(getattr(run, "last_error", "") or "").strip().lower()
                ),
                None,
            )
            if failure_run is not None:
                authoritative_failure = {
                    "stage_name": failure_run.stage_name or task.current_stage,
                    "stage_run": failure_run,
                    "failure_code": "owner_lost_retry_exhausted",
                    "failure_category": "infrastructure",
                    "failure_message": str(getattr(failure_run, "last_error", None) or "owner_lost_retry_exhausted"),
                    "reason": "owner_lost_retry_exhausted_stage_run",
                }
        if str(authoritative_failure.get("failure_code") or "").strip() == "owner_lost_retry_exhausted" if authoritative_failure else False:
            self._finalize_task_after_authoritative_failure(
                db,
                task,
                failure_ctx=authoritative_failure,
                previous_status=current_status,
                event_type="task_owner_lost_final_failed",
            )
            return
        if self._recover_streaming_parent_running_state_locked(
            db,
            task,
            record_event=current_status == "dispatching",
            reason="refresh_task_status_after_sync",
        ):
            return
        if str(task.status or "").strip() == "running" and str(task.current_stage or "").strip() and not stage_runs:
            task.status = "pending"
            self._clear_task_failure_state(task)
            self._clear_task_abnormal_reason_snapshot(db, task)
        if self._refresh_task_status_after_sync_handle_active_running_stages(db, task, stage_runs=stage_runs, previous_status=current_status):
            return
        if self._refresh_task_status_after_sync_handle_retry_and_reopen(db, task, stage_runs=stage_runs, previous_status=current_status):
            return
        if stage_runs and all(str(run.status or "").strip() == "success" for run in stage_runs):
            task.status = "pending"
            task.last_error = None
            task.finished_at = None
            self._clear_task_abnormal_reason_snapshot(db, task)
            task.summary = self._clear_failure_fields_from_summary(dict(task.summary or {}))
            return
        if task.status == "failed" and not self._task_has_active_reconcile_items(db, task):
            self._finalize_task(db, task)
            return
        self._finalize_task(db, task)

    def _task_has_active_reconcile_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        for item in self._task_reconcile_candidate_items(db, task, force=False):
            normalized_status = self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()
            if normalized_status in {"pending", "queued", "dispatching", "running"}:
                return True
            if self._item_needs_downstream_binding_reconcile(item):
                return True
        return False

    def _refresh_task_status_after_sync_early_return(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        from app.service import task_manager as task_manager_module

        if bool(getattr(task, "_owned_execution_requeue_emitted", False)):
            task.status = "pending"
            task.finished_at = None
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            return True
        active_cancel_operation = self._active_cancel_operation(db, task.id)
        if self._ensure_task_remains_cancelling(db, task, active_cancel_operation=active_cancel_operation) is not None:
            return True
        if self._recover_failed_cancelled_task_state(db, task):
            return True
        active_operation = self._active_operation(db, task.id)
        if task.status == "cancelled":
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
            self._invalidate_task_execution(task)
            task.finished_at = task.finished_at or task_manager_module._now()
            return True
        if task.status == task_manager_module.TASK_STATUS_CANCEL_FAILED:
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
            self._invalidate_task_execution(task)
            task.finished_at = task.finished_at or task_manager_module._now()
            return True
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.finished_at = None
            return True
        if active_operation is not None:
            if self._task_runtime_phase(task) != task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            task.finished_at = None
            task.last_error = None if str(active_operation.status or "").strip() in {"accepted", "queued", "running"} else task.last_error
            task.current_operation_id = active_operation.id
            return True
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        if (
            task.status == "failed"
            and not stage_runs
            and not db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).first()
        ):
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
            self._invalidate_task_execution(task)
            task.finished_at = task.finished_at or task_manager_module._now()
            return True
        return False

    def _refresh_task_status_after_sync_refresh_authoritative_stages(self: TaskManager, db: Session, task: BinarySecurityTask) -> list[BinarySecurityStageRun]:
        runs_by_stage = {
            str(run.stage_name or "").strip(): run
            for run in db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        }
        for stage_name in self._stage_sequence_for_task(task):
            if not self._stage_enabled(task, stage_name):
                continue
            stage_run = runs_by_stage.get(stage_name)
            stage_items = self._stage_items(db, task.id, stage_name)
            stage_run_status = str(stage_run.status or "").strip() if stage_run is not None else ""
            if stage_items or (
                self._is_streaming_tail_stage(task, stage_name)
                and normalize_stage_name(stage_name) == "dataflow_vuln_scan"
                and stage_run_status in {"failed", "downstream_missing", "cancelled", "partial_success"}
            ):
                self._refresh_stage_from_authoritative_items(db, task, stage_name)
        return db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()

    def _refresh_task_status_after_sync_handle_active_running_stages(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun],
        previous_status: str,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        statuses = [run.status for run in stage_runs]
        if not any(status in {"running", "dispatching"} for status in statuses):
            return False
        authoritative_failure_ctx = self._current_stage_authoritative_failure_context(db, task, stage_runs=stage_runs)
        if authoritative_failure_ctx is None:
            authoritative_failure_ctx = self._earlier_stage_authoritative_failure_context(db, task, stage_runs=stage_runs)
        if authoritative_failure_ctx is not None:
            self._finalize_task_after_authoritative_failure(
                db,
                task,
                failure_ctx=authoritative_failure_ctx,
                previous_status=previous_status,
            )
            return True
        preserve_dispatching = self._can_preserve_dispatching_state(db, task, stage_runs=stage_runs)
        if str(previous_status or "").strip() == "dispatching" and not preserve_dispatching:
            failed_stage_run = next((run for run in stage_runs if str(run.status or "").strip() == "failed"), None)
            if failed_stage_run is not None:
                failure_snapshot = self._stage_failure_snapshot(task, failed_stage_run)
                self._finalize_task_after_authoritative_failure(
                    db,
                    task,
                    failure_ctx={
                        "stage_name": failed_stage_run.stage_name or task.current_stage,
                        "stage_run": failed_stage_run,
                        "failure_code": failure_snapshot.get("failure_code"),
                        "failure_category": failure_snapshot.get("failure_category"),
                        "failure_message": failed_stage_run.last_error or failure_snapshot.get("failure_message") or failure_snapshot.get("error"),
                        "reason": "failed_stage_run_present_after_dispatching_preserve_rejected",
                    },
                    previous_status=previous_status,
                )
                return True
            task.status = "pending"
            task.finished_at = None
            self._clear_task_failure_state(task)
            if self._is_streaming_tail_stage(task, task.current_stage) and self._tail_requires_execution_takeover(db, task):
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.tail_reconcile_state = "idle"
            else:
                self._set_task_runtime_phase(
                    task,
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, task.current_stage) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                )
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
            self._clear_task_abnormal_reason_snapshot(db, task)
            return True
        task.status = "running"
        active_run = next((run for run in stage_runs if run.status in {"running", "dispatching"}), None)
        if active_run and active_run.stage_name:
            task.current_stage = active_run.stage_name
        preserve_dispatch = self._should_preserve_task_dispatch_ownership(task, previous_status=previous_status)
        if preserve_dispatch:
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
        else:
            if self._is_streaming_tail_stage(task, task.current_stage) and self._tail_requires_execution_takeover(db, task):
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.tail_reconcile_state = "idle"
            else:
                self._set_task_runtime_phase(
                    task,
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, task.current_stage) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                )
        if not preserve_dispatch:
            if self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                lease = self._activate_tail_reconciliation(
                    db,
                    task,
                    now_value=task_manager_module._now(),
                    fallback_status="pending",
                    takeover_result="refresh",
                )
                if not self._runtime_lease_is_active(lease):
                    if str(task.current_stage or "").strip() and self._is_streaming_tail_stage(task, task.current_stage):
                        task.status = "running"
                    else:
                        task.status = "pending"
            else:
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                self._release_tail_reconcile_owner(task.id)
                current_stage_items = self._stage_items(db, task.id, str(task.current_stage or "").strip())
                has_live_downstream_children = self._stage_has_live_downstream_children(current_stage_items)
                if (
                    not has_live_downstream_children
                    and str(previous_status or "").strip() in {"running", "dispatching", "pending"}
                    and self._should_requeue_for_owned_execution(
                        db,
                        task,
                        next_stage=str(task.current_stage or "").strip() or None,
                        next_stage_status="running",
                    )
                ):
                    self._requeue_owned_execution_takeover(
                        db,
                        task,
                        stage_name=str(task.current_stage or "").strip() or None,
                        reason="refresh_task_status_no_active_owner",
                        event_type="owned_execution_takeover_requeued",
                        message="检测到执行接管悬空，已重新排队等待 worker 接管",
                        event_payload={"source": "refresh_task_status_after_sync"},
                    )
                    return True
        task.finished_at = None
        self._clear_task_failure_state(task)
        self._clear_task_abnormal_reason_snapshot(db, task)
        task.summary = self._clear_failure_fields_from_summary(dict(task.summary or {}))
        return True

    def _refresh_task_status_after_sync_handle_retry_and_reopen(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun],
        previous_status: str,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        current_status = str(previous_status or "").strip()
        vuln_run = next((run for run in stage_runs if normalize_stage_name(run.stage_name) == "dataflow_vuln_scan"), None)
        had_stage_retry_mode = task.execution_mode in {"stage_retry", "stage_retry_failed_items", "stage_retry_full"} and bool(task.target_stage_name)
        had_task_retry_mode = task.execution_mode in {"task_retry", "task_retry_failed_items"} and bool(task.target_stage_name)
        original_target_stage_name = str(task.target_stage_name or "").strip() or None
        summary_before_retry_clear = dict(task.summary or {})
        preferred_retry_next_stage = None
        if had_stage_retry_mode:
            stale_stages = [str(stage).strip() for stage in (summary_before_retry_clear.get("stale_stages") or []) if str(stage).strip()]
            preferred_retry_next_stage = stale_stages[0] if stale_stages else None
            self._clear_retry_execution_context(
                db,
                task,
                stage_name=task.current_stage,
                payload={"status": task.status, "stage_retry_mode": True},
            )
        if had_task_retry_mode:
            self._clear_retry_execution_context(
                db,
                task,
                stage_name=task.current_stage,
                payload={"status": task.status, "task_retry_mode": True},
            )
        failed_stage_run = next(
            (run for run in stage_runs if str(run.status or "").strip() in {"failed", "downstream_missing", "cancelled"}),
            None,
        )
        if failed_stage_run is not None and not had_stage_retry_mode and not had_task_retry_mode:
            failed_items = self._stage_items(db, task.id, str(failed_stage_run.stage_name or ""))
            exhausted_owner_lost_items = [item for item in failed_items if self._owner_lost_retry_exhausted(task, item)]
            if exhausted_owner_lost_items:
                exhausted_item = exhausted_owner_lost_items[0]
                self._finalize_task_after_authoritative_failure(
                    db,
                    task,
                    failure_ctx={
                        "stage_name": failed_stage_run.stage_name or task.current_stage,
                        "stage_run": failed_stage_run,
                        "failure_code": "owner_lost_retry_exhausted",
                        "failure_category": "infrastructure",
                        "failure_message": str(exhausted_item.error_message or "").strip() or "owner_lost_retry_exhausted",
                        "reason": "owner_lost_retry_exhausted_after_sync",
                    },
                    previous_status=current_status,
                    event_type="task_owner_lost_final_failed",
                )
                return True
        if (
            failed_stage_run is not None
            and vuln_run is not None
            and normalize_stage_name(str(failed_stage_run.stage_name or "").strip()) == "dataflow_vuln_scan"
            and str(vuln_run.status or "").strip() in {"success", "partial_success"}
        ):
            failed_stage_run = None
        if (
            failed_stage_run is not None
            and self._streaming_mode_enabled(task)
            and normalize_stage_name(str(failed_stage_run.stage_name or "").strip()) == "dataflow_vuln_scan"
            and not had_stage_retry_mode
            and not had_task_retry_mode
        ):
            task.status = "running"
            task.current_stage = failed_stage_run.stage_name or task.current_stage
            task.finished_at = None
            if self._tail_requires_execution_takeover(db, task):
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.tail_reconcile_state = "idle"
            else:
                self._set_task_runtime_phase(
                    task,
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                )
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                if self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                    self._activate_tail_reconciliation(
                        db,
                        task,
                        now_value=task_manager_module._now(),
                        fallback_status="pending",
                        takeover_result="refresh",
                    )
            return True
        next_stage = self._next_incomplete_stage(db, task)
        if had_task_retry_mode and not next_stage and original_target_stage_name:
            stage_sequence = self._stage_sequence_for_task(task)
            if original_target_stage_name in stage_sequence:
                target_index = stage_sequence.index(original_target_stage_name)
                for candidate_stage in stage_sequence[target_index + 1 :]:
                    if self._stage_enabled(task, candidate_stage):
                        next_stage = candidate_stage
                        break
        if had_stage_retry_mode and preferred_retry_next_stage:
            next_stage = preferred_retry_next_stage
        if (
            failed_stage_run is not None
            and not had_stage_retry_mode
            and not had_task_retry_mode
            and not self._should_reopen_failed_stage_after_archive_input_repair(db, task, failed_stage_run)
            and not self._is_streaming_tail_stage(task, failed_stage_run.stage_name)
        ):
            failed_items = self._stage_items(db, task.id, str(failed_stage_run.stage_name or ""))
            recoverable_owner_lost = any(self._owner_lost_retry_exhausted(task, item) is False and self._is_owner_lost_recoverable_failure(
                failure_message=str(item.error_message or "").strip() or None,
                failure_category=self._stage_failure_snapshot(task, failed_stage_run).get("failure_category"),
                error_type=self._stage_item_sync_error_type_value(item),
                item=item,
            ) for item in failed_items)
            if recoverable_owner_lost:
                task.status = "pending"
                task.current_stage = failed_stage_run.stage_name or task.current_stage
                task.finished_at = None
                task.last_error = None
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                self._clear_task_abnormal_reason_snapshot(db, task)
                self._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                return True
            if self._is_streaming_tail_stage(task, failed_stage_run.stage_name):
                task.status = "running" if str(task.status or "").strip() in {"running", "dispatching"} else "pending"
                task.current_stage = failed_stage_run.stage_name or task.current_stage
                task.finished_at = None
                task.last_error = None
                if self._tail_requires_execution_takeover(db, task):
                    self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                    task.tail_reconcile_state = "idle"
                else:
                    self._set_task_runtime_phase(
                        task,
                        task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                        if self._should_enter_tail_reconciliation(db, task)
                        else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    )
                    task.dispatcher_instance_id = None
                    task.dispatch_started_at = None
                    task.lease_expires_at = None
                    if self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                        self._activate_tail_reconciliation(
                            db,
                            task,
                            now_value=task_manager_module._now(),
                            fallback_status="pending",
                            takeover_result="refresh",
                        )
                    else:
                        self._release_tail_reconcile_owner(task.id)
                self._clear_task_abnormal_reason_snapshot(db, task)
                return True
            if not failed_items and "owner pod lost" in str(getattr(failed_stage_run, "last_error", "") or "").lower():
                task.status = "failed"
                task.current_stage = failed_stage_run.stage_name or task.current_stage
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
                task.finished_at = task.finished_at or task_manager_module._now()
                self._record_event(
                    db,
                    task,
                    "task_finalized_after_stage_failure",
                    "阶段失败，停止后续推进",
                    level="warning",
                    stage_name=task.current_stage,
                )
                self._record_event(
                    db,
                    task,
                    "task_finalized_after_child_failure",
                    "子任务失败已上卷到父任务",
                    level="warning",
                    stage_name=task.current_stage,
                )
                return True
            task.status = "pending"
            task.current_stage = failed_stage_run.stage_name or task.current_stage
            task.finished_at = None
            task.last_error = None
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._clear_task_abnormal_reason_snapshot(db, task)
            self._set_task_runtime_phase(task, TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            return True
        if (
            failed_stage_run is not None
            and not self._should_reopen_failed_stage_after_archive_input_repair(db, task, failed_stage_run)
            and self._should_terminalize_parent_for_failed_stage(task, failed_stage_run)
        ):
            failure_snapshot = self._stage_failure_snapshot(task, failed_stage_run)
            self._finalize_task_after_authoritative_failure(
                db,
                task,
                failure_ctx={
                    "stage_name": failed_stage_run.stage_name or task.current_stage,
                    "stage_run": failed_stage_run,
                    "failure_code": failure_snapshot.get("failure_code"),
                    "failure_category": failure_snapshot.get("failure_category"),
                    "failure_message": failed_stage_run.last_error or failure_snapshot.get("failure_message") or failure_snapshot.get("error"),
                    "reason": "failed_stage_run_terminalized_after_sync",
                },
                previous_status=current_status,
                event_type="task_finalized_after_stage_failure",
            )
            return True
        if (
            failed_stage_run is not None
            and not had_stage_retry_mode
            and not had_task_retry_mode
            and not self._should_reopen_failed_stage_after_archive_input_repair(db, task, failed_stage_run)
        ):
            failed_items = self._stage_items(db, task.id, str(failed_stage_run.stage_name or ""))
            exhausted_owner_lost_items = [item for item in failed_items if self._owner_lost_retry_exhausted(task, item)]
            if exhausted_owner_lost_items:
                exhausted_item = exhausted_owner_lost_items[0]
                self._finalize_task_after_authoritative_failure(
                    db,
                    task,
                    failure_ctx={
                        "stage_name": failed_stage_run.stage_name or task.current_stage,
                        "stage_run": failed_stage_run,
                        "failure_code": "owner_lost_retry_exhausted",
                        "failure_category": "infrastructure",
                        "failure_message": str(exhausted_item.error_message or "").strip() or "owner_lost_retry_exhausted",
                        "reason": "owner_lost_retry_exhausted_after_sync",
                    },
                    previous_status=current_status,
                    event_type="task_owner_lost_final_failed",
                )
                return True
            if not failed_items:
                failed_stage_error = " ".join(
                    str(part or "").strip()
                    for part in (
                        failed_stage_run.last_error,
                        getattr(failed_stage_run, "error_message", None),
                        getattr(failed_stage_run, "reason", None),
                    )
                    if str(part or "").strip()
                )
                if "task owner pod lost" in failed_stage_error.lower() or "owner pod lost" in failed_stage_error.lower():
                    failure_snapshot = self._stage_failure_snapshot(task, failed_stage_run)
                    self._finalize_task_after_authoritative_failure(
                        db,
                        task,
                        failure_ctx={
                            "stage_name": failed_stage_run.stage_name or task.current_stage,
                            "stage_run": failed_stage_run,
                            "failure_code": failure_snapshot.get("failure_code"),
                            "failure_category": failure_snapshot.get("failure_category"),
                            "failure_message": failed_stage_run.last_error or failure_snapshot.get("failure_message") or failure_snapshot.get("error"),
                            "reason": "failed_stage_run_owner_lost_without_child_items",
                        },
                        previous_status=current_status,
                        event_type="task_finalized_after_stage_failure",
                    )
                    return True
        if (
            failed_stage_run is not None
            and not had_stage_retry_mode
            and not had_task_retry_mode
            and not self._should_reopen_failed_stage_after_archive_input_repair(db, task, failed_stage_run)
        ):
            if self._is_terminal_business_stage_failure(task, failed_stage_run):
                task.status = "pending"
                task.current_stage = failed_stage_run.stage_name or task.current_stage
                task.finished_at = None
                task.last_error = None
                self._clear_task_abnormal_reason_snapshot(db, task)
                return True
            task.status = "pending"
            task.current_stage = failed_stage_run.stage_name or task.current_stage
            task.finished_at = None
            if self._is_streaming_tail_stage(task, failed_stage_run.stage_name) and self._tail_requires_execution_takeover(db, task):
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.tail_reconcile_state = "idle"
            else:
                self._set_task_runtime_phase(
                    task,
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, failed_stage_run.stage_name) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                )
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                if self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                    self._activate_tail_reconciliation(
                        db,
                        task,
                        now_value=task_manager_module._now(),
                        fallback_status="pending",
                        takeover_result="refresh",
                    )
                else:
                    self._release_tail_reconcile_owner(task.id)
            return True
        next_stage_run = next((run for run in stage_runs if run.stage_name == next_stage), None)
        next_stage_status = next_stage_run.status if next_stage_run else "pending"
        if (
            next_stage
            and str(next_stage_status or "").strip() in {"pending", "queued", "running", "dispatching"}
            and (
                (had_stage_retry_mode and preferred_retry_next_stage == next_stage)
                or had_task_retry_mode
                or self._stage_has_real_runnable_work(db, task, next_stage)
            )
        ):
            previous_stage_name = str(task.current_stage or "").strip()
            task.status = "running" if str(next_stage_status or "").strip() in {"running", "dispatching"} else "pending"
            task.current_stage = next_stage
            task.finished_at = None
            task.last_error = None
            if self._is_streaming_tail_stage(task, next_stage) and self._tail_requires_execution_takeover(db, task):
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.tail_reconcile_state = "idle"
            else:
                self._set_task_runtime_phase(
                    task,
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, next_stage) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                )
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                if self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                    lease = self._activate_tail_reconciliation(
                        db,
                        task,
                        now_value=task_manager_module._now(),
                        fallback_status="pending",
                        takeover_result="refresh",
                    )
                    if not self._runtime_lease_is_active(lease):
                        task.status = "pending"
                else:
                    self._release_tail_reconcile_owner(task.id)
            summary = dict(task.summary or {})
            if summary.get("stale_from_stage") and next_stage in set(summary.get("stale_stages") or []):
                summary["stale_stages"] = []
                summary["stale_reason"] = None
                summary["stale_from_stage"] = None
                task.summary = summary
            next_stage_items = self._stage_items(db, task.id, next_stage)
            has_live_downstream_children = next_stage == previous_stage_name and self._stage_has_live_downstream_children(next_stage_items)
            should_owned_execution_requeue = (
                not has_live_downstream_children
                and str(current_status or "").strip() in {"running", "dispatching", "pending"}
                and self._should_requeue_for_owned_execution(
                    db,
                    task,
                    next_stage=next_stage,
                    next_stage_status=str(next_stage_status or "").strip(),
                )
            )
            if should_owned_execution_requeue and str(next_stage_status or "").strip() in {"running", "dispatching"}:
                self._requeue_owned_execution_takeover(
                    db,
                    task,
                    stage_name=next_stage,
                    reason="downstream_sync_no_active_owner",
                    event_type="task_requeued_after_downstream_sync",
                    message=f"下游状态同步完成，任务继续进入阶段并重新排队等待 worker 接管: {next_stage}",
                    event_payload={"stage_status": str(next_stage_status or "").strip() or None},
                )
            elif str(next_stage_status or "").strip() in {"pending", "queued", "running", "dispatching"}:
                resume_decision = self._decide_task_resume_after_stage_reset(
                    db,
                    task,
                    next_stage=next_stage,
                    resume_reason="downstream_sync_resume",
                    source="downstream_sync",
                    message=f"下游状态同步完成，任务继续进入阶段: {next_stage}",
                    payload={"stage_status": str(next_stage_status or "").strip() or None},
                )
                resume_decision.event_type = "task_requeued_after_downstream_sync"
                if not resume_decision.should_resume:
                    self._record_event(
                        db,
                        task,
                        "task_resume_blocked",
                        "下游状态同步完成，但当前仍不满足重新排队条件",
                        level="warning",
                        stage_name=next_stage,
                        payload=dict(resume_decision.payload or {}),
                    )
                else:
                    self._apply_task_resume_decision(db, task, resume_decision)
            return True
        if (
            not next_stage
            and vuln_run is not None
            and str(vuln_run.status or "").strip() in {"success", "partial_success"}
            and str(task.status or "").strip() == "pending"
            and current_status in {"pending", "dispatching", "running"}
        ):
            self._record_event(
                db,
                task,
                "task_requeued_after_downstream_sync",
                "下游状态同步完成，任务已回到待调度状态",
                stage_name=str(vuln_run.stage_name or "").strip() or task.current_stage,
            )
            return True
        if failed_stage_run is not None and not had_stage_retry_mode and not had_task_retry_mode and not next_stage:
            task.status = "failed"
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
            task.current_stage = failed_stage_run.stage_name or task.current_stage
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.finished_at = task.finished_at or task_manager_module._now()
            return True
        if failed_stage_run is not None and not had_stage_retry_mode and not had_task_retry_mode:
            failed_items = self._stage_items(db, task.id, str(failed_stage_run.stage_name or ""))
            if failed_items and not self._stage_has_nonterminal_items(failed_items):
                task.status = "failed"
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
                task.current_stage = failed_stage_run.stage_name or task.current_stage
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.finished_at = task.finished_at or task_manager_module._now()
                return True
        return False

    def _finalize_task(self: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        from app.service import task_manager as task_manager_module

        with self._task_execution_owner_lock:
            self._task_execution_owners.pop(task.id, None)
        if self._finalize_task_handle_terminal_shortcuts(db, task):
            return
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        if self._finalize_task_handle_active_progress(db, task, stage_runs=stage_runs):
            return
        if self._finalize_task_handle_resume_or_missing_stage(db, task, stage_runs=stage_runs):
            return
        statuses = [run.status for run in stage_runs]
        vuln_run = next((run for run in stage_runs if normalize_stage_name(run.stage_name) == "dataflow_vuln_scan"), None)
        if statuses and all(status == "success" for status in statuses):
            task.status = "success"
        elif vuln_run and vuln_run.status in {"success", "partial_success"}:
            task.status = "partial_success" if any(status in {"failed", "partial_success", "downstream_missing"} for status in statuses) else "success"
        elif any(status in {"failed", "partial_success", "downstream_missing"} for status in statuses):
            task.status = "failed"
        else:
            task.status = "success"
        stale_stages = list((task.summary or {}).get("stale_stages") or [])
        summary_payload = dict(task.summary or {})
        has_materialized_stale_context = any(
            bool(summary_payload.get(key))
            for key in (
                "selected_modules",
                "entry_results",
                "b2s_results",
                "dataflow_results",
                "vuln_results",
            )
        ) or bool(getattr(task, "stage_summary", None))
        if stale_stages and task.status == "success" and (
            str(getattr(task, "status", "") or "").strip() == "partial_success"
            or has_materialized_stale_context
        ):
            task.status = "partial_success"
        self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = task_manager_module._now()
        self._last_task_heartbeat_at.pop(task.id, None)
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all()
        archive_jobs = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id).all()
        stage_summaries = self._build_stage_summaries(db, task, self._stage_sequence_for_task(task), stage_runs, items)
        self._sync_task_abnormal_reason_snapshot(
            db,
            task,
            None if task.status == "success" else self._task_abnormal_reason(task, stage_summaries, items, archive_jobs),
        )
        task_manager_module.observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
        task_manager_module.observe_task_duration(
            phase="execution",
            duration_seconds=task_manager_module._elapsed_seconds_since(task.started_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        task_manager_module.observe_task_duration(
            phase="total",
            duration_seconds=task_manager_module._elapsed_seconds_since(task.created_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        self._record_event(db, task, "task_finished", f"任务结束: {task.status}")

    def _finalize_task_handle_terminal_shortcuts(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        from app.service import task_manager as task_manager_module

        if self._ensure_task_remains_cancelling(db, task) is not None:
            self._last_task_heartbeat_at.pop(task.id, None)
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            return True
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._last_task_heartbeat_at.pop(task.id, None)
            return True
        if task.status in {"cancelled", task_manager_module.TASK_STATUS_CANCEL_FAILED}:
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
            stage_sequence = self._stage_sequence_for_task(task)
            stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
            items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all()
            archive_jobs = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id).all()
            stage_summaries = self._build_stage_summaries(db, task, stage_sequence, stage_runs, items)
            self._sync_task_abnormal_reason_snapshot(db, task, self._task_abnormal_reason(task, stage_summaries, items, archive_jobs))
            if task.status == task_manager_module.TASK_STATUS_CANCEL_FAILED:
                self._invalidate_task_execution(task)
                task.finished_at = task.finished_at or task_manager_module._now()
            else:
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.finished_at = task_manager_module._now()
            self._last_task_heartbeat_at.pop(task.id, None)
            return True
        return False

    def _finalize_task_handle_active_progress(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun],
    ) -> bool:
        from app.service import task_manager as task_manager_module

        vuln_run = next((run for run in stage_runs if normalize_stage_name(run.stage_name) == "dataflow_vuln_scan"), None)
        has_active_streaming_upstream, active_streaming_stage, active_streaming_status = self._streaming_has_active_upstream_stage(task, stage_runs)
        original_runtime_phase = str(getattr(task, "runtime_phase", "") or "").strip()
        if has_active_streaming_upstream:
            task.status = "running" if active_streaming_status in {"running", "dispatching", "applying"} else "pending"
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            task.tail_reconcile_state = "idle"
            task.current_stage = active_streaming_stage
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.finished_at = None
            task.last_error = None
            self._release_tail_reconcile_owner(task.id)
            self._last_task_heartbeat_at.pop(task.id, None)
            self._record_event(
                db,
                task,
                "task_finalize_deferred_for_streaming_upstream",
                f"深度模式下仍有上游阶段活跃，转回 worker 接管继续执行: {active_streaming_stage}",
                level="info",
                stage_name=active_streaming_stage,
                payload={"stage_status": active_streaming_status},
            )
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            if (
                original_runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
                and self._should_requeue_for_owned_execution(
                db,
                task,
                next_stage=active_streaming_stage,
                next_stage_status=str(active_streaming_status or "").strip(),
                )
            ):
                self._requeue_owned_execution_takeover(
                    db,
                    task,
                    stage_name=active_streaming_stage,
                    reason="finalize_streaming_upstream_no_active_owner",
                    event_type="owned_execution_takeover_requeued",
                    message=f"检测到执行接管悬空，已重新排队等待 worker 接管: {active_streaming_stage}",
                    event_payload={"stage_status": active_streaming_status, "source": "finalize_streaming_upstream"},
                )
            return True
        has_active_incomplete_stage, active_stage_name, active_stage_status = self._has_any_active_incomplete_stage(db, task, stage_runs)
        if not has_active_incomplete_stage:
            return False
        task.status = "running" if active_stage_status in {"running", "dispatching", "applying"} else "pending"
        task.current_stage = active_stage_name or task.current_stage
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.lease_expires_at = None
        task.finished_at = None
        task.last_error = None
        if (
            self._is_streaming_tail_stage(task, active_stage_name)
            and self._tail_requires_execution_takeover(db, task)
            and str(active_stage_status or "").strip() in {"running", "dispatching", "applying"}
        ):
            task.status = "running"
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            task.tail_reconcile_state = "idle"
            self._release_tail_reconcile_owner(task.id)
            self._last_task_heartbeat_at.pop(task.id, None)
            self._record_event(
                db,
                task,
                "task_finalize_deferred_for_active_stage",
                f"仍有活跃未完成阶段，转回 worker 接管继续执行: {active_stage_name}",
                level="info",
                stage_name=active_stage_name,
                payload={"stage_status": active_stage_status},
            )
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            return True
        if self._is_streaming_tail_stage(task, active_stage_name) and self._should_enter_tail_reconciliation(db, task):
            task.status = "running"
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION)
            task.tail_reconcile_state = "idle"
        else:
            self._release_tail_reconcile_owner(task.id)
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
        self._last_task_heartbeat_at.pop(task.id, None)
        self._record_event(
            db,
            task,
            "task_finalize_deferred_for_active_stage",
            f"仍有活跃未完成阶段，延迟任务收口: {active_stage_name}",
            level="info",
            stage_name=active_stage_name,
            payload={"stage_status": active_stage_status},
        )
        self._sync_task_abnormal_reason_snapshot(db, task, None)
        if (
            original_runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
            and self._should_requeue_for_owned_execution(
            db,
            task,
            next_stage=active_stage_name,
            next_stage_status=str(active_stage_status or "").strip(),
            )
        ):
            self._requeue_owned_execution_takeover(
                db,
                task,
                stage_name=active_stage_name,
                reason="finalize_active_stage_no_active_owner",
                event_type="owned_execution_takeover_requeued",
                message=f"检测到执行接管悬空，已重新排队等待 worker 接管: {active_stage_name}",
                event_payload={"stage_status": active_stage_status, "source": "finalize_active_stage"},
            )
        return True

    def _finalize_task_handle_resume_or_missing_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun],
    ) -> bool:
        from app.service import task_manager as task_manager_module

        vuln_run = next((run for run in stage_runs if normalize_stage_name(run.stage_name) == "dataflow_vuln_scan"), None)
        next_stage = self._next_incomplete_stage(db, task)
        if next_stage:
            if vuln_run and vuln_run.status in {"success", "partial_success"}:
                next_stage = None
            else:
                next_stage_run = next((run for run in stage_runs if run.stage_name == next_stage), None)
                next_stage_items = self._stage_items(db, task.id, next_stage)
                next_stage_status = (
                    self._normalize_downstream_status(next_stage_run.status) or str(next_stage_run.status or "").strip()
                    if next_stage_run is not None
                    else "pending"
                )
                if next_stage_items:
                    item_status = self._aggregate_item_statuses([item.status for item in next_stage_items])
                    if item_status in {"pending", "queued", "running", "dispatching"}:
                        next_stage_status = item_status
                if next_stage_status in {"failed", "downstream_missing", "cancelled"} and next_stage_items and not self._stage_has_nonterminal_items(next_stage_items):
                    task.status = "failed"
                    self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
                    task.current_stage = next_stage
                    task.dispatcher_instance_id = None
                    task.dispatch_started_at = None
                    task.lease_expires_at = None
                    task.finished_at = task_manager_module._now()
                    task.last_error = next_stage_run.last_error if next_stage_run is not None else task.last_error
                    self._last_task_heartbeat_at.pop(task.id, None)
                    stage_summaries = self._build_stage_summaries(
                        db,
                        task,
                        self._stage_sequence_for_task(task),
                        stage_runs,
                        db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all(),
                    )
                    items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all()
                    archive_jobs = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id).all()
                    self._sync_task_abnormal_reason_snapshot(db, task, self._task_abnormal_reason(task, stage_summaries, items, archive_jobs))
                    return True
                task.status = "running" if next_stage_status in {"running", "dispatching", "applying"} else "pending"
                task.current_stage = next_stage
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.finished_at = None
                task.last_error = None
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.tail_reconcile_state = "idle"
                self._release_tail_reconcile_owner(task.id)
                self._last_task_heartbeat_at.pop(task.id, None)
                if self._should_requeue_for_owned_execution(
                    db,
                    task,
                    next_stage=next_stage,
                    next_stage_status=str(next_stage_status or "").strip(),
                ):
                    self._requeue_owned_execution_takeover(
                        db,
                        task,
                        stage_name=next_stage,
                        reason="finalize_deferred_no_active_owner",
                        event_type="owned_execution_takeover_requeued",
                        message=f"检测到执行接管悬空，已重新排队等待 worker 接管: {next_stage}",
                        event_payload={"stage_status": next_stage_status},
                    )
                else:
                    self._record_event(
                        db,
                        task,
                        "task_finalize_deferred_for_incomplete_stage",
                        f"任务仍有未完成阶段，保持活跃状态等待继续推进: {next_stage}",
                        level="warning",
                        stage_name=next_stage,
                        payload={"stage_status": next_stage_status},
                    )
                    self._sync_task_abnormal_reason_snapshot(db, task, None)
                    if next_stage_status in {"pending", "queued"} or next_stage_run is None:
                        self._enqueue_task(task.id)
                return True
        else:
            runs_by_stage = {str(run.stage_name or "").strip(): run for run in stage_runs}
            missing_enabled_stage = next(
                (
                    stage_name
                    for stage_name in self._stage_sequence_for_task(task)
                    if (
                        self._stage_enabled(task, stage_name)
                        and runs_by_stage.get(stage_name) is None
                        and not self._should_finalize_without_entries(db, task, stage_name)
                    )
                ),
                None,
            )
            if missing_enabled_stage and not (vuln_run and vuln_run.status in {"success", "partial_success"}):
                task.status = "pending"
                self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
                task.current_stage = missing_enabled_stage
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.lease_expires_at = None
                task.finished_at = None
                task.last_error = None
                self._last_task_heartbeat_at.pop(task.id, None)
                self._record_event(
                    db,
                    task,
                    "task_finalize_deferred_for_missing_stage",
                    f"任务缺少已启用阶段的执行记录，保持活跃状态等待补跑: {missing_enabled_stage}",
                    level="warning",
                    stage_name=missing_enabled_stage,
                )
                self._sync_task_abnormal_reason_snapshot(db, task, None)
                self._enqueue_task(task.id)
                return True
        return False
