from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    TASK_TERMINAL_STATUSES,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
    TASK_TYPE_SOURCE,
    normalize_stage_name,
)

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskStateMachineMixin:
    def _task_has_any_active_children(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        active_statuses = {"pending", "queued", "dispatching", "running", "applying", "reconciling"}
        runs = list(stage_runs or db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all())
        items = list(stage_items or db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all())
        if any(str(getattr(run, "status", "") or "").strip() in active_statuses for run in runs):
            return True
        if any((self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower()) in active_statuses for item in items):
            return True
        archive_jobs = (
            db.query(task_manager_module.BinarySecurityArchiveJob)
            .filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id)
            .all()
        )
        if any(str(getattr(job, "archive_status", "") or "").strip() in active_statuses for job in archive_jobs):
            return True
        runtime_lease = self._runtime_lease_for_task(db, task.id)
        if self._runtime_lease_is_active(runtime_lease):
            return True
        if str(getattr(task, "status", "") or "").strip() in active_statuses and (
            str(getattr(task, "dispatcher_instance_id", "") or "").strip()
            or str(getattr(task, "runtime_phase", "") or "").strip() == TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
        ):
            return True
        return False

    def _task_children_all_terminal(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ) -> bool:
        return not self._task_has_any_active_children(db, task, stage_runs=stage_runs, stage_items=stage_items)

    def _task_has_pending_stage_materialization(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
    ) -> bool:
        next_stage = self._next_incomplete_stage(db, task)
        if not next_stage:
            return False
        normalized_stage = normalize_stage_name(next_stage)
        runs = list(stage_runs or db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all())
        next_stage_run = next((run for run in runs if normalize_stage_name(run.stage_name) == normalized_stage), None)
        next_stage_items = self._stage_items(db, task.id, next_stage)
        if next_stage_run is not None or next_stage_items:
            return False
        if self._should_skip_stage_without_runnable_work(db, task, next_stage):
            return False
        if self._should_finalize_without_entries(db, task, next_stage):
            return False
        return True

    def _task_has_resumable_execution_path(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
    ) -> bool:
        snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
        workflow_blocked_stage = self._workflow_blocked_on_stage(task, snapshots)
        next_stage = self._next_incomplete_stage(db, task)
        if workflow_blocked_stage or next_stage:
            return True
        return False

    def _task_requires_runtime_takeover_or_requeue(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
    ) -> bool:
        snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
        blocked_stage = self._workflow_blocked_on_stage(task, snapshots)
        if not blocked_stage:
            return False
        blocked_snapshot = next(
            (snapshot for snapshot in snapshots if str(snapshot.get("stage_name") or "").strip() == str(blocked_stage or "").strip()),
            None,
        )
        blocked_status = str((blocked_snapshot or {}).get("status") or "").strip()
        if blocked_status not in {"pending", "queued", "dispatching", "running", "applying", "reconciling"}:
            return False
        return self._should_requeue_for_owned_execution(
            db,
            task,
            next_stage=blocked_stage,
            next_stage_status=blocked_status,
        )

    def _evaluate_task_finalization_gate(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ):
        from app.service import task_manager as task_manager_module

        runs = list(stage_runs or db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all())
        items = list(stage_items or db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all())
        next_stage = self._next_incomplete_stage(db, task)
        snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=runs)
        blocked_stage = self._workflow_blocked_on_stage(task, snapshots)
        has_authoritative_failure = (
            self._current_stage_authoritative_failure_context(db, task, stage_runs=runs) is not None
            or self._earlier_stage_authoritative_failure_context(db, task, stage_runs=runs) is not None
        )
        has_active_items = self._task_has_any_active_children(db, task, stage_runs=runs, stage_items=items)
        has_nonterminal_items = any(
            (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower())
            not in {"success", "failed", "cancelled", "partial_success", "downstream_missing", "skipped"}
            for item in items
        )
        has_pending_materialization = self._task_has_pending_stage_materialization(db, task, stage_runs=runs)
        has_runtime_takeover_need = self._task_requires_runtime_takeover_or_requeue(db, task, stage_runs=runs)
        has_resumable_path = self._task_has_resumable_execution_path(db, task, stage_runs=runs)
        materializable_stage = next(
            (
                str(snapshot.get("stage_name") or "").strip()
                for snapshot in snapshots
                if (
                    str(snapshot.get("stage_name") or "").strip()
                    and not bool(snapshot.get("has_stage_run"))
                    and bool(snapshot.get("enabled"))
                    and bool(snapshot.get("has_materialized_inputs"))
                )
            ),
            None,
        )

        if task.status in {"cancelled", task_manager_module.TASK_STATUS_CANCEL_FAILED}:
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=True,
                reason_code="terminal_shortcut",
                blocked_by_stage=blocked_stage,
                next_stage=next_stage,
                has_active_items=has_active_items,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=has_resumable_path,
                has_pending_materialization=has_pending_materialization,
                has_runtime_takeover_need=has_runtime_takeover_need,
                has_authoritative_failure=has_authoritative_failure,
            )

        if has_active_items:
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="active_children_present",
                blocked_by_stage=blocked_stage,
                next_stage=next_stage,
                has_active_items=True,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=has_resumable_path,
                has_pending_materialization=has_pending_materialization,
                has_runtime_takeover_need=has_runtime_takeover_need,
                has_authoritative_failure=has_authoritative_failure,
            )

        if materializable_stage:
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="pending_stage_materialization",
                blocked_by_stage=materializable_stage,
                next_stage=materializable_stage,
                has_active_items=False,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=True,
                has_pending_materialization=True,
                has_runtime_takeover_need=has_runtime_takeover_need,
                has_authoritative_failure=has_authoritative_failure,
            )

        if blocked_stage:
            blocked_snapshot = next(
                (snapshot for snapshot in snapshots if str(snapshot.get("stage_name") or "").strip() == str(blocked_stage or "").strip()),
                None,
            )
            blocked_has_run = bool((blocked_snapshot or {}).get("has_stage_run"))
            blocked_has_inputs = (
                self._stage_has_materialized_inputs(db, task, blocked_stage)
                if self._stage_requires_materialized_inputs(task, blocked_stage)
                else True
            )
            if not blocked_has_run and blocked_has_inputs:
                return task_manager_module._TaskFinalizeGateDecision(
                    allowed=False,
                    reason_code="pending_stage_materialization",
                    blocked_by_stage=blocked_stage,
                    next_stage=blocked_stage,
                    has_active_items=False,
                    has_nonterminal_items=has_nonterminal_items,
                    has_resumable_path=True,
                    has_pending_materialization=True,
                    has_runtime_takeover_need=has_runtime_takeover_need,
                    has_authoritative_failure=has_authoritative_failure,
                )
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="next_stage_resumable",
                blocked_by_stage=blocked_stage,
                next_stage=blocked_stage,
                has_active_items=False,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=True,
                has_pending_materialization=has_pending_materialization,
                has_runtime_takeover_need=has_runtime_takeover_need,
                has_authoritative_failure=has_authoritative_failure,
            )

        if next_stage:
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="next_stage_resumable",
                blocked_by_stage=blocked_stage or next_stage,
                next_stage=next_stage,
                has_active_items=False,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=True,
                has_pending_materialization=has_pending_materialization,
                has_runtime_takeover_need=has_runtime_takeover_need,
                has_authoritative_failure=has_authoritative_failure,
            )

        if has_pending_materialization:
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="pending_stage_materialization",
                blocked_by_stage=blocked_stage,
                next_stage=next_stage,
                has_active_items=False,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=has_resumable_path,
                has_pending_materialization=True,
                has_runtime_takeover_need=has_runtime_takeover_need,
                has_authoritative_failure=has_authoritative_failure,
            )

        if has_runtime_takeover_need:
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="runtime_takeover_required",
                blocked_by_stage=blocked_stage,
                next_stage=next_stage,
                has_active_items=False,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=has_resumable_path,
                has_pending_materialization=has_pending_materialization,
                has_runtime_takeover_need=True,
                has_authoritative_failure=has_authoritative_failure,
            )

        if has_resumable_path:
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="resumable_execution_path_present",
                blocked_by_stage=blocked_stage,
                next_stage=next_stage,
                has_active_items=False,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=True,
                has_pending_materialization=has_pending_materialization,
                has_runtime_takeover_need=has_runtime_takeover_need,
                has_authoritative_failure=has_authoritative_failure,
            )

        if not self._workflow_ready_for_finalization(snapshots):
            return task_manager_module._TaskFinalizeGateDecision(
                allowed=False,
                reason_code="workflow_not_ready_for_finalization",
                blocked_by_stage=blocked_stage,
                next_stage=next_stage,
                has_active_items=False,
                has_nonterminal_items=has_nonterminal_items,
                has_resumable_path=False,
                has_pending_materialization=False,
                has_runtime_takeover_need=False,
                has_authoritative_failure=has_authoritative_failure,
            )

        return task_manager_module._TaskFinalizeGateDecision(
            allowed=True,
            reason_code="ready_for_finalization",
            blocked_by_stage=blocked_stage,
            next_stage=next_stage,
            has_active_items=False,
            has_nonterminal_items=has_nonterminal_items,
            has_resumable_path=False,
            has_pending_materialization=False,
            has_runtime_takeover_need=False,
            has_authoritative_failure=has_authoritative_failure,
        )

    def _missing_entry_results_failure_context(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str = "dataflow_vuln_scan",
        reason: str,
    ) -> dict[str, Any] | None:
        from app.service import task_manager as task_manager_module

        normalized_stage = normalize_stage_name(stage_name)
        if normalized_stage != "dataflow_vuln_scan":
            return None
        if self._task_type(task) != TASK_TYPE_SOURCE:
            return None
        if self._entry_results(task):
            return None
        stage_run = self._ensure_stage_run(db, task, stage_name)
        failure_message = "entry_analysis 未产出 entry_results，无法继续进入 dataflow_vuln_scan"
        stage_run.status = "failed"
        stage_run.finished_at = stage_run.finished_at or task_manager_module._now()
        stage_run.last_error = failure_message
        stage_run.counts = self._stage_counts(db, stage_run)
        return {
            "stage_name": stage_name,
            "stage_run": stage_run,
            "failure_code": "missing_entry_results",
            "failure_category": "business",
            "failure_message": failure_message,
            "reason": reason,
        }

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
        if not self._apply_task_main_state_update(
            db,
            task,
            source="state_machine",
            reason="检测到活动取消操作，任务进入取消中",
            stage_name=task.current_stage,
            status=task_manager_module.TASK_STATUS_CANCELLING,
            finished_at=None,
            last_error=None,
        ):
            return operation
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
        if not self._apply_task_main_state_update(
            db,
            task,
            source="state_machine",
            reason="取消操作失败，任务进入取消失败",
            stage_name=task.current_stage,
            status=task_manager_module.TASK_STATUS_CANCEL_FAILED,
            runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
            finished_at=task.finished_at or task_manager_module._now(),
            last_error=str(operation.error_message or task.last_error or "cancel operation failed"),
            clear_runtime_owner=True,
        ):
            return True
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

    def _streaming_dataflow_terminalization_ready(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        if not self._streaming_mode_enabled(task):
            return True
        gate = self._build_streaming_dataflow_completion_gate(db, task)
        return bool(gate.get("ready_for_terminal_status"))

    def _normalize_stage_terminal_status(self: TaskManager, status: str | None) -> str:
        return self._normalize_downstream_status(status) or str(status or "").strip()

    def _stage_success_like(self: TaskManager, status: str | None) -> bool:
        return self._normalize_stage_terminal_status(status) in {"success", "skipped"}

    def _stage_failed_like(self: TaskManager, status: str | None) -> bool:
        return self._normalize_stage_terminal_status(status) in {"failed", "partial_success", "cancelled", "downstream_missing"}

    def _stage_ready_for_terminalization(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        stage_run: BinarySecurityStageRun | None,
        items: list[BinarySecurityStageItem],
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        normalized_status = self._normalize_stage_terminal_status(
            self._business_stage_status(task, stage_name, stage_run, items, db=db)
        )
        if not self._task_status_is_terminal(normalized_status):
            return False
        if self._should_finalize_without_entries(db, task, stage_name):
            return True
        if stage_run is None and not items and not self._should_finalize_without_entries(db, task, stage_name):
            return False
        if items and self._stage_has_nonterminal_items(items):
            return False
        if self._stage_archive_success_blocked(task, stage_name, items, db=db):
            return False
        if normalized_stage == "dataflow_vuln_scan":
            return self._streaming_dataflow_terminalization_ready(db, task)
        if stage_run is not None:
            return True
        return True

    def _stage_has_unresolved_expected_outputs(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        stage_run: BinarySecurityStageRun | None,
        items: list[BinarySecurityStageItem],
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        if self._should_finalize_without_entries(db, task, stage_name):
            return False
        if normalized_stage == "dataflow_vuln_scan":
            if not self._streaming_mode_enabled(task):
                return False
            gate = self._build_streaming_dataflow_completion_gate(db, task)
            return bool(gate.get("missing_entry_count") or 0) > 0 or not bool(gate.get("counts_aligned"))
        if stage_run is not None and self._task_status_is_terminal(self._normalize_stage_terminal_status(stage_run.status)):
            return False
        if (
            self._stage_requires_materialized_inputs(task, stage_name)
            and not items
            and not self._stage_has_materialized_inputs(db, task, stage_name, allow_rebuild=False)
        ):
            return True
        return False

    def _build_workflow_stage_snapshots(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
    ) -> list[dict[str, Any]]:
        if stage_runs is None:
            stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        runs_by_stage = {str(run.stage_name or "").strip(): run for run in stage_runs}
        snapshots: list[dict[str, Any]] = []
        previous_terminal = True
        for stage_name in self._stage_sequence_for_task(task):
            enabled = self._stage_enabled(task, stage_name)
            if not enabled:
                continue
            stage_run = runs_by_stage.get(stage_name)
            stage_items = self._stage_items(db, task.id, stage_name)
            stage_status = self._business_stage_status(task, stage_name, stage_run, stage_items, db=db)
            normalized_status = self._normalize_stage_terminal_status(stage_status)
            is_terminal = self._task_status_is_terminal(normalized_status)
            has_active_items = any((self._normalize_downstream_status(item.status) or str(item.status or "").strip()) in {"pending", "queued", "running", "dispatching"} for item in stage_items)
            unresolved_expected_outputs = self._stage_has_unresolved_expected_outputs(db, task, stage_name, stage_run, stage_items)
            ready_for_terminalization = self._stage_ready_for_terminalization(db, task, stage_name, stage_run, stage_items)
            snapshot = {
                "stage_name": stage_name,
                "enabled": True,
                "has_stage_run": stage_run is not None,
                "item_count": len(stage_items),
                "status": normalized_status or "pending",
                "is_terminal": is_terminal,
                "is_success_like": self._stage_success_like(normalized_status),
                "is_failed_like": self._stage_failed_like(normalized_status),
                "has_active_items": has_active_items,
                "has_materialized_inputs": (
                    self._stage_has_materialized_inputs(db, task, stage_name, allow_rebuild=False)
                    if self._stage_requires_materialized_inputs(task, stage_name)
                    else True
                ),
                "has_unresolved_expected_outputs": unresolved_expected_outputs,
                "ready_for_terminalization": ready_for_terminalization,
                "ready_for_failure_escalation": bool(previous_terminal and ready_for_terminalization and self._stage_failed_like(normalized_status) and not has_active_items and not unresolved_expected_outputs),
                "previous_stages_terminal": previous_terminal,
            }
            snapshots.append(snapshot)
            previous_terminal = previous_terminal and bool(snapshot["is_terminal"]) and bool(snapshot["ready_for_terminalization"])
        return snapshots

    def _workflow_ready_for_finalization(
        self: TaskManager,
        snapshots: list[dict[str, Any]],
    ) -> bool:
        if not snapshots:
            return False
        return all(
            bool(snapshot.get("has_stage_run"))
            and bool(snapshot.get("is_terminal"))
            and bool(snapshot.get("ready_for_terminalization"))
            and not bool(snapshot.get("has_active_items"))
            and not bool(snapshot.get("has_unresolved_expected_outputs"))
            for snapshot in snapshots
        )

    def _workflow_blocked_on_stage(
        self: TaskManager,
        task: BinarySecurityTask,
        snapshots: list[dict[str, Any]],
    ) -> str | None:
        for snapshot in snapshots:
            stage_name = str(snapshot.get("stage_name") or "").strip()
            if (
                self._is_streaming_tail_stage(task, stage_name)
                and not int(snapshot.get("item_count") or 0)
                and not bool(snapshot.get("has_active_items"))
                and not bool(snapshot.get("has_unresolved_expected_outputs"))
                and str(snapshot.get("status") or "").strip() in {"pending", "queued", "running", "dispatching"}
            ):
                continue
            if not bool(snapshot.get("has_stage_run")):
                return stage_name or None
            if not bool(snapshot.get("is_terminal")) or not bool(snapshot.get("ready_for_terminalization")):
                return stage_name or None
            if bool(snapshot.get("has_active_items")) or bool(snapshot.get("has_unresolved_expected_outputs")):
                return stage_name or None
        return None

    def _stage_ready_to_escalate_failure(
        self: TaskManager,
        snapshots: list[dict[str, Any]],
        stage_name: str,
    ) -> bool:
        target = next((snapshot for snapshot in snapshots if str(snapshot.get("stage_name") or "").strip() == str(stage_name or "").strip()), None)
        if target is None:
            return False
        if not bool(target.get("ready_for_failure_escalation")):
            return False
        later = False
        for snapshot in snapshots:
            current_name = str(snapshot.get("stage_name") or "").strip()
            if current_name == str(stage_name or "").strip():
                later = True
                continue
            if not later:
                continue
            later_status = str(snapshot.get("status") or "").strip()
            later_item_count = int(snapshot.get("item_count") or 0)
            later_has_active_items = bool(snapshot.get("has_active_items"))
            if later_has_active_items:
                return False
            if later_status in {"pending", "queued", "running", "dispatching"} and later_item_count <= 0:
                continue
            if bool(snapshot.get("has_unresolved_expected_outputs")):
                return False
            if not bool(snapshot.get("has_stage_run")):
                continue
            if later_status not in {"pending", "queued", "running", "dispatching"}:
                return False
        return True

    def _aggregate_workflow_terminal_status(
        self: TaskManager,
        task: BinarySecurityTask,
        snapshots: list[dict[str, Any]],
    ) -> str:
        del task
        statuses = [self._normalize_stage_terminal_status(snapshot.get("status")) for snapshot in snapshots]
        if statuses and all(self._stage_success_like(status) for status in statuses):
            return "success"
        if any(status == "cancelled" for status in statuses) and all(status in {"cancelled", "success", "skipped"} for status in statuses):
            return "cancelled"
        if any(status == "partial_success" for status in statuses):
            return "partial_success"
        failed_like_count = sum(1 for status in statuses if self._stage_failed_like(status))
        if failed_like_count:
            return "failed"
        return "success"

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
        workflow_snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
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
        if (
            stage_run is not None
            and self._stage_ready_to_escalate_failure(workflow_snapshots, stage_name)
            and self._should_terminalize_parent_for_failed_stage(task, stage_run)
        ):
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
        if not self._stage_ready_to_escalate_failure(workflow_snapshots, stage_name):
            return None
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
        workflow_snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
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
            if (
                stage_run is not None
                and self._stage_ready_to_escalate_failure(workflow_snapshots, stage_name)
                and self._should_terminalize_parent_for_failed_stage(task, stage_run)
            ):
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
            if not self._stage_ready_to_escalate_failure(workflow_snapshots, stage_name):
                continue
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
        if not self._apply_task_main_state_update(
            db,
            task,
            source="state_machine",
            reason="检测到权威失败，任务终止",
            stage_name=stage_name,
            status="failed",
            runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
            finished_at=task.finished_at or task_manager_module._now(),
            last_error=failure_message,
            clear_runtime_owner=True,
        ):
            return
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

    def _should_finalize_after_authoritative_failure(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        failure_ctx: dict[str, Any] | None = None,
        stage_runs: list[BinarySecurityStageRun] | None = None,
    ) -> bool:
        gate = self._evaluate_task_finalization_gate(db, task, stage_runs=stage_runs)
        if gate.allowed or str(gate.reason_code or "").strip() == "authoritative_failure":
            return True
        if not gate.has_authoritative_failure:
            return False

        failed_stage = str((failure_ctx or {}).get("stage_name") or "").strip()
        if not failed_stage:
            return False

        ordered_stage_names = [
            str(name or "").strip()
            for name in self._stage_sequence_for_task(task)
            if str(name or "").strip()
        ]
        stage_index = {name: idx for idx, name in enumerate(ordered_stage_names)}
        failed_idx = stage_index.get(failed_stage)
        current_stage = str(task.current_stage or "").strip()
        current_idx = stage_index.get(current_stage)
        blocked_stage = str(gate.blocked_by_stage or gate.next_stage or "").strip()
        blocked_idx = stage_index.get(blocked_stage)

        if gate.reason_code == "pending_stage_materialization":
            if failed_idx is None or blocked_idx is None:
                return False
            return failed_idx <= blocked_idx

        if gate.reason_code in {
            "active_children_present",
            "next_stage_resumable",
            "resumable_execution_path_present",
            "runtime_takeover_required",
        }:
            if failed_idx is None or current_idx is None:
                return False
            return failed_idx <= current_idx

        return False
    def _next_incomplete_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> str | None:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
        workflow_blocked_stage = self._workflow_blocked_on_stage(task, snapshots)
        if workflow_blocked_stage:
            return workflow_blocked_stage
        for snapshot in snapshots:
            stage_name = str(snapshot.get("stage_name") or "").strip()
            upstream_retried, _ = self._upstream_stage_retried(db, task, stage_name)
            if upstream_retried:
                continue
            if str(snapshot.get("status") or "").strip() == "partial_success" and not self._partial_success_advancement_enabled(task, stage_name):
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
            return not bool(self._entry_analysis_inputs(db, task))
        if normalized_stage == "dataflow_vuln_scan":
            if self._task_type(task) == TASK_TYPE_SOURCE and not bool(self._effective_entry_inputs(task)):
                return True
            return not bool(self._entry_results(task))
        return False

    def _first_failed_terminal_stage(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> str | None:
        snapshots = self._build_workflow_stage_snapshots(db, task)
        for snapshot in snapshots:
            stage_name = str(snapshot.get("stage_name") or "").strip()
            if self._stage_ready_to_escalate_failure(snapshots, stage_name):
                return stage_name
        return None

    def _reconcile_task_summary_in_session(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ):
        self._refresh_task_status_after_sync(db, task)
        return self._task_state_snapshot(task)

    def _reconcile_item_layer_facts_in_session(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_name: str,
    ):
        stage_run = self._reconcile_stage_domain_in_session(db, task, stage_name)
        snapshot = self._reconcile_task_summary_in_session(db, task)
        return stage_run, snapshot

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
        stage_run, snapshot = self._reconcile_item_layer_facts_in_session(
            db,
            task,
            stage_name=stage_name,
        )
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
        enqueue_task: bool = True,
    ) -> bool:
        if not decision.should_resume or not decision.next_stage:
            return False
        if (
            self._streaming_mode_enabled(task)
            and str(getattr(task, "status", "") or "").strip() in {"running", "dispatching"}
            and str(getattr(task, "current_stage", "") or "").strip()
            and not self._is_streaming_tail_stage(task, task.current_stage)
            and self._is_streaming_tail_stage(task, decision.next_stage)
        ):
            return False
        previous_stage = str(getattr(task, "current_stage", "") or "").strip() or None
        self._set_task_runtime_transition_guard(
            task,
            from_stage=previous_stage,
            to_stage=decision.next_stage,
            reason=decision.resume_reason or "task_resume",
        )
        self._apply_task_main_state_update(
            db,
            task,
            source="state_machine",
            reason="阶段完成后任务重新进入待调度",
            status="pending",
            stage_name=decision.next_stage,
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            finished_at=None,
            last_error=None,
        )
        task.summary = self._clear_failure_fields_from_summary(dict(task.summary or {}))
        self._clear_task_abnormal_reason_snapshot(db, task)
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
        if enqueue_task:
            setattr(task, "_task_enqueue_emitted", True)
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

    def _task_retry_failed_items_support(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> tuple[bool, str | None, str | None, list[BinarySecurityStageItem]]:
        from app.service import task_manager as task_manager_module

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
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            return False, "当前任务等待模块确认，请先确认模块后再重试失败项", None, []

        stage_name, items = self._first_failed_retry_stage(db, task)
        if stage_name and items:
            upstream_retried, upstream_stage = self._upstream_stage_retried(db, task, stage_name)
            if upstream_retried:
                return False, (
                    f"阶段 {task_manager_module.STAGE_TITLES.get(stage_name, stage_name)} 的上游阶段 "
                    f"{task_manager_module.STAGE_TITLES.get(upstream_stage or '', upstream_stage or '')} 已发生重试，不能只重试失败项"
                ), None, []
            reason = self._continue_stage_input_error(db, task, stage_name)
            if reason:
                return False, reason, stage_name, []
            return True, None, stage_name, items

        reason: str | None = None
        stage_name = self._first_failed_terminal_stage(db, task)
        if not stage_name:
            stage_name = self._next_incomplete_stage(db, task)
        if stage_name:
            archive_stage_name, archive_reason = self._archive_pending_full_retry_stage(db, task, stage_name)
            if archive_stage_name:
                return True, None, archive_stage_name, []
            global_archive_stage_name, global_archive_reason = self._archive_pending_full_retry_stage(db, task)
            if global_archive_stage_name:
                return True, None, global_archive_stage_name, []
            return False, global_archive_reason or archive_reason or reason, stage_name, []

        archive_stage_name, archive_reason = self._archive_pending_full_retry_stage(db, task)
        if archive_stage_name:
            return True, None, archive_stage_name, []
        return False, archive_reason or "当前任务没有可重试的失败项", None, []

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
        current_stage = str(task.current_stage or "").strip()
        stale_stages = {
            str(stage_name or "").strip()
            for stage_name in list((task.summary or {}).get("stale_stages") or [])
            if str(stage_name or "").strip()
        }
        stage_runs = {
            str(run.stage_name or "").strip(): run
            for run in db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        }
        recoverable_terminal_stage = None
        for stage_name in stage_sequence:
            upstream_retried, _ = self._upstream_stage_retried(db, task, stage_name)
            if upstream_retried:
                continue
            stage_items = self._stage_items(db, task.id, stage_name)
            if any(
                self._normalize_stage_terminal_status(item.status) in {"failed", "partial_success", "cancelled", "downstream_missing"}
                for item in stage_items
            ):
                recoverable_terminal_stage = stage_name
                break
            stage_run = stage_runs.get(stage_name)
            if stage_run is not None and self._normalize_stage_terminal_status(stage_run.status) in {
                "failed",
                "partial_success",
                "cancelled",
                "downstream_missing",
            }:
                recoverable_terminal_stage = stage_name
                break
        current_stage_run = stage_runs.get(current_stage) if current_stage else None
        current_stage_status = self._normalize_stage_terminal_status(getattr(current_stage_run, "status", None))
        current_stage_items = self._stage_items(db, task.id, current_stage) if current_stage else []
        prioritize_current_stage = bool(
            current_stage
            and (
                (
                    str(task.status or "").strip() in {"failed", "partial_success", "cancelled", "downstream_missing"}
                    and (current_stage_run is not None or bool(current_stage_items))
                )
                or
                current_stage in stale_stages
                or current_stage_status in {"failed", "partial_success", "cancelled", "downstream_missing"}
                or any(self._is_terminal_item_status(item.status) for item in current_stage_items)
            )
        )
        failed_terminal_stage = self._first_failed_terminal_stage(db, task)
        target_stage = recoverable_terminal_stage or failed_terminal_stage or (
            current_stage if prioritize_current_stage else self._next_incomplete_stage(db, task)
        )
        if target_stage is None:
            return False, "当前任务所有阶段都已成功，没有可继续的后续阶段", None
        reason = self._continue_stage_input_error(db, task, target_stage)
        if reason and not prioritize_current_stage:
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
        source_event_type: str | None = None,
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
            archive_error = summary.get("error") or "总任务产物归档失败"
            if not self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="总任务产物归档失败，任务终止",
                stage_name=stage_name,
                status="failed",
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                clear_runtime_owner=True,
                finished_at=task_manager_module._now(),
                last_error=archive_error,
            ):
                return True
            self._invalidate_task_execution(task)
            blocked_item_ids = self._suppress_later_stage_items_after_archive_blocked(
                db,
                task,
                stage_name=stage_name,
                error_message=archive_error,
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
            if not self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="进入 streaming tail 收口",
                stage_name=decision.next_stage,
                status="running",
                runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
                finished_at=None,
                last_error=None,
                clear_runtime_owner=True,
            ):
                return True
            lease = self._activate_tail_reconciliation(
                db,
                task,
                now_value=task_manager_module._now(),
                fallback_status="pending",
                takeover_result="refresh",
            )
            if not self._runtime_lease_is_active(lease):
                self._repair_running_lease_invariant(
                    db,
                    task,
                    reason="activate_streaming_tail_without_active_runtime_lease",
                    stage_name=decision.next_stage,
                    event_payload={"source": "handle_stage_terminal_decision"},
                )
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
                skip_enqueue = (
                    str(source_event_type or "").strip() == "archive_job_copied"
                    and str(task.status or "").strip() == "pending"
                    and str(task.current_stage or "").strip() == str(resume_decision.next_stage or "").strip()
                )
                self._apply_task_resume_decision(
                    db,
                    task,
                    resume_decision,
                    enqueue_task=not skip_enqueue,
                )
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        if decision.action == "finalize_success":
            self._finalize_task(db, task)
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        return False

    def _decide_task_layer_reconcile(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        signal: dict[str, Any],
    ):
        from app.service import task_manager as task_manager_module

        source_event_type = str(signal.get("source_event_type") or "").strip() or None
        reconcile_reason = str(signal.get("reconcile_reason") or signal.get("reason") or "").strip() or "task_layer_reconcile"
        stage_name = str(signal.get("stage_name") or task.current_stage or "").strip() or None
        decision = task_manager_module._TaskLayerReconcileDecision(
            action="noop",
            stage_name=stage_name,
            payload={},
            source_event_type=source_event_type,
            reconcile_reason=reconcile_reason,
        )
        if source_event_type in {"stage_worker_start_requested", "downstream_status_observed"}:
            decision.action = "refresh_only"
            return decision
        if source_event_type == "stale_execution_requeue_requested":
            decision.action = "refresh_only"
            return decision
        if source_event_type in {"task_execution_failed", "archive_job_copy_failed"}:
            failure_ctx = self._current_stage_authoritative_failure_context(db, task)
            if failure_ctx is None:
                failure_ctx = self._earlier_stage_authoritative_failure_context(db, task)
            if failure_ctx is not None:
                decision.action = "failure_finalize"
                decision.stage_name = str(failure_ctx.get("stage_name") or stage_name or task.current_stage or "").strip() or None
                decision.payload = {"failure_ctx": dict(failure_ctx)}
                return decision
            if str(task.status or "").strip() in TASK_TERMINAL_STATUSES:
                decision.action = "finalize_task"
            else:
                decision.action = "refresh_only"
            return decision
        if source_event_type in {"stage_worker_terminal_observed", "archive_job_copied", "downstream_terminal_observed"}:
            resolved_stage_name = stage_name or str(task.current_stage or "").strip() or None
            if str(task.status or "").strip() in TASK_TERMINAL_STATUSES:
                decision.action = "finalize_task"
                decision.stage_name = resolved_stage_name
                return decision
            if not resolved_stage_name:
                decision.action = "refresh_only"
                return decision
            stage_run = (
                db.query(BinarySecurityStageRun)
                .filter(
                    BinarySecurityStageRun.task_id == task.id,
                    BinarySecurityStageRun.stage_name == resolved_stage_name,
                )
                .first()
            )
            if stage_run is None:
                decision.action = "refresh_only"
                return decision
            if (
                source_event_type == "archive_job_copied"
                and self._streaming_mode_enabled(task)
                and resolved_stage_name == "entry_analysis"
                and self._is_streaming_tail_stage(task, "dataflow_vuln_scan")
            ):
                decision.action = "refresh_only"
                return decision
            stage_status = str(getattr(stage_run, "status", "") or "").strip()
            if stage_status in TASK_TERMINAL_STATUSES:
                decision.action = "stage_terminal_apply"
                decision.stage_name = resolved_stage_name
                decision.stage_status = stage_status
                decision.summary = dict(getattr(stage_run, "output_summary", None) or {})
                return decision
            decision.action = "refresh_only"
            return decision
        return decision

    async def _apply_task_layer_reconcile_decision(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        decision,
        signal: dict[str, Any],
    ) -> bool:
        state_event_id = str(signal.get("state_event_id") or "").strip() or None
        metadata_path = Path(task.workspace_root) / "input" / "task-metadata.json"
        if decision.action in {"noop", "refresh_only"}:
            return False
        if decision.action == "stage_terminal_apply" and decision.stage_name and decision.stage_status:
            return await self._apply_task_action_after_stage_terminal(
                db,
                task,
                stage_name=decision.stage_name,
                status=decision.stage_status,
                summary=dict(decision.summary or {}),
                payload=dict(decision.payload or {}),
                state_event_id=state_event_id,
                source_event_type=str(signal.get("source_event_type") or "").strip() or None,
            )
        if decision.action == "failure_finalize":
            failure_ctx = dict((decision.payload or {}).get("failure_ctx") or {})
            if not failure_ctx:
                return False
            self._finalize_task_after_authoritative_failure(
                db,
                task,
                failure_ctx=failure_ctx,
                previous_status=str(signal.get("previous_status") or task.status or "").strip() or None,
            )
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        if decision.action == "finalize_task":
            self._finalize_task(db, task)
            await self._write_task_metadata_async(task, metadata_path, status=task.status)
            return True
        return False

    async def _run_task_layer_reconcile_signal(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        signal: dict[str, Any],
    ) -> bool:
        source_event_type = str(signal.get("source_event_type") or "").strip()
        reconcile_reason = str(signal.get("reconcile_reason") or signal.get("reason") or "").strip() or "task_layer_reconcile"
        stage_name = str(signal.get("stage_name") or task.current_stage or "").strip() or None
        state_event_id = str(signal.get("state_event_id") or "").strip() or None

        before_status = str(task.status or "").strip()
        before_stage = str(task.current_stage or "").strip()
        before_phase = str(getattr(task, "runtime_phase", "") or "").strip()
        setattr(task, "_task_enqueue_emitted", False)

        self._refresh_task_status_after_sync(db, task)
        decision = self._decide_task_layer_reconcile(
            db,
            task,
            signal=signal,
        )
        applied = await self._apply_task_layer_reconcile_decision(
            db,
            task,
            decision=decision,
            signal=signal,
        )

        after_status = str(task.status or "").strip()
        after_stage = str(task.current_stage or "").strip()
        after_phase = str(getattr(task, "runtime_phase", "") or "").strip()
        changed = applied or (before_status, before_stage, before_phase) != (after_status, after_stage, after_phase)
        self._record_event(
            db,
            task,
            "task_layer_reconcile_completed" if changed else "task_layer_reconcile_noop",
            "事实层更新已由 owner worker 串行收口任务主状态" if changed else "事实层更新已检查，未产生新的任务层变更",
            stage_name=stage_name or str(task.current_stage or "").strip() or None,
            payload={
                "source_event_type": source_event_type or None,
                "state_event_id": state_event_id,
                "reconcile_reason": reconcile_reason,
                "fact_applied": bool(signal.get("fact_applied")),
                "decision_action": getattr(decision, "action", None),
                "before_status": before_status,
                "before_stage": before_stage or None,
                "before_runtime_phase": before_phase or None,
                "after_status": after_status,
                "after_stage": after_stage or None,
                "after_runtime_phase": after_phase or None,
            },
        )
        return changed

    def _refresh_task_status_after_sync(self: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        current_status = str(task.status or "").strip()

        def _normalize_running_lease_invariant(reason: str) -> bool:
            return self._repair_running_lease_invariant(
                db,
                task,
                reason=reason,
                stage_name=str(task.current_stage or "").strip() or None,
                event_payload={"source": "refresh_task_status_after_sync"},
            )

        early_outcome = self._refresh_task_status_after_sync_early_return(db, task)
        if early_outcome:
            _normalize_running_lease_invariant("refresh_task_status_after_sync_early_return")
            return
        stage_runs = self._refresh_task_status_after_sync_refresh_authoritative_stages(db, task)
        if any(
            str(run.status or "").strip() == "failed"
            and str(getattr(run, "stage_name", "") or "").strip() == str(task.current_stage or "").strip()
            and self._is_terminal_business_stage_failure(task, run)
            for run in stage_runs
        ):
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="当前阶段出现终态业务失败，任务回到待执行等待后续处理",
                status="pending",
                stage_name=task.current_stage,
                finished_at=None,
                last_error=None,
            )
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
        if (
            str(authoritative_failure.get("failure_code") or "").strip() == "owner_lost_retry_exhausted"
            if authoritative_failure
            else False
        ) and self._should_finalize_after_authoritative_failure(
            db,
            task,
            failure_ctx=authoritative_failure,
            stage_runs=stage_runs,
        ):
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
            _normalize_running_lease_invariant("refresh_task_status_after_sync_streaming_parent_recovered")
            return
        if str(task.status or "").strip() == "running" and str(task.current_stage or "").strip() and not stage_runs:
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="任务缺少权威阶段运行记录，回退为待执行",
                status="pending",
                stage_name=task.current_stage,
                finished_at=None,
                last_error=None,
            )
            self._clear_task_failure_state(task)
            self._clear_task_abnormal_reason_snapshot(db, task)
        if self._refresh_task_status_after_sync_handle_active_running_stages(db, task, stage_runs=stage_runs, previous_status=current_status):
            _normalize_running_lease_invariant("refresh_task_status_after_sync_active_running_stages")
            return
        if self._refresh_task_status_after_sync_handle_retry_and_reopen(db, task, stage_runs=stage_runs, previous_status=current_status):
            _normalize_running_lease_invariant("refresh_task_status_after_sync_retry_or_reopen")
            return
        finalize_gate = self._evaluate_task_finalization_gate(db, task, stage_runs=stage_runs)
        if not finalize_gate.allowed:
            self._handle_finalize_gate_blocked_active_path(
                db,
                task,
                stage_runs=stage_runs,
                finalize_gate=finalize_gate,
            )
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
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="owned execution 已触发重排队，任务保持待执行",
                status="pending",
                stage_name=task.current_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                finished_at=None,
                clear_runtime_owner=True,
            )
            return True
        active_cancel_operation = self._active_cancel_operation(db, task.id)
        if self._ensure_task_remains_cancelling(db, task, active_cancel_operation=active_cancel_operation) is not None:
            return True
        if self._recover_failed_cancelled_task_state(db, task):
            return True
        active_operation = self._active_operation(db, task.id)
        if task.status == "cancelled":
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="取消任务进入 terminal 收口",
                stage_name=task.current_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                finished_at=task.finished_at or task_manager_module._now(),
                clear_runtime_owner=True,
            )
            self._invalidate_task_execution(task)
            return True
        if task.status == task_manager_module.TASK_STATUS_CANCEL_FAILED:
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="取消失败任务进入 terminal 收口",
                stage_name=task.current_stage,
                status=task_manager_module.TASK_STATUS_CANCEL_FAILED,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                finished_at=task.finished_at or task_manager_module._now(),
                last_error=task.last_error,
                clear_runtime_owner=True,
            )
            self._invalidate_task_execution(task)
            return True
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="待模块确认任务保持 owned execution 运行期状态",
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                finished_at=None,
                clear_runtime_owner=True,
                record_blocked_event=False,
            )
            return True
        if active_operation is not None:
            if self._release_unsupported_task_row_owner(
                db,
                task,
                active_operation=active_operation,
                reason="active_operation_without_local_runtime",
            ):
                self._apply_task_main_state_update(
                    db,
                    task,
                    source="state_machine",
                    reason="活动操作接管运行期 owner 后保持 owned execution",
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                    record_blocked_event=False,
                )
                task.current_operation_id = active_operation.id
                return True
            if self._task_runtime_phase(task) != task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                self._apply_task_main_state_update(
                    db,
                    task,
                    source="state_machine",
                    reason="活动操作存在，任务维持 owned execution 运行期状态",
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                    last_error=None if str(active_operation.status or "").strip() in {"accepted", "queued", "running"} else self._MAIN_STATE_UNSET,
                    record_blocked_event=False,
                )
            else:
                self._apply_task_main_state_update(
                    db,
                    task,
                    source="state_machine",
                    reason="tail reconcile 期间存在活动操作，保留当前运行期状态",
                    finished_at=None,
                    last_error=None if str(active_operation.status or "").strip() in {"accepted", "queued", "running"} else self._MAIN_STATE_UNSET,
                    record_blocked_event=False,
                )
            task.current_operation_id = active_operation.id
            return True
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        if (
            task.status == "failed"
            and not stage_runs
            and not db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).first()
        ):
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="失败任务缺少阶段事实时进入 terminal 收口",
                status="failed",
                stage_name=task.current_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                finished_at=task.finished_at or task_manager_module._now(),
                last_error=task.last_error,
                clear_runtime_owner=True,
            )
            self._invalidate_task_execution(task)
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
        if authoritative_failure_ctx is not None and self._should_finalize_after_authoritative_failure(
            db,
            task,
            failure_ctx=authoritative_failure_ctx,
            stage_runs=stage_runs,
        ):
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
            next_runtime_phase = task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
            clear_runtime_owner = False
            if self._is_streaming_tail_stage(task, task.current_stage) and self._tail_requires_execution_takeover(db, task):
                task.tail_reconcile_state = "idle"
            else:
                next_runtime_phase = (
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, task.current_stage) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
                )
                clear_runtime_owner = True
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="dispatching 状态无法保留时回退为待执行",
                status="pending",
                stage_name=task.current_stage,
                runtime_phase=next_runtime_phase,
                finished_at=None,
                last_error=None,
                clear_runtime_owner=clear_runtime_owner,
            )
            self._clear_task_failure_state(task)
            self._clear_task_abnormal_reason_snapshot(db, task)
            return True
        self._apply_task_main_state_update(
            db,
            task,
            source="state_machine",
            reason="存在活跃阶段运行，任务进入运行态",
            status="running",
            stage_name=task.current_stage,
            finished_at=None,
            last_error=None,
        )
        active_run = next((run for run in stage_runs if run.status in {"running", "dispatching"}), None)
        active_stage_name = active_run.stage_name if active_run and active_run.stage_name else task.current_stage
        preserve_dispatch = self._should_preserve_task_dispatch_ownership(task, previous_status=previous_status)
        next_runtime_phase = task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
        if not preserve_dispatch:
            if self._is_streaming_tail_stage(task, active_stage_name) and self._tail_requires_execution_takeover(db, task):
                task.tail_reconcile_state = "idle"
            else:
                next_runtime_phase = (
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, active_stage_name) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
                )
        self._apply_task_main_state_update(
            db,
            task,
            source="state_machine",
            reason="存在活跃阶段运行，任务进入运行态",
            status="running",
            stage_name=active_stage_name,
            runtime_phase=next_runtime_phase,
            finished_at=None,
            last_error=None,
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
                        self._apply_task_main_state_update(
                            db,
                            task,
                            source="state_machine",
                            reason="tail 收口租约未建立但仍保留 streaming tail 运行态",
                            status="running",
                            stage_name=task.current_stage,
                            finished_at=None,
                            last_error=None,
                        )
                    else:
                        self._apply_task_main_state_update(
                            db,
                            task,
                            source="state_machine",
                            reason="tail 收口租约未建立，任务回到待执行",
                            status="pending",
                            stage_name=task.current_stage,
                            finished_at=None,
                            last_error=None,
                        )
            else:
                self._apply_task_main_state_update(
                    db,
                    task,
                    source="state_machine",
                    reason="非 tail reconcile 活跃阶段释放运行期 owner，等待 worker 重新接管",
                    clear_runtime_owner=True,
                    record_blocked_event=False,
                )
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

        def _apply_retry_reopen_patch(
            *,
            status: str,
            reason: str,
            stage_name: str | None,
            runtime_phase: str | None = None,
            clear_runtime_owner: bool = False,
            finished_at: Any = None,
            last_error: Any = None,
        ) -> bool:
            return self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason=reason,
                status=status,
                stage_name=stage_name,
                runtime_phase=runtime_phase,
                finished_at=finished_at,
                last_error=last_error,
                clear_runtime_owner=clear_runtime_owner,
            )

        current_status = str(previous_status or "").strip()
        vuln_run = next((run for run in stage_runs if normalize_stage_name(run.stage_name) == "dataflow_vuln_scan"), None)
        streaming_dataflow_ready = self._streaming_dataflow_terminalization_ready(db, task)
        workflow_snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
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
            and streaming_dataflow_ready
            and str(vuln_run.status or "").strip() in {"success", "partial_success"}
        ):
            failed_stage_run = None
        if (
            failed_stage_run is not None
            and self._streaming_mode_enabled(task)
            and normalize_stage_name(str(failed_stage_run.stage_name or "").strip()) == "dataflow_vuln_scan"
            and not streaming_dataflow_ready
            and not had_stage_retry_mode
            and not had_task_retry_mode
        ):
            failed_items = self._stage_items(db, task.id, "dataflow_vuln_scan")
            deferred_status = "running" if any(str(item.status or "").strip() in {"running", "dispatching"} for item in failed_items) else "pending"
            failed_stage_name = failed_stage_run.stage_name or task.current_stage
            if self._tail_requires_execution_takeover(db, task):
                _apply_retry_reopen_patch(
                    status=deferred_status,
                    reason="streaming dataflow 尾段未终态，任务按权威结果刷新状态",
                    stage_name=failed_stage_name,
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                    last_error=None,
                )
                task.tail_reconcile_state = "idle"
            else:
                next_runtime_phase = (
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
                )
                _apply_retry_reopen_patch(
                    status=deferred_status,
                    reason="streaming dataflow 尾段未终态，任务按权威结果刷新状态",
                    stage_name=failed_stage_name,
                    runtime_phase=next_runtime_phase,
                    finished_at=None,
                    last_error=None,
                    clear_runtime_owner=True,
                )
                if next_runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
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
                _apply_retry_reopen_patch(
                    status="pending",
                    reason="owner lost 可恢复，任务回到待执行",
                    stage_name=failed_stage_run.stage_name or task.current_stage,
                    runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                    last_error=None,
                    clear_runtime_owner=True,
                )
                self._clear_task_abnormal_reason_snapshot(db, task)
                return True
            if self._is_streaming_tail_stage(task, failed_stage_run.stage_name):
                streaming_status = "running" if str(task.status or "").strip() in {"running", "dispatching"} else "pending"
                failed_stage_name = failed_stage_run.stage_name or task.current_stage
                if self._tail_requires_execution_takeover(db, task):
                    _apply_retry_reopen_patch(
                        status=streaming_status,
                        reason="streaming tail 失败阶段根据当前上下文刷新任务状态",
                        stage_name=failed_stage_name,
                        runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                        finished_at=None,
                        last_error=None,
                    )
                    task.tail_reconcile_state = "idle"
                else:
                    next_runtime_phase = (
                        task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                        if self._should_enter_tail_reconciliation(db, task)
                        else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
                    )
                    _apply_retry_reopen_patch(
                        status=streaming_status,
                        reason="streaming tail 失败阶段根据当前上下文刷新任务状态",
                        stage_name=failed_stage_name,
                        runtime_phase=next_runtime_phase,
                        finished_at=None,
                        last_error=None,
                        clear_runtime_owner=True,
                    )
                    if next_runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
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
                _apply_retry_reopen_patch(
                    status="failed",
                    reason="owner pod lost 且无可恢复子项，任务失败",
                    stage_name=failed_stage_run.stage_name or task.current_stage,
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                    clear_runtime_owner=True,
                    finished_at=task.finished_at or task_manager_module._now(),
                )
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
            _apply_retry_reopen_patch(
                status="pending",
                reason="失败阶段等待重新接管，任务回到待执行",
                stage_name=failed_stage_run.stage_name or task.current_stage,
                runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                finished_at=None,
                last_error=None,
                clear_runtime_owner=True,
            )
            self._clear_task_abnormal_reason_snapshot(db, task)
            return True
        if (
            failed_stage_run is not None
            and not self._should_reopen_failed_stage_after_archive_input_repair(db, task, failed_stage_run)
            and self._stage_ready_to_escalate_failure(workflow_snapshots, str(failed_stage_run.stage_name or "").strip())
            and self._should_terminalize_parent_for_failed_stage(task, failed_stage_run)
            and self._should_finalize_after_authoritative_failure(
                db,
                task,
                failure_ctx={
                    "stage_name": failed_stage_run.stage_name or task.current_stage,
                },
                stage_runs=stage_runs,
            )
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
            if exhausted_owner_lost_items and self._should_finalize_after_authoritative_failure(
                db,
                task,
                failure_ctx={
                    "stage_name": failed_stage_run.stage_name or task.current_stage,
                },
                stage_runs=stage_runs,
            ):
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
                    if not self._should_finalize_after_authoritative_failure(
                        db,
                        task,
                        failure_ctx={
                            "stage_name": failed_stage_run.stage_name or task.current_stage,
                        },
                        stage_runs=stage_runs,
                    ):
                        return False
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
            if not self._stage_ready_to_escalate_failure(workflow_snapshots, str(failed_stage_run.stage_name or "").strip()):
                _apply_retry_reopen_patch(
                    status="running" if any(bool(snapshot.get("has_active_items")) or str(snapshot.get("status") or "").strip() in {"running", "dispatching"} for snapshot in workflow_snapshots) else "pending",
                    reason="失败阶段尚未满足升级失败条件，任务保持活跃",
                    stage_name=self._workflow_blocked_on_stage(task, workflow_snapshots) or failed_stage_run.stage_name or task.current_stage,
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                    last_error=None,
                )
                self._clear_task_abnormal_reason_snapshot(db, task)
                return True
            if self._is_terminal_business_stage_failure(task, failed_stage_run):
                _apply_retry_reopen_patch(
                    status="pending",
                    reason="终态业务失败阶段等待后续人工或系统处理，任务回到待执行",
                    stage_name=failed_stage_run.stage_name or task.current_stage,
                    finished_at=None,
                    last_error=None,
                )
                self._clear_task_abnormal_reason_snapshot(db, task)
                return True
            failed_stage_name = failed_stage_run.stage_name or task.current_stage
            if self._is_streaming_tail_stage(task, failed_stage_run.stage_name) and self._tail_requires_execution_takeover(db, task):
                _apply_retry_reopen_patch(
                    status="pending",
                    reason="失败阶段等待重新接管，任务保持待执行",
                    stage_name=failed_stage_name,
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                )
                task.tail_reconcile_state = "idle"
            else:
                next_runtime_phase = (
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, failed_stage_run.stage_name) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
                )
                _apply_retry_reopen_patch(
                    status="pending",
                    reason="失败阶段等待重新接管，任务保持待执行",
                    stage_name=failed_stage_name,
                    runtime_phase=next_runtime_phase,
                    finished_at=None,
                    clear_runtime_owner=True,
                )
                if next_runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
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
            next_task_status = "running" if str(next_stage_status or "").strip() in {"running", "dispatching"} else "pending"
            if self._is_streaming_tail_stage(task, next_stage) and self._tail_requires_execution_takeover(db, task):
                _apply_retry_reopen_patch(
                    status=next_task_status,
                    reason="下一个未完成阶段存在可执行工作，刷新任务状态",
                    stage_name=next_stage,
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    finished_at=None,
                    last_error=None,
                )
                task.tail_reconcile_state = "idle"
            else:
                next_runtime_phase = (
                    task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    if self._is_streaming_tail_stage(task, next_stage) and self._should_enter_tail_reconciliation(db, task)
                    else task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION
                )
                _apply_retry_reopen_patch(
                    status=next_task_status,
                    reason="下一个未完成阶段存在可执行工作，刷新任务状态",
                    stage_name=next_stage,
                    runtime_phase=next_runtime_phase,
                    finished_at=None,
                    last_error=None,
                    clear_runtime_owner=True,
                )
                if next_runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION:
                    lease = self._activate_tail_reconciliation(
                        db,
                        task,
                        now_value=task_manager_module._now(),
                        fallback_status="pending",
                        takeover_result="refresh",
                    )
                    if not self._runtime_lease_is_active(lease):
                        _apply_retry_reopen_patch(
                            status="pending",
                            reason="tail 收口租约未建立，下一个阶段等待重新调度",
                            stage_name=next_stage,
                            finished_at=None,
                        )
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
            _apply_retry_reopen_patch(
                status="failed",
                reason="无后续阶段且存在失败阶段，任务终止失败",
                stage_name=failed_stage_run.stage_name or task.current_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                clear_runtime_owner=True,
                finished_at=task.finished_at or task_manager_module._now(),
            )
            return True
        if (
            failed_stage_run is not None
            and not had_stage_retry_mode
            and not had_task_retry_mode
            and not (
                self._streaming_mode_enabled(task)
                and normalize_stage_name(str(failed_stage_run.stage_name or "").strip()) == "dataflow_vuln_scan"
                and not streaming_dataflow_ready
            )
        ):
            failed_items = self._stage_items(db, task.id, str(failed_stage_run.stage_name or ""))
            if failed_items and not self._stage_has_nonterminal_items(failed_items):
                _apply_retry_reopen_patch(
                    status="failed",
                    reason="失败阶段已无非终态子项，任务终止失败",
                    stage_name=failed_stage_run.stage_name or task.current_stage,
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                    clear_runtime_owner=True,
                    finished_at=task.finished_at or task_manager_module._now(),
                )
                return True
        return False

    def _finalize_task(self: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        from app.service import task_manager as task_manager_module

        with self._task_execution_owner_lock:
            self._task_execution_owners.pop(task.id, None)
        if self._finalize_task_handle_terminal_shortcuts(db, task):
            return
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        finalize_gate = self._evaluate_task_finalization_gate(db, task, stage_runs=stage_runs)
        if not finalize_gate.allowed:
            task_manager_module.logger.info(
                "binary-security finalize gate blocked task_id=%s reason=%s blocked_by_stage=%s next_stage=%s",
                task.id,
                finalize_gate.reason_code or "-",
                finalize_gate.blocked_by_stage or "-",
                finalize_gate.next_stage or "-",
            )
            self._handle_finalize_gate_blocked_active_path(
                db,
                task,
                stage_runs=stage_runs,
                finalize_gate=finalize_gate,
            )
            return
        workflow_snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
        snapshots = workflow_snapshots
        workflow_terminalization_ready = self._workflow_ready_for_finalization(snapshots)
        if not workflow_terminalization_ready:
            blocked_stage = self._workflow_blocked_on_stage(task, snapshots)
            if blocked_stage is None:
                blocked_stage = next(
                    (
                        str(snapshot.get("stage_name") or "").strip()
                        for snapshot in snapshots
                        if str(snapshot.get("status") or "").strip() == "partial_success"
                        and not self._partial_success_advancement_enabled(task, str(snapshot.get("stage_name") or "").strip())
                    ),
                    None,
                )
            blocked_snapshot = next((snapshot for snapshot in snapshots if str(snapshot.get("stage_name") or "").strip() == str(blocked_stage or "").strip()), None)
            blocked_status = str((blocked_snapshot or {}).get("status") or "").strip()
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="工作流未满足最终收口条件，任务保持活跃",
                status="running" if blocked_status in {"running", "dispatching"} or bool((blocked_snapshot or {}).get("has_active_items")) else "pending",
                stage_name=blocked_stage or task.current_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )
            task.tail_reconcile_state = "idle"
            self._last_task_heartbeat_at.pop(task.id, None)
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            return
        final_status = self._aggregate_workflow_terminal_status(task, snapshots)
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
        if stale_stages and final_status == "success" and (
            str(getattr(task, "status", "") or "").strip() == "partial_success"
            or has_materialized_stale_context
        ):
            final_status = "partial_success"
        self._apply_task_main_state_update(
            db,
            task,
            source="state_machine",
            reason="工作流全部阶段完成，聚合最终任务状态",
            status=final_status,
            stage_name=task.current_stage,
            runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
            clear_runtime_owner=True,
            finished_at=task_manager_module._now(),
        )
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

    def _handle_finalize_gate_blocked_active_path(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_runs: list[BinarySecurityStageRun] | None = None,
        finalize_gate=None,
    ) -> bool:
        from app.service import task_manager as task_manager_module

        runs = list(stage_runs or db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all())
        gate = finalize_gate or self._evaluate_task_finalization_gate(db, task, stage_runs=runs)
        task_manager_module.logger.info(
            "binary-security finalize gate diverted task_id=%s reason=%s blocked_by_stage=%s next_stage=%s",
            task.id,
            gate.reason_code or "-",
            gate.blocked_by_stage or "-",
            gate.next_stage or "-",
        )
        if self._finalize_task_handle_active_progress(db, task, stage_runs=runs):
            return True
        snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=runs)
        blocked_stage = str(gate.next_stage or gate.blocked_by_stage or self._workflow_blocked_on_stage(task, snapshots) or task.current_stage or "").strip()
        blocked_snapshot = next(
            (snapshot for snapshot in snapshots if str(snapshot.get("stage_name") or "").strip() == blocked_stage),
            None,
        )
        blocked_status = str((blocked_snapshot or {}).get("status") or "").strip()
        if gate.reason_code == "pending_stage_materialization":
            next_status = "pending"
        else:
            next_status = "running" if blocked_status in {"running", "dispatching", "applying"} or bool((blocked_snapshot or {}).get("has_active_items")) else "pending"
        if blocked_stage:
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="finalize gate 未通过，任务保持活跃等待继续推进",
                status=next_status,
                stage_name=blocked_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )
            task.tail_reconcile_state = "idle"
            self._release_tail_reconcile_owner(task.id)
            self._last_task_heartbeat_at.pop(task.id, None)
            self._record_event(
                db,
                task,
                "task_finalize_deferred_for_incomplete_stage",
                f"任务仍可继续推进，延迟任务收口: {blocked_stage}",
                level="info",
                stage_name=blocked_stage,
                payload={"reason_code": gate.reason_code, "stage_status": blocked_status or None},
            )
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            if (
                next_status == "pending"
                and (gate.has_resumable_path or gate.has_pending_materialization)
                and not bool(getattr(task, "_task_enqueue_emitted", False))
            ):
                setattr(task, "_task_enqueue_emitted", True)
                self._enqueue_task(task.id)
            return True
        return False

    def _finalize_task_handle_terminal_shortcuts(self: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        from app.service import task_manager as task_manager_module

        if self._ensure_task_remains_cancelling(db, task) is not None:
            self._last_task_heartbeat_at.pop(task.id, None)
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            return True
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="待模块确认任务保持 owned execution 运行期状态",
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                record_blocked_event=False,
            )
            self._sync_task_abnormal_reason_snapshot(db, task, None)
            self._last_task_heartbeat_at.pop(task.id, None)
            return True
        if task.status in {"cancelled", task_manager_module.TASK_STATUS_CANCEL_FAILED}:
            finished_at = (
                task.finished_at or task_manager_module._now()
                if task.status == task_manager_module.TASK_STATUS_CANCEL_FAILED
                else task_manager_module._now()
            )
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="终态取消任务进入 terminal 收口",
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TERMINAL,
                clear_runtime_owner=task.status != task_manager_module.TASK_STATUS_CANCEL_FAILED,
                finished_at=finished_at,
                record_blocked_event=False,
            )
            stage_sequence = self._stage_sequence_for_task(task)
            stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
            items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all()
            archive_jobs = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.task_id == task.id).all()
            stage_summaries = self._build_stage_summaries(db, task, stage_sequence, stage_runs, items)
            self._sync_task_abnormal_reason_snapshot(db, task, self._task_abnormal_reason(task, stage_summaries, items, archive_jobs))
            if task.status == task_manager_module.TASK_STATUS_CANCEL_FAILED:
                self._invalidate_task_execution(task)
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
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="深度模式仍有上游阶段活跃，任务延迟收口",
                status="running" if active_streaming_status in {"running", "dispatching", "applying"} else "pending",
                stage_name=active_streaming_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )
            task.tail_reconcile_state = "idle"
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
        next_active_status = "running" if active_stage_status in {"running", "dispatching", "applying"} else "pending"
        if (
            self._is_streaming_tail_stage(task, active_stage_name)
            and self._tail_requires_execution_takeover(db, task)
            and str(active_stage_status or "").strip() in {"running", "dispatching", "applying"}
        ):
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="活跃 tail 阶段需转回 owned execution 继续执行",
                status="running",
                stage_name=active_stage_name,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )
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
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="活跃 tail 阶段进入 tail reconciliation",
                status="running",
                stage_name=active_stage_name,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )
            task.tail_reconcile_state = "idle"
        else:
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="仍有活跃未完成阶段，任务延迟最终收口",
                status=next_active_status,
                stage_name=active_stage_name or task.current_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )
            self._release_tail_reconcile_owner(task.id)
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

        snapshots = self._build_workflow_stage_snapshots(db, task, stage_runs=stage_runs)
        workflow_blocked_stage = self._workflow_blocked_on_stage(task, snapshots)
        next_stage = self._next_incomplete_stage(db, task)
        if workflow_blocked_stage is None and self._workflow_ready_for_finalization(snapshots):
            return False
        if workflow_blocked_stage:
            next_stage = workflow_blocked_stage
        if next_stage:
            next_stage_run = next((run for run in stage_runs if run.stage_name == next_stage), None)
            next_stage_items = self._stage_items(db, task.id, next_stage)
            next_snapshot = next((snapshot for snapshot in snapshots if str(snapshot.get("stage_name") or "").strip() == next_stage), None)
            next_stage_status = str((next_snapshot or {}).get("status") or (
                self._normalize_downstream_status(next_stage_run.status) or str(next_stage_run.status or "").strip()
                if next_stage_run is not None
                else "pending"
            )).strip()
            self._apply_task_main_state_update(
                db,
                task,
                source="state_machine",
                reason="任务仍有未完成阶段，保持活跃等待继续推进",
                status="running" if next_stage_status in {"running", "dispatching", "applying"} or bool((next_snapshot or {}).get("has_active_items")) else "pending",
                stage_name=workflow_blocked_stage or next_stage,
                runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                clear_runtime_owner=True,
                finished_at=None,
                last_error=None,
            )
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
            if missing_enabled_stage and workflow_blocked_stage:
                if not self._apply_task_main_state_update(
                    db,
                    task,
                    source="state_machine",
                    reason="缺少已启用阶段的执行记录，任务回到待执行等待补跑",
                    stage_name=missing_enabled_stage,
                    status="pending",
                    runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    clear_runtime_owner=True,
                    finished_at=None,
                    last_error=None,
                ):
                    return True
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
