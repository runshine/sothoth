from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, normalize_stage_name
from app.observability import observe_task_snapshot_lock_retry

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskStageRuntimeMixin:
    def _streaming_dataflow_materialized_item_keys(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> list[str]:
        if not self._streaming_mode_enabled(task):
            return []
        keys: list[str] = []
        seen: set[str] = set()
        for item in list(self._stage_items(db, task.id, "dataflow_vuln_scan") or []):
            entry_key = str(getattr(item, "item_key", "") or "").strip()
            if not entry_key or entry_key in seen:
                continue
            seen.add(entry_key)
            keys.append(entry_key)
        return keys

    def _build_streaming_dataflow_completion_gate(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> dict[str, object]:
        module_state = self._entry_module_completion_state(task, db)
        materialized_item_keys = self._streaming_dataflow_materialized_item_keys(db, task)
        materialized_key_set = set(materialized_item_keys)
        expected_entry_keys = [
            str(entry.get("entry_key") or "").strip()
            for entry in list(self._effective_entry_inputs(task, db) or [])
            if isinstance(entry, dict) and str(entry.get("entry_key") or "").strip()
        ]
        expected_key_set = set(expected_entry_keys)
        missing_entry_keys = [key for key in expected_entry_keys if key not in materialized_key_set]
        counts_aligned = len(expected_key_set) == len(materialized_key_set)
        ready_for_terminal_status = bool(
            bool(module_state.get("complete"))
            and counts_aligned
            and not missing_entry_keys
        )
        return {
            "entry_analysis_status": None,
            "entry_analysis_terminal": bool(module_state.get("complete")),
            "expected_entry_keys": expected_entry_keys,
            "expected_entry_count": len(expected_key_set),
            "materialized_item_keys": materialized_item_keys,
            "materialized_item_count": len(materialized_key_set),
            "counts_aligned": counts_aligned,
            "missing_entry_keys": missing_entry_keys,
            "missing_entry_count": len(missing_entry_keys),
            "expected_entry_module_count": int(module_state.get("expected_module_count") or 0),
            "materialized_entry_module_count": int(module_state.get("materialized_module_count") or 0),
            "missing_module_keys": list(module_state.get("missing_module_keys") or []),
            "module_counts_aligned": bool(module_state.get("complete")),
            "ready_for_terminal_status": ready_for_terminal_status,
        }

    def _streaming_dataflow_gate_should_defer_terminal_status(
        self: TaskManager,
        task: BinarySecurityTask,
        items: list[BinarySecurityStageItem],
        gate: dict[str, object] | None,
        *,
        aggregated_status: str | None,
    ) -> bool:
        if not gate:
            return False
        if aggregated_status not in {"success", "partial_success", "failed", "cancelled", "downstream_missing"}:
            return False
        if bool(gate.get("ready_for_terminal_status")):
            return False
        expected_entry_count = int(gate.get("expected_entry_count") or 0)
        materialized_item_count = int(gate.get("materialized_item_count") or 0)
        if expected_entry_count == materialized_item_count:
            return False
        if not items:
            return True
        item_statuses = [str(getattr(item, "status", "") or "").strip() for item in items]
        if all(status in {"success", "partial_success"} for status in item_statuses):
            return False
        return True

    def _streaming_dataflow_gate_deferred_status(
        self: TaskManager,
        items: list[BinarySecurityStageItem],
    ) -> str:
        if any(str(item.status or "").strip() == "running" for item in items):
            return "running"
        if any(str(item.status or "").strip() == "dispatching" for item in items):
            return "dispatching"
        return "pending"

    def _empty_streaming_stage_run_status(
        self: TaskManager,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
    ) -> str:
        if not self._streaming_mode_enabled(task) or not self._is_streaming_tail_stage(task, stage_run.stage_name):
            return "pending"
        current = str(stage_run.status or "").strip()
        if current == "success":
            return current
        if current in {"failed", "downstream_missing", "cancelled", "partial_success"}:
            return "pending"
        if current in {"running", "dispatching"}:
            return "running"
        if current in {"queued", "pending"}:
            return "pending"
        return "pending"

    def _empty_streaming_stage_run_last_error(
        self: TaskManager,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
    ) -> str | None:
        if not self._streaming_mode_enabled(task) or not self._is_streaming_tail_stage(task, stage_run.stage_name):
            return None
        current_status = str(stage_run.status or "").strip()
        if current_status in {"failed", "downstream_missing", "partial_success"}:
            return stage_run.last_error
        return None

    def _refresh_streaming_tail_stage_state(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> None:
        self._refresh_stage_run_from_items(db, task, stage_name)
        if stage_name == "entry_analysis":
            stage_run = self._latest_stage_run(db, task.id, stage_name)
            try:
                self._rebuild_entry_results_from_stage_items(db, task, stage_run)
            except TypeError:
                # Keep older test doubles and monkeypatches working when they still use the
                # historical 2-arg helper signature.
                self._rebuild_entry_results_from_stage_items(db, task)
        elif normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            self._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")

    def _refresh_stage_from_authoritative_items_once(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> BinarySecurityStageRun | None:
        handler = self._stage_handler(stage_name)
        if handler is not None and handler.manages_stage_refresh():
            handler.refresh_summary_from_items(self, db, task)
        elif self._is_streaming_tail_stage(task, stage_name):
            self._refresh_streaming_tail_stage_state(db, task, stage_name)
        else:
            self._refresh_stage_run_from_items(db, task, stage_name)
        return self._latest_stage_run(db, task.id, stage_name)

    def _refresh_stage_from_authoritative_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        retry_on_lock: bool = True,
        operation: str = "authoritative_stage_refresh",
    ) -> BinarySecurityStageRun | None:
        from app.service import task_manager as task_manager_module

        attempts = self._retryable_write_attempts() if retry_on_lock else 1
        task_id = str(task.id or "").strip()
        for attempt in range(1, attempts + 1):
            try:
                return self._refresh_stage_from_authoritative_items_once(db, task, stage_name)
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc):
                    raise
                result = "retry_scheduled" if attempt < attempts else "failed"
                observe_task_snapshot_lock_retry(
                    operation=operation,
                    stage=stage_name,
                    result=result,
                )
                task_manager_module.logger.warning(
                    "binary-security task snapshot lock conflict task_id=%s stage_name=%s operation=%s attempt=%s result=%s runtime_role=%s",
                    task_id or "-",
                    stage_name or "-",
                    operation,
                    attempt,
                    result,
                    self._service_role(),
                    exc_info=(attempt >= attempts),
                )
                with suppress(Exception):
                    db.rollback()
                if attempt >= attempts:
                    raise
                self._sleep_after_retryable_lock_error(attempt)
                refreshed_task = (
                    db.query(BinarySecurityTask)
                    .filter(BinarySecurityTask.id == task_id)
                    .first()
                )
                if refreshed_task is not None:
                    task = refreshed_task
        return None

    def _reconcile_stage_domain_in_session(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> BinarySecurityStageRun | None:
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_stage_name:
            return None
        handler = self._stage_handler(normalized_stage_name)
        if handler is not None and handler.manages_stage_refresh():
            handler.refresh_summary_from_items(self, db, task)
            return self._latest_stage_run(db, task.id, normalized_stage_name)
        self._refresh_stage_run_from_items(db, task, normalized_stage_name)
        return self._latest_stage_run(db, task.id, normalized_stage_name)

    def _reconcile_retry_affected_stages_in_session(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        stage_names: list[str],
    ) -> list[str]:
        reconciled: list[str] = []
        seen: set[str] = set()
        for stage_name in stage_names:
            normalized_stage_name = str(stage_name or "").strip()
            if not normalized_stage_name or normalized_stage_name in seen:
                continue
            seen.add(normalized_stage_name)
            self._reconcile_stage_domain_in_session(db, task, normalized_stage_name)
            reconciled.append(normalized_stage_name)
        return reconciled

    def _refresh_stage_run_from_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> None:
        from app.service import task_manager as task_manager_module

        stage_run = self._latest_stage_run(db, task.id, stage_name)
        if not stage_run:
            return
        items = self._stage_items(db, task.id, stage_name)
        deduped_items: list[BinarySecurityStageItem] = []
        seen_item_ids: set[str] = set()
        seen_identity_keys: set[str] = set()
        for item in items:
            item_id = str(item.id or "").strip()
            if item_id and item_id in seen_item_ids:
                continue
            identity_key = str(getattr(item, "item_identity_key", "") or "").strip()
            if not identity_key:
                identity_key = self._stage_item_identity(item.item_key, item.parent_key)
            if identity_key and identity_key in seen_identity_keys:
                continue
            if item_id:
                seen_item_ids.add(item_id)
            if identity_key:
                seen_identity_keys.add(identity_key)
            deduped_items.append(item)
        items = deduped_items
        streaming_dataflow_gate: dict[str, object] | None = None
        if items:
            status = self._aggregate_item_statuses([item.status for item in items])
            if status in {"success", "partial_success"} and self._stage_has_sync_degraded_items(items):
                status = "running" if any(str(item.status or "").strip() in {"running", "dispatching"} for item in items) else "pending"
            if status in {"success", "partial_success"} and self._stage_has_orchestration_degraded_items(items):
                status = "running" if any(str(item.status or "").strip() in {"running", "dispatching"} for item in items) else "pending"
            if (
                self._streaming_mode_enabled(task)
                and normalize_stage_name(stage_name) == "dataflow_vuln_scan"
                and self._is_streaming_tail_stage(task, stage_name)
            ):
                streaming_dataflow_gate = self._build_streaming_dataflow_completion_gate(db, task)
                if self._streaming_dataflow_gate_should_defer_terminal_status(
                    task,
                    items,
                    streaming_dataflow_gate,
                    aggregated_status=status,
                ):
                    deferred_status = self._streaming_dataflow_gate_deferred_status(items)
                    if deferred_status != status:
                        self._record_event(
                            db,
                            task,
                            "dataflow_terminalization_deferred_for_missing_streaming_items",
                            "数据流漏洞挖掘阶段仍在等待流式条目到齐，暂不进入终态",
                            level="info",
                            stage_name=stage_name,
                            payload={
                                "aggregated_item_status": status,
                                "deferred_stage_status": deferred_status,
                                "entry_analysis_status": streaming_dataflow_gate.get("entry_analysis_status"),
                                "expected_entry_count": int(streaming_dataflow_gate.get("expected_entry_count") or 0),
                                "materialized_item_count": int(streaming_dataflow_gate.get("materialized_item_count") or 0),
                                "missing_entry_count": int(streaming_dataflow_gate.get("missing_entry_count") or 0),
                                "missing_entry_keys_sample": list(streaming_dataflow_gate.get("missing_entry_keys") or [])[:10],
                            },
                        )
                    status = deferred_status
        else:
            status = self._empty_streaming_stage_run_status(task, stage_run)
        stage_run.status = status
        stage_run.counts = self._stage_counts(db, stage_run)
        if items:
            if status in {"failed", "partial_success", "downstream_missing", "cancelled"}:
                stage_run.last_error = next(
                    (
                        item.error_message
                        for item in items
                        if item.status in {"failed", "downstream_missing", "cancelled"} and item.error_message
                    ),
                    None,
                )
            else:
                stage_run.last_error = None
        else:
            stage_run.last_error = self._empty_streaming_stage_run_last_error(task, stage_run)
        self._merge_stage_run_output_summary(
            task,
            stage_run,
            {
                "status_synced": True,
                "sync_status": status,
                **(
                    {
                        "streaming_completion_gate_ready": bool(streaming_dataflow_gate.get("ready_for_terminal_status")),
                        "expected_entry_count": int(streaming_dataflow_gate.get("expected_entry_count") or 0),
                        "materialized_item_count": int(streaming_dataflow_gate.get("materialized_item_count") or 0),
                        "missing_entry_count": int(streaming_dataflow_gate.get("missing_entry_count") or 0),
                    }
                    if streaming_dataflow_gate is not None
                    else {}
                ),
                **stage_run.counts,
            },
        )
        items_present = bool(items)
        active_items_present = any(str(item.status or "").strip() in {"running", "dispatching"} for item in items)
        should_start = False
        if status in {"running", "dispatching"}:
            should_start = items_present
        elif status in {"pending", "queued"}:
            should_start = items_present
        if status in {"running", "pending", "queued", "dispatching"}:
            stage_run.finished_at = None
            if should_start:
                stage_run.started_at = stage_run.started_at or task_manager_module._now()
            elif self._is_streaming_tail_stage(task, stage_name) and stage_run.started_at is None:
                self._record_event(
                    db,
                    task,
                    "streaming_tail_stage_start_suppressed",
                    f"流式尾段尚无真实子项，保留未启动态: {stage_name}",
                    stage_name=stage_name,
                    payload={
                        "stage_name": stage_name,
                        "status": status,
                        "items_present": items_present,
                        "active_items_present": active_items_present,
                    },
                )
        else:
            stage_run.finished_at = stage_run.finished_at or task_manager_module._now()
        if stage_name == "firmware_unpack":
            success_items = [self._load_stage_item_result_payload(item) for item in items if item.status == "success"]
            compact_success = self._compact_stage_success_items("firmware_unpack_results", success_items)
            task.summary = {**(task.summary or {}), "firmware_unpack_results": compact_success}
            task.metrics = {
                **(task.metrics or {}),
                "unpacked_firmware_count": int(stage_run.counts.get("success_items", 0)),
                "failed_firmware_count": int(stage_run.counts.get("failed_items", 0)),
            }
        elif stage_name == "entry_analysis":
            self._rebuild_entry_results_from_stage_items(db, task, stage_run)
        self._update_task_stage_summary_entry(task, stage_run)
