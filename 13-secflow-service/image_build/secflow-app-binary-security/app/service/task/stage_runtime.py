from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, build_stage_item_identity_key, normalize_stage_name
from app.observability import observe_task_snapshot_lock_retry
from app.service.task.shared import _deduplicate_entry_keys

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskStageRuntimeMixin:
    def _queued_stage_child_create_item_ids(
        self: TaskManager,
        task_id: str,
        stage_name: str,
    ) -> set[str]:
        normalized_task_id = str(task_id or "").strip()
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_task_id or not normalized_stage_name:
            return set()
        queued_entries = self._run_async_blocking(
            task_manager_module.get_task_queue().list_task_sync_requests(
                normalized_task_id,
                context="kg_reseed_sync_queue_list",
            )
        ) or []
        queued_item_ids: set[str] = set()
        for entry in list(queued_entries or []):
            if str(entry.get("operation") or "").strip() != "child_create":
                continue
            if str(entry.get("stage_name") or "").strip() != normalized_stage_name:
                continue
            for item_id in list(entry.get("item_ids") or []):
                normalized_item_id = str(item_id or "").strip()
                if normalized_item_id:
                    queued_item_ids.add(normalized_item_id)
        return queued_item_ids

    def _available_stage_child_create_slots(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ) -> int:
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_stage_name:
            return 0
        items = stage_items if stage_items is not None else self._stage_items(db, task.id, normalized_stage_name)
        active_count = sum(1 for item in items if self._child_counts_as_active_for_parallelism(item))
        queued_create_item_ids = self._queued_stage_child_create_item_ids(task.id, normalized_stage_name)
        queued_unbound_count = sum(
            1
            for item in items
            if str(getattr(item, "id", "") or "").strip() in queued_create_item_ids
            and not str(getattr(item, "downstream_task_id", "") or "").strip()
            and not self._child_counts_as_active_for_parallelism(item)
        )
        return max(
            0,
            int(self._stage_parallelism(task, normalized_stage_name)) - active_count - queued_unbound_count,
        )

    def _stage_has_authoritative_progress_facts(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        stage_run: BinarySecurityStageRun | None = None,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ) -> bool:
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_stage_name:
            return False
        resolved_stage_run = stage_run or self._latest_stage_run(db, task.id, normalized_stage_name)
        if resolved_stage_run is not None:
            resolved_status = str(getattr(resolved_stage_run, "status", "") or "").strip().lower()
            if resolved_status in {
                "running",
                "dispatching",
                "success",
                "partial_success",
                "failed",
                "cancelled",
                "downstream_missing",
            }:
                return True
            if getattr(resolved_stage_run, "started_at", None) or getattr(resolved_stage_run, "finished_at", None):
                return True
        resolved_stage_items = stage_items if stage_items is not None else self._stage_items(db, task.id, normalized_stage_name)
        if not resolved_stage_items:
            return False
        for item in resolved_stage_items:
            item_status = str(getattr(item, "status", "") or "").strip().lower()
            if item_status in {
                "pending",
                "queued",
                "running",
                "dispatching",
                "success",
                "partial_success",
                "failed",
                "cancelled",
                "downstream_missing",
            }:
                return True
            if (
                getattr(item, "started_at", None)
                or getattr(item, "finished_at", None)
                or str(getattr(item, "downstream_task_id", "") or "").strip()
            ):
                return True
        return False

    def _advance_task_current_stage_from_authoritative_facts(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        stage_run: BinarySecurityStageRun | None = None,
        stage_items: list[BinarySecurityStageItem] | None = None,
    ) -> bool:
        normalized_stage_name = str(stage_name or "").strip()
        if not normalized_stage_name:
            return False
        sequence = self._stage_sequence_for_task(task)
        if normalized_stage_name not in sequence:
            return False
        current_stage = str(getattr(task, "current_stage", "") or "").strip()
        if current_stage == normalized_stage_name:
            return False
        if current_stage in sequence and sequence.index(current_stage) > sequence.index(normalized_stage_name):
            return False
        if not self._stage_has_authoritative_progress_facts(
            db,
            task,
            normalized_stage_name,
            stage_run=stage_run,
            stage_items=stage_items,
        ):
            return False
        previous_stage = current_stage or None
        task.current_stage = normalized_stage_name
        self._record_event(
            db,
            task,
            "task_current_stage_advanced_from_authoritative_facts",
            f"阶段权威事实已落库，父任务主阶段推进到: {normalized_stage_name}",
            level="info",
            stage_name=normalized_stage_name,
            payload={
                "previous_stage": previous_stage,
                "current_stage": normalized_stage_name,
                "advance_source": "authoritative_stage_refresh",
            },
        )
        return True

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
        db: Session,
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
        if not self._streaming_dataflow_terminalization_ready(db, task):
            return True
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
        db: Session,
        task: BinarySecurityTask,
        items: list[BinarySecurityStageItem],
    ) -> str:
        if items and not self._streaming_dataflow_terminalization_ready(db, task):
            return "running"
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
        current = str(stage_run.status or "").strip()
        if not self._streaming_mode_enabled(task) or not self._is_streaming_tail_stage(task, stage_run.stage_name):
            if current == "success":
                return current
            if current in {"running", "dispatching"}:
                return "running"
            return "pending"
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

    def _refresh_kg_streaming_inputs_if_needed(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        if not self._streaming_mode_enabled(task):
            return False
        if normalize_stage_name(self._pipeline_profile(task)) != normalize_stage_name("kg_source_vuln_scan"):
            return False
        kg_stage_run = self._latest_stage_run(db, task.id, "knowledge_graph_entry_fetch")
        if kg_stage_run is None:
            return False
        kg_stage_status = str(getattr(kg_stage_run, "status", "") or "").strip().lower()
        if kg_stage_status in {"success", "failed", "cancelled", "downstream_missing", "partial_success"}:
            return False
        if str(getattr(task, "status", "") or "").strip().lower() in {"success", "failed", "cancelled", "downstream_missing", "partial_success"}:
            return False
        previous_entry_keys = {
            str(entry.get("entry_key") or "").strip()
            for entry in list(self._effective_entry_inputs(task, db) or [])
            if isinstance(entry, dict) and str(entry.get("entry_key") or "").strip()
        }
        refresh_result = self._run_async_blocking(self._stage_knowledge_graph_entry_fetch(db, task, kg_stage_run, None, False))
        refreshed = bool(refresh_result)
        current_entry_keys = {
            str(entry.get("entry_key") or "").strip()
            for entry in list(self._effective_entry_inputs(task, db) or [])
            if isinstance(entry, dict) and str(entry.get("entry_key") or "").strip()
        }
        new_entry_keys = sorted(current_entry_keys - previous_entry_keys)
        created_item_ids: list[str] = []
        scheduled_item_ids: list[str] = []
        available_slots = 0
        if new_entry_keys:
            dataflow_stage_run = self._latest_stage_run(db, task.id, "dataflow_vuln_scan")
            if dataflow_stage_run is not None:
                stage_inputs = [
                    entry
                    for entry in list(self._effective_entry_inputs(task, db) or [])
                    if isinstance(entry, dict)
                ]
                self._prepare_stage_items_for_execution(
                    db,
                    task=task,
                    stage_run=dataflow_stage_run,
                    inputs=_deduplicate_entry_keys(stage_inputs),
                    downstream_service="dataflow_vuln_scan",
                    identity=lambda entry: (
                        entry["entry_key"],
                        entry["function_name"],
                        entry.get("module_key"),
                        entry,
                    ),
                    output_ref=lambda _entry: {},
                )
                target_identity_keys = {
                    build_stage_item_identity_key(
                        str(entry.get("entry_key") or "").strip(),
                        entry.get("module_key"),
                    )
                    for entry in stage_inputs
                    if isinstance(entry, dict) and str(entry.get("entry_key") or "").strip() in new_entry_keys
                }
                created_item_ids = [
                    str(item.id or "").strip()
                    for item in self._stage_items(db, task.id, "dataflow_vuln_scan")
                    if (
                        str(item.item_identity_key or "").strip() in target_identity_keys
                        and str(item.status or "").strip().lower() in {"queued", "pending", "dispatching", "running"}
                        and not str(item.downstream_task_id or "").strip()
                    )
                ]
                child_create_candidate_count = len(created_item_ids)
                available_slots = self._available_stage_child_create_slots(
                    db,
                    task,
                    "dataflow_vuln_scan",
                )
                scheduled_item_ids = created_item_ids[:available_slots] if available_slots > 0 else []
                if scheduled_item_ids:
                    self._run_async_blocking(
                        self._enqueue_task_sync_request(
                            task,
                            db=db,
                            operation="child_create",
                            source="knowledge_graph_incremental_reseed",
                            reason="knowledge_graph_incremental_reseed_child_create",
                            stage_name="dataflow_vuln_scan",
                            item_ids=scheduled_item_ids,
                            source_event_type="knowledge_graph_entry_incremental_inputs_materialized",
                            payload={
                                "new_entry_keys": new_entry_keys[:50],
                                "new_entry_count": len(new_entry_keys),
                                "child_create_candidate_count": child_create_candidate_count,
                                "child_create_scheduled_count": len(scheduled_item_ids),
                                "child_create_deferred_count": max(0, child_create_candidate_count - len(scheduled_item_ids)),
                                "available_slots_at_enqueue": available_slots,
                            },
                            priority=10,
                        )
                    )
            self._record_event(
                db,
                task,
                "knowledge_graph_entry_incremental_inputs_materialized",
                "知识图谱增量入口已写回任务输入，等待数据流漏洞挖掘阶段继续创建新子任务",
                level="info",
                stage_name="knowledge_graph_entry_fetch",
                payload={
                    "new_entry_count": len(new_entry_keys),
                    "new_entry_keys_sample": new_entry_keys[:10],
                    "previous_entry_count": len(previous_entry_keys),
                    "current_entry_count": len(current_entry_keys),
                    "dataflow_reseeded": dataflow_stage_run is not None,
                    "dataflow_child_create_enqueued": bool(scheduled_item_ids),
                    "created_item_count": len(created_item_ids),
                    "child_create_candidate_count": len(created_item_ids),
                    "child_create_scheduled_count": len(scheduled_item_ids),
                    "child_create_deferred_count": max(0, len(created_item_ids) - len(scheduled_item_ids)),
                    "available_slots_at_enqueue": available_slots if new_entry_keys else 0,
                },
            )
        return refreshed or bool(new_entry_keys)

    def _refresh_stage_from_authoritative_items_once(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
    ) -> BinarySecurityStageRun | None:
        normalized_stage_name = normalize_stage_name(stage_name)
        if normalized_stage_name == "dataflow_vuln_scan":
            self._refresh_kg_streaming_inputs_if_needed(db, task)
        handler = self._stage_handler(stage_name)
        if handler is not None and handler.manages_stage_refresh():
            handler.refresh_summary_from_items(self, db, task)
        elif self._is_streaming_tail_stage(task, stage_name):
            self._refresh_streaming_tail_stage_state(db, task, stage_name)
        else:
            self._refresh_stage_run_from_items(db, task, stage_name)
        stage_run = self._latest_stage_run(db, task.id, stage_name)
        stage_items = self._stage_items(db, task.id, stage_name)
        self._advance_task_current_stage_from_authoritative_facts(
            db,
            task,
            stage_name,
            stage_run=stage_run,
            stage_items=stage_items,
        )
        return stage_run

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
            stage_run = self._latest_stage_run(db, task.id, normalized_stage_name)
            stage_items = self._stage_items(db, task.id, normalized_stage_name)
            self._advance_task_current_stage_from_authoritative_facts(
                db,
                task,
                normalized_stage_name,
                stage_run=stage_run,
                stage_items=stage_items,
            )
            return stage_run
        self._refresh_stage_run_from_items(db, task, normalized_stage_name)
        stage_run = self._latest_stage_run(db, task.id, normalized_stage_name)
        stage_items = self._stage_items(db, task.id, normalized_stage_name)
        self._advance_task_current_stage_from_authoritative_facts(
            db,
            task,
            normalized_stage_name,
            stage_run=stage_run,
            stage_items=stage_items,
        )
        return stage_run

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
                    db,
                    task,
                    items,
                    streaming_dataflow_gate,
                    aggregated_status=status,
                ):
                    deferred_status = self._streaming_dataflow_gate_deferred_status(db, task, items)
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
                        "archive_progress": self._stage_archive_progress_detail(
                            db,
                            task,
                            stage_name,
                            items=items,
                        ),
                    }
                    if normalize_stage_name(stage_name) == "dataflow_vuln_scan"
                    else {}
                ),
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
