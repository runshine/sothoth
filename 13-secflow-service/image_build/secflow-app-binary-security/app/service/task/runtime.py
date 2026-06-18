from __future__ import annotations

import asyncio
import hashlib
import inspect
from contextlib import suppress
from typing import TYPE_CHECKING

from sqlalchemy import func
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskRuntimeServiceMixin:
    @staticmethod
    def _task_lease_expires_at():
        from app.service import task_manager as task_manager_module

        return task_manager_module._now() + task_manager_module.timedelta(seconds=180)

    def _entry_terminal_payload_requires_recreate(
        self: TaskManager,
        *,
        retrying: bool,
        payload: dict[str, object] | None,
    ) -> tuple[bool, str]:
        downstream_status = str((payload or {}).get("status") or "").strip().lower()
        mapped_status = self._map_downstream_status(downstream_status) or downstream_status or "failed"
        if retrying and mapped_status in {"cancelled", "failed", "downstream_missing"}:
            return True, mapped_status
        return False, mapped_status

    async def _sync_streaming_task_tail_state(self: TaskManager, task_id: str) -> None:
        from pathlib import Path

        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == task_id
            ).first()
            if task is None:
                return
            tail_items = self._stage_items(db, task.id, "dataflow_vuln_scan")
            tail_runs = [
                run
                for run in db.query(task_manager_module.BinarySecurityStageRun).filter(
                    task_manager_module.BinarySecurityStageRun.task_id == task.id
                ).all()
                if str(getattr(run, "stage_name", "") or "").strip() == "dataflow_vuln_scan"
            ]
            active_tail_item = any(
                str(getattr(item, "status", "") or "").strip() in {"pending", "queued", "running", "dispatching"}
                for item in tail_items
            )
            nonterminal_tail_run = next(
                (
                    run
                    for run in tail_runs
                    if str(getattr(run, "status", "") or "").strip() in {"pending", "queued", "running", "dispatching"}
                ),
                None,
            )
            failed_tail_run = next(
                (
                    run
                    for run in tail_runs
                    if str(getattr(run, "status", "") or "").strip() == "failed"
                ),
                None,
            )
            if not self._entry_results(task):
                rebuilt_rows: list[dict[str, object]] = []
                for item in self._stage_items(db, task.id, "entry_analysis"):
                    if str(item.status or "").strip() != "success":
                        continue
                    result = self._load_stage_item_result_payload(item)
                    preview_rows = [row for row in list(result.get("entries_preview") or []) if isinstance(row, dict)]
                    if not preview_rows:
                        continue
                    rebuilt_rows.append(
                        {
                            "module_key": result.get("module_key") or dict(item.input_ref or {}).get("module_key") or item.item_key,
                            "module_name": result.get("module_name") or dict(item.input_ref or {}).get("module_name") or item.item_name,
                            "entries": [dict(preview_rows[0])],
                        }
                    )
                if rebuilt_rows:
                    summary = dict(task.summary or {})
                    summary["entry_results"] = rebuilt_rows
                    task.summary = summary
            current_stage_before_sync = str(task.current_stage or "").strip()
            authoritative_tail_item_present = any(
                str(getattr(item, "status", "") or "").strip() in {"running", "dispatching", "success", "failed", "partial_success", "cancelled"}
                or bool(getattr(item, "started_at", None))
                or bool(getattr(item, "finished_at", None))
                or bool(str(getattr(item, "downstream_task_id", "") or "").strip())
                for item in tail_items
            )
            authoritative_tail_run_present = any(
                bool(getattr(run, "started_at", None))
                or bool(getattr(run, "finished_at", None))
                or str(getattr(run, "status", "") or "").strip() in {"running", "failed", "success", "partial_success", "cancelled"}
                for run in tail_runs
            )
            authoritative_tail_progress = (
                active_tail_item
                or authoritative_tail_item_present
                or authoritative_tail_run_present
                or current_stage_before_sync == "dataflow_vuln_scan"
            )
            if self._entry_results(task) and authoritative_tail_progress:
                task.current_stage = "dataflow_vuln_scan"
                if active_tail_item:
                    task.status = "running"
                elif failed_tail_run is not None:
                    task.status = (
                        "failed"
                        if current_stage_before_sync == "dataflow_vuln_scan"
                        else "pending" if nonterminal_tail_run is not None and not str(getattr(failed_tail_run, "last_error", "") or "").strip() else "failed"
                    )
                elif nonterminal_tail_run is not None:
                    task.status = "pending"
                else:
                    task.status = "running"
                task.last_error = None
                task.finished_at = None
            elif active_tail_item or authoritative_tail_progress:
                task.current_stage = "dataflow_vuln_scan"
                task.status = "running" if active_tail_item else "pending"
                task.last_error = None
                task.finished_at = None
            elif str(task.current_stage or "").strip() == "dataflow_vuln_scan":
                task.status = "failed"
                task.finished_at = None
            else:
                task.status = "pending"
                task.finished_at = None
            if str(task.current_stage or "").strip() == "dataflow_vuln_scan":
                task.dispatcher_instance_id = self.instance_id
                task.dispatch_started_at = task.dispatch_started_at or task_manager_module._now()
                task.lease_expires_at = task.lease_expires_at or self._task_lease_expires_at()
            await self._write_task_metadata_async(
                task,
                Path(task.workspace_root) / "input" / "task-metadata.json",
                status=task.status,
            )
            db.commit()
        finally:
            with suppress(Exception):
                db.close()

    def _run_parent_reclaim_pass(self: TaskManager, db: Session):
        from app.service import task_manager as task_manager_module

        if not isinstance(db, Session):
            return (
                self._requeue_stale_operations(db),
                self._reclaim_stale_dispatching_locked(db),
                self._requeue_orphaned_owned_execution_locked(db),
                self._reclaim_stale_streaming_stage_items_locked(db),
                self._reclaim_stale_running_locked(db),
                self._requeue_released_running_locked(db),
                self._recover_missing_stage_terminal_events_locked(db),
            )
        if not self._acquire_coordinator_lease(task_manager_module.PARENT_RECLAIM_COORDINATOR_LEASE):
            return False, False, False, False, False, False, False
        return (
            self._requeue_stale_operations(db),
            self._reclaim_stale_dispatching_locked(db),
            self._requeue_orphaned_owned_execution_locked(db),
            self._reclaim_stale_streaming_stage_items_locked(db),
            self._reclaim_stale_running_locked(db),
            self._requeue_released_running_locked(db),
            self._recover_missing_stage_terminal_events_locked(db),
        )

    async def _dispatch_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        session_factory = task_manager_module.get_session_factory()
        while self._running:
            task_id = None
            db = session_factory()
            try:
                with task_manager_module.observe_scheduler_loop("task_dispatch"):
                    self._mark_loop_heartbeat("task_dispatch")
                    task_id = await task_manager_module.get_task_queue().pop_task(self.cfg.queue.block_timeout_seconds)
                    if task_id:
                        claimed_id = self._dispatch_task_by_id(db, task_id)
                        if claimed_id:
                            task = (
                                db.query(task_manager_module.BinarySecurityTask)
                                .filter(task_manager_module.BinarySecurityTask.id == claimed_id)
                                .first()
                            )
                            task_manager_module.logger.info(
                                "binary-security dispatch claimed task and is attempting runtime start: "
                                "task_id=%s queue_task_id=%s status=%s runtime_phase=%s dispatcher_instance_id=%s "
                                "current_operation_id=%s lease_expires_at=%s",
                                claimed_id,
                                task_id,
                                str(getattr(task, "status", "") or "").strip() if task is not None else "",
                                str(self._task_runtime_phase(task)) if task is not None else "",
                                str(getattr(task, "dispatcher_instance_id", "") or "").strip() if task is not None else "",
                                str(getattr(task, "current_operation_id", "") or "").strip() if task is not None else "",
                                task_manager_module._isoformat_or_none(getattr(task, "lease_expires_at", None))
                                if task is not None
                                else None,
                            )
                            started = await self._start_task_runtime(claimed_id)
                            if started:
                                task_manager_module.logger.info(
                                    "binary-security dispatch successfully handed task to local runtime: "
                                    "task_id=%s queue_task_id=%s local_handle_present=%s",
                                    claimed_id,
                                    task_id,
                                    self._runtime_handle(claimed_id) is not None,
                                )
                            else:
                                task = (
                                    db.query(task_manager_module.BinarySecurityTask)
                                    .filter(task_manager_module.BinarySecurityTask.id == claimed_id)
                                    .first()
                                )
                                current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip() if task is not None else ""
                                current_status = str(getattr(task, "status", "") or "").strip() if task is not None else ""
                                dispatcher_instance_id = str(getattr(task, "dispatcher_instance_id", "") or "").strip() if task is not None else ""
                                runtime_phase = str(self._task_runtime_phase(task)) if task is not None else ""
                                handle = self._runtime_handle(claimed_id)
                                task_manager_module.logger.warning(
                                    "binary-security dispatch claimed task but runtime start returned false: task_id=%s queue_task_id=%s "
                                    "status=%s runtime_phase=%s dispatcher_instance_id=%s current_operation_id=%s "
                                    "local_handle_present=%s local_handle_done=%s local_handle_cancel_requested=%s",
                                    claimed_id,
                                    task_id,
                                    current_status,
                                    runtime_phase,
                                    dispatcher_instance_id,
                                    current_operation_id,
                                    handle is not None,
                                    handle.done() if handle is not None else None,
                                    getattr(handle, "cancel_requested", None) if handle is not None else None,
                                )
                    await self._reconcile_work_queues(db)
                    await self._observe_runtime_metrics(db)
                    self._mark_loop_heartbeat("task_dispatch")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._recover_loop_db_error("task_dispatch", db, exc)
                task_manager_module.logger.exception("binary-security task dispatch loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                with suppress(Exception):
                    db.close()

    def _active_dispatch_count(self: TaskManager, db: Session) -> int:
        from app.service import task_manager as task_manager_module

        return int(
            db.query(func.count(task_manager_module.BinarySecurityTask.id))
            .filter(task_manager_module.BinarySecurityTask.status.in_(["dispatching", "running"]))
            .scalar()
            or 0
        )

    async def _reconcile_work_queues(self: TaskManager, db: Session) -> None:
        from app.service import task_manager as task_manager_module

        now_value = task_manager_module._now()
        interval_seconds = max(5, int(getattr(self.cfg.queue, "reconcile_interval_seconds", 30) or 30))
        if self._last_queue_reconcile_at is not None:
            elapsed = (now_value - self._last_queue_reconcile_at).total_seconds()
            if elapsed < interval_seconds:
                return
        queue = task_manager_module.get_task_queue()
        seed_batch_size = max(1, int(getattr(self.cfg.queue, "seed_batch_size", 20) or 20))
        task_rows = (
            db.query(task_manager_module.BinarySecurityTask.id)
            .filter(task_manager_module.BinarySecurityTask.status.in_(["pending", "dispatching", "running"]))
            .order_by(
                task_manager_module.BinarySecurityTask.updated_at.asc(),
                task_manager_module.BinarySecurityTask.created_at.asc(),
                task_manager_module.BinarySecurityTask.id.asc(),
            )
            .limit(seed_batch_size)
            .all()
        )
        for (task_id,) in task_rows:
            await queue.push_task(str(task_id))
        operation_rows = (
            db.query(task_manager_module.BinarySecurityTaskOperation.task_id)
            .filter(task_manager_module.BinarySecurityTaskOperation.status.in_(["pending", "queued", "running", "accepted"]))
            .order_by(
                task_manager_module.BinarySecurityTaskOperation.updated_at.asc(),
                task_manager_module.BinarySecurityTaskOperation.created_at.asc(),
                task_manager_module.BinarySecurityTaskOperation.task_id.asc(),
            )
            .limit(seed_batch_size)
            .all()
        )
        for (operation_task_id,) in operation_rows:
            normalized_task_id = str(operation_task_id or "").strip()
            if normalized_task_id:
                await queue.push_task(normalized_task_id)
        await queue.cleanup_dedupe_orphans(self.cfg.queue.task_queue_key)
        self._last_queue_reconcile_at = now_value

    async def _stage_item_dispatch_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        session_factory = task_manager_module.get_session_factory()
        while self._running:
            db = session_factory()
            try:
                with task_manager_module.observe_scheduler_loop("stage_item_dispatch"):
                    self._mark_loop_heartbeat("stage_item_dispatch")
                    claimed_ids = self._claim_streaming_stage_items(db)
                    if claimed_ids:
                        async with self._stage_item_worker_lock:
                            for item_id in claimed_ids:
                                existing = self._stage_item_workers.get(item_id)
                                if existing is not None and not existing.done():
                                    continue
                                self._stage_item_workers[item_id] = asyncio.create_task(
                                    self._run_stage_item_by_id(item_id),
                                    name=f"binary-security-stage-item-{item_id}",
                                )
                    await self._observe_runtime_metrics(db)
                    self._mark_loop_heartbeat("stage_item_dispatch")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._recover_loop_db_error("stage_item_dispatch", db, exc)
                task_manager_module.logger.exception("binary-security stage item dispatch loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                with suppress(Exception):
                    db.close()
            await asyncio.sleep(max(1, int(self.cfg.scheduler.stage_poll_interval_seconds or 5)))

    def _dispatch_once(self: TaskManager, db: Session) -> list[str]:
        (
            stale_operations_requeued,
            stale_reclaimed,
            orphaned_owned_execution_requeued,
            stale_stage_item_reclaimed,
            stale_running_reclaimed,
            released_running_requeued,
            recovered_missing_terminal_events,
        ) = self._run_parent_reclaim_pass(db)
        service_config = self._load_service_config(db)
        active_count = self._active_dispatch_count(db)
        slots = max(0, service_config.max_concurrent_tasks - active_count)
        claimed_ids = self._claim_pending_tasks(db, slots)
        if (
            stale_operations_requeued
            or stale_reclaimed
            or orphaned_owned_execution_requeued
            or stale_stage_item_reclaimed
            or stale_running_reclaimed
            or released_running_requeued
            or recovered_missing_terminal_events
            or claimed_ids
        ):
            db.commit()
        return claimed_ids

    def _dispatch_task_by_id(self: TaskManager, db: Session, task_id: str) -> str | None:
        from app.service import task_manager as task_manager_module

        self._run_parent_reclaim_pass(db)
        service_config = self._load_service_config(db)
        active_count = self._active_dispatch_count(db)
        if active_count >= service_config.max_concurrent_tasks:
            return None
        task = db.query(task_manager_module.BinarySecurityTask).filter(
            task_manager_module.BinarySecurityTask.id == task_id
        ).first()
        if task is None:
            return None
        current_operation = None
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip()
        if current_operation_id:
            current_operation = (
                db.query(task_manager_module.BinarySecurityTaskOperation)
                .filter(task_manager_module.BinarySecurityTaskOperation.id == current_operation_id)
                .first()
            )
        if self._release_unsupported_task_row_owner(
            db,
            task,
            active_operation=current_operation,
            reason="dispatch_attempt_without_local_runtime",
        ):
            db.commit()
            self._enqueue_task(task.id)
            return None
        has_owner_inbox_work = bool(
            current_operation is not None
            and str(getattr(current_operation, "status", "") or "").strip().lower()
            in task_manager_module.TASK_OPERATION_ACTIVE_STATUSES
        )
        current_status = str(getattr(task, "status", "") or "").strip().lower()
        if has_owner_inbox_work and current_status:
            if current_status != "pending":
                task_manager_module.logger.info(
                    "binary-security dispatch claiming non-pending task because owner inbox work is active: "
                    "task_id=%s status=%s runtime_phase=%s current_operation_id=%s operation_status=%s dispatcher_instance_id=%s",
                    task_id,
                    current_status,
                    self._task_runtime_phase(task),
                    current_operation_id,
                    str(getattr(current_operation, "status", "") or "").strip().lower() if current_operation is not None else None,
                    str(getattr(task, "dispatcher_instance_id", "") or "").strip() or None,
                )
            if not self._task_row_owner_is_runtime_supported(db, task, active_operation=current_operation):
                task_manager_module.logger.warning(
                    "binary-security dispatch observed active owner inbox work but task row owner is unsupported and will be reclaimed: "
                    "task_id=%s status=%s runtime_phase=%s current_operation_id=%s operation_status=%s dispatcher_instance_id=%s",
                    task_id,
                    current_status,
                    self._task_runtime_phase(task),
                    current_operation_id,
                    str(getattr(current_operation, "status", "") or "").strip().lower() if current_operation is not None else None,
                    str(getattr(task, "dispatcher_instance_id", "") or "").strip() or None,
                )
                if self._release_unsupported_task_row_owner(
                    db,
                    task,
                    active_operation=current_operation,
                    reason="dispatch_attempt_with_unsupported_foreign_owner",
                ):
                    db.commit()
                    self._enqueue_task(task.id)
                    return None
        if (
            self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
            and self._tail_requires_execution_takeover(db, task)
        ):
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
            task.tail_reconcile_state = "idle"
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._release_tail_reconcile_owner(task.id)
            db.flush()
        if self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION and not self._is_reducer_role():
            return None
        current_status = str(getattr(task, "status", "") or "").strip().lower()
        if current_status != "pending" and not has_owner_inbox_work:
            return None
        if current_status in task_manager_module.TASK_TERMINAL_STATUSES and not has_owner_inbox_work:
            return None
        started_at = task_manager_module._now()
        lease_expires_at = self._next_lease_expiry(db, now_value=started_at)
        updated = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(
                task_manager_module.BinarySecurityTask.id == task_id,
                self._lease_filter_available(),
            )
            .update(
                {
                    task_manager_module.BinarySecurityTask.status: "dispatching",
                    task_manager_module.BinarySecurityTask.runtime_phase: task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                    task_manager_module.BinarySecurityTask.dispatcher_instance_id: self.instance_id,
                    task_manager_module.BinarySecurityTask.dispatch_started_at: started_at,
                    task_manager_module.BinarySecurityTask.lease_expires_at: lease_expires_at,
                    task_manager_module.BinarySecurityTask.updated_at: started_at,
                },
                synchronize_session=False,
            )
        )
        if updated:
            db.commit()
            return task_id
        return None

    def _claim_streaming_stage_items(self: TaskManager, db: Session) -> list[str]:
        from app.service import task_manager as task_manager_module

        claimed_ids: list[str] = []
        claimed_counts_by_stage: dict[tuple[str, str], int] = {}
        seen_non_owner_skip_keys: set[tuple[str, str, str, str]] = set()
        pending_items = (
            db.query(task_manager_module.BinarySecurityStageItem)
            .filter(task_manager_module.BinarySecurityStageItem.status.in_(["pending", "queued"]))
            .order_by(
                task_manager_module.BinarySecurityStageItem.created_at.asc(),
                task_manager_module.BinarySecurityStageItem.id.asc(),
            )
            .all()
        )
        for item in pending_items:
            if item.stage_name not in task_manager_module.STREAMING_TAIL_STAGES:
                continue
            try:
                task = db.query(task_manager_module.BinarySecurityTask).filter(
                    task_manager_module.BinarySecurityTask.id == item.task_id
                ).first()
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc):
                    raise
                db.rollback()
                task_manager_module.logger.warning(
                    "binary-security streaming stage item claim skipped by retryable lock conflict while loading task: item_id=%s task_id=%s",
                    item.id,
                    item.task_id,
                )
                continue
            if task is None or not self._streaming_mode_enabled(task):
                continue
            if task.status in task_manager_module.TASK_TERMINAL_STATUSES or task.status == "cancelled":
                continue
            if not self._is_streaming_tail_stage(task, item.stage_name):
                continue
            if self._task_runtime_phase(task) != task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION:
                continue
            if str(task.dispatcher_instance_id or "").strip() != str(self.instance_id or "").strip():
                skip_key = (
                    str(task.id or ""),
                    str(item.stage_name or ""),
                    str(task.dispatcher_instance_id or "").strip(),
                    str(self.instance_id or "").strip(),
                )
                self._record_non_owner_streaming_claim_skip(
                    db,
                    task,
                    item,
                    emit_event=skip_key not in seen_non_owner_skip_keys,
                )
                seen_non_owner_skip_keys.add(skip_key)
                continue
            if not task.dispatch_started_at or not self._lease_is_active(task):
                continue
            if self._stage_item_orchestration_in_retry_backoff(item):
                continue
            dispatch_throttle = self._effective_runtime_policy(task).get("dispatch_throttle") or {}
            throttle_entry = dict(dispatch_throttle.get(item.stage_name) or {}) if isinstance(dispatch_throttle, dict) else {}
            max_new_items_per_tick = int(throttle_entry.get("max_new_items_per_tick") or 0)
            throttle_key = (str(task.id), str(item.stage_name))
            if max_new_items_per_tick > 0 and claimed_counts_by_stage.get(throttle_key, 0) >= max_new_items_per_tick:
                continue
            try:
                active_count = int(
                    db.query(func.count(task_manager_module.BinarySecurityStageItem.id))
                    .filter(
                        task_manager_module.BinarySecurityStageItem.task_id == task.id,
                        task_manager_module.BinarySecurityStageItem.stage_name == item.stage_name,
                        task_manager_module.BinarySecurityStageItem.status.in_(["dispatching", "queued", "running"]),
                    )
                    .scalar()
                    or 0
                )
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc):
                    raise
                db.rollback()
                task_manager_module.logger.warning(
                    "binary-security streaming stage item claim skipped by retryable lock conflict while counting active items: item_id=%s stage=%s",
                    item.id,
                    item.stage_name,
                )
                continue
            if active_count >= self._stage_parallelism(task, item.stage_name):
                continue
            try:
                updated = (
                    db.query(task_manager_module.BinarySecurityStageItem)
                    .filter(
                        task_manager_module.BinarySecurityStageItem.id == item.id,
                        task_manager_module.BinarySecurityStageItem.status.in_(["pending", "queued"]),
                    )
                    .update(
                        {
                            task_manager_module.BinarySecurityStageItem.status: "dispatching",
                            task_manager_module.BinarySecurityStageItem.claim_owner_instance_id: str(self.instance_id or "").strip() or None,
                            task_manager_module.BinarySecurityStageItem.claim_execution_token: self._dispatch_token(task),
                            task_manager_module.BinarySecurityStageItem.claim_started_at: task_manager_module._now(),
                            task_manager_module.BinarySecurityStageItem.started_at: task_manager_module._now(),
                            task_manager_module.BinarySecurityStageItem.updated_at: task_manager_module._now(),
                        },
                        synchronize_session=False,
                    )
                )
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc):
                    raise
                db.rollback()
                task_manager_module.logger.warning(
                    "binary-security streaming stage item claim skipped by retryable lock conflict while updating item: item_id=%s stage=%s",
                    item.id,
                    item.stage_name,
                )
                continue
            if updated:
                claimed_ids.append(item.id)
                claimed_counts_by_stage[throttle_key] = claimed_counts_by_stage.get(throttle_key, 0) + 1
        if claimed_ids:
            try:
                db.commit()
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc):
                    raise
                db.rollback()
                task_manager_module.logger.warning(
                    "binary-security streaming stage item claim commit skipped by retryable lock conflict: item_ids=%s",
                    claimed_ids,
                )
                return []
        return claimed_ids

    def _requeue_orphaned_owned_execution_locked(self: TaskManager, db: Session) -> bool:
        from app.service import task_manager as task_manager_module

        rows = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(
                task_manager_module.BinarySecurityTask.runtime_phase == task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
                task_manager_module.BinarySecurityTask.status.in_(["pending", "running"]),
            )
            .all()
        )
        if not rows:
            return False
        changed = False
        for task in rows:
            stage_name = str(task.current_stage or "").strip() or None
            if not stage_name:
                continue
            if self._has_local_task_execution_owner(task.id) or self._task_has_active_streaming_stage_workers(task.id):
                continue
            lease = self._runtime_lease_for_task(db, task.id)
            if self._runtime_lease_is_active(lease):
                continue
            if not self._should_requeue_for_owned_execution(db, task, next_stage=stage_name, next_stage_status="running"):
                continue
            self._requeue_owned_execution_takeover(
                db,
                task,
                stage_name=stage_name,
                reason="orphaned_owned_execution_without_active_holder",
                event_type="owned_execution_takeover_requeued",
                message=f"检测到执行接管悬空，已重新排队等待 worker 接管: {stage_name}",
                event_payload={"source": "parent_reclaim_pass"},
            )
            changed = True
        if changed:
            db.flush()
        return changed

    def _reclaim_stale_dispatching_locked(self: TaskManager, db: Session) -> bool:
        from app.service import task_manager as task_manager_module

        service_config = self._load_service_config(db)
        stale_rows = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(
                task_manager_module.BinarySecurityTask.status == "dispatching",
                task_manager_module.BinarySecurityTask.dispatch_started_at.isnot(None),
                task_manager_module.BinarySecurityTask.lease_expires_at.isnot(None),
            )
            .all()
        )
        if not stale_rows:
            return False
        local_workers = {
            task_id for task_id, worker in self._workers.items()
            if not worker.done()
        }
        reclaimed = False
        for task in stale_rows:
            if self._task_has_active_cancel_operation(db, task) or str(task.status or "").strip() == task_manager_module.TASK_STATUS_CANCELLING:
                continue
            if task.id in local_workers and str(task.dispatcher_instance_id or "").strip() == self.instance_id:
                continue
            lease, runtime_lease_owner, runtime_lease_expires_at = self._runtime_lease_context(db, task)
            if self._runtime_lease_is_active(lease):
                if (
                    self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION
                    and str(lease.owner_instance_id or "").strip() == str(self.instance_id or "").strip()
                    and self._has_tail_reconcile_owner(task.id)
                ):
                    task_manager_module.observe_tail_reconcile_requeue_blocked("active_local_tail_lease")
                    continue
                continue
            active_stage_name, active_item_count, has_downstream_refs = self._streaming_tail_active_context(db, task)
            if active_item_count > 0:
                continue
            lease_remaining = task_manager_module._seconds_until(task.lease_expires_at)
            if lease_remaining is None:
                elapsed_seconds = task_manager_module._elapsed_seconds_since(task.dispatch_started_at)
                if elapsed_seconds is None or elapsed_seconds < service_config.dispatch_timeout_seconds:
                    continue
            elif lease_remaining > 0:
                continue
            failure_ctx = self._current_stage_authoritative_failure_context(db, task)
            if failure_ctx is None:
                failure_ctx = self._earlier_stage_authoritative_failure_context(db, task)
            if failure_ctx is None:
                stage_runs = db.query(task_manager_module.BinarySecurityStageRun).filter(
                    task_manager_module.BinarySecurityStageRun.task_id == task.id
                ).all()
                current_stage_name = str(task.current_stage or "").strip()
                current_stage_run = next(
                    (run for run in stage_runs if str(getattr(run, "stage_name", "") or "").strip() == current_stage_name),
                    None,
                )
                should_terminalize_failed_stage = False
                if current_stage_run is not None:
                    stage_error_text = " ".join(
                        str(part or "").strip()
                        for part in (
                            getattr(current_stage_run, "last_error", None),
                            getattr(current_stage_run, "error_message", None),
                            getattr(current_stage_run, "reason", None),
                        )
                        if str(part or "").strip()
                    ).lower()
                    should_terminalize_failed_stage = (
                        str(getattr(current_stage_run, "status", "") or "").strip() == "failed"
                        and (
                            "task owner pod lost" in stage_error_text
                            or "owner pod lost" in stage_error_text
                            or self._is_terminal_business_stage_failure(task, current_stage_run)
                        )
                    )
                if current_stage_run is not None and should_terminalize_failed_stage:
                    snapshot = self._stage_failure_snapshot(task, current_stage_run)
                    failure_ctx = {
                        "stage_name": current_stage_name,
                        "stage_run": current_stage_run,
                        "failure_code": snapshot.get("failure_code"),
                        "failure_category": snapshot.get("failure_category"),
                        "failure_message": snapshot.get("failure_message") or snapshot.get("error") or getattr(current_stage_run, "last_error", None),
                        "reason": "stale_dispatching_stage_run_failed",
                    }
            if failure_ctx is not None:
                self._finalize_task_after_authoritative_failure(
                    db,
                    task,
                    failure_ctx=failure_ctx,
                    previous_status="dispatching",
                )
                reclaimed = True
                continue
            dispatcher_instance_id = str(task.dispatcher_instance_id or "").strip() or None
            dispatch_started_at = task.dispatch_started_at
            task_lease_expires_at = task.lease_expires_at
            task.status = "pending"
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            task.last_error = None
            task_manager_module.observe_dispatch_reclaim("dispatch_timeout")
            self._record_event(
                db,
                task,
                "dispatch_reclaimed",
                "调度超时，任务已回收并重新进入队列",
                level="warning",
                stage_name=task.current_stage,
                payload={
                    "dispatcher_instance_id": dispatcher_instance_id,
                    "dispatch_started_at": task_manager_module._isoformat_or_none(dispatch_started_at),
                    "task_lease_expires_at": task_manager_module._isoformat_or_none(task_lease_expires_at),
                    "runtime_lease_owner": runtime_lease_owner,
                    "runtime_lease_expires_at": task_manager_module._isoformat_or_none(runtime_lease_expires_at),
                    "active_stage_name": active_stage_name or task.current_stage,
                    "active_item_count": active_item_count,
                    "reclaim_reason": "dispatch_timeout",
                    "has_downstream_refs": has_downstream_refs,
                },
            )
            reclaimed = True
        if reclaimed:
            db.flush()
        return reclaimed

    def _reclaim_stale_streaming_stage_items_locked(self: TaskManager, db: Session) -> bool:
        from app.service import task_manager as task_manager_module

        service_config = self._load_service_config(db)
        stale_rows = (
            db.query(task_manager_module.BinarySecurityStageItem)
            .filter(
                task_manager_module.BinarySecurityStageItem.stage_name.in_(list(task_manager_module.STREAMING_TAIL_STAGES)),
                task_manager_module.BinarySecurityStageItem.status == "dispatching",
            )
            .all()
        )
        if not stale_rows:
            return False
        local_workers = {
            task_id for task_id, worker in self._stage_item_workers.items()
            if not worker.done()
        }
        reclaimed = False
        timeout_seconds = max(int(service_config.dispatch_timeout_seconds or 0), 60)
        for item in stale_rows:
            if item.id in local_workers:
                continue
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == item.task_id
            ).first()
            if str(item.claim_owner_instance_id or "").strip() and task is not None and self._stage_item_claim_matches_task_execution(item, task):
                continue
            if str(item.downstream_task_id or "").strip():
                continue
            reference_time = item.updated_at or item.started_at or item.created_at
            elapsed_seconds = task_manager_module._elapsed_seconds_since(reference_time)
            if elapsed_seconds is None or elapsed_seconds < timeout_seconds:
                continue
            previous_status = str(item.status or "").strip()
            item.status = "pending"
            item.error_message = None
            item.finished_at = None
            item.claim_owner_instance_id = None
            item.claim_execution_token = None
            item.claim_started_at = None
            if task is not None:
                self._merge_stage_item_result_fields(
                    task,
                    item,
                    stage_name=str(item.stage_name or "").strip(),
                    updates={"dispatch_reclaimed_at": task_manager_module._now().isoformat()},
                )
            else:
                item.result = {
                    **(item.result or {}),
                    "dispatch_reclaimed_at": task_manager_module._now().isoformat(),
                }
            if task is not None:
                self._record_event(
                    db,
                    task,
                    "streaming_stage_item_dispatch_reclaimed",
                    f"流式阶段子任务调度超时，已回收重试: {item.stage_name}:{item.item_key}",
                    level="warning",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "previous_status": previous_status,
                        "requeued_status": item.status,
                        "downstream_task_id": item.downstream_task_id,
                        "elapsed_seconds": elapsed_seconds,
                    },
                )
            reclaimed = True
        if reclaimed:
            db.flush()
        return reclaimed

    def _requeue_released_running_locked(self: TaskManager, db: Session) -> bool:
        from app.service import task_manager as task_manager_module

        released_rows = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(
                task_manager_module.BinarySecurityTask.status == "running",
                task_manager_module.or_(
                    task_manager_module.BinarySecurityTask.dispatcher_instance_id.is_(None),
                    task_manager_module.BinarySecurityTask.dispatcher_instance_id == "",
                ),
                task_manager_module.BinarySecurityTask.dispatch_started_at.is_(None),
                task_manager_module.BinarySecurityTask.lease_expires_at.is_(None),
            )
            .all()
        )
        if not released_rows:
            return False
        requeued = False
        for task in released_rows:
            if self._task_has_active_cancel_operation(db, task) or str(task.status or "").strip() == task_manager_module.TASK_STATUS_CANCELLING:
                continue
            lease = self._runtime_lease_for_task(db, task.id)
            if self._runtime_lease_is_active(lease):
                continue
            if self._has_local_task_execution_owner(task.id) or self._task_has_active_streaming_stage_workers(task.id):
                continue
            runtime_lease_owner = str(lease.owner_instance_id or "").strip() or None if lease is not None else None
            runtime_lease_expires_at = lease.lease_expires_at if lease is not None else None
            if self._release_streaming_parent_for_takeover_locked(
                db,
                task,
                runtime_lease_owner=runtime_lease_owner,
                runtime_lease_expires_at=runtime_lease_expires_at,
                reason="released_running_without_owner_with_active_tail",
            ):
                task_manager_module.observe_runtime_lease_owner_mismatch("released_running_with_active_tail")
                requeued = True
                continue
            stage_name = task.current_stage or self._stage_sequence_for_task(task)[0]
            active_items = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.task_id == task.id,
                task_manager_module.BinarySecurityStageItem.stage_name == stage_name,
                task_manager_module.BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
            ).all()
            has_downstream_refs = any(str(item.downstream_task_id or "").strip() for item in active_items)
            if active_items or has_downstream_refs:
                continue
            task.status = "pending"
            task.updated_at = task_manager_module._now()
            task.last_error = None
            task_manager_module.observe_running_requeue("released_without_owner")
            self._record_event(
                db,
                task,
                "running_execution_requeued",
                "已将释放后的运行任务重新纳入待调度队列，等待新的 worker 安全接管",
                level="warning",
                stage_name=stage_name,
                payload={
                    "stage_name": stage_name,
                    "active_item_count": len(active_items),
                    "runtime_lease_owner": None,
                    "runtime_lease_stale": True,
                },
            )
            requeued = True
        if requeued:
            db.flush()
        return requeued

    def _reclaim_stale_running_locked(self: TaskManager, db: Session) -> bool:
        from app.service import task_manager as task_manager_module

        service_config = self._load_service_config(db)
        stale_rows = (
            db.query(task_manager_module.BinarySecurityTask)
            .filter(task_manager_module.BinarySecurityTask.status == "running")
            .all()
        )
        if not stale_rows:
            return False
        reclaimed = False
        local_workers = {
            task_id for task_id, worker in self._workers.items()
            if not worker.done()
        }
        timeout_seconds = max(int(service_config.dispatch_timeout_seconds or 0), 60)
        for task in stale_rows:
            if self._task_has_active_cancel_operation(db, task) or str(task.status or "").strip() == task_manager_module.TASK_STATUS_CANCELLING:
                continue
            lease = self._runtime_lease_for_task(db, task.id)
            if self._runtime_lease_is_active(lease):
                continue
            if task.id in local_workers and str(task.dispatcher_instance_id or "").strip() == str(self.instance_id or "").strip():
                continue
            if self._release_streaming_parent_for_takeover_locked(
                db,
                task,
                runtime_lease_owner=str(getattr(lease, "owner_instance_id", "") or "").strip() or None if lease is not None else None,
                runtime_lease_expires_at=getattr(lease, "lease_expires_at", None) if lease is not None else None,
                reason="stale_running_without_active_runtime_lease",
            ):
                reclaimed = True
                continue
            reference_time = task.updated_at or task.dispatch_started_at or task.started_at
            elapsed_seconds = task_manager_module._elapsed_seconds_since(reference_time)
            if elapsed_seconds is None or elapsed_seconds < timeout_seconds:
                continue
            failure_ctx = self._current_stage_authoritative_failure_context(db, task)
            if failure_ctx is None:
                failure_ctx = self._earlier_stage_authoritative_failure_context(db, task)
            if failure_ctx is not None:
                self._finalize_task_after_authoritative_failure(
                    db,
                    task,
                    failure_ctx=failure_ctx,
                    previous_status="running",
                )
                reclaimed = True
                continue
            stage_runs = db.query(task_manager_module.BinarySecurityStageRun).filter(
                task_manager_module.BinarySecurityStageRun.task_id == task.id
            ).all()
            current_stage_run = next(
                (
                    run
                    for run in stage_runs
                    if str(getattr(run, "stage_name", "") or "").strip() == str(task.current_stage or "").strip()
                ),
                None,
            )
            if current_stage_run is not None:
                current_stage_run.status = "failed"
                current_stage_run.finished_at = current_stage_run.finished_at or task_manager_module._now()
                current_stage_run.last_error = str(getattr(current_stage_run, "last_error", None) or "任务运行心跳超时").strip()
            current_stage_name = str(task.current_stage or "").strip()
            active_items = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.task_id == task.id,
                task_manager_module.BinarySecurityStageItem.stage_name == current_stage_name,
            ).all()
            for item in active_items:
                item_status = str(item.status or "").strip()
                if item_status in {"pending", "queued", "dispatching", "running"}:
                    item.status = "failed"
                    item.finished_at = item.finished_at or task_manager_module._now()
                    item.error_message = item.error_message or "任务运行心跳超时"
            task.status = "failed"
            task.finished_at = task.finished_at or task_manager_module._now()
            task.last_error = task.last_error or "任务运行心跳超时"
            self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_TERMINAL)
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
            self._record_event(
                db,
                task,
                "dispatching_state_force_terminalized",
                "检测到当前阶段已进入终态失败，父任务已自动结束 dispatching 收口",
                level="warning",
                stage_name=current_stage_name or None,
                payload={"previous_status": "running", "reason": "stale_running_timeout"},
            )
            self._record_event(
                db,
                task,
                "task_finalized_after_child_failure",
                "下游子任务已终态失败，父任务已直接收口为 failed",
                level="warning",
                stage_name=current_stage_name or None,
                payload={"stage_name": current_stage_name or None, "requeue_suppressed": True},
            )
            reclaimed = True
        if reclaimed:
            db.flush()
        return reclaimed

    async def _run_task(self: TaskManager, task_id: str) -> None:
        from app.service import task_manager as task_manager_module

        session_factory = task_manager_module.get_session_factory()
        db = session_factory()
        execution_token: str | None = None
        owner_registered = False
        try:
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == task_id
            ).first()
            if task is None:
                task_manager_module.logger.warning(
                    "binary-security run_task aborted before execution because task row is missing: task_id=%s",
                    task_id,
                )
            if (
                task is None
                or task.status != "dispatching"
                or task.dispatcher_instance_id != self.instance_id
                or not self._lease_is_active(task, db=db)
            ):
                if task is not None:
                    task_manager_module.logger.warning(
                        "binary-security run_task exited before switching to running due to failed precondition: "
                        "task_id=%s status=%s dispatcher_instance_id=%s expected_instance_id=%s lease_active=%s current_operation_id=%s runtime_phase=%s",
                        task_id,
                        str(task.status or "").strip(),
                        str(task.dispatcher_instance_id or "").strip(),
                        str(self.instance_id or "").strip(),
                        self._lease_is_active(task, db=db),
                        str(getattr(task, "current_operation_id", "") or "").strip(),
                        self._task_runtime_phase(task),
                    )
                return
            task_manager_module.logger.info(
                "binary-security run_task entering active execution: task_id=%s current_operation_id=%s runtime_phase=%s dispatch_started_at=%s lease_expires_at=%s",
                task_id,
                str(getattr(task, "current_operation_id", "") or "").strip(),
                self._task_runtime_phase(task),
                task_manager_module._isoformat_or_none(getattr(task, "dispatch_started_at", None)),
                task_manager_module._isoformat_or_none(getattr(task, "lease_expires_at", None)),
            )
            if task.started_at is None:
                task.started_at = task_manager_module._now()
            started_at = task.dispatch_started_at or task_manager_module._now()
            task.dispatch_started_at = started_at
            task.lease_expires_at = self._next_lease_expiry(db, now_value=started_at)
            execution_token = task.dispatch_started_at.isoformat() if task.dispatch_started_at else None
            task.status = "running"
            self._upsert_runtime_lease(db, task, now_value=started_at, owner_instance_id=self.instance_id)
            self._clear_task_abnormal_reason_snapshot(db, task)
            self._bind_execution_token(task)
            self._register_task_execution_owner(task.id, "primary_task_worker")
            owner_registered = True
            task_manager_module.observe_task_lifecycle("started", status=task.status, task_type=self._task_type(task))
            self._record_event(
                db,
                task,
                "task_dispatched",
                f"任务由实例 {self.instance_id} 启动执行",
                payload={"dispatcher_instance_id": self.instance_id},
            )
            async with self._worker_lock:
                handle = self._workers.get(task.id)
                if handle is not None:
                    handle.execution_token = execution_token
            active_stage_name, active_item_count, has_downstream_refs = self._streaming_tail_active_context(db, task)
            current_stage_is_streaming_tail = self._is_streaming_tail_stage(task, task.current_stage)
            if (active_item_count <= 0 and not has_downstream_refs) and current_stage_is_streaming_tail:
                current_stage_items = self._stage_items(db, task.id, str(task.current_stage or "").strip())
                active_item_count = sum(
                    1
                    for item in current_stage_items
                    if (self._normalize_downstream_status(item.status) or str(item.status or "").strip().lower())
                    in {"pending", "queued", "dispatching", "running"}
                )
                has_downstream_refs = any(str(item.downstream_task_id or "").strip() for item in current_stage_items)
                if active_item_count > 0 and not active_stage_name:
                    active_stage_name = str(task.current_stage or "").strip() or None
            if active_item_count > 0 or has_downstream_refs or current_stage_is_streaming_tail:
                self._record_event(
                    db,
                    task,
                    "downstream_reconcile_resumed_after_takeover",
                    "新的 worker 已接管流式尾段父任务，继续执行下游状态对账与阶段收口",
                    stage_name=active_stage_name or task.current_stage,
                    payload={
                        "dispatcher_instance_id": self.instance_id,
                        "active_stage_name": active_stage_name or task.current_stage,
                        "active_item_count": active_item_count,
                        "has_downstream_refs": has_downstream_refs,
                    },
                )
            db.commit()
            task_manager_module.logger.info(
                "binary-security run_task committed active execution state: "
                "task_id=%s status=%s runtime_phase=%s current_operation_id=%s execution_token=%s",
                task_id,
                str(task.status or "").strip(),
                self._task_runtime_phase(task),
                str(getattr(task, "current_operation_id", "") or "").strip(),
                execution_token,
            )
            operation_passes = 0
            while await self._run_current_task_operation(task_id):
                operation_passes += 1
                task_manager_module.logger.info(
                    "binary-security run_task consumed task operation pass: task_id=%s passes=%s",
                    task_id,
                    operation_passes,
                )
            verification_db = session_factory()
            try:
                task_after_operation = (
                    verification_db.query(task_manager_module.BinarySecurityTask)
                    .filter(task_manager_module.BinarySecurityTask.id == task_id)
                    .first()
                )
                if task_after_operation is not None and str(getattr(task_after_operation, "current_operation_id", "") or "").strip():
                    task_manager_module.logger.warning(
                        "binary-security run_task stopped consuming task operations while current_operation_id is still present: "
                        "task_id=%s current_operation_id=%s status=%s runtime_phase=%s",
                        task_id,
                        str(getattr(task_after_operation, "current_operation_id", "") or "").strip(),
                        str(getattr(task_after_operation, "status", "") or "").strip(),
                        self._task_runtime_phase(task_after_operation),
                    )
            finally:
                verification_db.close()
            while await self._run_task_runtime_signals(task_id):
                pass
            await self._execute_task(task_id)
        except task_manager_module.StaleTaskExecution:
            return
        except Exception as exc:
            with suppress(Exception):
                db.rollback()
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == task_id
            ).first()
            if task:
                current_token = task.dispatch_started_at.isoformat() if task.dispatch_started_at else None
                same_execution = (
                    task.dispatcher_instance_id == self.instance_id
                    and execution_token is not None
                    and execution_token == current_token
                    and task.status in {"dispatching", "running"}
                )
                if not same_execution:
                    return
                self._enqueue_state_event(
                    db,
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name=task.current_stage,
                    event_type="task_execution_failed",
                    idempotency_key=(
                        f"task_execution_failed:{task.id}:"
                        f"{execution_token or current_token or ''}:{hashlib.sha1(str(exc).encode('utf-8')).hexdigest()}"
                    ),
                    payload={
                        "error": str(exc),
                        "dispatcher_instance_id": self.instance_id,
                        "execution_token": execution_token or current_token,
                    },
                )
                db.commit()
        finally:
            if owner_registered:
                self._release_task_execution_owner(task_id, "primary_task_worker")
            async with self._worker_lock:
                handle = self._workers.get(task_id)
            if handle is not None and handle.heartbeat_task is not None and not handle.heartbeat_task.done():
                handle.heartbeat_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await handle.heartbeat_task
            cleanup_db = session_factory()
            try:
                task = cleanup_db.query(task_manager_module.BinarySecurityTask).filter(
                    task_manager_module.BinarySecurityTask.id == task_id
                ).first()
                if (
                    task is None
                    or str(task.status or "").strip().lower() in task_manager_module.TASK_TERMINAL_STATUSES
                    or (
                        not self._has_local_task_execution_owner(task_id)
                        and not self._task_has_active_streaming_stage_workers(task_id)
                        and not self._should_preserve_tail_runtime_lease(cleanup_db, task)
                    )
                ):
                    self._clear_runtime_lease(cleanup_db, task_id, owner_instance_id=self.instance_id)
                    self._release_tail_reconcile_owner(task_id)
                    cleanup_db.commit()
                elif self._should_preserve_tail_runtime_lease(cleanup_db, task):
                    task_manager_module.observe_tail_reconcile_heartbeat("preserved_on_worker_exit")
            except Exception:
                cleanup_db.rollback()
                task_manager_module.logger.exception("binary-security runtime lease cleanup failed: task_id=%s", task_id)
            finally:
                cleanup_db.close()
            async with self._worker_lock:
                self._workers.pop(task_id, None)
            db.close()

    async def _execute_task(self: TaskManager, task_id: str) -> None:
        from app.service import task_manager as task_manager_module

        session_factory = task_manager_module.get_session_factory()
        db = session_factory()
        try:
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == task_id
            ).first()
            if not task:
                return
            self._bind_execution_token(task)
            token = self._service_token()
            stage_sequence = self._stage_sequence_for_task(task)
            start_index = stage_sequence.index(task.current_stage) if task.current_stage in stage_sequence else 0
            stage_retry_mode = task.execution_mode in {"stage_retry", "stage_retry_failed_items", "stage_retry_full"} and bool(task.target_stage_name)
            task_retry_mode = task.execution_mode in {"task_retry", "task_retry_failed_items"} and bool(task.target_stage_name)
            target_stage_name = task.target_stage_name if (stage_retry_mode or task_retry_mode) else None
            target_stage_index = stage_sequence.index(target_stage_name) if target_stage_name in stage_sequence else start_index
            if stage_retry_mode:
                start_index = min(start_index, target_stage_index)
            for stage_name in stage_sequence[start_index:]:
                if stage_retry_mode and stage_sequence.index(stage_name) < target_stage_index:
                    continue
                db.refresh(task)
                if task.status == "cancelled":
                    return
                if not self._stage_enabled(task, stage_name):
                    stage_run = self._ensure_stage_run(db, task, stage_name)
                    stage_run.status = "success"
                    stage_run.started_at = stage_run.started_at or task_manager_module._now()
                    stage_run.finished_at = task_manager_module._now()
                    await self._persist_stage_run_output_summary_async(task, stage_run, {"reason": "disabled_by_stage_options"})
                    stage_run.counts = self._stage_counts(db, stage_run)
                    task.stage_summary = {
                        **task.stage_summary,
                        stage_name: {
                            "status": "success",
                            "counts": stage_run.counts,
                            "finished_at": stage_run.finished_at.isoformat(),
                            "reason": "disabled_by_stage_options",
                        },
                    }
                    self._record_event(db, task, "stage_completed", f"阶段未启用，按配置完成: {stage_name}", stage_name=stage_name)
                    task_manager_module.observe_stage_duration(
                        stage=stage_name,
                        result="success",
                        duration_seconds=task_manager_module._elapsed_seconds_since(stage_run.started_at),
                    )
                    db.commit()
                    continue
                start_event = self._enqueue_state_event(
                    db,
                    task=task,
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name=stage_name,
                    event_type="stage_worker_start_requested",
                    idempotency_key=(
                        f"stage_worker_start_requested:{task.id}:{stage_name}:"
                        f"{task.dispatch_started_at.isoformat() if task.dispatch_started_at else ''}"
                    ),
                    payload={
                        "stage_name": stage_name,
                        "stage_retry_mode": bool(stage_retry_mode),
                        "task_retry_mode": bool(task_retry_mode),
                        "target_stage_name": target_stage_name,
                    },
                )
                if start_event is not None:
                    self._apply_stage_worker_start_requested_locked(db, start_event)
                handler = self._run_stage_executor
                stage_run = self._ensure_stage_run(db, task, stage_name)
                existing_stage_items = self._stage_items(db, task.id, stage_name) if task_retry_mode else []
                db.commit()
                retry_existing = False
                if task.execution_mode in {"stage_retry_failed_items", "task_retry_failed_items"} and stage_name == target_stage_name:
                    retry_existing = True
                elif task_retry_mode and existing_stage_items:
                    retry_existing = True
                status, summary = await handler(db, task, stage_run, token, retry_existing=retry_existing)
                execution_token = task.dispatch_started_at.isoformat() if task.dispatch_started_at else None
                self._emit_stage_terminal_event_safely(
                    db,
                    task=task,
                    stage_name=stage_name,
                    status=status,
                    summary=summary,
                    stage_retry_mode=bool(stage_retry_mode),
                    task_retry_mode=bool(task_retry_mode),
                    target_stage_name=target_stage_name,
                    execution_token=execution_token,
                )
                self._record_event(
                    db,
                    task,
                    "stage_worker_terminal_observed",
                    f"阶段 worker 已完成，等待 reducer 串行收口: {stage_name}",
                    stage_name=stage_name,
                    payload={"status": status},
                )
                try:
                    db.commit()
                except Exception:
                    db.rollback()
                    task = db.query(task_manager_module.BinarySecurityTask).filter(
                        task_manager_module.BinarySecurityTask.id == task_id
                    ).first()
                    if task is not None:
                        self._emit_stage_terminal_event_safely(
                            db,
                            task=task,
                            stage_name=stage_name,
                            status=status,
                            summary=summary,
                            stage_retry_mode=bool(stage_retry_mode),
                            task_retry_mode=bool(task_retry_mode),
                            target_stage_name=target_stage_name,
                            execution_token=execution_token,
                        )
                        self._record_missing_stage_terminal_event(
                            db,
                            task,
                            stage_name=stage_name,
                            status=status,
                            reason="worker_commit_retry_after_failure",
                            summary=summary,
                            execution_token=execution_token,
                        )
                        db.commit()
                db.refresh(task)
                if str(task.status or "").strip() in task_manager_module.TASK_TERMINAL_STATUSES:
                    return
        finally:
            db.close()

    async def _run_stage_item_by_id(self: TaskManager, item_id: str) -> None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        owner_task_id: str | None = None
        owner_kind = f"streaming_stage_item:{item_id}"
        expected_claim_owner_instance_id: str | None = None
        expected_claim_execution_token: str | None = None
        try:
            item = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.id == item_id
            ).first()
            if item is None:
                return
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == item.task_id
            ).first()
            if task is None or not self._streaming_mode_enabled(task):
                return
            if task.status in task_manager_module.TASK_TERMINAL_STATUSES or task.status == "cancelled":
                return
            current_task_owner = str(task.dispatcher_instance_id or "").strip()
            current_task_token = self._dispatch_token(task)
            current_claim_owner = str(item.claim_owner_instance_id or "").strip()
            current_claim_token = self._stage_item_claim_token(item)
            if (
                not current_claim_owner
                and not current_claim_token
                and current_task_owner == str(self.instance_id or "").strip()
                and current_task_token
            ):
                expected_claim_execution_token = self._bind_stage_item_claim(
                    item,
                    task=task,
                    owner_instance_id=self.instance_id,
                )
                expected_claim_owner_instance_id = str(item.claim_owner_instance_id or "").strip() or None
                db.commit()
            else:
                expected_claim_owner_instance_id = current_claim_owner or None
                expected_claim_execution_token = current_claim_token
            if (
                not expected_claim_owner_instance_id
                or not expected_claim_execution_token
                or expected_claim_owner_instance_id != str(self.instance_id or "").strip()
                or current_task_owner != str(self.instance_id or "").strip()
                or expected_claim_execution_token != current_task_token
            ):
                raise task_manager_module.StaleTaskExecution(
                    f"任务 {task.id} 当前 streaming stage item claim 已切换: "
                    f"item_owner={expected_claim_owner_instance_id or '-'} task_owner={current_task_owner or '-'} "
                    f"item_token={expected_claim_execution_token or '-'} task_token={current_task_token or '-'}"
                )
            owner_task_id = task.id
            self._register_task_execution_owner(owner_task_id, owner_kind)
            await self._ensure_task_execution_current_async(task)
            stage_run = self._ensure_stage_run(db, task, item.stage_name)
            db.commit()
            payload = dict(item.input_ref or {})
            token = self._service_token()
            if item.stage_name == "entry_analysis":
                await self._run_entry_item(task, stage_run, payload, token, False)
            elif task_manager_module.normalize_stage_name(item.stage_name) == "dataflow_vuln_scan":
                await self._run_dataflow_item(task, stage_run, payload, token, False)
            elif task_manager_module.normalize_stage_name(item.stage_name) == "dataflow_vuln_scan":
                await self._run_dataflow_item(task, stage_run, payload, token, False)
            await self._sync_streaming_task_tail_state(task.id)
        except task_manager_module.StaleTaskExecution as exc:
            item = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.id == item_id
            ).first()
            task = (
                db.query(task_manager_module.BinarySecurityTask).filter(
                    task_manager_module.BinarySecurityTask.id == item.task_id
                ).first()
                if item is not None else None
            )
            requeued = False
            if (
                item is not None
                and str(item.status or "").strip().lower() == "dispatching"
                and expected_claim_owner_instance_id
                and expected_claim_execution_token
            ):
                requeued = bool(
                    db.query(task_manager_module.BinarySecurityStageItem)
                    .filter(
                        task_manager_module.BinarySecurityStageItem.id == item.id,
                        task_manager_module.BinarySecurityStageItem.status == "dispatching",
                        task_manager_module.BinarySecurityStageItem.claim_owner_instance_id == expected_claim_owner_instance_id,
                        task_manager_module.BinarySecurityStageItem.claim_execution_token == expected_claim_execution_token,
                    )
                    .update(
                        {
                            task_manager_module.BinarySecurityStageItem.status: "pending",
                            task_manager_module.BinarySecurityStageItem.error_message: str(exc),
                            task_manager_module.BinarySecurityStageItem.finished_at: None,
                            task_manager_module.BinarySecurityStageItem.claim_owner_instance_id: None,
                            task_manager_module.BinarySecurityStageItem.claim_execution_token: None,
                            task_manager_module.BinarySecurityStageItem.claim_started_at: None,
                            task_manager_module.BinarySecurityStageItem.updated_at: task_manager_module._now(),
                        },
                        synchronize_session=False,
                    )
                )
                item = db.query(task_manager_module.BinarySecurityStageItem).filter(
                    task_manager_module.BinarySecurityStageItem.id == item_id
                ).first()
            if requeued and item is not None:
                if task is not None and self._should_hold_task_on_stage_after_requeue(db, task, item.stage_name):
                    task.status = "running"
                    task.current_stage = item.stage_name
                    task.finished_at = None
                    task.last_error = None
                    task.dispatcher_instance_id = None
                    task.dispatch_started_at = None
                    task.lease_expires_at = None
                db.commit()
                if task is not None:
                    self._record_event(
                        db,
                        task,
                        "streaming_stage_item_requeued_after_stale_execution",
                        f"流式阶段子任务执行 token 失效，已重新排队: {item.stage_name}:{item.item_key}",
                        level="warning",
                        stage_name=item.stage_name,
                        item=item,
                        payload={
                            "error": str(exc),
                            "requeued_status": item.status,
                            "claim_owner_instance_id": expected_claim_owner_instance_id,
                            "claim_execution_token": expected_claim_execution_token,
                            "task_dispatcher_instance_id": str(getattr(task, 'dispatcher_instance_id', '') or '').strip() or None if task is not None else None,
                            "task_execution_token": self._dispatch_token(task) if task is not None else None,
                            "stale_action": "requeued",
                        },
                    )
                    db.commit()
            elif task is not None and item is not None:
                self._record_event(
                    db,
                    task,
                    "streaming_stage_item_stale_requeue_ignored",
                    f"流式阶段子任务 stale 回退已忽略，claim 已被新执行代接管: {item.stage_name}:{item.item_key}",
                    level="warning",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "error": str(exc),
                        "expected_claim_owner_instance_id": expected_claim_owner_instance_id,
                        "expected_claim_execution_token": expected_claim_execution_token,
                        "current_claim_owner_instance_id": str(item.claim_owner_instance_id or "").strip() or None,
                        "current_claim_execution_token": self._stage_item_claim_token(item),
                        "task_dispatcher_instance_id": str(getattr(task, "dispatcher_instance_id", "") or "").strip() or None,
                        "task_execution_token": self._dispatch_token(task),
                        "stale_action": "ignored_claim_mismatch",
                    },
                )
                db.commit()
            task_manager_module.logger.warning(
                "binary-security streaming stage item stale execution: item_id=%s task_id=%s claim_owner=%s claim_token=%s stale_action=%s error=%s",
                item_id,
                task.id if task is not None else None,
                expected_claim_owner_instance_id,
                expected_claim_execution_token,
                "requeued" if requeued else "ignored_claim_mismatch",
                exc,
            )
        except Exception as exc:
            item = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.id == item_id
            ).first()
            task = (
                db.query(task_manager_module.BinarySecurityTask).filter(
                    task_manager_module.BinarySecurityTask.id == item.task_id
                ).first()
                if item is not None else None
            )
            if item is not None and str(item.status or "").strip().lower() == "dispatching":
                retryable_transport = self._is_retryable_downstream_transport_error(exc)
                recoverable = retryable_transport or self._is_recoverable_orchestration_error(exc)
                item.status = "queued" if recoverable else "pending"
                item.error_message = str(exc)
                item.finished_at = None
                if recoverable:
                    state = self._build_next_stage_item_orchestration_failure_state(item)
                    self._mark_stage_item_orchestration_observation(
                        item,
                        source="streaming_stage_worker",
                        observed_at=task_manager_module._now(),
                        error_message=str(exc),
                        error_type=self._classify_orchestration_error(exc),
                        last_result="error",
                        consecutive_error_count=state.consecutive_error_count,
                        budget_exhausted=state.budget_exhausted,
                        next_retry_at=state.next_retry_at,
                    )
                db.commit()
                if task is not None:
                    self._record_event(
                        db,
                        task,
                        "streaming_stage_item_requeued_after_worker_error",
                        f"流式阶段子任务执行异常，已重新排队: {item.stage_name}:{item.item_key}",
                        level="warning",
                        stage_name=item.stage_name,
                        item=item,
                        payload={
                            "error": str(exc),
                            "retryable_transport": retryable_transport,
                            "recoverable_orchestration": recoverable,
                            "error_type": self._classify_orchestration_error(exc),
                            "next_retry_at": task_manager_module._isoformat_or_none(
                                self._stage_item_next_orchestration_retry_at_value(item)
                            ),
                            "budget_exhausted": self._stage_item_orchestration_error_budget_exhausted(item),
                            "requeued_status": item.status,
                        },
                    )
                    db.commit()
            task_manager_module.logger.exception("binary-security streaming stage item worker failed: item_id=%s", item_id)
        finally:
            if owner_task_id:
                self._release_task_execution_owner(owner_task_id, owner_kind)
            db.close()
            async with self._stage_item_worker_lock:
                self._stage_item_workers.pop(item_id, None)

    def _dispatch_token(self: TaskManager, task) -> str | None:
        return task.dispatch_started_at.isoformat() if task.dispatch_started_at else None

    async def _run_stage_pool(
        self: TaskManager,
        task,
        items,
        concurrency,
        runner,
        retries: int = 0,
        initial_retry: bool = False,
    ):
        effective_concurrency = concurrency
        semaphore = asyncio.Semaphore(max(1, effective_concurrency))
        runner_signature = inspect.signature(runner)
        supports_auto_retrying = "auto_retrying" in runner_signature.parameters or any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in runner_signature.parameters.values()
        )

        async def wrapped(item: dict):
            async with semaphore:
                await self._ensure_task_execution_current_async(task)
                if await self._is_task_cancelled_async(task.id):
                    return {"status": "cancelled", "error": "task cancelled", "item": item}
                attempts = 0
                result = await runner(item, initial_retry)
                await self._ensure_task_execution_current_async(task)
                while result.get("status") == "failed" and attempts < max(0, retries):
                    attempts += 1
                    await self._ensure_task_execution_current_async(task)
                    if supports_auto_retrying:
                        result = await runner(item, True, auto_retrying=True)
                    else:
                        result = await runner(item, True)
                    await self._ensure_task_execution_current_async(task)
                    result["attempts"] = attempts + 1
                return result

        return await asyncio.gather(*(wrapped(item) for item in items))

    async def _run_firmware_item(
        self: TaskManager,
        task,
        stage_run,
        input_file,
        token,
        retrying: bool = False,
        auto_retrying: bool = False,
    ) -> dict[str, object]:
        from app.service import task_manager as task_manager_module

        get_session_factory = task_manager_module.get_session_factory
        ValidationError = task_manager_module.ValidationError
        UpstreamError = task_manager_module.UpstreamError
        StaleTaskExecution = task_manager_module.StaleTaskExecution
        normalize_stage_name = task_manager_module.normalize_stage_name
        _downstream_origin_payload = task_manager_module._downstream_origin_payload
        _now = task_manager_module._now
        RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE
        RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = (
            task_manager_module.RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL
        )
        Path = task_manager_module.Path

        session = get_session_factory()()
        try:
            firmware_key = input_file["firmware_key"]
            input_path = Path(task.workspace_root) / "input" / input_file["filename"]
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=firmware_key,
                item_name=input_file["filename"],
                parent_key=firmware_key,
                downstream_service="firmware_unpacker",
                input_ref={"filename": input_file["filename"], "path": str(input_path)},
                output_ref={"downstream_service": "firmware_unpacker"},
                retrying=retrying,
                auto_retrying=auto_retrying,
                running_status="queued",
            )
            session.commit()
            active_payload = await self._active_downstream_payload(task, item, token)
            retry_strategy = None
            retry_strategy_status = None
            if retrying:
                retry_strategy, retry_strategy_status = self._classify_retry_downstream_strategy(
                    item,
                    active_payload=active_payload,
                )
                action_snapshot = await self._prepare_retry_child_for_reuse_or_recreate(
                    session,
                    task,
                    item,
                    strategy=retry_strategy,
                    observed_status=retry_strategy_status,
                    token=token,
                )
                self._store_retry_item_action(task, action_snapshot)
                session.commit()
                if retry_strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL:
                    active_payload = None
            if active_payload is not None:
                item.status = self._map_downstream_status(str(active_payload.get("status") or "")) or "running"
                item.downstream_task_id = active_payload.get("task_id") or active_payload.get("id") or item.downstream_task_id
                item.started_at = item.started_at or _now()
                self._merge_stage_item_result_fields(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    updates={"project_id": task.project_id},
                )
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                    success_statuses={"success"},
                    failure_statuses={"failed", "cancelled"},
                    task=task,
                    item=item,
                )
                created = None
            else:
                reusable_payload = None if retrying else await self._find_reusable_firmware_unpack_payload(
                    task,
                    item,
                    token,
                )
                if reusable_payload is not None:
                    downstream_status = str(reusable_payload.get("status") or "").lower()
                    mapped_reusable_status = self._map_downstream_status(downstream_status)
                    item.downstream_task_id = (
                        reusable_payload.get("task_id") or reusable_payload.get("id") or item.downstream_task_id
                    )
                    await self._cleanup_duplicate_downstream_refs_for_item(
                        session,
                        task,
                        item,
                        token,
                        keep_task_ids={str(item.downstream_task_id or "").strip()},
                    )
                    self._merge_stage_item_result_fields(
                        task,
                        item,
                        stage_name=stage_run.stage_name,
                        updates={"project_id": task.project_id},
                    )
                    if mapped_reusable_status in {"queued", "running"}:
                        item.status = mapped_reusable_status
                        item.started_at = item.started_at or _now()
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                    else:
                        payload = dict(reusable_payload)
                        status = self._status_from_downstream_payload(payload, success_statuses={"success"})
                        session.commit()
                    created = None
                elif retrying and retry_strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE and self._has_retryable_downstream_task(item):
                    control = await self._downstream_control_existing_task(
                        session,
                        stage_name=stage_run.stage_name,
                        task=task,
                        item=item,
                        token=token,
                    )
                    outcome = str(control.get("outcome") or "")
                    if outcome == "accepted":
                        created = dict(control.get("payload") or {})
                    elif outcome == "already_running":
                        payload = dict(control.get("payload") or {})
                        item.status = self._map_downstream_status(str(payload.get("status") or "")) or "running"
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        item.started_at = item.started_at or _now()
                        self._merge_stage_item_result_fields(
                            task,
                            item,
                            stage_name=stage_run.stage_name,
                            updates={"project_id": task.project_id},
                        )
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                        created = None
                    elif outcome == "already_terminal":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        self._merge_stage_item_result_fields(
                            task,
                            item,
                            stage_name=stage_run.stage_name,
                            updates={"project_id": task.project_id},
                        )
                        session.commit()
                        status = self._status_from_downstream_payload(payload, success_statuses={"success"})
                        created = None
                    elif outcome == "not_found":
                        item.status = "downstream_missing"
                        item.error_message = str(control.get("error_message") or "下游子任务不存在")
                        item.finished_at = _now()
                        session.commit()
                        return {"status": "downstream_missing", "error": item.error_message, "item": input_file}
                    elif outcome == "transport_error":
                        return self._defer_item_after_downstream_transport_error(
                            session,
                            task,
                            item,
                            operation="firmware_unpack",
                            exc=UpstreamError(str(control.get("error_message") or "下游通信异常")),
                            response_item=input_file,
                        )
                    else:
                        raise ValidationError(str(control.get("error_message") or "下游重试失败"))
                else:
                    created = await self._downstream_create_task(
                        session,
                        task,
                        item,
                        service="firmware_unpacker",
                        token=token,
                        payload={
                            "firmware_path": str(input_path),
                            "origin": _downstream_origin_payload(task, item),
                        },
                    )
            if created is not None:
                item.status = "running"
                old_downstream_task_id = await self._replace_active_child_binding(
                    session,
                    task,
                    item,
                    new_downstream_task_id=created.get("task_id") or created.get("id"),
                    token=token,
                    reason="firmware_unpack_child_create",
                )
                item.started_at = _now()
                self._merge_stage_item_result_fields(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    updates={"project_id": task.project_id},
                )
                self._record_downstream_item_disposition(
                    session,
                    task,
                    item,
                    event_type="retry_item_new_child_created" if retrying else "downstream_child_created",
                    message="已创建新的下游子任务",
                    payload={
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                        "old_downstream_task_id": old_downstream_task_id,
                        "new_downstream_task_id": item.downstream_task_id,
                        "strategy": retry_strategy if retrying else None,
                        "old_downstream_status": retry_strategy_status if retrying else None,
                    },
                )
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                    success_statuses={"success"},
                    failure_statuses={"failed", "cancelled"},
                    task=task,
                    item=item,
                )
            mapped_status = (
                "success"
                if status == "success"
                else "cancelled"
                if status == "cancelled"
                else "downstream_missing"
                if status == "downstream_missing"
                else "failed"
            )
            item.status = mapped_status
            item.error_message = None if mapped_status in {"success", "partial_success"} else (
                payload.get("error") or payload.get("error_message") or payload.get("message")
            )
            item.finished_at = _now()
            item.started_at = item.started_at or _now()
            archive_root, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": input_file}
            if archive_root is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": input_file, "archive_blocked": True}
            result = {
                **input_file,
                "input_path": str(input_path),
                "unpacked_root": str(archive_root),
                "downstream": self._lightweight_downstream_payload(payload),
            }
            self._persist_stage_item_result(
                task,
                item,
                stage_name=stage_run.stage_name,
                result={**self._load_stage_item_result_payload(item), **result},
            )
            item.output_ref = {
                **(item.output_ref or {}),
                "archive_root": str(archive_root),
                "unpacked_root": result["unpacked_root"],
            }
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except UpstreamError as exc:
            session.rollback()
            if "item" in locals():
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="firmware_unpack",
                    exc=exc,
                    response_item=input_file,
                )
            return {"status": "pending", "error": str(exc), "item": input_file, "deferred_mode": "redispatch"}
        except Exception as exc:
            if "item" in locals() and self._is_retryable_downstream_transport_error(exc):
                session.rollback()
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="firmware_unpack",
                    exc=exc,
                    response_item=input_file,
                )
            if "item" in locals() and self._is_recoverable_orchestration_error(exc):
                session.rollback()
                return self._defer_item_after_orchestration_error(
                    session,
                    task,
                    item,
                    operation="firmware_unpack",
                    exc=exc,
                    response_item=input_file,
                )
            session.rollback()
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": input_file}
        finally:
            session.close()

    async def _run_system_analysis_item(
        self: TaskManager,
        task,
        stage_run,
        firmware,
        retrying: bool = False,
        auto_retrying: bool = False,
    ) -> dict[str, object]:
        from app.service import task_manager as task_manager_module

        get_session_factory = task_manager_module.get_session_factory
        ValidationError = task_manager_module.ValidationError
        UpstreamError = task_manager_module.UpstreamError
        StaleTaskExecution = task_manager_module.StaleTaskExecution
        _downstream_origin_payload = task_manager_module._downstream_origin_payload
        _now = task_manager_module._now
        RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE
        RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = (
            task_manager_module.RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL
        )

        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=firmware["firmware_key"],
                item_name=firmware["filename"],
                parent_key=firmware["firmware_key"],
                downstream_service="system_analyse",
                input_ref={
                    "input_path": firmware["unpacked_root"],
                    "firmware_key": firmware["firmware_key"],
                    "task_type": self._task_type(task),
                    "analysis_mode": self._task_type(task),
                },
                retrying=retrying,
                auto_retrying=auto_retrying,
            )
            session.commit()
            active_payload = await self._active_downstream_payload(task, item)
            retry_strategy = None
            retry_strategy_status = None
            if retrying:
                retry_strategy, retry_strategy_status = self._classify_retry_downstream_strategy(
                    item,
                    active_payload=active_payload,
                )
                action_snapshot = await self._prepare_retry_child_for_reuse_or_recreate(
                    session,
                    task,
                    item,
                    strategy=retry_strategy,
                    observed_status=retry_strategy_status,
                    token=self._resolve_downstream_token(),
                )
                self._store_retry_item_action(task, action_snapshot)
                session.commit()
                if retry_strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL:
                    active_payload = None
            if active_payload is not None:
                item.status = self._map_downstream_status(str(active_payload.get("status") or "")) or "running"
                item.downstream_task_id = active_payload.get("task_id") or active_payload.get("id") or item.downstream_task_id
                item.started_at = item.started_at or _now()
                item.error_message = None
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, None),
                    success_statuses={"passed", "success"},
                    failure_statuses={"failed", "error", "cancelled"},
                    task=task,
                    item=item,
                )
            else:
                reusable_payload = None if retrying else await self._find_reusable_system_analysis_payload(
                    task,
                    item,
                    self._resolve_downstream_token(),
                )
                if reusable_payload is not None:
                    downstream_status = str(reusable_payload.get("status") or "").lower()
                    mapped_reusable_status = self._map_downstream_status(downstream_status)
                    if mapped_reusable_status in {"queued", "running"}:
                        item.status = mapped_reusable_status
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, None),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled"},
                            task=task,
                            item=item,
                        )
                    else:
                        session.commit()
                        payload = await self._downstream_fetch_item_payload(task, item, None)
                        downstream_status = str(payload.get("status") or "").lower()
                        if downstream_status in {"passed", "success"}:
                            status = "success"
                        elif downstream_status == "cancelled":
                            status = "cancelled"
                        elif downstream_status == "downstream_missing":
                            status = "downstream_missing"
                        else:
                            status = "failed"
                elif retrying and retry_strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE and self._has_retryable_downstream_task(item):
                    control = await self._downstream_control_existing_task(
                        session,
                        stage_name=stage_run.stage_name,
                        task=task,
                        item=item,
                        token=self._resolve_downstream_token(),
                    )
                    outcome = str(control.get("outcome") or "")
                    if outcome == "accepted":
                        created = dict(control.get("payload") or {})
                        item.downstream_task_id = created.get("task_id") or item.downstream_task_id
                        item.status = "running"
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, None),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled"},
                            task=task,
                            item=item,
                        )
                    elif outcome == "already_running":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        item.status = self._map_downstream_status(str(payload.get("status") or "")) or "running"
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, None),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled"},
                            task=task,
                            item=item,
                        )
                    elif outcome == "already_terminal":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        session.commit()
                        status = self._status_from_downstream_payload(payload, success_statuses={"passed", "success"})
                    elif outcome == "not_found":
                        item.status = "downstream_missing"
                        item.error_message = str(control.get("error_message") or "下游子任务不存在")
                        item.finished_at = _now()
                        session.commit()
                        return {
                            "status": "downstream_missing",
                            "item": self._lightweight_system_analysis_input(firmware),
                            "error": item.error_message,
                        }
                    elif outcome == "transport_error":
                        return self._defer_item_after_downstream_transport_error(
                            session,
                            task,
                            item,
                            operation="system_analysis",
                            exc=UpstreamError(str(control.get("error_message") or "下游通信异常")),
                            response_item=firmware,
                        )
                    else:
                        raise ValidationError(str(control.get("error_message") or "下游重试失败"))
                else:
                    created = await self._downstream_create_task(
                        session,
                        task,
                        item,
                        service="system_analyse",
                        token=self._resolve_downstream_token(),
                        payload={
                            "task_name": f"{task.name}-{firmware['firmware_name']}-system-analysis",
                            "input_path": firmware["unpacked_root"],
                            "origin": _downstream_origin_payload(task, item),
                            "analysis_mode": self._task_type(task),
                        },
                    )
                    old_downstream_task_id = await self._replace_active_child_binding(
                        session,
                        task,
                        item,
                        new_downstream_task_id=created.get("task_id") or created.get("id"),
                        token=self._resolve_downstream_token(),
                        reason="system_analysis_child_create",
                    )
                    item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
                    item.started_at = item.started_at or _now()
                    item.error_message = None
                    self._record_downstream_item_disposition(
                        session,
                        task,
                        item,
                        event_type="retry_item_new_child_created" if retrying else "downstream_child_created",
                        message="已创建新的下游子任务",
                        payload={
                            "stage_name": item.stage_name,
                            "item_id": item.id,
                            "item_key": item.item_key,
                            "old_downstream_task_id": old_downstream_task_id,
                            "new_downstream_task_id": item.downstream_task_id,
                            "strategy": retry_strategy if retrying else None,
                            "old_downstream_status": retry_strategy_status if retrying else None,
                        },
                    )
                    session.commit()
                    status, payload = await self._poll_until_terminal(
                        lambda: self._downstream_fetch_item_payload(task, item, None),
                        success_statuses={"passed", "success"},
                        failure_statuses={"failed", "error", "cancelled"},
                        task=task,
                        item=item,
                    )
            result_payload = {}
            if status == "success":
                try:
                    result_payload = await self._downstream_fetch_item_result(item)
                except Exception:
                    result_payload = {}
            archive_payload = {**payload, **({"result": result_payload} if result_payload else {})}
            mapped_status = (
                "success"
                if status == "success"
                else "cancelled"
                if status == "cancelled"
                else "downstream_missing"
                if status == "downstream_missing"
                else "failed"
            )
            item.status = mapped_status
            item.finished_at = _now()
            archive_root, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=archive_payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {
                    "status": mapped_status,
                    "item": self._lightweight_system_analysis_input(firmware),
                    "error": item.error_message,
                }
            if archive_root is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {
                    "status": "archive_blocked",
                    "error": error,
                    "item": self._lightweight_system_analysis_input(firmware),
                    "archive_blocked": True,
                }
            modules = self._parse_system_analysis_modules(archive_root, firmware, result_payload)
            result = {
                **self._lightweight_system_analysis_input(firmware),
                "module_count": len(modules),
                "modules_file": str(archive_root / "system_analysis_modules.json"),
                "modules_preview": self._lightweight_modules_for_storage(modules),
                "downstream": self._lightweight_downstream_payload(payload),
                "system_analysis_result": self._lightweight_system_analysis_result(result_payload),
            }
            self._persist_stage_item_result(
                task,
                item,
                stage_name=stage_run.stage_name,
                result=result,
            )
            item.output_ref = {
                **(item.output_ref or {}),
                "artifact_root": str(archive_root),
                "archive_root": str(archive_root),
            }
            session.commit()
            return {
                "status": item.status,
                "item": {**result, "modules": modules},
                "error": payload.get("error") or payload.get("error_message"),
            }
        except StaleTaskExecution:
            session.rollback()
            raise
        except UpstreamError as exc:
            session.rollback()
            if "item" in locals():
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="system_analysis",
                    exc=exc,
                    response_item=firmware,
                )
            return {"status": "pending", "error": str(exc), "item": firmware, "deferred_mode": "redispatch"}
        except Exception as exc:
            if "item" in locals() and self._is_retryable_downstream_transport_error(exc):
                session.rollback()
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="system_analysis",
                    exc=exc,
                    response_item=firmware,
                )
            if "item" in locals() and self._is_recoverable_orchestration_error(exc):
                session.rollback()
                return self._defer_item_after_orchestration_error(
                    session,
                    task,
                    item,
                    operation="system_analysis",
                    exc=exc,
                    response_item=firmware,
                )
            if "item" in locals():
                session.rollback()
                item = session.merge(item)
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                self._persist_stage_item_result(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    result={
                        **self._lightweight_system_analysis_input(firmware),
                        "error": str(exc),
                        "downstream_task_id": item.downstream_task_id,
                    },
                )
                session.commit()
            return {"status": "failed", "error": str(exc), "item": firmware}
        finally:
            session.close()

    async def _run_b2s_item(
        self: TaskManager,
        task,
        stage_run,
        module,
        token,
        retrying: bool = False,
        auto_retrying: bool = False,
    ) -> dict[str, object]:
        from app.service import task_manager as task_manager_module

        get_session_factory = task_manager_module.get_session_factory
        ValidationError = task_manager_module.ValidationError
        UpstreamError = task_manager_module.UpstreamError
        StaleTaskExecution = task_manager_module.StaleTaskExecution
        _downstream_origin_payload = task_manager_module._downstream_origin_payload
        _now = task_manager_module._now
        RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE
        RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = (
            task_manager_module.RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL
        )
        TASK_TYPE_BINARY_MODULE = task_manager_module.TASK_TYPE_BINARY_MODULE
        Path = task_manager_module.Path

        session = get_session_factory()()
        try:
            entry_input = self._normalize_entry_analysis_module_input(task, module)
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                downstream_service="binary_to_source",
                input_ref=module,
                retrying=retrying,
                auto_retrying=auto_retrying,
            )
            session.commit()
            elf_tasks = self._build_module_elf_tasks(module)
            active_payload = await self._active_downstream_payload(task, item, token)
            retry_strategy = None
            retry_strategy_status = None
            if retrying:
                retry_strategy, retry_strategy_status = self._classify_retry_downstream_strategy(
                    item,
                    active_payload=active_payload,
                )
                action_snapshot = await self._prepare_retry_child_for_reuse_or_recreate(
                    session,
                    task,
                    item,
                    strategy=retry_strategy,
                    observed_status=retry_strategy_status,
                    token=token,
                )
                self._store_retry_item_action(task, action_snapshot)
                session.commit()
                if retry_strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL:
                    active_payload = None
            if active_payload is not None:
                item.status = self._map_downstream_status(str(active_payload.get("status") or "")) or item.status
                item.downstream_task_id = (
                    active_payload.get("task_id") or active_payload.get("id") or item.downstream_task_id
                )
                item.started_at = item.started_at or _now()
                item.error_message = None
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                    success_statuses={"success", "partial_success", "completed"},
                    failure_statuses={"failed", "cancelled"},
                    task=task,
                    item=item,
                )
            else:
                reusable_payload = None if retrying else await self._find_reusable_b2s_payload(task, item, token)
                if reusable_payload is not None:
                    downstream_status = str(reusable_payload.get("status") or "").lower()
                    mapped_reusable_status = self._map_downstream_status(downstream_status)
                    if mapped_reusable_status in {"queued", "running"}:
                        item.status = mapped_reusable_status
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success", "partial_success", "completed"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                    else:
                        session.commit()
                        payload = await self._downstream_fetch_item_payload(task, item, token or "")
                        downstream_status = str(payload.get("status") or "").lower()
                        if downstream_status in {"success", "partial_success", "completed"}:
                            status = "success"
                        elif downstream_status == "cancelled":
                            status = "cancelled"
                        elif downstream_status == "downstream_missing":
                            status = "downstream_missing"
                        else:
                            status = "failed"
                elif retrying and retry_strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE and self._has_retryable_downstream_task(item):
                    control = await self._downstream_control_existing_task(
                        session,
                        stage_name=stage_run.stage_name,
                        task=task,
                        item=item,
                        token=token,
                    )
                    outcome = str(control.get("outcome") or "")
                    if outcome == "accepted":
                        created = dict(control.get("payload") or {})
                        item.downstream_task_id = created.get("id") or item.downstream_task_id
                        item.status = "running"
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success", "partial_success", "completed"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                    elif outcome == "already_running":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        item.status = self._map_downstream_status(str(payload.get("status") or "")) or "running"
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success", "partial_success", "completed"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                    elif outcome == "already_terminal":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        session.commit()
                        status = self._status_from_downstream_payload(
                            payload,
                            success_statuses={"success", "partial_success", "completed"},
                        )
                    elif outcome == "not_found":
                        item.status = "downstream_missing"
                        item.error_message = str(control.get("error_message") or "下游子任务不存在")
                        item.finished_at = _now()
                        session.commit()
                        return {"status": "downstream_missing", "error": item.error_message, "item": module}
                    elif outcome == "transport_error":
                        return self._defer_item_after_downstream_transport_error(
                            session,
                            task,
                            item,
                            operation="binary_to_source",
                            exc=UpstreamError(str(control.get("error_message") or "下游通信异常")),
                            response_item=module,
                        )
                    else:
                        raise ValidationError(str(control.get("error_message") or "下游重试失败"))
                else:
                    b2s_mode, b2s_engine = self._b2s_execution_mode(task)
                    created = await self._downstream_create_task(
                        session,
                        task,
                        item,
                        service="binary_to_source",
                        token=token,
                        payload={
                            "name": f"{task.name}-{module['module_name']}",
                            "elf_tasks": elf_tasks,
                            "origin": _downstream_origin_payload(task, item),
                            "mode": b2s_mode,
                            "engine": b2s_engine,
                        },
                    )
                    old_downstream_task_id = await self._replace_active_child_binding(
                        session,
                        task,
                        item,
                        new_downstream_task_id=created.get("task_id") or created.get("id"),
                        token=token,
                        reason="binary_to_source_child_create",
                    )
                    self._merge_stage_item_result_fields(
                        task,
                        item,
                        stage_name=stage_run.stage_name,
                        updates={"project_id": task.project_id},
                    )
                    item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
                    item.started_at = item.started_at or _now()
                    item.error_message = None
                    self._record_downstream_item_disposition(
                        session,
                        task,
                        item,
                        event_type="retry_item_new_child_created" if retrying else "downstream_child_created",
                        message="已创建新的下游子任务",
                        payload={
                            "stage_name": item.stage_name,
                            "item_id": item.id,
                            "item_key": item.item_key,
                            "old_downstream_task_id": old_downstream_task_id,
                            "new_downstream_task_id": item.downstream_task_id,
                            "strategy": retry_strategy if retrying else None,
                            "old_downstream_status": retry_strategy_status if retrying else None,
                        },
                    )
                    session.commit()
                    status, payload = await self._poll_until_terminal(
                        lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                        success_statuses={"success", "partial_success", "completed"},
                        failure_statuses={"failed", "cancelled"},
                        task=task,
                        item=item,
                    )
            self._merge_stage_item_result_fields(
                task,
                item,
                stage_name=stage_run.stage_name,
                updates={"project_id": task.project_id},
            )
            session.commit()
            extra_paths: list[str] = []
            for child in payload.get("items", []):
                if child.get("output_dir"):
                    extra_paths.append(child["output_dir"])
                for file_path in child.get("generated_files") or []:
                    src = Path(file_path)
                    if src.exists():
                        extra_paths.append(str(src.parent))
            mapped_status = (
                "success"
                if status == "success"
                else "cancelled"
                if status == "cancelled"
                else "downstream_missing"
                if status == "downstream_missing"
                else "failed"
            )
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
                extra_paths=extra_paths,
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": module}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": module, "archive_blocked": True}
            artifact_kind_summary: dict[str, int] = {}
            result_kind_summary: dict[str, int] = {}
            result_kinds: list[str] = []
            primary_result_kind = None
            item_summaries: list[dict[str, object]] = []
            prepared_entry = self._build_b2s_result_payload(
                task,
                module,
                payload,
                archived_dir,
                entry_input=entry_input,
                project_id=task.project_id,
            )
            result = dict(prepared_entry)
            if result.get("artifact_index_path"):
                artifact_index_path = str(result.get("artifact_index_path") or "").strip()
            else:
                artifact_index_path = ""
            b2s_result_summary_version = int(result.get("result_summary_version") or 1)
            for row in result.get("result_items") or []:
                if not isinstance(row, dict):
                    continue
                summary_row = dict(row)
                item_summaries.append(summary_row)
                kind = str(summary_row.get("kind") or "").strip()
                if kind:
                    artifact_kind_summary[kind] = artifact_kind_summary.get(kind, 0) + 1
                key = str(summary_row.get("result_kind") or "").strip()
                if key:
                    result_kind_summary[key] = result_kind_summary.get(key, 0) + 1
                    result_kinds.append(key)
                    if primary_result_kind is None:
                        primary_result_kind = key
            downstream_result_summary = dict(result.get("downstream_result_summary") or {})
            if downstream_result_summary:
                for key, value in downstream_result_summary.items():
                    if isinstance(value, int):
                        result_kind_summary[key] = max(result_kind_summary.get(key, 0), value)
            result["artifact_kind_summary"] = artifact_kind_summary
            result["result_kind_summary"] = result_kind_summary
            result["result_kinds"] = result_kinds
            result["primary_result_kind"] = primary_result_kind
            result["artifact_index_path"] = artifact_index_path
            result["result_summary_version"] = b2s_result_summary_version
            result["downstream"] = payload
            if result.get("task_type") == TASK_TYPE_BINARY_MODULE:
                result["entry_module_name"] = result.get("module_name")
            self._persist_stage_item_result(
                task,
                item,
                stage_name=stage_run.stage_name,
                result=result,
            )
            item.output_ref = {
                **(item.output_ref or {}),
                "artifact_root": str(archived_dir),
                "archive_root": str(archived_dir),
                "artifact_index_path": artifact_index_path or None,
            }
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except UpstreamError as exc:
            session.rollback()
            if "item" in locals():
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="binary_to_source",
                    exc=exc,
                    response_item=module,
                )
            return {"status": "pending", "error": str(exc), "item": module, "deferred_mode": "redispatch"}
        except Exception as exc:
            if "item" in locals() and self._is_retryable_downstream_transport_error(exc):
                session.rollback()
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="binary_to_source",
                    exc=exc,
                    response_item=module,
                )
            if "item" in locals() and self._is_recoverable_orchestration_error(exc):
                session.rollback()
                return self._defer_item_after_orchestration_error(
                    session,
                    task,
                    item,
                    operation="binary_to_source",
                    exc=exc,
                    response_item=module,
                )
            session.rollback()
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": module}
        finally:
            session.close()

    async def _run_entry_item(
        self: TaskManager,
        task,
        stage_run,
        module,
        token,
        retrying: bool = False,
        auto_retrying: bool = False,
    ) -> dict[str, object]:
        from app.service import task_manager as task_manager_module

        get_session_factory = task_manager_module.get_session_factory
        ValidationError = task_manager_module.ValidationError
        UpstreamError = task_manager_module.UpstreamError
        StaleTaskExecution = task_manager_module.StaleTaskExecution
        normalize_stage_name = task_manager_module.normalize_stage_name
        _downstream_origin_payload = task_manager_module._downstream_origin_payload
        _now = task_manager_module._now
        RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE
        RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = (
            task_manager_module.RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL
        )

        session = get_session_factory()()
        try:
            entry_input = self._normalize_entry_analysis_module_input(task, module)
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                downstream_service="entry_analyse",
                input_ref=module,
                retrying=retrying,
                auto_retrying=auto_retrying,
            )
            session.commit()
            active_payload = await self._active_downstream_payload(task, item, token)
            retry_strategy = None
            retry_strategy_status = None
            if retrying:
                retry_strategy, retry_strategy_status = self._classify_retry_downstream_strategy(
                    item,
                    active_payload=active_payload,
                )
                action_snapshot = await self._prepare_retry_child_for_reuse_or_recreate(
                    session,
                    task,
                    item,
                    strategy=retry_strategy,
                    observed_status=retry_strategy_status,
                    token=token,
                )
                self._store_retry_item_action(task, action_snapshot)
                session.commit()
                if retry_strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL:
                    active_payload = None
            if active_payload is not None:
                item.status = self._map_downstream_status(str(active_payload.get("status") or "")) or "running"
                item.downstream_task_id = (
                    active_payload.get("task_id") or active_payload.get("id") or item.downstream_task_id
                )
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                    success_statuses={"passed", "success"},
                    failure_statuses={"failed", "error", "cancelled"},
                    task=task,
                    item=item,
                )
                created = None
            else:
                reusable_payload = None if retrying else await self._find_reusable_entry_payload(task, item, token)
                if reusable_payload is not None:
                    downstream_status = str(reusable_payload.get("status") or "").lower()
                    mapped_reusable_status = self._map_downstream_status(downstream_status)
                    item.downstream_task_id = (
                        reusable_payload.get("task_id") or reusable_payload.get("id") or item.downstream_task_id
                    )
                    await self._cleanup_duplicate_downstream_refs_for_item(
                        session,
                        task,
                        item,
                        token,
                        keep_task_ids={str(item.downstream_task_id or "").strip()},
                    )
                    if mapped_reusable_status in {"pending", "queued", "dispatching", "running"}:
                        item.status = mapped_reusable_status
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled"},
                            task=task,
                            item=item,
                        )
                    else:
                        payload = dict(reusable_payload)
                        should_recreate, terminal_status = self._entry_terminal_payload_requires_recreate(
                            retrying=retrying,
                            payload=payload,
                        )
                        if should_recreate:
                            input_contract = self._build_entry_analysis_input_contract(entry_input)
                            item.downstream_task_id = None
                            created = await self._downstream_create_task(
                                session,
                                task,
                                item,
                                service="entry_analyse",
                                token=token,
                                payload={
                                    "task_name": f"{task.name}-{entry_input['module_name']}-entry",
                                    "input_path": input_contract["module_dir"],
                                    "module_name": entry_input["module_name"],
                                    "source_path": input_contract["source_root"],
                                    "origin": {
                                        **_downstream_origin_payload(task, item),
                                        "input_contract": input_contract,
                                        "entry_descriptor_root": entry_input.get("entry_descriptor_root"),
                                        "entry_files_list": entry_input.get("entry_files_list"),
                                    },
                                },
                            )
                        else:
                            status = terminal_status
                            created = None
                elif retrying and retry_strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE and self._has_retryable_downstream_task(item):
                    control = await self._downstream_control_existing_task(
                        session,
                        stage_name=stage_run.stage_name,
                        task=task,
                        item=item,
                        token=token,
                    )
                    outcome = str(control.get("outcome") or "")
                    if outcome == "accepted":
                        created = dict(control.get("payload") or {})
                    elif outcome == "already_running":
                        payload = dict(control.get("payload") or {})
                        item.status = self._map_downstream_status(str(payload.get("status") or "")) or "running"
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled"},
                            task=task,
                            item=item,
                        )
                        created = None
                    elif outcome == "already_terminal":
                        payload = dict(control.get("payload") or {})
                        terminal_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        item.downstream_task_id = terminal_task_id
                        terminal_status = self._status_from_downstream_payload(
                            payload,
                            success_statuses={"passed", "success"},
                        )
                        if self._should_recreate_entry_child_from_terminal_status(
                            retrying=retrying,
                            terminal_status=terminal_status,
                        ):
                            input_contract = self._build_entry_analysis_input_contract(entry_input)
                            item.downstream_task_id = None
                            created = await self._downstream_create_task(
                                session,
                                task,
                                item,
                                service="entry_analyse",
                                token=token,
                                payload={
                                    "task_name": f"{task.name}-{entry_input['module_name']}-entry",
                                    "input_path": input_contract["module_dir"],
                                    "module_name": entry_input["module_name"],
                                    "source_path": input_contract["source_root"],
                                    "origin": {
                                        **_downstream_origin_payload(task, item),
                                        "input_contract": input_contract,
                                        "entry_descriptor_root": entry_input.get("entry_descriptor_root"),
                                        "entry_files_list": entry_input.get("entry_files_list"),
                                    },
                                },
                            )
                        else:
                            session.commit()
                            status = terminal_status
                            created = None
                    elif outcome == "not_found":
                        item.status = "downstream_missing"
                        item.error_message = str(control.get("error_message") or "下游子任务不存在")
                        item.finished_at = _now()
                        session.commit()
                        return {"status": "downstream_missing", "error": item.error_message, "item": module}
                    elif outcome == "transport_error":
                        return self._defer_item_after_downstream_transport_error(
                            session,
                            task,
                            item,
                            operation="entry_analysis",
                            exc=UpstreamError(str(control.get("error_message") or "下游通信异常")),
                            response_item=entry_input if "entry_input" in locals() else module,
                        )
                    else:
                        raise ValidationError(str(control.get("error_message") or "下游重试失败"))
                else:
                    input_contract = self._build_entry_analysis_input_contract(entry_input)
                    created = await self._downstream_create_task(
                        session,
                        task,
                        item,
                        service="entry_analyse",
                        token=token,
                        payload={
                            "task_name": f"{task.name}-{entry_input['module_name']}-entry",
                            "input_path": input_contract["module_dir"],
                            "module_name": entry_input["module_name"],
                            "source_path": input_contract["source_root"],
                            "origin": {
                                **_downstream_origin_payload(task, item),
                                "input_contract": input_contract,
                                "entry_descriptor_root": entry_input.get("entry_descriptor_root"),
                                "entry_files_list": entry_input.get("entry_files_list"),
                            },
                        },
                    )
            if created is not None:
                created_task_id = str(created.get("task_id") or "").strip()
                current_downstream_task_id = str(item.downstream_task_id or "").strip()
                if created_task_id and (
                    not current_downstream_task_id or current_downstream_task_id == created_task_id
                ):
                    item.downstream_task_id = created_task_id
                item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
                self._record_downstream_item_disposition(
                    session,
                    task,
                    item,
                    event_type="retry_item_new_child_created" if retrying else "downstream_child_created",
                    message="已创建新的下游子任务",
                    payload={
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                        "old_downstream_task_id": None,
                        "new_downstream_task_id": item.downstream_task_id,
                        "strategy": retry_strategy if retrying else None,
                        "old_downstream_status": retry_strategy_status if retrying else None,
                    },
                )
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                    success_statuses={"passed", "success"},
                    failure_statuses={"failed", "error", "cancelled"},
                    task=task,
                    item=item,
                )
            service_output = self._materialize_stage_artifact(
                self._service_output_path(
                    task,
                    item.downstream_service or stage_run.stage_name,
                    module["module_key"],
                    item.downstream_task_id,
                ),
                item.downstream_task_id,
                payload,
                db=session,
                task=task,
                item=item,
            )
            entries = self._parse_entries(service_output, entry_input)
            mapped_status = (
                "success"
                if status == "success"
                else "cancelled"
                if status == "cancelled"
                else "downstream_missing"
                if status == "downstream_missing"
                else "failed"
            )
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": entry_input}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {
                    "status": "archive_blocked",
                    "error": error,
                    "item": entry_input,
                    "archive_blocked": True,
                }
            archived_entries = self._parse_entries(archived_dir, entry_input)
            if archived_entries:
                entries = archived_entries
            result = {
                **entry_input,
                "entries": entries,
                "source_dir": entry_input["source_dir"],
                "downstream": payload,
            }
            self._persist_stage_item_result(
                task,
                item,
                stage_name=stage_run.stage_name,
                result=result,
            )
            item.output_ref = {
                **(item.output_ref or {}),
                "artifact_root": str(archived_dir),
                "archive_root": str(archived_dir),
            }
            if self._streaming_mode_enabled(task):
                self._trigger_dataflow_items_from_entry_result(session, task, result, upstream_item=item)
            session.commit()
            return {
                "status": item.status,
                "item": result,
                "error": payload.get("error") or payload.get("error_message"),
            }
        except StaleTaskExecution:
            session.rollback()
            raise
        except UpstreamError as exc:
            session.rollback()
            if "item" in locals():
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="entry_analysis",
                    exc=exc,
                    response_item=entry_input if "entry_input" in locals() else module,
                )
            return {
                "status": "pending",
                "error": str(exc),
                "item": entry_input if "entry_input" in locals() else module,
                "deferred_mode": "redispatch",
            }
        except Exception as exc:
            if "item" in locals() and self._is_retryable_downstream_transport_error(exc):
                session.rollback()
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="entry_analysis",
                    exc=exc,
                    response_item=entry_input if "entry_input" in locals() else module,
                )
            if "item" in locals() and self._is_recoverable_orchestration_error(exc):
                session.rollback()
                return self._defer_item_after_orchestration_error(
                    session,
                    task,
                    item,
                    operation="entry_analysis",
                    exc=exc,
                    response_item=entry_input if "entry_input" in locals() else module,
                )
            session.rollback()
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {
                "status": "failed",
                "error": str(exc),
                "item": entry_input if "entry_input" in locals() else module,
            }
        finally:
            session.close()

    async def _run_dataflow_item(
        self: TaskManager,
        task,
        stage_run,
        entry,
        token,
        retrying: bool = False,
        auto_retrying: bool = False,
    ) -> dict[str, object]:
        from app.service import task_manager as task_manager_module

        get_session_factory = task_manager_module.get_session_factory
        ValidationError = task_manager_module.ValidationError
        UpstreamError = task_manager_module.UpstreamError
        StaleTaskExecution = task_manager_module.StaleTaskExecution
        normalize_stage_name = task_manager_module.normalize_stage_name
        _downstream_origin_payload = task_manager_module._downstream_origin_payload
        _entry_signature_params = task_manager_module._entry_signature_params
        _now = task_manager_module._now
        RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE
        RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = (
            task_manager_module.RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL
        )

        session = get_session_factory()()
        try:
            try:
                entry = self._validate_entry_output_contract(entry)
            except ValidationError:
                recovered_entry = self._recover_entry_output_contract(session, task, entry)
                if recovered_entry:
                    entry = self._validate_entry_output_contract(
                        {**entry, **recovered_entry},
                        allow_fallback=True,
                    )
                else:
                    entry = self._validate_entry_output_contract(entry)
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=entry["entry_key"],
                item_name=entry["function_name"],
                parent_key=entry["module_key"],
                downstream_service="dataflow_vuln_scan",
                input_ref=entry,
                retrying=retrying,
                auto_retrying=auto_retrying,
            )
            session.commit()
            active_payload = await self._active_downstream_payload(task, item, token)
            retry_strategy = None
            retry_strategy_status = None
            if retrying:
                retry_strategy, retry_strategy_status = self._classify_retry_downstream_strategy(
                    item,
                    active_payload=active_payload,
                )
                action_snapshot = await self._prepare_retry_child_for_reuse_or_recreate(
                    session,
                    task,
                    item,
                    strategy=retry_strategy,
                    observed_status=retry_strategy_status,
                    token=self._resolve_downstream_token(token),
                )
                self._store_retry_item_action(task, action_snapshot)
                session.commit()
                if retry_strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL:
                    active_payload = None
            taint_params = [str(value).strip() for value in (entry.get("taint_params") or []) if str(value).strip()]
            if not taint_params:
                taint_params = _entry_signature_params(entry)
            definition_found = bool(entry.get("is_definition_found", True))
            definition_kind = self._resolve_entry_definition_kind(entry)
            definition_file = str(entry.get("definition_file") or entry.get("file_name") or "").strip()
            definition_line = str(entry.get("definition_line") or entry.get("line_no") or "").strip()
            module_input_path = str(entry.get("module_input_path") or "").strip()
            source_root_path = str(entry.get("source_root_path") or "").strip()
            if not module_input_path or not source_root_path:
                recovered_entry = self._recover_entry_output_contract(session, task, entry)
                if recovered_entry:
                    entry = {**recovered_entry, **entry}
                    module_input_path = module_input_path or str(entry.get("module_input_path") or "").strip()
                    source_root_path = source_root_path or str(entry.get("source_root_path") or "").strip()
            if not definition_found:
                item.status = "failed"
                item.finished_at = _now()
                item.error_message = "未找到函数定义，无法执行数据流分析"
                self._persist_stage_item_result(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    result={**entry, "failed": True, "failure_reason": item.error_message},
                )
                session.commit()
                return {"status": "failed", "error": item.error_message, "item": entry}
            if definition_kind != "definition":
                item.status = "failed"
                item.finished_at = _now()
                item.error_message = "入口仅定位到声明，无法执行数据流分析"
                self._persist_stage_item_result(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    result={
                        **entry,
                        "failed": True,
                        "failure_reason": item.error_message,
                        "definition_kind": definition_kind,
                    },
                )
                session.commit()
                return {"status": "failed", "error": item.error_message, "item": entry}
            if not taint_params:
                item.status = "failed"
                item.finished_at = _now()
                item.error_message = "未识别到明确污点参数，无法执行数据流分析"
                self._persist_stage_item_result(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    result={**entry, "failed": True, "failure_reason": item.error_message},
                )
                session.commit()
                return {"status": "failed", "error": item.error_message, "item": entry}
            if not module_input_path:
                item.status = "failed"
                item.finished_at = _now()
                item.error_message = "未找到可用于数据流分析的模块输入目录"
                self._persist_stage_item_result(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    result={**entry, "failed": True, "failure_reason": item.error_message},
                )
                session.commit()
                return {"status": "failed", "error": item.error_message, "item": entry}
            if not source_root_path:
                item.status = "failed"
                item.finished_at = _now()
                item.error_message = "未找到可用于数据流分析的源码根目录"
                self._persist_stage_item_result(
                    task,
                    item,
                    stage_name=stage_run.stage_name,
                    result={**entry, "failed": True, "failure_reason": item.error_message},
                )
                session.commit()
                return {"status": "failed", "error": item.error_message, "item": entry}
            normalized_source_file = self._normalize_dfa_source_file(source_root_path, entry)
            prompt = f"分析文件 {definition_file or entry['file_name']} 中函数 {entry['function_name']} 的外部输入数据流"
            line_hint = ""
            if definition_line:
                line_hint = definition_line if definition_line.upper().startswith("L") else f"L{definition_line}"
            allow_rebind = not auto_retrying
            if active_payload is not None:
                item.status = self._map_downstream_status(str(active_payload.get("status") or "")) or "running"
                item.downstream_task_id = active_payload.get("task_id") or active_payload.get("id") or item.downstream_task_id
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, None),
                    success_statuses={"passed", "success"},
                    failure_statuses={"failed", "error", "cancelled", "invalid_input", "completed_limited"},
                    task=task,
                    item=item,
                )
            else:
                reusable_payload = None if retrying else await self._find_reusable_dataflow_payload(
                    task,
                    item,
                    allow_rebind=allow_rebind,
                )
                if reusable_payload is not None:
                    downstream_status = str(reusable_payload.get("status") or "").lower()
                    mapped_reusable_status = self._map_downstream_status(downstream_status)
                    await self._cleanup_duplicate_downstream_refs_for_item(
                        session,
                        task,
                        item=item,
                        token=token,
                        keep_task_ids={str(item.downstream_task_id or "").strip()},
                    )
                    if mapped_reusable_status in {"queued", "running"}:
                        item.status = mapped_reusable_status
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, None),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled", "invalid_input", "completed_limited"},
                            task=task,
                            item=item,
                        )
                    else:
                        session.commit()
                        payload = await self._downstream_fetch_item_payload(task, item, None)
                        downstream_status = str(payload.get("status") or "").lower()
                        if downstream_status in {"passed", "success"}:
                            status = "success"
                        elif downstream_status == "cancelled":
                            status = "cancelled"
                        elif downstream_status == "downstream_missing":
                            status = "downstream_missing"
                        else:
                            status = "failed"
                elif retrying and retry_strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE and self._has_retryable_downstream_task(item):
                    control = await self._downstream_control_existing_task(
                        session,
                        stage_name=stage_run.stage_name,
                        task=task,
                        item=item,
                        token=self._resolve_downstream_token(token),
                    )
                    outcome = str(control.get("outcome") or "")
                    if outcome == "accepted":
                        created = dict(control.get("payload") or {})
                        item.downstream_task_id = created.get("task_id") or item.downstream_task_id
                        item.status = "running"
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, None),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled", "invalid_input", "completed_limited"},
                            task=task,
                            item=item,
                        )
                    elif outcome == "already_running":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        item.status = self._map_downstream_status(str(payload.get("status") or "")) or "running"
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, None),
                            success_statuses={"passed", "success"},
                            failure_statuses={"failed", "error", "cancelled", "invalid_input", "completed_limited"},
                            task=task,
                            item=item,
                        )
                    elif outcome == "already_terminal":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        session.commit()
                        status = self._status_from_downstream_payload(payload, success_statuses={"passed", "success"})
                    elif outcome == "not_found":
                        item.status = "downstream_missing"
                        item.error_message = str(control.get("error_message") or "下游子任务不存在")
                        item.finished_at = _now()
                        session.commit()
                        return {"status": "downstream_missing", "error": item.error_message, "item": entry}
                    elif outcome == "transport_error":
                        return self._defer_item_after_downstream_transport_error(
                            session,
                            task,
                            item,
                            operation="dataflow_vuln_scan",
                            exc=UpstreamError(str(control.get("error_message") or "下游通信异常")),
                            response_item=entry,
                        )
                    else:
                        raise ValidationError(str(control.get("error_message") or "下游重试失败"))
                else:
                    created = await self._downstream_create_task(
                        session,
                        task,
                        item,
                        service="dataflow_vuln_scan",
                        token=self._resolve_downstream_token(token),
                        payload={
                            "task_name": f"{task.name}-{entry['function_name']}-scan",
                            "module_input_path": module_input_path,
                            "source_root_path": source_root_path,
                            "prompt_content": prompt,
                            "origin": _downstream_origin_payload(task, item),
                            "source_file": normalized_source_file,
                            "function_name": entry["function_name"],
                            "line_hint": line_hint,
                            "definition_kind": definition_kind,
                            "taint_params": taint_params,
                            "function_description": str(entry.get("function_description") or ""),
                            "function_description_source": str(entry.get("function_description_source") or ""),
                            "entry_reason": str(entry.get("entry_reason") or ""),
                            "entry_reason_source": str(entry.get("entry_reason_source") or ""),
                            "taint_details": [
                                dict(detail)
                                for detail in (entry.get("taint_details") or [])
                                if isinstance(detail, dict)
                            ],
                        },
                    )
                    old_downstream_task_id = await self._replace_active_child_binding(
                        session,
                        task,
                        item,
                        new_downstream_task_id=created.get("task_id") or created.get("id"),
                        token=self._resolve_downstream_token(token),
                        reason="dataflow_vuln_scan_child_create",
                    )
                    self._record_downstream_item_disposition(
                        session,
                        task,
                        item,
                        event_type="retry_item_new_child_created" if retrying else "downstream_child_created",
                        message="已创建新的下游子任务",
                        payload={
                            "stage_name": item.stage_name,
                            "item_id": item.id,
                            "item_key": item.item_key,
                            "old_downstream_task_id": old_downstream_task_id,
                            "new_downstream_task_id": item.downstream_task_id,
                            "strategy": retry_strategy if retrying else None,
                            "old_downstream_status": retry_strategy_status if retrying else None,
                        },
                    )
                    session.commit()
                    status, payload = await self._poll_until_terminal(
                        lambda: self._downstream_fetch_item_payload(task, item, None),
                        success_statuses={"passed", "success"},
                        failure_statuses={"failed", "error", "cancelled", "invalid_input", "completed_limited"},
                        task=task,
                        item=item,
                    )
            artifact_root = self._service_output_dir(
                task,
                item.downstream_service or stage_run.stage_name,
                entry["entry_key"],
                item.downstream_task_id,
            )
            materialized = self._materialize_stage_artifact(
                artifact_root,
                item.downstream_task_id,
                payload,
                db=session,
                task=task,
                item=item,
            )
            dataflow_dir = self._resolve_dataflow_directory(materialized)
            data_flow_file = self._find_first(
                materialized,
                [r"final_report\.md", r"dataflow-.*\.md", r".*result.*\.md", r"report\.md"],
            )
            downstream_status = str(payload.get("status") or "").lower()
            mapped_status = self._map_downstream_status(downstream_status) or (
                "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            )
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = (
                    payload.get("error")
                    or payload.get("error_message")
                    or payload.get("analysis_status")
                    or payload.get("completion_reason")
                )
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": entry}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": entry, "archive_blocked": True}
            archived_data_flow_file = self._find_first(
                archived_dir,
                [r"final_report\.md", r"dataflow-.*\.md", r".*result.*\.md", r"report\.md"],
            )
            effective_dataflow_dir = dataflow_dir or archived_dir
            result = self._build_dataflow_output_contract(
                entry,
                artifact_root=str(archived_dir),
                archive_root=str(archived_dir),
                module_input_path=module_input_path,
                source_root_path=source_root_path,
                source_dir=source_root_path,
                source_file=normalized_source_file,
                data_flow_file=str(archived_data_flow_file or data_flow_file or ""),
                dataflow_dir=str(effective_dataflow_dir),
            )
            result["downstream"] = payload
            self._persist_stage_item_result(
                task,
                item,
                stage_name=stage_run.stage_name,
                result=result,
            )
            item.output_ref = {**(item.output_ref or {}), "artifact_root": str(archived_dir), "archive_root": str(archived_dir)}
            if self._streaming_mode_enabled(task):
                self._trigger_vuln_items_from_dataflow_result(session, task, result, upstream_item=item)
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except UpstreamError as exc:
            session.rollback()
            if "item" in locals():
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="dataflow_vuln_scan",
                    exc=exc,
                    response_item=entry,
                )
            return {"status": "pending", "error": str(exc), "item": entry, "deferred_mode": "redispatch"}
        except Exception as exc:
            if "item" in locals() and self._is_retryable_downstream_transport_error(exc):
                session.rollback()
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="dataflow_vuln_scan",
                    exc=exc,
                    response_item=entry,
                )
            if "item" in locals() and self._is_recoverable_orchestration_error(exc):
                session.rollback()
                return self._defer_item_after_orchestration_error(
                    session,
                    task,
                    item,
                    operation="dataflow_vuln_scan",
                    exc=exc,
                    response_item=entry,
                )
            if "item" in locals():
                session.rollback()
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": entry}
        finally:
            session.close()

    async def _run_vuln_item(
        self: TaskManager,
        task,
        stage_run,
        dataflow_result,
        token,
        retrying: bool = False,
        auto_retrying: bool = False,
    ) -> dict[str, object]:
        from app.service import task_manager as task_manager_module

        get_session_factory = task_manager_module.get_session_factory
        ValidationError = task_manager_module.ValidationError
        UpstreamError = task_manager_module.UpstreamError
        StaleTaskExecution = task_manager_module.StaleTaskExecution
        normalize_stage_name = task_manager_module.normalize_stage_name
        _downstream_origin_payload = task_manager_module._downstream_origin_payload
        _now = task_manager_module._now
        RETRY_CHILD_ABNORMAL_STATUSES = task_manager_module.RETRY_CHILD_ABNORMAL_STATUSES
        RETRY_CHILD_STRATEGY_ADOPT_ACTIVE = task_manager_module.RETRY_CHILD_STRATEGY_ADOPT_ACTIVE
        RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL = (
            task_manager_module.RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL
        )

        session = get_session_factory()()
        try:
            dataflow_result = self._validate_dataflow_output_contract(dataflow_result)
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=dataflow_result["entry_key"],
                item_name=dataflow_result["function_name"],
                parent_key=dataflow_result["module_key"],
                downstream_service="dataflow_vuln_scan",
                input_ref=dataflow_result,
                retrying=retrying,
                auto_retrying=auto_retrying,
            )
            session.commit()
            active_payload = await self._active_downstream_payload(task, item, token)
            retry_strategy = None
            retry_strategy_status = None
            force_recreate_vuln_child = False
            original_item_status = self._map_downstream_status(str(item.status or "")) or (
                str(item.status or "").strip().lower() or None
            )
            if retrying:
                retry_strategy, retry_strategy_status = self._classify_retry_downstream_strategy(
                    item,
                    active_payload=active_payload,
                )
                if (
                    normalize_stage_name(stage_run.stage_name) == "dataflow_vuln_scan"
                    and active_payload is None
                    and str(item.downstream_task_id or "").strip()
                ):
                    normalized_current_status = (
                        original_item_status
                        or self._latest_observed_downstream_status(item)
                        or self._map_downstream_status(str(item.status or ""))
                        or (str(item.status or "").strip().lower() or None)
                    )
                    if normalized_current_status in RETRY_CHILD_ABNORMAL_STATUSES:
                        force_recreate_vuln_child = True
                else:
                    force_recreate_vuln_child = (
                        normalize_stage_name(stage_run.stage_name) == "dataflow_vuln_scan"
                        and retry_strategy == RETRY_CHILD_STRATEGY_RECREATE_FROM_ABNORMAL
                    )
                action_snapshot = await self._prepare_retry_child_for_reuse_or_recreate(
                    session,
                    task,
                    item,
                    strategy=retry_strategy,
                    observed_status=retry_strategy_status,
                    token=token,
                )
                self._store_retry_item_action(task, action_snapshot)
                session.commit()
                if force_recreate_vuln_child:
                    active_payload = None
                    created = await self._recreate_vuln_downstream_task(
                        session,
                        task,
                        item,
                        dataflow_result,
                        token,
                        control={
                            "outcome": "already_terminal",
                            "error_message": str(item.error_message or "") or None,
                        },
                    )
                    if created is not None:
                        old_downstream_task_id = await self._replace_active_child_binding(
                            session,
                            task,
                            item,
                            new_downstream_task_id=created.get("task_id") or created.get("id"),
                            token=token,
                            reason="dataflow_vuln_scan_recreate_child_create",
                        )
                        item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
                        self._mark_downstream_binding_created(item, message="下游已创建，状态待同步")
                        self._record_downstream_item_disposition(
                            session,
                            task,
                            item,
                            event_type="retry_item_new_child_created",
                            message="已创建新的下游子任务",
                            payload={
                                "stage_name": item.stage_name,
                                "item_id": item.id,
                                "item_key": item.item_key,
                                "old_downstream_task_id": old_downstream_task_id,
                                "new_downstream_task_id": item.downstream_task_id,
                                "strategy": retry_strategy,
                                "old_downstream_status": retry_strategy_status,
                            },
                        )
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success", "succeeded", "completed"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                        artifacts = await self._downstream_fetch_item_artifacts(item, token or "")
                        archive_payload = {
                            **payload,
                            "artifacts": artifacts,
                            "workspace_root": artifacts.get("workspace_root"),
                        }
                        mapped_status = (
                            "success"
                            if status == "success"
                            else "cancelled"
                            if status == "cancelled"
                            else "downstream_missing"
                            if status == "downstream_missing"
                            else "failed"
                        )
                        item.status = mapped_status
                        item.finished_at = _now()
                        archived_dir, archive_job = await self._queue_archive_and_wait(
                            session,
                            task,
                            item,
                            payload=archive_payload,
                            mapped_status=mapped_status,
                            before_status="running",
                        )
                        if mapped_status != "success":
                            item.error_message = payload.get("error") or payload.get("error_message")
                            session.commit()
                            return {"status": mapped_status, "error": item.error_message, "item": dataflow_result}
                        if archived_dir is None:
                            error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                            item.error_message = error
                            session.commit()
                            return {
                                "status": "archive_blocked",
                                "error": error,
                                "item": dataflow_result,
                                "archive_blocked": True,
                            }
                        result = {
                            **dataflow_result,
                            "workspace_root": artifacts.get("workspace_root"),
                            "artifact_files": artifacts.get("files", []),
                            "downstream": self._lightweight_downstream_payload(payload),
                            "artifacts": artifacts,
                        }
                        self._persist_stage_item_result(
                            task,
                            item,
                            stage_name=stage_run.stage_name,
                            result=result,
                        )
                        item.output_ref = {
                            **(item.output_ref or {}),
                            "workspace_root": artifacts.get("workspace_root"),
                            "archive_root": str(archived_dir),
                        }
                        session.commit()
                        return {
                            "status": item.status,
                            "item": result,
                            "error": payload.get("error") or payload.get("error_message"),
                        }
            if active_payload is not None:
                item.downstream_task_id = active_payload.get("task_id") or active_payload.get("id") or item.downstream_task_id
                item.status = self._map_downstream_status(str(active_payload.get("status") or "")) or "pending"
                self._mark_downstream_binding_created(item, message="下游已创建，状态待同步")
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                    success_statuses={"success", "succeeded", "completed"},
                    failure_statuses={"failed", "cancelled"},
                    task=task,
                    item=item,
                )
                created = None
            else:
                reusable_payload = None if retrying else await self._find_reusable_vuln_payload(task, item, token)
                if reusable_payload is not None:
                    downstream_status = str(reusable_payload.get("status") or "").lower()
                    mapped_reusable_status = self._map_downstream_status(downstream_status)
                    item.downstream_task_id = reusable_payload.get("task_id") or reusable_payload.get("id") or item.downstream_task_id
                    self._mark_downstream_binding_created(item, message="下游已创建，状态待同步")
                    await self._cleanup_duplicate_downstream_refs_for_item(
                        session,
                        task,
                        item,
                        token,
                        keep_task_ids={str(item.downstream_task_id or "").strip()},
                    )
                    if mapped_reusable_status in {"pending", "dispatching", "running"}:
                        item.status = mapped_reusable_status
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success", "succeeded", "completed"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                    else:
                        payload = dict(reusable_payload)
                        status = self._status_from_downstream_payload(
                            payload,
                            success_statuses={"success", "succeeded", "completed"},
                        )
                    created = None
                elif retrying and not force_recreate_vuln_child and retry_strategy == RETRY_CHILD_STRATEGY_ADOPT_ACTIVE and self._has_retryable_downstream_task(item):
                    control = await self._downstream_control_existing_task(
                        session,
                        stage_name=stage_run.stage_name,
                        task=task,
                        item=item,
                        token=token,
                    )
                    outcome = str(control.get("outcome") or "")
                    if outcome == "accepted":
                        created = dict(control.get("payload") or {})
                    elif outcome == "already_running":
                        payload = dict(control.get("payload") or {})
                        item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                        item.status = self._map_downstream_status(str(payload.get("status") or "")) or "dispatching"
                        session.commit()
                        status, payload = await self._poll_until_terminal(
                            lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                            success_statuses={"success", "succeeded", "completed"},
                            failure_statuses={"failed", "cancelled"},
                            task=task,
                            item=item,
                        )
                        created = None
                    elif outcome == "already_terminal":
                        if normalize_stage_name(stage_run.stage_name) == "dataflow_vuln_scan" and self._is_vuln_retry_recreate_outcome(control):
                            created = await self._recreate_vuln_downstream_task(
                                session,
                                task,
                                item,
                                dataflow_result,
                                token,
                                control=control,
                            )
                        else:
                            payload = dict(control.get("payload") or {})
                            item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                            session.commit()
                            status = self._status_from_downstream_payload(
                                payload,
                                success_statuses={"success", "succeeded", "completed"},
                            )
                            created = None
                    elif normalize_stage_name(stage_run.stage_name) == "dataflow_vuln_scan" and self._is_vuln_retry_recreate_outcome(control):
                        created = await self._recreate_vuln_downstream_task(
                            session,
                            task,
                            item,
                            dataflow_result,
                            token,
                            control=control,
                        )
                    elif outcome == "transport_error":
                        active_payload = await self._active_downstream_payload(task, item, token)
                        if active_payload is not None:
                            payload = dict(active_payload)
                            item.downstream_task_id = payload.get("task_id") or payload.get("id") or item.downstream_task_id
                            item.status = self._map_downstream_status(str(payload.get("status") or "")) or "dispatching"
                            session.commit()
                            status, payload = await self._poll_until_terminal(
                                lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                                success_statuses={"success", "succeeded", "completed"},
                                failure_statuses={"failed", "cancelled"},
                                task=task,
                                item=item,
                            )
                            created = None
                        else:
                            return self._defer_item_after_downstream_transport_error(
                                session,
                                task,
                                item,
                                operation="dataflow_vuln_scan",
                                exc=UpstreamError(str(control.get("error_message") or "下游通信异常")),
                                response_item=dataflow_result,
                            )
                    elif outcome == "not_found":
                        item.status = "downstream_missing"
                        item.error_message = str(control.get("error_message") or "下游子任务不存在")
                        item.finished_at = _now()
                        session.commit()
                        return {"status": "downstream_missing", "error": item.error_message, "item": dataflow_result}
                    else:
                        raise ValidationError(str(control.get("error_message") or "下游重试失败"))
                else:
                    self._mark_downstream_binding_creating(item)
                    session.commit()
                    dataflow_input_dir = self._resolve_vuln_scan_dataflow_input_dir(dataflow_result)
                    source_dir = str(dataflow_result.get("source_root_path") or dataflow_result.get("source_dir") or "")
                    if not dataflow_input_dir:
                        raise ValidationError("数据流漏洞挖掘输入缺少 data_flow_root/dataflow_dir")
                    if not source_dir:
                        raise ValidationError("数据流漏洞挖掘输入缺少 source_dir")
                    created = await self._downstream_create_task(
                        session,
                        task,
                        item,
                        service="dataflow_vuln_scan",
                        token=token,
                        payload={
                            "title": f"{task.name}-{dataflow_result['function_name']}-scan",
                            "data_flow_path": dataflow_input_dir,
                            "source_dir": source_dir,
                            "origin": _downstream_origin_payload(task, item),
                        },
                    )
            if created is not None:
                old_downstream_task_id = await self._replace_active_child_binding(
                    session,
                    task,
                    item,
                    new_downstream_task_id=created.get("task_id") or created.get("id"),
                    token=token,
                    reason=f"{stage_run.stage_name}_child_create",
                )
                item.status = self._map_downstream_status(str(created.get("status") or "")) or "pending"
                self._mark_downstream_binding_created(item, message="下游已创建，状态待同步")
                self._record_downstream_item_disposition(
                    session,
                    task,
                    item,
                    event_type="retry_item_new_child_created" if retrying else "downstream_child_created",
                    message="已创建新的下游子任务",
                    payload={
                        "stage_name": item.stage_name,
                        "item_id": item.id,
                        "item_key": item.item_key,
                        "old_downstream_task_id": old_downstream_task_id,
                        "new_downstream_task_id": item.downstream_task_id,
                        "strategy": retry_strategy if retrying else None,
                        "old_downstream_status": retry_strategy_status if retrying else None,
                    },
                )
                session.commit()
                status, payload = await self._poll_until_terminal(
                    lambda: self._downstream_fetch_item_payload(task, item, token or ""),
                    success_statuses={"success", "succeeded", "completed"},
                    failure_statuses={"failed", "cancelled"},
                    task=task,
                    item=item,
                )
            artifacts = await self._downstream_fetch_item_artifacts(item, token or "")
            archive_payload = {**payload, "artifacts": artifacts, "workspace_root": artifacts.get("workspace_root")}
            mapped_status = (
                "success"
                if status == "success"
                else "cancelled"
                if status == "cancelled"
                else "downstream_missing"
                if status == "downstream_missing"
                else "failed"
            )
            item.status = mapped_status
            item.finished_at = _now()
            archived_dir, archive_job = await self._queue_archive_and_wait(
                session,
                task,
                item,
                payload=archive_payload,
                mapped_status=mapped_status,
                before_status="running",
            )
            if mapped_status != "success":
                item.error_message = payload.get("error") or payload.get("error_message")
                session.commit()
                return {"status": mapped_status, "error": item.error_message, "item": dataflow_result}
            if archived_dir is None:
                error = archive_job.error_message if archive_job is not None else "总任务产物归档失败"
                item.error_message = error
                session.commit()
                return {"status": "archive_blocked", "error": error, "item": dataflow_result, "archive_blocked": True}
            result = {
                **dataflow_result,
                "workspace_root": artifacts.get("workspace_root"),
                "artifact_files": artifacts.get("files", []),
                "downstream": self._lightweight_downstream_payload(payload),
                "artifacts": artifacts,
            }
            self._persist_stage_item_result(
                task,
                item,
                stage_name=stage_run.stage_name,
                result=result,
            )
            item.output_ref = {
                **(item.output_ref or {}),
                "workspace_root": artifacts.get("workspace_root"),
                "archive_root": str(archived_dir),
            }
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except StaleTaskExecution:
            session.rollback()
            raise
        except UpstreamError as exc:
            session.rollback()
            if "item" in locals():
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="dataflow_vuln_scan",
                    exc=exc,
                    response_item=dataflow_result,
                )
            return {"status": "pending", "error": str(exc), "item": dataflow_result, "deferred_mode": "redispatch"}
        except Exception as exc:
            if "item" in locals() and self._is_retryable_downstream_transport_error(exc):
                session.rollback()
                return self._defer_item_after_downstream_transport_error(
                    session,
                    task,
                    item,
                    operation="dataflow_vuln_scan",
                    exc=exc,
                    response_item=dataflow_result,
                )
            if "item" in locals() and self._is_recoverable_orchestration_error(exc):
                session.rollback()
                return self._defer_item_after_orchestration_error(
                    session,
                    task,
                    item,
                    operation="dataflow_vuln_scan",
                    exc=exc,
                    response_item=dataflow_result,
                )
            if "item" in locals():
                session.rollback()
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": dataflow_result}
        finally:
            session.close()
