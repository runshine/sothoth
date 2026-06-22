from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError
from sqlalchemy.orm import Session

from app.observability import (
    observe_archive_action,
    observe_archive_reclaim,
    observe_scheduler_loop,
    observe_task_heartbeat_loop_duration,
)

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskLifecycleServiceMixin:
    def _should_defer_stale_operation_release(self: TaskManager, db: Session, task, operation) -> bool:
        from app.service import task_manager as task_manager_module

        if operation is None:
            return False
        if str(getattr(operation, "operation_type", "") or "").strip() != task_manager_module.TASK_ACTION_CANCEL:
            return False
        if str(getattr(task, "current_operation_id", "") or "").strip() != str(getattr(operation, "id", "") or "").strip():
            return False
        if not self._task_has_supported_control_operation_runtime(db, task, active_operation=operation):
            return False
        return True

    def _requeue_stale_operations(self: TaskManager, db: Session) -> bool:
        from app.service import task_manager as task_manager_module

        changed = False
        active_operations = (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(
                task_manager_module.BinarySecurityTaskOperation.status.in_(
                    list(task_manager_module.TASK_OPERATION_ACTIVE_STATUSES)
                )
            )
            .all()
        )
        for operation in active_operations:
            task_id = str(getattr(operation, "task_id", "") or "").strip()
            if not task_id:
                continue
            task = (
                db.query(task_manager_module.BinarySecurityTask)
                .filter(task_manager_module.BinarySecurityTask.id == task_id)
                .first()
            )
            if task is None:
                continue
            if self._reconcile_stale_task_operation(db, task, operation):
                changed = True
                continue
            if self._should_defer_stale_operation_release(db, task, operation):
                self._record_event(
                    db,
                    task,
                    "task_owner_release_deferred_for_active_cancel_finalize",
                    "检测到取消收尾窗口仍由当前 control operation 正常推进，本次不释放 owner",
                    level="info",
                    stage_name=task.current_stage,
                    payload={
                        "reason_code": "cancel_finalize_window_runtime_supported",
                        "current_operation_id": str(getattr(operation, "id", "") or "").strip() or None,
                        "operation_runtime": self._operation_runtime_snapshot(operation),
                    },
                )
                continue
            if self._task_row_owner_is_runtime_supported(db, task, active_operation=operation):
                continue
            released = self._release_unsupported_task_row_owner(
                db,
                task,
                active_operation=operation,
                reason="stale_active_operation_without_supported_runtime",
            )
            if not released:
                continue
            self._enqueue_task(task.id)
            changed = True
        if changed:
            db.flush()
        return changed

    async def _seed_work_queues(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            queue = task_manager_module.get_task_queue()
            task_ids: list[str] = []
            task_count = 0
            operation_task_count = 0
            for task in db.query(task_manager_module.BinarySecurityTask).all():
                status = str(getattr(task, "status", "") or "").strip().lower()
                task_id = str(getattr(task, "id", "") or "").strip()
                if not task_id:
                    continue
                if status in {"pending", "dispatching", "running"}:
                    task_count += 1
                    task_ids.append(task_id)
            for operation in db.query(task_manager_module.BinarySecurityTaskOperation).all():
                operation_task_id = str(getattr(operation, "task_id", "") or "").strip()
                status = str(getattr(operation, "status", "") or "").strip().lower()
                if not operation_task_id:
                    continue
                if status in {"pending", "queued", "accepted", "running"}:
                    operation_task_count += 1
                    task_ids.append(operation_task_id)
            unique_task_ids = list(dict.fromkeys(task_ids))
            task_manager_module.logger.info(
                "binary-security seed_work_queues starting: db_task_candidates=%s operation_task_candidates=%s unique_task_ids=%s",
                task_count,
                operation_task_count,
                len(unique_task_ids),
            )
            try:
                for task_id in unique_task_ids:
                    await queue.push_task(task_id, context="startup_seed")
            except Exception:
                task_manager_module.logger.exception(
                    "binary-security seed_work_queues_failed: unique_task_ids=%s first_failed_task_id=%s",
                    len(unique_task_ids),
                    task_id,
                )
                raise
            task_manager_module.logger.info(
                "binary-security seed_work_queues completed: unique_task_ids=%s",
                len(unique_task_ids),
            )
        finally:
            with suppress(Exception):
                db.close()

    def _task_operation_lock_expires_at(
        self: TaskManager,
        *,
        now_value: datetime | None = None,
        ttl_seconds: int = 60,
    ) -> datetime:
        base = now_value or task_shared._now()
        effective_ttl = self._task_operation_lock_ttl_seconds() if int(ttl_seconds) == 60 else max(30, int(ttl_seconds))
        return base + timedelta(seconds=effective_ttl)

    def _task_operation_lock_ttl_seconds(self: TaskManager) -> int:
        return max(30, int(getattr(self.cfg.scheduler, "task_operation_lock_ttl_seconds", 60) or 60))

    def _task_operation_lock_heartbeat_interval_seconds(self: TaskManager) -> int:
        configured = int(getattr(self.cfg.scheduler, "task_operation_lock_heartbeat_interval_seconds", 15) or 15)
        return max(5, min(configured, max(5, int(self._task_operation_lock_ttl_seconds() / 2))))

    def _operation_step_batch_size(self: TaskManager) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "operation_step_batch_size", 10) or 10))

    def _loop_stale_threshold_seconds(self: TaskManager, loop_name: str) -> int:
        configured = int(getattr(self.cfg.scheduler, "worker_ready_loop_stale_seconds", 90) or 90)
        interval_seconds = {
            "task_dispatch": max(1, int(getattr(self.cfg.queue, "block_timeout_seconds", 5) or 5)),
            "archive_dispatch": max(1, int(getattr(self.cfg.scheduler, "poll_interval_seconds", 5) or 5)),
            "stage_item_dispatch": max(1, int(getattr(self.cfg.scheduler, "stage_poll_interval_seconds", 5) or 5)),
            "downstream_reconcile": max(1, int(getattr(self.cfg.scheduler, "downstream_reconcile_interval_seconds", 30) or 30)),
            "stage_item_sync_reconcile": self._stage_item_sync_reconcile_interval_seconds(),
            "archive_runtime_reconcile": self._archive_runtime_reconcile_interval_seconds(),
            "state_repair_reconcile": self._state_repair_reconcile_interval_seconds(),
            "readless_reconcile": max(1, int(getattr(self.cfg.scheduler, "readless_reconcile_interval_seconds", 300) or 300)),
            "state_reducer": max(1, int(getattr(self.cfg.scheduler, "poll_interval_seconds", 5) or 5)),
            "reducer_metrics_snapshot": max(5, int(getattr(self.cfg.scheduler, "poll_interval_seconds", 5) or 5)),
            "task_heartbeat": max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 15) or 15)),
        }.get(loop_name, configured)
        return max(configured, interval_seconds * 2 + 15)

    def _mark_loop_heartbeat(self: TaskManager, loop_name: str, *, now_value: datetime | None = None) -> None:
        self._loop_heartbeats[str(loop_name)] = now_value or task_shared._now()

    def _recover_loop_db_error(self: TaskManager, loop_name: str, db: Session | None, exc: Exception) -> None:
        from app.service import task_manager as task_manager_module

        if db is not None:
            with suppress(Exception):
                db.rollback()
            with suppress(Exception):
                db.close()
        if isinstance(exc, (OperationalError, SATimeoutError)):
            with suppress(Exception):
                task_manager_module.get_engine().dispose()
            task_manager_module.logger.warning("binary-security %s loop reset database engine after db error: %s", loop_name, exc)

    def _loop_runtime_detail(self: TaskManager, loop_name: str, task: asyncio.Task | None) -> dict[str, Any]:
        task_running = bool(task and not task.done())
        heartbeat_at = self._loop_heartbeats.get(loop_name)
        heartbeat_age_seconds = task_shared._elapsed_seconds_since(heartbeat_at)
        stale_after_seconds = self._loop_stale_threshold_seconds(loop_name)
        heartbeat_alive = bool(
            heartbeat_at
            and heartbeat_age_seconds is not None
            and heartbeat_age_seconds <= stale_after_seconds
        )
        alive = bool(task_running or heartbeat_alive)
        stale = bool(alive and heartbeat_at and heartbeat_age_seconds is not None and heartbeat_age_seconds > stale_after_seconds)
        return {
            "alive": alive,
            "task_running": task_running,
            "heartbeat_alive": heartbeat_alive,
            "heartbeat_at": task_shared._isoformat_or_none(heartbeat_at),
            "heartbeat_age_seconds": None if heartbeat_age_seconds is None else round(float(heartbeat_age_seconds), 3),
            "stale_after_seconds": stale_after_seconds,
            "stale": stale,
        }

    def runtime_status(self: TaskManager) -> dict[str, object]:
        loop_details = {
            "task_dispatch": self._loop_runtime_detail("task_dispatch", self._loop_task),
            "archive_dispatch": self._loop_runtime_detail("archive_dispatch", self._archive_loop_task),
            "stage_item_dispatch": self._loop_runtime_detail("stage_item_dispatch", self._stage_item_loop_task),
            "state_reducer": self._loop_runtime_detail("state_reducer", self._state_reducer_loop_task),
            "reducer_metrics_snapshot": self._loop_runtime_detail("reducer_metrics_snapshot", self._reducer_metrics_snapshot_loop_task),
            "compat_heartbeat_fallback": self._loop_runtime_detail("task_heartbeat", self._task_heartbeat_loop_task),
        }
        return {
            "running": self._running,
            "loops": {loop_name: bool(detail.get("alive")) for loop_name, detail in loop_details.items() if loop_name != "compat_heartbeat_fallback"},
            "loop_details": loop_details,
            "workers": {
                "task_workers": len([handle for handle in self._workers.values() if not handle.done()]),
                "task_heartbeat_workers": len([
                    handle for handle in self._workers.values()
                    if handle.heartbeat_task is not None and not handle.heartbeat_task.done()
                ]),
                "operation_workers": 0,
                "stage_item_workers": len([task for task in self._stage_item_workers.values() if not task.done()]),
                "archive_workers": len([task for task in self._archive_workers if not task.done()]),
            },
            "tail_reconcile_active": bool(self._is_reducer_role() and self._runtime_lease_capable()),
            "lease_auditor_active": bool(self._is_reducer_role() and self._runtime_lease_capable()),
        }

    def _collect_runtime_metrics_snapshot_sync(self: TaskManager) -> dict[str, int]:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            service_config = self._load_service_config(db)
            pending_tasks = int(
                db.query(task_manager_module.func.count(task_manager_module.BinarySecurityTask.id))
                .filter(task_manager_module.BinarySecurityTask.status == "pending")
                .scalar()
                or 0
            )
            running_tasks = int(
                db.query(task_manager_module.func.count(task_manager_module.BinarySecurityTask.id))
                .filter(task_manager_module.BinarySecurityTask.status.in_(["dispatching", "running"]))
                .scalar()
                or 0
            )
            archive_pending_jobs = int(
                db.query(task_manager_module.func.count(task_manager_module.BinarySecurityArchiveJob.id))
                .filter(task_manager_module.BinarySecurityArchiveJob.archive_status == "pending")
                .scalar()
                or 0
            )
            archive_running_jobs = int(
                db.query(task_manager_module.func.count(task_manager_module.BinarySecurityArchiveJob.id))
                .filter(task_manager_module.BinarySecurityArchiveJob.archive_status == "running")
                .scalar()
                or 0
            )
            archive_applying_jobs = int(
                db.query(task_manager_module.func.count(task_manager_module.BinarySecurityArchiveJob.id))
                .filter(task_manager_module.BinarySecurityArchiveJob.archive_status == "applying")
                .scalar()
                or 0
            )
            leased_tasks = int(
                db.query(task_manager_module.func.count(task_manager_module.BinarySecurityTaskRuntimeLease.task_id))
                .scalar()
                or 0
            )
        finally:
            with suppress(Exception):
                db.close()
        return {
            "pending_tasks": pending_tasks,
            "running_tasks": running_tasks,
            "archive_pending_jobs": archive_pending_jobs,
            "archive_running_jobs": archive_running_jobs,
            "archive_applying_jobs": archive_applying_jobs,
            "leased_tasks": leased_tasks,
            "task_capacity": int(getattr(service_config, "max_concurrent_tasks", 0) or 0),
        }

    def _observe_worker_counts(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        task_manager_module.observe_worker_counts(
            task_workers=len([task for task in self._workers.values() if not task.done()]),
            operation_workers=len([task for task in self._operation_workers.values() if not task.done()]),
            archive_workers=len([task for task in self._archive_workers if not task.done()]),
            task_heartbeat_workers=len([
                handle for handle in self._workers.values()
                if handle.heartbeat_task is not None and not handle.heartbeat_task.done()
            ]),
        )

    async def _observe_runtime_metrics(self: TaskManager, db: Session | None, *, reconcile_candidates: int = 0) -> None:
        from app.service import task_manager as task_manager_module

        del db
        queue_snapshot = await task_manager_module.get_task_queue().snapshot()
        runtime_snapshot = await asyncio.to_thread(self._collect_runtime_metrics_snapshot_sync)
        task_manager_module.observe_queue_depths(
            redis_task_queue=int(dict(queue_snapshot.get("task_queue") or {}).get("length") or 0),
            task_queue_oldest_age_seconds=dict(queue_snapshot.get("task_queue") or {}).get("oldest_age_seconds"),
            pending_tasks=int(runtime_snapshot.get("pending_tasks") or 0),
            running_tasks=int(runtime_snapshot.get("running_tasks") or 0),
            archive_pending_jobs=int(runtime_snapshot.get("archive_pending_jobs") or 0),
            archive_running_jobs=int(runtime_snapshot.get("archive_running_jobs") or 0),
            archive_applying_jobs=int(runtime_snapshot.get("archive_applying_jobs") or 0),
            leased_tasks=int(runtime_snapshot.get("leased_tasks") or 0),
            reconcile_candidates=max(0, int(reconcile_candidates or 0)),
        )
        task_manager_module.observe_slot_usage(
            task_capacity=int(runtime_snapshot.get("task_capacity") or 0),
            task_active=len([handle for handle in self._workers.values() if not handle.done()]),
            action_active=0,
            action_capacity=max(1, int(getattr(self.cfg.scheduler, "downstream_action_concurrency", 1) or 1)),
        )

    async def _reconcile_downstream_task_ref(self: TaskManager, ref: dict[str, str], token: str | None) -> None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            task = self._task_or_404(db, ref["project_id"], ref["task_id"])
            self._merge_task_runtime_signal(
                task,
                "pending_downstream_sync",
                source="lease_auditor_signal",
                reason="downstream_reconcile_requested",
                force=False,
                extra={"requested_by_token_present": bool(str(token or "").strip())},
            )
            db.commit()
            self._enqueue_task(task.id)
        finally:
            db.close()

    def _list_tasks_with_deferred_cleanup(self: TaskManager, db: Session) -> list[dict[str, str]]:
        from app.service import task_manager as task_manager_module

        now_value = task_shared._now()
        refs: list[dict[str, str]] = []
        for task in db.query(task_manager_module.BinarySecurityTask).all():
            snapshot = dict(getattr(task, "cleanup_snapshot", None) or {})
            deferred_refs = [
                dict(row)
                for row in list(snapshot.get("deferred_downstream_refs") or [])
                if isinstance(row, dict)
            ]
            if not deferred_refs:
                continue
            if not bool(snapshot.get("cleanup_partial_failed")) and str(snapshot.get("deferred_cleanup_status") or "").strip() == "succeeded":
                continue
            next_retry_at = task_shared._parse_iso_datetime(snapshot.get("deferred_cleanup_next_retry_at"))
            if next_retry_at is not None and next_retry_at > now_value:
                continue
            task_id = str(getattr(task, "id", "") or "").strip()
            project_id = str(getattr(task, "project_id", "") or "").strip()
            if not task_id or not project_id:
                continue
            refs.append({"project_id": project_id, "task_id": task_id})
        return refs

    async def _reconcile_deferred_cleanup_task_ref(self: TaskManager, ref: dict[str, str], token: str | None) -> None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            task = (
                db.query(task_manager_module.BinarySecurityTask)
                .filter(
                    task_manager_module.BinarySecurityTask.project_id == ref["project_id"],
                    task_manager_module.BinarySecurityTask.id == ref["task_id"],
                )
                .first()
            )
            if task is None:
                return
            snapshot = dict(task.cleanup_snapshot or {})
            deferred_refs = [
                dict(row)
                for row in list(snapshot.get("deferred_downstream_refs") or [])
                if isinstance(row, dict)
            ]
            if not deferred_refs:
                return
            self._merge_task_runtime_signal(
                task,
                "pending_cleanup_retry",
                source="lease_auditor_signal",
                reason="legacy_delete_cleanup_retry_requested",
                extra={
                    "deferred_ref_count": len(deferred_refs),
                    "requested_by_token_present": bool(str(token or "").strip()),
                },
            )
            self._record_event(
                db,
                task,
                "task_delete_cleanup_retry_deferred",
                "检测到历史删除遗留引用，已通知任务 owner 串行恢复清理",
                level="warning",
                payload={
                    "task_id": task.id,
                    "project_id": task.project_id,
                    "remaining_deferred_count": len(deferred_refs),
                    "source": "lease_auditor_signal",
                    "legacy_recovery": True,
                },
            )
            db.commit()
            self._enqueue_task(task.id)
        finally:
            db.close()

    async def _reconcile_stale_stage_item_sync_ref(self: TaskManager, ref: dict[str, Any], token: str | None) -> None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            task = self._task_or_404(db, ref["project_id"], ref["task_id"])
            self._record_event(
                db,
                task,
                "downstream_sync_reconcile_triggered",
                "检测到阶段下游同步陈旧，已通知任务 owner 串行重同步",
                stage_name=ref.get("stage_name"),
                payload={
                    "task_id": ref["task_id"],
                    "stage_name": ref.get("stage_name"),
                    "item_ids": list(ref.get("item_ids") or []),
                    "resolution_reason": "stale_sync_attempt",
                    "source": "lease_auditor_signal",
                },
            )
            self._merge_task_runtime_signal(
                task,
                "pending_downstream_sync",
                source="lease_auditor_signal",
                reason="stale_sync_attempt",
                stage_name=str(ref.get("stage_name") or "").strip() or None,
                item_ids=[str(item_id).strip() for item_id in list(ref.get("item_ids") or []) if str(item_id).strip()],
                force=True,
            )
            db.commit()
            self._enqueue_task(task.id)
        finally:
            db.close()

    def _list_tasks_with_stale_stage_item_syncs(self: TaskManager, db: Session) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        now_value = task_shared._now()
        stale_threshold_seconds = self._stage_item_sync_stale_seconds()
        batch_size = max(1, int(getattr(self.cfg.scheduler, "stage_item_sync_reconcile_batch_size", 100) or 100))
        refs: list[dict[str, Any]] = []
        for task in db.query(task_manager_module.BinarySecurityTask).all():
            task_id = str(getattr(task, "id", "") or "").strip()
            project_id = str(getattr(task, "project_id", "") or "").strip()
            if not task_id or not project_id:
                continue
            if self._task_runtime_phase(task) == task_manager_module.TASK_RUNTIME_PHASE_TAIL_RECONCILIATION and not self._is_reducer_role():
                continue
            items = self._task_reconcile_candidate_items(
                db,
                task,
                force=False,
                include_failed_terminal_items=True,
            )
            if not items:
                continue
            stage_item_ids: dict[str, list[str]] = {}
            for item in items:
                item_id = str(getattr(item, "id", "") or "").strip()
                stage_name = str(getattr(item, "stage_name", "") or "").strip()
                if not item_id or not stage_name:
                    continue
                stale = False
                if self._item_needs_downstream_binding_reconcile(item) or self._item_missing_recorded_downstream_status(item):
                    stale = True
                else:
                    next_retry_at = self._stage_item_next_sync_retry_at_value(item)
                    if next_retry_at is not None and next_retry_at <= now_value:
                        stale = True
                    else:
                        attempt_at = self._stage_item_sync_attempt_at_value(item)
                        if attempt_at is None:
                            stale = True
                        else:
                            stale = (now_value - attempt_at).total_seconds() >= stale_threshold_seconds
                if not stale:
                    continue
                stage_item_ids.setdefault(stage_name, []).append(item_id)
            for stage_name, item_ids in stage_item_ids.items():
                refs.append(
                    {
                        "project_id": project_id,
                        "task_id": task_id,
                        "stage_name": stage_name,
                        "item_ids": item_ids,
                    }
                )
                if len(refs) >= batch_size:
                    return refs
        return refs

    async def _task_heartbeat_loop(self: TaskManager) -> None:
        interval_seconds = max(5, int(getattr(self.cfg.scheduler, "heartbeat_update_interval_seconds", 0) or 15))
        while self._running:
            started = time.perf_counter()
            try:
                self._mark_loop_heartbeat("task_heartbeat")
                await asyncio.to_thread(self._refresh_task_heartbeats_once)
            except asyncio.CancelledError:
                raise
            except Exception:
                from app.service import task_manager as task_manager_module

                task_manager_module.logger.exception("binary-security task heartbeat loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                self._mark_loop_heartbeat("task_heartbeat")
                observe_task_heartbeat_loop_duration(time.perf_counter() - started)
            await asyncio.sleep(interval_seconds)

    async def _downstream_reconcile_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        interval_seconds = max(
            5,
            int(
                getattr(self.cfg.scheduler, "downstream_reconcile_interval_seconds", 30)
                or self.cfg.scheduler.stage_poll_interval_seconds
                or self.cfg.scheduler.poll_interval_seconds
                or 30
            ),
        )
        while self._running:
            db = task_manager_module.get_session_factory()()
            try:
                with observe_scheduler_loop("downstream_reconcile"):
                    self._mark_loop_heartbeat("downstream_reconcile")
                    task_refs = await asyncio.to_thread(self._list_tasks_needing_downstream_sync, db)
                    token = self._service_token()
                    results = await self._run_with_limits(
                        task_refs,
                        lambda ref: self._reconcile_downstream_task_ref(ref, token),
                        concurrency=max(1, min(int(self.cfg.scheduler.downstream_sync_concurrency or 1), 8)),
                        timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
                    )
                    for ref, _, exc in results:
                        if exc is None:
                            continue
                        try:
                            task = self._task_or_404(db, ref["project_id"], ref["task_id"])
                            self._record_event(
                                db,
                                task,
                                "downstream_status_reconcile_failed",
                                f"后台同步下游状态失败: {exc}",
                                level="warning",
                                payload={
                                    "task_id": ref["task_id"],
                                    "project_id": ref["project_id"],
                                    "error": str(exc),
                                    "error_type": exc.__class__.__name__,
                                    "downstream_sync_batch_size": int(
                                        getattr(self.cfg.scheduler, "downstream_sync_batch_size", 50) or 50
                                    ),
                                },
                            )
                            db.commit()
                        except Exception:
                            db.rollback()
                    deferred_cleanup_refs = await asyncio.to_thread(self._list_tasks_with_deferred_cleanup, db)
                    deferred_results = await self._run_with_limits(
                        deferred_cleanup_refs,
                        lambda ref: self._reconcile_deferred_cleanup_task_ref(ref, token),
                        concurrency=max(1, min(int(self.cfg.scheduler.downstream_sync_concurrency or 1), 8)),
                        timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
                    )
                    for ref, _, exc in deferred_results:
                        if exc is None:
                            continue
                        try:
                            task = self._task_or_404(db, ref["project_id"], ref["task_id"])
                            self._record_event(
                                db,
                                task,
                                "task_delete_cleanup_reconcile_failed",
                                f"历史删除遗留恢复失败: {exc}",
                                level="warning",
                                payload={
                                    "task_id": ref["task_id"],
                                    "project_id": ref["project_id"],
                                    "error": str(exc),
                                    "error_type": exc.__class__.__name__,
                                },
                            )
                            db.commit()
                        except Exception:
                            db.rollback()
                    await self._observe_runtime_metrics(db, reconcile_candidates=len(task_refs))
                    self._mark_loop_heartbeat("downstream_reconcile")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._recover_loop_db_error("downstream_reconcile", db, exc)
                task_manager_module.logger.exception("binary-security downstream reconcile loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                db.close()
            await asyncio.sleep(interval_seconds)

    async def _stage_item_sync_reconcile_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        interval_seconds = self._stage_item_sync_reconcile_interval_seconds()
        while self._running:
            db = task_manager_module.get_session_factory()()
            try:
                with observe_scheduler_loop("stage_item_sync_reconcile"):
                    self._mark_loop_heartbeat("stage_item_sync_reconcile")
                    refs = await asyncio.to_thread(self._list_tasks_with_stale_stage_item_syncs, db)
                    token = self._service_token()
                    results = await self._run_with_limits(
                        refs,
                        lambda ref: self._reconcile_stale_stage_item_sync_ref(ref, token),
                        concurrency=max(1, min(int(self.cfg.scheduler.downstream_sync_concurrency or 1), 8)),
                        timeout_seconds=self.cfg.scheduler.downstream_request_timeout_seconds,
                    )
                    for ref, _, exc in results:
                        if exc is None:
                            continue
                        with suppress(Exception):
                            task = self._task_or_404(db, ref["project_id"], ref["task_id"])
                            self._record_event(
                                db,
                                task,
                                "downstream_sync_reconcile_failed",
                                f"后台 stale sync 收敛失败: {exc}",
                                level="warning",
                                stage_name=ref.get("stage_name"),
                                payload={
                                    "task_id": ref["task_id"],
                                    "project_id": ref["project_id"],
                                    "stage_name": ref.get("stage_name"),
                                    "item_ids": list(ref.get("item_ids") or []),
                                    "error": str(exc),
                                    "error_type": exc.__class__.__name__,
                                },
                            )
                            db.commit()
                    self._mark_loop_heartbeat("stage_item_sync_reconcile")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._recover_loop_db_error("stage_item_sync_reconcile", db, exc)
                task_manager_module.logger.exception("binary-security stage item sync reconcile loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                db.close()
            await asyncio.sleep(interval_seconds)

    async def _archive_runtime_reconcile_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        interval_seconds = self._archive_runtime_reconcile_interval_seconds()
        while self._running:
            try:
                self._mark_loop_heartbeat("archive_runtime_reconcile")
                # Archive runtime repair is now owner-driven. The passive loop only
                # advertises liveness while real rebuild/apply work is consumed by
                # the owning task worker via runtime signals.
                self._mark_loop_heartbeat("archive_runtime_reconcile")
            except asyncio.CancelledError:
                raise
            except Exception:
                task_manager_module.logger.exception("binary-security archive runtime reconcile loop crashed and recovered")
                await asyncio.sleep(1)
            await asyncio.sleep(interval_seconds)

    async def _state_repair_reconcile_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        interval_seconds = self._state_repair_reconcile_interval_seconds()
        while self._running:
            try:
                self._mark_loop_heartbeat("state_repair_reconcile")
                db = task_manager_module.get_session_factory()()
                try:
                    await asyncio.to_thread(self._reconcile_orphan_task_workspaces_once, db)
                finally:
                    db.close()
                self._mark_loop_heartbeat("state_repair_reconcile")
            except asyncio.CancelledError:
                raise
            except Exception:
                task_manager_module.logger.exception("binary-security state repair reconcile loop crashed and recovered")
                await asyncio.sleep(1)
            await asyncio.sleep(interval_seconds)

    async def _archive_dispatch_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        while self._running:
            try:
                with observe_scheduler_loop("archive_dispatch"):
                    self._mark_loop_heartbeat("archive_dispatch")
                    await asyncio.to_thread(self._reclaim_stale_archive_jobs)
                    await self._schedule_archive_workers()
                    self._mark_loop_heartbeat("archive_dispatch")
            except asyncio.CancelledError:
                raise
            except Exception:
                task_manager_module.logger.exception("binary-security archive dispatch loop crashed and recovered")
                await asyncio.sleep(1)
            await asyncio.sleep(max(1, self.cfg.scheduler.poll_interval_seconds))

    def _next_archived_job(self: TaskManager) -> str | None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            jobs = (
                db.query(task_manager_module.BinarySecurityArchiveJob)
                .filter(task_manager_module.BinarySecurityArchiveJob.archive_status == "archived")
                .order_by(
                    task_manager_module.BinarySecurityArchiveJob.updated_at.asc(),
                    task_manager_module.BinarySecurityArchiveJob.created_at.asc(),
                    task_manager_module.BinarySecurityArchiveJob.id.asc(),
                )
                .all()
            )
            for job in jobs:
                if str(getattr(job, "owner_id", "") or "").strip():
                    continue
                job.archive_status = "applying"
                job.owner_id = str(self.instance_id or "").strip() or None
                job.updated_at = task_shared._now()
                db.commit()
                return str(job.id or "").strip() or None
            db.rollback()
            return None
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _claim_archive_job(self: TaskManager) -> str | None:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            jobs = (
                db.query(task_manager_module.BinarySecurityArchiveJob)
                .filter(task_manager_module.BinarySecurityArchiveJob.archive_status == "pending")
                .order_by(
                    task_manager_module.BinarySecurityArchiveJob.updated_at.asc(),
                    task_manager_module.BinarySecurityArchiveJob.created_at.asc(),
                    task_manager_module.BinarySecurityArchiveJob.id.asc(),
                )
                .all()
            )
            for job in jobs:
                if str(getattr(job, "owner_id", "") or "").strip():
                    continue
                if not self._archive_job_ready_for_retry(job):
                    continue
                job.archive_status = "running"
                job.owner_id = str(self.instance_id or "").strip() or None
                now_value = task_shared._now()
                job.started_at = now_value
                job.updated_at = now_value
                job.error_message = None
                db.commit()
                return str(job.id or "").strip() or None
            db.rollback()
            return None
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    async def _schedule_archive_workers(self: TaskManager) -> None:
        max_workers = max(1, int(getattr(self.cfg.scheduler, "archive_job_concurrency", 0) or 1))
        async with self._archive_worker_lock:
            self._archive_workers = {task for task in self._archive_workers if not task.done()}
            slots = max_workers - len(self._archive_workers)
            if slots <= 0:
                return
            assignments: list[tuple[str, str]] = []
            for _ in range(slots):
                archived_job_id = await asyncio.to_thread(self._next_archived_job)
                if archived_job_id:
                    observe_archive_action("claim", "apply")
                    assignments.append(("apply", archived_job_id))
                    continue
                job_id = await asyncio.to_thread(self._claim_archive_job)
                if job_id:
                    observe_archive_action("claim", "copy")
                    assignments.append(("copy", job_id))
                    continue
                break
            for work_type, job_id in assignments:
                worker = asyncio.create_task(
                    self._archive_worker(work_type, job_id),
                    name=f"binary-security-archive-{work_type}-{job_id}",
                )
                self._archive_workers.add(worker)
            self._observe_worker_counts()

    async def _archive_worker(self: TaskManager, work_type: str, job_id: str) -> None:
        try:
            if work_type == "apply":
                await asyncio.to_thread(
                    self._enqueue_archive_state_event_by_job_id,
                    job_id,
                    event_type="archive_job_copied",
                    payload={"source": "archive_apply_claim"},
                )
            else:
                await self._process_archive_job(job_id)
        except asyncio.CancelledError:
            if work_type == "copy":
                await asyncio.to_thread(self._requeue_running_archive_job_if_owned, job_id, "archive worker cancelled")
            raise
        finally:
            async with self._archive_worker_lock:
                self._archive_workers.discard(asyncio.current_task())
            self._observe_worker_counts()

    def _archive_reclaim_timeout_seconds(self: TaskManager) -> int:
        return max(30, int(getattr(self.cfg.scheduler, "archive_reclaim_timeout_seconds", 300) or 300))

    def _archive_reclaim_max_attempts(self: TaskManager) -> int:
        return max(1, int(getattr(self.cfg.scheduler, "archive_reclaim_max_attempts", 3) or 3))

    def _archive_copy_missing_source_retry_schedule_seconds(self: TaskManager) -> list[int]:
        raw_schedule = getattr(self.cfg.scheduler, "archive_copy_missing_source_retry_schedule_seconds", None)
        values = raw_schedule if isinstance(raw_schedule, list) else [60, 120, 180]
        schedule = [max(1, int(value)) for value in values if str(value).strip()]
        return schedule or [60, 120, 180]

    def _archive_job_retry_attempt(self: TaskManager, job) -> int:
        return max(0, int((job.payload or {}).get("copy_retry_attempt") or 0))

    def _archive_job_retry_next_at(self: TaskManager, job) -> datetime | None:
        raw = (job.payload or {}).get("copy_retry_next_at")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(str(raw))
        except Exception:
            return None

    def _archive_job_ready_for_retry(self: TaskManager, job, *, now: datetime | None = None) -> bool:
        del now
        next_retry_at = self._archive_job_retry_next_at(job)
        if next_retry_at is None:
            return True
        return task_shared._seconds_until(next_retry_at) is None or task_shared._seconds_until(next_retry_at) <= 0

    def _clear_archive_job_retry_metadata(self: TaskManager, job) -> dict[str, object]:
        payload = dict(job.payload or {})
        for key in (
            "copy_retry_reason",
            "copy_retry_attempt",
            "copy_retry_next_at",
            "copy_retry_schedule_seconds",
            "last_missing_source_observed_at",
            "last_source_candidates",
            "last_source_candidate_count",
            "last_source_candidates_preview",
        ):
            payload.pop(key, None)
        return payload

    def _schedule_archive_job_missing_source_retry(
        self: TaskManager,
        db,
        task,
        item,
        job,
        *,
        source_candidates: list[str],
    ) -> tuple[bool, int | None, datetime | None]:
        from app.service import task_manager as task_manager_module

        schedule = self._archive_copy_missing_source_retry_schedule_seconds()
        retry_attempt = self._archive_job_retry_attempt(job)
        if retry_attempt >= len(schedule):
            return False, None, None
        retry_delay_seconds = int(schedule[retry_attempt])
        next_retry_at = task_shared._now() + timedelta(seconds=retry_delay_seconds)
        payload = self._clear_archive_job_retry_metadata(job)
        payload.update(
            {
                "copy_retry_reason": task_manager_module.ARCHIVE_COPY_MISSING_SOURCE_RETRY_REASON,
                "copy_retry_attempt": retry_attempt + 1,
                "copy_retry_next_at": next_retry_at.isoformat(),
                "copy_retry_schedule_seconds": schedule,
                "last_missing_source_observed_at": task_shared._now().isoformat(),
                "last_source_candidate_count": len(source_candidates),
                "last_source_candidates_preview": list(source_candidates[: task_manager_module.DB_ARTIFACT_PREVIEW_LIMIT]),
            }
        )
        job.payload = payload
        job.archive_status = "pending"
        job.owner_id = None
        job.error_message = None
        job.archive_root = None
        job.started_at = None
        job.completed_at = None
        job.updated_at = task_shared._now()
        self._record_event(
            db,
            task,
            "downstream_archive_job_delayed_retry_scheduled",
            f"下游产物暂未就绪，已安排 {retry_delay_seconds}s 后重试归档",
            stage_name=job.stage_name,
            item=item,
            level="warning",
            payload={
                "archive_job_id": job.id,
                "retry_attempt": retry_attempt + 1,
                "retry_delay_seconds": retry_delay_seconds,
                "next_retry_at": next_retry_at.isoformat(),
                "source_candidate_count": len(source_candidates),
                "source_candidates_preview": list(source_candidates[: task_manager_module.DB_ARTIFACT_PREVIEW_LIMIT]),
                "downstream_task_id": job.downstream_task_id,
                "resolution_reason": task_manager_module.ARCHIVE_COPY_MISSING_SOURCE_RETRY_REASON,
            },
        )
        return True, retry_delay_seconds, next_retry_at

    def _active_archive_job_ids(self: TaskManager) -> set[str]:
        active_job_ids: set[str] = set()
        for worker in self._archive_workers:
            if worker.done():
                continue
            name = str(worker.get_name() or "")
            prefix = "binary-security-archive-"
            if not name.startswith(prefix):
                continue
            job_id = name.split("-")[-1]
            if job_id:
                active_job_ids.add(job_id)
        return active_job_ids

    def _requeue_running_archive_job_if_owned(self: TaskManager, job_id: str, reason: str) -> bool:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            job = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.id == job_id).first()
            if job is None or str(job.archive_status or "").strip() != "running":
                return False
            if str(job.owner_id or "").strip() != str(self.instance_id or "").strip():
                return False
            task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == job.task_id).first()
            if task is None:
                return False
            item = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.id == job.item_id).first()
            self._requeue_archive_jobs(
                db,
                task,
                [job],
                stage_name=job.stage_name,
                event_type="downstream_archive_job_owner_lost",
                event_message="归档 worker 中断，归档任务已自动回退重排队",
            )
            self._record_event(
                db,
                task,
                "downstream_archive_job_owner_lost",
                "归档 worker 中断，运行中的归档任务已自动回退重排队",
                stage_name=job.stage_name,
                item=item,
                level="warning",
                payload={"archive_job_id": job.id, "owner_id_before": self.instance_id, "resolution_reason": reason},
            )
            observe_archive_reclaim("owner_cleanup")
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False
        finally:
            db.close()

    def _requeue_owned_running_archive_jobs(self: TaskManager) -> int:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            jobs = (
                db.query(task_manager_module.BinarySecurityArchiveJob)
                .filter(
                    task_manager_module.BinarySecurityArchiveJob.archive_status == "running",
                    task_manager_module.BinarySecurityArchiveJob.owner_id == self.instance_id,
                )
                .order_by(task_manager_module.BinarySecurityArchiveJob.updated_at.asc(), task_manager_module.BinarySecurityArchiveJob.id.asc())
                .all()
            )
            if not jobs:
                return 0
            tasks_by_id = {
                str(task.id): task
                for task in db.query(task_manager_module.BinarySecurityTask).filter(
                    task_manager_module.BinarySecurityTask.id.in_([str(job.task_id) for job in jobs if job.task_id])
                ).all()
            }
            reclaimed = 0
            for job in jobs:
                task = tasks_by_id.get(str(job.task_id))
                if task is None:
                    continue
                item = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.id == job.item_id).first()
                self._requeue_archive_jobs(
                    db,
                    task,
                    [job],
                    stage_name=job.stage_name,
                    event_type="downstream_archive_job_owner_lost",
                    event_message="归档实例停止，运行中的归档任务已自动回退重排队",
                )
                self._record_event(
                    db,
                    task,
                    "downstream_archive_job_owner_lost",
                    "归档实例停止，运行中的归档任务已自动回退重排队",
                    stage_name=job.stage_name,
                    item=item,
                    level="warning",
                    payload={"archive_job_id": job.id, "owner_id_before": self.instance_id, "resolution_reason": "stop_cleanup"},
                )
                reclaimed += 1
            if reclaimed:
                observe_archive_reclaim("stop_cleanup")
                db.commit()
            else:
                db.rollback()
            return reclaimed
        except Exception:
            db.rollback()
            return 0
        finally:
            db.close()

    def _reclaim_stale_archive_jobs(self: TaskManager) -> int:
        from app.service import task_manager as task_manager_module

        db = task_manager_module.get_session_factory()()
        try:
            active_job_ids = self._active_archive_job_ids()
            timeout_seconds = self._archive_reclaim_timeout_seconds()
            max_attempts = self._archive_reclaim_max_attempts()
            now = task_shared._now()
            jobs = (
                db.query(task_manager_module.BinarySecurityArchiveJob)
                .filter(task_manager_module.BinarySecurityArchiveJob.archive_status == "running")
                .order_by(task_manager_module.BinarySecurityArchiveJob.updated_at.asc(), task_manager_module.BinarySecurityArchiveJob.id.asc())
                .all()
            )
            reclaimed = 0
            for job in jobs:
                if str(job.id or "") in active_job_ids:
                    continue
                if job.archive_root or job.completed_at:
                    continue
                last_progress_at = job.updated_at or job.started_at or job.created_at
                if last_progress_at is None:
                    continue
                if (now - last_progress_at).total_seconds() < timeout_seconds:
                    continue
                task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == job.task_id).first()
                if task is None:
                    continue
                item = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.id == job.item_id).first()
                attempts = int(job.attempts or 0)
                owner_before = str(job.owner_id or "").strip() or None
                has_active_task_owner = bool(
                    str(getattr(task, "dispatcher_instance_id", "") or "").strip()
                    and self._lease_is_active(task, db=db)
                )
                if has_active_task_owner:
                    job.archive_status = "failed"
                    job.error_message = "archive worker lost after claim; delegated to task owner repair"
                    job.completed_at = now
                    job.updated_at = now
                    job.owner_id = None
                    job.archive_root = None
                    self._merge_task_runtime_signal(
                        task,
                        "pending_archive_rebuild",
                        source="lease_auditor_signal",
                        reason="stale_running_archive_job",
                        stage_name=str(job.stage_name or "").strip() or None,
                        archive_job_ids=[str(job.id or "").strip()],
                        extra={
                            "rebuild_mode": "failed_items",
                            "resolution_reason": "stale_running_archive_job",
                            "timeout_seconds": timeout_seconds,
                        },
                    )
                    self._record_event(
                        db,
                        task,
                        "downstream_archive_rebuild_deferred_to_owner",
                        "归档任务长时间无进展，已通知任务 owner 串行重建归档",
                        stage_name=job.stage_name,
                        item=item,
                        level="warning",
                        payload={
                            "archive_job_id": job.id,
                            "attempts": attempts,
                            "owner_id_before": owner_before,
                            "resolution_reason": "stale_running_archive_job",
                            "timeout_seconds": timeout_seconds,
                            "source": "lease_auditor_signal",
                        },
                    )
                    reclaimed += 1
                    continue
                if attempts > max_attempts:
                    job.archive_status = "failed"
                    job.error_message = "archive worker lost after claim; reclaim exhausted"
                    job.completed_at = now
                    job.updated_at = now
                    self._record_event(
                        db,
                        task,
                        "downstream_archive_job_reclaim_failed",
                        "归档任务在运行态丢失且已超过自动回收预算，需人工处理",
                        stage_name=job.stage_name,
                        item=item,
                        level="warning",
                        payload={
                            "archive_job_id": job.id,
                            "attempts": attempts,
                            "owner_id_before": owner_before,
                            "resolution_reason": "archive_reclaim_exhausted",
                            "timeout_seconds": timeout_seconds,
                        },
                    )
                    observe_archive_reclaim("failed")
                    reclaimed += 1
                    continue
                self._requeue_archive_jobs(
                    db,
                    task,
                    [job],
                    stage_name=job.stage_name,
                    event_type="downstream_archive_job_requeued_after_reclaim",
                    event_message="归档任务在运行态丢失，已自动回退重排队",
                )
                self._record_event(
                    db,
                    task,
                    "downstream_archive_job_owner_lost",
                    "归档任务长时间无进展且无本地 worker 持有，判定为运行态丢失",
                    stage_name=job.stage_name,
                    item=item,
                    level="warning",
                    payload={
                        "archive_job_id": job.id,
                        "attempts": attempts,
                        "owner_id_before": owner_before,
                        "resolution_reason": "stale_running_archive_job",
                        "timeout_seconds": timeout_seconds,
                    },
                )
                observe_archive_reclaim("requeued")
                reclaimed += 1
            if reclaimed:
                db.commit()
            else:
                db.rollback()
            return reclaimed
        except Exception:
            db.rollback()
            return 0
        finally:
            db.close()
