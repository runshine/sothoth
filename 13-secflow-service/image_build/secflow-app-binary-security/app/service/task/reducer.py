from __future__ import annotations

import asyncio
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.exception import ValidationError
from app.model import BinarySecurityStateEvent, BinarySecurityStageItem, TASK_TERMINAL_STATUSES, normalize_stage_name
from app.observability import (
    observe_archive_job_statuses,
    observe_stage_duration,
    observe_state_dead_letter,
    observe_state_event_lag,
    observe_state_event_queues,
    observe_state_reducer_event,
    observe_state_reducer_health,
    observe_state_reducer_run,
    observe_task_duration,
    observe_task_error,
    observe_task_lifecycle,
    observe_task_state_lock,
)

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskReducerServiceMixin:
    async def _state_reducer_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        interval_seconds = max(1, int(self.cfg.scheduler.poll_interval_seconds or 5))
        while self._running:
            db = task_manager_module.get_session_factory()()
            try:
                with task_manager_module.observe_scheduler_loop("state_reducer"):
                    self._mark_loop_heartbeat("state_reducer")
                    await asyncio.to_thread(self._observe_state_runtime_metrics, db)
                    processed = 0
                    for _ in range(max(1, int(self.cfg.scheduler.downstream_action_concurrency or 1))):
                        event_id = self._claim_state_event(db)
                        if not event_id:
                            break
                        processed += 1
                        await self._reduce_state_event(event_id)
                    await self._observe_runtime_metrics(db)
                    self._state_reducer_consecutive_crash_count = 0
                    observe_state_reducer_health(
                        pod=self.instance_id,
                        loop_ok_at=time.time(),
                        consecutive_crash_count=0,
                    )
                    self._mark_loop_heartbeat("state_reducer")
                    if processed:
                        continue
            except asyncio.CancelledError:
                raise
            except Exception:
                self._state_reducer_consecutive_crash_count += 1
                observe_state_reducer_health(
                    pod=self.instance_id,
                    crash_at=time.time(),
                    consecutive_crash_count=self._state_reducer_consecutive_crash_count,
                )
                task_manager_module.logger.exception("binary-security state reducer loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                db.close()
            await asyncio.sleep(interval_seconds)

    async def _reducer_metrics_snapshot_loop(self: TaskManager) -> None:
        interval_seconds = max(5, int(self.cfg.scheduler.poll_interval_seconds or 5))
        self._mark_loop_heartbeat("reducer_metrics_snapshot")
        await self._publish_reducer_metrics_snapshot()
        self._mark_loop_heartbeat("reducer_metrics_snapshot")
        while self._running:
            await asyncio.sleep(interval_seconds)
            await self._publish_reducer_metrics_snapshot()
            self._mark_loop_heartbeat("reducer_metrics_snapshot")

    async def _publish_reducer_metrics_snapshot(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        try:
            payload, _ = await asyncio.to_thread(task_manager_module.render_metrics)
            await task_manager_module.get_reducer_metrics_snapshot_store().write_snapshot(
                metrics_payload=payload.decode("utf-8", errors="ignore"),
                source_pod=self.instance_id,
            )
        except Exception:
            task_manager_module.logger.exception("binary-security failed to publish reducer metrics snapshot")

    def _observe_state_runtime_metrics(self: TaskManager, db: Session) -> None:
        from app.service import task_manager as task_manager_module

        rows = (
            db.query(task_manager_module.BinarySecurityStateEvent.status, task_manager_module.func.count(task_manager_module.BinarySecurityStateEvent.id))
            .group_by(task_manager_module.BinarySecurityStateEvent.status)
            .all()
        )
        status_counts = {str(status or "unknown"): int(count or 0) for status, count in rows}
        oldest_ages: dict[str, float] = {}
        for status in {"pending", "processing", "retryable", "dead_letter"}:
            oldest = (
                db.query(task_manager_module.func.min(task_manager_module.BinarySecurityStateEvent.created_at))
                .filter(task_manager_module.BinarySecurityStateEvent.status == status)
                .scalar()
            )
            oldest_ages[status] = max(0.0, (task_shared._now() - oldest).total_seconds()) if oldest else 0.0
        observe_state_event_queues(status_counts=status_counts, oldest_ages=oldest_ages)
        archive_rows = (
            db.query(
                task_manager_module.BinarySecurityArchiveJob.stage_name,
                task_manager_module.BinarySecurityArchiveJob.archive_status,
                task_manager_module.func.count(task_manager_module.BinarySecurityArchiveJob.id),
            )
            .group_by(
                task_manager_module.BinarySecurityArchiveJob.stage_name,
                task_manager_module.BinarySecurityArchiveJob.archive_status,
            )
            .all()
        )
        observe_archive_job_statuses(
            {(str(stage or "unknown"), str(status or "unknown")): int(count or 0) for stage, status, count in archive_rows}
        )

    def _claim_state_event(self: TaskManager, db: Session) -> str | None:
        from app.service import task_manager as task_manager_module

        now_value = task_shared._now()
        try:
            event = (
                db.query(task_manager_module.BinarySecurityStateEvent)
                .filter(
                    task_manager_module.BinarySecurityStateEvent.status.in_(["pending", "retryable", "processing"]),
                    task_manager_module.BinarySecurityStateEvent.available_at <= now_value,
                    task_manager_module.or_(
                        task_manager_module.BinarySecurityStateEvent.status != "processing",
                        task_manager_module.BinarySecurityStateEvent.lease_expires_at.is_(None),
                        task_manager_module.BinarySecurityStateEvent.lease_expires_at < now_value,
                    ),
                )
                .order_by(
                    task_manager_module.BinarySecurityStateEvent.available_at.asc(),
                    task_manager_module.BinarySecurityStateEvent.created_at.asc(),
                    task_manager_module.BinarySecurityStateEvent.id.asc(),
                )
                .first()
            )
        except OperationalError as exc:
            if not self._is_retryable_lock_error(exc):
                raise
            db.rollback()
            task_manager_module.logger.warning("binary-security state reducer skipped event claim after retryable lock conflict during lookup")
            return None
        if event is None:
            return None
        try:
            updated = (
                db.query(task_manager_module.BinarySecurityStateEvent)
                .filter(
                    task_manager_module.BinarySecurityStateEvent.id == event.id,
                    task_manager_module.BinarySecurityStateEvent.status.in_(["pending", "retryable", "processing"]),
                    task_manager_module.or_(
                        task_manager_module.BinarySecurityStateEvent.status != "processing",
                        task_manager_module.BinarySecurityStateEvent.lease_expires_at.is_(None),
                        task_manager_module.BinarySecurityStateEvent.lease_expires_at < now_value,
                    ),
                )
                .update(
                    {
                        task_manager_module.BinarySecurityStateEvent.status: "processing",
                        task_manager_module.BinarySecurityStateEvent.leased_by: self.instance_id,
                        task_manager_module.BinarySecurityStateEvent.processed_by: self.instance_id,
                        task_manager_module.BinarySecurityStateEvent.lease_expires_at: now_value + timedelta(seconds=task_manager_module.STATE_EVENT_LEASE_SECONDS),
                        task_manager_module.BinarySecurityStateEvent.processing_started_at: now_value,
                        task_manager_module.BinarySecurityStateEvent.processing_finished_at: None,
                        task_manager_module.BinarySecurityStateEvent.processing_result: "processing",
                        task_manager_module.BinarySecurityStateEvent.attempts: int(event.attempts or 0) + 1,
                        task_manager_module.BinarySecurityStateEvent.last_error_message: None,
                        task_manager_module.BinarySecurityStateEvent.updated_at: now_value,
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
        except OperationalError as exc:
            if not self._is_retryable_lock_error(exc):
                raise
            db.rollback()
            task_manager_module.logger.warning(
                "binary-security state reducer skipped event claim after retryable lock conflict: event_id=%s",
                getattr(event, "id", None),
            )
            return None
        return event.id if updated else None

    def _acquire_task_state_lease(self: TaskManager, db: Session, task_id: str, *, operation: str = "state_reduce") -> str | None:
        from app.service import task_manager as task_manager_module

        started = time.perf_counter()
        now_value = task_shared._now()
        token = uuid.uuid4().hex
        expires_at = now_value + timedelta(seconds=task_manager_module.TASK_STATE_LEASE_SECONDS)
        values = {
            task_manager_module.BinarySecurityTaskStateLease.owner_id: self.instance_id,
            task_manager_module.BinarySecurityTaskStateLease.lease_token: token,
            task_manager_module.BinarySecurityTaskStateLease.lease_expires_at: expires_at,
            task_manager_module.BinarySecurityTaskStateLease.heartbeat_at: now_value,
            task_manager_module.BinarySecurityTaskStateLease.operation: operation,
            task_manager_module.BinarySecurityTaskStateLease.updated_at: now_value,
        }
        max_attempts = self._retryable_write_attempts()
        for attempt in range(max_attempts):
            updated = (
                db.query(task_manager_module.BinarySecurityTaskStateLease)
                .filter(
                    task_manager_module.BinarySecurityTaskStateLease.task_id == task_id,
                    task_manager_module.or_(
                        task_manager_module.BinarySecurityTaskStateLease.lease_expires_at.is_(None),
                        task_manager_module.BinarySecurityTaskStateLease.lease_expires_at <= now_value,
                        task_manager_module.BinarySecurityTaskStateLease.owner_id == self.instance_id,
                    ),
                )
                .update(values, synchronize_session=False)
            )
            if updated:
                try:
                    db.flush()
                    observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=1)
                    return token
                except OperationalError as exc:
                    if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                        raise
                    db.rollback()
                    self._sleep_after_retryable_lock_error(attempt + 1)
                    continue
            try:
                lease = task_manager_module.BinarySecurityTaskStateLease(
                    task_id=task_id,
                    owner_id=self.instance_id,
                    lease_token=token,
                    lease_expires_at=expires_at,
                    heartbeat_at=now_value,
                    operation=operation,
                    updated_at=now_value,
                )
                with self._savepoint(db):
                    db.add(lease)
                    db.flush()
                observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=1)
                return token
            except IntegrityError:
                updated = (
                    db.query(task_manager_module.BinarySecurityTaskStateLease)
                    .filter(
                        task_manager_module.BinarySecurityTaskStateLease.task_id == task_id,
                        task_manager_module.or_(
                            task_manager_module.BinarySecurityTaskStateLease.lease_expires_at.is_(None),
                            task_manager_module.BinarySecurityTaskStateLease.lease_expires_at <= now_value,
                            task_manager_module.BinarySecurityTaskStateLease.owner_id == self.instance_id,
                        ),
                    )
                    .update(values, synchronize_session=False)
                )
                if updated:
                    try:
                        db.flush()
                        observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=1)
                        return token
                    except OperationalError as exc:
                        if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                            raise
                        db.rollback()
                        self._sleep_after_retryable_lock_error(attempt + 1)
                        continue
                observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=0)
                return None
            except OperationalError as exc:
                if not self._is_retryable_lock_error(exc) or attempt >= max_attempts - 1:
                    raise
                db.rollback()
                self._sleep_after_retryable_lock_error(attempt + 1)
        observe_task_state_lock(operation=operation, wait_seconds=time.perf_counter() - started, active=0)
        return None

    def _release_task_state_lease(
        self: TaskManager,
        db: Session,
        task_id: str,
        *,
        token: str,
        operation: str = "state_reduce",
        held_started: float | None = None,
    ) -> None:
        from app.service import task_manager as task_manager_module

        lease = db.query(task_manager_module.BinarySecurityTaskStateLease).filter(task_manager_module.BinarySecurityTaskStateLease.task_id == task_id).first()
        if lease is not None and lease.lease_token == token:
            db.delete(lease)
            db.flush()
        observe_task_state_lock(
            operation=operation,
            held_seconds=(time.perf_counter() - held_started) if held_started is not None else None,
            active=0,
        )

    async def _reduce_state_event(self: TaskManager, event_id: str) -> None:
        from app.service import task_manager as task_manager_module

        started = time.perf_counter()
        db = task_manager_module.get_session_factory()()
        event: task_manager_module.BinarySecurityStateEvent | None = None
        lease_token: str | None = None
        held_started: float | None = None
        result = "unknown"
        try:
            event = db.query(task_manager_module.BinarySecurityStateEvent).filter(task_manager_module.BinarySecurityStateEvent.id == event_id).first()
            if event is None or event.status != "processing" or event.leased_by != self.instance_id:
                result = "skipped"
                return
            lease_token = self._acquire_task_state_lease(db, event.task_id)
            if not lease_token:
                event.status = "retryable"
                event.available_at = task_shared._now() + timedelta(seconds=self._lock_busy_backoff_seconds(event))
                event.leased_by = None
                event.lease_expires_at = None
                event.processing_finished_at = task_shared._now()
                event.processing_result = "lock_busy_backoff"
                event.last_error_message = "task state lease busy"
                event.updated_at = task_shared._now()
                db.commit()
                result = "lock_busy"
                return
            held_started = time.perf_counter()
            db.commit()
            await self._apply_state_event_locked(db, event)
            event = db.query(task_manager_module.BinarySecurityStateEvent).filter(task_manager_module.BinarySecurityStateEvent.id == event_id).first()
            if event is None:
                result = "missing_after_apply"
                return
            event_type = event.event_type
            event.status = "processed"
            finished_at = task_shared._now()
            event.processed_at = finished_at
            event.processing_finished_at = finished_at
            event.processing_result = "success"
            event.leased_by = None
            event.lease_expires_at = None
            event.error_message = None
            event.last_error_message = None
            event.updated_at = finished_at
            observe_state_event_lag(event_type, (task_shared._now() - event.created_at).total_seconds() if event.created_at else None)
            observe_state_reducer_event(event_type, "processed")
            observe_state_reducer_health(pod=self.instance_id, event_processed_at=time.time())
            result = "success"
            db.commit()
        except Exception as exc:
            db.rollback()
            result = "failed"
            if event is not None:
                try:
                    event = db.query(task_manager_module.BinarySecurityStateEvent).filter(task_manager_module.BinarySecurityStateEvent.id == event_id).first()
                    if event is not None:
                        event.error_message = str(exc)
                        event.leased_by = None
                        event.lease_expires_at = None
                        finished_at = task_shared._now()
                        event.processing_finished_at = finished_at
                        event.last_error_message = str(exc)
                        event.updated_at = finished_at
                        if int(event.attempts or 0) >= task_manager_module.STATE_EVENT_MAX_ATTEMPTS:
                            event.status = "dead_letter"
                            event.processed_at = finished_at
                            event.processing_result = "dead_letter"
                            observe_state_dead_letter(event.event_type, "max_attempts")
                        else:
                            event.status = "retryable"
                            event.processing_result = "retryable"
                            event.available_at = task_shared._now() + timedelta(seconds=min(300, 2 ** max(1, int(event.attempts or 1))))
                        db.commit()
                except Exception:
                    db.rollback()
            task_manager_module.logger.exception("binary-security state reducer failed: event=%s", event_id)
        finally:
            if lease_token and event is not None:
                try:
                    self._release_task_state_lease(db, event.task_id, token=lease_token, held_started=held_started)
                    db.commit()
                except Exception:
                    db.rollback()
            db.close()
            observe_state_reducer_run(result=result, pod=self.instance_id, duration_seconds=time.perf_counter() - started)

    async def _apply_state_event_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        payload = dict(event.payload or {})
        if event.event_type == "archive_job_copied":
            await self._apply_archive_job_status_locked(
                db,
                event.archive_job_id or "",
                payload.get("archive_root"),
                state_event_id=event.id,
            )
            return
        if event.event_type == "archive_job_copy_failed":
            self._apply_archive_job_copy_failed_locked(db, event)
            return
        if event.event_type in {"downstream_status_observed", "downstream_terminal_observed"}:
            await self._apply_downstream_status_event_locked(db, event)
            return
        if event.event_type == "stage_worker_terminal_observed":
            await self._apply_stage_worker_terminal_event_locked(db, event)
            return
        if event.event_type == "task_execution_failed":
            await self._apply_task_execution_failed_locked(db, event)
            return
        if event.event_type == "stage_worker_start_requested":
            self._apply_stage_worker_start_requested_locked(db, event)
            return
        if event.event_type == "manual_policy_update_requested":
            self._apply_manual_policy_update_requested_locked(db, event)
            return
        task_manager_module.logger.info("binary-security state reducer ignored event type: %s", event.event_type)

    async def _apply_downstream_status_event_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        item = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.id == event.item_id).first()
        if task is None or item is None:
            return
        payload = dict(event.payload or {})
        if task.status == "cancelled":
            self._record_event(
                db,
                task,
                "downstream_status_event_ignored",
                "下游状态事件晚于取消事件到达，已忽略以避免恢复已取消任务",
                level="warning",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "state_event_id": event.id,
                    "downstream_service": item.downstream_service,
                    "downstream_task_id": item.downstream_task_id,
                    "ignored_status": payload.get("mapped_status") or payload.get("downstream_status"),
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        mapped_status = str(payload.get("mapped_status") or "").strip()
        if not mapped_status:
            return
        mapped_status = self._map_downstream_status(mapped_status) or mapped_status
        downstream_payload = dict(payload.get("downstream_payload") or {})
        payload_downstream_task_id = self._payload_downstream_task_id(downstream_payload) or self._payload_downstream_task_id(payload)
        current_downstream_task_id = self._current_downstream_task_id(item)
        if payload_downstream_task_id and current_downstream_task_id and payload_downstream_task_id != current_downstream_task_id:
            self._mark_stage_item_sync_observation(
                item,
                sync_status="binding_mismatch",
                synced_at=task_shared._now(),
                error_message="旧 child 的下游状态事件已被忽略",
                error_type="binding_mismatch",
                status_raw=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                mapped_status=mapped_status,
                downstream_status=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                state_applied=False,
                last_sync_result="error",
            )
            self._record_binding_mismatch_event(
                db,
                task,
                item,
                event_type="downstream_binding_mismatch_detected",
                message="旧 child 的下游状态事件已被忽略，未回写当前阶段项",
                payload=self._binding_mismatch_payload(
                    source="downstream_status_event",
                    expected_downstream_task_id=current_downstream_task_id,
                    actual_downstream_task_id=payload_downstream_task_id,
                    payload_downstream_task_id=payload_downstream_task_id,
                ),
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if not self._payload_matches_current_child(item, downstream_payload or payload):
            self._mark_stage_item_sync_observation(
                item,
                sync_status="binding_mismatch",
                synced_at=task_shared._now(),
                error_message="旧 child 的下游状态事件已被忽略",
                error_type="binding_mismatch",
                status_raw=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                mapped_status=mapped_status,
                downstream_status=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
                state_applied=False,
                last_sync_result="error",
            )
            self._record_binding_mismatch_event(
                db,
                task,
                item,
                event_type="downstream_binding_mismatch_detected",
                message="旧 child 的下游状态事件已被忽略，未回写当前阶段项",
                payload=self._binding_mismatch_payload(
                    source="downstream_status_event",
                    expected_downstream_task_id=current_downstream_task_id,
                    actual_downstream_task_id=payload_downstream_task_id,
                    payload_downstream_task_id=payload_downstream_task_id,
                ),
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        self._apply_child_task_status_change(
            db,
            task=task,
            item=item,
            change_source="state_reducer",
            after_status=mapped_status,
            downstream_payload=downstream_payload,
            sync_status="synced",
            downstream_status_raw=self._string_or_none(payload.get("status_raw") or payload.get("downstream_status")),
            downstream_status_mapped=mapped_status,
            downstream_status=self._string_or_none(payload.get("downstream_status") or downstream_payload.get("status")),
            state_applied=True,
            error_message=(
                payload.get("error_message")
                or downstream_payload.get("error")
                or downstream_payload.get("error_message")
                or downstream_payload.get("message")
                or item.error_message
            ),
            error_type=self._string_or_none(payload.get("error_type")),
            http_status=self._int_or_none(payload.get("http_status")),
            state_event_id=event.id,
            extra_payload={"downstream_payload": self._lightweight_downstream_payload(downstream_payload)},
        )
        self._reconcile_after_item_layer_update_in_session(
            db,
            task,
            stage_name=item.stage_name,
            preferred_stage_name=item.stage_name,
            reason="downstream_status_event_without_active_holder",
            message="检测到下游状态已推进但当前无 active holder，已重新排队等待 worker 接管",
            payload={
                "source": "downstream_status_event_applied",
                "item_id": item.id,
                "downstream_task_id": item.downstream_task_id,
            },
        )
        if self._is_streaming_tail_stage(task, item.stage_name) and mapped_status in {"failed", "downstream_missing", "cancelled"}:
            task.status = "running"
            task.current_stage = item.stage_name
            task.finished_at = None
        self._record_event(
            db,
            task,
            "downstream_status_event_applied",
            "下游状态事件已由 reducer 串行应用",
            level="warning" if mapped_status in {"failed", "cancelled", "downstream_missing"} else "info",
            stage_name=item.stage_name,
            item=item,
            payload={
                "state_event_id": event.id,
                "before_status": payload.get("before_status"),
                "after_status": mapped_status,
                "http_status": payload.get("http_status"),
                "error_type": payload.get("error_type"),
                "status_raw": payload.get("status_raw") or payload.get("downstream_status"),
                "mapped_status": mapped_status,
                "state_applied": True,
                "downstream_status": payload.get("downstream_status"),
                "downstream_service": item.downstream_service,
                "downstream_task_id": item.downstream_task_id,
            },
        )
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    async def _apply_downstream_terminal_observed_locked(
        self: TaskManager,
        db: Session,
        event: BinarySecurityStateEvent,
    ) -> None:
        await self._apply_downstream_status_event_locked(db, event)

    def _apply_downstream_status_inline(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        mapped_status: str,
        downstream_payload: dict[str, Any] | None,
        error_message: str | None,
        synced_at: object | None = None,
    ) -> None:
        self._apply_child_task_status_change(
            None,
            task=None,
            item=item,
            change_source="downstream_sync",
            after_status=mapped_status,
            downstream_payload=downstream_payload,
            sync_status="synced",
            downstream_status_raw=self._string_or_none((downstream_payload or {}).get("status")),
            downstream_status_mapped=self._map_downstream_status(mapped_status) or mapped_status,
            downstream_status=self._string_or_none((downstream_payload or {}).get("status")),
            state_applied=True,
            error_message=error_message,
            synced_at=synced_at,
        )

    def _should_apply_downstream_intermediate_status(
        self: TaskManager,
        item: BinarySecurityStageItem,
        *,
        mapped_status: str,
        payload: dict[str, Any] | None,
    ) -> bool:
        before_status = str(item.status or "").strip().lower()
        if self._should_apply_current_child_intermediate_recovery(item, mapped_status=mapped_status, payload=payload):
            return True
        normalized_stage_name = normalize_stage_name(item.stage_name)
        if mapped_status == "running":
            if normalized_stage_name == "dataflow_vuln_scan":
                return before_status in {"pending", "queued", "running", "dispatching", "success", "failed"}
            return before_status in {"pending", "queued", "running", "dispatching", "success", "failed"}
        if mapped_status == "queued":
            return before_status in {"running", "queued"}
        if mapped_status == "pending":
            if before_status != "running":
                return False
            if str(item.downstream_service or "").strip() == "entry_analyse":
                return self._entry_payload_matches_stage_item(item, payload)
            return True
        return False

    async def _apply_stage_worker_terminal_event_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        payload = dict(event.payload or {})
        stage_name = str(event.stage_name or payload.get("stage_name") or "").strip()
        status = str(payload.get("status") or "").strip()
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        if task is None or not stage_name or not status:
            return
        payload = self._load_externalized_event_payload(task, payload)
        stage_name = str(event.stage_name or payload.get("stage_name") or stage_name).strip()
        status = str(payload.get("status") or status).strip()
        observed_terminal_status = status
        terminal_failure_statuses = {"failed", "downstream_missing", "cancelled"}
        summary = dict(payload.get("summary") or {})
        if task.status == "cancelled":
            self._record_event(
                db,
                task,
                "stage_worker_terminal_ignored",
                "阶段终态事件晚于取消事件到达，已忽略以避免恢复已取消任务",
                level="warning",
                stage_name=stage_name,
                payload={"state_event_id": event.id, "ignored_status": status},
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        active_stage_status = status in {"pending", "queued", "running", "dispatching"}
        stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
            task_manager_module.BinarySecurityStageRun.task_id == task.id,
            task_manager_module.BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if stage_run is None:
            stage_run = self._ensure_stage_run(db, task, stage_name)
        ignore_terminal, ignore_reason = self._should_ignore_stage_terminal_event(
            db,
            task,
            stage_name=stage_name,
            event=event,
            payload=payload,
            stage_run=stage_run,
        )
        if ignore_terminal:
            self._record_event(
                db,
                task,
                "stage_worker_terminal_stale_generation_ignored" if ignore_reason == "stale_generation" else "stage_worker_terminal_duplicate_ignored",
                "历史阶段终态事件已忽略，避免重复推进父任务",
                level="warning",
                stage_name=stage_name,
                payload={
                    "state_event_id": event.id,
                    "ignored_reason": ignore_reason,
                    "event_stage_generation": payload.get("stage_generation"),
                    "current_stage_generation": self._stage_terminal_generation_key(task, stage_name, db=db, stage_run=stage_run),
                    "current_stage": task.current_stage,
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if stage_name == "system_analysis":
            stage_run = self._refresh_stage_from_authoritative_items(db, task, stage_name) or stage_run
            summary = dict(stage_run.output_summary or summary)
            status = str(stage_run.status or status).strip() or status
            active_stage_status = status in {"pending", "queued", "running", "dispatching"}
        elif self._is_streaming_tail_stage(task, stage_name):
            existing_items = self._stage_items(db, task.id, stage_name)
            if existing_items:
                stage_run = self._refresh_stage_from_authoritative_items(db, task, stage_name) or stage_run
                summary = dict(stage_run.output_summary or summary)
                status = str(stage_run.status or status).strip() or status
                active_stage_status = status in {"pending", "queued", "running", "dispatching"}
                has_live_downstream_child = self._stage_has_live_downstream_children(existing_items)
                if observed_terminal_status in terminal_failure_statuses and active_stage_status and has_live_downstream_child:
                    self._record_event(
                        db,
                        task,
                        "stage_worker_terminal_deferred",
                        "阶段终态事件与活跃子项冲突，已按权威子项状态延后收敛",
                        level="warning",
                        stage_name=stage_name,
                        payload={
                            "state_event_id": event.id,
                            "observed_status": observed_terminal_status,
                            "authoritative_stage_status": status,
                        },
                    )
                    observed_terminal_status = status
            else:
                if (
                    observed_terminal_status in terminal_failure_statuses
                    and self._is_streaming_tail_stage(task, stage_name)
                    and not bool(payload.get("stage_retry_mode"))
                    and not bool(payload.get("task_retry_mode"))
                ):
                    stage_run.status = "pending"
                    stage_run.finished_at = None
                    stage_run.last_error = None
                    self._merge_stage_run_output_summary(task, stage_run, {"status_synced": True, "sync_status": "pending"})
                    self._update_task_stage_summary_entry(task, stage_run)
                    self._record_event(
                        db,
                        task,
                        "stage_worker_terminal_ignored_for_empty_streaming_tail",
                        "空流式尾段的历史终态事件已忽略，等待真实子项状态收敛",
                        level="warning",
                        stage_name=stage_name,
                        payload={
                            "state_event_id": event.id,
                            "observed_status": observed_terminal_status,
                        },
                    )
                    active_stage_status = True
                    status = "pending"
                    observed_terminal_status = "pending"
                else:
                    stage_run.status = "waiting_confirmation" if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION else ("running" if active_stage_status else status)
                    stage_run.finished_at = None if active_stage_status else task_shared._now()
                    if not active_stage_status:
                        observe_stage_duration(
                            stage=stage_name,
                            result=stage_run.status,
                            duration_seconds=task_shared._elapsed_seconds_since(stage_run.started_at),
                        )
                    await self._persist_stage_run_output_summary_async(task, stage_run, summary)
                    stage_run.counts = self._stage_counts(db, stage_run)
                    if status in {"failed", "partial_success", "downstream_missing"}:
                        stage_run.last_error = summary.get("error")
                    self._merge_task_stage_summary_entry(
                        task,
                        stage_run,
                        {
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
        else:
            existing_items = self._stage_items(db, task.id, stage_name)
            if existing_items:
                stage_run = self._refresh_stage_from_authoritative_items(db, task, stage_name) or stage_run
                summary = dict(stage_run.output_summary or summary)
                status = str(stage_run.status or status).strip() or status
                active_stage_status = status in {"pending", "queued", "running", "dispatching"}
                has_live_downstream_child = self._stage_has_live_downstream_children(existing_items)
                if observed_terminal_status in terminal_failure_statuses and active_stage_status and has_live_downstream_child:
                    self._record_event(
                        db,
                        task,
                        "stage_worker_terminal_deferred",
                        "阶段终态事件与活跃下游子任务冲突，已按权威子项状态延后收敛",
                        level="warning",
                        stage_name=stage_name,
                        payload={
                            "state_event_id": event.id,
                            "observed_status": observed_terminal_status,
                            "authoritative_stage_status": status,
                        },
                    )
                    observed_terminal_status = status
            else:
                stage_run.status = "waiting_confirmation" if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION else ("running" if active_stage_status else status)
                stage_run.finished_at = None if active_stage_status else task_shared._now()
                if not active_stage_status:
                    observe_stage_duration(
                        stage=stage_name,
                        result=stage_run.status,
                        duration_seconds=task_shared._elapsed_seconds_since(stage_run.started_at),
                    )
                await self._persist_stage_run_output_summary_async(task, stage_run, summary)
                stage_run.counts = self._stage_counts(db, stage_run)
                if status in {"failed", "partial_success", "downstream_missing"}:
                    stage_run.last_error = summary.get("error")
                self._merge_task_stage_summary_entry(
                    task,
                    stage_run,
                    {
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
        task.current_stage = stage_name
        if stage_name == "firmware_unpack":
            task.metrics = {**task.metrics, "unpacked_firmware_count": int(summary.get("success_count", 0)), "failed_firmware_count": int(summary.get("failed_count", 0))}
        elif stage_name == "system_analysis":
            stage_summary = dict(stage_run.output_summary or {})
            task.metrics = {
                **task.metrics,
                "high_risk_module_count": int(stage_summary.get("high_risk_module_count", summary.get("high_risk_module_count", 0)) or 0),
                "medium_risk_module_count": int(stage_summary.get("medium_risk_module_count", summary.get("medium_risk_module_count", 0)) or 0),
                "low_risk_module_count": int(stage_summary.get("low_risk_module_count", summary.get("low_risk_module_count", 0)) or 0),
                "candidate_module_count": int(stage_summary.get("candidate_module_count", summary.get("candidate_module_count", 0)) or 0),
                "selected_module_count": int(stage_summary.get("selected_module_count", summary.get("selected_module_count", 0)) or 0),
            }
            task_summary = dict(task.summary or {})
            if self._normalize_downstream_status(stage_run.status) == "success" and not task_summary.get("selected_modules"):
                self._refresh_system_analysis_stage_from_synced_items(db, task)
                task_summary = dict(task.summary or {})
                if task_summary.get("selected_modules"):
                    stage_run = db.query(task_manager_module.BinarySecurityStageRun).filter(
                        task_manager_module.BinarySecurityStageRun.task_id == task.id,
                        task_manager_module.BinarySecurityStageRun.stage_name == stage_name,
                    ).first() or stage_run
                    stage_summary = dict(stage_run.output_summary or stage_summary)
                    task.metrics = {
                        **task.metrics,
                        "high_risk_module_count": int(stage_summary.get("high_risk_module_count", summary.get("high_risk_module_count", 0)) or 0),
                        "medium_risk_module_count": int(stage_summary.get("medium_risk_module_count", summary.get("medium_risk_module_count", 0)) or 0),
                        "low_risk_module_count": int(stage_summary.get("low_risk_module_count", summary.get("low_risk_module_count", 0)) or 0),
                        "candidate_module_count": int(stage_summary.get("candidate_module_count", summary.get("candidate_module_count", 0)) or 0),
                        "selected_module_count": int(stage_summary.get("selected_module_count", summary.get("selected_module_count", 0)) or 0),
                    }
        elif stage_name == "entry_analysis":
            task.metrics = {**task.metrics, "entry_count": int(summary.get("entry_count", 0))}
        elif normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            task.metrics = {**task.metrics, "vuln_result_count": int(summary.get("vuln_result_count", summary.get("success_count", 0)) or 0)}
        if observed_terminal_status in terminal_failure_statuses:
            status = observed_terminal_status
            active_stage_status = False
            for item in self._stage_items(db, task.id, stage_name):
                if str(item.status or "").strip() not in {"pending", "queued", "running", "dispatching"}:
                    continue
                item.status = status
                item.finished_at = item.finished_at or task_shared._now()
                item.error_message = summary.get("failure_message") or summary.get("error") or item.error_message
            stage_run.status = status
            stage_run.finished_at = stage_run.finished_at or task_shared._now()
            stage_run.last_error = summary.get("failure_message") or summary.get("error") or stage_run.last_error
        if active_stage_status:
            task.status = "running"
            task.current_stage = stage_name
            task.last_error = None
            task.finished_at = None
            self._record_event(
                db,
                task,
                "stage_waiting_downstream_progress",
                "阶段仍在等待下游明确状态，已保留在当前阶段继续跟进",
                stage_name=stage_name,
                payload={
                    "state_event_id": event.id,
                    "stage_status": status,
                    "deferred_mode": "redispatch" if status == "pending" else "reconcile",
                },
            )
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            self._invalidate_task_execution(task)
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if bool(payload.get("stage_retry_mode")) and stage_name == str(payload.get("target_stage_name") or ""):
            self._record_event(
                db,
                task,
                "stage_retry_finished",
                f"阶段重试完成: {stage_name}",
                stage_name=stage_name,
                payload={"status": status, "state_event_id": event.id},
            )
        if status == "failed":
            if bool(payload.get("stage_retry_mode")) or bool(payload.get("task_retry_mode")):
                self._clear_retry_execution_context(db, task, stage_name=stage_name, payload={"status": status, "state_event_id": event.id})
            self._record_event(
                db,
                task,
                "stage_failed",
                f"阶段失败，停止后续推进: {stage_name}",
                level="error",
                stage_name=stage_name,
                payload={
                    "error": task.last_error,
                    "state_event_id": event.id,
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
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        if bool(payload.get("stage_retry_mode")) or bool(payload.get("task_retry_mode")):
            self._clear_retry_execution_context(db, task, stage_name=stage_name, payload={"status": status, "state_event_id": event.id})
        if self._ensure_task_remains_cancelling(db, task) is not None:
            await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            return
        handled = await self._apply_task_action_after_stage_terminal(db, task, stage_name=stage_name, status=status, summary=summary, payload=payload, state_event_id=event.id)
        if handled:
            return

    async def _apply_task_execution_failed_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        payload = dict(event.payload or {})
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        expected_dispatcher = str(payload.get("dispatcher_instance_id") or "").strip()
        expected_execution_token = str(payload.get("execution_token") or "").strip()
        current_execution_token = task.dispatch_started_at.isoformat() if task.dispatch_started_at else ""
        if expected_dispatcher and task.dispatcher_instance_id not in {None, expected_dispatcher}:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前 dispatcher 已变化",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": event.id, "dispatcher_instance_id": expected_dispatcher},
            )
            return
        if expected_execution_token and current_execution_token and expected_execution_token != current_execution_token:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前执行 token 已变化",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": event.id, "execution_token": expected_execution_token},
            )
            return
        if task.status not in {"dispatching", "running"}:
            self._record_event(
                db,
                task,
                "task_execution_failed_ignored",
                "执行失败事件已过期，当前任务不在运行态",
                level="warning",
                stage_name=task.current_stage,
                payload={"state_event_id": event.id, "status": task.status},
            )
            return
        error_message = str(payload.get("error") or "任务执行失败")
        task.status = "failed"
        task.last_error = error_message
        self._invalidate_task_execution(task)
        task.finished_at = task_shared._now()
        observe_task_error("execution_error", stage=str(task.current_stage or "unknown"), result="failed")
        observe_task_lifecycle("finished", status=task.status, task_type=self._task_type(task))
        observe_task_duration(
            phase="execution",
            duration_seconds=task_shared._elapsed_seconds_since(task.started_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        observe_task_duration(
            phase="total",
            duration_seconds=task_shared._elapsed_seconds_since(task.created_at),
            status=task.status,
            task_type=self._task_type(task),
        )
        self._record_event(
            db,
            task,
            "task_failed",
            f"任务执行失败: {error_message}",
            level="error",
            stage_name=task.current_stage,
            payload={"state_event_id": event.id},
        )
        await self._write_task_metadata_async(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    def _apply_manual_policy_update_requested_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        payload = dict(event.payload or {})
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
        if task is None:
            return
        mode = str(payload.get("mode") or "policy").strip()
        before = dict(payload.get("before") or {})
        after = dict(payload.get("after") or {})
        if not after:
            raise ValidationError("策略更新事件缺少目标策略")
        if mode == "runtime_override":
            task.runtime_override = after
            task.runtime_override_version = int(getattr(task, "runtime_override_version", 0) or 0) + 1
            task.runtime_override_updated_at = task_shared._now()
            task.runtime_override_updated_by = str(payload.get("updated_by") or "").strip() or None
            self._record_event(
                db,
                task,
                "task_runtime_policy_updated",
                "任务运行时策略已由 reducer 更新",
                payload={"before": before, "after": after, "effective_scope": payload.get("effective_scope") or "tail_claim_immediate", "state_event_id": event.id},
            )
            return
        task.policy = after
        if mode == "concurrency":
            self._record_event(
                db,
                task,
                "task_concurrency_updated",
                "任务阶段并发配置已由 reducer 更新",
                payload={"before": payload.get("concurrency_before") or before.get("stage_parallelism") or {}, "after": payload.get("concurrency_after") or after.get("stage_parallelism") or {}, "state_event_id": event.id},
            )
        else:
            self._record_event(
                db,
                task,
                "task_policy_updated",
                "任务策略已由 reducer 更新",
                payload={"before": before, "after": after, "effective_scope": payload.get("effective_scope") or "future_stages_only", "state_event_id": event.id},
            )

    def _apply_archive_job_copy_failed_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        job = db.query(task_manager_module.BinarySecurityArchiveJob).filter(task_manager_module.BinarySecurityArchiveJob.id == event.archive_job_id).first()
        if job is None:
            return
        task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == job.task_id).first()
        item = db.query(task_manager_module.BinarySecurityStageItem).filter(task_manager_module.BinarySecurityStageItem.id == job.item_id).first()
        if task is None:
            return
        payload = dict(event.payload or {})
        job.archive_status = "failed"
        job.error_message = payload.get("error") or job.error_message or "下游产物归档失败"
        job.completed_at = job.completed_at or task_shared._now()
        job.updated_at = task_shared._now()
        if task.status not in TASK_TERMINAL_STATUSES:
            task.status = "failed"
            task.current_stage = job.stage_name
            task.last_error = job.error_message
            task.finished_at = task_shared._now()
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.lease_expires_at = None
        self._record_event(
            db,
            task,
            "downstream_archive_job_copy_failed",
            "下游产物归档复制失败，已由 reducer 记录失败事实",
            level="warning",
            stage_name=job.stage_name,
            item=item,
            payload={"state_event_id": event.id, "archive_job_id": job.id, "archive_status": job.archive_status, "error": job.error_message},
        )
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)

    def _repair_retryable_state_events(self: TaskManager, db: Session) -> int:
        from app.service import task_manager as task_manager_module

        batch_size = self._state_repair_reconcile_batch_size()
        events = (
            db.query(task_manager_module.BinarySecurityStateEvent)
            .filter(task_manager_module.BinarySecurityStateEvent.status.in_(["retryable", "dead_letter"]))
            .order_by(task_manager_module.BinarySecurityStateEvent.updated_at.asc(), task_manager_module.BinarySecurityStateEvent.id.asc())
            .limit(batch_size)
            .all()
        )
        repaired = 0
        for event in events:
            task = db.query(task_manager_module.BinarySecurityTask).filter(task_manager_module.BinarySecurityTask.id == event.task_id).first()
            if task is None:
                continue
            if self._is_lock_busy_state_event(event):
                continue
            if str(task.status or "").strip() in task_manager_module.TASK_TERMINAL_STATUSES:
                continue
            event.status = "pending"
            event.available_at = task_shared._now()
            event.leased_by = None
            event.lease_expires_at = None
            event.processing_result = "requeued_for_repair"
            event.updated_at = task_shared._now()
            self._record_event(
                db,
                task,
                "task_state_repair_reconcile_triggered",
                "检测到 retryable/dead-letter reducer 事件，已重新排队修复",
                stage_name=event.stage_name,
                payload={
                    "state_event_id": event.id,
                    "event_type": event.event_type,
                    "resolution_reason": "retryable_or_dead_letter_state_event",
                },
            )
            repaired += 1
        if repaired:
            db.commit()
        else:
            db.rollback()
        return repaired
