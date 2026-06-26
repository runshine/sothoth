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
    observe_state_owner_event,
    observe_state_owner_health,
    observe_state_owner_run,
    observe_task_duration,
    observe_task_error,
    observe_task_lifecycle,
    observe_task_state_lock,
)

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskStateEventInboxServiceMixin:
    def _bootstrap_state_event_inbox_metrics_snapshot_payload(self: TaskManager) -> str:
        return "\n".join(
            [
                "# HELP secflow_binary_security_state_event_inbox_bootstrap_snapshot State event inbox bootstrap snapshot placeholder.",
                "# TYPE secflow_binary_security_state_event_inbox_bootstrap_snapshot gauge",
                "secflow_binary_security_state_event_inbox_bootstrap_snapshot 1",
            ]
        )

    async def _state_event_inbox_loop(self: TaskManager) -> None:
        from app.service import task_manager as task_manager_module

        interval_seconds = max(1, int(self.cfg.scheduler.poll_interval_seconds or 5))
        while self._running:
            db = task_manager_module.get_session_factory()()
            try:
                with task_manager_module.observe_scheduler_loop("state_event_inbox"):
                    self._mark_loop_heartbeat("state_event_inbox")
                    await asyncio.to_thread(self._observe_state_runtime_metrics, db)
                    processed = 0
                    for _ in range(max(1, int(self.cfg.scheduler.downstream_action_concurrency or 1))):
                        event_id = self._claim_state_event(db)
                        if not event_id:
                            break
                        processed += 1
                        await self._reduce_state_event(event_id)
                    await self._observe_runtime_metrics(db)
                    self._state_event_inbox_consecutive_crash_count = 0
                    observe_state_owner_health(
                        pod=self.instance_id,
                        loop_ok_at=time.time(),
                        consecutive_crash_count=0,
                    )
                    self._mark_loop_heartbeat("state_event_inbox")
                    if processed:
                        continue
            except asyncio.CancelledError:
                raise
            except Exception:
                self._state_event_inbox_consecutive_crash_count += 1
                observe_state_owner_health(
                    pod=self.instance_id,
                    crash_at=time.time(),
                    consecutive_crash_count=self._state_event_inbox_consecutive_crash_count,
                )
                task_manager_module.logger.exception("binary-security state event inbox loop crashed and recovered")
                await asyncio.sleep(1)
            finally:
                db.close()
            await asyncio.sleep(interval_seconds)

    async def _state_event_inbox_metrics_loop(self: TaskManager) -> None:
        interval_seconds = max(5, int(self.cfg.scheduler.poll_interval_seconds or 5))
        self._mark_loop_heartbeat("state_event_inbox_metrics")
        await self._publish_state_event_inbox_metrics_snapshot(lightweight=True)
        self._mark_loop_heartbeat("state_event_inbox_metrics")
        while self._running:
            await asyncio.sleep(interval_seconds)
            await self._publish_state_event_inbox_metrics_snapshot()
            self._mark_loop_heartbeat("state_event_inbox_metrics")

    async def _publish_state_event_inbox_metrics_snapshot(self: TaskManager, *, lightweight: bool = False) -> None:
        from app.service import task_manager as task_manager_module

        try:
            if lightweight:
                payload = self._bootstrap_state_event_inbox_metrics_snapshot_payload().encode("utf-8")
            else:
                payload, _ = await asyncio.to_thread(task_manager_module.render_metrics)
            await task_manager_module.get_state_event_inbox_metrics_snapshot_store().write_snapshot(
                metrics_payload=payload.decode("utf-8", errors="ignore"),
                source_pod=self.instance_id,
            )
        except Exception:
            task_manager_module.logger.exception("binary-security failed to publish state event inbox metrics snapshot")

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
            task_manager_module.logger.warning("binary-security state event inbox skipped event claim after retryable lock conflict during lookup")
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
                "binary-security state event inbox skipped event claim after retryable lock conflict: event_id=%s",
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
            observe_state_owner_event(event_type, "processed")
            observe_state_owner_health(pod=self.instance_id, event_processed_at=time.time())
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
            task_manager_module.logger.exception("binary-security state event inbox failed: event=%s", event_id)
        finally:
            if lease_token and event is not None:
                try:
                    self._release_task_state_lease(db, event.task_id, token=lease_token, held_started=held_started)
                    db.commit()
                except Exception:
                    db.rollback()
            db.close()
            observe_state_owner_run(result=result, pod=self.instance_id, duration_seconds=time.perf_counter() - started)

    async def _apply_state_event_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        from app.service import task_manager as task_manager_module

        previous_origin = getattr(self, "_active_timeline_origin_state_event", None)
        self._active_timeline_origin_state_event = event
        try:
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
            task_manager_module.logger.info("binary-security state event inbox ignored event type: %s", event.event_type)
        finally:
            self._active_timeline_origin_state_event = previous_origin

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
                "检测到 retryable/dead-letter state event inbox 事件，已重新排队修复",
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
