from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.model import BinarySecurityStateEvent, TASK_TERMINAL_STATUSES
from app.observability import (
    observe_archive_job_statuses,
    observe_stage_duration,
    observe_state_dead_letter,
    observe_state_event_lag,
    observe_state_event_queues,
    observe_state_owner_event,
    observe_state_owner_health,
    observe_state_owner_run,
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
            try:
                with task_manager_module.observe_scheduler_loop("state_event_inbox"):
                    self._mark_loop_heartbeat("state_event_inbox")
                    task_manager_module.logger.info(
                        "binary-security legacy state_event_inbox loop is compatibility-disabled; "
                        "owner worker is the only normal fact-apply control plane"
                    )
                    self._state_event_inbox_consecutive_crash_count = 0
                    observe_state_owner_health(
                        pod=self.instance_id,
                        loop_ok_at=time.time(),
                        consecutive_crash_count=0,
                    )
                    self._mark_loop_heartbeat("state_event_inbox")
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
        del db
        return None

    def _acquire_task_state_lease(self: TaskManager, db: Session, task_id: str, *, operation: str = "state_reduce") -> str | None:
        del db, task_id, operation
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
        del db, task_id, token, operation, held_started

    async def _reduce_state_event(self: TaskManager, event_id: str) -> None:
        from app.service import task_manager as task_manager_module

        task_manager_module.logger.info(
            "binary-security compat state event replay started: event_id=%s",
            event_id,
        )
        started = time.perf_counter()
        db = task_manager_module.get_session_factory()()
        event: task_manager_module.BinarySecurityStateEvent | None = None
        result = "unknown"
        try:
            event = db.query(task_manager_module.BinarySecurityStateEvent).filter(task_manager_module.BinarySecurityStateEvent.id == event_id).first()
            if event is None or event.status != "processing" or event.leased_by != self.instance_id:
                result = "skipped"
                return
            task = db.query(task_manager_module.BinarySecurityTask).filter(
                task_manager_module.BinarySecurityTask.id == event.task_id
            ).first()
            if task is not None:
                runtime_lease = self._runtime_lease_for_task(db, task.id)
                lease_owner = str(getattr(runtime_lease, "owner_instance_id", "") or "").strip()
                dispatcher_owner = str(getattr(task, "dispatcher_instance_id", "") or "").strip()
                local_owner_active = bool(
                    (lease_owner == str(self.instance_id or "").strip() and self._runtime_lease_is_active(runtime_lease))
                    or (
                        dispatcher_owner == str(self.instance_id or "").strip()
                        and self._lease_is_active(task, db=db)
                    )
                )
                foreign_owner_active = bool(
                    (lease_owner and lease_owner != str(self.instance_id or "").strip() and self._runtime_lease_is_active(runtime_lease))
                    or (
                        dispatcher_owner
                        and dispatcher_owner != str(self.instance_id or "").strip()
                        and self._lease_is_active(task, db=db)
                    )
                )
                if (
                    not local_owner_active
                    and str(getattr(task, "status", "") or "").strip() not in task_manager_module.TASK_TERMINAL_STATUSES
                ):
                    finished_at = task_shared._now()
                    event.status = "processed"
                    event.available_at = finished_at
                    event.processed_at = finished_at
                    event.processing_finished_at = finished_at
                    event.processing_result = "owner_signal_requeued"
                    event.leased_by = None
                    event.lease_expires_at = None
                    event.error_message = None
                    event.last_error_message = None
                    event.updated_at = finished_at
                    self._request_task_layer_reconcile(
                        db,
                        task,
                        stage_name=event.stage_name,
                        source_event_type=event.event_type,
                        state_event_id=event.id,
                        reconcile_reason=(
                            "compat_state_event_forwarded_to_owner"
                            if foreign_owner_active
                            else "compat_state_event_requeued_for_owner"
                        ),
                        message=(
                            "兼容 state event replay 检测到外部 owner 仍然活跃，已转交 owner worker 串行收口"
                            if foreign_owner_active
                            else "兼容 state event replay 不再直接 apply 事实，已重新入队等待 owner worker 串行收口"
                        ),
                        event_type="owned_execution_takeover_requeued",
                        event_level="warning",
                        event_payload={
                            "compat_replay_forwarded": True,
                            "compat_replay_owner_only": True,
                            "owner_apply_required": True,
                            "forward_reason": "foreign_owner_active" if foreign_owner_active else "owner_not_active_on_replay_path",
                            "runtime_lease_owner": lease_owner or None,
                            "dispatcher_instance_id": dispatcher_owner or None,
                        },
                    )
                    observe_state_owner_event(event.event_type, "forwarded")
                    observe_state_owner_health(pod=self.instance_id, event_processed_at=time.time())
                    result = "forwarded"
                    db.commit()
                    return
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
            task_manager_module.logger.exception("binary-security compat state event replay failed: event=%s", event_id)
        finally:
            db.close()
            observe_state_owner_run(result=result, pod=self.instance_id, duration_seconds=time.perf_counter() - started)

    async def _apply_state_event_locked(self: TaskManager, db: Session, event: BinarySecurityStateEvent) -> None:
        await self._apply_compat_state_event_via_owner_fact_apply(db, event)

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
            repaired_at = task_shared._now()
            previous_processing_result = str(getattr(event, "processing_result", "") or "").strip() or None
            previous_status = str(getattr(event, "status", "") or "").strip() or None
            event.status = "processed"
            event.available_at = repaired_at
            event.leased_by = None
            event.lease_expires_at = None
            event.processed_at = repaired_at
            event.processing_finished_at = repaired_at
            event.processing_result = "owner_signal_requeued"
            event.updated_at = repaired_at
            self._request_task_layer_reconcile(
                db,
                task,
                stage_name=event.stage_name,
                source_event_type=event.event_type,
                state_event_id=event.id,
                reconcile_reason="legacy_retryable_state_event_repaired",
                message="检测到历史 retryable/dead-letter state event，已转交 owner worker 串行收口",
                event_type="owned_execution_takeover_requeued",
                event_level="warning",
                event_payload={
                    "legacy_state_event_status": previous_status,
                    "legacy_processing_result": previous_processing_result,
                    "resolution_reason": "retryable_or_dead_letter_state_event",
                },
            )
            self._record_event(
                db,
                task,
                "task_state_repair_reconcile_triggered",
                "检测到 retryable/dead-letter state event inbox 事件，已转交 owner worker 修复",
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
