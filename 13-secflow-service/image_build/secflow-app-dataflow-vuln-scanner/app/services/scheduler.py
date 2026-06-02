from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
from collections import deque
import threading
import time
from datetime import timedelta
from typing import Any, Dict, List

from fastapi import HTTPException, status
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import (
    RunIndex,
    SchedulerWorker,
    SchedulerWorkerSlotReservation,
    TriggerTask,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.observability.service_ops import observe_service_operation
from app.schemas import (
    SchedulerWorkerResponse,
    WorkerActiveJobResponse,
    WorkerClusterCapacityResponse,
    WorkerClusterCapacitySummaryResponse,
    WorkerClusterWorkerResponse,
)
from app.services.dataflow_worker_client import DataflowWorkerError, get_dataflow_worker_client
from app.services.execution_service import get_execution_service
from app.services.runtime_config_service import get_runtime_config_service
from app.time_utils import now_local

logger = logging.getLogger(__name__)

ACTIVE_JOB_STATUSES = {"queued", "pending", "dispatching", "starting", "running", "cancel_requested", "delete_requested"}
TERMINAL_EXECUTION_STATUSES = {"succeeded", "failed", "cancelled"}
WORKER_SLOT_OCCUPYING_DISPATCH_STATUSES = {"queued", "dispatching", "starting", "running", "cancel_requested", "delete_requested"}
WORKER_SLOT_OCCUPYING_EXECUTION_STATUSES = {"dispatching", "starting", "running", "cancel_requested", "delete_requested"}


@dataclasses.dataclass
class WorkerLoadSnapshot:
    worker_id: str
    capacity: int
    healthy: bool
    execution_ids: set[str] = dataclasses.field(default_factory=set)
    running_execution_ids: set[str] = dataclasses.field(default_factory=set)
    sources: dict[str, set[str]] = dataclasses.field(default_factory=lambda: {"db": set(), "worker": set(), "reservation": set()})
    probe_error: str | None = None

    @property
    def used_slots(self) -> int:
        return len(self.execution_ids)

    @property
    def running_jobs(self) -> int:
        return len(self.running_execution_ids)

    @property
    def available_slots(self) -> int:
        return max(self.capacity - self.used_slots, 0)


class SchedulerService:
    def __init__(self) -> None:
        self._started = False
        self._tasks: List[asyncio.Task] = []
        self._running_tasks: Dict[str, Any] = {}
        self._worker_status = "active"
        self._heartbeat_published = False
        self._cluster_capacity_summary_snapshot: WorkerClusterCapacitySummaryResponse | None = None
        self._cluster_capacity_summary_snapshot_at = None
        self._cluster_capacity_summary_lock = threading.Lock()
        self._active_reconcile_running = False
        self._execution_health_lock = threading.Lock()
        self._startup_failure_timestamps: deque[float] = deque()
        self._stale_without_pid_timestamps: deque[float] = deque()
        self._requeued_before_process_start_timestamps: deque[float] = deque()
        self._degraded_until_monotonic: float = 0.0
        self._dispatch_backoff_lock = threading.Lock()
        self._dispatch_backoff_until_by_execution: dict[str, float] = {}
        self._dispatch_backoff_attempts_by_execution: dict[str, int] = {}
        self._worker_cooldown_until_by_pod: dict[str, float] = {}
        self._worker_snapshot_cache_lock = threading.Lock()
        self._worker_snapshot_cache: dict[tuple[str, bool], tuple[float, dict[str, WorkerLoadSnapshot]]] = {}
        self._dispatch_capacity_conflict_total = 0
        self._dispatch_backoff_scheduled_total = 0
        self._dispatch_skipped_due_to_backoff_total = 0

    @property
    def role(self) -> str:
        role = str(get_config().scheduler.role or "standalone").strip().lower()
        return role if role in {"standalone", "api", "manager", "worker"} else "standalone"

    @property
    def is_worker_role(self) -> bool:
        return self.role in {"standalone", "worker"}

    @property
    def is_http_worker_role(self) -> bool:
        return self.role in {"worker", "standalone"}

    @property
    def is_manager_role(self) -> bool:
        return self.role in {"standalone", "manager"}

    @property
    def runs_worker(self) -> bool:
        return get_config().scheduler.enabled and self.is_worker_role

    @property
    def runs_manager(self) -> bool:
        return get_config().scheduler.enabled and self.role in {"standalone", "manager"}

    @property
    def pod_id(self) -> str:
        return get_config().scheduler.pod_id

    @property
    def host_name(self) -> str:
        return get_config().scheduler.host_name

    @property
    def capacity(self) -> int:
        db = get_db_session()
        try:
            cfg = get_runtime_config_service().get_config(db)
            return int((((cfg or {}).get("scheduler") or {}).get("worker_capacity")) or get_config().scheduler.worker_capacity)
        except Exception:
            return get_config().scheduler.worker_capacity
        finally:
            db.close()

    @property
    def has_unlimited_capacity(self) -> bool:
        return self.capacity <= 0

    def has_available_capacity(self) -> bool:
        return self.has_unlimited_capacity or self.local_running_count() < self.capacity

    def _execution_health_window_seconds(self) -> int:
        return max(60, int(get_config().scheduler.execution_health_window_seconds or 600))

    def _execution_degraded_cooldown_seconds(self) -> int:
        return max(60, int(get_config().scheduler.execution_degraded_cooldown_seconds or 600))

    def _prune_execution_health_samples_locked(self, now_monotonic: float) -> None:
        cutoff = now_monotonic - self._execution_health_window_seconds()
        for bucket in (
            self._startup_failure_timestamps,
            self._stale_without_pid_timestamps,
            self._requeued_before_process_start_timestamps,
        ):
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

    def _execution_health_snapshot(self) -> dict[str, Any]:
        with self._execution_health_lock:
            now_monotonic = time.monotonic()
            self._prune_execution_health_samples_locked(now_monotonic)
            return {
                "queued_without_process_count": len(self._stale_without_pid_timestamps),
                "startup_fail_count": len(self._startup_failure_timestamps),
                "requeued_before_process_start_count": len(self._requeued_before_process_start_timestamps),
                "stale_without_pid_count": len(self._stale_without_pid_timestamps),
                "degraded": self._degraded_until_monotonic > now_monotonic,
            }

    def _restore_worker_execution_health_if_ready(self) -> None:
        should_restore = False
        with self._execution_health_lock:
            now_monotonic = time.monotonic()
            self._prune_execution_health_samples_locked(now_monotonic)
            if self._worker_status == "degraded" and self._degraded_until_monotonic and now_monotonic >= self._degraded_until_monotonic:
                self._degraded_until_monotonic = 0.0
                should_restore = True
        if should_restore:
            self._worker_status = "active"

    def _record_execution_health_sample(self, bucket_name: str, *, reason: str, payload: dict[str, Any] | None = None) -> None:
        degrade = False
        snapshot: dict[str, Any] = {}
        with self._execution_health_lock:
            now_monotonic = time.monotonic()
            self._prune_execution_health_samples_locked(now_monotonic)
            bucket = {
                "startup_fail": self._startup_failure_timestamps,
                "stale_without_pid": self._stale_without_pid_timestamps,
                "requeued_before_process_start": self._requeued_before_process_start_timestamps,
            }[bucket_name]
            bucket.append(now_monotonic)
            startup_fail_count = len(self._startup_failure_timestamps)
            stale_without_pid_count = len(self._stale_without_pid_timestamps)
            requeue_count = len(self._requeued_before_process_start_timestamps)
            snapshot = {
                "startup_fail_count": startup_fail_count,
                "stale_without_pid_count": stale_without_pid_count,
                "requeued_before_process_start_count": requeue_count,
            }
            degrade = (
                self._worker_status == "active"
                and (
                    startup_fail_count >= max(1, int(get_config().scheduler.execution_degraded_consecutive_startup_failures or 3))
                    or stale_without_pid_count >= max(1, int(get_config().scheduler.execution_degraded_stale_without_pid_count or 5))
                )
            )
            if degrade:
                self._degraded_until_monotonic = now_monotonic + self._execution_degraded_cooldown_seconds()
        if not degrade:
            return
        self._worker_status = "degraded"
        logger.warning(
            "worker execution health degraded pod=%s reason=%s startup_fail_count=%s stale_without_pid_count=%s requeue_count=%s",
            self.pod_id,
            reason,
            snapshot.get("startup_fail_count"),
            snapshot.get("stale_without_pid_count"),
            snapshot.get("requeued_before_process_start_count"),
        )
        try:
            self._heartbeat_once()
        except Exception:
            logger.exception("failed to publish worker degraded heartbeat")

    async def start(self) -> None:
        if self._started or not get_config().scheduler.enabled:
            return
        self._started = True
        self._worker_status = "active"
        self._tasks = []
        if self.runs_worker:
            await asyncio.to_thread(self._heartbeat_once)
            self._tasks.append(asyncio.create_task(self._heartbeat_loop(), name="scheduler-heartbeat"))
        if self.runs_worker and self.role == "standalone":
            self._tasks.extend(
                [
                    asyncio.create_task(self._dispatch_loop(), name="scheduler-dispatch"),
                ]
            )
        elif self.runs_worker and self.role == "worker":
            await asyncio.to_thread(self._start_assigned_jobs)
            self._tasks.append(asyncio.create_task(self._assigned_dispatch_loop(), name="scheduler-assigned-dispatch"))
        elif self.role == "manager":
            await asyncio.to_thread(self._dispatch_pending_to_workers_once)
            self._tasks.append(asyncio.create_task(self._manager_dispatch_loop(), name="scheduler-manager-dispatch"))
        if self.runs_manager or self.runs_worker:
            self._tasks.append(asyncio.create_task(self._cleanup_loop(), name="scheduler-cleanup"))
        if self.role in {"standalone", "api", "manager"}:
            self._tasks.append(asyncio.create_task(self._active_reconcile_loop(), name="scheduler-active-reconcile"))
        logger.info("scheduler started role=%s worker_enabled=%s capacity=%s", self.role, self.runs_worker, self.capacity)

    async def stop(self) -> None:
        if not self._started:
            return
        self._worker_status = "draining"
        if self.runs_worker:
            await asyncio.to_thread(self._heartbeat_once)
        self._started = False
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        if self.runs_worker:
            db = get_db_session()
            try:
                worker = db.get(SchedulerWorker, self.pod_id)
                if worker is not None:
                    worker.status = "offline"
                    worker.running_count = len(self._running_tasks)
                    worker.last_heartbeat_at = now_local()
                    db.add(worker)
                    db.commit()
            finally:
                db.close()

    def health_payload(self) -> Dict[str, str]:
        return {
            "status": "ok",
            "pod_id": self.pod_id,
            "database": "ok",
            "scheduler": "running" if self._started else "stopped",
            "scheduler_role": self.role,
            "worker_enabled": "true" if self.runs_worker else "false",
        }

    def advertise_url(self) -> str:
        template = str(get_config().dataflow_worker.advertise_url_template or "").strip()
        scheduler_cfg = get_config().scheduler
        if template:
            return template.format(
                pod_id=self.pod_id,
                host_name=self.host_name,
                pod_namespace=scheduler_cfg.pod_namespace,
                headless_service_name=scheduler_cfg.worker_headless_service_name,
            ).rstrip("/")
        return (
            f"http://{self.pod_id}."
            f"{scheduler_cfg.worker_headless_service_name}."
            f"{scheduler_cfg.pod_namespace}.svc.cluster.local:8080"
        )

    def local_running_count(self) -> int:
        return len(self._running_tasks)

    def _now_monotonic(self) -> float:
        return time.monotonic()

    def _dispatch_backoff_initial_seconds(self) -> int:
        return max(60, int(get_config().scheduler.dispatch_capacity_backoff_initial_seconds or 60))

    def _dispatch_backoff_max_seconds(self) -> int:
        return max(self._dispatch_backoff_initial_seconds(), int(get_config().scheduler.dispatch_capacity_backoff_max_seconds or 60))

    def _worker_capacity_cooldown_seconds(self) -> int:
        return max(60, int(get_config().scheduler.worker_capacity_cooldown_seconds or 60))

    def _worker_snapshot_cache_ttl_seconds(self) -> int:
        return max(1, int(get_config().scheduler.worker_snapshot_cache_ttl_seconds or 3))

    def _prune_dispatch_backoff_locked(self, now_monotonic: float) -> None:
        expired_execution_ids = [
            execution_id
            for execution_id, deadline in self._dispatch_backoff_until_by_execution.items()
            if deadline <= now_monotonic
        ]
        for execution_id in expired_execution_ids:
            self._dispatch_backoff_until_by_execution.pop(execution_id, None)
            self._dispatch_backoff_attempts_by_execution.pop(execution_id, None)
        expired_worker_ids = [
            worker_id
            for worker_id, deadline in self._worker_cooldown_until_by_pod.items()
            if deadline <= now_monotonic
        ]
        for worker_id in expired_worker_ids:
            self._worker_cooldown_until_by_pod.pop(worker_id, None)

    def _execution_dispatch_backoff_remaining_seconds(self, execution_id: str) -> float:
        execution_key = str(execution_id or "").strip()
        if not execution_key:
            return 0.0
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_key)
            if execution is not None and execution.dispatch_backoff_until is not None:
                return max((execution.dispatch_backoff_until - now_local()).total_seconds(), 0.0)
        finally:
            db.close()
        with self._dispatch_backoff_lock:
            now_monotonic = self._now_monotonic()
            self._prune_dispatch_backoff_locked(now_monotonic)
            deadline = self._dispatch_backoff_until_by_execution.get(execution_key)
            if not deadline:
                return 0.0
            return max(deadline - now_monotonic, 0.0)

    def _worker_in_dispatch_cooldown(self, worker_pod_id: str) -> bool:
        worker_key = str(worker_pod_id or "").strip()
        if not worker_key:
            return False
        with self._dispatch_backoff_lock:
            now_monotonic = self._now_monotonic()
            self._prune_dispatch_backoff_locked(now_monotonic)
            deadline = self._worker_cooldown_until_by_pod.get(worker_key)
            return bool(deadline and deadline > now_monotonic)

    def _schedule_dispatch_backoff(
        self,
        execution_id: str,
        *,
        reason: str,
        worker_pod_id: str | None = None,
        payload_extra: dict[str, Any] | None = None,
    ) -> None:
        execution_key = str(execution_id or "").strip()
        if not execution_key:
            return
        now_monotonic = self._now_monotonic()
        with self._dispatch_backoff_lock:
            self._prune_dispatch_backoff_locked(now_monotonic)
            attempts = int(self._dispatch_backoff_attempts_by_execution.get(execution_key, 0)) + 1
            self._dispatch_backoff_attempts_by_execution[execution_key] = attempts
            backoff_seconds = min(
                self._dispatch_backoff_initial_seconds() * (2 ** max(attempts - 1, 0)),
                self._dispatch_backoff_max_seconds(),
            )
            deadline = now_monotonic + backoff_seconds
            self._dispatch_backoff_until_by_execution[execution_key] = deadline
            if worker_pod_id:
                self._worker_cooldown_until_by_pod[str(worker_pod_id)] = now_monotonic + self._worker_capacity_cooldown_seconds()
            self._dispatch_backoff_scheduled_total += 1
        logger.info(
            "dispatch backoff scheduled execution=%s worker=%s backoff_seconds=%s reason=%s",
            execution_key,
            worker_pod_id,
            backoff_seconds,
            reason,
        )
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_key)
            if execution is not None:
                execution.dispatch_backoff_until = now_local() + timedelta(seconds=backoff_seconds)
                execution.dispatch_backoff_reason = reason
                execution.dispatch_backoff_attempt = attempts
                execution.status = "pending"
                execution.public_status = "pending"
                execution.dispatch_status = None
                execution.owner_pod_id = None
                execution.worker_job_id = None
                execution.worker_url = None
                trigger = db.get(TriggerTask, execution.trigger_task_id)
                if trigger is not None and str(trigger.status or "").strip().lower() in {"pending", "dispatching", "running"}:
                    trigger.status = "pending"
                    trigger.public_status = "pending"
                    trigger.message = execution.message or f"dispatch backoff scheduled: {reason}"
                    db.add(trigger)
                db.add(execution)
                db.commit()
            if self._has_recent_dispatch_backoff_event(db, execution_key, worker_pod_id, reason):
                return
            payload_json = {
                "reason": reason,
                "worker_pod_id": worker_pod_id,
                "backoff_seconds": backoff_seconds,
                "backoff_until": execution.dispatch_backoff_until.isoformat() if execution is not None and execution.dispatch_backoff_until is not None else None,
                "attempt": attempts,
            }
            if payload_extra:
                payload_json.update(payload_extra)
            get_execution_service().record_event(
                db,
                execution_id=execution_key,
                event_type="dispatch_backoff_scheduled",
                message=f"dispatch backoff scheduled: {reason}",
                level="warning",
                payload_json=payload_json,
            )
        finally:
            db.close()

    def _clear_dispatch_backoff(self, execution_id: str) -> None:
        execution_key = str(execution_id or "").strip()
        if not execution_key:
            return
        with self._dispatch_backoff_lock:
            self._dispatch_backoff_until_by_execution.pop(execution_key, None)
            self._dispatch_backoff_attempts_by_execution.pop(execution_key, None)
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_key)
            if execution is None:
                return
            execution.dispatch_backoff_until = None
            execution.dispatch_backoff_reason = None
            execution.dispatch_backoff_attempt = 0
            db.add(execution)
            db.commit()
        finally:
            db.close()

    def _has_recent_dispatch_backoff_event(
        self,
        db: Session,
        execution_id: str,
        worker_pod_id: str | None,
        reason: str,
    ) -> bool:
        threshold = now_local() - timedelta(seconds=30)
        events = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == execution_id,
                WorkflowExecutionEvent.event_type == "dispatch_backoff_scheduled",
                WorkflowExecutionEvent.created_at >= threshold,
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .limit(5)
            .all()
        )
        for event in events:
            payload = event.payload_json or {}
            if str(payload.get("worker_pod_id") or "") == str(worker_pod_id or "") and str(payload.get("reason") or "") == str(reason or ""):
                return True
        return False

    def list_workers(self, db: Session) -> List[SchedulerWorkerResponse]:
        workers = db.query(SchedulerWorker).order_by(SchedulerWorker.last_heartbeat_at.desc()).all()
        return [SchedulerWorkerResponse.model_validate(item, from_attributes=True) for item in workers]

    def get_worker(self, db: Session, pod_id: str) -> SchedulerWorkerResponse:
        worker = db.get(SchedulerWorker, pod_id)
        if worker is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scheduler worker not found")
        return SchedulerWorkerResponse.model_validate(worker, from_attributes=True)

    def _cluster_capacity_base(
        self,
        db: Session,
    ) -> tuple[list[SchedulerWorker], Any, int]:
        workers = db.query(SchedulerWorker).order_by(SchedulerWorker.last_heartbeat_at.desc(), SchedulerWorker.pod_id.asc()).all()
        worker_timeout_at = now_local() - timedelta(seconds=get_config().scheduler.worker_timeout_seconds)
        queued_jobs = (
            db.query(WorkflowExecution)
            .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
            .join(WorkflowDefinition, WorkflowExecution.workflow_definition_id == WorkflowDefinition.id)
            .filter(
                ~WorkflowExecution.status.in_(tuple(TERMINAL_EXECUTION_STATUSES)),
                TriggerTask.status.in_(["pending", "dispatching", "running", "cancel_requested", "delete_requested"]),
                WorkflowDefinition.enabled.is_(True),
                or_(
                    WorkflowExecution.status == "pending",
                    WorkflowExecution.dispatch_status.in_(["dispatching", "queued"]),
                ),
            )
            .count()
        )
        return workers, worker_timeout_at, queued_jobs

    @staticmethod
    def _active_execution_filter():
        return and_(
            ~WorkflowExecution.status.in_(tuple(TERMINAL_EXECUTION_STATUSES)),
            or_(
                WorkflowExecution.status.in_(tuple(ACTIVE_JOB_STATUSES)),
                WorkflowExecution.dispatch_status.in_(tuple(ACTIVE_JOB_STATUSES)),
            ),
        )

    def _running_count_for_worker(self, db: Session, pod_id: str, *, exclude_execution_id: str | None = None) -> int:
        query = db.query(WorkflowExecution).filter(
            WorkflowExecution.owner_pod_id == pod_id,
            self._active_execution_filter(),
        )
        if exclude_execution_id:
            query = query.filter(WorkflowExecution.id != exclude_execution_id)
        return int(query.count() or 0)

    def _started_count_for_worker(self, db: Session, pod_id: str) -> int:
        return int(
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.owner_pod_id == pod_id,
                WorkflowExecution.status.in_(["starting", "running", "cancel_requested", "delete_requested"]),
            )
            .count()
            or 0
        )

    def _reservation_query(self, db: Session):
        return db.query(SchedulerWorkerSlotReservation).filter(SchedulerWorkerSlotReservation.lease_expires_at >= now_local())

    def _release_reservation(self, db: Session, execution_id: str) -> None:
        (
            db.query(SchedulerWorkerSlotReservation)
            .filter(SchedulerWorkerSlotReservation.execution_id == execution_id)
            .delete(synchronize_session=False)
        )

    def _add_execution_to_snapshot(self, snapshot: WorkerLoadSnapshot, execution_id: str, source: str, *, running: bool = False) -> None:
        if not execution_id:
            return
        snapshot.execution_ids.add(execution_id)
        snapshot.sources.setdefault(source, set()).add(execution_id)
        if running:
            snapshot.running_execution_ids.add(execution_id)

    def _build_worker_load_snapshots(
        self,
        db: Session,
        workers: list[SchedulerWorker],
        *,
        include_worker_jobs: bool,
    ) -> dict[str, WorkerLoadSnapshot]:
        cache_key = (
            ",".join(sorted(str(worker.pod_id) for worker in workers)),
            bool(include_worker_jobs),
        )
        now_monotonic = self._now_monotonic()
        with self._worker_snapshot_cache_lock:
            cached = self._worker_snapshot_cache.get(cache_key)
            if cached is not None:
                cached_at, cached_value = cached
                if now_monotonic - cached_at < self._worker_snapshot_cache_ttl_seconds():
                    return {
                        worker_id: dataclasses.replace(snapshot)
                        for worker_id, snapshot in cached_value.items()
                    }

        worker_timeout_at = now_local() - timedelta(seconds=get_config().scheduler.worker_timeout_seconds)
        snapshots: dict[str, WorkerLoadSnapshot] = {}
        for worker in workers:
            worker_id = str(worker.pod_id)
            healthy = bool(worker.last_heartbeat_at and worker.last_heartbeat_at >= worker_timeout_at and worker.status == "active")
            snapshots[worker_id] = WorkerLoadSnapshot(
                worker_id=worker_id,
                capacity=max(int(worker.capacity or 0), 0),
                healthy=healthy,
            )

        if not snapshots:
            return snapshots

        active_executions = (
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.owner_pod_id.in_(list(snapshots.keys())),
                ~WorkflowExecution.status.in_(tuple(TERMINAL_EXECUTION_STATUSES)),
                or_(
                    WorkflowExecution.status.in_(tuple(WORKER_SLOT_OCCUPYING_EXECUTION_STATUSES | {"pending"})),
                    WorkflowExecution.dispatch_status.in_(tuple(WORKER_SLOT_OCCUPYING_DISPATCH_STATUSES)),
                ),
            )
            .all()
        )
        for execution in active_executions:
            owner_pod_id = str(execution.owner_pod_id or "").strip()
            snapshot = snapshots.get(owner_pod_id)
            if snapshot is None:
                continue
            if not owner_pod_id:
                continue
            running = str(execution.status or "").strip().lower() == "running" or str(execution.dispatch_status or "").strip().lower() == "running"
            self._add_execution_to_snapshot(snapshot, str(execution.id), "db", running=running)

        reservations = self._reservation_query(db).all()
        for reservation in reservations:
            worker_id = str(reservation.worker_pod_id or "").strip()
            snapshot = snapshots.get(worker_id)
            if snapshot is None:
                continue
            execution = db.get(WorkflowExecution, reservation.execution_id)
            if execution is not None:
                dispatch_status = str(execution.dispatch_status or "").strip().lower()
                if execution.worker_job_id and dispatch_status in WORKER_SLOT_OCCUPYING_DISPATCH_STATUSES:
                    continue
            self._add_execution_to_snapshot(snapshot, str(reservation.execution_id), "reservation")

        if not include_worker_jobs:
            return snapshots

        for worker in workers:
            worker_id = str(worker.pod_id)
            snapshot = snapshots[worker_id]
            worker_url = self._worker_url_from_registry(worker)
            if not worker_url or not snapshot.healthy:
                continue
            try:
                jobs = get_dataflow_worker_client(worker_url).list_jobs()
            except Exception as exc:
                snapshot.probe_error = str(exc)
                continue
            for job in jobs:
                if not isinstance(job, dict) or not self._job_is_active(job):
                    continue
                execution_id = str(job.get("execution_id") or job.get("id") or "").strip()
                if not execution_id:
                    continue
                running = str(job.get("status") or "").strip().lower() == "running"
                self._add_execution_to_snapshot(snapshot, execution_id, "worker", running=running)
        with self._worker_snapshot_cache_lock:
            self._worker_snapshot_cache[cache_key] = (
                now_monotonic,
                {
                    worker_id: dataclasses.replace(snapshot)
                    for worker_id, snapshot in snapshots.items()
                },
            )
        return snapshots

    def _compute_cluster_capacity_summary(self, db: Session) -> WorkerClusterCapacitySummaryResponse:
        started = time.perf_counter()
        workers, worker_timeout_at, queued_jobs = self._cluster_capacity_base(db)
        snapshots = self._build_worker_load_snapshots(db, workers, include_worker_jobs=False)
        worker_rows: list[WorkerClusterWorkerResponse] = []
        total_capacity = 0
        total_running = 0
        total_used = 0
        total_schedulable = 0
        healthy_workers = 0
        stale_workers = 0

        for worker in workers:
            heartbeat_healthy = bool(worker.last_heartbeat_at and worker.last_heartbeat_at >= worker_timeout_at and worker.status == "active")
            capacity = max(int(worker.capacity or 0), 0)
            snapshot = snapshots.get(str(worker.pod_id)) or WorkerLoadSnapshot(worker_id=str(worker.pod_id), capacity=capacity, healthy=heartbeat_healthy)
            running_jobs = snapshot.running_jobs
            used_slots = snapshot.used_slots
            available_slots = snapshot.available_slots if heartbeat_healthy else 0
            healthy = heartbeat_healthy
            if healthy:
                healthy_workers += 1
                total_schedulable += available_slots
            else:
                stale_workers += 1
            total_capacity += capacity
            total_running += running_jobs
            total_used += used_slots
            worker_rows.append(
                WorkerClusterWorkerResponse(
                    worker_id=str(worker.pod_id),
                    host_name=str(worker.host_name or worker.pod_id),
                    healthy=healthy,
                    max_concurrent_jobs=capacity,
                    running_jobs=running_jobs,
                    used_slots=used_slots,
                    available_slots=available_slots,
                    schedulable_slots=available_slots,
                    source="scheduler_worker",
                    last_heartbeat_at=worker.last_heartbeat_at,
                    error=None if healthy else "worker heartbeat stale or worker status inactive",
                    active_jobs=[],
                )
            )

        response = WorkerClusterCapacitySummaryResponse(
            worker_count=len(worker_rows),
            healthy_workers=healthy_workers,
            stale_workers=stale_workers,
            total_capacity=total_capacity,
            running_jobs=total_running,
            used_slots=total_used,
            queued_jobs=queued_jobs,
            available_slots=total_schedulable,
            schedulable_slots=total_schedulable,
            updated_at=now_local(),
            workers=worker_rows,
            detail_mode="summary",
        )
        observe_service_operation("cluster_capacity_summary", max(time.perf_counter() - started, 0.0))
        return response

    def _cluster_capacity_summary_snapshot_copy(self) -> WorkerClusterCapacitySummaryResponse | None:
        with self._cluster_capacity_summary_lock:
            snapshot = self._cluster_capacity_summary_snapshot
            return snapshot.model_copy(deep=True) if snapshot is not None else None

    def _cluster_capacity_summary_snapshot_stale(self) -> bool:
        with self._cluster_capacity_summary_lock:
            if self._cluster_capacity_summary_snapshot_at is None:
                return True
            age = (now_local() - self._cluster_capacity_summary_snapshot_at).total_seconds()
            return age >= 30

    def dispatch_backoff_metrics(self) -> dict[str, Any]:
        with self._dispatch_backoff_lock:
            now_monotonic = self._now_monotonic()
            self._prune_dispatch_backoff_locked(now_monotonic)
            return {
                "capacity_conflict_total": self._dispatch_capacity_conflict_total,
                "backoff_scheduled_total": self._dispatch_backoff_scheduled_total,
                "skipped_due_to_backoff_total": self._dispatch_skipped_due_to_backoff_total,
                "active_execution_backoffs": len(self._dispatch_backoff_until_by_execution),
                "active_worker_cooldowns": len(self._worker_cooldown_until_by_pod),
            }

    def _set_cluster_capacity_summary_snapshot(
        self,
        snapshot: WorkerClusterCapacitySummaryResponse,
    ) -> WorkerClusterCapacitySummaryResponse:
        copied = snapshot.model_copy(deep=True)
        with self._cluster_capacity_summary_lock:
            self._cluster_capacity_summary_snapshot = copied
            self._cluster_capacity_summary_snapshot_at = now_local()
        return copied.model_copy(deep=True)

    def _refresh_cluster_capacity_summary_snapshot(
        self,
        db: Session,
    ) -> WorkerClusterCapacitySummaryResponse:
        return self._set_cluster_capacity_summary_snapshot(self._compute_cluster_capacity_summary(db))

    def get_cluster_capacity_summary(self, db: Session) -> WorkerClusterCapacitySummaryResponse:
        snapshot = self._cluster_capacity_summary_snapshot_copy()
        if snapshot is not None and not self._cluster_capacity_summary_snapshot_stale():
            return snapshot
        refreshed = self._refresh_cluster_capacity_summary_snapshot(db)
        return refreshed

    def get_cluster_capacity(self, db: Session) -> WorkerClusterCapacityResponse:
        started = time.perf_counter()
        workers, worker_timeout_at, queued_jobs = self._cluster_capacity_base(db)
        snapshots = self._build_worker_load_snapshots(db, workers, include_worker_jobs=False)
        worker_rows: list[WorkerClusterWorkerResponse] = []
        active_executions = (
            db.query(WorkflowExecution, TriggerTask, RunIndex)
            .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
            .outerjoin(RunIndex, RunIndex.linked_execution_id == WorkflowExecution.id)
            .filter(self._active_execution_filter())
            .all()
        )
        execution_map: dict[str, tuple[WorkflowExecution, TriggerTask, RunIndex | None]] = {}
        for execution, trigger, run_index in active_executions:
            execution_map[str(execution.id)] = (execution, trigger, run_index)

        total_capacity = 0
        total_running = 0
        total_used = 0
        total_schedulable = 0
        healthy_workers = 0
        stale_workers = 0
        for worker in workers:
            heartbeat_healthy = bool(worker.last_heartbeat_at and worker.last_heartbeat_at >= worker_timeout_at and worker.status == "active")
            snapshot = snapshots.get(str(worker.pod_id)) or WorkerLoadSnapshot(
                worker_id=str(worker.pod_id),
                capacity=max(int(worker.capacity or 0), 0),
                healthy=heartbeat_healthy,
            )
            try:
                jobs = self._list_worker_jobs_for_capacity(worker)
                active_jobs = [self._build_active_job_payload(job, execution_map) for job in jobs if self._job_is_active(job)]
                active_jobs.sort(key=lambda item: item.started_at or item.updated_at or now_local())
                error = snapshot.probe_error
            except Exception as exc:
                logger.exception("failed to probe worker jobs for cluster capacity: pod_id=%s", worker.pod_id)
                active_jobs = []
                error = str(exc)
            healthy = heartbeat_healthy and error is None
            if healthy:
                healthy_workers += 1
                total_schedulable += snapshot.available_slots
            else:
                stale_workers += 1
            running_jobs = snapshot.running_jobs
            used_slots = snapshot.used_slots
            capacity = max(int(worker.capacity or 0), 0)
            available_slots = snapshot.available_slots if healthy else 0
            total_capacity += capacity
            total_running += running_jobs
            total_used += used_slots
            worker_rows.append(
                WorkerClusterWorkerResponse(
                    worker_id=str(worker.pod_id),
                    host_name=str(worker.host_name or worker.pod_id),
                    healthy=healthy,
                    max_concurrent_jobs=capacity,
                    running_jobs=running_jobs,
                    used_slots=used_slots,
                    available_slots=available_slots,
                    schedulable_slots=available_slots,
                    source="scheduler_worker",
                    last_heartbeat_at=worker.last_heartbeat_at,
                    error=error,
                    active_jobs=active_jobs,
                )
            )

        response = WorkerClusterCapacityResponse(
            worker_count=len(worker_rows),
            healthy_workers=healthy_workers,
            stale_workers=stale_workers,
            total_capacity=total_capacity,
            running_jobs=total_running,
            used_slots=total_used,
            queued_jobs=queued_jobs,
            available_slots=total_schedulable,
            schedulable_slots=total_schedulable,
            updated_at=now_local(),
            workers=worker_rows,
        )
        observe_service_operation("cluster_capacity_detail", max(time.perf_counter() - started, 0.0))
        return response

    def set_worker_status(self, db: Session, pod_id: str, status_value: str) -> None:
        worker = db.get(SchedulerWorker, pod_id)
        if worker is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scheduler worker not found")
        worker.status = status_value
        worker.last_heartbeat_at = now_local()
        db.add(worker)
        db.commit()
        if pod_id == self.pod_id:
            self._worker_status = status_value

    async def _heartbeat_loop(self) -> None:
        interval = get_config().scheduler.heartbeat_interval_seconds
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self._heartbeat_once)

    def _heartbeat_once(self) -> None:
        if not self.runs_worker:
            return
        self._restore_worker_execution_health_if_ready()
        db = get_db_session()
        try:
            worker = db.get(SchedulerWorker, self.pod_id)
            now = now_local()
            first_heartbeat = not self._heartbeat_published
            metadata_json = {
                "service": "secflow-app-dataflow-vuln-scanner",
                "role": self.role,
                "advertise_url": self.advertise_url(),
                "execution_health": self._execution_health_snapshot(),
            }
            if worker is None:
                worker = SchedulerWorker(
                    pod_id=self.pod_id,
                    host_name=self.host_name,
                    capacity=self.capacity,
                    running_count=len(self._running_tasks),
                    last_heartbeat_at=now,
                    status=self._worker_status,
                    metadata_json=metadata_json,
                )
            else:
                # Do not inherit stale DB "draining" on process startup; a restarted
                # worker should come back active unless it receives a fresh drain.
                if (
                    not first_heartbeat
                    and self._worker_status not in {"draining", "offline"}
                    and worker.status in {"active", "draining"}
                ):
                    self._worker_status = worker.status
                worker.host_name = self.host_name
                worker.capacity = self.capacity
                worker.running_count = len(self._running_tasks)
                worker.last_heartbeat_at = now
                worker.status = self._worker_status
                worker.metadata_json = metadata_json
            db.add(worker)
            db.commit()
            self._heartbeat_published = True
        finally:
            db.close()

    async def _dispatch_loop(self) -> None:
        interval = get_config().scheduler.poll_interval_seconds
        while True:
            await asyncio.sleep(interval)
            if not self.runs_worker:
                continue
            if self._worker_status != "active":
                continue
            while self.has_available_capacity():
                execution_id = await asyncio.to_thread(self._claim_next_execution)
                if not execution_id:
                    break
                self._schedule_execution(execution_id)

    async def _assigned_dispatch_loop(self) -> None:
        interval = get_config().scheduler.poll_interval_seconds
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self._start_assigned_jobs)

    async def _manager_dispatch_loop(self) -> None:
        interval = get_config().scheduler.poll_interval_seconds
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self._dispatch_pending_to_workers_once)

    def _dispatch_pending_to_workers_once(self) -> None:
        if not self.is_manager_role:
            return
        for execution_id in self._pending_worker_dispatch_execution_ids():
            try:
                self._dispatch_execution_to_worker(execution_id)
            except Exception:
                logger.exception("manager failed to dispatch pending execution %s", execution_id)

    def _pending_worker_dispatch_execution_ids(self, limit: int | None = None) -> list[str]:
        db = get_db_session()
        try:
            query = (
                db.query(WorkflowExecution.id)
                .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
                .join(WorkflowDefinition, WorkflowExecution.workflow_definition_id == WorkflowDefinition.id)
                .filter(
                    WorkflowExecution.status == "pending",
                    WorkflowExecution.owner_pod_id.is_(None),
                    WorkflowExecution.worker_job_id.is_(None),
                    or_(WorkflowExecution.dispatch_status.is_(None), WorkflowExecution.dispatch_status == ""),
                    TriggerTask.status == "pending",
                    WorkflowDefinition.enabled.is_(True),
                )
                .order_by(TriggerTask.priority.desc(), TriggerTask.created_at.asc())
            )
            if limit is not None and limit > 0:
                query = query.limit(limit)
            rows = query.all()
            ready_execution_ids: list[str] = []
            for row in rows:
                execution_id = str(row[0])
                if self._execution_dispatch_backoff_remaining_seconds(execution_id) > 0:
                    with self._dispatch_backoff_lock:
                        self._dispatch_skipped_due_to_backoff_total += 1
                    continue
                ready_execution_ids.append(execution_id)
            return ready_execution_ids
        finally:
            db.close()

    def _start_assigned_jobs(self) -> None:
        if self.role != "worker" or self._worker_status != "active":
            return
        while True:
            if not self.has_unlimited_capacity:
                db = get_db_session()
                try:
                    current_running = self._started_count_for_worker(db, self.pod_id)
                    if current_running >= self.capacity:
                        break
                finally:
                    db.close()
            execution_id = self._claim_next_assigned_execution()
            if not execution_id:
                break
            self._schedule_execution_thread(execution_id)

    def _claim_next_assigned_execution(self) -> str | None:
        db = get_db_session()
        try:
            candidate = (
                db.query(WorkflowExecution, TriggerTask)
                .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
                .filter(
                    WorkflowExecution.status.in_(["pending", "dispatching"]),
                    WorkflowExecution.owner_pod_id == self.pod_id,
                    WorkflowExecution.worker_job_id.isnot(None),
                    WorkflowExecution.dispatch_status.in_(["queued", "dispatching"]),
                    TriggerTask.status.in_(["pending", "dispatching"]),
                )
                .order_by(TriggerTask.priority.desc(), TriggerTask.created_at.asc())
                .first()
            )
            if candidate is None:
                return None
            execution, trigger = candidate
            return self._claim_assigned_execution(db, execution, trigger)
        finally:
            db.close()

    def _claim_assigned_execution(self, db: Session, execution: WorkflowExecution, trigger: TriggerTask) -> str | None:
        updated_execution = (
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.id == execution.id,
                WorkflowExecution.status.in_(["pending", "dispatching", "starting"]),
                WorkflowExecution.owner_pod_id == self.pod_id,
                WorkflowExecution.dispatch_status.in_(["queued", "dispatching"]),
            )
            .update(
                {
                    WorkflowExecution.status: "starting",
                    WorkflowExecution.dispatch_status: "starting",
                    WorkflowExecution.dispatch_error: None,
                    WorkflowExecution.message: f"starting on worker {self.pod_id}",
                },
                synchronize_session=False,
            )
        )
        updated_trigger = (
            db.query(TriggerTask)
            .filter(TriggerTask.id == trigger.id, TriggerTask.status.in_(["pending", "dispatching"]))
            .update(
                {
                    TriggerTask.status: "dispatching",
                    TriggerTask.message: f"starting on worker {self.pod_id}",
                },
                synchronize_session=False,
            )
        )
        if updated_execution != 1 or updated_trigger != 1:
            db.rollback()
            return None
        db.commit()
        get_execution_service().record_event(
            db,
            execution_id=execution.id,
            event_type="worker_job_starting",
            message=f"worker job starting on {self.pod_id}",
            payload_json={"worker_pod_id": self.pod_id, "dispatch_status_after": "starting"},
        )
        logger.info("starting assigned execution %s on worker %s", execution.id, self.pod_id)
        return execution.id

    def _claim_next_execution(self) -> str | None:
        if not self.is_worker_role:
            return None
        db = get_db_session()
        try:
            candidates = (
                db.query(WorkflowExecution, TriggerTask, WorkflowDefinition)
                .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
                .join(WorkflowDefinition, WorkflowExecution.workflow_definition_id == WorkflowDefinition.id)
                .filter(
                    WorkflowExecution.status == "pending",
                    TriggerTask.status == "pending",
                    WorkflowDefinition.enabled.is_(True),
                )
                .order_by(TriggerTask.priority.desc(), TriggerTask.created_at.asc())
                .limit(64)
                .all()
            )
            for execution, trigger, _definition in candidates:
                updated_execution = (
                    db.query(WorkflowExecution)
                    .filter(
                        WorkflowExecution.id == execution.id,
                        WorkflowExecution.status == "pending",
                        WorkflowExecution.owner_pod_id.is_(None),
                    )
                    .update(
                        {
                            WorkflowExecution.status: "starting",
                            WorkflowExecution.owner_pod_id: self.pod_id,
                            WorkflowExecution.dispatch_status: "starting",
                            WorkflowExecution.dispatch_error: None,
                            WorkflowExecution.message: f"starting by {self.pod_id}",
                        },
                        synchronize_session=False,
                    )
                )
                if updated_execution != 1:
                    db.rollback()
                    continue
                updated_trigger = (
                    db.query(TriggerTask)
                    .filter(TriggerTask.id == trigger.id, TriggerTask.status == "pending")
                    .update(
                        {
                            TriggerTask.status: "dispatching",
                            TriggerTask.message: f"starting by {self.pod_id}",
                        },
                        synchronize_session=False,
                    )
                )
                if updated_trigger != 1:
                    db.rollback()
                    continue
                db.commit()
                get_execution_service().record_event(
                    db,
                    execution_id=execution.id,
                    event_type="worker_job_starting",
                    message=f"worker job starting on {self.pod_id}",
                    payload_json={"worker_pod_id": self.pod_id, "mode": "standalone_claim", "dispatch_status_after": "starting"},
                )
                logger.info("starting execution %s on pod %s", execution.id, self.pod_id)
                return execution.id
            return None
        finally:
            db.close()

    def _claim_execution_now(self, execution_id: str) -> str | None:
        if not self.is_worker_role:
            return None
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None or execution.status != "pending" or execution.owner_pod_id is not None:
                return None
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is None or trigger.status != "pending":
                return None
            definition = db.get(WorkflowDefinition, execution.workflow_definition_id)
            if definition is None or not definition.enabled:
                return None
            updated_execution = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.id == execution_id,
                    WorkflowExecution.status == "pending",
                    WorkflowExecution.owner_pod_id.is_(None),
                )
                .update(
                    {
                        WorkflowExecution.status: "starting",
                        WorkflowExecution.owner_pod_id: self.pod_id,
                        WorkflowExecution.dispatch_status: "starting",
                        WorkflowExecution.dispatch_error: None,
                        WorkflowExecution.message: f"starting immediately by {self.pod_id}",
                    },
                    synchronize_session=False,
                )
            )
            updated_trigger = (
                db.query(TriggerTask)
                .filter(TriggerTask.id == trigger.id, TriggerTask.status == "pending")
                .update(
                    {
                        TriggerTask.status: "dispatching",
                        TriggerTask.message: f"starting immediately by {self.pod_id}",
                    },
                    synchronize_session=False,
                )
            )
            if updated_execution != 1 or updated_trigger != 1:
                db.rollback()
                return None
            db.commit()
            get_execution_service().record_event(
                db,
                execution_id=execution_id,
                event_type="worker_job_starting",
                message=f"worker job starting on {self.pod_id}",
                payload_json={"worker_pod_id": self.pod_id, "mode": "start_execution_now", "dispatch_status_after": "starting"},
            )
            logger.info("immediately starting execution %s on pod %s", execution_id, self.pod_id)
            return execution_id
        finally:
            db.close()

    def start_execution_now(self, execution_id: str | None) -> bool:
        if not execution_id or execution_id in self._running_tasks:
            return False
        if self.role == "standalone":
            if self._worker_status != "active" or not self.has_available_capacity():
                return False
            claimed_execution_id = self._claim_execution_now(execution_id)
            if not claimed_execution_id:
                return False
            self._schedule_execution_thread(claimed_execution_id)
            return True
        if self.role == "manager":
            return self._dispatch_execution_to_worker(execution_id)
        if self.role == "worker":
            return False
        if not self.is_worker_role:
            return False
        if self._worker_status != "active" or not self.has_available_capacity():
            return False
        claimed_execution_id = self._claim_execution_now(execution_id)
        if not claimed_execution_id:
            return False
        self._schedule_execution_thread(claimed_execution_id)
        return True

    def _dispatch_execution_to_worker(self, execution_id: str) -> bool:
        db = get_db_session()
        try:
            candidates = self._rank_dataflow_workers(db, execution_id)
        finally:
            db.close()

        if not candidates:
            self._schedule_dispatch_backoff(execution_id, reason="no_healthy_worker_available")
            return False

        attempts = max(1, int(get_config().dataflow_worker.dispatch_max_retries or 1))
        tried_worker_ids: set[str] = set()
        last_worker_url = ""
        last_worker_pod_id = ""
        last_error = ""
        capacity_errors: list[dict[str, str]] = []

        for worker_pod_id, worker_url in candidates:
            if worker_pod_id in tried_worker_ids:
                continue
            tried_worker_ids.add(worker_pod_id)
            last_worker_url = worker_url
            last_worker_pod_id = worker_pod_id
            if not self._reserve_dispatch_worker(execution_id, worker_pod_id, worker_url):
                return False

            for attempt in range(1, attempts + 1):
                try:
                    job = get_dataflow_worker_client(worker_url).create_job(
                        {
                            "execution_id": execution_id,
                            "worker_url": worker_url,
                            "worker_pod_id": worker_pod_id,
                        }
                    )
                    self._mark_dispatch_success(execution_id, worker_url, job)
                    return True
                except DataflowWorkerError as exc:
                    last_error = str(exc)
                    if self._is_capacity_exceeded_error(last_error):
                        with self._dispatch_backoff_lock:
                            self._dispatch_capacity_conflict_total += 1
                        capacity_errors.append({"worker_pod_id": worker_pod_id, "worker_url": worker_url, "error": last_error})
                        self._reset_dispatch_reservation(execution_id)
                        self._schedule_dispatch_backoff(
                            execution_id,
                            reason="capacity_exceeded",
                            worker_pod_id=worker_pod_id,
                            payload_extra={"worker_url": worker_url},
                        )
                        break
                    if attempt < attempts:
                        time.sleep(max(0, int(get_config().dataflow_worker.dispatch_retry_interval_seconds or 0)))
            else:
                self._mark_dispatch_failure(execution_id, worker_url, last_error or "dataflow worker dispatch failed", worker_pod_id=worker_pod_id)
                return False

        if capacity_errors:
            logger.info(
                "dispatch deferred after worker capacity conflicts execution=%s conflicts=%s",
                execution_id,
                len(capacity_errors),
            )
            return False
        self._mark_dispatch_failure(
            execution_id,
            last_worker_url,
            last_error or "dataflow worker capacity exceeded",
            worker_pod_id=last_worker_pod_id,
            payload_extra={"capacity_errors": capacity_errors},
        )
        return False

    def _reserve_dispatch_worker(self, execution_id: str, worker_pod_id: str, worker_url: str) -> bool:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None or execution.status != "pending":
                return False
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is None or trigger.status != "pending":
                return False
            message = f"dispatching to worker {worker_url}"
            lease_expires_at = now_local() + timedelta(seconds=max(1, int(get_config().scheduler.reservation_lease_seconds or 30)))
            self._release_reservation(db, execution_id)
            db.flush()
            updated_execution = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.id == execution_id,
                    WorkflowExecution.status == "pending",
                    or_(WorkflowExecution.owner_pod_id.is_(None), WorkflowExecution.owner_pod_id == worker_pod_id),
                    or_(WorkflowExecution.worker_job_id.is_(None), WorkflowExecution.worker_job_id == execution.id),
                    or_(WorkflowExecution.dispatch_status.is_(None), WorkflowExecution.dispatch_status == "", WorkflowExecution.dispatch_status == "dispatching"),
                )
                .update(
                    {
                        WorkflowExecution.owner_pod_id: worker_pod_id,
                        WorkflowExecution.worker_url: worker_url,
                        WorkflowExecution.worker_job_id: execution.id,
                        WorkflowExecution.dispatch_status: "dispatching",
                        WorkflowExecution.dispatch_error: None,
                        WorkflowExecution.message: message,
                    },
                    synchronize_session=False,
                )
            )
            if updated_execution != 1:
                db.rollback()
                return False
            updated_trigger = (
                db.query(TriggerTask)
                .filter(TriggerTask.id == trigger.id, TriggerTask.status == "pending")
                .update({TriggerTask.message: message}, synchronize_session=False)
            )
            if updated_trigger != 1:
                db.rollback()
                return False
            db.add(
                SchedulerWorkerSlotReservation(
                    reservation_id=f"rsv-{execution_id}",
                    worker_pod_id=worker_pod_id,
                    execution_id=execution_id,
                    status="reserved",
                    lease_expires_at=lease_expires_at,
                )
            )
            db.commit()
            return True
        finally:
            db.close()

    def _reset_dispatch_reservation(self, execution_id: str) -> None:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            self._release_reservation(db, execution_id)
            db.flush()
            execution.owner_pod_id = None
            execution.worker_url = None
            execution.worker_job_id = None
            execution.dispatch_status = None
            execution.dispatch_error = None
            execution.dispatch_backoff_until = None
            execution.dispatch_backoff_reason = None
            execution.dispatch_backoff_attempt = 0
            execution.message = "worker capacity exceeded; trying another worker"
            if trigger is not None and trigger.status == "pending":
                trigger.message = execution.message
                db.add(trigger)
            db.add(execution)
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _is_capacity_exceeded_error(error: str) -> bool:
        return "capacity_exceeded" in str(error or "").lower()

    def _choose_dataflow_worker(self, db: Session, execution_id: str) -> tuple[str, str]:
        candidates = self._rank_dataflow_workers(db, execution_id)
        if not candidates:
            raise DataflowWorkerError("no healthy registry worker available")
        return candidates[0]

    def _rank_dataflow_workers(self, db: Session, execution_id: str) -> list[tuple[str, str]]:
        workers = self._healthy_registry_workers(db)
        if not workers:
            raise DataflowWorkerError("no healthy registry worker available")

        registry_worker_urls: dict[str, str] = {}
        for worker in workers:
            worker_url = self._worker_url_from_registry(worker)
            if not worker_url:
                continue
            pod_id = str(worker.pod_id)
            registry_worker_urls[pod_id] = worker_url
        if not registry_worker_urls:
            raise DataflowWorkerError("no healthy registry worker available")
        snapshots = self._build_worker_load_snapshots(db, workers, include_worker_jobs=True)
        counts: dict[str, int] = {}
        worker_map = {str(worker.pod_id): worker for worker in workers}
        for worker_id in registry_worker_urls:
            snapshot = snapshots.get(worker_id, WorkerLoadSnapshot(worker_id=worker_id, capacity=0, healthy=False))
            worker = worker_map.get(worker_id)
            metadata = dict(getattr(worker, "metadata_json", {}) or {}) if worker is not None else {}
            execution_health = dict(metadata.get("execution_health") or {})
            degraded = str(getattr(worker, "status", "") or "").strip().lower() in {"degraded", "draining"}
            if snapshot.probe_error or degraded or self._worker_in_dispatch_cooldown(worker_id):
                counts[worker_id] = 1_000_000
                continue
            counts[worker_id] = (
                snapshot.used_slots
                + int(execution_health.get("startup_fail_count") or 0) * 100
                + int(execution_health.get("requeued_before_process_start_count") or 0) * 10
            )

        salt = int(hashlib.sha256(execution_id.encode("utf-8")).hexdigest(), 16)
        ordered_pod_ids = list(registry_worker_urls.keys())
        _, best_pod_id = min(
            enumerate(ordered_pod_ids),
            key=lambda item: (counts[item[1]], (item[0] - salt) % len(ordered_pod_ids)),
        )
        return sorted(
            ((pod_id, registry_worker_urls[pod_id]) for pod_id in ordered_pod_ids),
            key=lambda item: (
                counts[item[0]],
                (ordered_pod_ids.index(item[0]) - salt) % len(ordered_pod_ids),
                0 if item[0] == best_pod_id else 1,
            ),
        )

    def _healthy_registry_workers(self, db: Session) -> list[SchedulerWorker]:
        worker_timeout_at = now_local() - timedelta(seconds=get_config().scheduler.worker_timeout_seconds)
        workers = (
            db.query(SchedulerWorker)
            .filter(
                SchedulerWorker.status == "active",
                SchedulerWorker.last_heartbeat_at.isnot(None),
                SchedulerWorker.last_heartbeat_at >= worker_timeout_at,
            )
            .order_by(SchedulerWorker.last_heartbeat_at.desc(), SchedulerWorker.pod_id.asc())
            .all()
        )
        return [worker for worker in workers if self._worker_url_from_registry(worker)]

    def _reservation_counts(self, db: Session) -> dict[str, int]:
        rows = self._reservation_query(db).all()
        counts: dict[str, int] = {}
        for reservation in rows:
            key = str(reservation.worker_pod_id)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _list_worker_jobs_for_capacity(self, worker: SchedulerWorker) -> list[dict[str, Any]]:
        jobs_from_db = self._active_jobs_from_db(worker)
        worker_url = self._worker_url_from_registry(worker)
        if not worker_url:
            return jobs_from_db
        jobs = get_dataflow_worker_client(worker_url).list_jobs()
        return [job for job in jobs if isinstance(job, dict)]

    def _active_jobs_from_db(self, worker: SchedulerWorker) -> list[dict[str, Any]]:
        db = get_db_session()
        try:
            executions = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.owner_pod_id == worker.pod_id,
                    self._active_execution_filter(),
                )
                .order_by(WorkflowExecution.started_at.asc(), WorkflowExecution.updated_at.asc())
                .all()
            )
            return [self._job_payload(item) for item in executions]
        finally:
            db.close()

    @staticmethod
    def _worker_url_from_registry(worker: SchedulerWorker) -> str | None:
        metadata = worker.metadata_json or {}
        advertise_url = str(metadata.get("advertise_url") or "").strip().rstrip("/")
        if advertise_url:
            return advertise_url
        return None

    @staticmethod
    def _job_is_active(job: dict[str, Any]) -> bool:
        return str(job.get("status") or "").strip().lower() in ACTIVE_JOB_STATUSES

    @staticmethod
    def _build_active_job_payload(
        job: dict[str, Any],
        execution_map: dict[str, tuple[WorkflowExecution, TriggerTask, RunIndex | None]],
    ) -> WorkerActiveJobResponse:
        execution_id = str(job.get("execution_id") or job.get("id") or "")
        mapped = False
        mapping_reason = "orphan_job"
        task_id = None
        task_title = None
        run_name = None
        run_path = None
        project_id = None
        started_at = None
        updated_at = None
        dispatch_status = None
        worker_url = str(job.get("worker_url") or "") or None

        mapped_tuple = execution_map.get(execution_id)
        if mapped_tuple is not None:
            execution, trigger, run_index = mapped_tuple
            mapped = True
            mapping_reason = "execution_id"
            task_id = str(trigger.id)
            task_title = str(getattr(trigger, "title", "") or "")
            project_id = str(trigger.project_id or "")
            started_at = execution.started_at
            updated_at = execution.updated_at
            dispatch_status = execution.dispatch_status
            worker_url = worker_url or execution.worker_url or None
            if run_index is not None:
                run_name = run_index.run_name
                run_path = run_index.run_root_path

        return WorkerActiveJobResponse(
            execution_id=execution_id,
            task_id=task_id,
            task_title=task_title,
            status=str(job.get("status") or "unknown"),
            worker_job_id=str(job.get("id") or job.get("worker_job_id") or execution_id),
            worker_url=worker_url,
            dispatch_status=dispatch_status,
            started_at=started_at,
            updated_at=updated_at,
            run_name=run_name,
            run_path=run_path,
            project_id=project_id,
            mapped=mapped,
            mapping_reason=mapping_reason,
        )

    def _mark_dispatch_success(self, execution_id: str, worker_url: str, job: dict[str, Any]) -> None:
        self._clear_dispatch_backoff(execution_id)
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return
            job_id = str(job.get("id") or job.get("job_id") or execution.worker_job_id or execution.id)
            execution.worker_url = worker_url
            execution.worker_job_id = job_id
            job_phase = str(job.get("phase") or job.get("status") or "queued").strip().lower()
            execution.dispatch_status = job_phase or "queued"
            execution.dispatch_error = None
            if execution.status == "pending":
                execution.message = f"queued on worker {worker_url}"
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is not None and trigger.status == "pending":
                trigger.message = execution.message
                db.add(trigger)
            self._release_reservation(db, execution_id)
            db.add(execution)
            db.commit()
            get_execution_service().record_event(
                db,
                execution_id=execution_id,
                event_type="worker_dispatch_succeeded",
                message=f"execution dispatched to {worker_url}",
                payload_json={"worker_url": worker_url, "job": job},
            )
        finally:
            db.close()

    def _mark_dispatch_failure(
        self,
        execution_id: str,
        worker_url: str,
        error: str,
        *,
        worker_pod_id: str | None = None,
        payload_extra: dict[str, Any] | None = None,
    ) -> None:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return
            execution.worker_url = None
            execution.worker_job_id = None
            execution.dispatch_status = None
            execution.dispatch_error = error
            execution.message = f"worker dispatch failed, requeued: {error}"
            execution.owner_pod_id = None
            execution.status = "pending"
            execution.public_status = "pending"
            execution.started_at = None
            execution.process_pid = None
            execution.process_started_at = None
            execution.process_status = "not_started"
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is not None and trigger.status in {"pending", "dispatching"}:
                trigger.status = "pending"
                trigger.public_status = "pending"
                trigger.control_state = "none"
                trigger.message = execution.message
                db.add(trigger)
            elif trigger is not None and trigger.status == "running":
                trigger.status = "pending"
                trigger.public_status = "pending"
                trigger.control_state = "none"
                trigger.message = execution.message
                db.add(trigger)
            self._release_reservation(db, execution_id)
            db.add(execution)
            db.commit()
            payload_json = {"worker_url": worker_url, "worker_pod_id": worker_pod_id, "error": error}
            if payload_extra:
                payload_json.update(payload_extra)
            if self._has_recent_dispatch_requeue_event(db, execution_id, worker_url, worker_pod_id, error):
                return
            get_execution_service().record_event(
                db,
                execution_id=execution_id,
                event_type="worker_dispatch_requeued",
                message=execution.message,
                level="warning",
                payload_json=payload_json,
            )
        finally:
            db.close()

    def _has_recent_dispatch_requeue_event(
        self,
        db: Session,
        execution_id: str,
        worker_url: str,
        worker_pod_id: str | None,
        error: str,
    ) -> bool:
        threshold = now_local() - timedelta(seconds=30)
        events = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == execution_id,
                WorkflowExecutionEvent.event_type == "worker_dispatch_requeued",
                WorkflowExecutionEvent.created_at >= threshold,
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .limit(5)
            .all()
        )
        for event in events:
            payload = event.payload_json or {}
            if (
                str(payload.get("worker_url") or "") == str(worker_url or "")
                and str(payload.get("worker_pod_id") or "") == str(worker_pod_id or "")
                and str(payload.get("error") or "") == str(error or "")
            ):
                return True
        return False

    def _requeue_if_not_process_started(self, execution_id: str, error: str) -> bool:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return False
            if execution.process_pid or execution.process_started_at:
                return False
            if str(execution.status or "").strip().lower() not in {"dispatching", "starting", "running", "failed"}:
                return False

            trigger = db.get(TriggerTask, execution.trigger_task_id)
            message = f"worker job start failed before process launch, requeued: {error}"
            worker_url = execution.worker_url
            owner_pod_id = execution.owner_pod_id
            worker_job_id = execution.worker_job_id
            self._release_reservation(db, execution_id)
            execution.worker_url = None
            execution.worker_job_id = None
            execution.owner_pod_id = None
            execution.status = "pending"
            execution.public_status = "pending"
            execution.control_state = "none"
            execution.dispatch_status = None
            execution.dispatch_error = error
            execution.process_status = "not_started"
            execution.process_pid = None
            execution.process_started_at = None
            execution.process_finished_at = None
            execution.started_at = None
            execution.finished_at = None
            execution.message = message
            if trigger is not None and str(trigger.status or "").strip().lower() in {"pending", "dispatching", "running", "failed"}:
                trigger.status = "pending"
                trigger.public_status = "pending"
                trigger.control_state = "none"
                trigger.started_at = None
                trigger.finished_at = None
                trigger.message = message
                db.add(trigger)
            db.add(execution)
            db.commit()
            get_execution_service().record_event(
                db,
                execution_id=execution_id,
                event_type="worker_job_start_failed",
                message=message,
                level="warning",
                payload_json={
                    "error": error,
                    "worker_url": worker_url,
                    "owner_pod_id": owner_pod_id,
                    "worker_job_id": worker_job_id,
                    "process_pid": None,
                },
            )
            get_execution_service().record_event(
                db,
                execution_id=execution_id,
                event_type="worker_job_requeued_before_process_start",
                message=message,
                level="warning",
                payload_json={"reason": "process_not_started", "error": error, "worker_pod_id": self.pod_id},
            )
            self._record_execution_health_sample(
                "requeued_before_process_start",
                reason=error,
                payload={
                    "execution_id": execution_id,
                    "owner_pod_id": owner_pod_id,
                    "worker_job_id": worker_job_id,
                },
            )
            logger.warning(
                "requeued execution %s before process start owner=%s job=%s error=%s",
                execution_id,
                owner_pod_id,
                worker_job_id,
                error,
            )
            return True
        finally:
            db.close()

    def _schedule_execution(self, execution_id: str) -> None:
        if execution_id in self._running_tasks:
            return

        async def runner() -> None:
            try:
                await asyncio.to_thread(get_execution_service().run_claimed_execution, execution_id)
            except Exception as exc:
                logger.exception("execution %s failed during startup/execution", execution_id)
                await asyncio.to_thread(self._requeue_if_not_process_started, execution_id, str(exc))
            finally:
                self._running_tasks.pop(execution_id, None)
                await asyncio.to_thread(self._heartbeat_once)

        task = asyncio.create_task(runner(), name=f"execution-{execution_id}")
        self._running_tasks[execution_id] = task

    def _schedule_execution_thread(self, execution_id: str) -> None:
        if execution_id in self._running_tasks:
            return

        def runner() -> None:
            try:
                get_execution_service().run_claimed_execution(execution_id)
            except Exception as exc:
                logger.exception("execution %s failed during startup/execution", execution_id)
                self._record_execution_health_sample(
                    "startup_fail",
                    reason=str(exc),
                    payload={"execution_id": execution_id},
                )
                self._requeue_if_not_process_started(execution_id, str(exc))
            finally:
                self._running_tasks.pop(execution_id, None)
                self._heartbeat_once()
                self._start_assigned_jobs()

        thread = threading.Thread(target=runner, name=f"execution-{execution_id}", daemon=True)
        self._running_tasks[execution_id] = thread
        thread.start()

    def list_local_jobs(self) -> list[dict[str, Any]]:
        if not self.is_http_worker_role:
            return []
        db = get_db_session()
        try:
            jobs = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.owner_pod_id == self.pod_id,
                    WorkflowExecution.worker_job_id.isnot(None),
                )
                .order_by(WorkflowExecution.created_at.desc())
                .limit(200)
                .all()
            )
            return [self._job_payload(item) for item in jobs]
        finally:
            db.close()

    def get_local_job(self, job_id: str) -> dict[str, Any] | None:
        db = get_db_session()
        try:
            execution = self._local_job_query(db, job_id)
            return self._job_payload(execution) if execution is not None else None
        finally:
            db.close()

    def create_local_job(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.is_http_worker_role or self.role == "manager":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="this service instance is not a dataflow worker")
        if self._worker_status != "active":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"worker is {self._worker_status}")
        execution_id = str(payload.get("execution_id") or "").strip()
        if not execution_id:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="execution_id is required")
        worker_url = str(payload.get("worker_url") or "").strip()

        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution not found")
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="trigger task not found")
            if execution.status in TERMINAL_EXECUTION_STATUSES:
                return self._job_payload(execution)
            if execution.status != "pending" or trigger.status != "pending":
                return self._job_payload(execution)
            if execution.worker_job_id and execution.owner_pod_id not in {None, self.pod_id}:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="execution is assigned to another worker")
            current_used = self._running_count_for_worker(db, self.pod_id, exclude_execution_id=execution.id)
            if not self.has_unlimited_capacity and current_used >= self.capacity:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="capacity_exceeded")

            execution.owner_pod_id = self.pod_id
            execution.worker_url = worker_url or execution.worker_url
            execution.worker_job_id = execution.worker_job_id or execution.id
            execution.status = "dispatching"
            execution.public_status = "dispatching"
            execution.control_state = "none"
            execution.dispatch_status = "queued"
            execution.dispatch_error = None
            execution.message = f"queued on worker {self.pod_id}"
            trigger.status = "dispatching"
            trigger.public_status = "dispatching"
            trigger.control_state = "none"
            trigger.message = execution.message
            db.add(execution)
            db.add(trigger)
            db.commit()
            job = self._job_payload(execution)
            get_execution_service().record_event(
                db,
                execution_id=execution.id,
                event_type="worker_job_queued",
                message=f"worker job queued on {self.pod_id}",
                payload_json={
                    "worker_url": execution.worker_url,
                    "worker_job_id": execution.worker_job_id,
                    "phase": "queued",
                    "dispatch_status_after": "queued",
                },
            )
        finally:
            db.close()

        self._start_assigned_jobs()
        return self.get_local_job(job["id"]) or job

    def cancel_local_job(self, job_id: str) -> dict[str, Any]:
        if not self.is_http_worker_role or self.role == "manager":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="this service instance is not a dataflow worker")
        db = get_db_session()
        try:
            execution = self._local_job_query(db, job_id)
            if execution is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            now = now_local()
            if execution.status in {"pending", "dispatching", "starting"}:
                execution.status = "cancelled"
                execution.public_status = "cancelled"
                execution.control_state = "none"
                execution.finished_at = now
                execution.dispatch_status = "cancelled"
                execution.process_status = "not_started"
                execution.message = "cancelled before worker start"
                if trigger is not None and trigger.status in {"pending", "dispatching"}:
                    trigger.status = "cancelled"
                    trigger.public_status = "cancelled"
                    trigger.control_state = "none"
                    trigger.finished_at = now
                    trigger.message = execution.message
                    db.add(trigger)
                db.add(execution)
                db.commit()
                return self._job_payload(execution)

            if execution.status in {"running", "cancel_requested", "delete_requested"}:
                requested_status = "delete_requested" if execution.status == "delete_requested" else "cancel_requested"
                execution.status = requested_status
                execution.dispatch_status = requested_status
                execution.process_status = "delete_requested" if requested_status == "delete_requested" else "stop_requested"
                execution.message = "delete requested" if requested_status == "delete_requested" else "cancel requested"
                if trigger is not None and trigger.status in {"running", "cancel_requested", "delete_requested"}:
                    trigger.status = requested_status
                    trigger.message = execution.message
                    db.add(trigger)
                db.add(execution)
                db.commit()
                if execution.workspace_root:
                    get_execution_service()._write_run_control_state(
                        execution.workspace_root,
                        status_text=requested_status,
                        message=execution.message or requested_status,
                    )
                get_execution_service()._signal_local_cli_process(execution.id, wait=False)
                payload = self._job_payload(execution)
                payload["status"] = "running"
                return payload

            return self._job_payload(execution)
        finally:
            db.close()

    def drain_local_jobs(self, *, reason: str = "worker draining", wait_seconds: int = 45) -> dict[str, Any]:
        if not self.is_http_worker_role or self.role == "manager":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="this service instance is not a dataflow worker")
        self._worker_status = "draining"
        try:
            self._heartbeat_once()
        except Exception:
            logger.exception("failed to publish worker draining heartbeat")

        db = get_db_session()
        try:
            jobs = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.owner_pod_id == self.pod_id,
                    WorkflowExecution.status.in_(tuple(ACTIVE_JOB_STATUSES)),
                )
                .order_by(WorkflowExecution.created_at.asc())
                .all()
            )
            job_ids = [str(item.worker_job_id or item.id) for item in jobs]
        finally:
            db.close()

        cancelled: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for job_id in job_ids:
            try:
                cancelled.append(self.cancel_local_job(job_id))
            except Exception as exc:
                logger.exception("failed to cancel local job during drain: job_id=%s", job_id)
                errors.append({"job_id": job_id, "error": str(exc)})

        deadline = time.monotonic() + max(0, int(wait_seconds or 0))
        while self._running_tasks and time.monotonic() < deadline:
            time.sleep(1)
        self._worker_status = "offline"
        try:
            self._heartbeat_once()
        except Exception:
            logger.exception("failed to publish worker drain completion heartbeat")
        return {
            "status": "offline",
            "pod_id": self.pod_id,
            "reason": reason,
            "cancel_requested": len(cancelled),
            "running_remaining": len(self._running_tasks),
            "jobs": cancelled,
            "errors": errors,
        }

    def _local_job_query(self, db: Session, job_id: str) -> WorkflowExecution | None:
        return (
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.owner_pod_id == self.pod_id,
                WorkflowExecution.worker_job_id == job_id,
            )
            .first()
            or db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.owner_pod_id == self.pod_id,
                WorkflowExecution.id == job_id,
            )
            .first()
        )

    @staticmethod
    def _job_payload(execution: WorkflowExecution) -> dict[str, Any]:
        status_text = str(execution.status or "pending")
        if status_text == "pending" and execution.worker_job_id:
            status_text = "queued"
        elif status_text == "starting":
            status_text = "starting"
        elif status_text == "dispatching":
            status_text = "dispatching"
        elif status_text == "succeeded":
            status_text = "success"
        return {
            "id": execution.worker_job_id or execution.id,
            "execution_id": execution.id,
            "task_id": execution.trigger_task_id,
            "status": status_text,
            "phase": execution.dispatch_status or execution.process_status or execution.status,
            "worker_url": execution.worker_url or "",
            "owner_pod_id": execution.owner_pod_id or "",
            "process_pid": execution.process_pid,
            "error": execution.dispatch_error or "",
            "created_at": execution.created_at.isoformat() if execution.created_at else None,
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
        }

    async def _cleanup_loop(self) -> None:
        interval = get_config().scheduler.cleanup_interval_seconds
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self._cleanup_once)

    async def _active_reconcile_loop(self) -> None:
        interval = max(1, int(get_config().scheduler.active_reconcile_interval_seconds or 30))
        while True:
            await asyncio.sleep(interval)
            if self._active_reconcile_running:
                continue
            self._active_reconcile_running = True
            try:
                db = get_db_session()
                try:
                    get_execution_service().reconcile_active_tasks(
                        db,
                        limit=int(get_config().scheduler.active_reconcile_limit or 100),
                    )
                finally:
                    db.close()
            except Exception:
                logger.exception("active reconcile loop failed")
            finally:
                self._active_reconcile_running = False

    def _cleanup_once(self) -> None:
        db = get_db_session()
        try:
            now = now_local()
            worker_timeout_at = now - timedelta(seconds=get_config().scheduler.worker_timeout_seconds)
            stale_dispatch_at = now - timedelta(seconds=max(1, int(get_config().scheduler.requeue_stuck_dispatch_after_seconds or 60)))
            offline_workers = (
                db.query(SchedulerWorker)
                .filter(SchedulerWorker.last_heartbeat_at < worker_timeout_at, SchedulerWorker.status != "offline")
                .all()
            )
            for worker in offline_workers:
                worker.status = "offline"
                db.add(worker)

            expired_reservations = (
                db.query(SchedulerWorkerSlotReservation)
                .filter(SchedulerWorkerSlotReservation.lease_expires_at < now)
                .all()
            )
            for reservation in expired_reservations:
                db.delete(reservation)

            stuck_executions = (
                db.query(WorkflowExecution)
                .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
                .filter(
                    WorkflowExecution.owner_pod_id.isnot(None),
                    WorkflowExecution.worker_job_id.isnot(None),
                    WorkflowExecution.status.in_(["pending", "dispatching", "starting"]),
                    WorkflowExecution.dispatch_status.in_(["dispatching", "queued", "starting"]),
                    WorkflowExecution.updated_at <= stale_dispatch_at,
                    TriggerTask.status.in_(["pending", "dispatching"]),
                )
                .all()
            )
            for execution in stuck_executions:
                trigger = db.get(TriggerTask, execution.trigger_task_id)
                self._release_reservation(db, str(execution.id))
                execution.owner_pod_id = None
                execution.worker_job_id = None
                execution.worker_url = None
                execution.status = "pending"
                execution.public_status = "pending"
                execution.dispatch_status = None
                execution.dispatch_error = "dispatch timed out and was requeued"
                execution.process_status = "not_started"
                execution.process_pid = None
                execution.process_started_at = None
                execution.message = "worker dispatch timed out and was requeued"
                execution.started_at = None
                db.add(execution)
                if trigger is not None and trigger.status in {"pending", "dispatching"}:
                    trigger.status = "pending"
                    trigger.public_status = "pending"
                    trigger.control_state = "none"
                    trigger.message = execution.message
                    db.add(trigger)
                elif trigger is not None and trigger.status == "running":
                    trigger.status = "pending"
                    trigger.public_status = "pending"
                    trigger.control_state = "none"
                    trigger.message = execution.message
                    db.add(trigger)
                get_execution_service().record_event(
                    db,
                    execution_id=str(execution.id),
                    event_type="worker_job_requeued_before_process_start",
                    message=execution.message,
                    level="warning",
                    payload_json={"reason": "dispatch_timeout"},
                )

            orphaned_dispatches = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.owner_pod_id.is_(None),
                    WorkflowExecution.worker_job_id.isnot(None),
                    WorkflowExecution.dispatch_status.in_(["queued", "dispatching", "starting"]),
                )
                .all()
            )
            worker_url_to_pod: dict[str, str] = {}
            for worker in db.query(SchedulerWorker).all():
                advertise_url = self._worker_url_from_registry(worker)
                if advertise_url:
                    worker_url_to_pod[advertise_url.rstrip("/")] = str(worker.pod_id)
            reservation_map = {
                str(item.execution_id): str(item.worker_pod_id)
                for item in self._reservation_query(db).all()
            }
            for execution in orphaned_dispatches:
                owner_pod_id = reservation_map.get(str(execution.id))
                if not owner_pod_id and execution.worker_url:
                    owner_pod_id = worker_url_to_pod.get(str(execution.worker_url).rstrip("/"))
                if owner_pod_id:
                    execution.owner_pod_id = owner_pod_id
                    db.add(execution)

            terminal_with_active_dispatch = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.status.in_(tuple(TERMINAL_EXECUTION_STATUSES)),
                    WorkflowExecution.dispatch_status.in_(["queued", "dispatching", "running", "cancel_requested", "delete_requested"]),
                )
                .all()
            )
            for execution in terminal_with_active_dispatch:
                execution.dispatch_status = str(execution.status)
                execution.dispatch_error = execution.dispatch_error or "terminal execution cleared from active capacity"
                self._release_reservation(db, str(execution.id))
                db.add(execution)

            db.commit()
            get_execution_service().reconcile_stale_active_executions(db)
            db.commit()
        finally:
            db.close()


_scheduler_service: SchedulerService | None = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = SchedulerService()
    return _scheduler_service
