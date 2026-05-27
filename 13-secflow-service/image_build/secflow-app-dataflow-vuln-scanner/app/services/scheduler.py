from __future__ import annotations

import asyncio
import functools
import hashlib
import logging
import threading
import time
from datetime import datetime, timedelta
import json
from typing import Any, Dict, List

from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import (
    RunIndex,
    SchedulerWorker,
    SchedulerWorkerSlotReservation,
    TriggerTask,
    WorkflowDefinition,
    WorkflowExecution,
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

ACTIVE_JOB_STATUSES = {"queued", "pending", "running", "cancel_requested", "delete_requested"}
TERMINAL_EXECUTION_STATUSES = {"succeeded", "failed", "cancelled"}


class SchedulerService:
    def __init__(self) -> None:
        self._started = False
        self._tasks: List[asyncio.Task] = []
        self._running_tasks: Dict[str, Any] = {}
        self._worker_status = "active"
        self._heartbeat_published = False
        self._cluster_capacity_summary_snapshot: WorkerClusterCapacitySummaryResponse | None = None
        self._cluster_capacity_summary_snapshot_at: datetime | None = None
        self._cluster_capacity_summary_refreshing = False
        self._cluster_capacity_summary_lock = threading.Lock()
        self._cluster_capacity_summary_hits_total = 0
        self._cluster_capacity_summary_misses_total = 0
        self._cluster_capacity_summary_refresh_failures_total = 0
        self._cluster_capacity_summary_last_refresh_duration_seconds = 0.0

    @property
    def role(self) -> str:
        role = str(get_config().scheduler.role or "standalone").strip().lower()
        return role if role in {"standalone", "manager", "worker"} else "standalone"

    @property
    def is_worker_role(self) -> bool:
        return self.role in {"standalone", "worker"}

    @property
    def is_http_worker_role(self) -> bool:
        return self.role in {"worker", "standalone"}

    @property
    def is_manager_role(self) -> bool:
        return self.role == "manager"

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
        return get_config().scheduler.worker_capacity

    @property
    def has_unlimited_capacity(self) -> bool:
        return self.capacity <= 0

    def has_available_capacity(self) -> bool:
        return self.has_unlimited_capacity or self.local_running_count() < self.capacity

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
            await asyncio.to_thread(functools.partial(self._refresh_cluster_capacity_summary_snapshot, force=True))
            self._tasks.append(asyncio.create_task(self._cluster_capacity_summary_loop(), name="scheduler-cluster-capacity-summary"))
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

    @property
    def runtime_config(self) -> dict[str, Any]:
        db = get_db_session()
        try:
            return get_runtime_config_service().get_config(db)
        finally:
            db.close()

    @property
    def discovery_mode(self) -> str:
        mode = str((self.runtime_config.get("scheduler") or {}).get("discovery_mode") or get_config().scheduler.discovery_mode or "registry").strip().lower()
        return mode if mode in {"registry", "static_urls", "hybrid"} else "registry"

    @property
    def reservation_lease_seconds(self) -> int:
        return max(5, int((self.runtime_config.get("scheduler") or {}).get("reservation_lease_seconds") or get_config().scheduler.reservation_lease_seconds or 30))

    @property
    def worker_queue_depth(self) -> int:
        return max(0, int((self.runtime_config.get("scheduler") or {}).get("worker_queue_depth") or get_config().scheduler.worker_queue_depth or 0))

    @property
    def dispatch_batch_size(self) -> int:
        return max(1, int((self.runtime_config.get("scheduler") or {}).get("dispatch_batch_size") or get_config().scheduler.dispatch_batch_size or 8))

    @property
    def requeue_stuck_dispatch_after_seconds(self) -> int:
        return max(10, int((self.runtime_config.get("scheduler") or {}).get("requeue_stuck_dispatch_after_seconds") or get_config().scheduler.requeue_stuck_dispatch_after_seconds or 60))

    @property
    def cluster_capacity_summary_refresh_interval_seconds(self) -> int:
        scheduler_cfg = self.runtime_config.get("scheduler") or {}
        return max(2, int(scheduler_cfg.get("cluster_capacity_summary_refresh_interval_seconds") or 5))

    @property
    def cluster_capacity_summary_stale_after_seconds(self) -> int:
        scheduler_cfg = self.runtime_config.get("scheduler") or {}
        return max(
            self.cluster_capacity_summary_refresh_interval_seconds,
            int(scheduler_cfg.get("cluster_capacity_summary_stale_after_seconds") or 15),
        )

    def configured_worker_urls(self) -> list[str]:
        cfg = get_config().dataflow_worker
        runtime_cfg = self.runtime_config.get("dataflow_worker") or {}
        configured_urls = runtime_cfg.get("worker_urls")
        workers = [url.rstrip("/") for url in (cfg.worker_urls or []) if url and url.strip()]
        if isinstance(configured_urls, list):
            workers = [str(url).rstrip("/") for url in configured_urls if str(url).strip()]
        base_url = str(runtime_cfg.get("base_url") or cfg.base_url or "").rstrip("/")
        return workers or ([base_url] if base_url else [])

    def advertise_url(self) -> str:
        runtime_cfg = self.runtime_config.get("dataflow_worker") or {}
        template = str(runtime_cfg.get("advertise_url_template") or get_config().dataflow_worker.advertise_url_template or "").strip()
        if template:
            return template.format(pod_id=self.pod_id, host_name=self.host_name)
        return f"http://{self.host_name}:8080"

    def local_running_count(self) -> int:
        return len(self._running_tasks)

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
    ) -> tuple[list[SchedulerWorker], datetime, dict[str, int], int]:
        workers = db.query(SchedulerWorker).order_by(SchedulerWorker.last_heartbeat_at.desc(), SchedulerWorker.pod_id.asc()).all()
        worker_timeout_at = now_local() - timedelta(seconds=get_config().scheduler.worker_timeout_seconds)
        reservation_counts = self._reservation_counts(db)
        queued_jobs = (
            db.query(WorkflowExecution)
            .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
            .join(WorkflowDefinition, WorkflowExecution.workflow_definition_id == WorkflowDefinition.id)
            .filter(
                WorkflowExecution.status == "pending",
                TriggerTask.status == "pending",
                WorkflowDefinition.enabled.is_(True),
            )
            .count()
        )
        return workers, worker_timeout_at, reservation_counts, queued_jobs

    def _compute_cluster_capacity_summary(self, db: Session) -> WorkerClusterCapacitySummaryResponse:
        started = time.perf_counter()
        workers, worker_timeout_at, reservation_counts, queued_jobs = self._cluster_capacity_base(db)
        worker_rows: list[WorkerClusterWorkerResponse] = []
        total_capacity = 0
        total_running = 0
        healthy_workers = 0
        stale_workers = 0

        for worker in workers:
            heartbeat_healthy = bool(worker.last_heartbeat_at and worker.last_heartbeat_at >= worker_timeout_at and worker.status == "active")
            capacity = max(int(worker.capacity or 0), 0)
            running_jobs = max(int(worker.running_count or 0), 0)
            available_slots = max(capacity - running_jobs - reservation_counts.get(str(worker.pod_id), 0), 0)
            healthy = heartbeat_healthy
            if healthy:
                healthy_workers += 1
            else:
                stale_workers += 1
            total_capacity += capacity
            total_running += running_jobs
            worker_rows.append(
                WorkerClusterWorkerResponse(
                    worker_id=str(worker.pod_id),
                    host_name=str(worker.host_name or worker.pod_id),
                    healthy=healthy,
                    max_concurrent_jobs=capacity,
                    running_jobs=running_jobs,
                    available_slots=available_slots,
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
            queued_jobs=queued_jobs,
            available_slots=max(total_capacity - total_running, 0),
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
            return age >= self.cluster_capacity_summary_stale_after_seconds

    def _set_cluster_capacity_summary_snapshot(
        self,
        snapshot: WorkerClusterCapacitySummaryResponse,
    ) -> WorkerClusterCapacitySummaryResponse:
        copied = snapshot.model_copy(deep=True)
        with self._cluster_capacity_summary_lock:
            self._cluster_capacity_summary_snapshot = copied
            self._cluster_capacity_summary_snapshot_at = now_local()
        return copied.model_copy(deep=True)

    def cluster_capacity_summary_snapshot_metrics(self) -> dict[str, float]:
        with self._cluster_capacity_summary_lock:
            age_seconds = (
                max((now_local() - self._cluster_capacity_summary_snapshot_at).total_seconds(), 0.0)
                if self._cluster_capacity_summary_snapshot_at is not None
                else -1.0
            )
            stale = 1.0 if self._cluster_capacity_summary_snapshot_at is not None and age_seconds >= self.cluster_capacity_summary_stale_after_seconds else 0.0
            return {
                "hits_total": float(self._cluster_capacity_summary_hits_total),
                "misses_total": float(self._cluster_capacity_summary_misses_total),
                "refresh_failures_total": float(self._cluster_capacity_summary_refresh_failures_total),
                "last_refresh_duration_seconds": float(self._cluster_capacity_summary_last_refresh_duration_seconds or 0.0),
                "age_seconds": age_seconds,
                "available": 1.0 if self._cluster_capacity_summary_snapshot is not None else 0.0,
                "stale": stale,
                "refreshing": 1.0 if self._cluster_capacity_summary_refreshing else 0.0,
            }

    def _refresh_cluster_capacity_summary_snapshot(
        self,
        db: Session | None = None,
        *,
        force: bool = False,
    ) -> WorkerClusterCapacitySummaryResponse | None:
        started = time.perf_counter()
        with self._cluster_capacity_summary_lock:
            if self._cluster_capacity_summary_refreshing:
                snapshot = self._cluster_capacity_summary_snapshot
                return snapshot.model_copy(deep=True) if snapshot is not None else None
            if not force and self._cluster_capacity_summary_snapshot_at is not None:
                age = (now_local() - self._cluster_capacity_summary_snapshot_at).total_seconds()
                if age < self.cluster_capacity_summary_refresh_interval_seconds:
                    snapshot = self._cluster_capacity_summary_snapshot
                    return snapshot.model_copy(deep=True) if snapshot is not None else None
            self._cluster_capacity_summary_refreshing = True

        owns_db = db is None
        session = db or get_db_session()
        try:
            snapshot = self._compute_cluster_capacity_summary(session)
            stored = self._set_cluster_capacity_summary_snapshot(snapshot)
            with self._cluster_capacity_summary_lock:
                self._cluster_capacity_summary_last_refresh_duration_seconds = max(time.perf_counter() - started, 0.0)
            return stored
        except Exception:
            logger.exception("failed to refresh cluster capacity summary snapshot")
            with self._cluster_capacity_summary_lock:
                self._cluster_capacity_summary_refresh_failures_total += 1
                self._cluster_capacity_summary_last_refresh_duration_seconds = max(time.perf_counter() - started, 0.0)
                snapshot = self._cluster_capacity_summary_snapshot
                return snapshot.model_copy(deep=True) if snapshot is not None else None
        finally:
            with self._cluster_capacity_summary_lock:
                self._cluster_capacity_summary_refreshing = False
            if owns_db:
                session.close()

    def get_cluster_capacity_summary(self, db: Session) -> WorkerClusterCapacitySummaryResponse:
        snapshot = self._cluster_capacity_summary_snapshot_copy()
        if snapshot is not None and not self._cluster_capacity_summary_snapshot_stale():
            with self._cluster_capacity_summary_lock:
                self._cluster_capacity_summary_hits_total += 1
            return snapshot
        with self._cluster_capacity_summary_lock:
            self._cluster_capacity_summary_misses_total += 1
        refreshed = self._refresh_cluster_capacity_summary_snapshot(db, force=bool(snapshot is None))
        if refreshed is not None:
            return refreshed
        if snapshot is not None:
            return snapshot
        return self._compute_cluster_capacity_summary(db)

    def get_cluster_capacity(self, db: Session) -> WorkerClusterCapacityResponse:
        started = time.perf_counter()
        workers, worker_timeout_at, reservation_counts, queued_jobs = self._cluster_capacity_base(db)
        worker_rows: list[WorkerClusterWorkerResponse] = []

        active_executions = (
            db.query(WorkflowExecution, TriggerTask, RunIndex)
            .join(TriggerTask, WorkflowExecution.trigger_task_id == TriggerTask.id)
            .outerjoin(RunIndex, RunIndex.linked_execution_id == WorkflowExecution.id)
            .filter(
                or_(
                    WorkflowExecution.status.in_(tuple(ACTIVE_JOB_STATUSES)),
                    WorkflowExecution.dispatch_status.in_(tuple(ACTIVE_JOB_STATUSES)),
                )
            )
            .all()
        )
        execution_map: dict[str, tuple[WorkflowExecution, TriggerTask, RunIndex | None]] = {}
        for execution, trigger, run_index in active_executions:
            execution_map[str(execution.id)] = (execution, trigger, run_index)

        total_capacity = 0
        total_running = 0
        healthy_workers = 0
        stale_workers = 0

        for worker in workers:
            heartbeat_healthy = bool(worker.last_heartbeat_at and worker.last_heartbeat_at >= worker_timeout_at and worker.status == "active")
            try:
                jobs = self._list_worker_jobs_for_capacity(worker)
                active_jobs = [self._build_active_job_payload(job, execution_map) for job in jobs if self._job_is_active(job)]
                active_jobs.sort(key=lambda item: item.started_at or item.updated_at or now_local())
                error = None
            except Exception as exc:
                logger.exception("failed to probe worker jobs for cluster capacity: pod_id=%s", worker.pod_id)
                active_jobs = []
                error = str(exc)
            healthy = heartbeat_healthy and error is None
            if healthy:
                healthy_workers += 1
            else:
                stale_workers += 1
            running_jobs = len(active_jobs)
            capacity = max(int(worker.capacity or 0), 0)
            available_slots = max(capacity - running_jobs - reservation_counts.get(str(worker.pod_id), 0), 0)
            total_capacity += capacity
            total_running += running_jobs
            worker_rows.append(
                WorkerClusterWorkerResponse(
                    worker_id=str(worker.pod_id),
                    host_name=str(worker.host_name or worker.pod_id),
                    healthy=healthy,
                    max_concurrent_jobs=capacity,
                    running_jobs=running_jobs,
                    available_slots=available_slots,
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
            queued_jobs=queued_jobs,
            available_slots=max(total_capacity - total_running, 0),
            updated_at=now_local(),
            workers=worker_rows,
        )
        observe_service_operation("cluster_capacity_detail", max(time.perf_counter() - started, 0.0))
        return response

    def _reservation_counts(self, db: Session) -> dict[str, int]:
        rows = (
            db.query(SchedulerWorkerSlotReservation.worker_pod_id)
            .filter(
                SchedulerWorkerSlotReservation.status == "reserved",
                SchedulerWorkerSlotReservation.lease_expires_at >= now_local(),
            )
            .all()
        )
        counts: dict[str, int] = {}
        for (worker_pod_id,) in rows:
            key = str(worker_pod_id)
            counts[key] = counts.get(key, 0) + 1
        return counts

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

    def _list_worker_jobs_for_capacity(self, worker: SchedulerWorker) -> list[dict[str, Any]]:
        jobs_from_db = self._active_jobs_from_db(worker)
        worker_url = self._resolve_worker_url(worker, jobs_from_db)
        if not worker_url:
            return jobs_from_db
        jobs = get_dataflow_worker_client(worker_url).list_jobs()
        return [job for job in jobs if isinstance(job, dict)]

    def _resolve_worker_url(self, worker: SchedulerWorker, jobs_from_db: list[dict[str, Any]]) -> str | None:
        urls = self.configured_worker_urls()
        if not urls:
            return None
        if len(urls) == 1:
            return urls[0]
        for job in jobs_from_db:
            worker_url = str(job.get("worker_url") or "").strip().rstrip("/")
            if worker_url:
                return worker_url
        host_name = str(worker.host_name or "").strip().lower()
        pod_id = str(worker.pod_id or "").strip().lower()
        for url in urls:
            normalized = url.lower()
            if host_name and host_name in normalized:
                return url
            if pod_id and pod_id in normalized:
                return url
        return urls[0]

    def _active_jobs_from_db(self, worker: SchedulerWorker) -> list[dict[str, Any]]:
        db = get_db_session()
        try:
            executions = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.owner_pod_id == worker.pod_id,
                    or_(
                        WorkflowExecution.status.in_(tuple(ACTIVE_JOB_STATUSES)),
                        WorkflowExecution.dispatch_status.in_(tuple(ACTIVE_JOB_STATUSES)),
                    ),
                )
                .all()
            )
            return [self._job_payload(execution) for execution in executions]
        finally:
            db.close()

    @staticmethod
    def _job_is_active(job: dict[str, Any]) -> bool:
        status_text = str(job.get("status") or "").strip().lower()
        phase_text = str(job.get("phase") or "").strip().lower()
        return status_text in ACTIVE_JOB_STATUSES or phase_text in ACTIVE_JOB_STATUSES

    @staticmethod
    def _build_active_job_payload(
        job: dict[str, Any],
        execution_map: dict[str, tuple[WorkflowExecution, TriggerTask, RunIndex | None]],
    ) -> WorkerActiveJobResponse:
        execution_id = str(job.get("execution_id") or job.get("id") or "")
        mapped_execution = execution_map.get(execution_id)
        execution = mapped_execution[0] if mapped_execution else None
        trigger = mapped_execution[1] if mapped_execution else None
        run_index = mapped_execution[2] if mapped_execution else None
        return WorkerActiveJobResponse(
            execution_id=execution_id,
            task_id=str(trigger.id) if trigger is not None else None,
            task_title=SchedulerService._trigger_title_for_capacity(trigger),
            status=str(job.get("status") or execution.status if execution is not None else "running"),
            worker_job_id=str(job.get("id") or execution.worker_job_id or execution_id),
            worker_url=str(job.get("worker_url") or execution.worker_url) if execution is not None or job.get("worker_url") else None,
            dispatch_status=str(job.get("phase") or execution.dispatch_status or execution.process_status) if execution is not None or job.get("phase") else None,
            started_at=execution.started_at if execution is not None else None,
            updated_at=execution.updated_at if execution is not None else None,
            run_name=str(run_index.run_name) if run_index is not None and getattr(run_index, "run_name", None) else None,
            run_path=str(run_index.run_root_path) if run_index is not None and getattr(run_index, "run_root_path", None) else None,
            project_id=str(execution.project_id) if execution is not None else None,
            mapped=execution is not None and trigger is not None,
            mapping_reason="matched_execution" if execution is not None and trigger is not None else "orphan_job",
        )

    @staticmethod
    def _trigger_title_for_capacity(trigger: TriggerTask | None) -> str | None:
        if trigger is None:
            return None
        payload = trigger.input_tasks_json
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        tasks = payload.get("tasks") if isinstance(payload, dict) else None
        if isinstance(tasks, list) and tasks:
            first = tasks[0]
            if isinstance(first, dict):
                title = str(first.get("title") or "").strip()
                if title:
                    return title
        return str(trigger.id)

    async def _heartbeat_loop(self) -> None:
        interval = get_config().scheduler.heartbeat_interval_seconds
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self._heartbeat_once)

    def _heartbeat_once(self) -> None:
        if not self.runs_worker:
            return
        db = get_db_session()
        try:
            worker = db.get(SchedulerWorker, self.pod_id)
            now = now_local()
            first_heartbeat = not self._heartbeat_published
            if worker is None:
                worker = SchedulerWorker(
                    pod_id=self.pod_id,
                    host_name=self.host_name,
                    capacity=self.capacity,
                    running_count=len(self._running_tasks),
                    last_heartbeat_at=now,
                    status=self._worker_status,
                    metadata_json={
                        "service": "secflow-app-dataflow-vuln-scanner",
                        "role": self.role,
                        "advertise_url": self.advertise_url(),
                    },
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
                worker.metadata_json = {
                    "service": "secflow-app-dataflow-vuln-scanner",
                    "role": self.role,
                    "advertise_url": self.advertise_url(),
                }
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
        for execution_id in self._pending_worker_dispatch_execution_ids(limit=self.dispatch_batch_size):
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
            return [str(row[0]) for row in rows]
        finally:
            db.close()

    def _start_assigned_jobs(self) -> None:
        if self.role != "worker" or self._worker_status != "active":
            return
        while self.has_available_capacity():
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
                    WorkflowExecution.status == "pending",
                    WorkflowExecution.owner_pod_id == self.pod_id,
                    WorkflowExecution.worker_job_id.isnot(None),
                    WorkflowExecution.dispatch_status == "queued",
                    TriggerTask.status == "pending",
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
        now = now_local()
        updated_execution = (
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.id == execution.id,
                WorkflowExecution.status == "pending",
                WorkflowExecution.owner_pod_id == self.pod_id,
                WorkflowExecution.dispatch_status == "queued",
            )
            .update(
                {
                    WorkflowExecution.status: "running",
                    WorkflowExecution.started_at: now,
                    WorkflowExecution.dispatch_status: "running",
                    WorkflowExecution.dispatch_error: None,
                    WorkflowExecution.message: f"started by worker {self.pod_id}",
                },
                synchronize_session=False,
            )
        )
        updated_trigger = (
            db.query(TriggerTask)
            .filter(TriggerTask.id == trigger.id, TriggerTask.status == "pending")
            .update(
                {
                    TriggerTask.status: "running",
                    TriggerTask.started_at: now,
                    TriggerTask.message: f"started by worker {self.pod_id}",
                },
                synchronize_session=False,
            )
        )
        if updated_execution != 1 or updated_trigger != 1:
            db.rollback()
            return None
        db.commit()
        logger.info("started assigned execution %s on worker %s", execution.id, self.pod_id)
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
                now = now_local()
                updated_execution = (
                    db.query(WorkflowExecution)
                    .filter(
                        WorkflowExecution.id == execution.id,
                        WorkflowExecution.status == "pending",
                        WorkflowExecution.owner_pod_id.is_(None),
                    )
                    .update(
                        {
                            WorkflowExecution.status: "running",
                            WorkflowExecution.owner_pod_id: self.pod_id,
                            WorkflowExecution.started_at: now,
                            WorkflowExecution.message: f"started by {self.pod_id}",
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
                            TriggerTask.status: "running",
                            TriggerTask.started_at: now,
                            TriggerTask.message: f"started by {self.pod_id}",
                        },
                        synchronize_session=False,
                    )
                )
                if updated_trigger != 1:
                    db.rollback()
                    continue
                db.commit()
                logger.info("started execution %s on pod %s", execution.id, self.pod_id)
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
            now = now_local()
            updated_execution = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.id == execution_id,
                    WorkflowExecution.status == "pending",
                    WorkflowExecution.owner_pod_id.is_(None),
                )
                .update(
                    {
                        WorkflowExecution.status: "running",
                        WorkflowExecution.owner_pod_id: self.pod_id,
                        WorkflowExecution.started_at: now,
                        WorkflowExecution.message: f"started immediately by {self.pod_id}",
                    },
                    synchronize_session=False,
                )
            )
            updated_trigger = (
                db.query(TriggerTask)
                .filter(TriggerTask.id == trigger.id, TriggerTask.status == "pending")
                .update(
                    {
                        TriggerTask.status: "running",
                        TriggerTask.started_at: now,
                        TriggerTask.message: f"started immediately by {self.pod_id}",
                    },
                    synchronize_session=False,
                )
            )
            if updated_execution != 1 or updated_trigger != 1:
                db.rollback()
                return None
            db.commit()
            logger.info("immediately started execution %s on pod %s", execution_id, self.pod_id)
            return execution_id
        finally:
            db.close()

    def start_execution_now(self, execution_id: str | None) -> bool:
        if not execution_id or execution_id in self._running_tasks:
            return False
        if self.is_manager_role:
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
        worker_url = ""
        worker_pod_id = ""
        last_error = ""
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None or execution.status != "pending":
                return False
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is None or trigger.status != "pending":
                return False
            worker_pod_id, worker_url = self._choose_dataflow_worker(db, execution_id)
            self._reserve_worker_slot(db, worker_pod_id, execution_id)
            message = f"dispatching to worker {worker_url}"
            updated_execution = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.id == execution_id,
                    WorkflowExecution.status == "pending",
                    WorkflowExecution.owner_pod_id.is_(None),
                    WorkflowExecution.worker_job_id.is_(None),
                    or_(WorkflowExecution.dispatch_status.is_(None), WorkflowExecution.dispatch_status == ""),
                )
                .update(
                    {
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
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

        attempts = max(1, int((self.runtime_config.get("dataflow_worker") or {}).get("dispatch_max_retries") or get_config().dataflow_worker.dispatch_max_retries or 1))
        retry_interval = max(0, int((self.runtime_config.get("dataflow_worker") or {}).get("dispatch_retry_interval_seconds") or get_config().dataflow_worker.dispatch_retry_interval_seconds or 0))
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
                if attempt < attempts:
                    time.sleep(retry_interval)

        self._mark_dispatch_failure(execution_id, worker_url, last_error or "dataflow worker dispatch failed")
        return False

    def _choose_dataflow_worker(self, db: Session, execution_id: str) -> tuple[str, str]:
        if self.discovery_mode == "static_urls":
            worker_url = self._choose_dataflow_worker_from_urls(db, execution_id)
            return worker_url, worker_url

        workers = self._healthy_registry_workers(db)
        if workers:
            reservations = self._reservation_counts(db)
            candidates: list[tuple[int, str, str]] = []
            for worker in workers:
                running_count = self._running_count_for_worker(db, str(worker.pod_id))
                reserved_count = reservations.get(str(worker.pod_id), 0)
                capacity = max(int(worker.capacity or 0), 0)
                if capacity > 0 and running_count + reserved_count >= capacity + self.worker_queue_depth:
                    continue
                worker_url = self._worker_url_from_registry(worker)
                if not worker_url:
                    continue
                candidates.append((running_count + reserved_count, str(worker.pod_id), worker_url))
            if candidates:
                salt = int(hashlib.sha256(execution_id.encode("utf-8")).hexdigest(), 16)
                candidates.sort(key=lambda item: (item[0], (hash(item[1]) - salt)))
                _, worker_pod_id, worker_url = candidates[0]
                return worker_pod_id, worker_url

        worker_url = self._choose_dataflow_worker_from_urls(db, execution_id)
        return worker_url, worker_url

    def _choose_dataflow_worker_from_urls(self, db: Session, execution_id: str) -> str:
        workers = self.configured_worker_urls()
        if len(workers) == 1:
            return workers[0]

        counts = {worker: 0 for worker in workers}
        for worker in workers:
            try:
                jobs = get_dataflow_worker_client(worker).list_jobs()
                counts[worker] += sum(1 for job in jobs if str(job.get("status") or "") in ACTIVE_JOB_STATUSES)
            except Exception:
                counts[worker] += 1_000_000

        active_executions = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.status.in_(list(ACTIVE_JOB_STATUSES)))
            .all()
        )
        for execution in active_executions:
            worker_url = str(execution.worker_url or "").rstrip("/")
            if worker_url in counts:
                counts[worker_url] += 1

        salt = int(hashlib.sha256(execution_id.encode("utf-8")).hexdigest(), 16)
        return min(enumerate(workers), key=lambda item: (counts[item[1]], (item[0] - salt) % len(workers)))[1]

    def _healthy_registry_workers(self, db: Session) -> list[SchedulerWorker]:
        timeout_seconds = int((self.runtime_config.get("scheduler") or {}).get("worker_timeout_seconds") or get_config().scheduler.worker_timeout_seconds or 300)
        worker_timeout_at = now_local() - timedelta(seconds=timeout_seconds)
        return (
            db.query(SchedulerWorker)
            .filter(
                SchedulerWorker.status == "active",
                SchedulerWorker.last_heartbeat_at >= worker_timeout_at,
            )
            .order_by(SchedulerWorker.last_heartbeat_at.desc(), SchedulerWorker.pod_id.asc())
            .all()
        )

    def _worker_url_from_registry(self, worker: SchedulerWorker) -> str | None:
        metadata = worker.metadata_json if isinstance(worker.metadata_json, dict) else {}
        advertise_url = str(metadata.get("advertise_url") or "").strip()
        if advertise_url:
            return advertise_url.rstrip("/")
        urls = self.configured_worker_urls()
        host_name = str(worker.host_name or "").strip().lower()
        pod_id = str(worker.pod_id or "").strip().lower()
        for url in urls:
            normalized = url.lower()
            if host_name and host_name in normalized:
                return url
            if pod_id and pod_id in normalized:
                return url
        if self.discovery_mode == "hybrid" and urls:
            return urls[0]
        return None

    def _running_count_for_worker(self, db: Session, worker_pod_id: str) -> int:
        return (
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.owner_pod_id == worker_pod_id,
                or_(
                    WorkflowExecution.status.in_(tuple(ACTIVE_JOB_STATUSES)),
                    WorkflowExecution.dispatch_status.in_(tuple(ACTIVE_JOB_STATUSES)),
                ),
            )
            .count()
        )

    def _reserve_worker_slot(self, db: Session, worker_pod_id: str, execution_id: str) -> None:
        expires_at = now_local() + timedelta(seconds=self.reservation_lease_seconds)
        reservation = (
            db.query(SchedulerWorkerSlotReservation)
            .filter(SchedulerWorkerSlotReservation.execution_id == execution_id)
            .first()
        )
        if reservation is None:
            reservation = SchedulerWorkerSlotReservation(
                id=f"resv-{execution_id}",
                worker_pod_id=worker_pod_id,
                execution_id=execution_id,
                status="reserved",
                lease_expires_at=expires_at,
            )
        else:
            reservation.worker_pod_id = worker_pod_id
            reservation.status = "reserved"
            reservation.lease_expires_at = expires_at
        db.add(reservation)

    def _mark_dispatch_success(self, execution_id: str, worker_url: str, job: dict[str, Any]) -> None:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return
            job_id = str(job.get("id") or job.get("job_id") or execution.worker_job_id or execution.id)
            execution.worker_url = worker_url
            execution.worker_job_id = job_id
            execution.dispatch_status = str(job.get("status") or "queued")
            execution.dispatch_error = None
            reservation = (
                db.query(SchedulerWorkerSlotReservation)
                .filter(SchedulerWorkerSlotReservation.execution_id == execution_id)
                .first()
            )
            if reservation is not None:
                reservation.status = "accepted"
                db.add(reservation)
            if execution.status == "pending":
                execution.message = f"queued on worker {worker_url}"
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is not None and trigger.status == "pending":
                trigger.message = execution.message
                db.add(trigger)
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

    def _mark_dispatch_failure(self, execution_id: str, worker_url: str, error: str) -> None:
        db = get_db_session()
        try:
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return
            execution.worker_url = None
            execution.worker_job_id = None
            execution.dispatch_status = None
            execution.dispatch_error = error
            execution.message = f"worker dispatch failed: {error}"
            reservation = (
                db.query(SchedulerWorkerSlotReservation)
                .filter(SchedulerWorkerSlotReservation.execution_id == execution_id)
                .first()
            )
            if reservation is not None:
                db.delete(reservation)
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            if trigger is not None and trigger.status == "pending":
                trigger.message = execution.message
                db.add(trigger)
            db.add(execution)
            db.commit()
            get_execution_service().record_event(
                db,
                execution_id=execution_id,
                event_type="worker_dispatch_failed",
                message=execution.message,
                level="warning",
                payload_json={"worker_url": worker_url, "error": error},
            )
        finally:
            db.close()

    def _schedule_execution(self, execution_id: str) -> None:
        if execution_id in self._running_tasks:
            return

        async def runner() -> None:
            try:
                await asyncio.to_thread(get_execution_service().run_claimed_execution, execution_id)
            except Exception:
                logger.exception("execution %s failed", execution_id)
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
            except Exception:
                logger.exception("execution %s failed", execution_id)
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

            execution.owner_pod_id = self.pod_id
            execution.worker_url = worker_url or execution.worker_url
            execution.worker_job_id = execution.worker_job_id or execution.id
            execution.dispatch_status = "queued"
            execution.dispatch_error = None
            reservation = (
                db.query(SchedulerWorkerSlotReservation)
                .filter(SchedulerWorkerSlotReservation.execution_id == execution_id)
                .first()
            )
            if reservation is not None:
                reservation.status = "accepted"
                db.add(reservation)
            execution.message = f"queued on worker {self.pod_id}"
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
                payload_json={"worker_url": execution.worker_url, "worker_job_id": execution.worker_job_id},
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
            if execution.status == "pending":
                execution.status = "cancelled"
                execution.finished_at = now
                execution.dispatch_status = "cancelled"
                execution.process_status = "not_started"
                execution.message = "cancelled before worker start"
                if trigger is not None and trigger.status == "pending":
                    trigger.status = "cancelled"
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
                return self._job_payload(execution)

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

    async def _cluster_capacity_summary_loop(self) -> None:
        while True:
            await asyncio.sleep(self.cluster_capacity_summary_refresh_interval_seconds)
            await asyncio.to_thread(self._refresh_cluster_capacity_summary_snapshot)

    def _cleanup_once(self) -> None:
        db = get_db_session()
        try:
            now = now_local()
            worker_timeout_seconds = int((self.runtime_config.get("scheduler") or {}).get("worker_timeout_seconds") or get_config().scheduler.worker_timeout_seconds or 300)
            worker_retention_seconds = int((self.runtime_config.get("scheduler") or {}).get("worker_retention_seconds") or get_config().scheduler.worker_retention_seconds or 1800)
            worker_timeout_at = now - timedelta(seconds=worker_timeout_seconds)
            worker_retention_at = now - timedelta(seconds=worker_retention_seconds)
            offline_workers = (
                db.query(SchedulerWorker)
                .filter(SchedulerWorker.last_heartbeat_at < worker_timeout_at, SchedulerWorker.status != "offline")
                .all()
            )
            for worker in offline_workers:
                worker.status = "offline"
                db.add(worker)

            stale_workers = (
                db.query(SchedulerWorker)
                .filter(
                    SchedulerWorker.status == "offline",
                    SchedulerWorker.last_heartbeat_at < worker_retention_at,
                )
                .all()
            )
            for worker in stale_workers:
                db.delete(worker)

            self._cleanup_stale_reservations(db, now)
            self._requeue_stuck_dispatches(db, now)

            db.commit()
            get_execution_service().reconcile_stale_active_executions(db)
            db.commit()
        finally:
            db.close()

    def _cleanup_stale_reservations(self, db: Session, now: Any) -> None:
        reservations = (
            db.query(SchedulerWorkerSlotReservation)
            .filter(SchedulerWorkerSlotReservation.lease_expires_at < now)
            .all()
        )
        for reservation in reservations:
            execution = db.get(WorkflowExecution, reservation.execution_id)
            if execution is not None and execution.status == "pending" and execution.owner_pod_id is None:
                execution.dispatch_status = None
                execution.dispatch_error = "reservation expired"
                execution.worker_url = None
                execution.worker_job_id = None
                db.add(execution)
            db.delete(reservation)

    def _requeue_stuck_dispatches(self, db: Session, now: Any) -> None:
        threshold = now - timedelta(seconds=self.requeue_stuck_dispatch_after_seconds)
        executions = (
            db.query(WorkflowExecution)
            .filter(
                WorkflowExecution.status == "pending",
                WorkflowExecution.owner_pod_id.is_(None),
                WorkflowExecution.dispatch_status == "dispatching",
                WorkflowExecution.updated_at < threshold,
            )
            .all()
        )
        for execution in executions:
            execution.dispatch_status = None
            execution.dispatch_error = "dispatch timeout requeued"
            execution.worker_url = None
            execution.worker_job_id = None
            db.add(execution)
            reservation = (
                db.query(SchedulerWorkerSlotReservation)
                .filter(SchedulerWorkerSlotReservation.execution_id == execution.id)
                .first()
            )
            if reservation is not None:
                db.delete(reservation)


_scheduler_service: SchedulerService | None = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = SchedulerService()
    return _scheduler_service
