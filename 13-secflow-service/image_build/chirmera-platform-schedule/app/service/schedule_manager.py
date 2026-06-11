"""Schedule job management, queueing runtime, and worker dispatch."""

from __future__ import annotations

import asyncio
import json
import math
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Any, Optional

import httpx
from croniter import croniter
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import ConflictError, NotFoundError, UpstreamError, ValidationError
from app.model import ScheduleExecution, ScheduleExecutionEvent, ScheduleJob, get_db_session
from app.service.http_client import get_shared_async_client
from app.service.redis_runtime import get_redis_runtime
from app.service.user_task_manager import get_user_task_manager


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _json_path_get(payload: Any, path: str | None) -> Any:
    if not path:
        return None
    value = payload
    for part in [item for item in str(path).split(".") if item]:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def _render_payload(template: Any, variables: dict[str, Any]) -> Any:
    if isinstance(template, dict):
        return {key: _render_payload(value, variables) for key, value in template.items()}
    if isinstance(template, list):
        return [_render_payload(item, variables) for item in template]
    if isinstance(template, str):
        try:
            return template.format(**variables)
        except Exception:
            return template
    return template


def _localized(now: datetime, timezone_name: str | None) -> datetime:
    tz_name = str(timezone_name or "UTC").strip() or "UTC"
    tz = ZoneInfo(tz_name)
    return now.replace(tzinfo=timezone.utc).astimezone(tz)


def _next_run(
    trigger_type: str,
    *,
    cron_expr: str | None,
    interval_seconds: int | None,
    timezone_name: str | None = "UTC",
    base: datetime | None = None,
) -> datetime | None:
    now = base or utcnow()
    if trigger_type == "interval" and interval_seconds:
        return now + timedelta(seconds=int(interval_seconds))
    if trigger_type == "cron" and cron_expr:
        localized = _localized(now, timezone_name)
        next_local = croniter(cron_expr, localized).get_next(datetime)
        if next_local.tzinfo is None:
            next_local = next_local.replace(tzinfo=localized.tzinfo)
        return next_local.astimezone(timezone.utc).replace(tzinfo=None)
    return None


def _parse_retry_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    defaults = get_config().retry
    payload = dict(policy or {})
    return {
        "strategy": str(payload.get("strategy") or "exponential_backoff"),
        "max_attempts": max(1, int(payload.get("max_attempts") or defaults.default_max_attempts)),
        "initial_delay_seconds": max(1, int(payload.get("initial_delay_seconds") or defaults.default_initial_delay_seconds)),
        "max_delay_seconds": max(1, int(payload.get("max_delay_seconds") or defaults.default_max_delay_seconds)),
        "jitter": bool(payload.get("jitter", True)),
    }


class ScheduleManager:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.redis = get_redis_runtime()
        self.pod_name = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME") or "chirmera-platform-schedule"

    def get_job_or_404(self, db: Session, project_id: str, job_id: str) -> ScheduleJob:
        job = db.query(ScheduleJob).filter(
            ScheduleJob.project_id == project_id,
            ScheduleJob.id == job_id,
            ScheduleJob.deleted.is_(False),
        ).first()
        if job is None:
            raise NotFoundError("ScheduleJob", job_id)
        return job

    def get_execution_or_404(self, db: Session, project_id: str, execution_id: str) -> ScheduleExecution:
        execution = db.query(ScheduleExecution).filter(
            ScheduleExecution.project_id == project_id,
            ScheduleExecution.id == execution_id,
        ).first()
        if execution is None:
            raise NotFoundError("ScheduleExecution", execution_id)
        return execution

    def _validate_payload(self, payload) -> None:
        if payload.trigger_type == "cron" and not payload.cron_expr:
            raise ValidationError("cron 任务必须提供 cron_expr")
        if payload.trigger_type == "interval" and not payload.interval_seconds:
            raise ValidationError("interval 任务必须提供 interval_seconds")
        if payload.auth_mode == "static_bearer" and not payload.static_bearer_token:
            raise ValidationError("static_bearer 模式必须提供 static_bearer_token")

    def _apply_job(self, job: ScheduleJob, payload, actor: str) -> ScheduleJob:
        self._validate_payload(payload)
        job.name = payload.name
        job.description = payload.description
        job.enabled = payload.enabled
        job.trigger_type = payload.trigger_type
        job.cron_expr = payload.cron_expr
        job.interval_seconds = payload.interval_seconds
        job.timezone = payload.timezone
        job.target_method = payload.target_method
        job.target_url = payload.target_url
        job.target_headers = dict(payload.target_headers or {})
        job.target_query = dict(payload.target_query or {})
        job.target_body_template = dict(payload.target_body_template or {})
        job.auth_mode = payload.auth_mode
        job.static_bearer_token = payload.static_bearer_token
        job.success_status_codes = list(payload.success_status_codes or [200, 201, 202])
        job.response_task_id_path = payload.response_task_id_path
        job.dedupe_window_seconds = payload.dedupe_window_seconds
        job.max_concurrency = max(1, int(getattr(payload, "max_concurrency", 1) or 1))
        job.dispatch_timeout_seconds = getattr(payload, "dispatch_timeout_seconds", None)
        job.retry_policy = _parse_retry_policy(getattr(payload, "retry_policy", None))
        job.target_bucket = getattr(payload, "target_bucket", None) or None
        job.misfire_policy = str(getattr(payload, "misfire_policy", "fire_once") or "fire_once")
        job.paused_until = getattr(payload, "paused_until", None)
        if job.enabled:
            job.next_run_at = _next_run(
                payload.trigger_type,
                cron_expr=payload.cron_expr,
                interval_seconds=payload.interval_seconds,
                timezone_name=payload.timezone,
                base=utcnow(),
            )
        else:
            job.next_run_at = None
        job.updated_by = actor
        job.version = int(job.version or 0) + 1
        return job

    def list_jobs(self, db: Session, project_id: str, page: int = 1, page_size: int = 50) -> tuple[int, list[ScheduleJob]]:
        query = db.query(ScheduleJob).filter(ScheduleJob.project_id == project_id, ScheduleJob.deleted.is_(False))
        total = query.count()
        items = query.order_by(ScheduleJob.created_at.desc()).offset(max(0, page - 1) * page_size).limit(page_size).all()
        return total, items

    def create_job(self, db: Session, project_id: str, payload, actor: str) -> ScheduleJob:
        exists = db.query(ScheduleJob).filter(
            ScheduleJob.project_id == project_id,
            ScheduleJob.name == payload.name,
            ScheduleJob.deleted.is_(False),
        ).first()
        if exists is not None:
            raise ConflictError(f"调度任务已存在: {payload.name}")
        job = ScheduleJob(project_id=project_id, created_by=actor, updated_by=actor)
        self._apply_job(job, payload, actor)
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def update_job(self, db: Session, project_id: str, job_id: str, payload, actor: str) -> ScheduleJob:
        job = self.get_job_or_404(db, project_id, job_id)
        duplicate = db.query(ScheduleJob).filter(
            ScheduleJob.project_id == project_id,
            ScheduleJob.name == payload.name,
            ScheduleJob.id != job_id,
            ScheduleJob.deleted.is_(False),
        ).first()
        if duplicate is not None:
            raise ConflictError(f"调度任务已存在: {payload.name}")
        self._apply_job(job, payload, actor)
        db.commit()
        db.refresh(job)
        return job

    def set_enabled(self, db: Session, project_id: str, job_id: str, enabled: bool, actor: str) -> ScheduleJob:
        job = self.get_job_or_404(db, project_id, job_id)
        job.enabled = enabled
        job.updated_by = actor
        job.version = int(job.version or 0) + 1
        job.next_run_at = _next_run(
            job.trigger_type,
            cron_expr=job.cron_expr,
            interval_seconds=job.interval_seconds,
            timezone_name=job.timezone,
            base=utcnow(),
        ) if enabled else None
        db.commit()
        db.refresh(job)
        return job

    def list_executions(self, db: Session, project_id: str, job_id: str, page: int = 1, page_size: int = 50) -> tuple[int, list[ScheduleExecution]]:
        self.get_job_or_404(db, project_id, job_id)
        query = db.query(ScheduleExecution).filter(
            ScheduleExecution.project_id == project_id,
            ScheduleExecution.schedule_job_id == job_id,
        )
        total = query.count()
        items = query.order_by(ScheduleExecution.created_at.desc()).offset(max(0, page - 1) * page_size).limit(page_size).all()
        return total, items

    def list_execution_events(self, db: Session, execution_id: str) -> list[ScheduleExecutionEvent]:
        return db.query(ScheduleExecutionEvent).filter(
            ScheduleExecutionEvent.execution_id == execution_id
        ).order_by(ScheduleExecutionEvent.created_at.asc()).all()

    def list_due_jobs(self, db: Session) -> list[ScheduleJob]:
        now = utcnow()
        return db.query(ScheduleJob).filter(
            ScheduleJob.enabled.is_(True),
            ScheduleJob.deleted.is_(False),
            ScheduleJob.next_run_at.is_not(None),
            ScheduleJob.next_run_at <= now,
            ((ScheduleJob.paused_until.is_(None)) | (ScheduleJob.paused_until <= now)),
        ).order_by(ScheduleJob.next_run_at.asc()).limit(self.cfg.scheduler.batch_size).all()

    def _append_event(
        self,
        db: Session,
        execution_id: str,
        event_type: str,
        message: str,
        payload: dict[str, Any] | None = None,
        *,
        event_source: str = "api",
        attempt_no: int | None = None,
        lease_token: str | None = None,
    ) -> None:
        db.add(
            ScheduleExecutionEvent(
                execution_id=execution_id,
                event_type=event_type,
                event_source=event_source,
                attempt_no=attempt_no,
                lease_token=lease_token,
                message=message,
                payload=payload or {},
            )
        )

    def _job_bucket_key(self, job: ScheduleJob) -> str:
        bucket = job.target_bucket or f"target:{job.target_method}:{job.target_url}"
        return bucket[:120]

    def _dedupe_key_for_schedule(self, job: ScheduleJob, scheduled_for: datetime) -> str:
        return f"{job.id}:{scheduled_for.isoformat()}"

    def _calc_retry_at(self, execution: ScheduleExecution, job: ScheduleJob) -> datetime:
        policy = _parse_retry_policy(job.retry_policy)
        attempt_idx = max(1, int(execution.attempt_no or 1))
        delay = policy["initial_delay_seconds"]
        if policy["strategy"] == "fixed":
            effective = delay
        else:
            effective = min(policy["max_delay_seconds"], delay * int(math.pow(2, max(0, attempt_idx - 1))))
        return utcnow() + timedelta(seconds=effective)

    def _is_retryable_status(self, status_code: int | None) -> bool:
        return status_code in {429, 502, 503, 504}

    def _can_retry(self, execution: ScheduleExecution, job: ScheduleJob, status_code: int | None = None) -> bool:
        policy = _parse_retry_policy(job.retry_policy)
        if int(execution.attempt_no or 1) >= int(policy["max_attempts"]):
            return False
        return status_code is None or self._is_retryable_status(status_code)

    def _create_execution_record(
        self,
        db: Session,
        job: ScheduleJob,
        trigger_source: str,
        *,
        scheduled_for: datetime,
        dedupe_key: str,
    ) -> ScheduleExecution:
        execution = ScheduleExecution(
            schedule_job_id=job.id,
            project_id=job.project_id,
            trigger_source=trigger_source,
            status="queued",
            scheduled_for=scheduled_for,
            dedupe_key=dedupe_key,
            trace_id=uuid.uuid4().hex,
            target_bucket=self._job_bucket_key(job),
            retry_at=scheduled_for,
        )
        db.add(execution)
        db.flush()
        return execution

    def _working_status_query(self, db: Session):
        return db.query(ScheduleExecution).filter(
            ScheduleExecution.status.in_(["reserved", "running"])
        )

    def _job_limits(self, job: ScheduleJob) -> tuple[int, int, int]:
        return (
            max(1, int(job.max_concurrency or 1)),
            max(1, int(self.cfg.limits.project_default_concurrency)),
            max(1, int(self.cfg.limits.target_default_concurrency)),
        )

    def _working_count_for_job(self, db: Session, job_id: str) -> int:
        return self._working_status_query(db).filter(
            ScheduleExecution.schedule_job_id == job_id
        ).count()

    def _working_count_for_project(self, db: Session, project_id: str) -> int:
        return self._working_status_query(db).filter(
            ScheduleExecution.project_id == project_id
        ).count()

    def _working_count_for_target(self, db: Session, project_id: str, target_bucket: str) -> int:
        return self._working_status_query(db).filter(
            ScheduleExecution.project_id == project_id,
            ScheduleExecution.target_bucket == target_bucket,
        ).count()

    def _capacity_snapshot(self, db: Session, job: ScheduleJob, execution: ScheduleExecution) -> dict[str, int]:
        target_bucket = execution.target_bucket or self._job_bucket_key(job)
        return {
            "job_limit": max(1, int(job.max_concurrency or 1)),
            "project_limit": max(1, int(self.cfg.limits.project_default_concurrency)),
            "target_limit": max(1, int(self.cfg.limits.target_default_concurrency)),
            "job_working": self._working_count_for_job(db, job.id),
            "project_working": self._working_count_for_project(db, execution.project_id),
            "target_working": self._working_count_for_target(db, execution.project_id, target_bucket),
        }

    def _reserve_execution(self, db: Session, execution: ScheduleExecution, job: ScheduleJob, *, actor: str) -> bool:
        if execution.status != "queued":
            return False
        snapshot = self._capacity_snapshot(db, job, execution)
        if (
            snapshot["job_working"] >= snapshot["job_limit"]
            or snapshot["project_working"] >= snapshot["project_limit"]
            or snapshot["target_working"] >= snapshot["target_limit"]
        ):
            execution.capacity_reject_count = int(execution.capacity_reject_count or 0) + 1
            execution.capacity_reject_reason = "capacity_full"
            execution.capacity_reject_at = utcnow()
            self._append_event(
                db,
                execution.id,
                "capacity_rejected",
                "Execution stayed queued because working capacity is full",
                snapshot,
                event_source=actor,
                attempt_no=execution.attempt_no,
            )
            return False

        execution.status = "reserved"
        execution.reserved_at = utcnow()
        execution.capacity_reject_reason = None
        execution.capacity_reject_at = None
        self._append_event(
            db,
            execution.id,
            "reserved",
            "Execution reserved for worker dispatch",
            snapshot,
            event_source=actor,
            attempt_no=execution.attempt_no,
        )
        return True

    def claim_execution_if_capacity(self, db: Session, execution_id: str) -> tuple[ScheduleExecution | None, bool]:
        execution = db.query(ScheduleExecution).filter(
            ScheduleExecution.id == execution_id
        ).first()
        if execution is None:
            return None, False
        if execution.status != "queued":
            return execution, False

        job = self.get_job_or_404(db, execution.project_id, execution.schedule_job_id)
        reserved = self._reserve_execution(db, execution, job, actor="worker")
        db.commit()
        db.refresh(execution)
        return execution, reserved

    async def enqueue_execution(self, execution_id: str) -> None:
        await self.redis.enqueue_ready(execution_id)

    async def enqueue_reserved_execution(self, execution_id: str) -> None:
        await self.redis.enqueue_ready(execution_id)

    async def trigger_job(self, db: Session, project_id: str, job_id: str, actor_token: str | None, trigger_source: str = "manual") -> ScheduleExecution:
        del actor_token
        job = self.get_job_or_404(db, project_id, job_id)
        scheduled_for = utcnow()
        execution = self._create_execution_record(
            db,
            job,
            trigger_source,
            scheduled_for=scheduled_for,
            dedupe_key=f"manual:{uuid.uuid4().hex}",
        )
        self._append_event(db, execution.id, "queued", "Execution queued by manual trigger", {"scheduled_for": scheduled_for.isoformat()}, event_source="api", attempt_no=execution.attempt_no)
        db.commit()
        await self.enqueue_execution(execution.id)
        db.refresh(execution)
        return execution

    def create_due_execution(self, db: Session, job: ScheduleJob) -> ScheduleExecution | None:
        scheduled_for = job.next_run_at or utcnow()
        dedupe_key = self._dedupe_key_for_schedule(job, scheduled_for)
        existing = db.query(ScheduleExecution).filter(
            ScheduleExecution.project_id == job.project_id,
            ScheduleExecution.schedule_job_id == job.id,
            ScheduleExecution.dedupe_key == dedupe_key,
        ).first()
        if existing is not None:
            job.next_run_at = _next_run(
                job.trigger_type,
                cron_expr=job.cron_expr,
                interval_seconds=job.interval_seconds,
                timezone_name=job.timezone,
                base=scheduled_for,
            )
            return None
        execution = self._create_execution_record(
            db,
            job,
            "scheduler",
            scheduled_for=scheduled_for,
            dedupe_key=dedupe_key,
        )
        self._append_event(db, execution.id, "queued", "Execution queued by scheduler", {"scheduled_for": scheduled_for.isoformat()}, event_source="scheduler", attempt_no=execution.attempt_no)
        job.last_run_at = scheduled_for
        job.next_run_at = _next_run(
            job.trigger_type,
            cron_expr=job.cron_expr,
            interval_seconds=job.interval_seconds,
            timezone_name=job.timezone,
            base=scheduled_for,
        )
        return execution

    async def process_due_jobs(self) -> int:
        db = get_db_session()
        execution_ids: list[str] = []
        try:
            for job in self.list_due_jobs(db):
                try:
                    execution = self.create_due_execution(db, job)
                except ConflictError:
                    continue
                reserved = self._reserve_execution(db, execution, job, actor="scheduler")
                db.commit()
                if execution is not None and reserved:
                    execution_ids.append(execution.id)
            db.commit()
        finally:
            db.close()
        for execution_id in execution_ids:
            await self.enqueue_execution(execution_id)
        return len(execution_ids)

    async def requeue_pending_executions(self) -> int:
        db = get_db_session()
        execution_ids: list[str] = []
        try:
            items = db.query(ScheduleExecution).filter(
                ScheduleExecution.status.in_(["queued", "reserved"])
            ).order_by(ScheduleExecution.created_at.asc()).limit(self.cfg.scheduler.batch_size).all()
            for execution in items:
                if execution.status == "queued":
                    job = self.get_job_or_404(db, execution.project_id, execution.schedule_job_id)
                    if not self._reserve_execution(db, execution, job, actor="scheduler"):
                        continue
                execution_ids.append(execution.id)
            db.commit()
        finally:
            db.close()
        for execution_id in execution_ids:
            await self.enqueue_execution(execution_id)
        return len(execution_ids)

    async def promote_delay_queue(self) -> int:
        due = await self.redis.promote_due_delay(self.cfg.scheduler.delay_promote_batch_size)
        return len(due)

    async def reclaim_stale_executions(self) -> int:
        db = get_db_session()
        reclaimed = 0
        try:
            stale = db.query(ScheduleExecution).filter(
                ScheduleExecution.status.in_(["reserved", "running"]),
                ScheduleExecution.lease_expire_at.is_not(None),
                ScheduleExecution.lease_expire_at < utcnow(),
            ).limit(self.cfg.scheduler.batch_size).all()
            for execution in stale:
                if await self.redis.execution_lease_exists(execution.id):
                    continue
                job = self.get_job_or_404(db, execution.project_id, execution.schedule_job_id)
                if self._can_retry(execution, job):
                    execution.status = "retry_wait"
                    execution.attempt_no = int(execution.attempt_no or 1) + 1
                    execution.retry_at = self._calc_retry_at(execution, job)
                    execution.result_code = "LEASE_EXPIRED"
                    execution.result_reason = "worker lease expired"
                    self._append_event(
                        db,
                        execution.id,
                        "retry_wait",
                        "Execution lease expired and was requeued",
                        {"retry_at": execution.retry_at.isoformat()},
                        event_source="reclaimer",
                        attempt_no=execution.attempt_no,
                    )
                    await self.redis.schedule_delay(execution.id, execution.retry_at.timestamp())
                else:
                    execution.status = "timeout"
                    execution.finished_at = utcnow()
                    execution.result_code = "LEASE_EXPIRED"
                    execution.result_reason = "worker lease expired"
                    execution.error_message = "执行租约过期，任务被标记为超时"
                    self._append_event(
                        db,
                        execution.id,
                        "timeout",
                        "Execution lease expired and reached retry limit",
                        event_source="reclaimer",
                        attempt_no=execution.attempt_no,
                    )
                execution.lease_owner = None
                execution.lease_token = None
                execution.lease_expire_at = None
                reclaimed += 1
            db.commit()
        finally:
            db.close()
        return reclaimed

    async def dispatch_execution(self, execution_id: str) -> ScheduleExecution | None:
        lease_token = uuid.uuid4().hex
        if not await self.redis.acquire_execution_lease(execution_id, lease_token, self.cfg.worker.lease_seconds):
            return None
        db = get_db_session()
        bucket_keys: list[str] = []
        heartbeat_task: asyncio.Task | None = None
        try:
            execution = db.query(ScheduleExecution).filter(ScheduleExecution.id == execution_id).first()
            if execution is None:
                await self.redis.release_execution_lease(execution_id, lease_token)
                return None
            if execution.status not in {"reserved", "queued", "retry_wait", "failed", "timeout"}:
                await self.redis.release_execution_lease(execution_id, lease_token)
                return execution
            job = self.get_job_or_404(db, execution.project_id, execution.schedule_job_id)
            if execution.status == "queued":
                reserved = self._reserve_execution(db, execution, job, actor="worker")
                if not reserved:
                    db.commit()
                    await self.redis.release_execution_lease(execution_id, lease_token)
                    return execution
            execution.status = "running"
            execution.lease_owner = self.pod_name
            execution.lease_token = lease_token
            execution.worker_pod = self.pod_name
            execution.lease_expire_at = utcnow() + timedelta(seconds=self.cfg.worker.lease_seconds)
            execution.heartbeat_at = utcnow()
            execution.retry_at = None
            self._append_event(db, execution.id, "running", "Execution lease acquired", event_source="worker", attempt_no=execution.attempt_no, lease_token=lease_token)
            db.commit()

            bucket_keys = [
                f"project:{execution.project_id}:inflight",
                f"bucket:{execution.target_bucket or self._job_bucket_key(job)}:inflight",
                f"job:{job.id}:inflight",
            ]
            limits = [
                self.cfg.limits.project_default_concurrency,
                self.cfg.limits.target_default_concurrency,
                max(1, int(job.max_concurrency or 1)),
            ]
            for bucket_key, limit in zip(bucket_keys, limits):
                if not await self.redis.acquire_bucket_slot(bucket_key, limit, self.cfg.worker.lease_seconds):
                    execution.status = "retry_wait"
                    execution.retry_at = utcnow() + timedelta(seconds=self.cfg.limits.queue_requeue_delay_seconds)
                    execution.result_code = "BACKPRESSURE"
                    execution.result_reason = "concurrency limit reached"
                    execution.lease_owner = None
                    execution.lease_token = None
                    execution.lease_expire_at = None
                    self._append_event(
                        db,
                        execution.id,
                        "retry_wait",
                        "Execution delayed by concurrency limits",
                        {"retry_at": execution.retry_at.isoformat(), "bucket_key": bucket_key},
                        event_source="worker",
                        attempt_no=execution.attempt_no,
                    )
                    db.commit()
                    await self.redis.schedule_delay(execution.id, execution.retry_at.timestamp())
                    await self.redis.release_execution_lease(execution_id, lease_token)
                    return execution

            heartbeat_task = asyncio.create_task(self._heartbeat(execution_id, lease_token))

            variables = {
                "project_id": execution.project_id,
                "job_id": job.id,
                "execution_id": execution.id,
                "triggered_at": utcnow().isoformat(),
            }
            headers = dict(job.target_headers or {})
            if job.auth_mode == "machine_token" and self.cfg.auth_service.service_machine_token:
                headers["Authorization"] = f"Bearer {self.cfg.auth_service.service_machine_token}"
            elif job.auth_mode == "static_bearer" and job.static_bearer_token:
                headers["Authorization"] = f"Bearer {job.static_bearer_token}"

            params = _render_payload(job.target_query or {}, variables)
            body = _render_payload(job.target_body_template or {}, variables)
            execution.request_snapshot = {
                "method": job.target_method,
                "url": job.target_url,
                "headers": headers,
                "params": params,
                "json": body,
            }
            execution.status = "running"
            execution.started_at = utcnow()
            self._append_event(db, execution.id, "running", "Dispatch started", execution.request_snapshot, event_source="worker", attempt_no=execution.attempt_no, lease_token=lease_token)
            db.commit()

            started = time.perf_counter()
            timeout = int(job.dispatch_timeout_seconds or self.cfg.scheduler.execution_timeout_seconds)
            client = await get_shared_async_client("schedule-dispatch", timeout=timeout)
            try:
                response = await client.request(
                    job.target_method,
                    job.target_url,
                    headers=headers,
                    params=params,
                    json=body if job.target_method != "GET" else None,
                )
            except httpx.TimeoutException as exc:
                execution.finished_at = utcnow()
                execution.status = "timeout"
                execution.error_message = "下游请求超时"
                execution.result_code = "TIMEOUT"
                execution.result_reason = "request timeout"
                if self._can_retry(execution, job):
                    execution.status = "retry_wait"
                    execution.attempt_no = int(execution.attempt_no or 1) + 1
                    execution.retry_at = self._calc_retry_at(execution, job)
                    await self.redis.schedule_delay(execution.id, execution.retry_at.timestamp())
                self._append_event(db, execution.id, "timeout", "Dispatch timeout", event_source="worker", attempt_no=execution.attempt_no, lease_token=lease_token)
                db.commit()
                raise UpstreamError("下游请求超时") from exc
            except httpx.RequestError as exc:
                execution.finished_at = utcnow()
                execution.error_message = f"下游请求失败: {exc}"
                execution.result_code = "REQUEST_ERROR"
                execution.result_reason = str(exc)
                if self._can_retry(execution, job):
                    execution.status = "retry_wait"
                    execution.attempt_no = int(execution.attempt_no or 1) + 1
                    execution.retry_at = self._calc_retry_at(execution, job)
                    await self.redis.schedule_delay(execution.id, execution.retry_at.timestamp())
                else:
                    execution.status = "failed"
                self._append_event(db, execution.id, "failed", "Dispatch request failed", {"error": str(exc)}, event_source="worker", attempt_no=execution.attempt_no, lease_token=lease_token)
                db.commit()
                raise UpstreamError(f"下游请求失败: {exc}") from exc

            duration_ms = int((time.perf_counter() - started) * 1000)
            try:
                payload = response.json()
            except Exception:
                payload = {"raw_text": response.text}
            execution.response_snapshot = payload if isinstance(payload, dict) else {"payload": payload}
            execution.http_status = response.status_code
            execution.finished_at = utcnow()
            execution.duration_ms = duration_ms
            execution.lease_owner = None
            execution.lease_token = None
            execution.lease_expire_at = None
            success_status_codes = set(int(item) for item in (job.success_status_codes or [200, 201, 202]))
            if response.status_code in success_status_codes:
                execution.status = "succeeded"
                execution.result_code = "OK"
                execution.result_reason = "dispatch succeeded"
                downstream_task_id = _json_path_get(payload, job.response_task_id_path) if isinstance(payload, dict) else None
                if downstream_task_id is None and isinstance(payload, dict):
                    downstream_task_id = payload.get("task_id") or payload.get("id")
                execution.downstream_task_id = str(downstream_task_id) if downstream_task_id is not None else None
                execution.downstream_task_name = str(payload.get("name") or payload.get("task_name") or "") if isinstance(payload, dict) else None
                self._append_event(db, execution.id, "succeeded", "Dispatch succeeded", {"http_status": response.status_code}, event_source="worker", attempt_no=execution.attempt_no)
            else:
                execution.error_message = f"下游返回异常状态码: {response.status_code}"
                execution.result_code = f"HTTP_{response.status_code}"
                execution.result_reason = "unexpected response status"
                if self._can_retry(execution, job, response.status_code):
                    execution.status = "retry_wait"
                    execution.attempt_no = int(execution.attempt_no or 1) + 1
                    execution.retry_at = self._calc_retry_at(execution, job)
                    await self.redis.schedule_delay(execution.id, execution.retry_at.timestamp())
                    self._append_event(db, execution.id, "retry_wait", "Dispatch scheduled for retry", {"http_status": response.status_code, "retry_at": execution.retry_at.isoformat()}, event_source="worker", attempt_no=execution.attempt_no)
                else:
                    execution.status = "failed"
                    self._append_event(db, execution.id, "failed", "Dispatch failed", {"http_status": response.status_code}, event_source="worker", attempt_no=execution.attempt_no)
            db.commit()
            db.refresh(execution)
            return execution
        finally:
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass
            for bucket_key in bucket_keys:
                await self.redis.release_bucket_slot(bucket_key)
            await self.redis.release_execution_lease(execution_id, lease_token)
            db.close()

    async def _heartbeat(self, execution_id: str, lease_token: str) -> None:
        while True:
            await asyncio.sleep(max(1, int(self.cfg.worker.heartbeat_seconds)))
            await self.redis.renew_execution_lease(execution_id, lease_token, self.cfg.worker.lease_seconds)
            db = get_db_session()
            try:
                execution = db.query(ScheduleExecution).filter(ScheduleExecution.id == execution_id).first()
                if execution is None:
                    return
                execution.heartbeat_at = utcnow()
                execution.lease_expire_at = utcnow() + timedelta(seconds=self.cfg.worker.lease_seconds)
                db.commit()
            finally:
                db.close()

    async def runtime_overview(self) -> dict[str, Any]:
        db = get_db_session()
        try:
            queue_snapshot = await self.redis.metrics_snapshot()
            inflight = db.query(ScheduleExecution).filter(ScheduleExecution.status.in_(["queued", "reserved", "running", "retry_wait"])).count()
            queued = db.query(ScheduleExecution).filter(ScheduleExecution.status == "queued").count()
            reserved = db.query(ScheduleExecution).filter(ScheduleExecution.status == "reserved").count()
            running = db.query(ScheduleExecution).filter(ScheduleExecution.status == "running").count()
            succeeded = db.query(ScheduleExecution).filter(ScheduleExecution.status == "succeeded").count()
            failed = db.query(ScheduleExecution).filter(ScheduleExecution.status.in_(["failed", "timeout"])).count()
            jobs_total = db.query(ScheduleJob).filter(ScheduleJob.deleted.is_(False)).count()
            active_jobs = db.query(ScheduleJob).filter(ScheduleJob.deleted.is_(False), ScheduleJob.enabled.is_(True)).count()
            return {
                "queue": {
                    "length": queue_snapshot["ready_length"],
                    "oldest_age_seconds": queue_snapshot["ready_oldest_age_seconds"],
                    "backend": queue_snapshot["queue_backend"],
                },
                "leader": {
                    "token": queue_snapshot["leader"],
                    "is_local": queue_snapshot["leader"] == self.pod_name,
                    "pod_name": self.pod_name,
                },
                "workers": {
                    "local_pod": self.pod_name,
                    "concurrency": self.cfg.worker.concurrency,
                    "inflight_executions": inflight,
                    "queued_executions": queued,
                    "reserved_executions": reserved,
                    "running_executions": running,
                },
                "stats": {
                    "jobs_total": jobs_total,
                    "active_jobs": active_jobs,
                    "succeeded_total": succeeded,
                    "failed_total": failed,
                },
                "redis_available": queue_snapshot["redis_available"],
            }
        finally:
            db.close()

    def job_runtime(self, db: Session, project_id: str, job_id: str) -> dict[str, Any]:
        job = self.get_job_or_404(db, project_id, job_id)
        executions = db.query(ScheduleExecution).filter(
            ScheduleExecution.project_id == project_id,
            ScheduleExecution.schedule_job_id == job_id,
        ).order_by(ScheduleExecution.created_at.desc()).limit(20).all()
        inflight = sum(1 for item in executions if item.status in {"queued", "reserved", "running", "retry_wait"})
        failures = sum(1 for item in executions if item.status in {"failed", "timeout"})
        return {
            "job_id": job.id,
            "project_id": project_id,
            "next_run_at": job.next_run_at,
            "last_run_at": job.last_run_at,
            "inflight_count": inflight,
            "last_execution_status": executions[0].status if executions else None,
            "recent_error_rate": failures / max(1, len(executions)),
        }

    async def metrics_text(self) -> str:
        overview = await self.runtime_overview()
        lines = [
            "# HELP chirmera_schedule_ready_queue_length Ready queue depth",
            "# TYPE chirmera_schedule_ready_queue_length gauge",
            f"chirmera_schedule_ready_queue_length {overview['queue']['length']}",
            "# HELP chirmera_schedule_ready_queue_oldest_age_seconds Oldest queued age",
            "# TYPE chirmera_schedule_ready_queue_oldest_age_seconds gauge",
            f"chirmera_schedule_ready_queue_oldest_age_seconds {overview['queue']['oldest_age_seconds']}",
            "# HELP chirmera_schedule_inflight_executions Current inflight executions",
            "# TYPE chirmera_schedule_inflight_executions gauge",
            f"chirmera_schedule_inflight_executions {overview['workers']['inflight_executions']}",
            "# HELP chirmera_schedule_reserved_executions Current reserved executions",
            "# TYPE chirmera_schedule_reserved_executions gauge",
            f"chirmera_schedule_reserved_executions {overview['workers']['reserved_executions']}",
            "# HELP chirmera_schedule_running_executions Current running executions",
            "# TYPE chirmera_schedule_running_executions gauge",
            f"chirmera_schedule_running_executions {overview['workers']['running_executions']}",
        ]
        return "\n".join(lines) + "\n"


class SchedulerRuntime:
    def __init__(self, manager: ScheduleManager):
        self.manager = manager
        self.config = get_config().scheduler
        self._root_config = get_config()
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._leader_token = manager.pod_name

    async def _loop(self) -> None:
        renew_every = max(1, int(self.config.leader_renew_seconds))
        last_reclaim = 0.0
        while self._running:
            acquired = await self.manager.redis.acquire_leader(self._leader_token, self.config.leader_lease_seconds)
            if not acquired:
                if await self.manager.redis.current_leader() == self._leader_token:
                    await self.manager.redis.renew_leader(self._leader_token, self.config.leader_lease_seconds)
                await asyncio.sleep(max(1, int(self.config.poll_interval_seconds)))
                continue
            await self.manager.redis.renew_leader(self._leader_token, self.config.leader_lease_seconds)
            await self.manager.process_due_jobs()
            await self.manager.promote_delay_queue()
            await self.manager.requeue_pending_executions()
            await get_user_task_manager().auto_dispatch_ready_tasks(
                batch_size=max(1, int(self._root_config.scheduler.ready_backfill_batch_size)),
                actor="schedule-auto-dispatcher",
            )
            now_monotonic = time.monotonic()
            if now_monotonic - last_reclaim >= max(1, int(self.config.reclaim_interval_seconds)):
                await self.manager.reclaim_stale_executions()
                last_reclaim = now_monotonic
            await asyncio.sleep(max(1, min(int(self.config.poll_interval_seconds), renew_every)))

    async def start(self) -> None:
        if self._running or not self.config.enabled:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.manager.redis.release_leader(self._leader_token)


class WorkerRuntime:
    def __init__(self, manager: ScheduleManager):
        self.manager = manager
        self.config = get_config()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._workers: set[asyncio.Task] = set()
        self._draining = False

    async def _worker_loop(self) -> None:
        while self._running and not self._draining:
            execution_id = await self.manager.redis.pop_ready(timeout_seconds=1)
            if not execution_id:
                await asyncio.sleep(max(0.1, float(self.config.worker.idle_sleep_seconds)))
                continue
            try:
                await self.manager.dispatch_execution(execution_id)
            except Exception:
                pass

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        for _ in range(max(1, int(self.config.worker.concurrency))):
            task = asyncio.create_task(self._worker_loop())
            self._workers.add(task)
            task.add_done_callback(self._workers.discard)
        async def _wait_all() -> None:
            if self._workers:
                await asyncio.gather(*self._workers, return_exceptions=True)
        self._task = asyncio.create_task(_wait_all())

    async def stop(self) -> None:
        if not self._running:
            return
        self._draining = True
        self._running = False
        for task in list(self._workers):
            task.cancel()
        for task in list(self._workers):
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._workers.clear()


_schedule_manager: Optional[ScheduleManager] = None
_scheduler_runtime: Optional[SchedulerRuntime] = None
_worker_runtime: Optional[WorkerRuntime] = None


def get_schedule_manager() -> ScheduleManager:
    global _schedule_manager
    if _schedule_manager is None:
        _schedule_manager = ScheduleManager()
    return _schedule_manager


def get_scheduler_runtime() -> SchedulerRuntime:
    global _scheduler_runtime
    if _scheduler_runtime is None:
        _scheduler_runtime = SchedulerRuntime(get_schedule_manager())
    return _scheduler_runtime


def get_worker_runtime() -> WorkerRuntime:
    global _worker_runtime
    if _worker_runtime is None:
        _worker_runtime = WorkerRuntime(get_schedule_manager())
    return _worker_runtime
