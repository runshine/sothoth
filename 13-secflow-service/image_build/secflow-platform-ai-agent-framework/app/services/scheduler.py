from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import (
    SchedulerWorker,
    TriggerTask,
    WorkflowDefinition,
    WorkflowExecution,
    get_db_session,
)
from app.schemas import SchedulerWorkerResponse
from app.services.execution_service import get_execution_service

logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self) -> None:
        self._started = False
        self._tasks: List[asyncio.Task] = []
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._worker_status = "active"

    @property
    def pod_id(self) -> str:
        return get_config().scheduler.pod_id

    @property
    def host_name(self) -> str:
        return get_config().scheduler.host_name

    @property
    def capacity(self) -> int:
        return get_config().scheduler.worker_capacity

    async def start(self) -> None:
        if self._started or not get_config().scheduler.enabled:
            return
        self._started = True
        await asyncio.to_thread(self._heartbeat_once)
        self._tasks = [
            asyncio.create_task(self._heartbeat_loop(), name="scheduler-heartbeat"),
            asyncio.create_task(self._dispatch_loop(), name="scheduler-dispatch"),
            asyncio.create_task(self._lease_loop(), name="scheduler-lease"),
            asyncio.create_task(self._cleanup_loop(), name="scheduler-cleanup"),
        ]

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        db = get_db_session()
        try:
            worker = db.get(SchedulerWorker, self.pod_id)
            if worker is not None:
                worker.status = "offline"
                worker.running_count = len(self._running_tasks)
                worker.last_heartbeat_at = datetime.utcnow()
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
        }

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

    def set_worker_status(self, db: Session, pod_id: str, status_value: str) -> None:
        worker = db.get(SchedulerWorker, pod_id)
        if worker is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scheduler worker not found")
        worker.status = status_value
        worker.last_heartbeat_at = datetime.utcnow()
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
        db = get_db_session()
        try:
            worker = db.get(SchedulerWorker, self.pod_id)
            now = datetime.utcnow()
            if worker is None:
                worker = SchedulerWorker(
                    pod_id=self.pod_id,
                    host_name=self.host_name,
                    capacity=self.capacity,
                    running_count=len(self._running_tasks),
                    last_heartbeat_at=now,
                    status=self._worker_status,
                    metadata_json={"service": "secflow-ai-agent-framework"},
                )
            else:
                self._worker_status = worker.status
                worker.host_name = self.host_name
                worker.capacity = self.capacity
                worker.running_count = len(self._running_tasks)
                worker.last_heartbeat_at = now
                worker.metadata_json = {"service": "secflow-ai-agent-framework"}
            db.add(worker)
            db.commit()
        finally:
            db.close()

    async def _dispatch_loop(self) -> None:
        interval = get_config().scheduler.poll_interval_seconds
        while True:
            await asyncio.sleep(interval)
            if self._worker_status != "active":
                continue
            while self.local_running_count() < self.capacity:
                execution_id = await asyncio.to_thread(self._claim_next_execution)
                if not execution_id:
                    break
                self._schedule_execution(execution_id)

    def _claim_next_execution(self) -> str | None:
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
            for execution, trigger, definition in candidates:
                if definition.max_concurrency <= 0:
                    continue
                try:
                    locked_definition = (
                        db.query(WorkflowDefinition)
                        .filter(WorkflowDefinition.id == definition.id)
                        .with_for_update()
                        .one()
                    )
                except Exception:
                    db.rollback()
                    locked_definition = definition
                running_same_definition = (
                    db.query(WorkflowExecution)
                    .filter(
                        WorkflowExecution.workflow_definition_id == locked_definition.id,
                        WorkflowExecution.status == "running",
                    )
                    .count()
                )
                if running_same_definition >= locked_definition.max_concurrency:
                    db.rollback()
                    continue
                now = datetime.utcnow()
                lease_expires_at = now + timedelta(seconds=get_config().scheduler.lease_duration_seconds)
                lease_token = uuid.uuid4().hex
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
                            WorkflowExecution.lease_token: lease_token,
                            WorkflowExecution.lease_expires_at: lease_expires_at,
                            WorkflowExecution.started_at: now,
                            WorkflowExecution.message: f"claimed by {self.pod_id}",
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
                            TriggerTask.message: f"claimed by {self.pod_id}",
                        },
                        synchronize_session=False,
                    )
                )
                if updated_trigger != 1:
                    db.rollback()
                    continue
                db.commit()
                logger.info("claimed execution %s on pod %s", execution.id, self.pod_id)
                return execution.id
            return None
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

    async def _lease_loop(self) -> None:
        interval = max(1, get_config().scheduler.lease_duration_seconds // 3)
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self._renew_local_leases)

    def _renew_local_leases(self) -> None:
        if not self._running_tasks:
            return
        db = get_db_session()
        try:
            now = datetime.utcnow()
            lease_expires_at = now + timedelta(seconds=get_config().scheduler.lease_duration_seconds)
            for execution_id in list(self._running_tasks):
                db.query(WorkflowExecution).filter(
                    WorkflowExecution.id == execution_id,
                    WorkflowExecution.owner_pod_id == self.pod_id,
                    WorkflowExecution.status.in_(["running", "cancel_requested"]),
                ).update(
                    {
                        WorkflowExecution.lease_expires_at: lease_expires_at,
                    },
                    synchronize_session=False,
                )
            db.commit()
        finally:
            db.close()

    async def _cleanup_loop(self) -> None:
        interval = get_config().scheduler.cleanup_interval_seconds
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(self._cleanup_once)

    def _cleanup_once(self) -> None:
        db = get_db_session()
        try:
            now = datetime.utcnow()
            worker_timeout_at = now - timedelta(seconds=get_config().scheduler.worker_timeout_seconds)
            offline_workers = (
                db.query(SchedulerWorker)
                .filter(SchedulerWorker.last_heartbeat_at < worker_timeout_at, SchedulerWorker.status != "offline")
                .all()
            )
            for worker in offline_workers:
                worker.status = "offline"
                db.add(worker)

            expired_executions = (
                db.query(WorkflowExecution)
                .filter(
                    WorkflowExecution.status == "running",
                    WorkflowExecution.lease_expires_at.isnot(None),
                    WorkflowExecution.lease_expires_at < now,
                )
                .all()
            )
            for execution in expired_executions:
                execution.status = "orphaned"
                execution.message = "execution lease expired"
                db.add(execution)
                trigger = db.get(TriggerTask, execution.trigger_task_id)
                if trigger is not None and trigger.status == "running":
                    trigger.status = "failed"
                    trigger.message = "execution orphaned after lease expiry"
                    trigger.finished_at = now
                    db.add(trigger)
            db.commit()
        finally:
            db.close()


_scheduler_service: SchedulerService | None = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = SchedulerService()
    return _scheduler_service
