from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy.orm import Session

from app.config import get_config
from app.model import EvolutionTask, SchedulerWorker, get_db_session
from app.observability import get_observability
from app.service.task_service import get_task_service
from app.time_utils import now_local

logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self) -> None:
        self._started = False
        self._tasks: list[asyncio.Task] = []
        self._running: dict[str, asyncio.Task] = {}
        self._worker_status = "active"

    @property
    def role(self) -> str:
        role = str(get_config().scheduler.role or "standalone").strip().lower()
        return role if role in {"standalone", "manager", "worker"} else "standalone"

    @property
    def is_worker_role(self) -> bool:
        return self.role in {"standalone", "worker"} and self.capacity > 0

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

    async def start(self) -> None:
        if self._started or not get_config().scheduler.enabled:
            return
        self._started = True
        if self.runs_worker:
            await asyncio.to_thread(self._heartbeat_once)
            self._tasks.extend(
                [
                    asyncio.create_task(self._heartbeat_loop(), name="binary-evolution-heartbeat"),
                    asyncio.create_task(self._dispatch_loop(), name="binary-evolution-dispatch"),
                ]
            )
        if self.runs_worker or self.runs_manager:
            self._tasks.append(asyncio.create_task(self._cleanup_loop(), name="binary-evolution-cleanup"))

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        self._worker_status = "draining"
        if self.runs_worker:
            await asyncio.to_thread(self._heartbeat_once)
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(get_config().scheduler.heartbeat_interval_seconds)
            await asyncio.to_thread(self._heartbeat_once)

    def _heartbeat_once(self) -> None:
        db = get_db_session()
        try:
            now = now_local()
            worker = db.get(SchedulerWorker, self.pod_id)
            if worker is None:
                worker = SchedulerWorker(
                    pod_id=self.pod_id,
                    host_name=self.host_name,
                    capacity=self.capacity,
                    running_count=len(self._running),
                    last_heartbeat_at=now,
                    status=self._worker_status,
                    metadata_json={"service": "secflow-app-binary-evolution-center", "role": self.role},
                )
            else:
                worker.host_name = self.host_name
                worker.capacity = self.capacity
                worker.running_count = len(self._running)
                worker.last_heartbeat_at = now
                worker.status = self._worker_status
                worker.metadata_json = {"service": "secflow-app-binary-evolution-center", "role": self.role}
            db.add(worker)
            db.commit()
        finally:
            db.close()

    async def _dispatch_loop(self) -> None:
        while True:
            await asyncio.sleep(get_config().scheduler.poll_interval_seconds)
            if not self.runs_worker or self._worker_status != "active":
                continue
            db = get_db_session()
            try:
                max_tasks = get_task_service().get_service_config(db).config.max_concurrent_tasks
            finally:
                db.close()
            while len(self._running) < min(self.capacity, max_tasks):
                task_id = await asyncio.to_thread(self._claim_next_task)
                if not task_id:
                    break
                self._schedule_task(task_id)

    def _claim_next_task(self) -> str | None:
        db = get_db_session()
        try:
            candidate = (
                db.query(EvolutionTask)
                .filter(EvolutionTask.deleted.is_(False), EvolutionTask.status == "pending")
                .order_by(EvolutionTask.created_at.asc())
                .first()
            )
            if candidate is None:
                return None
            updated = (
                db.query(EvolutionTask)
                .filter(EvolutionTask.id == candidate.id, EvolutionTask.status == "pending")
                .update(
                    {
                        EvolutionTask.status: "running",
                        EvolutionTask.owner_pod_id: self.pod_id,
                        EvolutionTask.started_at: candidate.started_at or now_local(),
                        EvolutionTask.message: f"started by {self.pod_id}",
                    },
                    synchronize_session=False,
                )
            )
            if updated != 1:
                db.rollback()
                return None
            db.commit()
            claimed = db.get(EvolutionTask, candidate.id)
            if claimed is not None:
                get_observability().record_task_started(claimed)
            return candidate.id
        finally:
            db.close()

    def _schedule_task(self, task_id: str) -> None:
        async def _runner() -> None:
            db = get_db_session()
            try:
                await get_task_service().run_task(db, task_id)
            finally:
                db.close()
                self._running.pop(task_id, None)

        self._running[task_id] = asyncio.create_task(_runner(), name=f"binary-evolution-{task_id}")

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(get_config().scheduler.cleanup_interval_seconds)
            db = get_db_session()
            try:
                timeout_at = now_local() - timedelta(seconds=get_config().scheduler.worker_timeout_seconds)
                workers = db.query(SchedulerWorker).filter(SchedulerWorker.last_heartbeat_at < timeout_at, SchedulerWorker.status != "offline").all()
                for worker in workers:
                    worker.status = "offline"
                    db.add(worker)
                db.commit()
            finally:
                db.close()

    def health_payload(self) -> dict[str, str]:
        return {
            "status": "ok",
            "scheduler": "running" if self._started else "stopped",
            "scheduler_role": self.role,
            "worker_enabled": "true" if self.runs_worker else "false",
            "pod_id": self.pod_id,
        }


_scheduler_service: SchedulerService | None = None


def get_scheduler_service() -> SchedulerService:
    global _scheduler_service
    if _scheduler_service is None:
        _scheduler_service = SchedulerService()
    return _scheduler_service
