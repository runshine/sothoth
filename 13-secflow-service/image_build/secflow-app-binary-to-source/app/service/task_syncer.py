"""Background task sync loop for B2S task/item status reconciliation."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import suppress
from datetime import timedelta

from sqlalchemy.exc import IntegrityError

from app.config import get_config
from app.model import B2SDispatchLease, B2STask, get_db_session, get_session_factory
from app.observability import get_observability
from app.service.readless_sync import ReadlessSyncStats, run_readless_sync_loop
from app.service.task_service import refresh_task_function_stats, sync_task
from app.time_utils import now_local

logger = logging.getLogger(__name__)


class B2STaskSyncer:
    def __init__(self) -> None:
        self.owner_id = os.environ.get("POD_NAME") or f"b2s-task-syncer-{os.getpid()}"
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="b2s-task-syncer")

    async def stop(self) -> None:
        self._stopping.set()
        if not self._task:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task

    async def _run(self) -> None:
        interval_seconds = max(2, int(getattr(get_config().pi_re_agent, "dispatch_interval_seconds", 2)))

        async def _before_tick() -> bool:
            return await self._acquire_lease()

        def _candidate_ids_loader() -> list[str]:
            db = get_db_session()
            try:
                return [
                    str(task.id)
                    for task in db.query(B2STask)
                    .filter(B2STask.status.in_(["pending", "queued", "running", "dispatching", "cancelling"]))
                    .order_by(B2STask.updated_at.asc(), B2STask.created_at.asc())
                    .limit(64)
                    .all()
                ]
            finally:
                db.close()

        async def _process_one(task_id: str) -> tuple[bool, bool]:
            db = get_session_factory()()
            try:
                task = db.query(B2STask).filter(B2STask.id == task_id).first()
                if task is None:
                    return False, False
                before_status = str(task.status or "")
                before_updated_at = task.updated_at
                await sync_task(db, task)
                stats_changed = refresh_task_function_stats(db, task, inspect_files=True, only_missing=True, commit=False)
                changed = str(task.status or "") != before_status or task.updated_at != before_updated_at or stats_changed
                db.commit()
                return True, changed
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

        def _observe(stats: ReadlessSyncStats) -> None:
            get_observability().record_task_sync_tick(
                attempted=stats.attempted,
                succeeded=stats.succeeded,
                changed=stats.changed,
                failed=stats.failed,
                duration_seconds=max(0.0, time.perf_counter() - started_at[0]),
                owner_id=self.owner_id,
            )

        started_at = [time.perf_counter()]

        def _reset_started_at() -> None:
            started_at[0] = time.perf_counter()

        def _observe_and_reset(stats: ReadlessSyncStats) -> None:
            _observe(stats)
            _reset_started_at()

        _reset_started_at()
        await run_readless_sync_loop(
            should_stop=lambda: self._stopping.is_set(),
            interval_seconds=interval_seconds,
            before_tick=_before_tick,
            candidate_ids_loader=_candidate_ids_loader,
            process_one=_process_one,
            observe=_observe_and_reset,
        )

    async def _acquire_lease(self) -> bool:
        cfg = get_config().pi_re_agent
        db = get_db_session()
        try:
            now = now_local()
            lease_until = now + timedelta(seconds=max(5, cfg.dispatcher_lease_seconds))
            lease = db.query(B2SDispatchLease).filter(B2SDispatchLease.lease_name == "b2s_task_syncer").first()
            if lease is None:
                try:
                    db.add(B2SDispatchLease(
                        lease_name="b2s_task_syncer",
                        owner_id=self.owner_id,
                        lease_until=lease_until,
                        renewed_at=now,
                    ))
                    db.commit()
                    return True
                except IntegrityError:
                    db.rollback()
                    return False
            if lease.owner_id == self.owner_id or lease.lease_until <= now:
                lease.owner_id = self.owner_id
                lease.lease_until = lease_until
                lease.renewed_at = now
                db.commit()
                return True
            return False
        finally:
            db.close()

_task_syncer: B2STaskSyncer | None = None


def get_task_syncer() -> B2STaskSyncer:
    global _task_syncer
    if _task_syncer is None:
        _task_syncer = B2STaskSyncer()
    return _task_syncer
