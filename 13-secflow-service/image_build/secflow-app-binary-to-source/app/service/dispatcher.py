"""Background dispatcher that keeps pi-re-agent workers saturated from B2S queue."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import suppress
from datetime import timedelta

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app.config import get_config
from app.model import B2SDispatchLease, B2STask, B2STaskItem, get_db_session
from app.service.pi_cluster import get_pi_cluster_monitor
from app.service.task_service import dispatch_item_to_pi, recompute_task_status
from app.time_utils import now_local

logger = logging.getLogger(__name__)


class B2SDispatcher:
    def __init__(self) -> None:
        self.owner_id = os.environ.get("POD_NAME") or f"b2s-dispatcher-{os.getpid()}"
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._last_capacity_refresh = 0.0

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="b2s-dispatcher")

    async def stop(self) -> None:
        self._stopping.set()
        if not self._task:
            return
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task

    async def _run(self) -> None:
        cfg = get_config().pi_re_agent
        while not self._stopping.is_set():
            try:
                if time.monotonic() - self._last_capacity_refresh >= max(1, cfg.capacity_refresh_seconds):
                    await get_pi_cluster_monitor().refresh_once()
                    self._last_capacity_refresh = time.monotonic()
                if await self._acquire_lease():
                    await self._dispatch_once()
            except Exception as exc:
                logger.warning("B2S dispatcher tick failed: %s", exc, exc_info=True)
            await asyncio.sleep(max(1, cfg.dispatch_interval_seconds))

    async def _acquire_lease(self) -> bool:
        cfg = get_config().pi_re_agent
        db = get_db_session()
        try:
            now = now_local()
            lease_until = now + timedelta(seconds=max(5, cfg.dispatcher_lease_seconds))
            lease = db.query(B2SDispatchLease).filter(B2SDispatchLease.lease_name == "b2s_dispatcher").first()
            if lease is None:
                try:
                    db.add(B2SDispatchLease(
                        lease_name="b2s_dispatcher",
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

    async def _dispatch_once(self) -> None:
        cfg = get_config().pi_re_agent
        snapshot = await get_pi_cluster_monitor().snapshot()
        queued_buffer = max(0, snapshot.worker_count * cfg.queued_buffer_per_worker)
        max_inflight = snapshot.total_capacity + queued_buffer

        db = get_db_session()
        try:
            now = now_local()
            touched_tasks: set[str] = set()
            if max_inflight > 0:
                inflight = db.query(B2STaskItem).filter(
                    B2STaskItem.status.in_(["queued", "running"]),
                    B2STaskItem.pi_job_id.isnot(None),
                ).count()
                dispatch_limit = min(cfg.max_dispatch_batch_size, max(0, max_inflight - inflight))
                if dispatch_limit > 0:
                    items = db.query(B2STaskItem).filter(
                        or_(
                            B2STaskItem.status == "pending",
                            (B2STaskItem.status == "queued") & B2STaskItem.pi_job_id.is_(None),
                        ),
                        or_(B2STaskItem.next_dispatch_at.is_(None), B2STaskItem.next_dispatch_at <= now),
                    ).order_by(B2STaskItem.created_at.asc(), B2STaskItem.sequence_no.asc()).limit(dispatch_limit).all()
                    for item in items:
                        await dispatch_item_to_pi(db, item, owner_id=self.owner_id)
                        touched_tasks.add(item.task_id)
                        db.commit()
            for task_id in touched_tasks:
                task = db.query(B2STask).filter(B2STask.id == task_id).first()
                if task:
                    recompute_task_status(db, task)
            if touched_tasks:
                db.commit()
        finally:
            db.close()


_dispatcher = B2SDispatcher()


def get_dispatcher() -> B2SDispatcher:
    return _dispatcher
