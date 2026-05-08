"""Concurrency controls for fileserver."""

from __future__ import annotations

import asyncio
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from app.config import get_config
from app.exception import AppException


QueueClass = Literal["FAST", "IO_HEAVY", "STREAM"]

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
queue_class_ctx: ContextVar[str] = ContextVar("queue_class", default="FAST")


class BusyError(AppException):
    def __init__(self, queue_class: str):
        super().__init__(503, "QUEUE_BUSY", f"请求队列繁忙: {queue_class}")


@dataclass
class QueueStats:
    name: str
    limit: int
    active: int = 0
    queued: int = 0
    timeouts: int = 0
    completed: int = 0
    total_wait_ms: float = 0.0


class QueueController:
    def __init__(self) -> None:
        cfg = get_config().concurrency
        self._semaphores = {
            "FAST": asyncio.Semaphore(cfg.fast_limit),
            "IO_HEAVY": asyncio.Semaphore(cfg.io_heavy_limit),
            "STREAM": asyncio.Semaphore(cfg.stream_limit),
        }
        self._stats = {
            name: QueueStats(name=name, limit=limit)
            for name, limit in (
                ("FAST", cfg.fast_limit),
                ("IO_HEAVY", cfg.io_heavy_limit),
                ("STREAM", cfg.stream_limit),
            )
        }
        self._queue_timeout = cfg.queue_timeout_seconds

    async def __aenter_queue(self, queue_class: QueueClass):
        sem = self._semaphores[queue_class]
        stats = self._stats[queue_class]
        stats.queued += 1
        start = time.perf_counter()
        try:
            await asyncio.wait_for(sem.acquire(), timeout=self._queue_timeout)
        except TimeoutError as exc:
            stats.timeouts += 1
            raise BusyError(queue_class) from exc
        finally:
            stats.queued -= 1
        wait_ms = (time.perf_counter() - start) * 1000
        stats.total_wait_ms += wait_ms
        stats.active += 1
        return sem, stats

    async def run(self, queue_class: QueueClass, coro):
        sem, stats = await self.__aenter_queue(queue_class)
        token = queue_class_ctx.set(queue_class)
        try:
            return await coro
        finally:
            queue_class_ctx.reset(token)
            stats.active -= 1
            stats.completed += 1
            sem.release()

    def snapshot(self) -> dict:
        output: dict[str, dict] = {}
        for name, stats in self._stats.items():
            avg_wait = stats.total_wait_ms / stats.completed if stats.completed else 0.0
            output[name] = {
                "limit": stats.limit,
                "active": stats.active,
                "queued": stats.queued,
                "timeouts": stats.timeouts,
                "completed": stats.completed,
                "avg_queue_wait_ms": round(avg_wait, 3),
            }
        return output


_controller: QueueController | None = None


def get_queue_controller() -> QueueController:
    global _controller
    if _controller is None:
        _controller = QueueController()
    return _controller


def new_request_id() -> str:
    req_id = uuid.uuid4().hex
    request_id_ctx.set(req_id)
    return req_id


def get_request_id() -> str:
    return request_id_ctx.get()


def get_queue_class() -> str:
    return queue_class_ctx.get()
