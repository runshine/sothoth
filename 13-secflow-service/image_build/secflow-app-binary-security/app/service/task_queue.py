"""Redis-backed task queue helpers."""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from redis.asyncio import Redis

from app.config import get_config


class TaskQueue:
    def __init__(self) -> None:
        self.config = get_config().queue
        self._client: Redis | None = None
        self._lock = asyncio.Lock()

    async def _client_or_create(self) -> Redis:
        async with self._lock:
            if self._client is None:
                self._client = Redis.from_url(self.config.redis_url, decode_responses=True)
            return self._client

    async def push_task(self, task_id: str) -> None:
        client = await self._client_or_create()
        await self._push_unique(client, self.config.task_queue_key, str(task_id))

    async def push_action(self, task_id: str) -> None:
        client = await self._client_or_create()
        await self._push_unique(client, self.config.action_queue_key, str(task_id))

    async def pop_task(self, timeout_seconds: int | None = None) -> Optional[str]:
        client = await self._client_or_create()
        result = await client.blpop(
            self.config.task_queue_key,
            timeout=max(1, int(timeout_seconds or self.config.block_timeout_seconds)),
        )
        return await self._consume_result(client, self.config.task_queue_key, result)

    async def pop_action(self, timeout_seconds: int | None = None) -> Optional[str]:
        client = await self._client_or_create()
        result = await client.blpop(
            self.config.action_queue_key,
            timeout=max(1, int(timeout_seconds or self.config.block_timeout_seconds)),
        )
        return await self._consume_result(client, self.config.action_queue_key, result)

    async def _push_unique(self, client: Redis, queue_key: str, task_id: str) -> None:
        value = str(task_id or "").strip()
        if not value:
            return
        dedupe_key = f"{queue_key}:dedupe"
        added = await client.sadd(dedupe_key, value)
        if added:
            await client.rpush(queue_key, value)
            await client.zadd(f"{queue_key}:enqueued_at", {value: time.time()})

    async def _consume_result(self, client: Redis, queue_key: str, result) -> Optional[str]:
        if not result:
            return None
        _, value = result
        task_id = str(value or "").strip() or None
        if task_id:
            await client.srem(f"{queue_key}:dedupe", task_id)
            await client.zrem(f"{queue_key}:enqueued_at", task_id)
        return task_id

    async def queue_stats(self, queue_key: str) -> dict[str, float | int]:
        client = await self._client_or_create()
        length = int(await client.llen(queue_key) or 0)
        oldest = await client.zrange(f"{queue_key}:enqueued_at", 0, 0, withscores=True)
        oldest_age_seconds = 0.0
        if oldest:
            _, score = oldest[0]
            try:
                oldest_age_seconds = max(0.0, time.time() - float(score))
            except (TypeError, ValueError):
                oldest_age_seconds = 0.0
        return {
            "length": length,
            "oldest_age_seconds": oldest_age_seconds,
        }

    async def snapshot(self) -> dict[str, dict[str, float | int]]:
        client = await self._client_or_create()
        task_queue, action_queue = await asyncio.gather(
            self.queue_stats(self.config.task_queue_key),
            self.queue_stats(self.config.action_queue_key),
        )
        return {
            "task_queue": task_queue,
            "action_queue": action_queue,
        }

    async def close(self) -> None:
        async with self._lock:
            client = self._client
            self._client = None
        if client is not None:
            await client.aclose()


_task_queue: TaskQueue | None = None


def get_task_queue() -> TaskQueue:
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue()
    return _task_queue


async def close_task_queue() -> None:
    global _task_queue
    queue = _task_queue
    _task_queue = None
    if queue is not None:
        await queue.close()
