"""Redis-backed task queue helpers."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.config import get_config


logger = logging.getLogger(__name__)


class TaskQueue:
    def __init__(self) -> None:
        self.config = get_config().queue

    def _new_client(self) -> Redis:
        return Redis.from_url(
            self.config.redis_url,
            decode_responses=True,
            socket_timeout=max(10, int(self.config.block_timeout_seconds) + 5),
            socket_connect_timeout=5,
            health_check_interval=30,
            socket_keepalive=True,
        )

    async def push_task(self, task_id: str) -> None:
        client = self._new_client()
        try:
            await self._push_unique(client, self.config.task_queue_key, str(task_id))
        finally:
            await self._close_client(client)

    async def push_operation(self, operation_id: str) -> None:
        client = self._new_client()
        try:
            await self._push_unique(client, self.config.operation_queue_key, str(operation_id))
        finally:
            await self._close_client(client)

    async def pop_task(self, timeout_seconds: int | None = None) -> Optional[str]:
        client = self._new_client()
        try:
            try:
                result = await client.blpop(
                    self.config.task_queue_key,
                    timeout=max(1, int(timeout_seconds or self.config.block_timeout_seconds)),
                )
            except RedisTimeoutError:
                return None
            except (RedisConnectionError, OSError):
                return None
            return await self._consume_result(client, self.config.task_queue_key, result)
        finally:
            await self._close_client(client)

    async def pop_operation(self, timeout_seconds: int | None = None) -> Optional[str]:
        client = self._new_client()
        queue_key = self.config.operation_queue_key
        try:
            try:
                result = await client.blpop(
                    queue_key,
                    timeout=max(1, int(timeout_seconds or self.config.block_timeout_seconds)),
                )
            except RedisTimeoutError:
                return None
            except (RedisConnectionError, OSError):
                return None
            return await self._consume_result(client, queue_key, result)
        finally:
            await self._close_client(client)

    async def _close_client(self, client: Redis) -> None:
        try:
            await client.aclose()
        except Exception:
            logger.debug("failed closing redis client", exc_info=True)

    async def _push_unique(self, client: Redis, queue_key: str, task_id: str) -> None:
        value = str(task_id or "").strip()
        if not value:
            return
        dedupe_key = f"{queue_key}:dedupe"
        added = await client.sadd(dedupe_key, value)
        if added:
            await client.rpush(queue_key, value)
            await client.zadd(f"{queue_key}:enqueued_at", {value: time.time()})
            return

        # Heal stale dedupe entries left behind by interrupted consumers. If the
        # list no longer contains the task ID, re-enqueue it so preparing/pending
        # tasks cannot get stuck forever behind an orphaned dedupe marker.
        present_in_queue = await client.lpos(queue_key, value)
        if present_in_queue is not None:
            await client.zadd(f"{queue_key}:enqueued_at", {value: time.time()})
            return

        await client.srem(dedupe_key, value)
        restored = await client.sadd(dedupe_key, value)
        if restored:
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
            try:
                while await client.lpos(queue_key, task_id) is not None:
                    await client.lrem(queue_key, 1, task_id)
            except AttributeError:
                pass
        return task_id

    async def queue_stats(self, queue_key: str) -> dict[str, float | int]:
        client = self._new_client()
        try:
            length = int(await client.llen(queue_key) or 0)
            oldest = await client.zrange(f"{queue_key}:enqueued_at", 0, 0, withscores=True)
        except (RedisTimeoutError, RedisConnectionError, OSError):
            return {
                "length": 0,
                "oldest_age_seconds": 0.0,
            }
        finally:
            await self._close_client(client)
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
        task_queue, operation_queue = await asyncio.gather(
            self.queue_stats(self.config.task_queue_key),
            self.queue_stats(self.config.operation_queue_key),
        )
        return {
            "task_queue": task_queue,
            "operation_queue": operation_queue,
        }

    async def close(self) -> None:
        return


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
