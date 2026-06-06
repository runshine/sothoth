"""Redis-backed runtime primitives for scheduler/workers."""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from typing import Optional

from redis.asyncio import Redis

from app.config import get_config


class _LocalQueue:
    def __init__(self) -> None:
        self.ready = deque()
        self.delay: dict[str, float] = {}
        self.enqueued_at: dict[str, float] = {}
        self.leases: dict[str, tuple[str, float]] = {}
        self.locks: dict[str, asyncio.Lock] = {}
        self.ready_dedupe: set[str] = set()
        self.bucket_counts: dict[str, tuple[int, float]] = {}
        self._cond = asyncio.Condition()

    async def push_ready(self, execution_id: str) -> None:
        async with self._cond:
            if execution_id not in self.ready_dedupe:
                self.ready.append(execution_id)
                self.ready_dedupe.add(execution_id)
                self.enqueued_at[execution_id] = time.time()
                self._cond.notify_all()

    async def pop_ready(self, timeout_seconds: int) -> Optional[str]:
        end = time.time() + max(1, int(timeout_seconds))
        async with self._cond:
            while not self.ready:
                remaining = end - time.time()
                if remaining <= 0:
                    return None
                try:
                    await asyncio.wait_for(self._cond.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    return None
            execution_id = self.ready.popleft()
            self.ready_dedupe.discard(execution_id)
            self.enqueued_at.pop(execution_id, None)
            return execution_id


class RedisRuntime:
    def __init__(self) -> None:
        self.config = get_config().redis
        self._client: Redis | None = None
        self._lock = asyncio.Lock()
        self._local = _LocalQueue()
        self._force_local = not self.config.enabled
        self._pod_name = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME") or "local-pod"

    @property
    def key_prefix(self) -> str:
        return self.config.key_prefix.rstrip(":")

    @property
    def pod_name(self) -> str:
        return self._pod_name

    def key(self, suffix: str) -> str:
        return f"{self.key_prefix}:{suffix}"

    async def _get_client(self) -> Redis | None:
        if self._force_local:
            return None
        async with self._lock:
            if self._client is None:
                self._client = Redis.from_url(
                    self.config.url,
                    decode_responses=True,
                    socket_timeout=max(1, int(self.config.socket_timeout_seconds)),
                    socket_connect_timeout=max(1, int(self.config.socket_timeout_seconds)),
                    health_check_interval=30,
                    socket_keepalive=True,
                )
            try:
                await self._client.ping()
            except Exception:
                self._force_local = True
                return None
            return self._client

    async def is_redis_available(self) -> bool:
        return await self._get_client() is not None

    async def acquire_leader(self, token: str, ttl_seconds: int) -> bool:
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(self.key("leader"))
            if lease and lease[1] > time.time() and lease[0] != token:
                return False
            self._local.leases[self.key("leader")] = (token, time.time() + ttl_seconds)
            return True
        return bool(await client.set(self.key("leader"), token, ex=ttl_seconds, nx=True))

    async def renew_leader(self, token: str, ttl_seconds: int) -> bool:
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(self.key("leader"))
            if lease and lease[0] == token:
                self._local.leases[self.key("leader")] = (token, time.time() + ttl_seconds)
                return True
            return False
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("expire", KEYS[1], ARGV[2])
        end
        return 0
        """
        return bool(await client.eval(script, 1, self.key("leader"), token, int(ttl_seconds)))

    async def current_leader(self) -> Optional[str]:
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(self.key("leader"))
            if lease and lease[1] > time.time():
                return lease[0]
            return None
        return await client.get(self.key("leader"))

    async def release_leader(self, token: str) -> None:
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(self.key("leader"))
            if lease and lease[0] == token:
                self._local.leases.pop(self.key("leader"), None)
            return
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("del", KEYS[1])
        end
        return 0
        """
        await client.eval(script, 1, self.key("leader"), token)

    async def enqueue_ready(self, execution_id: str) -> None:
        client = await self._get_client()
        if client is None:
            await self._local.push_ready(execution_id)
            return
        dedupe_key = self.key("ready:dedupe")
        ready_key = self.key("ready")
        if await client.sadd(dedupe_key, execution_id):
            await client.rpush(ready_key, execution_id)
        await client.zadd(self.key("ready:enqueued_at"), {execution_id: time.time()})

    async def pop_ready(self, timeout_seconds: int = 1) -> Optional[str]:
        client = await self._get_client()
        if client is None:
            return await self._local.pop_ready(timeout_seconds)
        result = await client.blpop(self.key("ready"), timeout=max(1, int(timeout_seconds)))
        if not result:
            return None
        _, execution_id = result
        await client.srem(self.key("ready:dedupe"), execution_id)
        await client.zrem(self.key("ready:enqueued_at"), execution_id)
        return execution_id

    async def schedule_delay(self, execution_id: str, execute_at_epoch: float) -> None:
        client = await self._get_client()
        if client is None:
            self._local.delay[execution_id] = execute_at_epoch
            return
        await client.zadd(self.key("delay"), {execution_id: execute_at_epoch})

    async def promote_due_delay(self, limit: int) -> list[str]:
        now = time.time()
        client = await self._get_client()
        if client is None:
            due = [key for key, score in list(self._local.delay.items()) if score <= now][:limit]
            for key in due:
                self._local.delay.pop(key, None)
                await self._local.push_ready(key)
            return due
        values = await client.zrangebyscore(self.key("delay"), min="-inf", max=now, start=0, num=max(1, int(limit)))
        if not values:
            return []
        pipe = client.pipeline()
        for value in values:
            pipe.zrem(self.key("delay"), value)
            pipe.sadd(self.key("ready:dedupe"), value)
            pipe.rpush(self.key("ready"), value)
            pipe.zadd(self.key("ready:enqueued_at"), {value: time.time()})
        await pipe.execute()
        return values

    async def acquire_execution_lease(self, execution_id: str, token: str, ttl_seconds: int) -> bool:
        lease_key = self.key(f"lease:{execution_id}")
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(lease_key)
            if lease and lease[1] > time.time():
                return False
            self._local.leases[lease_key] = (token, time.time() + ttl_seconds)
            return True
        return bool(await client.set(lease_key, token, ex=ttl_seconds, nx=True))

    async def renew_execution_lease(self, execution_id: str, token: str, ttl_seconds: int) -> bool:
        lease_key = self.key(f"lease:{execution_id}")
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(lease_key)
            if lease and lease[0] == token:
                self._local.leases[lease_key] = (token, time.time() + ttl_seconds)
                return True
            return False
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("expire", KEYS[1], ARGV[2])
        end
        return 0
        """
        return bool(await client.eval(script, 1, lease_key, token, int(ttl_seconds)))

    async def release_execution_lease(self, execution_id: str, token: str) -> None:
        lease_key = self.key(f"lease:{execution_id}")
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(lease_key)
            if lease and lease[0] == token:
                self._local.leases.pop(lease_key, None)
            return
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("del", KEYS[1])
        end
        return 0
        """
        await client.eval(script, 1, lease_key, token)

    async def execution_lease_exists(self, execution_id: str) -> bool:
        lease_key = self.key(f"lease:{execution_id}")
        client = await self._get_client()
        if client is None:
            lease = self._local.leases.get(lease_key)
            return bool(lease and lease[1] > time.time())
        return bool(await client.exists(lease_key))

    async def acquire_bucket_slot(self, bucket_key: str, limit: int, ttl_seconds: int) -> bool:
        effective_limit = max(1, int(limit))
        redis_key = self.key(bucket_key)
        client = await self._get_client()
        if client is None:
            count, _ = self._local.bucket_counts.get(redis_key, (0, 0))
            if count >= effective_limit:
                return False
            self._local.bucket_counts[redis_key] = (count + 1, time.time() + ttl_seconds)
            return True
        script = """
        local current = tonumber(redis.call("get", KEYS[1]) or "0")
        local limit = tonumber(ARGV[1])
        if current >= limit then
          return 0
        end
        current = redis.call("incr", KEYS[1])
        redis.call("expire", KEYS[1], ARGV[2])
        return current
        """
        result = await client.eval(script, 1, redis_key, effective_limit, max(1, int(ttl_seconds)))
        return bool(result)

    async def release_bucket_slot(self, bucket_key: str) -> None:
        redis_key = self.key(bucket_key)
        client = await self._get_client()
        if client is None:
            count, expire_at = self._local.bucket_counts.get(redis_key, (0, 0))
            if count <= 1:
                self._local.bucket_counts.pop(redis_key, None)
            else:
                self._local.bucket_counts[redis_key] = (count - 1, expire_at)
            return
        script = """
        local current = tonumber(redis.call("get", KEYS[1]) or "0")
        if current <= 1 then
          return redis.call("del", KEYS[1])
        end
        return redis.call("decr", KEYS[1])
        """
        await client.eval(script, 1, redis_key)

    async def queue_stats(self) -> dict[str, float | int]:
        client = await self._get_client()
        if client is None:
            oldest = min(self._local.enqueued_at.values()) if self._local.enqueued_at else None
            return {
                "length": len(self._local.ready),
                "oldest_age_seconds": max(0.0, time.time() - oldest) if oldest else 0.0,
                "backend": "local",
            }
        length = int(await client.llen(self.key("ready")) or 0)
        oldest = await client.zrange(self.key("ready:enqueued_at"), 0, 0, withscores=True)
        oldest_age = 0.0
        if oldest:
            oldest_age = max(0.0, time.time() - float(oldest[0][1]))
        return {"length": length, "oldest_age_seconds": oldest_age, "backend": "redis"}

    async def metrics_snapshot(self) -> dict[str, str | int | float | bool | None]:
        leader = await self.current_leader()
        stats = await self.queue_stats()
        return {
            "leader": leader,
            "pod_name": self.pod_name,
            "ready_length": stats["length"],
            "ready_oldest_age_seconds": stats["oldest_age_seconds"],
            "redis_available": await self.is_redis_available(),
            "queue_backend": stats["backend"],
        }

    async def close(self) -> None:
        async with self._lock:
            client = self._client
            self._client = None
        if client is not None:
            await client.aclose()


_redis_runtime: RedisRuntime | None = None


def get_redis_runtime() -> RedisRuntime:
    global _redis_runtime
    if _redis_runtime is None:
        _redis_runtime = RedisRuntime()
    return _redis_runtime


async def close_redis_runtime() -> None:
    global _redis_runtime
    runtime = _redis_runtime
    _redis_runtime = None
    if runtime is not None:
        await runtime.close()
