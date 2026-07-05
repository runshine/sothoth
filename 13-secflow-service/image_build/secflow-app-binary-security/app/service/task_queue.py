"""Redis-backed task queue helpers."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Optional

from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.config import get_config


logger = logging.getLogger(__name__)
REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS = 10
REDIS_SOCKET_TIMEOUT_SECONDS = 10
DEFAULT_QUEUE_CONTEXT = "unspecified"
REDIS_REBUILD_RETRY_MAX_SLEEP_SECONDS = 10
REDIS_HEALTH_CHECK_INTERVAL_SECONDS = 10


class RedisSelfHealingClientHelper:
    def __init__(
        self,
        *,
        redis_url: str,
        client_log_name: str,
        client_type: str,
        extra_log_fields_fn=None,
    ) -> None:
        self.redis_url = redis_url
        self.client_log_name = str(client_log_name or "redis").strip() or "redis"
        self.client_type = str(client_type or "redis").strip() or "redis"
        self.extra_log_fields_fn = extra_log_fields_fn
        self._clients_by_loop_id: dict[asyncio.AbstractEventLoop, Redis] = {}

    def current_loop(self) -> asyncio.AbstractEventLoop:
        return asyncio.get_running_loop()

    def _extra_log_fields(self) -> tuple[str, list[Any]]:
        if self.extra_log_fields_fn is None:
            return "", []
        extra = dict(self.extra_log_fields_fn() or {})
        if not extra:
            return "", []
        fragments: list[str] = []
        values: list[Any] = []
        for key, value in extra.items():
            fragments.append(f" {key}=%s")
            values.append(value)
        return "".join(fragments), values

    def forget_client(self, client: Redis, *, loop: asyncio.AbstractEventLoop | None = None) -> None:
        if loop is not None:
            current = self._clients_by_loop_id.get(loop)
            if current is client:
                self._clients_by_loop_id.pop(loop, None)
            return
        stale_loops = [cached_loop for cached_loop, cached in self._clients_by_loop_id.items() if cached is client]
        for cached_loop in stale_loops:
            self._clients_by_loop_id.pop(cached_loop, None)

    def new_client(self, *, context: str = DEFAULT_QUEUE_CONTEXT) -> Redis:
        loop = self.current_loop()
        existing = self._clients_by_loop_id.get(loop)
        if existing is not None:
            return existing
        extra_fmt, extra_values = self._extra_log_fields()
        logger.info(
            f"binary-security {self.client_log_name} creating redis client: context=%s loop_id=%s redis_url=%s "
            f"socket_connect_timeout=%s socket_timeout=%s health_check_interval=%s active_loop_client_count=%s"
            f"{extra_fmt}",
            str(context or DEFAULT_QUEUE_CONTEXT).strip() or DEFAULT_QUEUE_CONTEXT,
            id(loop),
            str(self.redis_url or "").strip() or None,
            REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS,
            REDIS_SOCKET_TIMEOUT_SECONDS,
            REDIS_HEALTH_CHECK_INTERVAL_SECONDS,
            len(self._clients_by_loop_id),
            *extra_values,
        )
        client = Redis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
            socket_connect_timeout=REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS,
            health_check_interval=REDIS_HEALTH_CHECK_INTERVAL_SECONDS,
            socket_keepalive=True,
            retry_on_timeout=True,
        )
        self._clients_by_loop_id[loop] = client
        return client

    @staticmethod
    def is_retryable_connection_error(exc: Exception) -> bool:
        return isinstance(
            exc,
            (
                RedisConnectionError,
                RedisTimeoutError,
                OSError,
                ConnectionResetError,
                BrokenPipeError,
                EOFError,
            ),
        )

    async def close_client(self, client: Redis) -> None:
        loop = None
        try:
            loop = self.current_loop()
        except RuntimeError:
            loop = None
        try:
            await client.aclose()
        except Exception:
            logger.debug("failed closing redis client", exc_info=True)
        finally:
            self.forget_client(client, loop=loop)

    async def invalidate_cached_client(
        self,
        client: Redis,
        *,
        context: str,
        op_name: str,
        error: Exception,
    ) -> None:
        try:
            loop = self.current_loop()
            loop_id = id(loop)
        except RuntimeError:
            loop_id = None
        logger.warning(
            "binary-security redis client invalidated: op_name=%s context=%s loop_id=%s redis_client_type=%s redis_url=%s error_type=%s error=%s",
            str(op_name or "unknown").strip() or "unknown",
            str(context or DEFAULT_QUEUE_CONTEXT).strip() or DEFAULT_QUEUE_CONTEXT,
            loop_id,
            self.client_type,
            str(self.redis_url or "").strip() or None,
            error.__class__.__name__,
            error,
        )
        await self.close_client(client)

    @staticmethod
    async def sleep_before_rebuild_retry(attempt: int) -> None:
        backoff = min(REDIS_REBUILD_RETRY_MAX_SLEEP_SECONDS, max(1, int(attempt)))
        if attempt <= 1:
            backoff = 1
        elif attempt == 2:
            backoff = 2
        elif attempt == 3:
            backoff = 5
        else:
            backoff = REDIS_REBUILD_RETRY_MAX_SLEEP_SECONDS
        await asyncio.sleep(backoff)

    async def execute_with_rebuild_forever(
        self,
        op_name: str,
        *,
        context: str,
        fn,
    ):
        attempt = 0
        while True:
            client = self.new_client(context=context)
            try:
                result = await fn(client)
                if attempt > 0:
                    logger.info(
                        "binary-security redis operation recovered after rebuild: op_name=%s context=%s attempts=%s redis_client_type=%s redis_url=%s",
                        str(op_name or "unknown").strip() or "unknown",
                        str(context or DEFAULT_QUEUE_CONTEXT).strip() or DEFAULT_QUEUE_CONTEXT,
                        attempt + 1,
                        self.client_type,
                        str(self.redis_url or "").strip() or None,
                    )
                return result
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not self.is_retryable_connection_error(exc):
                    raise
                attempt += 1
                await self.invalidate_cached_client(
                    client,
                    context=context,
                    op_name=op_name,
                    error=exc,
                )
                logger.warning(
                    "binary-security redis client rebuild retry scheduled: op_name=%s context=%s attempt=%s redis_client_type=%s redis_url=%s error_type=%s error=%s",
                    str(op_name or "unknown").strip() or "unknown",
                    str(context or DEFAULT_QUEUE_CONTEXT).strip() or DEFAULT_QUEUE_CONTEXT,
                    attempt,
                    self.client_type,
                    str(self.redis_url or "").strip() or None,
                    exc.__class__.__name__,
                    exc,
                )
                await self.sleep_before_rebuild_retry(attempt)
                self.new_client(context=context)
                logger.info(
                    "binary-security redis client rebuilt successfully: op_name=%s context=%s attempt=%s loop_id=%s redis_client_type=%s redis_url=%s",
                    str(op_name or "unknown").strip() or "unknown",
                    str(context or DEFAULT_QUEUE_CONTEXT).strip() or DEFAULT_QUEUE_CONTEXT,
                    attempt,
                    id(self.current_loop()),
                    self.client_type,
                    str(self.redis_url or "").strip() or None,
                )

    async def ping(self, *, context: str) -> None:
        await self.execute_with_rebuild_forever(
            "ping",
            context=context,
            fn=lambda client: client.ping(),
        )

    async def close(self) -> None:
        clients = list(dict.fromkeys(self._clients_by_loop_id.values()))
        self._clients_by_loop_id.clear()
        for client in clients:
            try:
                await client.aclose()
            except Exception:
                logger.debug("failed closing redis client", exc_info=True)


class TaskQueue:
    def __init__(self) -> None:
        self.config = get_config().queue
        self._redis_helper = RedisSelfHealingClientHelper(
            redis_url=self.config.redis_url,
            client_log_name="task queue",
            client_type="task_queue",
            extra_log_fields_fn=lambda: {
                "task_queue_key": str(self.config.task_queue_key or "").strip() or None,
            },
        )

    def _current_loop(self) -> asyncio.AbstractEventLoop:
        return self._redis_helper.current_loop()

    def _forget_client(self, client: Redis, *, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self._redis_helper.forget_client(client, loop=loop)

    def _new_client(self, *, context: str = DEFAULT_QUEUE_CONTEXT) -> Redis:
        return self._redis_helper.new_client(context=context)

    @staticmethod
    def _is_retryable_redis_connection_error(exc: Exception) -> bool:
        return RedisSelfHealingClientHelper.is_retryable_connection_error(exc)

    async def _invalidate_cached_client(
        self,
        client: Redis,
        *,
        context: str,
        op_name: str,
        error: Exception,
    ) -> None:
        await self._redis_helper.invalidate_cached_client(
            client,
            context=context,
            op_name=op_name,
            error=error,
        )

    @staticmethod
    async def _sleep_before_redis_rebuild_retry(attempt: int) -> None:
        await RedisSelfHealingClientHelper.sleep_before_rebuild_retry(attempt)

    async def _execute_with_client_rebuild_forever(
        self,
        op_name: str,
        *,
        context: str,
        fn,
    ):
        return await self._redis_helper.execute_with_rebuild_forever(
            op_name,
            context=context,
            fn=fn,
        )

    async def ping(self, *, context: str = "startup_warmup") -> None:
        await self._redis_helper.ping(context=context)

    async def wait_until_ready(
        self,
        *,
        context: str = "startup_warmup",
        timeout_seconds: int | None = None,
        retry_interval_seconds: int | None = None,
    ) -> None:
        del timeout_seconds, retry_interval_seconds
        await self.ping(context=context)
        logger.info(
            "binary-security task queue redis warmup ok: context=%s timeout_semantics=infinite_until_recovered",
            str(context or DEFAULT_QUEUE_CONTEXT).strip() or DEFAULT_QUEUE_CONTEXT,
        )

    async def push_task(self, task_id: str, *, context: str = "task_enqueue") -> None:
        await self._execute_with_client_rebuild_forever(
            "push_task",
            context=context,
            fn=lambda client: self._push_unique(client, self.config.task_queue_key, str(task_id)),
        )

    async def push_delete_task(self, task_id: str, *, context: str = "task_delete_enqueue") -> None:
        queue_key = str(getattr(self.config, "delete_queue_key", "") or "binary_security_delete_queue").strip()
        await self._execute_with_client_rebuild_forever(
            "push_delete_task",
            context=context,
            fn=lambda client: self._push_unique(client, queue_key, str(task_id)),
        )

    async def push_owner_signal(
        self,
        owner_instance_id: str,
        task_id: str,
        *,
        context: str = "owner_signal_enqueue",
    ) -> None:
        normalized_owner = str(owner_instance_id or "").strip()
        normalized_task_id = str(task_id or "").strip()
        if not normalized_owner or not normalized_task_id:
            return
        signal_key = self._owner_signal_key(normalized_owner, normalized_task_id)
        payload = json.dumps(
            {
                "owner_instance_id": normalized_owner,
                "task_id": normalized_task_id,
                "signaled_at": time.time(),
                "context": str(context or DEFAULT_QUEUE_CONTEXT).strip() or DEFAULT_QUEUE_CONTEXT,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
        await self._execute_with_client_rebuild_forever(
            "push_owner_signal",
            context=context,
            fn=lambda client: client.set(signal_key, payload, ex=300),
        )

    async def consume_owner_signal(
        self,
        owner_instance_id: str,
        task_id: str,
        *,
        context: str = "owner_signal_consume",
    ) -> dict[str, Any] | None:
        normalized_owner = str(owner_instance_id or "").strip()
        normalized_task_id = str(task_id or "").strip()
        if not normalized_owner or not normalized_task_id:
            return None
        signal_key = self._owner_signal_key(normalized_owner, normalized_task_id)
        async def _consume(client: Redis):
            raw = await client.get(signal_key)
            if raw is None:
                return None
            await client.delete(signal_key)
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else None

        return await self._execute_with_client_rebuild_forever(
            "consume_owner_signal",
            context=context,
            fn=_consume,
        )

    async def force_requeue_task(self, task_id: str, *, context: str = "task_enqueue") -> None:
        await self._execute_with_client_rebuild_forever(
            "force_requeue_task",
            context=context,
            fn=lambda client: self._force_requeue(client, self.config.task_queue_key, str(task_id)),
        )

    async def force_requeue_delete_task(self, task_id: str, *, context: str = "task_delete_enqueue") -> None:
        queue_key = str(getattr(self.config, "delete_queue_key", "") or "binary_security_delete_queue").strip()
        await self._execute_with_client_rebuild_forever(
            "force_requeue_delete_task",
            context=context,
            fn=lambda client: self._force_requeue(client, queue_key, str(task_id)),
        )

    async def pop_task(self, timeout_seconds: int | None = None, *, context: str = "task_dispatch_pop") -> Optional[str]:
        async def _pop(client: Redis):
            result = await client.blpop(
                self.config.task_queue_key,
                timeout=max(1, int(timeout_seconds or self.config.block_timeout_seconds)),
            )
            return await self._consume_result(client, self.config.task_queue_key, result)

        return await self._execute_with_client_rebuild_forever(
            "pop_task",
            context=context,
            fn=_pop,
        )

    async def pop_delete_task(self, timeout_seconds: int | None = None, *, context: str = "task_delete_dispatch_pop") -> Optional[str]:
        queue_key = str(getattr(self.config, "delete_queue_key", "") or "binary_security_delete_queue").strip()
        async def _pop(client: Redis):
            result = await client.blpop(
                queue_key,
                timeout=max(1, int(timeout_seconds or self.config.block_timeout_seconds)),
            )
            return await self._consume_result(client, queue_key, result)

        return await self._execute_with_client_rebuild_forever(
            "pop_delete_task",
            context=context,
            fn=_pop,
        )

    async def _close_client(self, client: Redis) -> None:
        await self._redis_helper.close_client(client)

    async def _push_unique(self, client: Redis, queue_key: str, task_id: str) -> None:
        value = str(task_id or "").strip()
        if not value:
            return
        dedupe_key = f"{queue_key}:dedupe"
        enqueued_key = f"{queue_key}:enqueued_at"
        added = await client.sadd(dedupe_key, value)
        if added:
            await client.rpush(queue_key, value)
            await client.zadd(enqueued_key, {value: time.time()})
            return

        # Heal stale dedupe entries left behind by interrupted consumers. If the
        # list no longer contains the task ID, re-enqueue it so preparing/pending
        # tasks cannot get stuck forever behind an orphaned dedupe marker.
        present_in_queue = await client.lpos(queue_key, value)
        if present_in_queue is not None:
            await client.zadd(enqueued_key, {value: time.time()})
            return

        await client.srem(dedupe_key, value)
        restored = await client.sadd(dedupe_key, value)
        if restored:
            await client.rpush(queue_key, value)
            await client.zadd(enqueued_key, {value: time.time()})

    async def _force_requeue(self, client: Redis, queue_key: str, task_id: str) -> None:
        value = str(task_id or "").strip()
        if not value:
            return
        dedupe_key = f"{queue_key}:dedupe"
        enqueued_key = f"{queue_key}:enqueued_at"
        await client.srem(dedupe_key, value)
        try:
            while await client.lpos(queue_key, value) is not None:
                await client.lrem(queue_key, 1, value)
        except AttributeError:
            pass
        await client.zrem(enqueued_key, value)
        await client.sadd(dedupe_key, value)
        await client.rpush(queue_key, value)
        await client.zadd(enqueued_key, {value: time.time()})

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

    async def queue_stats(self, queue_key: str, *, context: str = "queue_snapshot") -> dict[str, float | int]:
        async def _stats(client: Redis):
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

        return await self._execute_with_client_rebuild_forever(
            "queue_stats",
            context=context,
            fn=_stats,
        )

    async def queue_positions(self, queue_key: str, *, context: str = "queue_snapshot") -> dict[str, int]:
        async def _positions(client: Redis):
            task_ids = [str(value or "").strip() for value in list(await client.lrange(queue_key, 0, -1) or [])]
            positions: dict[str, int] = {}
            for index, task_id in enumerate(task_ids, start=1):
                if task_id and task_id not in positions:
                    positions[task_id] = index
            return positions

        return await self._execute_with_client_rebuild_forever(
            "queue_positions",
            context=context,
            fn=_positions,
        )

    async def snapshot(self) -> dict[str, dict[str, float | int]]:
        task_queue = await self.queue_stats(self.config.task_queue_key, context="queue_snapshot")
        return {
            "task_queue": task_queue,
            "operation_queue": {
                "length": 0,
                "oldest_age_seconds": 0.0,
                "enabled": 0,
            },
        }

    async def dedupe_orphans(self, queue_key: str) -> dict[str, Any]:
        async def _dedupe(client: Redis):
            members = sorted(list(await client.smembers(f"{queue_key}:dedupe") or []))
            orphaned: list[str] = []
            missing_timestamps: list[str] = []
            for member in members:
                if await client.lpos(queue_key, member) is None:
                    orphaned.append(member)
                    continue
                timestamp_present = await client.zscore(f"{queue_key}:enqueued_at", member)
                if timestamp_present is None:
                    missing_timestamps.append(member)
                    await client.zadd(f"{queue_key}:enqueued_at", {member: time.time()})
            return {
                "dedupe_count": len(members),
                "orphan_count": len(orphaned),
                "orphan_ids": orphaned,
                "missing_timestamp_count": len(missing_timestamps),
                "missing_timestamp_ids": missing_timestamps,
            }

        return await self._execute_with_client_rebuild_forever(
            "dedupe_orphans",
            context="queue_snapshot",
            fn=_dedupe,
        )

    async def cleanup_dedupe_orphans(self, queue_key: str) -> dict[str, Any]:
        async def _cleanup(client: Redis):
            snapshot = await self.dedupe_orphans(queue_key)
            orphan_ids = list(snapshot.get("orphan_ids") or [])
            dedupe_key = f"{queue_key}:dedupe"
            enqueued_key = f"{queue_key}:enqueued_at"
            removed_ids: list[str] = []
            for orphan_id in orphan_ids:
                await client.srem(dedupe_key, orphan_id)
                await client.zrem(enqueued_key, orphan_id)
                removed_ids.append(orphan_id)
            return {
                **snapshot,
                "removed_orphan_count": len(removed_ids),
                "removed_orphan_ids": removed_ids,
            }

        return await self._execute_with_client_rebuild_forever(
            "cleanup_dedupe_orphans",
            context="queue_snapshot",
            fn=_cleanup,
        )

    async def close(self) -> None:
        await self._redis_helper.close()

    def _task_sync_queue_base(self, task_id: str) -> str:
        prefix = str(getattr(self.config, "task_sync_queue_prefix", "") or "").strip() or "bs:task_sync_queue"
        return f"{prefix}:{str(task_id or '').strip()}"

    def _task_sync_queue_keys(self, task_id: str) -> dict[str, str]:
        base = self._task_sync_queue_base(task_id)
        return {
            "queue": f"{base}:queue",
            "dedupe": f"{base}:dedupe",
            "payload_prefix": f"{base}:payload",
            "lock": f"{base}:repair_lock",
        }

    def _owner_signal_key(self, owner_instance_id: str, task_id: str) -> str:
        prefix = str(getattr(self.config, "task_sync_queue_prefix", "") or "").strip() or "bs:task_sync_queue"
        return f"{prefix}:owner_signal:{str(owner_instance_id or '').strip()}:{str(task_id or '').strip()}"

    async def enqueue_task_sync_request(
        self,
        task_id: str,
        entry: dict[str, Any],
        *,
        dedupe_key: str,
        context: str = "task_sync_enqueue",
    ) -> dict[str, Any]:
        normalized_task_id = str(task_id or "").strip()
        normalized_dedupe_key = str(dedupe_key or "").strip()
        if not normalized_task_id or not normalized_dedupe_key:
            raise ValueError("task_id and dedupe_key are required")
        keys = self._task_sync_queue_keys(normalized_task_id)
        now_score = self._task_sync_entry_score(entry)
        async def _enqueue(client: Redis):
            existing_item_id = await client.hget(keys["dedupe"], normalized_dedupe_key)
            if existing_item_id:
                payload_key = f"{keys['payload_prefix']}:{existing_item_id}"
                existing_raw = await client.get(payload_key)
                existing_entry = json.loads(existing_raw) if existing_raw else {}
                merged = self._merge_task_sync_entries(existing_entry, entry)
                merged["queue_item_id"] = str(existing_item_id).strip()
                await client.set(payload_key, json.dumps(merged, ensure_ascii=True, sort_keys=True))
                await client.zadd(keys["queue"], {merged["queue_item_id"]: self._task_sync_entry_score(merged)})
                return merged
            queue_item_id = str(entry.get("queue_item_id") or f"tsq_{uuid.uuid4().hex[:24]}").strip()
            normalized_entry = self._normalize_task_sync_entry(
                {
                    **dict(entry or {}),
                    "queue_item_id": queue_item_id,
                    "dedupe_key": normalized_dedupe_key,
                }
            )
            await client.set(
                f"{keys['payload_prefix']}:{queue_item_id}",
                json.dumps(normalized_entry, ensure_ascii=True, sort_keys=True),
            )
            await client.hset(keys["dedupe"], normalized_dedupe_key, queue_item_id)
            await client.zadd(keys["queue"], {queue_item_id: now_score})
            return normalized_entry
        return await self._execute_with_client_rebuild_forever(
            "enqueue_task_sync_request",
            context=context,
            fn=_enqueue,
        )

    async def pop_task_sync_request(
        self,
        task_id: str,
        *,
        now_epoch: float | None = None,
        context: str = "task_sync_pop",
    ) -> dict[str, Any] | None:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return None
        keys = self._task_sync_queue_keys(normalized_task_id)
        threshold = float(now_epoch if now_epoch is not None else time.time())
        async def _pop(client: Redis):
            queue_item_ids = await client.zrangebyscore(keys["queue"], "-inf", threshold, start=0, num=1)
            if not queue_item_ids:
                return None
            queue_item_id = str(queue_item_ids[0] or "").strip()
            if not queue_item_id:
                return None
            raw = await client.get(f"{keys['payload_prefix']}:{queue_item_id}")
            if raw is None:
                await client.zrem(keys["queue"], queue_item_id)
                return None
            payload = json.loads(raw)
            return self._normalize_task_sync_entry(payload)
        return await self._execute_with_client_rebuild_forever(
            "pop_task_sync_request",
            context=context,
            fn=_pop,
        )

    async def ack_task_sync_request(
        self,
        task_id: str,
        *,
        queue_item_id: str,
        dedupe_key: str | None = None,
        context: str = "task_sync_ack",
    ) -> None:
        normalized_task_id = str(task_id or "").strip()
        normalized_queue_item_id = str(queue_item_id or "").strip()
        if not normalized_task_id or not normalized_queue_item_id:
            return
        keys = self._task_sync_queue_keys(normalized_task_id)
        async def _ack(client: Redis):
            if dedupe_key:
                await client.hdel(keys["dedupe"], str(dedupe_key).strip())
            else:
                raw = await client.get(f"{keys['payload_prefix']}:{normalized_queue_item_id}")
                if raw:
                    payload = json.loads(raw)
                    resolved_dedupe_key = str(payload.get("dedupe_key") or "").strip()
                    if resolved_dedupe_key:
                        await client.hdel(keys["dedupe"], resolved_dedupe_key)
            await client.zrem(keys["queue"], normalized_queue_item_id)
            await client.delete(f"{keys['payload_prefix']}:{normalized_queue_item_id}")
            return None
        await self._execute_with_client_rebuild_forever(
            "ack_task_sync_request",
            context=context,
            fn=_ack,
        )

    async def retry_task_sync_request(
        self,
        task_id: str,
        entry: dict[str, Any],
        *,
        context: str = "task_sync_retry",
    ) -> dict[str, Any]:
        normalized_task_id = str(task_id or "").strip()
        normalized_entry = self._normalize_task_sync_entry(entry)
        queue_item_id = str(normalized_entry.get("queue_item_id") or "").strip()
        if not normalized_task_id or not queue_item_id:
            raise ValueError("task_id and queue_item_id are required")
        keys = self._task_sync_queue_keys(normalized_task_id)
        async def _retry(client: Redis):
            await client.set(
                f"{keys['payload_prefix']}:{queue_item_id}",
                json.dumps(normalized_entry, ensure_ascii=True, sort_keys=True),
            )
            await client.zadd(keys["queue"], {queue_item_id: self._task_sync_entry_score(normalized_entry)})
            dedupe_key = str(normalized_entry.get("dedupe_key") or "").strip()
            if dedupe_key:
                await client.hset(keys["dedupe"], dedupe_key, queue_item_id)
            return normalized_entry
        return await self._execute_with_client_rebuild_forever(
            "retry_task_sync_request",
            context=context,
            fn=_retry,
        )

    async def list_task_sync_requests(
        self,
        task_id: str,
        *,
        context: str = "task_sync_list",
    ) -> list[dict[str, Any]]:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return []
        keys = self._task_sync_queue_keys(normalized_task_id)
        async def _list(client: Redis):
            queue_item_ids = [str(value).strip() for value in list(await client.zrange(keys["queue"], 0, -1) or []) if str(value).strip()]
            entries: list[dict[str, Any]] = []
            for queue_item_id in queue_item_ids:
                raw = await client.get(f"{keys['payload_prefix']}:{queue_item_id}")
                if not raw:
                    continue
                entries.append(self._normalize_task_sync_entry(json.loads(raw)))
            return entries
        return await self._execute_with_client_rebuild_forever(
            "list_task_sync_requests",
            context=context,
            fn=_list,
        )

    async def has_due_task_sync_request(
        self,
        task_id: str,
        *,
        now_epoch: float | None = None,
        context: str = "task_sync_due_check",
    ) -> bool:
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            return False
        keys = self._task_sync_queue_keys(normalized_task_id)
        threshold = float(now_epoch if now_epoch is not None else time.time())
        async def _due(client: Redis):
            queue_item_ids = await client.zrangebyscore(keys["queue"], "-inf", threshold, start=0, num=1)
            return bool(queue_item_ids)
        return await self._execute_with_client_rebuild_forever(
            "has_due_task_sync_request",
            context=context,
            fn=_due,
        )

    async def acquire_task_sync_repair_lock(
        self,
        task_id: str,
        owner_token: str,
        *,
        ttl_seconds: int = 30,
        context: str = "task_sync_repair_lock",
    ) -> bool:
        normalized_task_id = str(task_id or "").strip()
        normalized_owner_token = str(owner_token or "").strip()
        if not normalized_task_id or not normalized_owner_token:
            return False
        keys = self._task_sync_queue_keys(normalized_task_id)
        return bool(await self._execute_with_client_rebuild_forever(
            "acquire_task_sync_repair_lock",
            context=context,
            fn=lambda client: client.set(keys["lock"], normalized_owner_token, ex=max(1, int(ttl_seconds)), nx=True),
        ))

    async def release_task_sync_repair_lock(
        self,
        task_id: str,
        owner_token: str,
        *,
        context: str = "task_sync_repair_unlock",
    ) -> None:
        normalized_task_id = str(task_id or "").strip()
        normalized_owner_token = str(owner_token or "").strip()
        if not normalized_task_id or not normalized_owner_token:
            return
        keys = self._task_sync_queue_keys(normalized_task_id)
        async def _release(client: Redis):
            current = await client.get(keys["lock"])
            if str(current or "").strip() == normalized_owner_token:
                await client.delete(keys["lock"])
            return None
        await self._execute_with_client_rebuild_forever(
            "release_task_sync_repair_lock",
            context=context,
            fn=_release,
        )

    @staticmethod
    def _task_sync_entry_score(entry: dict[str, Any]) -> float:
        raw = str(dict(entry or {}).get("next_retry_at") or dict(entry or {}).get("requested_at") or "").strip()
        if raw:
            try:
                return max(0.0, datetime.fromisoformat(raw).timestamp())
            except Exception:
                pass
        return time.time()

    @staticmethod
    def _normalize_task_sync_entry(entry: dict[str, Any] | None) -> dict[str, Any]:
        payload = dict(entry or {})
        normalized = {
            "queue_item_id": str(payload.get("queue_item_id") or "").strip() or None,
            "dedupe_key": str(payload.get("dedupe_key") or "").strip() or None,
            "sync_kind": str(payload.get("sync_kind") or "downstream_status").strip() or "downstream_status",
            "source": str(payload.get("source") or "").strip() or None,
            "reason": str(payload.get("reason") or "").strip() or None,
            "source_event_type": str(payload.get("source_event_type") or "").strip() or None,
            "stage_name": str(payload.get("stage_name") or "").strip() or None,
            "item_ids": sorted({str(item_id).strip() for item_id in list(payload.get("item_ids") or []) if str(item_id).strip()}),
            "archive_job_ids": sorted({str(job_id).strip() for job_id in list(payload.get("archive_job_ids") or []) if str(job_id).strip()}),
            "force": bool(payload.get("force")),
            "requested_at": str(payload.get("requested_at") or "").strip() or None,
            "last_requested_at": str(payload.get("last_requested_at") or "").strip() or None,
            "next_retry_at": str(payload.get("next_retry_at") or "").strip() or None,
            "attempts": int(payload.get("attempts") or 0),
            "priority": int(payload.get("priority") or 100),
            "payload": dict(payload.get("payload") or {}) if isinstance(payload.get("payload"), dict) else {},
            "last_error": str(payload.get("last_error") or "").strip() or None,
        }
        return normalized

    @classmethod
    def _merge_task_sync_entries(cls, existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        current = cls._normalize_task_sync_entry(existing)
        latest = cls._normalize_task_sync_entry(incoming)
        def _meaningful_value(value: Any) -> bool:
            if value is None:
                return False
            if isinstance(value, str):
                return bool(value)
            if isinstance(value, (list, tuple, set, dict)):
                return bool(value)
            return True
        merged = {
            **current,
            **{key: value for key, value in latest.items() if _meaningful_value(value)},
        }
        merged["item_ids"] = sorted({*list(current.get("item_ids") or []), *list(latest.get("item_ids") or [])})
        merged["archive_job_ids"] = sorted({*list(current.get("archive_job_ids") or []), *list(latest.get("archive_job_ids") or [])})
        merged["payload"] = {
            **dict(current.get("payload") or {}),
            **dict(latest.get("payload") or {}),
        }
        merged["force"] = bool(current.get("force") or latest.get("force"))
        merged["attempts"] = min(int(current.get("attempts") or 0), int(latest.get("attempts") or 0))
        merged["requested_at"] = current.get("requested_at") or latest.get("requested_at")
        merged["last_requested_at"] = latest.get("last_requested_at") or current.get("last_requested_at")
        merged["priority"] = min(int(current.get("priority") or 100), int(latest.get("priority") or 100))
        return merged


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
