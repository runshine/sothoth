import asyncio
import unittest
from unittest import mock

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.service.task_queue import TaskQueue


class _FakeRedis:
    def __init__(self):
        self.sets = {}
        self.lists = {}
        self.sorted_sets = {}
        self.ping_calls = 0

    async def sadd(self, key, value):
        bucket = self.sets.setdefault(key, set())
        before = len(bucket)
        bucket.add(value)
        return 1 if len(bucket) != before else 0

    async def smembers(self, key):
        return self.sets.get(key) or set()

    async def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)

    async def zadd(self, key, mapping):
        bucket = self.sorted_sets.setdefault(key, {})
        bucket.update(mapping)

    async def zrem(self, key, value):
        bucket = self.sorted_sets.setdefault(key, {})
        bucket.pop(value, None)

    async def llen(self, key):
        return len(self.lists.get(key) or [])

    async def lrange(self, key, start, stop):
        values = list(self.lists.get(key) or [])
        if stop == -1:
            stop = len(values) - 1
        return values[start : stop + 1]

    async def zrange(self, key, start, stop, withscores=False):
        del start, stop
        bucket = self.sorted_sets.get(key) or {}
        items = sorted(bucket.items(), key=lambda item: item[1])
        if not withscores:
            return [item[0] for item in items]
        return items

    async def zscore(self, key, value):
        return (self.sorted_sets.get(key) or {}).get(value)

    async def lpos(self, key, value):
        values = self.lists.get(key) or []
        try:
            return values.index(value)
        except ValueError:
            return None

    async def lrem(self, key, count, value):
        values = list(self.lists.get(key) or [])
        if count <= 0:
            raise NotImplementedError("fake redis only supports positive lrem count")
        removed = 0
        kept = []
        for current in values:
            if current == value and removed < count:
                removed += 1
                continue
            kept.append(current)
        self.lists[key] = kept
        return removed

    async def blpop(self, key, timeout=0):
        del timeout
        values = self.lists.get(key) or []
        if not values:
            return None
        return key, values.pop(0)

    async def srem(self, key, value):
        bucket = self.sets.setdefault(key, set())
        bucket.discard(value)

    async def aclose(self):
        return None

    async def ping(self):
        self.ping_calls += 1
        return True


class _FakeRedisTimeout(_FakeRedis):
    def __init__(self):
        super().__init__()
        self.closed = False

    async def blpop(self, key, timeout=0):
        del key, timeout
        raise RedisTimeoutError("Timeout reading from redis")

    async def aclose(self):
        self.closed = True
        return None


class _FakeRedisStatsConnectionError(_FakeRedis):
    def __init__(self):
        super().__init__()
        self.closed = False

    async def llen(self, key):
        del key
        raise RedisConnectionError("Connection closed by server")

    async def aclose(self):
        self.closed = True
        return None


class _FakeRedisPingFlaky(_FakeRedis):
    def __init__(self, failures_before_success):
        super().__init__()
        self.failures_before_success = failures_before_success
        self.closed = False

    async def ping(self):
        self.ping_calls += 1
        if self.failures_before_success > 0:
            self.failures_before_success -= 1
            raise RedisTimeoutError("Timeout connecting to server")
        return True

    async def aclose(self):
        self.closed = True
        return None


class _FakeRedisPushConnectionFlaky(_FakeRedis):
    def __init__(self, failures_before_success):
        super().__init__()
        self.failures_before_success = failures_before_success
        self.closed = False

    async def sadd(self, key, value):
        if self.failures_before_success > 0:
            self.failures_before_success -= 1
            raise RedisConnectionError("Connection closed by server")
        return await super().sadd(key, value)

    async def aclose(self):
        self.closed = True
        return None


class _FakeRedisTaskSyncDueFlaky(_FakeRedis):
    def __init__(self, failures_before_success):
        super().__init__()
        self.failures_before_success = failures_before_success
        self.closed = False

    async def zrangebyscore(self, key, min_score, max_score, start=0, num=None):
        del key, min_score, max_score, start, num
        if self.failures_before_success > 0:
            self.failures_before_success -= 1
            raise RedisConnectionError("Connection closed by server")
        return ["tsq-1"]

    async def aclose(self):
        self.closed = True
        return None


async def _bind_client_for_current_loop(queue: TaskQueue, client) -> None:
    queue._general_redis_helper._clients_by_loop_id[asyncio.get_running_loop()] = client


def _patch_helper_new_client(queue: TaskQueue, side_effect):
    return mock.patch.object(queue._general_redis_helper, "new_client", side_effect=side_effect)


async def _bind_blocking_client_for_current_loop(queue: TaskQueue, client, *, channel: str) -> None:
    helper = queue._blocking_helper_for_channel(channel)
    helper._clients_by_loop_id[asyncio.get_running_loop()] = client


def _patch_blocking_helper_new_client(queue: TaskQueue, channel: str, side_effect):
    helper = queue._blocking_helper_for_channel(channel)
    return mock.patch.object(helper, "new_client", side_effect=side_effect)


def _stable_client_factory(*clients):
    calls: list[str] = []

    def _factory(context="unspecified"):
        calls.append(context)
        index = min(len(calls), len(clients)) - 1
        return clients[index]

    return calls, _factory


class TaskQueueTests(unittest.TestCase):
    def test_push_task_dedupes_same_task_id(self):
        queue = TaskQueue()
        fake = _FakeRedis()

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            await queue.push_task("task-1")
            await queue.push_task("task-1")

        asyncio.run(_exercise())

        self.assertEqual(["task-1"], fake.lists[queue.config.task_queue_key])
        self.assertEqual({"task-1"}, fake.sets[f"{queue.config.task_queue_key}:dedupe"])

    def test_force_requeue_restores_orphaned_task(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        fake.sets[f"{queue.config.task_queue_key}:dedupe"] = {"task-1"}

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            await queue.force_requeue_task("task-1")

        asyncio.run(_exercise())

        self.assertEqual(["task-1"], fake.lists[queue.config.task_queue_key])
        self.assertEqual({"task-1"}, fake.sets[f"{queue.config.task_queue_key}:dedupe"])

    def test_dedupe_orphans_reports_set_without_list(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        fake.sets[f"{queue.config.task_queue_key}:dedupe"] = {"task-1"}

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            return await queue.dedupe_orphans(queue.config.task_queue_key)

        snapshot = asyncio.run(_exercise())

        self.assertEqual(1, snapshot["orphan_count"])
        self.assertEqual(["task-1"], snapshot["orphan_ids"])

    def test_dedupe_orphans_restores_missing_timestamp_for_live_entry(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        fake.sets[f"{queue.config.task_queue_key}:dedupe"] = {"task-1"}
        fake.lists[queue.config.task_queue_key] = ["task-1"]

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            return await queue.dedupe_orphans(queue.config.task_queue_key)

        snapshot = asyncio.run(_exercise())

        self.assertEqual(0, snapshot["orphan_count"])
        self.assertEqual(1, snapshot["missing_timestamp_count"])
        self.assertEqual(["task-1"], snapshot["missing_timestamp_ids"])
        self.assertIn("task-1", fake.sorted_sets[f"{queue.config.task_queue_key}:enqueued_at"])

    def test_cleanup_dedupe_orphans_removes_orphan_members(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        fake.sets[f"{queue.config.task_queue_key}:dedupe"] = {"task-1"}
        fake.sorted_sets[f"{queue.config.task_queue_key}:enqueued_at"] = {"task-1": 1.0}

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            return await queue.cleanup_dedupe_orphans(queue.config.task_queue_key)

        snapshot = asyncio.run(_exercise())

        self.assertEqual(1, snapshot["removed_orphan_count"])
        self.assertEqual(["task-1"], snapshot["removed_orphan_ids"])
        self.assertEqual(set(), fake.sets[f"{queue.config.task_queue_key}:dedupe"])
        self.assertEqual({}, fake.sorted_sets[f"{queue.config.task_queue_key}:enqueued_at"])

    def test_pop_task_removes_dedupe_marker(self):
        queue = TaskQueue()
        fake = _FakeRedis()

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            await _bind_blocking_client_for_current_loop(queue, fake, channel="task_dispatch_pop")
            await queue.push_task("task-1")
            return await queue.pop_task(timeout_seconds=1)

        popped = asyncio.run(_exercise())

        self.assertEqual("task-1", popped)
        self.assertEqual(set(), fake.sets[f"{queue.config.task_queue_key}:dedupe"])
        self.assertEqual(1, len(queue._general_redis_helper._clients_by_loop_id))
        self.assertEqual(1, len(queue._task_dispatch_blocking_redis_helper._clients_by_loop_id))

    def test_pop_task_rebuilds_blocking_client_after_connection_error(self):
        queue = TaskQueue()
        first = _FakeRedisTimeout()
        second = _FakeRedis()
        second.lists[queue.config.task_queue_key] = ["task-1"]
        _created, factory = _stable_client_factory(first, second)

        with _patch_blocking_helper_new_client(queue, "task_dispatch_pop", factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    return await queue.pop_task(timeout_seconds=1)

                popped = asyncio.run(_exercise())

        self.assertEqual("task-1", popped)
        self.assertTrue(first.closed)
        self.assertTrue(queue.blocking_client_recently_recovered(channel="task_dispatch_pop", within_seconds=60.0))

    def test_pop_delete_task_empty_poll_uses_blocking_client_without_timeout_error(self):
        queue = TaskQueue()
        fake = _FakeRedis()

        async def _exercise():
            await _bind_blocking_client_for_current_loop(queue, fake, channel="task_delete_dispatch_pop")
            return await queue.pop_delete_task(timeout_seconds=1)

        popped = asyncio.run(_exercise())

        self.assertIsNone(popped)
        self.assertEqual(1, len(queue._task_delete_blocking_redis_helper._clients_by_loop_id))

    def test_queue_stats_returns_empty_snapshot_after_connection_error(self):
        queue = TaskQueue()
        first = _FakeRedisStatsConnectionError()
        second = _FakeRedis()
        second.lists[queue.config.task_queue_key] = ["task-1"]
        second.sorted_sets[f"{queue.config.task_queue_key}:enqueued_at"] = {"task-1": 1.0}
        created, factory = _stable_client_factory(first, second)

        with _patch_helper_new_client(queue, factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    return await queue.queue_stats(queue.config.task_queue_key)

                stats = asyncio.run(_exercise())

        self.assertEqual(1, stats["length"])
        self.assertTrue(first.closed)

    def test_snapshot_marks_operation_queue_disabled_under_owner_only_runtime(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        fake.lists[queue.config.task_queue_key] = ["task-1"]

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            return await queue.snapshot()

        snapshot = asyncio.run(_exercise())

        self.assertEqual(1, snapshot["task_queue"]["length"])
        self.assertEqual(0, snapshot["operation_queue"]["length"])
        self.assertEqual(0, snapshot["operation_queue"]["enabled"])
        self.assertEqual(1, len(queue._general_redis_helper._clients_by_loop_id))

    def test_wait_until_ready_succeeds_after_ping(self):
        queue = TaskQueue()
        fake = _FakeRedis()

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            await queue.wait_until_ready(timeout_seconds=1, retry_interval_seconds=1)

        asyncio.run(_exercise())

        self.assertEqual(1, fake.ping_calls)

    def test_wait_until_ready_retries_until_ping_succeeds(self):
        queue = TaskQueue()
        first = _FakeRedisPingFlaky(failures_before_success=1)
        second = _FakeRedisPingFlaky(failures_before_success=0)
        created, factory = _stable_client_factory(first, second)

        with _patch_helper_new_client(queue, factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    await queue.wait_until_ready(timeout_seconds=3, retry_interval_seconds=1)

                asyncio.run(_exercise())

        self.assertTrue(first.closed)
        self.assertGreaterEqual(second.ping_calls, 1)

    def test_wait_until_ready_times_out_when_ping_never_recovers(self):
        queue = TaskQueue()
        fake = _FakeRedisPingFlaky(failures_before_success=99)

        async def _no_sleep(_seconds):
            return None

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            task = asyncio.create_task(queue.wait_until_ready(timeout_seconds=1, retry_interval_seconds=1))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
            asyncio.run(_exercise())

    def test_new_client_is_cached_within_same_loop(self):
        queue = TaskQueue()

        with mock.patch("app.service.task_queue.Redis.from_url") as from_url:
            fake_client = object()
            from_url.return_value = fake_client

            async def _exercise():
                first = queue._new_client(context="startup_warmup")
                second = queue._new_client(context="startup_seed")
                return first, second

            first, second = asyncio.run(_exercise())

        self.assertIs(fake_client, first)
        self.assertIs(fake_client, second)
        self.assertEqual(1, len(queue._general_redis_helper._clients_by_loop_id))
        from_url.assert_called_once()

    def test_blocking_client_is_cached_within_same_loop_per_channel(self):
        queue = TaskQueue()

        with mock.patch("app.service.task_queue.Redis.from_url") as from_url:
            fake_client = object()
            from_url.return_value = fake_client

            async def _exercise():
                first = queue._new_blocking_client(channel="task_dispatch_pop", context="task_dispatch_pop")
                second = queue._new_blocking_client(channel="task_dispatch_pop", context="task_dispatch_pop")
                return first, second

            first, second = asyncio.run(_exercise())

        self.assertIs(fake_client, first)
        self.assertIs(fake_client, second)
        self.assertEqual(1, len(queue._task_dispatch_blocking_redis_helper._clients_by_loop_id))
        from_url.assert_called_once()

    def test_general_and_blocking_clients_do_not_share_cache(self):
        queue = TaskQueue()

        with mock.patch("app.service.task_queue.Redis.from_url") as from_url:
            fake_general = object()
            fake_blocking = object()
            from_url.side_effect = [fake_general, fake_blocking]

            async def _exercise():
                general = queue._new_client(context="startup_warmup")
                blocking = queue._new_blocking_client(channel="task_dispatch_pop", context="task_dispatch_pop")
                return general, blocking

            general, blocking = asyncio.run(_exercise())

        self.assertIs(fake_general, general)
        self.assertIs(fake_blocking, blocking)
        self.assertIsNot(general, blocking)

    def test_new_client_is_isolated_per_event_loop(self):
        queue = TaskQueue()

        with mock.patch("app.service.task_queue.Redis.from_url") as from_url:
            fake_first = object()
            fake_second = object()
            from_url.side_effect = [fake_first, fake_second]

            async def _create():
                return queue._new_client(context="startup_seed")

            first = asyncio.run(_create())
            second = asyncio.run(_create())

        self.assertIs(fake_first, first)
        self.assertIs(fake_second, second)
        self.assertEqual(2, from_url.call_count)

    def test_push_task_keeps_cached_client_alive(self):
        queue = TaskQueue()
        fake = _FakeRedis()

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            await queue.push_task("task-1", context="startup_seed")

        asyncio.run(_exercise())

        self.assertEqual(1, len(queue._general_redis_helper._clients_by_loop_id))
        self.assertEqual(["task-1"], fake.lists[queue.config.task_queue_key])

    def test_queue_positions_returns_current_queue_membership(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        fake.lists[queue.config.task_queue_key] = ["task-1", "task-2", "task-1"]

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            return await queue.queue_positions(queue.config.task_queue_key)

        positions = asyncio.run(_exercise())

        self.assertEqual({"task-1": 1, "task-2": 2}, positions)

    def test_dedupe_orphans_keeps_cached_client_alive_on_success(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        fake.sets[f"{queue.config.task_queue_key}:dedupe"] = {"task-1"}
        fake.lists[queue.config.task_queue_key] = ["task-1"]

        async def _exercise():
            await _bind_client_for_current_loop(queue, fake)
            return await queue.dedupe_orphans(queue.config.task_queue_key)

        snapshot = asyncio.run(_exercise())

        self.assertEqual(0, snapshot["orphan_count"])
        self.assertEqual(1, len(queue._general_redis_helper._clients_by_loop_id))

    def test_push_task_rebuilds_cached_client_after_connection_error(self):
        queue = TaskQueue()
        first = _FakeRedisPushConnectionFlaky(failures_before_success=1)
        second = _FakeRedis()
        _created, factory = _stable_client_factory(first, second)

        with _patch_helper_new_client(queue, factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    await queue.push_task("task-1")

                asyncio.run(_exercise())

        self.assertTrue(first.closed)
        self.assertEqual(["task-1"], second.lists[queue.config.task_queue_key])

    def test_has_due_task_sync_request_rebuilds_cached_client_after_connection_error(self):
        queue = TaskQueue()
        first = _FakeRedisTaskSyncDueFlaky(failures_before_success=1)
        second = _FakeRedisTaskSyncDueFlaky(failures_before_success=0)
        _created, factory = _stable_client_factory(first, second)

        with _patch_helper_new_client(queue, factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    return await queue.has_due_task_sync_request("task-1")

                due = asyncio.run(_exercise())

        self.assertTrue(first.closed)
        self.assertTrue(due)

    def test_blocking_client_invalidate_does_not_affect_general_client(self):
        queue = TaskQueue()
        general = _FakeRedis()
        first_blocking = _FakeRedisTimeout()
        second_blocking = _FakeRedis()
        second_blocking.lists[queue.config.task_queue_key] = ["task-1"]
        _created, factory = _stable_client_factory(first_blocking, second_blocking)

        with _patch_blocking_helper_new_client(queue, "task_dispatch_pop", factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    await _bind_client_for_current_loop(queue, general)
                    await queue.push_task("task-2")
                    return await queue.pop_task(timeout_seconds=1)

                popped = asyncio.run(_exercise())

        self.assertEqual("task-1", popped)
        self.assertEqual(["task-2"], general.lists[queue.config.task_queue_key])
        self.assertTrue(first_blocking.closed)

    def test_general_client_invalidate_does_not_affect_blocking_client(self):
        queue = TaskQueue()
        blocking = _FakeRedis()
        blocking.lists[queue.config.task_queue_key] = ["task-1"]
        first_general = _FakeRedisPushConnectionFlaky(failures_before_success=1)
        second_general = _FakeRedis()
        _created, factory = _stable_client_factory(first_general, second_general)

        with _patch_helper_new_client(queue, factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    await _bind_blocking_client_for_current_loop(queue, blocking, channel="task_dispatch_pop")
                    await queue.push_task("task-1")
                    return await queue.pop_task(timeout_seconds=1)

                popped = asyncio.run(_exercise())

        self.assertEqual("task-1", popped)
        self.assertTrue(first_general.closed)

    def test_wait_until_ready_retries_forever_until_ping_succeeds(self):
        queue = TaskQueue()
        first = _FakeRedisPingFlaky(failures_before_success=1)
        second = _FakeRedisPingFlaky(failures_before_success=0)
        created, factory = _stable_client_factory(first, second)

        with _patch_helper_new_client(queue, factory):

            async def _no_sleep(_seconds):
                return None

            with mock.patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                async def _exercise():
                    await queue.wait_until_ready(timeout_seconds=1, retry_interval_seconds=1)

                asyncio.run(_exercise())

        self.assertTrue(first.closed)
        self.assertGreaterEqual(second.ping_calls, 1)


if __name__ == "__main__":
    unittest.main()
