import asyncio
import unittest

from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.service.task_queue import TaskQueue


class _FakeRedis:
    def __init__(self):
        self.sets = {}
        self.lists = {}
        self.sorted_sets = {}

    async def sadd(self, key, value):
        bucket = self.sets.setdefault(key, set())
        before = len(bucket)
        bucket.add(value)
        return 1 if len(bucket) != before else 0

    async def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)

    async def zadd(self, key, mapping):
        bucket = self.sorted_sets.setdefault(key, {})
        bucket.update(mapping)

    async def zrem(self, key, value):
        bucket = self.sorted_sets.setdefault(key, {})
        bucket.pop(value, None)

    async def lpos(self, key, value):
        values = self.lists.get(key) or []
        try:
            return values.index(value)
        except ValueError:
            return None

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


class _FakeRedisConnectionError(_FakeRedis):
    def __init__(self):
        super().__init__()
        self.closed = False

    async def blpop(self, key, timeout=0):
        del key, timeout
        raise RedisConnectionError("Connection closed by server")

    async def aclose(self):
        self.closed = True
        return None


class TaskQueueTests(unittest.TestCase):
    def test_push_task_dedupes_same_task_id(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        queue._client = fake

        asyncio.run(queue.push_task("task-1"))
        asyncio.run(queue.push_task("task-1"))

        self.assertEqual(["task-1"], fake.lists[queue.config.task_queue_key])
        self.assertEqual({"task-1"}, fake.sets[f"{queue.config.task_queue_key}:dedupe"])

    def test_pop_task_removes_dedupe_marker(self):
        queue = TaskQueue()
        fake = _FakeRedis()
        queue._client = fake

        asyncio.run(queue.push_task("task-1"))
        popped = asyncio.run(queue.pop_task(timeout_seconds=1))

        self.assertEqual("task-1", popped)
        self.assertEqual(set(), fake.sets[f"{queue.config.task_queue_key}:dedupe"])

    def test_pop_task_treats_redis_timeout_as_empty_poll(self):
        queue = TaskQueue()
        fake = _FakeRedisTimeout()
        queue._client = fake

        popped = asyncio.run(queue.pop_task(timeout_seconds=1))

        self.assertIsNone(popped)
        self.assertTrue(fake.closed)
        self.assertIsNone(queue._client)

    def test_pop_operation_resets_client_after_connection_error(self):
        queue = TaskQueue()
        fake = _FakeRedisConnectionError()
        queue._client = fake

        popped = asyncio.run(queue.pop_operation(timeout_seconds=1))

        self.assertIsNone(popped)
        self.assertTrue(fake.closed)
        self.assertIsNone(queue._client)


if __name__ == "__main__":
    unittest.main()
