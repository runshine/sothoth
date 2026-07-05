import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from redis.exceptions import ConnectionError as RedisConnectionError

from app.service.state_event_inbox_metrics_snapshot import StateEventInboxMetricsSnapshotStore


class StateEventInboxMetricsSnapshotTests(unittest.TestCase):
    def test_render_metrics_uses_snapshot_payload_and_metadata(self):
        store = StateEventInboxMetricsSnapshotStore()
        store.read_snapshot = AsyncMock(
            return_value={
                "metrics_payload": "# TYPE demo gauge\ndemo 7\n",
                "source_pod": "state-event-inbox-0",
                "generated_at": 100.0,
            }
        )
        with patch("app.service.state_event_inbox_metrics_snapshot.time.time", return_value=108.0):
            payload, content_type = asyncio.run(store.render_metrics())
        body = payload.decode("utf-8", errors="ignore")
        self.assertIn("demo 7", body)
        self.assertIn("secflow_binary_security_state_event_inbox_snapshot_available 1.0", body)
        self.assertIn("secflow_binary_security_state_event_inbox_snapshot_age_seconds 8.0", body)
        self.assertIn('secflow_binary_security_state_event_inbox_snapshot_source_info{pod="state-event-inbox-0"} 1', body)
        self.assertIn("text/plain", content_type)

    def test_render_metrics_uses_fallback_when_snapshot_missing(self):
        store = StateEventInboxMetricsSnapshotStore()
        store.read_snapshot = AsyncMock(return_value=None)
        payload, _ = asyncio.run(store.render_metrics(fallback_payload="# TYPE fallback gauge\nfallback 2\n"))
        body = payload.decode("utf-8", errors="ignore")
        self.assertIn("fallback 2", body)
        self.assertIn("secflow_binary_security_state_event_inbox_snapshot_available 1.0", body)

    def test_write_snapshot_serializes_payload_into_redis(self):
        fake_client = SimpleNamespace(set=AsyncMock())
        store = StateEventInboxMetricsSnapshotStore()
        calls = []

        async def _execute(op_name, *, context, fn):
            calls.append((op_name, context))
            return await fn(fake_client)

        store._redis_helper.execute_with_rebuild_forever = _execute
        asyncio.run(
            store.write_snapshot(
                metrics_payload="# TYPE demo gauge\ndemo 9\n",
                source_pod="state-event-inbox-1",
                generated_at=123.0,
            )
        )
        fake_client.set.assert_awaited_once()
        self.assertEqual(
            [("state_event_inbox_metrics_snapshot_write", "state_event_inbox_metrics_snapshot")],
            calls,
        )
        args = fake_client.set.await_args.args
        self.assertEqual("secflow:binary-security:state-event-inbox:metrics-snapshot:v1", args[0])
        self.assertIn('"source_pod": "state-event-inbox-1"', args[1])
        self.assertIn('"generated_at": 123.0', args[1])

    def test_snapshot_store_uses_shared_redis_helper_for_read_write_and_close(self):
        store = StateEventInboxMetricsSnapshotStore()
        helper = SimpleNamespace(
            execute_with_rebuild_forever=AsyncMock(
                side_effect=[
                    None,
                    '{"metrics_payload":"demo","source_pod":"state-event-inbox-1","generated_at":123.0}',
                ]
            ),
            close=AsyncMock(),
        )
        store._redis_helper = helper

        asyncio.run(
            store.write_snapshot(
                metrics_payload="# TYPE demo gauge\ndemo 1\n",
                source_pod="state-event-inbox-1",
                generated_at=123.0,
            )
        )
        snapshot = asyncio.run(store.read_snapshot())
        asyncio.run(store.close())

        self.assertEqual("state-event-inbox-1", snapshot["source_pod"])
        helper.execute_with_rebuild_forever.assert_any_await(
            "state_event_inbox_metrics_snapshot_write",
            context="state_event_inbox_metrics_snapshot",
            fn=unittest.mock.ANY,
        )
        helper.execute_with_rebuild_forever.assert_any_await(
            "state_event_inbox_metrics_snapshot_read",
            context="state_event_inbox_metrics_snapshot",
            fn=unittest.mock.ANY,
        )
        helper.close.assert_awaited_once()

    def test_snapshot_store_recovers_from_connection_error_via_shared_helper(self):
        first = SimpleNamespace(
            set=AsyncMock(side_effect=RedisConnectionError("Connection closed by server")),
            aclose=AsyncMock(),
        )
        second = SimpleNamespace(
            set=AsyncMock(return_value=True),
            aclose=AsyncMock(),
        )
        store = StateEventInboxMetricsSnapshotStore()
        created = []

        with patch.object(store._redis_helper, "new_client") as new_client:
            new_client.side_effect = lambda context="state_event_inbox_metrics_snapshot": created.append(context) or (first if len(created) == 1 else second)

            async def _no_sleep(_seconds):
                return None

            with patch("app.service.task_queue.asyncio.sleep", side_effect=_no_sleep):
                asyncio.run(
                    store.write_snapshot(
                        metrics_payload="# TYPE demo gauge\ndemo 3\n",
                        source_pod="state-event-inbox-2",
                        generated_at=321.0,
                    )
                )

        first.aclose.assert_awaited_once()
        second.set.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
