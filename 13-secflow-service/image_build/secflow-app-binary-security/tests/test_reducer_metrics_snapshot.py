import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.service.reducer_metrics_snapshot import ReducerMetricsSnapshotStore


class ReducerMetricsSnapshotTests(unittest.TestCase):
    def test_render_metrics_uses_snapshot_payload_and_metadata(self):
        store = ReducerMetricsSnapshotStore()
        store.read_snapshot = AsyncMock(
            return_value={
                "metrics_payload": "# TYPE demo gauge\ndemo 7\n",
                "source_pod": "reducer-0",
                "generated_at": 100.0,
            }
        )
        with patch("app.service.reducer_metrics_snapshot.time.time", return_value=108.0):
            payload, content_type = asyncio.run(store.render_metrics())
        body = payload.decode("utf-8", errors="ignore")
        self.assertIn("demo 7", body)
        self.assertIn("secflow_binary_security_reducer_snapshot_available 1.0", body)
        self.assertIn("secflow_binary_security_reducer_snapshot_age_seconds 8.0", body)
        self.assertIn('secflow_binary_security_reducer_snapshot_source_info{pod="reducer-0"} 1', body)
        self.assertIn("text/plain", content_type)

    def test_render_metrics_uses_fallback_when_snapshot_missing(self):
        store = ReducerMetricsSnapshotStore()
        store.read_snapshot = AsyncMock(return_value=None)
        payload, _ = asyncio.run(store.render_metrics(fallback_payload="# TYPE fallback gauge\nfallback 2\n"))
        body = payload.decode("utf-8", errors="ignore")
        self.assertIn("fallback 2", body)
        self.assertIn("secflow_binary_security_reducer_snapshot_available 1.0", body)

    def test_write_snapshot_serializes_payload_into_redis(self):
        fake_client = SimpleNamespace(set=AsyncMock())
        store = ReducerMetricsSnapshotStore()
        store._client_or_create = AsyncMock(return_value=fake_client)
        asyncio.run(
            store.write_snapshot(
                metrics_payload="# TYPE demo gauge\ndemo 9\n",
                source_pod="reducer-1",
                generated_at=123.0,
            )
        )
        fake_client.set.assert_awaited_once()
        args = fake_client.set.await_args.args
        self.assertEqual("secflow:binary-security:reducer:metrics-snapshot:v1", args[0])
        self.assertIn('"source_pod": "reducer-1"', args[1])
        self.assertIn('"generated_at": 123.0', args[1])

    def test_client_is_reused_across_snapshot_operations(self):
        fake_client = SimpleNamespace(
            set=AsyncMock(),
            get=AsyncMock(return_value='{"metrics_payload":"demo","source_pod":"reducer-1","generated_at":123.0}'),
            aclose=AsyncMock(),
        )
        store = ReducerMetricsSnapshotStore()
        with patch.object(store, "_new_client", return_value=fake_client) as new_client:
            asyncio.run(
                store.write_snapshot(
                    metrics_payload="# TYPE demo gauge\ndemo 1\n",
                    source_pod="reducer-1",
                    generated_at=123.0,
                )
            )
            snapshot = asyncio.run(store.read_snapshot())
            self.assertEqual("reducer-1", snapshot["source_pod"])
            self.assertEqual(1, new_client.call_count)
            fake_client.aclose.assert_not_awaited()
            asyncio.run(store.close())
            fake_client.aclose.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
