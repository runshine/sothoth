import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app.exception import UpstreamError
from app.service.downstream_base import JsonHttpClient


class _FakeAsyncClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def get(self, url, headers=None, params=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        outcome = self._responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "headers": headers, "json": json})
        outcome = self._responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def delete(self, url, headers=None):
        self.calls.append({"url": url, "headers": headers})
        outcome = self._responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class JsonHttpClientTests(unittest.TestCase):
    def test_base_url_rejects_paths(self):
        with self.assertRaisesRegex(Exception, "base_url 不允许包含路径"):
            JsonHttpClient(base_url="http://dfa/api/app/dataflow-vuln-scan", timeout=30)

    def test_build_url_normalizes_slashes(self):
        client = JsonHttpClient(base_url="http://dfa", timeout=30)
        self.assertEqual("http://dfa/api/app/dataflow-vuln-scan/tasks/dfa-1", client._build_url("/api/app/dataflow-vuln-scan//tasks/dfa-1"))
        self.assertEqual("http://dfa/api/app/dataflow-vuln-scan/tasks", client._build_url("api/app/dataflow-vuln-scan/tasks"))

    def test_get_retries_once_after_stale_connection_rebuild(self):
        request = httpx.Request("GET", "http://dfa/tasks/t1")
        stale_error = httpx.RemoteProtocolError(
            "Server disconnected without sending a response.",
            request=request,
        )
        first_client = _FakeAsyncClient([stale_error])
        second_client = _FakeAsyncClient([httpx.Response(200, json={"task_id": "t1", "status": "running"}, request=request)])
        client = JsonHttpClient(base_url="http://dfa", timeout=30)

        async def fake_get_shared_async_client(name, *, timeout=None):
            self.assertEqual("http://dfa", name)
            self.assertEqual(30, timeout)
            return first_client if not first_client.calls else second_client

        with (
            patch("app.service.downstream_base.get_shared_async_client", side_effect=fake_get_shared_async_client),
            patch("app.service.downstream_base.invalidate_shared_async_client", new=AsyncMock(return_value=True)) as invalidate_mock,
        ):
            payload = asyncio.run(client.get("/tasks/t1"))

        self.assertEqual("t1", payload["task_id"])
        self.assertEqual("running", payload["status"])
        invalidate_mock.assert_awaited_once_with("http://dfa", timeout=30)
        self.assertEqual(1, len(first_client.calls))
        self.assertEqual(1, len(second_client.calls))

    def test_get_raises_upstream_error_with_transport_metadata_after_retry_failure(self):
        request = httpx.Request("GET", "http://dfa/tasks/t1")
        stale_error = httpx.RemoteProtocolError(
            "Server disconnected without sending a response.",
            request=request,
        )
        connect_error = httpx.ConnectError("All connection attempts failed", request=request)
        first_client = _FakeAsyncClient([stale_error])
        second_client = _FakeAsyncClient([connect_error])
        client = JsonHttpClient(base_url="http://dfa", timeout=30)

        async def fake_get_shared_async_client(name, *, timeout=None):
            self.assertEqual("http://dfa", name)
            self.assertEqual(30, timeout)
            return first_client if not first_client.calls else second_client

        with (
            patch("app.service.downstream_base.get_shared_async_client", side_effect=fake_get_shared_async_client),
            patch("app.service.downstream_base.invalidate_shared_async_client", new=AsyncMock(return_value=True)) as invalidate_mock,
        ):
            with self.assertRaises(UpstreamError) as ctx:
                asyncio.run(client.get("/tasks/t1"))

        exc = ctx.exception
        self.assertEqual("connect_error", exc.error_type_detail)
        self.assertEqual("connect_error", exc.transport_error_kind)
        self.assertTrue(exc.retry_attempted)
        self.assertTrue(exc.client_recreated)
        invalidate_mock.assert_awaited_once_with("http://dfa", timeout=30)


if __name__ == "__main__":
    unittest.main()
