import time
import types
import unittest
from unittest.mock import patch

import sys

if "prometheus_client" not in sys.modules:
    fake_module = types.ModuleType("prometheus_client")

    class _Metric:
        def labels(self, *args, **kwargs):
            del args, kwargs
            return self

        def inc(self, *args, **kwargs):
            del args, kwargs
            return None

        def observe(self, *args, **kwargs):
            del args, kwargs
            return None

        def set(self, *args, **kwargs):
            del args, kwargs
            return None

    fake_module.CONTENT_TYPE_LATEST = "text/plain"
    fake_module.Counter = lambda *args, **kwargs: _Metric()
    fake_module.Gauge = lambda *args, **kwargs: _Metric()
    fake_module.Histogram = lambda *args, **kwargs: _Metric()
    fake_module.generate_latest = lambda: b""
    sys.modules["prometheus_client"] = fake_module

from app.services.auth import AuthService, TokenCacheEntry


class AuthServiceTokenCacheMetricsTests(unittest.TestCase):
    def test_get_cached_user_records_disabled(self):
        service = AuthService()
        service._cache_enabled = False

        with patch("app.services.auth.record_auth_token_cache") as record_metric:
            result = service._get_cached_user("token-a", None)

        self.assertIsNone(result)
        record_metric.assert_called_once_with("disabled")

    def test_get_cached_user_records_miss(self):
        service = AuthService()
        service._cache_enabled = True
        service._token_cache.clear()

        with patch("app.services.auth.record_auth_token_cache") as record_metric:
            result = service._get_cached_user("token-a", None)

        self.assertIsNone(result)
        record_metric.assert_called_once_with("miss")

    def test_get_cached_user_records_hit(self):
        service = AuthService()
        service._cache_enabled = True
        payload = {"id": "u1", "token_type": "user"}
        service._token_cache["token-a::"] = TokenCacheEntry(payload, ttl_seconds=60)

        with patch("app.services.auth.record_auth_token_cache") as record_metric:
            result = service._get_cached_user("token-a", None)

        self.assertEqual(payload, result)
        record_metric.assert_called_once_with("hit")

    def test_get_cached_user_records_expired(self):
        service = AuthService()
        service._cache_enabled = True
        payload = {"id": "u1", "token_type": "user"}
        entry = TokenCacheEntry(payload, ttl_seconds=1)
        entry.expiry_time = time.time() - 1
        service._token_cache["token-a::"] = entry

        with patch("app.services.auth.record_auth_token_cache") as record_metric:
            result = service._get_cached_user("token-a", None)

        self.assertIsNone(result)
        self.assertNotIn("token-a::", service._token_cache)
        record_metric.assert_called_once_with("expired")


if __name__ == "__main__":
    unittest.main()
