import asyncio
import types
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if "prometheus_client" not in sys.modules:
    fake_prometheus = types.ModuleType("prometheus_client")

    class _Metric:
        def labels(self, *args, **kwargs):
            return self

        def inc(self, *args, **kwargs):
            return None

        def set(self, *args, **kwargs):
            return None

        def observe(self, *args, **kwargs):
            return None

    fake_prometheus.CONTENT_TYPE_LATEST = "text/plain"
    fake_prometheus.Counter = lambda *args, **kwargs: _Metric()
    fake_prometheus.Gauge = lambda *args, **kwargs: _Metric()
    fake_prometheus.Histogram = lambda *args, **kwargs: _Metric()
    fake_prometheus.generate_latest = lambda *args, **kwargs: b""
    sys.modules["prometheus_client"] = fake_prometheus

from app import build_info
from app.api.firmware import health_check


class BuildInfoTests(unittest.TestCase):
    def test_build_service_meta_reads_build_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta_path = Path(tmp) / "build_meta.json"
            meta_path.write_text('{"build_version":"20260528-test"}\n', encoding="utf-8")
            with patch.object(build_info, "BUILD_META_PATH", meta_path):
                payload = build_info.build_service_meta()
        self.assertEqual("secflow-app-firmware-unpacker", payload["service_id"])
        self.assertEqual("固件解包服务", payload["service_name"])
        self.assertEqual("20260528-test", payload["build_version"])

    def test_health_check_includes_build_meta(self):
        with patch("app.api.firmware.get_worker_id", return_value="worker-1"):
            with patch("app.api.firmware.build_service_meta", return_value={
                "service_id": "secflow-app-firmware-unpacker",
                "service_name": "固件解包服务",
                "build_version": "20260528-health",
            }):
                payload = asyncio.run(health_check())
        self.assertEqual("ok", payload["status"])
        self.assertEqual("worker-1", payload["owner_id"])
        self.assertEqual("secflow-app-firmware-unpacker", payload["service_id"])
        self.assertEqual("固件解包服务", payload["service_name"])
        self.assertEqual("20260528-health", payload["build_version"])
