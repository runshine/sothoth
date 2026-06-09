import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import build_info
from app.api.tasks import health_check


class BuildInfoTests(unittest.TestCase):
    def test_build_service_meta_reads_build_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta_path = Path(tmp) / "build_meta.json"
            meta_path.write_text('{"build_version":"20260609-test"}\n', encoding="utf-8")
            with patch.object(build_info, "BUILD_META_PATH", meta_path):
                payload = build_info.build_service_meta()
        self.assertEqual("secflow-app-vuln-verify", payload["service_id"])
        self.assertEqual("漏洞验证服务", payload["service_name"])
        self.assertEqual("20260609-test", payload["build_version"])

    def test_build_service_meta_falls_back_when_meta_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_path = Path(tmp) / "missing-build-meta.json"
            with patch.object(build_info, "BUILD_META_PATH", missing_path):
                payload = build_info.build_service_meta()
        self.assertIsNone(payload["build_version"])

    def test_health_check_includes_build_version(self):
        with patch("app.api.tasks.build_service_meta", return_value={
            "service_id": "secflow-app-vuln-verify",
            "service_name": "漏洞验证服务",
            "build_version": "20260609-health",
        }):
            payload = asyncio.run(health_check())
        self.assertEqual("ok", payload["status"])
        self.assertEqual("secflow-app-vuln-verify", payload["service"])
        self.assertEqual("secflow-app-vuln-verify", payload["service_id"])
        self.assertEqual("漏洞验证服务", payload["service_name"])
        self.assertEqual("20260609-health", payload["build_version"])
