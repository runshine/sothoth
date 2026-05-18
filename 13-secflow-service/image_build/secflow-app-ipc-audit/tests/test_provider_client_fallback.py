from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import httpx

from app.core.config import load_config
from app.services.provider_client import ProviderClient, ProviderNotFoundError


class ProviderClientFallbackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-provider-fallback-")
        self.fallback_path = Path(self.temp_dir.name) / "providers.json"
        self._reset_config()
        self._set_env("IPC_AUDIT_PROVIDER_BASE_URL", "http://provider.example.test")
        self._set_env("IPC_AUDIT_PROVIDER_API_PREFIX", "/api/configcenter/service/llm")
        self._set_env("IPC_AUDIT_PROVIDER_FALLBACK_FILE", str(self.fallback_path))

    def tearDown(self) -> None:
        for key in (
            "IPC_AUDIT_PROVIDER_BASE_URL",
            "IPC_AUDIT_PROVIDER_API_PREFIX",
            "IPC_AUDIT_PROVIDER_FALLBACK_FILE",
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
        ):
            os.environ.pop(key, None)
        self._reset_config()
        self.temp_dir.cleanup()

    def test_list_and_detail_fallback_to_local_file_when_remote_unavailable(self) -> None:
        self._set_env("OPENAI_API_KEY", "sk-local-openai")
        self._set_env("OPENAI_BASE_URL", "https://proxy.local/v1")
        self.fallback_path.write_text(
            json.dumps(
                {
                    "default_provider_key": "local-openai",
                    "items": [
                        {
                            "provider_key": "local-openai",
                            "display_name": "Local OpenAI",
                            "provider_type": "openai",
                            "enabled": True,
                            "is_default": True,
                            "api_base": "${OPENAI_BASE_URL}",
                            "api_key": "${OPENAI_API_KEY}",
                            "model": "openai/gpt-5",
                            "env_bindings": {
                                "OPENAI_API_KEY": "${OPENAI_API_KEY}",
                                "OPENAI_BASE_URL": "${OPENAI_BASE_URL}",
                            },
                            "file_bindings": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        load_config()

        client = ProviderClient()

        def failing_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("provider down", request=request)

        client._client = httpx.Client(transport=httpx.MockTransport(failing_handler))

        listing = client.list_providers()
        detail = client.get_provider_detail("local-openai")

        self.assertEqual(listing["default_provider_key"], "local-openai")
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["provider_key"], "local-openai")
        self.assertEqual(detail["api_base"], "https://proxy.local/v1")
        self.assertEqual(detail["api_key"], "sk-local-openai")
        self.assertEqual(detail["env_bindings"]["OPENAI_API_KEY"], "sk-local-openai")

    def test_missing_provider_in_fallback_raises_not_found(self) -> None:
        self.fallback_path.write_text(
            json.dumps(
                {
                    "items": [
                        {
                            "provider_key": "local-openai",
                            "display_name": "Local OpenAI",
                            "provider_type": "openai",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        load_config()

        client = ProviderClient()

        def failing_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("provider down", request=request)

        client._client = httpx.Client(transport=httpx.MockTransport(failing_handler))

        with self.assertRaises(ProviderNotFoundError):
            client.get_provider_detail("missing-provider")

    @staticmethod
    def _set_env(key: str, value: str) -> None:
        os.environ[key] = value

    @staticmethod
    def _reset_config() -> None:
        import app.core.config as config_module

        config_module._config = None


if __name__ == "__main__":
    unittest.main()
