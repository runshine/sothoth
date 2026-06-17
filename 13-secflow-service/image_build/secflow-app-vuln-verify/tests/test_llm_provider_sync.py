import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from app.service.llm_provider_sync import (
    build_models_json,
    select_default_model_id,
    select_default_provider,
    sync_providers_to_pi,
)


class LlmProviderSyncTests(unittest.TestCase):
    def _payload(self):
        return {
            "default_provider_key": "local_minimax",
            "items": [
                {
                    "provider_key": "local_minimax",
                    "display_name": "LOCAL_MINIMAX",
                    "provider_type": "openai-compatible",
                    "enabled": True,
                    "is_default": True,
                    "api_base": "http://llm/v1",
                    "model": "MiniMax/MiniMax-M2.5",
                    "model_context_window": 160000,
                    "api_key": "sk-test",
                    "extra_config": {},
                },
                {
                    "provider_key": "disabled",
                    "provider_type": "anthropic",
                    "enabled": False,
                    "api_base": "http://disabled",
                    "model": "claude",
                    "api_key": "sk-disabled",
                    "extra_config": {},
                },
            ],
        }

    def test_build_models_json_filters_disabled_and_preserves_context(self):
        models_json = build_models_json(self._payload()["items"])

        self.assertEqual(["local_minimax"], list(models_json["providers"].keys()))
        provider = models_json["providers"]["local_minimax"]
        self.assertEqual("http://llm/v1", provider["baseUrl"])
        self.assertEqual("openai-completions", provider["api"])
        self.assertEqual("sk-test", provider["apiKey"])
        self.assertEqual("MiniMax/MiniMax-M2.5", provider["models"][0]["id"])
        self.assertEqual(160000, provider["models"][0]["contextWindow"])

    def test_select_default_provider_and_model_from_configcenter_payload(self):
        payload = self._payload()
        provider = select_default_provider(payload, payload["items"])

        self.assertIsNotNone(provider)
        self.assertEqual("local_minimax", provider["provider_key"])
        self.assertEqual("MiniMax/MiniMax-M2.5", select_default_model_id(provider))

    def test_sync_writes_real_models_and_settings_from_configcenter_default(self):
        payload = self._payload()

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual("Bearer machine-token", request.headers.get("authorization"))
            return httpx.Response(200, json=payload, request=request)

        with tempfile.TemporaryDirectory() as tmp:
            pi_dir = Path(tmp) / "pi"
            legacy_target = Path(tmp) / "legacy-models.json"
            legacy_target.write_text('{"legacy":true}', encoding="utf-8")
            pi_dir.mkdir()
            (pi_dir / "models.json").symlink_to(legacy_target)

            class FakeClient:
                def __init__(self, timeout):
                    self.timeout = timeout

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

                def get(self, url, headers=None):
                    request = httpx.Request("GET", url, headers=headers or {})
                    return handler(request)

            with patch("app.service.llm_provider_sync.httpx.Client", FakeClient):
                result = sync_providers_to_pi(
                    base_url="http://configcenter/api/configcenter",
                    token="machine-token",
                    timeout=3,
                    pi_dir=str(pi_dir),
                )

            self.assertTrue(result.ok)
            self.assertEqual("local_minimax", result.default_provider_key)
            self.assertEqual("MiniMax/MiniMax-M2.5", result.default_model)
            self.assertEqual("local_minimax/MiniMax/MiniMax-M2.5", result.default_model_ref)
            self.assertFalse((pi_dir / "models.json").is_symlink())

            models_json = json.loads((pi_dir / "models.json").read_text(encoding="utf-8"))
            settings_json = json.loads((pi_dir / "settings.json").read_text(encoding="utf-8"))
            self.assertIn("local_minimax", models_json["providers"])
            self.assertEqual("local_minimax", settings_json["defaultProvider"])
            self.assertEqual("MiniMax/MiniMax-M2.5", settings_json["defaultModel"])
            self.assertEqual('{"legacy":true}', legacy_target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
