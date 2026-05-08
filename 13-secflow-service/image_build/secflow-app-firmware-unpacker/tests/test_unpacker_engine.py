import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import app.model as model_module
from app.config import reload_config
from app.model import ServiceConfig, get_db_session, init_database
from app.unpacker_engine import (
    PI_AGENT_DIR_ENV,
    PI_MODELS_JSON_ENV,
    PiRpcClient,
    _build_models_json,
    _normalize_provider_env_bindings,
    _resolve_provider_model,
)


class UnpackerEngineHelpersTests(unittest.TestCase):
    def test_resolve_provider_model(self):
        self.assertEqual("glm-5", _resolve_provider_model("share_codex", "glm-5", None))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "glm-4"))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "share_codex/glm-4"))
        with self.assertRaisesRegex(ValueError, "不一致"):
            _resolve_provider_model("share_codex", "glm-5", "other/glm-4")

    def test_normalize_provider_env_bindings_prefers_custom_bindings(self):
        env = _normalize_provider_env_bindings(
            {
                "provider_type": "openai-compatible",
                "api_base": "http://llm.local/v1",
                "api_key": "secret",
                "model": "glm-5",
                "env_bindings": {
                    "OPENAI_API_KEY": "override-secret",
                    "CUSTOM_TRACE_ID": "trace-1",
                },
            }
        )
        self.assertEqual("override-secret", env["OPENAI_API_KEY"])
        self.assertEqual("http://llm.local/v1", env["OPENAI_BASE_URL"])
        self.assertEqual("glm-5", env["OPENAI_MODEL"])
        self.assertEqual("trace-1", env["CUSTOM_TRACE_ID"])

    def test_build_models_json_uses_provider_specific_api_key_env_name(self):
        payload = _build_models_json(
            {
                "provider_key": "anthropic-main",
                "provider_type": "anthropic",
                "api_base": "https://api.anthropic.com",
                "model": "claude-sonnet",
                "api_key": "secret",
                "env_bindings": {"ANTHROPIC_AUTH_TOKEN": "secret"},
            },
            "claude-sonnet",
        )
        provider = payload["providers"]["anthropic-main"]
        self.assertEqual("anthropic-messages", provider["api"])
        self.assertEqual("ANTHROPIC_AUTH_TOKEN", provider["apiKey"])


class _FakeProc:
    def __init__(self):
        self.pid = 4321
        self.stdin = self
        self.stdout = None
        self.stderr = None
        self._returncode = None

    def poll(self):
        return self._returncode

    def write(self, _text):
        return None

    def flush(self):
        return None

    def close(self):
        return None

    def terminate(self):
        self._returncode = 0

    def kill(self):
        self._returncode = 0

    def wait(self, timeout=None):
        self._returncode = 0
        return 0


class PiRpcClientRuntimeBindingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        config_path = root / "config.yaml"
        db_path = root / "tasks.db"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "database": {
                        "type": "sqlite",
                        "path": str(db_path),
                        "table_prefix": "secflow_app_firmware_unpacker_",
                    },
                    "configcenter_service": {
                        "enabled": True,
                        "base_url": "http://configcenter/api/configcenter",
                        "timeout": 30,
                    },
                }
            ),
            encoding="utf-8",
        )
        reload_config(str(config_path))
        model_module._engine = None
        model_module._SessionFactory = None
        init_database()
        db = get_db_session()
        try:
            row = db.query(ServiceConfig).filter(ServiceConfig.key == "llm_provider_key_executor").first()
            row.value = "share_codex"
            db.commit()
        finally:
            db.close()

    def tearDown(self):
        model_module._engine = None
        model_module._SessionFactory = None
        self._tmp.cleanup()

    def test_pi_rpc_client_prepares_isolated_agent_dir_and_env(self):
        captured = {}

        def _fake_popen(*args, **kwargs):
            captured["env"] = kwargs.get("env") or {}
            captured["args"] = args[0]
            return _FakeProc()

        fake_provider = {
            "provider_key": "share_codex",
            "provider_type": "openai-compatible",
            "api_base": "http://llm.local/v1",
            "api_key": "secret",
            "model": "glm-5",
            "env_bindings": {"OPENAI_API_KEY": "secret", "TRACE_FLAG": "enabled"},
            "max_tokens": 4096,
        }

        class _FakeClient:
            def get_llm_provider(self, provider_key: str):
                if provider_key != "share_codex":
                    raise AssertionError(provider_key)
                return fake_provider

        with patch("app.unpacker_engine.get_configcenter_client", return_value=_FakeClient()), \
             patch("app.unpacker_engine.subprocess.Popen", side_effect=_fake_popen), \
             patch("app.unpacker_engine.os.getpgid", return_value=123), \
             patch("app.unpacker_engine.os.killpg"):
            client = PiRpcClient(provider_role="executor")
            agent_dir = Path(captured["env"][PI_AGENT_DIR_ENV])
            self.assertTrue((agent_dir / "models.json").is_file())
            self.assertTrue((agent_dir / "settings.json").is_file())
            self.assertEqual(str(agent_dir / "models.json"), captured["env"][PI_MODELS_JSON_ENV])
            self.assertEqual("secret", captured["env"]["OPENAI_API_KEY"])
            self.assertEqual("glm-5", captured["env"]["SECFLOW_LLM_MODEL"])
            self.assertEqual("enabled", captured["env"]["TRACE_FLAG"])
            client.close()
            self.assertFalse(agent_dir.exists())
