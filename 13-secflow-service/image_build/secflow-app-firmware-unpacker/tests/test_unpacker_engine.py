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
    PiRpcClient,
    _resolve_provider_model,
    run_unpack,
)


class UnpackerEngineHelpersTests(unittest.TestCase):
    def test_resolve_provider_model(self):
        self.assertEqual("glm-5", _resolve_provider_model("share_codex", "glm-5", None))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "glm-4"))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "share_codex/glm-4"))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "other/glm-4"))

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
            row = db.query(ServiceConfig).filter(ServiceConfig.key == "llm_config_file_key_executor").first()
            if row is None:
                row = ServiceConfig(
                    key="llm_config_file_key_executor",
                    value="share_codex",
                    value_type="string",
                    description="",
                )
                db.add(row)
            else:
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
            def get_llm_config_file(self, provider_key: str):
                if provider_key != "share_codex":
                    raise AssertionError(provider_key)
                return {
                    "config_file_key": provider_key,
                    "default_model": f"{provider_key}/{fake_provider['model']}",
                    "models_json": {
                        "providers": {
                            provider_key: {
                                "type": "openai-compatible",
                                "baseURL": fake_provider["api_base"],
                                "apiKeyEnv": "OPENAI_API_KEY",
                                "models": [fake_provider["model"]],
                            }
                        }
                    },
                }

        with patch("app.unpacker_engine_pi.get_configcenter_client", return_value=_FakeClient()), \
             patch("app.unpacker_engine_pi.subprocess.Popen", side_effect=_fake_popen), \
             patch("app.unpacker_engine_pi.os.getpgid", return_value=123), \
             patch("app.unpacker_engine_pi.os.killpg"):
            client = PiRpcClient(provider_role="executor")
            agent_dir = Path(captured["env"][PI_AGENT_DIR_ENV])
            self.assertTrue((agent_dir / "models.json").is_file())
            self.assertTrue((agent_dir / "settings.json").is_file())
            client.close()
            self.assertFalse(agent_dir.exists())


class AgentFlowDelegationTests(unittest.TestCase):
    def test_run_unpack_delegates_to_agentflow_when_enabled(self):
        config = type("Config", (), {"agentflow": type("AgentFlow", (), {"enabled": True})()})()
        expected = {"status": "success", "message": "ok", "rounds": 1}

        with patch("app.unpacker_engine.get_config", return_value=config), \
             patch("app.cli.run_unpack_agentflow", return_value=expected) as mocked_run:
            result = run_unpack(
                task_id="task-1",
                firmware_path="/tmp/fw.bin",
                output_path="/tmp/output",
                llm_binding_snapshot={"roles": {}},
                cancel_check=lambda: False,
                register_cancel_hook=lambda hook: None,
                progress_callback=lambda stage: None,
                event_callback=lambda *args, **kwargs: None,
            )

        self.assertEqual(expected, result)
        mocked_run.assert_called_once()
        self.assertEqual("task-1", mocked_run.call_args.kwargs["task_id"])
        self.assertEqual("/tmp/fw.bin", mocked_run.call_args.kwargs["firmware_path"])
        self.assertEqual("/tmp/output", mocked_run.call_args.kwargs["output_path"])
