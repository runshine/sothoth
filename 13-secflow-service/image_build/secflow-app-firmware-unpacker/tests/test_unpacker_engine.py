import tempfile
import unittest
import json
import os
from pathlib import Path
from unittest.mock import patch
import sys

import yaml

import app.model as model_module
from app.config import reload_config
from app.model import ServiceConfig, get_db_session, init_database
from app.services.configcenter import build_models_json_from_provider
from app.subprocess_utils import run_streaming_process
from app.unpacker_engine import (
    PI_AGENT_DIR_ENV,
    PiRpcClient,
    _run_python_tool_unpack,
    _run_recursive_expand_command,
    _resolve_provider_model,
)
from app.evolution_engine import _publish_tool_to_store


class UnpackerEngineHelpersTests(unittest.TestCase):
    def test_resolve_provider_model(self):
        self.assertEqual("glm-5", _resolve_provider_model("share_codex", "glm-5", None))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "glm-4"))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "share_codex/glm-4"))
        self.assertEqual("glm-4", _resolve_provider_model("share_codex", "glm-5", "other/glm-4"))

    def test_build_models_json_uses_provider_specific_api(self):
        payload = build_models_json_from_provider(
            {
                "provider_key": "share_codex",
                "provider_type": "openai-compatible",
                "api_base": "http://llm.local/v1",
                "api_key": "secret",
                "model": "glm-5",
            }
        )
        provider = payload["providers"]["share_codex"]
        self.assertEqual("openai-completions", provider["api"])
        self.assertEqual("secret", provider["apiKey"])
        self.assertEqual("glm-5", provider["models"][0]["id"])


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
            for key, value in (
                ("llm_config_file_key_executor", "share_codex"),
                ("llm_model_executor", "glm-5"),
            ):
                row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
                if row is None:
                    db.add(ServiceConfig(key=key, value=value))
                else:
                    row.value = value
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
            "models_json": build_models_json_from_provider(
                {
                    "provider_key": "share_codex",
                    "provider_type": "openai-compatible",
                    "api_base": "http://llm.local/v1",
                    "api_key": "secret",
                    "model": "glm-5",
                }
            ),
            "max_tokens": 4096,
        }

        class _FakeClient:
            def get_llm_config_file(self, provider_key: str):
                if provider_key != "share_codex":
                    raise AssertionError(provider_key)
                return fake_provider

        with patch("app.unpacker_engine_pi.get_configcenter_client", return_value=_FakeClient()), \
             patch("app.unpacker_engine_pi.subprocess.Popen", side_effect=_fake_popen), \
             patch("app.unpacker_engine_pi.os.getpgid", return_value=123), \
             patch("app.unpacker_engine_pi.os.killpg"):
            client = PiRpcClient(
                provider_role="executor",
                task_id="task-1",
                llm_binding_snapshot={
                    "project_id": "p1",
                    "roles": {
                        "executor": {
                            "config_file_key": "share_codex",
                            "provider_key": "share_codex",
                            "model": "glm-5",
                            "model_selector": "share_codex/glm-5",
                            "runtime_dir": str(self._tmp.name) + "/data/p1/app/secflow-app-firmware-unpacker/task-1/run/.pi/agents/executor",
                            "models_json": fake_provider["models_json"],
                            "settings_json": {"defaultProvider": "share_codex", "defaultModel": "glm-5"},
                        }
                    },
                },
            )
            agent_dir = Path(captured["env"][PI_AGENT_DIR_ENV])
            self.assertTrue((agent_dir / "models.json").is_file())
            self.assertTrue((agent_dir / "settings.json").is_file())
            settings = json.loads((agent_dir / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual("share_codex", settings["defaultProvider"])
            self.assertEqual("glm-5", settings["defaultModel"])
            self.assertTrue(settings["compaction"]["enabled"])
            self.assertEqual(8192, settings["compaction"]["reserveTokens"])
            self.assertEqual(50000, settings["compaction"]["keepRecentTokens"])
            self.assertEqual("executor", agent_dir.name)
            self.assertIn("--model", captured["args"])
            self.assertIn("share_codex/glm-5", captured["args"])
            client.close()
            self.assertFalse(agent_dir.exists())

    def test_pi_rpc_client_identifies_invalid_request_overflow_and_compacts(self):
        fake_provider = {
            "provider_key": "share_codex",
            "provider_type": "openai-compatible",
            "api_base": "http://llm.local/v1",
            "api_key": "secret",
            "model": "glm-5",
            "models_json": build_models_json_from_provider(
                {
                    "provider_key": "share_codex",
                    "provider_type": "openai-compatible",
                    "api_base": "http://llm.local/v1",
                    "api_key": "secret",
                    "model": "glm-5",
                }
            ),
            "max_tokens": 4096,
        }

        class _FakeClient:
            def get_llm_config_file(self, provider_key: str):
                if provider_key != "share_codex":
                    raise AssertionError(provider_key)
                return fake_provider

        with patch("app.unpacker_engine_pi.get_configcenter_client", return_value=_FakeClient()), \
             patch("app.unpacker_engine_pi.subprocess.Popen", return_value=_FakeProc()), \
             patch("app.unpacker_engine_pi.os.getpgid", return_value=123), \
             patch("app.unpacker_engine_pi.os.killpg"), \
             patch.object(PiRpcClient, "_prompt_once") as prompt_once, \
             patch.object(PiRpcClient, "_run_compaction", return_value=True):
            prompt_once.side_effect = [
                RuntimeError(
                    "400 litellm.BadRequestError: Hosted_vllmException - "
                    '{"object":"error","message":"Prefiller\'s maximum context length is 131072 tokens, '
                    'however the input has 127564 tokens and the proxy reserves 4096 safety-buffer tokens '
                    'after chat template rendering. Please reduce the length of the input.",'
                    '"type":"invalid_request_error","code":"prefill_context_length_exceeded"}'
                ),
                "ok",
            ]
            client = PiRpcClient(
                provider_role="executor",
                task_id="task-1",
                session_path=Path(self._tmp.name) / "executor.jsonl",
                llm_binding_snapshot={
                    "project_id": "p1",
                    "roles": {
                        "executor": {
                            "config_file_key": "share_codex",
                            "provider_key": "share_codex",
                            "model": "glm-5",
                            "model_selector": "share_codex/glm-5",
                            "runtime_dir": str(Path(self._tmp.name) / "runtime" / "executor"),
                            "models_json": fake_provider["models_json"],
                            "settings_json": {"defaultProvider": "share_codex", "defaultModel": "glm-5"},
                        }
                    },
                },
            )
            result = client.prompt("summary")
            self.assertTrue(result.compaction_requested)
            self.assertTrue(result.compaction_completed)
            self.assertTrue(result.context_overflow_retrying)
            self.assertEqual("ok", result.output)
            client.close()


class StreamingSubprocessTests(unittest.TestCase):
    def test_run_streaming_process_drains_large_stdout_and_stderr(self):
        command = [
            sys.executable,
            "-c",
            (
                "import os, sys; "
                "os.write(sys.stdout.fileno(), b'A' * 262144); "
                "os.write(sys.stderr.fileno(), b'B' * 262144)"
            ),
        ]
        result = run_streaming_process(command, text=True)
        self.assertEqual(0, result.returncode)
        self.assertEqual(262144, len(result.stdout or ""))
        self.assertEqual(262144, len(result.stderr or ""))
        self.assertTrue((result.stdout or "").startswith("A"))
        self.assertTrue((result.stderr or "").startswith("B"))

    def test_recursive_expand_command_handles_large_output_without_deadlock(self):
        command = [
            sys.executable,
            "-c",
            (
                "import os, sys; "
                "os.write(sys.stdout.fileno(), (b'entry\\n' * 50000)); "
                "os.write(sys.stderr.fileno(), (b'warn\\n' * 50000))"
            ),
        ]
        result = _run_recursive_expand_command(command)
        self.assertEqual(0, result.returncode)
        self.assertIn("entry", result.stdout)
        self.assertIn("warn", result.stderr)

    def test_publish_tool_to_store_keeps_evolved_versioned_tool_even_when_final_round_not_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_dir = root / "tools" / "store"
            source_dir = root / "tools" / "active"
            source_dir.mkdir(parents=True, exist_ok=True)
            store_dir.mkdir(parents=True, exist_ok=True)

            source_target = store_dir / "20260527" / "huawei-cc-00000002-v5-20260527171433.py"
            source_target.parent.mkdir(parents=True, exist_ok=True)
            source_target.write_text("# old\n", encoding="utf-8")
            source_link = source_dir / "huawei-cc-00000002.py"
            source_link.symlink_to(os.path.relpath(source_target, start=source_link.parent))

            working_dir = root / "run" / "working_tool"
            working_dir.mkdir(parents=True, exist_ok=True)
            working_tool = working_dir / "huawei-cc-00000002-v6-20260528141625.py"
            working_tool.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env python3",
                        "# format_id: huawei-cc-00000002",
                        "# description: test",
                        "# extensions: cc",
                        "# magic_hex: 00000002",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with patch("app.evolution_engine.TOOLS_STORE_DIR", store_dir):
                published = _publish_tool_to_store(
                    firmware_path=str(root / "NE20E.cc"),
                    working_tool=working_tool,
                    source_tool=source_link,
                    tool_changed=False,
                )

            self.assertTrue(str(published).startswith(str(store_dir)))
            self.assertTrue(Path(published).is_file())
            self.assertNotEqual(str(source_link), published)

    def test_python_tool_unpack_handles_high_volume_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "output"
            input_dir = root / "input"
            run_dir = root / "run"
            tool_path = root / "spam_tool.py"
            output_dir.mkdir(parents=True, exist_ok=True)
            input_dir.mkdir(parents=True, exist_ok=True)
            run_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "task.json").write_text("{}", encoding="utf-8")
            tool_path.write_text(
                "\n".join(
                    [
                        "import sys",
                        "for i in range(5000):",
                        "    sys.stdout.write(f'line-{i}\\n')",
                        "sys.stdout.flush()",
                    ]
                ),
                encoding="utf-8",
            )
            result = _run_python_tool_unpack(
                str(root / "firmware.bin"),
                str(output_dir),
                {"path": str(tool_path), "filename": tool_path.name},
                run_dir,
            )
            self.assertTrue(result["success"])
            self.assertEqual(0, result["return_code"])
            self.assertIn("line-0", result["response"])
            self.assertIn("line-4999", result["response"])
