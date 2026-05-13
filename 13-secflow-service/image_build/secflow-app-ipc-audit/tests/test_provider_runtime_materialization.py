from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.services.provider_client import ProviderClientError
from app.services.provider_runtime import ResolvedProviderRuntime, get_provider_runtime_service


class FakeProviderClient:
    def __init__(self, details: dict[str, dict]) -> None:
        self.details = details

    def list_providers(self) -> dict:
        return {
            "total": len(self.details),
            "default_provider_key": next(iter(self.details.keys()), None),
            "items": list(self.details.values()),
        }

    def get_provider_detail(self, provider_key: str) -> dict:
        return dict(self.details[provider_key])


class ProviderRuntimeMaterializationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-provider-")
        self.runtime_root = Path(self.temp_dir.name) / "runtime"
        import app.services.provider_client as provider_client_module
        import app.services.provider_runtime as provider_runtime_module

        provider_client_module._provider_client = None
        provider_runtime_module._provider_runtime_service = None

    def tearDown(self) -> None:
        import app.services.provider_client as provider_client_module
        import app.services.provider_runtime as provider_runtime_module

        provider_client_module._provider_client = None
        provider_runtime_module._provider_runtime_service = None
        self.temp_dir.cleanup()

    def test_materialize_rewrites_whitelisted_paths_only(self) -> None:
        resolved = ResolvedProviderRuntime(
            provider_keys=["provider-a", "provider-b"],
            provider_snapshots=[],
            merged_env={"OPENAI_API_KEY": "sk-runtime-secret"},
            merged_files=[
                {
                    "path": "/root/.codex/config.toml",
                    "content": "model = \"gpt-5-codex\"\n",
                },
                {
                    "path": "/root/.config/opencode/opencode.json",
                    "content": "{\"provider\":\"runtime-secret\"}",
                },
            ],
            effective_model="openai/gpt-5",
            executor_model="openai/gpt-5",
        )

        materialized = get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)
        process_env = get_provider_runtime_service().build_process_env(resolved, materialized)

        self.assertEqual(process_env["HOME"], str(materialized.home_dir))
        self.assertEqual(process_env["XDG_CONFIG_HOME"], str(materialized.xdg_config_home))
        self.assertEqual(process_env["XDG_DATA_HOME"], str(materialized.xdg_data_home))
        self.assertTrue((materialized.home_dir / ".codex" / "config.toml").exists())
        self.assertTrue((materialized.xdg_config_home / "opencode" / "opencode.json").exists())
        self.assertEqual(
            (materialized.home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"),
            "model = \"gpt-5-codex\"\n",
        )
        self.assertEqual(
            (materialized.xdg_config_home / "opencode" / "opencode.json").read_text(encoding="utf-8"),
            "{\"provider\":\"runtime-secret\"}",
        )

    def test_non_whitelist_provider_path_fails(self) -> None:
        resolved = ResolvedProviderRuntime(
            provider_keys=["provider-a"],
            provider_snapshots=[],
            merged_env={},
            merged_files=[
                {
                    "path": "/tmp/not-allowed/provider.json",
                    "content": "{}",
                }
            ],
            effective_model=None,
            executor_model=None,
        )
        with self.assertRaises(ProviderClientError) as ctx:
            get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)
        self.assertIn("/tmp/not-allowed/provider.json", str(ctx.exception))

    def test_resolve_runtime_generates_codex_files_and_env_from_provider_fields(self) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(
            {
                "codex-prod": {
                    "provider_key": "codex-prod",
                    "display_name": "Codex Prod",
                    "provider_type": "openai",
                    "enabled": True,
                    "api_base": "https://proxy.example.test/v1",
                    "api_key": "sk-generated-codex",
                    "model": "gpt-5-codex",
                    "env_bindings": {},
                    "file_bindings": [],
                }
            }
        )

        resolved = get_provider_runtime_service().resolve_runtime(
            ["codex-prod"],
            executor_mode="codex_cli",
        )
        materialized = get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)
        process_env = get_provider_runtime_service().build_process_env(resolved, materialized)

        self.assertEqual(process_env["OPENAI_API_KEY"], "sk-generated-codex")
        self.assertEqual(process_env["OPENAI_BASE_URL"], "https://proxy.example.test/v1")
        self.assertEqual(resolved.executor_model, "gpt-5-codex")
        auth_path = materialized.home_dir / ".codex" / "auth.json"
        config_path = materialized.home_dir / ".codex" / "config.toml"
        self.assertTrue(auth_path.exists())
        self.assertTrue(config_path.exists())
        self.assertIn("sk-generated-codex", auth_path.read_text(encoding="utf-8"))
        config_text = config_path.read_text(encoding="utf-8")
        self.assertIn('model = "gpt-5-codex"', config_text)
        self.assertIn('model_provider = "codex_prod"', config_text)
        self.assertIn('base_url = "https://proxy.example.test/v1"', config_text)
        self.assertIn('env_key = "OPENAI_API_KEY"', config_text)

    def test_resolve_runtime_generates_opencode_config_from_provider_fields(self) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(
            {
                "moonshot-prod": {
                    "provider_key": "moonshot-prod",
                    "display_name": "Moonshot Prod",
                    "provider_type": "openai-compatible",
                    "enabled": True,
                    "api_base": "https://moonshot.example.test/v1",
                    "api_key": "sk-generated-opencode",
                    "model": "moonshot/kimi-k2",
                    "env_bindings": {},
                    "file_bindings": [
                        {
                            "name": "auth.json",
                            "path": "/root/.codex/auth.json",
                            "content": "{\"token\":\"not-used-for-opencode\"}",
                            "enabled": True,
                        }
                    ],
                }
            }
        )

        resolved = get_provider_runtime_service().resolve_runtime(
            ["moonshot-prod"],
            executor_mode="opencode_cli",
        )
        materialized = get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)
        process_env = get_provider_runtime_service().build_process_env(resolved, materialized)

        self.assertEqual(process_env["OPENAI_API_KEY"], "sk-generated-opencode")
        self.assertEqual(process_env["OPENAI_BASE_URL"], "https://moonshot.example.test/v1")
        self.assertEqual(resolved.executor_model, "moonshot_prod/moonshot/kimi-k2")
        config_path = materialized.xdg_config_home / "opencode" / "opencode.json"
        self.assertTrue(config_path.exists())
        config_text = config_path.read_text(encoding="utf-8")
        self.assertIn('"moonshot_prod"', config_text)
        self.assertIn('"https://moonshot.example.test/v1"', config_text)
        self.assertIn('"sk-generated-opencode"', config_text)
        self.assertIn('"model": "moonshot_prod/moonshot/kimi-k2"', config_text)

    def test_resolve_runtime_preserves_full_model_id_for_openai_compatible_opencode(self) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(
            {
                "local-minimax": {
                    "provider_key": "local-minimax",
                    "display_name": "Local MiniMax",
                    "provider_type": "openai-compatible",
                    "enabled": True,
                    "api_base": "http://provider.example.test/v1",
                    "api_key": "sk-generated-opencode",
                    "model": "MiniMax/MiniMax-M2.5",
                    "env_bindings": {},
                    "file_bindings": [],
                }
            }
        )

        resolved = get_provider_runtime_service().resolve_runtime(
            ["local-minimax"],
            executor_mode="opencode_cli",
        )
        materialized = get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)

        self.assertEqual(resolved.effective_model, "MiniMax/MiniMax-M2.5")
        self.assertEqual(resolved.executor_model, "local_minimax/MiniMax/MiniMax-M2.5")
        config_path = materialized.xdg_config_home / "opencode" / "opencode.json"
        config_text = config_path.read_text(encoding="utf-8")
        self.assertIn('"model": "local_minimax/MiniMax/MiniMax-M2.5"', config_text)
        self.assertIn('"MiniMax/MiniMax-M2.5"', config_text)

    def test_resolve_runtime_replaces_incompatible_codex_config(self) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(
            {
                "local-minimax": {
                    "provider_key": "local-minimax",
                    "display_name": "Local MiniMax",
                    "provider_type": "openai-compatible",
                    "enabled": True,
                    "api_base": "http://provider.example.test/v1",
                    "api_key": "sk-generated-codex",
                    "model": "MiniMax/MiniMax-M2.5",
                    "env_bindings": {},
                    "file_bindings": [
                        {
                            "name": "config.toml",
                            "path": "/root/.codex/config.toml",
                            "content": "\n".join(
                                [
                                    'model_provider = "OpenAI"',
                                    'model = "zai-org/GLM-5"',
                                    '[model_providers.OpenAI]',
                                    'wire_api = "chat"',
                                ]
                            )
                            + "\n",
                            "enabled": True,
                        }
                    ],
                }
            }
        )

        resolved = get_provider_runtime_service().resolve_runtime(
            ["local-minimax"],
            executor_mode="codex_cli",
        )
        materialized = get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)

        config_path = materialized.home_dir / ".codex" / "config.toml"
        config_text = config_path.read_text(encoding="utf-8")
        self.assertIn('model = "MiniMax/MiniMax-M2.5"', config_text)
        self.assertIn('wire_api = "responses"', config_text)
        self.assertNotIn('wire_api = "chat"', config_text)
        self.assertNotIn('model = "zai-org/GLM-5"', config_text)

    def test_resolve_runtime_replaces_invalid_opencode_config(self) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(
            {
                "local-minimax": {
                    "provider_key": "local-minimax",
                    "display_name": "Local MiniMax",
                    "provider_type": "openai-compatible",
                    "enabled": True,
                    "api_base": "http://provider.example.test/v1",
                    "api_key": "sk-generated-opencode",
                    "model": "MiniMax/MiniMax-M2.5",
                    "env_bindings": {},
                    "file_bindings": [
                        {
                            "name": "opencode.json",
                            "path": "/root/.config/opencode/opencode.json",
                            "content": "{\"provider\":\"bad-shape\"}",
                            "enabled": True,
                        }
                    ],
                }
            }
        )

        resolved = get_provider_runtime_service().resolve_runtime(
            ["local-minimax"],
            executor_mode="opencode_cli",
        )
        materialized = get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)

        config_path = materialized.xdg_config_home / "opencode" / "opencode.json"
        config_text = config_path.read_text(encoding="utf-8")
        self.assertIn('"model": "local_minimax/MiniMax/MiniMax-M2.5"', config_text)
        self.assertIn('"provider"', config_text)
        self.assertNotIn('"provider":"bad-shape"', config_text)


if __name__ == "__main__":
    unittest.main()
