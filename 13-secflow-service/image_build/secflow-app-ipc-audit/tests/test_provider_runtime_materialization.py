from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.services.provider_client import ProviderClientError
from app.services.provider_runtime import ResolvedProviderRuntime, get_provider_runtime_service


class ProviderRuntimeMaterializationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-provider-")
        self.runtime_root = Path(self.temp_dir.name) / "runtime"

    def tearDown(self) -> None:
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
        )
        with self.assertRaises(ProviderClientError) as ctx:
            get_provider_runtime_service().materialize_runtime(self.runtime_root, resolved)
        self.assertIn("/tmp/not-allowed/provider.json", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
