import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.agentflow_pipeline import build_firmware_unpack_pipeline
from app.config import reload_config
from app.unpacker_engine import run_unpack, run_unpack_legacy


class AgentFlowConfigTests(unittest.TestCase):
    def test_defaults_keep_legacy_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text("app:\n  port: 9999\n", encoding="utf-8")
            with patch.dict(os.environ, {"CONFIG_PATH": str(config_path)}, clear=False):
                cfg = reload_config(str(config_path))
            self.assertEqual("legacy", cfg.agentflow.engine_mode)
            self.assertFalse(cfg.agentflow.enabled)
            self.assertTrue(cfg.agentflow.fallback_to_legacy)

    def test_env_overrides_agentflow_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text("agentflow:\n  engine_mode: legacy\n", encoding="utf-8")
            env = {
                "UNPACKER_ENGINE_MODE": "agentflow",
                "AGENTFLOW_RUNS_DIR": "/tmp/agentflow-runs",
                "AGENTFLOW_MAX_CONCURRENT_RUNS": "7",
                "AGENTFLOW_FALLBACK_TO_LEGACY": "false",
            }
            with patch.dict(os.environ, env, clear=False):
                cfg = reload_config(str(config_path))
            self.assertEqual("agentflow", cfg.agentflow.engine_mode)
            self.assertEqual("/tmp/agentflow-runs", cfg.agentflow.runs_dir)
            self.assertEqual(7, cfg.agentflow.max_concurrent_runs)
            self.assertFalse(cfg.agentflow.fallback_to_legacy)


class AgentFlowPipelineTests(unittest.TestCase):
    def test_pipeline_contains_expected_nodes_and_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = {
                "base_dir": str(root),
                "firmware_path": str(root / "input" / "fw.bin"),
                "output_path": str(root / "output"),
                "tools_dir": str(root / "tools"),
                "preprocess_output_file": str(root / "run" / "preprocess.json"),
                "feature_match_output_file": str(root / "run" / "feature-match.json"),
                "final_result_file": str(root / "run" / "final_result.json"),
                "agentflow_concurrency": 2,
                "max_retries": 3,
                "node_timeout_seconds": 900,
                "use_worktree": False,
                "executor_extra_args": ["--append-system-prompt", "/tmp/exec.md"],
                "review_extra_args": ["--append-system-prompt", "/tmp/review.md"],
                "author_extra_args": ["--append-system-prompt", "/tmp/author.md"],
                "cleanup_extra_args": ["--append-system-prompt", "/tmp/cleanup.md"],
            }
            spec = build_firmware_unpack_pipeline(ctx)
            node_ids = {node.id for node in spec.nodes}
            self.assertEqual(
                {
                    "preprocess",
                    "feature_match",
                    "skill_executor",
                    "skill_reviewer",
                    "generic_executor",
                    "generic_reviewer",
                    "skill_author",
                    "cleanup",
                    "finalize",
                },
                node_ids,
            )
            node_map = spec.node_map
            self.assertIn("feature_match", node_map["skill_executor"].depends_on)
            self.assertIn("generic_executor", node_map["generic_reviewer"].depends_on)
            self.assertIn("generic_executor", node_map["generic_reviewer"].on_failure_restart)
            for node_id in ("skill_reviewer", "generic_reviewer"):
                criteria = node_map[node_id].success_criteria
                self.assertEqual(1, len(criteria))
                self.assertEqual("output_regex", criteria[0].kind)
                self.assertIn("AGENTFLOW_REVIEW_(SUCCESS|SKIPPED)", criteria[0].value)


class EngineDispatchTests(unittest.TestCase):
    def test_legacy_mode_dispatches_to_legacy_engine(self):
        with patch("app.unpacker_engine._get_unpack_engine_mode", return_value="legacy"):
            with patch("app.unpacker_engine.run_unpack_legacy", return_value={"status": "success"}) as legacy:
                self.assertEqual({"status": "success"}, run_unpack("/tmp/fw.bin", "/tmp/out"))
                legacy.assert_called_once()

    def test_agentflow_failure_falls_back_when_enabled(self):
        with patch("app.unpacker_engine._get_unpack_engine_mode", return_value="agentflow"):
            with patch("app.unpacker_engine._agentflow_fallback_enabled", return_value=True):
                with patch("app.agentflow_runner.run_unpack_agentflow", side_effect=RuntimeError("boom")):
                    with patch("app.unpacker_engine.run_unpack_legacy", return_value={"status": "success"}) as legacy:
                        self.assertEqual({"status": "success"}, run_unpack("/tmp/fw.bin", "/tmp/out"))
                        legacy.assert_called_once()

    def test_legacy_preprocess_success_result_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            firmware = root / "fw.zip"
            with zipfile.ZipFile(firmware, "w") as archive:
                archive.writestr("etc/version.txt", "1.0")
            output = root / "output"

            result = run_unpack_legacy(str(firmware), str(output))

            self.assertEqual("success", result["status"])
            self.assertEqual(0, result["rounds"])
            self.assertIn("quick pre-process", result["message"])
            self.assertTrue((output / "etc" / "version.txt").is_file())


if __name__ == "__main__":
    unittest.main()
