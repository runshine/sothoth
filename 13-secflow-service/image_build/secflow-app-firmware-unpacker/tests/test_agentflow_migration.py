import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.agentflow_pipeline import build_firmware_unpack_pipeline
from app.config import reload_config
from app.unpacker_engine import run_unpack


class AgentFlowConfigTests(unittest.TestCase):
    def test_defaults_use_agentflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text("app:\n  port: 9999\n", encoding="utf-8")
            with patch.dict(os.environ, {"CONFIG_PATH": str(config_path)}, clear=False):
                cfg = reload_config(str(config_path))
            self.assertTrue(cfg.agentflow.enabled)
            self.assertEqual(
                {
                    "enabled",
                    "runs_dir",
                    "max_concurrent_runs",
                    "node_timeout_seconds",
                    "use_worktree",
                    "cleanup_runs_retention_days",
                },
                set(cfg.agentflow.model_dump()),
            )

    def test_env_overrides_agentflow_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text("agentflow:\n  enabled: false\n", encoding="utf-8")
            env = {
                "AGENTFLOW_RUNS_DIR": "/tmp/agentflow-runs",
                "AGENTFLOW_MAX_CONCURRENT_RUNS": "7",
            }
            with patch.dict(os.environ, env, clear=False):
                cfg = reload_config(str(config_path))
            self.assertTrue(cfg.agentflow.enabled)
            self.assertEqual("/tmp/agentflow-runs", cfg.agentflow.runs_dir)
            self.assertEqual(7, cfg.agentflow.max_concurrent_runs)


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
    def test_run_unpack_dispatches_to_agentflow(self):
        with patch("app.agentflow_runner.run_unpack_agentflow", return_value={"status": "success"}) as agentflow:
            self.assertEqual({"status": "success"}, run_unpack("/tmp/fw.bin", "/tmp/out", task_id="t1", project_id="p1"))
            agentflow.assert_called_once_with(
                "/tmp/fw.bin",
                "/tmp/out",
                cancel_check=None,
                task_id="t1",
                project_id="p1",
            )

    def test_agentflow_failure_is_not_fallbacked(self):
        with patch("app.agentflow_runner.run_unpack_agentflow", side_effect=RuntimeError("boom")):
            with self.assertRaisesRegex(RuntimeError, "boom"):
                run_unpack("/tmp/fw.bin", "/tmp/out")


if __name__ == "__main__":
    unittest.main()
