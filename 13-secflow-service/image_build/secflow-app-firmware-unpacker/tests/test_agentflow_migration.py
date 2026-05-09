import json
import os
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from app.cli import _token_summary, run_unpack_agentflow
from app.cli import _skill_author_code, build_firmware_unpack_pipeline
from app.cli import reload_config


def _status(value):
    return SimpleNamespace(value=value)


def _node(output="", attempts=0, current_attempt=0, trace_events=None):
    return SimpleNamespace(
        output=output,
        final_response="",
        current_attempt=current_attempt,
        attempts=[object()] * attempts,
        trace_events=trace_events or [],
    )


def _record(status="completed", nodes=None, run_id="run-1"):
    return SimpleNamespace(id=run_id, status=_status(status), nodes=nodes or {})


class FakeRunStore:
    last = None

    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.record = None
        FakeRunStore.last = self

    def get_run(self, run_id):
        return self.record


class FakeOrchestrator:
    last = None
    next_record = None

    def __init__(self, store, max_concurrent_runs):
        self.store = store
        self.max_concurrent_runs = max_concurrent_runs
        self.cancelled = []
        FakeOrchestrator.last = self

    async def submit(self, pipeline):
        self.store.record = FakeOrchestrator.next_record
        return self.store.record

    async def cancel(self, run_id):
        self.cancelled.append(run_id)
        self.store.record.status = _status("cancelled")

    async def wait(self, run_id, timeout=5):
        return self.store.record


def _run_agentflow_with_record(record, output_path, **kwargs):
    FakeOrchestrator.next_record = record
    config = SimpleNamespace(
        agentflow=SimpleNamespace(
            runs_dir=str(Path(output_path).parent / "runs"),
            max_concurrent_runs=2,
            node_timeout_seconds=900,
            use_worktree=False,
        )
    )
    patches = [
        patch("app.cli.get_config", return_value=config),
        patch("app.cli.RunStore", FakeRunStore),
        patch("app.cli.Orchestrator", FakeOrchestrator),
        patch("app.cli.build_firmware_unpack_pipeline", return_value=object()),
        patch("app.cli.extract_firmware_features", return_value={"filename": "fw.bin"}),
        patch("app.cli.get_max_retries", return_value=2),
        patch("app.cli.compute_family_id", return_value="family-1"),
    ]
    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        return run_unpack_agentflow("/tmp/fw.bin", output_path, **kwargs)


def _write_fake_pi(fake_bin, mode="preprocess"):
    fake_bin.mkdir(parents=True, exist_ok=True)
    fake_pi = fake_bin / "pi"
    fake_pi.write_text(
        "#!/usr/bin/env python3\n"
        "import json, re, sys\n"
        "from pathlib import Path\n"
        f"mode = {mode!r}\n"
        "prompt = sys.stdin.read()\n"
        "skill_doc = '''---\\nname: generated skill\\ndescription: generated fallback skill\\nformat_id: generated-bin\\nextensions: .bin\\nmagic_hex: abcd1234\\nkeywords: generated\\nbinwalk_sigs: firmware\\nskill_status: candidate\\nskill_version: 1\\nfamily_id: generated-bin\\npromotion_success_count: 0\\npromotion_threshold: 5\\ntools: read, bash\\n---\\n\\nUse this generated guidance.\\n'''\n"
        "if mode == 'skill_success' and 'Review the matched-skill extraction result' in prompt:\n"
        "    text = 'AGENTFLOW_REVIEW_SUCCESS'\n"
        "elif mode == 'skill_fallback' and 'Review the matched-skill extraction result' in prompt:\n"
        "    text = 'AGENTFLOW_REVIEW_FAIL reason=skill output invalid'\n"
        "elif mode == 'skill_fallback' and 'Review the generic unpack result' in prompt:\n"
        "    text = 'AGENTFLOW_REVIEW_SUCCESS'\n"
        "elif mode == 'skill_fallback' and 'Author a reusable skill candidate' in prompt:\n"
        "    text = skill_doc\n"
        "elif mode == 'skill_fallback' and 'Unpack the firmware' in prompt:\n"
        "    match = re.search(r'^\\$output = (.+)$', prompt, re.MULTILINE)\n"
        "    if match:\n"
        "        out = Path(match.group(1).strip())\n"
        "        out.mkdir(parents=True, exist_ok=True)\n"
        "        (out / 'artifact.bin').write_bytes(b'payload')\n"
        "        (out / 'summary.txt').write_text('fallback unpack summary\\n', encoding='utf-8')\n"
        "    text = 'generic unpack done'\n"
        "elif mode == 'skill_success' and 'Unpack the firmware' in prompt:\n"
        "    text = 'AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_SKILL_SUCCESS'\n"
        "elif mode == 'skill_fallback' and 'matched skill file path shown by Skill gate' in prompt:\n"
        "    text = 'skill executor failed'\n"
        "elif mode == 'skill_success' and 'matched skill file path shown by Skill gate' in prompt:\n"
        "    text = 'skill executor completed'\n"
        "elif 'Review the matched-skill extraction result' in prompt:\n"
        "    text = 'AGENTFLOW_REVIEW_SKIPPED reason=SKIPPED_BY_PREPROCESS'\n"
        "elif 'Review the generic unpack result' in prompt:\n"
        "    text = 'AGENTFLOW_REVIEW_SKIPPED reason=SKIPPED_BY_PREPROCESS'\n"
        "elif 'Author a reusable skill candidate' in prompt:\n"
        "    text = 'SKIPPED_NO_SUCCESS'\n"
        "elif 'Clean and normalize the output directory' in prompt:\n"
        "    text = 'cleanup complete'\n"
        "elif 'If Preprocess contains JSON with success=true' in prompt:\n"
        "    text = 'AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS'\n"
        "else:\n"
        "    text = 'ok'\n"
        "message = {'role': 'assistant', 'content': [{'type': 'text', 'text': text}]}\n"
        "print(json.dumps({'type': 'message_end', 'message': message}))\n"
        "print(json.dumps({'type': 'agent_end', 'messages': [message]}))\n",
        encoding="utf-8",
    )
    fake_pi.chmod(0o755)
    return fake_pi


def _write_matching_skill(tools_dir):
    tools_dir.mkdir(parents=True, exist_ok=True)
    skill_path = tools_dir / "matched-bin.md"
    skill_path.write_text(
        "---\n"
        "name: matched bin\n"
        "description: matched binary skill\n"
        "format_id: matched-bin\n"
        "extensions: .bin\n"
        "magic_hex: abcd1234\n"
        "keywords: firmware\n"
        "binwalk_sigs: firmware\n"
        "skill_status: active\n"
        "skill_version: 1\n"
        "family_id: matched-bin\n"
        "promotion_success_count: 0\n"
        "promotion_threshold: 5\n"
        "tools: read, bash\n"
        "---\n\n"
        "Use the matched binary extraction procedure.\n",
        encoding="utf-8",
    )
    return skill_path


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
                    "profile",
                    "runs_dir",
                    "max_concurrent_runs",
                    "node_timeout_seconds",
                    "use_worktree",
                    "graph_optimization_enabled",
                    "graph_optimizer",
                    "graph_optimization_rounds",
                    "evolution_archive_dir",
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
                "AGENTFLOW_PROFILE": "staging",
                "AGENTFLOW_GRAPH_OPTIMIZATION_ENABLED": "true",
                "AGENTFLOW_GRAPH_OPTIMIZER": "pi",
                "AGENTFLOW_GRAPH_OPTIMIZATION_ROUNDS": "2",
                "AGENTFLOW_EVOLUTION_ARCHIVE_DIR": "/tmp/evolution",
            }
            with patch.dict(os.environ, env, clear=False):
                cfg = reload_config(str(config_path))
            self.assertTrue(cfg.agentflow.enabled)
            self.assertEqual("/tmp/agentflow-runs", cfg.agentflow.runs_dir)
            self.assertEqual(7, cfg.agentflow.max_concurrent_runs)
            self.assertEqual("staging", cfg.agentflow.profile)
            self.assertTrue(cfg.agentflow.graph_optimization_enabled)
            self.assertEqual("pi", cfg.agentflow.graph_optimizer)
            self.assertEqual(2, cfg.agentflow.graph_optimization_rounds)
            self.assertEqual("/tmp/evolution", cfg.agentflow.evolution_archive_dir)


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
                "skill_author_output_file": str(root / "run" / "generated_skill.md"),
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
                    "skill_gate",
                    "skill_executor",
                    "skill_reviewer",
                    "generic_executor",
                    "output_summary",
                    "generic_reviewer",
                    "skill_author",
                    "cleanup",
                    "finalize",
                },
                node_ids,
            )
            node_map = spec.node_map
            self.assertIn("feature_match", node_map["skill_gate"].depends_on)
            self.assertIn("skill_gate", node_map["skill_executor"].depends_on)
            self.assertIn("Skill gate contains matched=false", node_map["skill_executor"].prompt)
            self.assertIn("Do not read the full feature match JSON", node_map["skill_executor"].prompt)
            self.assertIn("feature_count_binwalk_sigs", node_map["feature_match"].prompt)
            self.assertIn("Path(payload['output_file']).write_text", node_map["feature_match"].prompt)
            self.assertNotIn("'system_prompt':", node_map["feature_match"].prompt)
            self.assertIn("generic_executor", node_map["output_summary"].depends_on)
            self.assertIn("output_summary", node_map["generic_reviewer"].depends_on)
            self.assertIn("generic_executor", node_map["generic_reviewer"].on_failure_restart)
            self.assertEqual([], node_map["generic_executor"].skip_if)
            self.assertIn("SKIPPED_BY_SKILL_SUCCESS", node_map["generic_executor"].prompt)
            self.assertIn("SKIPPED_BY_PREPROCESS", node_map["generic_executor"].prompt)
            for node_id in ("skill_reviewer", "generic_reviewer"):
                criteria = node_map[node_id].success_criteria
                self.assertEqual(1, len(criteria))
                self.assertEqual("output_regex", criteria[0].kind)
                self.assertIn("AGENTFLOW_REVIEW_(SUCCESS|SKIPPED)", criteria[0].value)
            for node_id in ("preprocess", "feature_match", "finalize"):
                self.assertIn("PYTHONPATH", node_map[node_id].env)
                self.assertIn("/app", node_map[node_id].env["PYTHONPATH"])
            self.assertIsNone(node_map["skill_executor"].timeout_seconds)
            self.assertIsNone(node_map["generic_executor"].timeout_seconds)
            for node_id in ("skill_executor", "generic_executor"):
                self.assertEqual(str(root / "input" / "fw.bin"), node_map[node_id].env["firmware"])
                self.assertEqual(str(root / "output"), node_map[node_id].env["output"])
                self.assertEqual(str(root / "input"), node_map[node_id].env["input"])
                self.assertEqual(str(root / "input" / "fw.bin"), node_map[node_id].env["FIRMWARE_PATH"])
                self.assertEqual(str(root / "output"), node_map[node_id].env["FIRMWARE_OUTPUT"])
                self.assertIn("exported in the bash tool environment", node_map[node_id].prompt)
            self.assertEqual(450, node_map["skill_reviewer"].timeout_seconds)
            self.assertEqual("python", node_map["output_summary"].agent)
            self.assertEqual("python", node_map["cleanup"].agent)
            self.assertIn("Always create $output/summary.txt", node_map["generic_executor"].prompt)
            self.assertIn("Required execution plan, in order:", node_map["generic_executor"].prompt)
            self.assertIn('binwalk "$firmware" > "$output/binwalk.txt"', node_map["generic_executor"].prompt)
            self.assertIn("Never read the full binwalk file", node_map["generic_executor"].prompt)
            self.assertIn("bounded shell commands", node_map["generic_executor"].prompt)
            self.assertIn("iflag=skip_bytes,count_bytes", node_map["generic_executor"].prompt)
            self.assertIn("Do not recursively copy `$output/binwalk_extract`", node_map["generic_executor"].prompt)
            self.assertIn("AGENTFLOW_GENERIC_DONE", node_map["generic_executor"].prompt)
            self.assertIn("Do not use `binwalk -eM`", node_map["generic_executor"].prompt)

    def test_pipeline_can_enable_graph_optimization_in_safe_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = {
                "base_dir": str(root),
                "firmware_path": str(root / "input" / "fw.bin"),
                "output_path": str(root / "output"),
                "tools_dir": str(root / "tools"),
                "preprocess_output_file": str(root / "run" / "preprocess.json"),
                "feature_match_output_file": str(root / "run" / "feature-match.json"),
                "skill_author_output_file": str(root / "run" / "generated_skill.md"),
                "final_result_file": str(root / "run" / "final_result.json"),
                "agentflow_concurrency": 2,
                "max_retries": 3,
                "node_timeout_seconds": 900,
                "use_worktree": False,
                "graph_optimization_enabled": True,
                "graph_optimizer": "pi",
                "graph_optimization_rounds": 2,
                "executor_extra_args": [],
                "review_extra_args": [],
                "author_extra_args": [],
                "cleanup_extra_args": [],
            }
            spec = build_firmware_unpack_pipeline(ctx)
            self.assertEqual("pi", spec.optimizer)
            self.assertEqual(2, spec.n_run)

    def test_pipeline_keeps_executor_nodes_unbounded_while_reviewers_use_timeouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = {
                "base_dir": str(root),
                "firmware_path": str(root / "input" / "fw.bin"),
                "output_path": str(root / "output"),
                "tools_dir": str(root / "tools"),
                "preprocess_output_file": str(root / "run" / "preprocess.json"),
                "feature_match_output_file": str(root / "run" / "feature-match.json"),
                "skill_author_output_file": str(root / "run" / "generated_skill.md"),
                "final_result_file": str(root / "run" / "final_result.json"),
                "agentflow_concurrency": 1,
                "max_retries": 1,
                "node_timeout_seconds": 30,
                "use_worktree": False,
                "executor_extra_args": [],
                "review_extra_args": [],
                "author_extra_args": [],
                "cleanup_extra_args": [],
            }
            node_map = build_firmware_unpack_pipeline(ctx).node_map
            self.assertIsNone(node_map["skill_executor"].timeout_seconds)
            self.assertIsNone(node_map["generic_executor"].timeout_seconds)
            self.assertEqual(15, node_map["generic_reviewer"].timeout_seconds)
            self.assertEqual("python", node_map["cleanup"].agent)

    def test_skill_author_caps_generated_skill_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            run = root / "run"
            output.mkdir()
            run.mkdir()
            (output / "summary.txt").write_text(("very long summary line " * 200) + "\n" * 2 + "keep this\n", encoding="utf-8")
            feature_payload = {
                "features": {
                    "family_id": "cc-00000000-lzma-compressed-data-properties",
                    "ext": ".cc",
                    "magic_hex": "00000000",
                    "binwalk_sigs": [f"signature {index} " + ("x" * 300) for index in range(100)],
                }
            }
            feature_file = run / "feature-match.json"
            feature_file.write_text(json.dumps(feature_payload), encoding="utf-8")
            skill_file = run / "generated_skill.md"
            ctx = {
                "feature_match_output_file": str(feature_file),
                "output_path": str(output),
                "skill_author_output_file": str(skill_file),
            }

            code = _skill_author_code(ctx).replace("{{ nodes.generic_reviewer.output }}", "AGENTFLOW_REVIEW_SUCCESS")
            exec(code, {})
            generated = skill_file.read_text(encoding="utf-8")

            self.assertLess(skill_file.stat().st_size, 20_000)
            self.assertLess(max(len(line) for line in generated.splitlines()), 1_000)
            self.assertIn("[summary truncated for reusable skill size]", generated)


class AgentFlowRunnerAdapterTests(unittest.TestCase):
    def test_token_summary_supports_gaiasec_usage_fields(self):
        events = [
            SimpleNamespace(
                kind="assistant_delta",
                raw={
                    "type": "message_update",
                    "message": {
                        "responseId": "resp-1",
                        "usage": {
                            "input": 0,
                            "output": 0,
                            "cacheRead": 0,
                            "cacheWrite": 0,
                            "totalTokens": 0,
                        },
                    },
                },
            ),
            SimpleNamespace(
                kind="message_end",
                raw={
                    "type": "message_end",
                    "message": {
                        "responseId": "resp-1",
                        "usage": {
                            "input": 4432,
                            "output": 382,
                            "cacheRead": 0,
                            "cacheWrite": 0,
                            "totalTokens": 4814,
                        },
                    },
                },
            ),
        ]
        record = _record(nodes={"skill_executor": _node(trace_events=events)})

        summary = _token_summary(record)

        self.assertEqual(
            {"prompt_tokens": 4432, "completion_tokens": 382, "total_tokens": 4814},
            summary["nodes"]["skill_executor"],
        )
        self.assertEqual(4432, summary["total_prompt_tokens"])
        self.assertEqual(382, summary["total_completion_tokens"])
        self.assertEqual(4814, summary["total_tokens"])
        self.assertEqual(4814, summary["grand_total"]["total_tokens"])

    def test_token_summary_deduplicates_streaming_usage_by_response_id(self):
        usage = {
            "prompt_tokens": 10,
            "completion_tokens": 4,
            "total_tokens": 14,
        }
        events = [
            SimpleNamespace(kind="assistant_delta", raw={"type": "message_update", "message": {"responseId": "resp-1", "usage": usage}}),
            SimpleNamespace(kind="turn_end", raw={"type": "turn_end", "message": {"responseId": "resp-1", "usage": usage}}),
            SimpleNamespace(kind="message_end", raw={"type": "message_end", "message": {"responseId": "resp-2", "usage": {"input_tokens": 7, "output_tokens": 3}}}),
        ]
        record = _record(nodes={"generic_executor": _node(trace_events=events)})

        summary = _token_summary(record)

        self.assertEqual(
            {"prompt_tokens": 17, "completion_tokens": 7, "total_tokens": 24},
            summary["nodes"]["generic_executor"],
        )

    def test_preprocess_success_result_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "task" / "output")
            record = _record(
                nodes={
                    "preprocess": _node('{"success": true, "method": "zip"}'),
                    "skill_reviewer": _node("AGENTFLOW_REVIEW_SKIPPED"),
                    "generic_executor": _node("AGENTFLOW_EXECUTOR_SKIPPED"),
                    "generic_reviewer": _node("AGENTFLOW_REVIEW_SKIPPED"),
                }
            )
            with patch("app.cli.match_skill", return_value=(None, 0, {"matched_status": "miss"})):
                result = _run_agentflow_with_record(record, output)

            self.assertEqual("success", result["status"])
            self.assertEqual(0, result["rounds"])
            self.assertFalse(result["fallback_to_llm"])
            self.assertEqual("run-1", result["agentflow_run_id"])
            self.assertEqual(str(Path(output).parent / "runs" / "run-1"), result["agentflow_run_dir"])
            self.assertIn("preprocess", result["node_attempts"])
            self.assertEqual(0, result["total_tokens"])
            self.assertTrue((Path(tmp) / "task" / "run" / "final_result.json").is_file())
            self.assertTrue((Path(tmp) / "task" / "run" / "tokens_summary.json").is_file())
            self.assertTrue((Path(tmp) / "task" / "run" / "agentflow_run_dir.txt").is_file())

    def test_skill_success_registers_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "task" / "output")
            skill = {"path": "/data/tools/skills/router.md", "skill_version": "1.0"}
            promoted = {**skill, "promotion_success_count": 3}
            record = _record(
                nodes={
                    "preprocess": _node('{"success": false}'),
                    "skill_reviewer": _node("AGENTFLOW_REVIEW_SUCCESS"),
                    "generic_executor": _node("AGENTFLOW_EXECUTOR_SKIPPED"),
                    "generic_reviewer": _node("AGENTFLOW_REVIEW_SKIPPED"),
                }
            )
            with patch("app.cli.match_skill", return_value=(skill, 95, {"matched_status": "hit"})):
                with patch("app.cli.register_skill_success", return_value=promoted) as register:
                    result = _run_agentflow_with_record(record, output)

            self.assertEqual("success", result["status"])
            self.assertEqual("/data/tools/skills/router.md", result["matched_skill"])
            self.assertEqual("1.0", result["matched_skill_version"])
            self.assertEqual(95, result["matched_skill_score"])
            self.assertEqual(3, result["promotion_success_count"])
            self.assertFalse(result["fallback_to_llm"])
            register.assert_called_once()

    def test_skill_failure_falls_back_to_generic_and_saves_candidate_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "task" / "output")
            skill = {"path": "/data/tools/skills/router.md", "skill_version": "1.0"}
            generated = {
                "path": "/data/tools/candidates/family-1.md",
                "skill_status": "candidate",
                "promotion_success_count": 0,
            }
            record = _record(
                nodes={
                    "preprocess": _node('{"success": false}'),
                    "skill_reviewer": _node("AGENTFLOW_REVIEW_FAIL reason=bad output"),
                    "generic_executor": _node("generic unpack done", attempts=2),
                    "generic_reviewer": _node("AGENTFLOW_REVIEW_SUCCESS"),
                    "skill_author": _node("# Skill\n\nReusable guidance."),
                },
                status="completed",
            )
            with patch("app.cli.match_skill", return_value=(skill, 80, {"matched_status": "hit"})):
                with patch("app.cli.save_candidate_skill", return_value=generated) as save_skill:
                    result = _run_agentflow_with_record(record, output)

            self.assertEqual("success", result["status"])
            self.assertEqual(2, result["rounds"])
            self.assertTrue(result["fallback_to_llm"])
            self.assertEqual("/data/tools/candidates/family-1.md", result["generated_skill_path"])
            self.assertEqual("candidate", result["generated_skill_status"])
            self.assertEqual("STRUCTURAL_FAILURE", result["failure_summary"]["failed_nodes"][0]["classification"]["category"])
            save_skill.assert_called_once()

    def test_failed_run_reports_attempt_rounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "task" / "output")
            record = _record(
                nodes={
                    "preprocess": _node('{"success": false}'),
                    "skill_reviewer": _node("AGENTFLOW_REVIEW_FAIL"),
                    "generic_executor": _node("generic failed", attempts=2),
                    "generic_reviewer": _node("AGENTFLOW_REVIEW_FAIL"),
                },
                status="failed",
            )
            with patch("app.cli.match_skill", return_value=(None, 0, {"matched_status": "miss"})):
                result = _run_agentflow_with_record(record, output)

            self.assertEqual("failed", result["status"])
            self.assertEqual(2, result["rounds"])
            self.assertIn("AgentFlow run failed: failed", result["message"])

    def test_failed_run_status_overrides_successful_node_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "task" / "output")
            skill = {"path": "/data/tools/skills/router.md", "skill_version": "1.0"}
            record = _record(
                nodes={
                    "preprocess": _node('{"success": false}'),
                    "skill_executor": _node("skill executor completed"),
                    "skill_reviewer": _node("AGENTFLOW_REVIEW_SUCCESS"),
                    "generic_executor": _node("AGENTFLOW_EXECUTOR_SKIPPED"),
                    "generic_reviewer": _node("AGENTFLOW_REVIEW_SKIPPED"),
                },
                status="failed",
            )
            with patch("app.cli.match_skill", return_value=(skill, 80, {"matched_status": "hit"})):
                with patch("app.cli.register_skill_success") as register_success:
                    result = _run_agentflow_with_record(record, output)

            self.assertEqual("failed", result["status"])
            self.assertEqual(0, result["rounds"])
            self.assertIn("AgentFlow run failed: failed", result["message"])
            register_success.assert_not_called()

    def test_cancelled_run_cancels_orchestrator_and_returns_cancelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "task" / "output")
            record = _record(
                nodes={"generic_executor": _node("partial", attempts=1)},
                status="running",
            )
            with patch("app.cli.match_skill", return_value=(None, 0, {"matched_status": "miss"})):
                result = _run_agentflow_with_record(record, output, cancel_check=unittest.mock.Mock(side_effect=[False, True]))

            self.assertEqual("cancelled", result["status"])
            self.assertEqual(1, result["rounds"])
            self.assertEqual("run-1", result["agentflow_run_id"])
            self.assertIn("cancellation_summary", result)
            self.assertIn("generic_executor", result["node_attempts"])
            self.assertEqual(["run-1"], FakeOrchestrator.last.cancelled)


class AgentFlowRunnerSmokeTests(unittest.TestCase):
    def test_real_agentflow_smoke_with_fake_pi_and_zip_preprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "bin"
            _write_fake_pi(fake_bin)

            firmware = root / "fw.zip"
            with zipfile.ZipFile(firmware, "w") as archive:
                archive.writestr("etc/version.txt", "1.0")
            tools_dir = root / "tools"
            output = root / "task" / "output"
            config = SimpleNamespace(
                agentflow=SimpleNamespace(
                    runs_dir=str(root / "runs"),
                    max_concurrent_runs=2,
                    node_timeout_seconds=30,
                    use_worktree=False,
                )
            )
            env = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "PYTHONPATH": os.pathsep.join(
                    [
                        str(Path(__file__).resolve().parents[1]),
                        str(Path(__file__).resolve().parents[1] / "app"),
                        os.environ.get("PYTHONPATH", ""),
                    ]
                ),
            }

            with patch.dict(os.environ, env, clear=False):
                with patch("app.cli.get_config", return_value=config):
                    with patch("app.cli.TOOLS_DIR", tools_dir):
                        result = run_unpack_agentflow(str(firmware), str(output))

            self.assertEqual("success", result["status"])
            self.assertEqual(0, result["rounds"])
            self.assertTrue((output / "etc" / "version.txt").is_file())
            self.assertTrue((root / "task" / "run" / "final_result.json").is_file())
            run_id = result["agentflow_run_id"]
            self.assertTrue((root / "runs" / run_id / "run.json").is_file())
            self.assertEqual(str(root / "runs" / run_id), result["agentflow_run_dir"])

    def test_real_agentflow_smoke_with_fake_pi_and_skill_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "bin"
            _write_fake_pi(fake_bin, mode="skill_success")
            tools_dir = root / "tools"
            skill_path = _write_matching_skill(tools_dir)
            firmware = root / "fw.bin"
            firmware.write_bytes(bytes.fromhex("abcd1234") + b"payload")
            output = root / "task" / "output"
            config = SimpleNamespace(
                agentflow=SimpleNamespace(
                    runs_dir=str(root / "runs"),
                    max_concurrent_runs=2,
                    node_timeout_seconds=30,
                    use_worktree=False,
                )
            )
            env = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "PYTHONPATH": os.pathsep.join(
                    [
                        str(Path(__file__).resolve().parents[1]),
                        str(Path(__file__).resolve().parents[1] / "app"),
                        os.environ.get("PYTHONPATH", ""),
                    ]
                ),
            }

            with patch.dict(os.environ, env, clear=False):
                with patch("app.cli.get_config", return_value=config):
                    with patch("app.cli.TOOLS_DIR", tools_dir):
                        result = run_unpack_agentflow(str(firmware), str(output))

            self.assertEqual("success", result["status"])
            self.assertEqual(str(skill_path), result["matched_skill"])
            self.assertEqual(1, result["promotion_success_count"])
            self.assertFalse(result["fallback_to_llm"])
            run_json = (
                root
                / "runs"
                / result["agentflow_run_id"]
                / "run.json"
            )
            run_payload = run_json.read_text(encoding="utf-8")
            self.assertIn('"generic_executor"', run_payload)
            self.assertIn('"status": "completed"', run_payload)
            self.assertIn('AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_SKILL_SUCCESS', run_payload)

    def test_real_agentflow_smoke_with_fake_pi_and_skill_fallback_author(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "bin"
            _write_fake_pi(fake_bin, mode="skill_fallback")
            tools_dir = root / "tools"
            skill_path = _write_matching_skill(tools_dir)
            firmware = root / "fw.bin"
            firmware.write_bytes(bytes.fromhex("abcd1234") + b"payload")
            output = root / "task" / "output"
            config = SimpleNamespace(
                agentflow=SimpleNamespace(
                    runs_dir=str(root / "runs"),
                    max_concurrent_runs=2,
                    node_timeout_seconds=30,
                    use_worktree=False,
                )
            )
            env = {
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "PYTHONPATH": os.pathsep.join(
                    [
                        str(Path(__file__).resolve().parents[1]),
                        str(Path(__file__).resolve().parents[1] / "app"),
                        os.environ.get("PYTHONPATH", ""),
                    ]
                ),
            }

            with patch.dict(os.environ, env, clear=False):
                with patch("app.cli.get_config", return_value=config):
                    with patch("app.cli.TOOLS_DIR", tools_dir):
                        result = run_unpack_agentflow(str(firmware), str(output))

            self.assertEqual("success", result["status"])
            self.assertEqual(str(skill_path), result["matched_skill"])
            self.assertTrue(result["fallback_to_llm"])
            self.assertEqual("candidate", result["generated_skill_status"])
            self.assertTrue(result["generated_skill_path"])
            self.assertTrue(Path(result["generated_skill_path"]).is_file())


if __name__ == "__main__":
    unittest.main()
