import os
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.agentflow_runner import run_unpack_agentflow
from app.agentflow_pipeline import build_firmware_unpack_pipeline
from app.config import reload_config
from app.unpacker_engine import run_unpack


def _status(value):
    return SimpleNamespace(value=value)


def _node(output="", attempts=0, current_attempt=0):
    return SimpleNamespace(
        output=output,
        final_response="",
        current_attempt=current_attempt,
        attempts=[object()] * attempts,
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
        patch("app.agentflow_runner.get_config", return_value=config),
        patch("app.agentflow_runner.RunStore", FakeRunStore),
        patch("app.agentflow_runner.Orchestrator", FakeOrchestrator),
        patch("app.agentflow_runner.build_firmware_unpack_pipeline", return_value=object()),
        patch("app.unpacker_engine.extract_firmware_features", return_value={"filename": "fw.bin"}),
        patch("app.unpacker_engine._get_max_retries", return_value=2),
        patch("app.agentflow_runner.compute_family_id", return_value="family-1"),
    ]
    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        return run_unpack_agentflow("/tmp/fw.bin", output_path, **kwargs)


def _write_fake_pi(fake_bin, mode="preprocess"):
    fake_bin.mkdir(parents=True, exist_ok=True)
    fake_pi = fake_bin / "pi"
    fake_pi.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
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
        "    text = 'generic unpack done'\n"
        "elif mode == 'skill_success' and 'Unpack the firmware' in prompt:\n"
        "    text = 'AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_SKILL_SUCCESS'\n"
        "elif mode in ('skill_success', 'skill_fallback') and 'Otherwise use the system_prompt' in prompt:\n"
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
            for node_id in ("preprocess", "feature_match", "finalize"):
                self.assertIn("PYTHONPATH", node_map[node_id].env)
                self.assertIn("/app", node_map[node_id].env["PYTHONPATH"])
            self.assertEqual(450, node_map["skill_reviewer"].timeout_seconds)
            self.assertEqual(300, node_map["cleanup"].timeout_seconds)

    def test_pipeline_respects_short_node_timeout_for_smoke_runs(self):
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
            self.assertEqual(30, node_map["generic_executor"].timeout_seconds)
            self.assertEqual(15, node_map["generic_reviewer"].timeout_seconds)
            self.assertEqual(10, node_map["cleanup"].timeout_seconds)


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


class AgentFlowRunnerAdapterTests(unittest.TestCase):
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
            with patch("app.agentflow_runner.match_skill", return_value=(None, 0, {"matched_status": "miss"})):
                result = _run_agentflow_with_record(record, output)

            self.assertEqual("success", result["status"])
            self.assertEqual(0, result["rounds"])
            self.assertFalse(result["fallback_to_llm"])
            self.assertEqual("run-1", result["agentflow_run_id"])
            self.assertTrue((Path(tmp) / "task" / "run" / "final_result.json").is_file())

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
            with patch("app.agentflow_runner.match_skill", return_value=(skill, 95, {"matched_status": "hit"})):
                with patch("app.agentflow_runner.register_skill_success", return_value=promoted) as register:
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
            with patch("app.agentflow_runner.match_skill", return_value=(skill, 80, {"matched_status": "hit"})):
                with patch("app.agentflow_runner.save_candidate_skill", return_value=generated) as save_skill:
                    result = _run_agentflow_with_record(record, output)

            self.assertEqual("success", result["status"])
            self.assertEqual(2, result["rounds"])
            self.assertTrue(result["fallback_to_llm"])
            self.assertEqual("/data/tools/candidates/family-1.md", result["generated_skill_path"])
            self.assertEqual("candidate", result["generated_skill_status"])
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
            with patch("app.agentflow_runner.match_skill", return_value=(None, 0, {"matched_status": "miss"})):
                result = _run_agentflow_with_record(record, output)

            self.assertEqual("failed", result["status"])
            self.assertEqual(2, result["rounds"])
            self.assertIn("AgentFlow run failed: failed", result["message"])

    def test_cancelled_run_cancels_orchestrator_and_returns_cancelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / "task" / "output")
            record = _record(
                nodes={"generic_executor": _node("partial", attempts=1)},
                status="running",
            )
            with patch("app.agentflow_runner.match_skill", return_value=(None, 0, {"matched_status": "miss"})):
                result = _run_agentflow_with_record(record, output, cancel_check=unittest.mock.Mock(side_effect=[False, True]))

            self.assertEqual("cancelled", result["status"])
            self.assertEqual(1, result["rounds"])
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
                with patch("app.agentflow_runner.get_config", return_value=config):
                    with patch("app.unpacker_engine.TOOLS_DIR", tools_dir):
                        result = run_unpack_agentflow(str(firmware), str(output))

            self.assertEqual("success", result["status"])
            self.assertEqual(0, result["rounds"])
            self.assertTrue((output / "etc" / "version.txt").is_file())
            self.assertTrue((root / "task" / "run" / "final_result.json").is_file())
            run_id = result["agentflow_run_id"]
            self.assertTrue((root / "task" / "run" / "agentflow" / "runs" / run_id / "run.json").is_file())

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
                with patch("app.agentflow_runner.get_config", return_value=config):
                    with patch("app.unpacker_engine.TOOLS_DIR", tools_dir):
                        result = run_unpack_agentflow(str(firmware), str(output))

            self.assertEqual("success", result["status"])
            self.assertEqual(str(skill_path), result["matched_skill"])
            self.assertEqual(1, result["promotion_success_count"])
            self.assertFalse(result["fallback_to_llm"])
            run_json = (
                root
                / "task"
                / "run"
                / "agentflow"
                / "runs"
                / result["agentflow_run_id"]
                / "run.json"
            )
            self.assertIn("SKIPPED_BY_SKILL_SUCCESS", run_json.read_text(encoding="utf-8"))

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
                with patch("app.agentflow_runner.get_config", return_value=config):
                    with patch("app.unpacker_engine.TOOLS_DIR", tools_dir):
                        result = run_unpack_agentflow(str(firmware), str(output))

            self.assertEqual("success", result["status"])
            self.assertEqual(str(skill_path), result["matched_skill"])
            self.assertTrue(result["fallback_to_llm"])
            self.assertEqual("candidate", result["generated_skill_status"])
            self.assertTrue(result["generated_skill_path"])
            self.assertTrue(Path(result["generated_skill_path"]).is_file())


class AgentFlowApiSmokeTests(unittest.TestCase):
    def test_project_task_api_smoke_updates_db_and_agentflow_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            db_path = root / "service.db"
            files_root = root / "files"
            config_path.write_text(
                "database:\n"
                "  type: sqlite\n"
                f"  path: {db_path}\n"
                "auth_service:\n"
                "  enabled: false\n"
                "project_service:\n"
                "  enabled: false\n"
                "registry:\n"
                "  enabled: false\n"
                "service:\n"
                "  max_background_workers: 1\n"
                "worker:\n"
                "  claim_interval_seconds: 1\n"
                "  claim_batch_size: 1\n"
                "agentflow:\n"
                f"  runs_dir: {root / 'runs'}\n"
                "  max_concurrent_runs: 2\n"
                "  node_timeout_seconds: 30\n",
                encoding="utf-8",
            )
            firmware = root / "fw.zip"
            with zipfile.ZipFile(firmware, "w") as archive:
                archive.writestr("etc/version.txt", "1.0")
            fake_bin = root / "bin"
            _write_fake_pi(fake_bin)
            env = {
                "CONFIG_PATH": str(config_path),
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "PYTHONPATH": os.pathsep.join(
                    [
                        str(Path(__file__).resolve().parents[1]),
                        str(Path(__file__).resolve().parents[1] / "app"),
                        os.environ.get("PYTHONPATH", ""),
                    ]
                ),
            }

            try:
                from app import model as model_module
                from app.api.dependencies import get_current_subject
                from app.config import reload_config
                from app.model import init_database
                from app.services import task_manager
            except ModuleNotFoundError as exc:
                self.skipTest(f"runtime dependency unavailable: {exc.name}")

            model_module._engine = None
            model_module._SessionFactory = None
            with patch.dict(os.environ, env, clear=False):
                reload_config(str(config_path))
                init_database()
                from app.main import app
                from fastapi.testclient import TestClient

                app.dependency_overrides[get_current_subject] = lambda: ({}, "token")
                try:
                    with patch("app.api.firmware.ensure_project_access", new=AsyncMock(return_value=None)):
                        with patch("app.services.task_manager.PROJECT_FILES_ROOT", files_root):
                            with patch("app.unpacker_engine.TOOLS_DIR", root / "tools"):
                                client = TestClient(app)
                                submitted = client.post(
                                    "/api/app/firmware-unpacker/projects/proj-1/tasks",
                                    json={"firmware_path": str(firmware), "project_id": "proj-1"},
                                )
                                self.assertEqual(201, submitted.status_code)
                                task_id = submitted.json()["task_id"]

                                self.assertTrue(task_manager._claim_task(task_id))
                                task_manager._run_claimed_task(task_id)

                                detail = client.get(f"/api/app/firmware-unpacker/projects/proj-1/tasks/{task_id}")
                                self.assertEqual(200, detail.status_code)
                                task = detail.json()
                                self.assertEqual("success", task["status"])
                                self.assertEqual("success", task["result_status"])
                                self.assertEqual(0, task["rounds"])
                                self.assertTrue(task["agentflow_run_id"])

                                agentflow = client.get(
                                    f"/api/app/firmware-unpacker/projects/proj-1/tasks/{task_id}/agentflow"
                                )
                                self.assertEqual(200, agentflow.status_code)
                                payload = agentflow.json()
                                self.assertEqual(task["agentflow_run_id"], payload["agentflow_run_id"])
                                self.assertEqual("completed", payload["status"])
                                self.assertTrue(
                                    (
                                        files_root
                                        / "proj-1"
                                        / "app/secflow-app-firmware-unpacker"
                                        / task_id
                                        / "run"
                                        / "final_result.json"
                                    ).is_file()
                                )
                finally:
                    app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
