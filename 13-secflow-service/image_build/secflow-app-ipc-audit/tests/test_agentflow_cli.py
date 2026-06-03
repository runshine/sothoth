from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from app.core.auth import Subject
from app.core.config import load_config
from app.db.database import init_database
from fastapi import HTTPException

from app.schemas import GraphValidateRequest, InputRef, TaskCreateRequest
from app.services.artifact_service import get_artifact_service
from app.services.execution_service import get_execution_service
from app.services.task_service import get_task_service
from app.workers.runner import write_json_file, write_text_file


class AgentFlowCliModeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-repo-")
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-state-")
        self.agentflow_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-agentflow-")
        self.repo_root = Path(self.repo_dir.name)
        self.state_root = Path(self.state_dir.name)
        self.agentflow_root = Path(self.agentflow_dir.name)

        project_dir = self.repo_root / "foundation" / "demo" / "service"
        project_dir.mkdir(parents=True)
        (project_dir / "bundle.json").write_text("{}\n", encoding="utf-8")
        (project_dir / "iface.idl").write_text("interface Demo {}\n", encoding="utf-8")
        self._write_fake_agentflow()

        self._reset_singletons()
        self._set_env("IPC_AUDIT_DATABASE_URL", f"sqlite:///{self.state_root / 'ipc-audit.db'}")
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_EXECUTION_MODE", "mock")
        self._set_env("IPC_AUDIT_AGENTFLOW_ROOT", str(self.agentflow_root))
        self._set_env("IPC_AUDIT_AGENTFLOW_PYTHON_BIN", sys.executable)
        self._set_env("IPC_AUDIT_AGENTFLOW_AGENT", "codex")
        self._set_env("IPC_AUDIT_CODEX_BIN", "/usr/local/bin/codex")
        self._set_env(
            "IPC_AUDIT_WORKSPACES_JSON",
            json.dumps(
                [
                    {
                        "workspace_id": "oh61-main",
                        "display_name": "OpenHarmony 6.1 Main Tree",
                        "repo_root": str(self.repo_root),
                        "entries_file": ".audit/ipc_entries.txt",
                        "bundle_scan_roots": ["base", "foundation"],
                        "allow_custom_project_path": True,
                        "supports_poc": True,
                        "default_pipeline_mode": "audit_then_poc",
                        "is_default": True,
                    }
                ]
            ),
        )
        load_config()
        init_database()
        self.subject = Subject(username="tester")

    def tearDown(self) -> None:
        for key in (
            "IPC_AUDIT_DATABASE_URL",
            "IPC_AUDIT_STATE_ROOT",
            "IPC_AUDIT_EXECUTION_MODE",
            "IPC_AUDIT_AGENTFLOW_ROOT",
            "IPC_AUDIT_AGENTFLOW_ROOT_CANDIDATES",
            "IPC_AUDIT_AGENTFLOW_PYTHON_BIN",
            "IPC_AUDIT_AGENTFLOW_AGENT",
            "IPC_AUDIT_CODEX_BIN",
            "IPC_AUDIT_WORKSPACES_JSON",
            "HDC_BIN",
            "OHEMU_HELPER_BIN",
            "OHEMU_WORKSPACE_ROOT",
            "OHEMU_QCOW2_PREPARED_ROOT",
            "OHEMU_RUNTIME_ROOT",
            "OHEMU_ARCH",
            "OHEMU_NETWORK_MODE",
            "OHEMU_HDC_BIND",
            "OHEMU_HDC_BASE_PORT",
            "OHEMU_BOOT_DIR",
            "OHEMU_SRC_DIR",
            "FAKE_AGENTFLOW_FAIL_NODE",
        ):
            os.environ.pop(key, None)
        self._reset_singletons()
        self.repo_dir.cleanup()
        self.state_dir.cleanup()
        self.agentflow_dir.cleanup()

    def test_agentflow_cli_runs_full_pipeline_and_preserves_sessions(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_then_poc",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        self.assertEqual(detail.status, "succeeded")
        self.assertEqual(attempt.status, "succeeded")
        self.assertEqual(attempt.effective_config["executor_mode"], "agentflow_cli")
        self.assertEqual(attempt.effective_config["execution_mode"], "agentflow_cli")
        self.assertEqual(attempt.effective_config["model"], "gpt-5-codex")

        audit_sessions = get_task_service().list_stage_sessions(task.task_id, str(detail.latest_attempt_id), "audit")
        poc_sessions = get_task_service().list_stage_sessions(task.task_id, str(detail.latest_attempt_id), "poc")
        self.assertCountEqual(
            [item["path"] for item in audit_sessions],
            [
                "runtime/audit/prompt.txt",
                "runtime/audit/events.jsonl",
                "runtime/audit/last-message.md",
            ],
        )
        self.assertCountEqual(
            [item["path"] for item in poc_sessions],
            [
                "runtime/poc/prompt.txt",
                "runtime/poc/events.jsonl",
                "runtime/poc/last-message.md",
            ],
        )

        audit_events = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "audit",
            "runtime/audit/events.jsonl",
        )["content"]
        self.assertIn('"type": "assistant_message"', audit_events)

        poc_last_message = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "poc",
            "runtime/poc/last-message.md",
        )["content"]
        self.assertIn("# Fake AgentFlow Message", poc_last_message)

        event_page = get_task_service().list_events(task.task_id, attempt_id=str(detail.latest_attempt_id), cursor=None, limit=200)
        stdout_event = next(item for item in event_page.items if item.event_type == "stage.stdout.appended" and item.stage_name == "audit")
        self.assertEqual(stdout_event.payload["session_file_path"], "runtime/audit/events.jsonl")
        self.assertEqual(stdout_event.payload["event_types"]["assistant_message"], 1)

        agent_event = next(item for item in event_page.items if item.event_type == "stage.agent.message" and item.stage_name == "poc")
        self.assertIn("# Fake AgentFlow Message", agent_event.payload["preview"])

        audit_log = get_task_service().get_stage_log(task.task_id, str(detail.latest_attempt_id), "audit", lines=260, cursor=None)
        self.assertIn("Executor mode: agentflow_cli", audit_log.content)
        self.assertIn(str(self.agentflow_root), audit_log.content)

        artifacts = get_task_service().list_artifacts(task.task_id, str(detail.latest_attempt_id))
        artifact_kinds = [item.artifact_kind for item in artifacts.items]
        self.assertIn("audit_report", artifact_kinds)
        self.assertIn("poc_report", artifact_kinds)
        self.assertIn("audited_result_json", artifact_kinds)

        attempt_root = self._attempt_root(task.task_id, str(detail.latest_attempt_id))
        pipeline_payload = json.loads((attempt_root / "runtime" / "agentflow-stage-pipeline.json").read_text(encoding="utf-8"))
        project_work_dir = str(self.repo_root / "foundation" / "demo" / "service")
        self.assertEqual(pipeline_payload["working_dir"], project_work_dir)
        self.assertEqual([node["id"] for node in pipeline_payload["nodes"]], ["audit", "poc"])
        self.assertEqual([node["target"]["cwd"] for node in pipeline_payload["nodes"]], [project_work_dir, project_work_dir])
        self.assertEqual(pipeline_payload["nodes"][1]["depends_on"], ["audit"])

        manifest = json.loads((attempt_root / "runtime" / "agentflow-stage-pipeline-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["kind"], "combined_stage_pipeline")
        self.assertEqual(manifest["stages"]["audit"]["status"], "succeeded")
        self.assertEqual(manifest["stages"]["poc"]["status"], "succeeded")

        invocations_path = self.agentflow_root / "invocations.jsonl"
        invocations = [json.loads(line) for line in invocations_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(invocations), 1)
        self.assertEqual(invocations[0]["node_ids"], ["audit", "poc"])
        self.assertEqual(invocations[0]["cwd"], project_work_dir)
        self.assertEqual(invocations[0]["working_dir"], project_work_dir)
        self.assertEqual(invocations[0]["node_cwds"], [project_work_dir, project_work_dir])

    def test_agentflow_root_resolves_nested_directory_for_k8s_style_mount(self) -> None:
        from app.core.config import load_config, resolve_agentflow_root
        from app.workers.runner import StageContext, build_agentflow_process_env_and_summary

        nested_parent = self.state_root / "agentflow-volume"
        nested_root = nested_parent / "agentflow-alpha"
        (nested_root / "agentflow").mkdir(parents=True, exist_ok=True)
        (nested_root / "agentflow" / "__init__.py").write_text("", encoding="utf-8")
        (nested_root / "agentflow" / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")

        self._set_env("IPC_AUDIT_AGENTFLOW_ROOT", str(nested_parent))
        self._reset_singletons()
        load_config()

        resolved_root = resolve_agentflow_root()
        self.assertEqual(resolved_root, nested_root.resolve())

        attempt_root = self.state_root / "attempt-nested-root"
        context = StageContext(
            task_id="task-nested-root",
            attempt_id="attempt-nested-root",
            workspace_id="oh61-main",
            stage_name="audit",
            input_kind="custom_project",
            pipeline_mode="custom_graph",
            project_path="foundation/demo/service",
            report_path=None,
            repo_root=self.repo_root,
            attempt_root=attempt_root,
            runtime_root=attempt_root / "runtime",
            logs_dir=attempt_root / "logs",
            artifacts_dir=attempt_root / "artifacts",
            scratch_dir=attempt_root / "scratch",
            effective_config={"executor_mode": "agentflow_cli"},
            provider_runtime=None,
        )
        process_env, summary, metadata = build_agentflow_process_env_and_summary(context)
        self.assertTrue(process_env["PYTHONPATH"].startswith(str(nested_root.resolve())))
        self.assertEqual(metadata["agentflow_root"], str(nested_root.resolve()))
        self.assertIn(str(nested_root.resolve()), summary)

    def test_custom_graph_progress_snapshot_reflects_completed_and_running_nodes(self) -> None:
        from app.workers.stage_graph import _build_graph_progress_snapshot

        attempt_root = self.state_root / "attempt-progress"
        attempt_root.mkdir(parents=True, exist_ok=True)
        audit_report = attempt_root / "exports" / "audit-report.md"
        write_text_file(audit_report, "# audit\n")

        runs_dir = attempt_root / "runtime" / "graph" / "agentflow-runs"
        run_dir = runs_dir / "run_live"
        (run_dir / "artifacts" / "audit").mkdir(parents=True, exist_ok=True)
        (run_dir / "artifacts" / "poc").mkdir(parents=True, exist_ok=True)
        write_json_file(
            run_dir / "artifacts" / "audit" / "result.json",
            {"status": "completed", "exit_code": 0},
        )
        write_json_file(
            run_dir / "artifacts" / "poc" / "launch.json",
            {"command": ["fake-agentflow"]},
        )

        snapshot = _build_graph_progress_snapshot(
            context=None,
            stage_names=["audit", "poc"],
            pipeline_payload={
                "name": "custom-graph",
                "nodes": [
                    {"id": "audit"},
                    {"id": "poc", "depends_on": ["audit"]},
                ],
            },
            report_outputs=[
                {
                    "output_id": "audit_report",
                    "node_id": "audit",
                    "title": "Audit Report",
                    "path": "exports/audit-report.md",
                    "absolute_path": audit_report,
                    "format": "markdown",
                    "required": True,
                    "order": 10,
                },
                {
                    "output_id": "poc_report",
                    "node_id": "poc",
                    "title": "PoC Report",
                    "path": "exports/poc-report.md",
                    "absolute_path": attempt_root / "exports" / "poc-report.md",
                    "format": "markdown",
                    "required": True,
                    "order": 20,
                },
            ],
            runs_dir=runs_dir,
        )
        self.assertEqual(snapshot["current_stage"], "poc")
        self.assertEqual(snapshot["nodes"]["audit"]["status"], "succeeded")
        self.assertEqual(snapshot["nodes"]["poc"]["status"], "running")

    def test_agentflow_cli_combined_pipeline_can_return_partial_success(self) -> None:
        self._set_env("FAKE_AGENTFLOW_FAIL_NODE", "poc")
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_then_poc",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        self.assertEqual(detail.status, "partial_success")
        self.assertEqual(attempt.status, "partial_success")

        stage_runs = {item.stage_name: item for item in attempt.stage_runs}
        self.assertEqual(stage_runs["audit"].status, "succeeded")
        self.assertEqual(stage_runs["poc"].status, "failed")

        artifacts = get_task_service().list_artifacts(task.task_id, str(detail.latest_attempt_id))
        artifact_kinds = [item.artifact_kind for item in artifacts.items]
        self.assertIn("audit_report", artifact_kinds)
        self.assertNotIn("poc_report", artifact_kinds)
        self.assertNotIn("audited_result_json", artifact_kinds)

        attempt_root = self._attempt_root(task.task_id, str(detail.latest_attempt_id))
        manifest = json.loads((attempt_root / "runtime" / "agentflow-stage-pipeline-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["stages"]["audit"]["status"], "succeeded")
        self.assertEqual(manifest["stages"]["poc"]["status"], "failed")

        invocations_path = self.agentflow_root / "invocations.jsonl"
        invocations = [json.loads(line) for line in invocations_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(invocations), 1)
        self.assertEqual(invocations[0]["node_ids"], ["audit", "poc"])

    def test_custom_graph_inline_json_publishes_dynamic_report_outputs(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="dynamic-graph-inline",
                workspace_id="oh61-main",
                pipeline_mode="custom_graph",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
                graph_source={
                    "type": "inline_json",
                    "content": {
                        "name": "dynamic-inline-graph",
                        "nodes": [
                            {
                                "id": "stage1",
                                "prompt": "write report to [[ task.report_outputs.stage1_report.absolute_path ]]",
                                "success_criteria": [
                                    {"kind": "file_nonempty", "path": "[[ task.report_outputs.stage1_report.absolute_path ]]"}
                                ],
                            },
                            {
                                "id": "stage2",
                                "depends_on": ["stage1"],
                                "prompt": "write report to [[ task.report_outputs.stage2_report.absolute_path ]]",
                                "success_criteria": [
                                    {"kind": "file_nonempty", "path": "[[ task.report_outputs.stage2_report.absolute_path ]]"}
                                ],
                            },
                        ],
                    },
                },
                report_outputs=[
                    {
                        "output_id": "stage1_report",
                        "node_id": "stage1",
                        "title": "Stage 1 Report",
                        "path": "exports/stage1-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 10,
                    },
                    {
                        "output_id": "stage2_report",
                        "node_id": "stage2",
                        "title": "Stage 2 Report",
                        "path": "exports/stage2-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 20,
                    },
                ],
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        self.assertEqual(detail.status, "succeeded")
        self.assertEqual(attempt.status, "succeeded")
        self.assertEqual([item.stage_name for item in attempt.stage_runs], ["stage1", "stage2"])
        self.assertEqual([item.output_id for item in attempt.report_outputs], ["stage1_report", "stage2_report"])
        self.assertTrue(all(item.exists for item in attempt.report_outputs))
        self.assertEqual([item.path for item in attempt.report_outputs], ["exports/stage1-report.md", "exports/stage2-report.md"])
        self.assertEqual(attempt.effective_config["materialized_graph_source"]["type"], "inline_json")
        project_work_dir = str(self.repo_root / "foundation" / "demo" / "service")
        self.assertEqual(attempt.effective_config["materialized_graph_source"]["content"]["working_dir"], project_work_dir)
        self.assertEqual(
            [item["id"] for item in attempt.effective_config["materialized_graph_source"]["content"]["nodes"]],
            ["stage1", "stage2"],
        )
        self.assertEqual(
            [item["target"]["cwd"] for item in attempt.effective_config["materialized_graph_source"]["content"]["nodes"]],
            [project_work_dir, project_work_dir],
        )
        self.assertEqual(
            attempt.effective_config["materialized_graph_source"]["content"]["nodes"][1]["depends_on"],
            ["stage1"],
        )
        self.assertEqual(
            [item["timeout_seconds"] for item in attempt.effective_config["materialized_graph_source"]["content"]["nodes"]],
            [load_config().execution.task_timeout_seconds, load_config().execution.task_timeout_seconds],
        )

        stage1_content = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "stage1",
            "runtime/stage1/prompt.txt",
        )["content"]
        self.assertIn("exports/stage1-report.md", stage1_content)

        artifacts = get_task_service().list_artifacts(task.task_id, str(detail.latest_attempt_id))
        report_artifacts = [item for item in artifacts.items if item.artifact_kind == "report_output"]
        self.assertEqual([item.relative_path for item in report_artifacts], ["exports/stage1-report.md", "exports/stage2-report.md"])

        graph_manifest = next(item for item in artifacts.items if item.artifact_kind == "graph_manifest")
        manifest_content = get_artifact_service().get_artifact_content(graph_manifest.artifact_id, max_bytes=1024 * 1024).content
        manifest_payload = json.loads(manifest_content)
        self.assertIn("stage1_report", manifest_content)
        self.assertIn("stage2_report", manifest_content)
        self.assertEqual(manifest_payload["pipeline"]["working_dir"], project_work_dir)
        self.assertEqual([item["id"] for item in manifest_payload["pipeline"]["nodes"]], ["stage1", "stage2"])
        self.assertEqual(manifest_payload["pipeline"]["nodes"][1]["depends_on"], ["stage1"])

        invocations_path = self.agentflow_root / "invocations.jsonl"
        invocations = [json.loads(line) for line in invocations_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(invocations[-1]["cwd"], project_work_dir)
        self.assertEqual(invocations[-1]["working_dir"], project_work_dir)
        self.assertEqual(invocations[-1]["node_cwds"], [project_work_dir, project_work_dir])

    def test_custom_graph_reconciles_extra_success_criteria_outputs_into_artifacts_and_attempt_outputs(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="dynamic-graph-extra-json-output",
                workspace_id="oh61-main",
                pipeline_mode="custom_graph",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
                graph_source={
                    "type": "inline_json",
                    "content": {
                        "name": "dynamic-inline-graph",
                        "nodes": [
                            {
                                "id": "audit",
                                "prompt": "write report to [[ task.report_outputs.audit_report.absolute_path ]]",
                                "success_criteria": [
                                    {"kind": "file_nonempty", "path": "[[ task.report_outputs.audit_report.absolute_path ]]"}
                                ],
                            },
                            {
                                "id": "poc",
                                "depends_on": ["audit"],
                                "prompt": "write report to [[ task.report_outputs.poc_report.absolute_path ]] and json to [[ task.attempt_root ]]/exports/audited-result.json",
                                "success_criteria": [
                                    {"kind": "file_nonempty", "path": "[[ task.report_outputs.poc_report.absolute_path ]]"},
                                    {"kind": "json_valid", "path": "[[ task.attempt_root ]]/exports/audited-result.json"},
                                ],
                            },
                        ],
                    },
                },
                report_outputs=[
                    {
                        "output_id": "audit_report",
                        "node_id": "audit",
                        "title": "Audit Report",
                        "path": "exports/audit-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 10,
                    },
                    {
                        "output_id": "poc_report",
                        "node_id": "poc",
                        "title": "PoC Report",
                        "path": "exports/poc-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 20,
                    },
                ],
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        output_paths = [item.path for item in attempt.report_outputs]
        self.assertEqual(
            output_paths,
            [
                "exports/audit-report.md",
                "exports/poc-report.md",
                "exports/audited-result.json",
            ],
        )
        audited_result_output = next(item for item in attempt.report_outputs if item.path == "exports/audited-result.json")
        self.assertEqual(audited_result_output.node_id, "poc")
        self.assertEqual(audited_result_output.format, "json")
        self.assertTrue(audited_result_output.exists)
        self.assertEqual(audited_result_output.output_id, "audited_result")

        artifacts = get_task_service().list_artifacts(task.task_id, str(detail.latest_attempt_id))
        artifact_by_path = {item.relative_path: item for item in artifacts.items}
        self.assertIn("exports/audited-result.json", artifact_by_path)
        self.assertEqual(artifact_by_path["exports/audited-result.json"].artifact_kind, "audited_result_json")

    def test_custom_graph_stage_sessions_fallback_to_agentflow_trace_while_runtime_files_missing(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="dynamic-graph-session-fallback",
                workspace_id="oh61-main",
                pipeline_mode="custom_graph",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
                graph_source={
                    "type": "inline_json",
                    "content": {
                        "name": "dynamic-inline-graph",
                        "nodes": [
                            {
                                "id": "stage1",
                                "prompt": "inspect and write later",
                            }
                        ],
                    },
                },
            ),
            self.subject,
        )
        detail = get_task_service().get_task(task.task_id)
        attempt_id = str(detail.latest_attempt_id)
        attempt_root = self._attempt_root(task.task_id, attempt_id)
        artifact_dir = attempt_root / "runtime" / "graph" / "agentflow-runs" / "run_fake" / "artifacts" / "stage1"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        trace_events = [
            {
                "timestamp": "2026-05-14T00:00:00Z",
                "node_id": "stage1",
                "agent": "opencode",
                "attempt": 1,
                "source": "stdout",
                "kind": "assistant_message",
                "title": "Assistant message",
                "content": "# Runtime Trace\n\nhello",
                "raw": {"type": "text", "text": "# Runtime Trace\n\nhello"},
            }
        ]
        (artifact_dir / "trace.jsonl").write_text(
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in trace_events),
            encoding="utf-8",
        )
        (artifact_dir / "result.json").write_text(
            json.dumps(
                {
                    "node_id": "stage1",
                    "status": "completed",
                    "exit_code": 0,
                    "final_response": "# Runtime Trace\n\nhello",
                    "output": "# Runtime Trace\n\nhello",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        stage_sessions = get_task_service().list_stage_sessions(task.task_id, attempt_id, "stage1")
        session_paths = [item["path"] for item in stage_sessions]
        self.assertIn("runtime/stage1/events.jsonl", session_paths)
        self.assertIn("runtime/stage1/last-message.md", session_paths)
        runtime_events_path = attempt_root / "runtime" / "stage1" / "events.jsonl"
        runtime_events_before = runtime_events_path.read_text(encoding="utf-8") if runtime_events_path.exists() else None

        events_file = get_task_service().get_stage_session_file(
            task.task_id,
            attempt_id,
            "stage1",
            "runtime/stage1/events.jsonl",
        )
        if runtime_events_before is None:
            self.assertFalse(runtime_events_path.exists())
        else:
            self.assertEqual(runtime_events_path.read_text(encoding="utf-8"), runtime_events_before)
        self.assertIn('"type": "assistant_message"', events_file["content"])
        self.assertIn("# Runtime Trace", events_file["content"])
        self.assertGreater(events_file["next_cursor"], 0)

        last_message_file = get_task_service().get_stage_session_file(
            task.task_id,
            attempt_id,
            "stage1",
            "runtime/stage1/last-message.md",
        )
        self.assertIn("# Runtime Trace", last_message_file["content"])

    def test_custom_graph_inline_json_supports_bracketed_report_output_access(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="dynamic-graph-inline-brackets",
                workspace_id="oh61-main",
                pipeline_mode="custom_graph",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
                graph_source={
                    "type": "inline_json",
                    "content": {
                        "name": "dynamic-inline-graph-brackets",
                        "nodes": [
                            {
                                "id": "audit",
                                "prompt": "write report to [[ task.report_outputs[\"audit_report\"].absolute_path ]]",
                                "success_criteria": [
                                    {"kind": "file_nonempty", "path": "[[ task.report_outputs[\"audit_report\"].absolute_path ]]"}
                                ],
                            },
                            {
                                "id": "poc",
                                "depends_on": ["audit"],
                                "prompt": "write report to [[ task.report_outputs[\"poc_report\"].absolute_path ]]",
                                "success_criteria": [
                                    {"kind": "file_nonempty", "path": "[[ task.report_outputs[\"poc_report\"].absolute_path ]]"}
                                ],
                            },
                        ],
                    },
                },
                report_outputs=[
                    {
                        "output_id": "audit_report",
                        "node_id": "audit",
                        "title": "Audit Report",
                        "path": "exports/audit-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 10,
                    },
                    {
                        "output_id": "poc_report",
                        "node_id": "poc",
                        "title": "PoC Report",
                        "path": "exports/poc-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 20,
                    },
                ],
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        self.assertEqual(detail.status, "succeeded")
        self.assertEqual(attempt.status, "succeeded")

        audit_prompt = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "audit",
            "runtime/audit/prompt.txt",
        )["content"]
        poc_prompt = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "poc",
            "runtime/poc/prompt.txt",
        )["content"]
        self.assertIn("exports/audit-report.md", audit_prompt)
        self.assertIn("exports/poc-report.md", poc_prompt)

        pipeline_payload = json.loads(
            (self._attempt_root(task.task_id, str(detail.latest_attempt_id)) / "runtime" / "graph" / "agentflow-pipeline.json").read_text(encoding="utf-8")
        )
        self.assertEqual([node["agent"] for node in pipeline_payload["nodes"]], ["opencode", "opencode"])

    def test_custom_graph_python_builder_publishes_dynamic_report_outputs(self) -> None:
        builder_path = self.repo_root / "build_graph.py"
        builder_path.write_text(
            "\n".join(
                [
                    "from __future__ import annotations",
                    "",
                    "import argparse",
                    "import json",
                    "from pathlib import Path",
                    "",
                    "",
                    "def main() -> None:",
                    "    parser = argparse.ArgumentParser()",
                    "    parser.add_argument('--context', required=True)",
                    "    parser.add_argument('--output', required=True)",
                    "    args = parser.parse_args()",
                    "    context = json.loads(Path(args.context).read_text(encoding='utf-8'))",
                    "    payload = {",
                    "        'name': 'dynamic-builder-graph',",
                    "        'nodes': [",
                    "            {",
                    "                'id': 'builder1',",
                    "                'prompt': f\"write report to {context['report_outputs']['builder1_report']['absolute_path']}\",",
                    "                'success_criteria': [{'kind': 'file_nonempty', 'path': context['report_outputs']['builder1_report']['absolute_path']}],",
                    "            },",
                    "            {",
                    "                'id': 'builder2',",
                    "                'depends_on': ['builder1'],",
                    "                'prompt': f\"write report to {context['report_outputs']['builder2_report']['absolute_path']}\",",
                    "                'success_criteria': [{'kind': 'file_nonempty', 'path': context['report_outputs']['builder2_report']['absolute_path']}],",
                    "            },",
                    "        ],",
                    "    }",
                    "    Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                    "",
                    "",
                    "if __name__ == '__main__':",
                    "    main()",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="dynamic-graph-builder",
                workspace_id="oh61-main",
                pipeline_mode="custom_graph",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
                graph_source={
                    "type": "python_builder",
                    "entry": "build_graph.py",
                    "declared_nodes": ["builder1", "builder2"],
                },
                report_outputs=[
                    {
                        "output_id": "builder1_report",
                        "node_id": "builder1",
                        "title": "Builder 1 Report",
                        "path": "exports/builder1-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 10,
                    },
                    {
                        "output_id": "builder2_report",
                        "node_id": "builder2",
                        "title": "Builder 2 Report",
                        "path": "exports/builder2-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 20,
                    },
                ],
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        self.assertEqual(detail.status, "succeeded")
        self.assertEqual([item.stage_name for item in attempt.stage_runs], ["builder1", "builder2"])
        self.assertEqual([item.output_id for item in attempt.report_outputs], ["builder1_report", "builder2_report"])
        self.assertTrue(all(item.exists for item in attempt.report_outputs))
        self.assertEqual(attempt.effective_config["materialized_graph_source"]["type"], "inline_json")
        self.assertEqual(
            [item["id"] for item in attempt.effective_config["materialized_graph_source"]["content"]["nodes"]],
            ["builder1", "builder2"],
        )
        self.assertEqual(
            attempt.effective_config["materialized_graph_source"]["content"]["nodes"][1]["depends_on"],
            ["builder1"],
        )

        invocations_path = self.agentflow_root / "invocations.jsonl"
        invocations = [json.loads(line) for line in invocations_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(invocations[-1]["node_ids"], ["builder1", "builder2"])

    def test_custom_graph_python_builder_renders_secflow_placeholders_before_agentflow(self) -> None:
        builder_path = self.repo_root / "build_graph_with_secflow_placeholders.py"
        builder_path.write_text(
            "\n".join(
                [
                    "from __future__ import annotations",
                    "",
                    "import argparse",
                    "import json",
                    "from pathlib import Path",
                    "",
                    "",
                    "def main() -> None:",
                    "    parser = argparse.ArgumentParser()",
                    "    parser.add_argument('--context', required=True)",
                    "    parser.add_argument('--output', required=True)",
                    "    args = parser.parse_args()",
                    "    payload = {",
                    "        'name': 'dynamic-builder-secflow-graph',",
                    "        'nodes': [",
                    "            {",
                    "                'id': 'builder1',",
                    "                'prompt': 'write report to [[ task.report_outputs[\"builder1_report\"].absolute_path ]]',",
                    "                'success_criteria': [{'kind': 'file_nonempty', 'path': '[[ task.report_outputs[\"builder1_report\"].absolute_path ]]'}],",
                    "            },",
                    "            {",
                    "                'id': 'builder2',",
                    "                'depends_on': ['builder1'],",
                    "                'prompt': 'write report to [[ task.report_outputs[\"builder2_report\"].absolute_path ]]',",
                    "                'success_criteria': [{'kind': 'file_nonempty', 'path': '[[ task.report_outputs[\"builder2_report\"].absolute_path ]]'}],",
                    "            },",
                    "        ],",
                    "    }",
                    "    Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                    "",
                    "",
                    "if __name__ == '__main__':",
                    "    main()",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="dynamic-graph-builder-secflow-placeholders",
                workspace_id="oh61-main",
                pipeline_mode="custom_graph",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
                graph_source={
                    "type": "python_builder",
                    "entry": "build_graph_with_secflow_placeholders.py",
                    "declared_nodes": ["builder1", "builder2"],
                },
                report_outputs=[
                    {
                        "output_id": "builder1_report",
                        "node_id": "builder1",
                        "title": "Builder 1 Report",
                        "path": "exports/builder1-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 10,
                    },
                    {
                        "output_id": "builder2_report",
                        "node_id": "builder2",
                        "title": "Builder 2 Report",
                        "path": "exports/builder2-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 20,
                    },
                ],
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt_id = str(detail.latest_attempt_id)
        attempt_root = self._attempt_root(task.task_id, attempt_id)
        project_work_dir = str(self.repo_root / "foundation" / "demo" / "service")
        graph_context = json.loads((attempt_root / "runtime" / "graph" / "graph-context.json").read_text(encoding="utf-8"))
        self.assertEqual(graph_context["task"]["project_path"], project_work_dir)
        self.assertEqual(graph_context["task"]["project_absolute_path"], project_work_dir)
        self.assertEqual(graph_context["task"]["project_relative_path"], "foundation/demo/service")
        self.assertEqual(graph_context["task"]["work_dir"], project_work_dir)
        pipeline_payload = json.loads((attempt_root / "runtime" / "graph" / "agentflow-pipeline.json").read_text(encoding="utf-8"))
        self.assertEqual(pipeline_payload["working_dir"], project_work_dir)
        self.assertEqual([node["target"]["cwd"] for node in pipeline_payload["nodes"]], [project_work_dir, project_work_dir])
        self.assertEqual(
            pipeline_payload["nodes"][0]["success_criteria"][0]["path"],
            str(attempt_root / "exports" / "builder1-report.md"),
        )
        self.assertEqual(
            pipeline_payload["nodes"][1]["success_criteria"][0]["path"],
            str(attempt_root / "exports" / "builder2-report.md"),
        )
        self.assertEqual(pipeline_payload["nodes"][1]["depends_on"], ["builder1"])

    def test_custom_graph_renders_poc_runtime_placeholders_from_env(self) -> None:
        self._set_env("HDC_BIN", "/workspace/files/vendor/edu/docker/src/hdc")
        self._set_env("OHEMU_HELPER_BIN", "/usr/local/bin/ipc-audit-qemu")
        self._set_env("OHEMU_WORKSPACE_ROOT", "/workspace/files")
        self._set_env("OHEMU_QCOW2_PREPARED_ROOT", "/workspace/files/vendor/edu/docker/volumes/qcow2_cache")
        self._set_env("OHEMU_RUNTIME_ROOT", "/var/lib/secflow-ipc-audit/ohemu")
        self._set_env("OHEMU_ARCH", "arm64")
        self._set_env("OHEMU_NETWORK_MODE", "bridge")
        self._set_env("OHEMU_HDC_BIND", "127.0.0.1")
        self._set_env("OHEMU_HDC_BASE_PORT", "55555")
        self._set_env("OHEMU_BOOT_DIR", "/workspace/files/vendor/edu/docker/volumes/qcow2_cache/arm64/boot")
        self._set_env("OHEMU_SRC_DIR", "/workspace/files/vendor/edu/docker/src")

        task = get_task_service().create_task(
            TaskCreateRequest(
                title="poc-runtime-placeholders",
                workspace_id="oh61-main",
                pipeline_mode="custom_graph",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="agentflow_cli",
                model="gpt-5-codex",
                graph_source={
                    "type": "inline_json",
                    "content": {
                        "name": "poc-runtime-graph",
                        "nodes": [
                            {
                                "id": "poc",
                                "prompt": (
                                    "helper [[ task.poc_runtime.helper_bin ]] "
                                    "hdc [[ task.poc_runtime.hdc_bin ]] "
                                    "root [[ task.poc_runtime.workspace_root ]] "
                                    "instance [[ task.poc_runtime.instance_name ]]"
                                ),
                                "success_criteria": [
                                    {
                                        "kind": "file_nonempty",
                                        "path": '[[ task.report_outputs["poc_report"].absolute_path ]]',
                                    }
                                ],
                            }
                        ],
                    },
                },
                report_outputs=[
                    {
                        "output_id": "poc_report",
                        "node_id": "poc",
                        "title": "PoC Report",
                        "path": "exports/poc-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 10,
                    }
                ],
            ),
            self.subject,
        )

        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        pipeline_payload = attempt.effective_config["materialized_graph_source"]["content"]
        prompt = pipeline_payload["nodes"][0]["prompt"]
        self.assertIn("/usr/local/bin/ipc-audit-qemu", prompt)
        self.assertIn("/workspace/files/vendor/edu/docker/src/hdc", prompt)
        self.assertIn("/workspace/files", prompt)
        self.assertIn("instance ipc-audit-", prompt)

    def test_validate_graph_rejects_unrendered_secflow_placeholders(self) -> None:
        with self.assertRaises(HTTPException) as context:
            get_task_service().validate_graph(
                GraphValidateRequest(
                    workspace_id="oh61-main",
                    executor_mode="agentflow_cli",
                    graph_source={
                        "type": "inline_json",
                        "content": {
                            "name": "invalid-inline-graph",
                            "nodes": [
                                {
                                    "id": "audit",
                                    "prompt": "write report to [[ task.missing_path ]]",
                                }
                            ],
                        },
                    },
                )
            )
        self.assertEqual(context.exception.status_code, 422)
        self.assertIn("invalid inline_json graph source", str(context.exception.detail))

    def _write_fake_agentflow(self) -> None:
        package_dir = self.agentflow_root / "agentflow"
        package_dir.mkdir(parents=True)
        (package_dir / "__init__.py").write_text("", encoding="utf-8")
        (package_dir / "cli.py").write_text(
            "\n".join(
                [
                    "from __future__ import annotations",
                    "",
                    "import json",
                    "import os",
                    "import sys",
                    "from pathlib import Path",
                    "",
                    "",
                    "def _option_value(name: str) -> str | None:",
                    "    if name not in sys.argv:",
                    "        return None",
                    "    index = sys.argv.index(name)",
                    "    if index + 1 >= len(sys.argv):",
                    "        return None",
                    "    return sys.argv[index + 1]",
                    "",
                    "",
                    "def main() -> None:",
                    "    if len(sys.argv) < 3 or sys.argv[1] != 'run':",
                    "        raise SystemExit(2)",
                    "    pipeline_path = Path(sys.argv[2])",
                    "    runs_dir_value = _option_value('--runs-dir') or os.environ.get('AGENTFLOW_RUNS_DIR')",
                    "    if not runs_dir_value:",
                    "        raise SystemExit('missing runs dir')",
                    "    runs_dir = Path(runs_dir_value)",
                    "    capture_root = Path(__file__).resolve().parent.parent",
                    "    payload = json.loads(pipeline_path.read_text(encoding='utf-8'))",
                    "    nodes = payload['nodes']",
                    "    fail_node = os.environ.get('FAKE_AGENTFLOW_FAIL_NODE', '').strip()",
                    "    invocation = {",
                    "        'pipeline_path': str(pipeline_path),",
                    "        'cwd': os.getcwd(),",
                    "        'working_dir': payload.get('working_dir'),",
                    "        'node_ids': [node.get('id') for node in nodes],",
                    "        'node_cwds': [(node.get('target') or {}).get('cwd') for node in nodes],",
                    "    }",
                    "    with (capture_root / 'invocations.jsonl').open('a', encoding='utf-8') as handle:",
                    "        handle.write(json.dumps(invocation, ensure_ascii=False) + '\\n')",
                    "    (capture_root / 'last_pipeline.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                    "    run_dir = runs_dir / 'run_fake'",
                    "    node_statuses = {}",
                    "    node_summaries = []",
                    "    overall_status = 'completed'",
                    "    overall_exit_code = 0",
                    "    for node in nodes:",
                    "        node_id = node['id']",
                    "        artifact_dir = run_dir / 'artifacts' / node_id",
                    "        artifact_dir.mkdir(parents=True, exist_ok=True)",
                    "        dependencies = node.get('depends_on', []) or []",
                    "        blocked = any(node_statuses.get(dep) != 'completed' for dep in dependencies)",
                    "        if blocked:",
                    "            status = 'skipped'",
                    "            exit_code = 1",
                    "            message = '# Fake AgentFlow Message\\n\\nskipped'",
                    "        elif fail_node and node_id == fail_node:",
                    "            status = 'failed'",
                    "            exit_code = 1",
                    "            message = '# Fake AgentFlow Message\\n\\nfailed'",
                    "        else:",
                    "            status = 'completed'",
                    "            exit_code = 0",
                    "            message = '# Fake AgentFlow Message\\n\\ncompleted'",
                    "            for criterion in node.get('success_criteria', []):",
                    "                path = Path(criterion.get('path', ''))",
                    "                if not path:",
                    "                    continue",
                    "                path.parent.mkdir(parents=True, exist_ok=True)",
                    "                if path.suffix == '.json':",
                    "                    path.write_text(json.dumps({'status': 'ok', 'count': 1}, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                    "                else:",
                    "                    path.write_text(f'# Fake AgentFlow Output {node_id}\\n\\ncompleted\\n', encoding='utf-8')",
                    "        trace_events = [",
                    "            {'timestamp': '2026-05-14T00:00:00Z', 'node_id': node_id, 'agent': node.get('agent', 'codex'), 'attempt': 1, 'source': 'stdout', 'kind': 'assistant_message', 'title': 'Assistant message', 'content': message},",
                    "            {'timestamp': '2026-05-14T00:00:01Z', 'node_id': node_id, 'agent': node.get('agent', 'codex'), 'attempt': 1, 'source': 'stdout', 'kind': status, 'title': status.title(), 'content': message},",
                    "        ]",
                    "        (artifact_dir / 'trace.jsonl').write_text(''.join(json.dumps(item, ensure_ascii=False) + '\\n' for item in trace_events), encoding='utf-8')",
                    "        (artifact_dir / 'stdout.log').write_text(f'agentflow node stdout {node_id}\\n', encoding='utf-8')",
                    "        (artifact_dir / 'stderr.log').write_text('', encoding='utf-8')",
                    "        (artifact_dir / 'launch.json').write_text(json.dumps({'command': ['fake-agentflow'], 'node_id': node_id}, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                    "        (artifact_dir / 'result.json').write_text(json.dumps({'node_id': node_id, 'status': status, 'exit_code': exit_code, 'final_response': message, 'output': message}, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')",
                    "        node_statuses[node_id] = status",
                    "        node_summaries.append({'id': node_id, 'status': status, 'attempts': 1, 'preview': status})",
                    "        if status != 'completed':",
                    "            overall_status = 'failed'",
                    "            overall_exit_code = 1",
                    "    print(json.dumps({'id': 'run_fake', 'status': overall_status, 'run_dir': str(run_dir), 'nodes': node_summaries}, ensure_ascii=False))",
                    "    raise SystemExit(overall_exit_code)",
                    "",
                    "",
                    "if __name__ == '__main__':",
                    "    main()",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _set_env(key: str, value: str) -> None:
        os.environ[key] = value

    def _attempt_root(self, task_id: str, attempt_id: str) -> Path:
        return self.state_root / "tasks" / task_id / "attempts" / attempt_id

    @staticmethod
    def _reset_singletons() -> None:
        import app.core.config as config_module
        import app.db.database as database_module
        import app.services.artifact_service as artifact_module
        import app.services.catalog_service as catalog_module
        import app.services.event_service as event_module
        import app.services.execution_service as execution_module
        import app.services.provider_client as provider_client_module
        import app.services.provider_runtime as provider_runtime_module
        import app.workers.scheduler as scheduler_module
        import app.services.task_service as task_module
        import app.services.workspace_service as workspace_module

        config_module._config = None
        database_module._database = None
        artifact_module._artifact_service = None
        catalog_module._catalog_service = None
        event_module._event_service = None
        execution_module._execution_service = None
        provider_client_module._provider_client = None
        provider_runtime_module._provider_runtime_service = None
        scheduler_module._scheduler_service = None
        task_module._task_service = None
        workspace_module._workspace_service = None


if __name__ == "__main__":
    unittest.main()
