from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from app.core.auth import Subject
from app.core.config import load_config
from app.db.database import init_database
from app.schemas import InputRef, TaskCreateRequest
from app.services.execution_service import get_execution_service
from app.services.task_service import get_task_service


class CodexCliModeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-repo-")
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-state-")
        self.tools_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-tools-")
        self.repo_root = Path(self.repo_dir.name)
        self.state_root = Path(self.state_dir.name)
        self.fake_codex = Path(self.tools_dir.name) / "fake-codex"

        project_dir = self.repo_root / "foundation" / "demo" / "service"
        project_dir.mkdir(parents=True)
        (project_dir / "bundle.json").write_text("{}\n", encoding="utf-8")
        (project_dir / "iface.idl").write_text("interface Demo {}\n", encoding="utf-8")
        self._write_fake_codex()

        self._reset_singletons()
        self._set_env("IPC_AUDIT_DATABASE_URL", f"sqlite:///{self.state_root / 'ipc-audit.db'}")
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_EXECUTION_MODE", "mock")
        self._set_env("IPC_AUDIT_CODEX_BIN", str(self.fake_codex))
        self._set_env("IPC_AUDIT_CODEX_JSON_OUTPUT", "true")
        self._set_env("IPC_AUDIT_CODEX_CAPTURE_LAST_MESSAGE", "true")
        self._set_env("IPC_AUDIT_POC_ENABLED", "true")
        self._set_env("IPC_AUDIT_POC_RUNTIME_AVAILABLE", "true")
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
            "IPC_AUDIT_CODEX_BIN",
            "IPC_AUDIT_CODEX_JSON_OUTPUT",
            "IPC_AUDIT_CODEX_CAPTURE_LAST_MESSAGE",
            "IPC_AUDIT_POC_ENABLED",
            "IPC_AUDIT_POC_RUNTIME_AVAILABLE",
            "IPC_AUDIT_WORKSPACES_JSON",
        ):
            os.environ.pop(key, None)
        self._reset_singletons()
        self.repo_dir.cleanup()
        self.state_dir.cleanup()
        self.tools_dir.cleanup()

    def test_codex_cli_writes_outputs_under_attempt_root_and_collects_sessions(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_then_poc",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="codex_cli",
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
        self.assertEqual(attempt.effective_config["executor_mode"], "codex_cli")
        self.assertEqual(attempt.effective_config["execution_mode"], "codex_cli")
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
        self.assertIn("This prompt is self-contained", audit_prompt)
        self.assertIn("This prompt is self-contained", poc_prompt)
        self.assertFalse(any(line.startswith("$") for line in audit_prompt.splitlines()))
        self.assertFalse(any(line.startswith("$") for line in poc_prompt.splitlines()))

        audit_events = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "audit",
            "runtime/audit/events.jsonl",
        )
        self.assertIn('"stage": "audit"', audit_events["content"])

        event_page = get_task_service().list_events(task.task_id, attempt_id=str(detail.latest_attempt_id), cursor=None, limit=200)
        event_types = [item.event_type for item in event_page.items]
        self.assertIn("stage.stdout.appended", event_types)
        self.assertIn("stage.agent.message", event_types)
        stdout_event = next(item for item in event_page.items if item.event_type == "stage.stdout.appended" and item.stage_name == "audit")
        self.assertEqual(stdout_event.payload["session_file_path"], "runtime/audit/events.jsonl")
        self.assertEqual(stdout_event.payload["event_types"]["message"], 1)
        agent_event = next(item for item in event_page.items if item.event_type == "stage.agent.message" and item.stage_name == "poc")
        self.assertEqual(agent_event.payload["session_file_path"], "runtime/poc/last-message.md")
        self.assertIn("# Fake PoC Message", agent_event.payload["preview"])

        audit_log = get_task_service().get_stage_log(task.task_id, str(detail.latest_attempt_id), "audit", lines=240, cursor=None)
        self.assertIn("-m gpt-5-codex", audit_log.content)

        attempt_root = self.state_root / "tasks" / task.task_id / "attempts" / str(detail.latest_attempt_id)
        self.assertTrue((attempt_root / "runtime" / "audit" / "outputs").exists())
        self.assertTrue((attempt_root / "runtime" / "poc" / "outputs").exists())
        self.assertFalse((self.repo_root / ".audit" / "secflow-app-ipc-audit").exists())

    def _write_fake_codex(self) -> None:
        script = "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json",
                "import sys",
                "from pathlib import Path",
                "",
                "args = sys.argv[1:]",
                "json_output = '--json' in args",
                "last_message_path = None",
                "for index, value in enumerate(args):",
                "    if value == '-o' and index + 1 < len(args):",
                "        last_message_path = Path(args[index + 1])",
                "prompt = args[-1]",
                "",
                "def extract(prefix: str) -> Path:",
                "    for line in prompt.splitlines():",
                "        if line.startswith(prefix):",
                "            return Path(line.split(': ', 1)[1].strip())",
                "    raise SystemExit(f'missing prompt field: {prefix}')",
                "",
                "if 'Output audited result json path:' in prompt:",
                "    report_path = extract('Output PoC report path:')",
                "    json_path = extract('Output audited result json path:')",
                "    report_path.parent.mkdir(parents=True, exist_ok=True)",
                "    json_path.parent.mkdir(parents=True, exist_ok=True)",
                "    report_path.write_text('# Fake PoC Report\\n', encoding='utf-8')",
                "    json_path.write_text(json.dumps({'ok': True}, ensure_ascii=False) + '\\n', encoding='utf-8')",
                "    final_message = '# Fake PoC Message\\n'",
                "    stage = 'poc'",
                "else:",
                "    report_path = extract('Output report path:')",
                "    report_path.parent.mkdir(parents=True, exist_ok=True)",
                "    report_path.write_text('# Fake Audit Report\\n', encoding='utf-8')",
                "    final_message = '# Fake Audit Message\\n'",
                "    stage = 'audit'",
                "",
                "if last_message_path is not None:",
                "    last_message_path.parent.mkdir(parents=True, exist_ok=True)",
                "    last_message_path.write_text(final_message, encoding='utf-8')",
                "",
                "event = {'type': 'message', 'stage': stage, 'text': f'fake {stage} event'}",
                "if json_output:",
                "    sys.stdout.write(json.dumps(event, ensure_ascii=False) + '\\n')",
                "else:",
                "    sys.stdout.write(f'fake {stage} output\\n')",
                "sys.stdout.flush()",
                "raise SystemExit(0)",
            ]
        )
        self.fake_codex.write_text(script + "\n", encoding="utf-8")
        self.fake_codex.chmod(0o755)

    @staticmethod
    def _set_env(key: str, value: str) -> None:
        os.environ[key] = value

    @staticmethod
    def _reset_singletons() -> None:
        import app.core.config as config_module
        import app.db.database as database_module
        import app.services.artifact_service as artifact_module
        import app.services.catalog_service as catalog_module
        import app.services.event_service as event_module
        import app.services.execution_service as execution_module
        import app.services.task_service as task_module
        import app.services.workspace_service as workspace_module
        import app.workers.scheduler as scheduler_module

        config_module._config = None
        database_module._database = None
        artifact_module._artifact_service = None
        catalog_module._catalog_service = None
        event_module._event_service = None
        execution_module._execution_service = None
        task_module._task_service = None
        workspace_module._workspace_service = None
        scheduler_module._scheduler_service = None


if __name__ == "__main__":
    unittest.main()
