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
from app.services.provider_client import ProviderNotFoundError
from app.services.execution_service import get_execution_service
from app.services.task_service import get_task_service
from app.workers.runner import StageContext, build_opencode_process_env


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
        if provider_key not in self.details:
            raise ProviderNotFoundError(f"provider not found: {provider_key}")
        return self.details[provider_key]


class OpenCodeCliModeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-repo-")
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-state-")
        self.tools_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-tools-")
        self.repo_root = Path(self.repo_dir.name)
        self.state_root = Path(self.state_dir.name)
        self.fake_opencode = Path(self.tools_dir.name) / "fake-opencode"

        project_dir = self.repo_root / "foundation" / "demo" / "service"
        project_dir.mkdir(parents=True)
        (project_dir / "bundle.json").write_text("{}\n", encoding="utf-8")
        (project_dir / "iface.idl").write_text("interface Demo {}\n", encoding="utf-8")
        self._write_fake_opencode()

        self._reset_singletons()
        self._set_env("IPC_AUDIT_DATABASE_URL", f"sqlite:///{self.state_root / 'ipc-audit.db'}")
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_EXECUTION_MODE", "mock")
        self._set_env("IPC_AUDIT_OPENCODE_BIN", str(self.fake_opencode))
        self._set_env("IPC_AUDIT_POC_ENABLED", "true")
        self._set_env("IPC_AUDIT_POC_RUNTIME_AVAILABLE", "true")
        self._set_env("FAKE_OPENCODE_EXPECT_XDG_PREFIX", str(self.state_root))
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
        self.provider_details = {
            "opencode-prod": {
                "provider_key": "opencode-prod",
                "display_name": "OpenCode Prod",
                "provider_type": "openai",
                "enabled": True,
                "is_default": True,
                "api_base": "https://api.openai.com/v1",
                "model": "openai/gpt-5-create",
                "updated_at": "2026-05-12T00:00:00Z",
                "api_key": "top-secret",
                "env_bindings": {
                    "OPENAI_API_KEY": "sk-create-secret",
                },
                "file_bindings": [
                    {
                        "name": "opencode.json",
                        "path": "/root/.config/opencode/opencode.json",
                        "content": "{\"provider\":\"create-secret\"}",
                        "enabled": True,
                    },
                    {
                        "name": "auth.json",
                        "path": "/root/.codex/auth.json",
                        "content": "{\"token\":\"create-secret\"}",
                        "enabled": True,
                    },
                ],
            }
        }
        self._install_provider_client()

    def tearDown(self) -> None:
        for key in (
            "IPC_AUDIT_DATABASE_URL",
            "IPC_AUDIT_STATE_ROOT",
            "IPC_AUDIT_EXECUTION_MODE",
            "IPC_AUDIT_OPENCODE_BIN",
            "IPC_AUDIT_POC_ENABLED",
            "IPC_AUDIT_POC_RUNTIME_AVAILABLE",
            "IPC_AUDIT_WORKSPACES_JSON",
            "FAKE_OPENCODE_EMPTY_FIRST",
            "FAKE_OPENCODE_ERROR_FIRST",
            "FAKE_OPENCODE_EXPECT_XDG_PREFIX",
            "FAKE_OPENCODE_EXPECT_XDG_CONFIG_PREFIX",
            "FAKE_OPENCODE_EXPECT_OPENAI_API_KEY",
            "FAKE_OPENCODE_EXPECT_OPENCODE_PROVIDER",
        ):
            os.environ.pop(key, None)
        self._reset_singletons()
        self.repo_dir.cleanup()
        self.state_dir.cleanup()
        self.tools_dir.cleanup()

    def test_opencode_cli_writes_outputs_and_derives_last_message(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_then_poc",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="opencode_cli",
                model="openai/gpt-5",
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
        self.assertEqual(attempt.effective_config["executor_mode"], "opencode_cli")
        self.assertEqual(attempt.effective_config["execution_mode"], "opencode_cli")
        self.assertEqual(attempt.effective_config["model"], "openai/gpt-5")

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

        audit_last_message = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "audit",
            "runtime/audit/last-message.md",
        )
        self.assertIn("# Fake Audit Message", audit_last_message["content"])

        event_page = get_task_service().list_events(task.task_id, attempt_id=str(detail.latest_attempt_id), cursor=None, limit=200)
        stdout_event = next(item for item in event_page.items if item.event_type == "stage.stdout.appended" and item.stage_name == "audit")
        self.assertEqual(stdout_event.payload["session_file_path"], "runtime/audit/events.jsonl")
        self.assertEqual(stdout_event.payload["event_types"]["assistant_message"], 1)
        agent_event = next(item for item in event_page.items if item.event_type == "stage.agent.message" and item.stage_name == "poc")
        self.assertIn("# Fake PoC Message", agent_event.payload["preview"])

        poc_log = get_task_service().get_stage_log(task.task_id, str(detail.latest_attempt_id), "poc", lines=240, cursor=None)
        self.assertIn("--dangerously-skip-permissions", poc_log.content)
        self.assertIn("-m openai/gpt-5", poc_log.content)
        self.assertIn("XDG_DATA_HOME:", poc_log.content)
        self.assertIn("/runtime/provider/xdg-data", poc_log.content)

    def test_opencode_cli_retries_missing_output_in_same_session(self) -> None:
        self._set_env("FAKE_OPENCODE_EMPTY_FIRST", "1")
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_only",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="opencode_cli",
                model="openai/gpt-5",
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
        self.assertEqual(attempt.stage_runs[0].message, "audit stage completed")

        audit_log = get_task_service().get_stage_log(task.task_id, str(detail.latest_attempt_id), "audit", lines=260, cursor=None)
        self.assertIn("opencode recovery retry 1/3", audit_log.content)
        self.assertIn("Retry reason: missing_output", audit_log.content)
        self.assertIn("--session ses_fake_retry", audit_log.content)

        audit_events = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "audit",
            "runtime/audit/events.jsonl",
        )["content"]
        self.assertIn('"sessionID": "ses_fake_retry"', audit_events)
        self.assertIn("# Fake Audit Message", audit_events)

    def test_opencode_cli_retries_last_error_event_in_same_session(self) -> None:
        self._set_env("FAKE_OPENCODE_ERROR_FIRST", "1")
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_only",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="opencode_cli",
                model="openai/gpt-5",
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
        self.assertEqual(attempt.stage_runs[0].message, "audit stage completed")

        audit_log = get_task_service().get_stage_log(task.task_id, str(detail.latest_attempt_id), "audit", lines=300, cursor=None)
        self.assertIn("opencode recovery retry 1/3", audit_log.content)
        self.assertIn("Retry reason: opencode_last_error", audit_log.content)
        self.assertIn("Previous return code: 1", audit_log.content)
        self.assertIn("--session ses_fake_error_retry", audit_log.content)

        audit_events = get_task_service().get_stage_session_file(
            task.task_id,
            str(detail.latest_attempt_id),
            "audit",
            "runtime/audit/events.jsonl",
        )["content"]
        self.assertIn('"type": "error"', audit_events)
        self.assertIn('"sessionID": "ses_fake_error_retry"', audit_events)
        self.assertIn("# Fake Audit Message", audit_events)

    def test_opencode_env_isolated_between_task_attempts(self) -> None:
        first = self._stage_context(
            task_id="ipc-audit-task-first",
            attempt_id="attempt-first",
        )
        second = self._stage_context(
            task_id="ipc-audit-task-second",
            attempt_id="attempt-second",
        )

        first_env = build_opencode_process_env(first)
        second_env = build_opencode_process_env(second)

        self.assertNotEqual(first_env["XDG_DATA_HOME"], second_env["XDG_DATA_HOME"])
        self.assertNotEqual(first_env["HOME"], second_env["HOME"])
        self.assertNotEqual(first_env["XDG_CONFIG_HOME"], second_env["XDG_CONFIG_HOME"])
        self.assertNotEqual(first_env["XDG_CACHE_HOME"], second_env["XDG_CACHE_HOME"])
        self.assertNotEqual(first_env["XDG_STATE_HOME"], second_env["XDG_STATE_HOME"])
        self.assertIn("ipc-audit-task-first", first_env["XDG_DATA_HOME"])
        self.assertIn("attempt-first", first_env["XDG_DATA_HOME"])
        self.assertIn("ipc-audit-task-second", second_env["XDG_DATA_HOME"])
        self.assertIn("attempt-second", second_env["XDG_DATA_HOME"])

        for env in (first_env, second_env):
            data_home = Path(env["XDG_DATA_HOME"])
            config_home = Path(env["XDG_CONFIG_HOME"])
            home_dir = Path(env["HOME"])
            cache_home = Path(env["XDG_CACHE_HOME"])
            state_home = Path(env["XDG_STATE_HOME"])
            self.assertTrue(home_dir.is_dir())
            self.assertTrue(config_home.is_dir())
            self.assertTrue(data_home.is_dir())
            self.assertTrue(cache_home.is_dir())
            self.assertTrue(state_home.is_dir())

    def test_opencode_cli_refetches_provider_runtime_env_and_model(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="provider-bound-opencode",
                workspace_id="oh61-main",
                pipeline_mode="audit_only",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="opencode_cli",
                provider_keys=["opencode-prod"],
            ),
            self.subject,
        )

        self.provider_details["opencode-prod"]["model"] = "openai/gpt-5-runtime"
        self.provider_details["opencode-prod"]["env_bindings"]["OPENAI_API_KEY"] = "sk-runtime-secret"
        self.provider_details["opencode-prod"]["file_bindings"][0]["content"] = "{\"provider\":\"runtime-secret\"}"
        self._set_env("FAKE_OPENCODE_EXPECT_XDG_PREFIX", str(self.state_root))
        self._set_env("FAKE_OPENCODE_EXPECT_XDG_CONFIG_PREFIX", str(self.state_root))
        self._set_env("FAKE_OPENCODE_EXPECT_OPENAI_API_KEY", "sk-runtime-secret")
        self._set_env("FAKE_OPENCODE_EXPECT_OPENCODE_PROVIDER", "openai")

        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        self.assertEqual(detail.status, "succeeded")
        self.assertEqual(attempt.status, "succeeded")

        audit_log = get_task_service().get_stage_log(task.task_id, str(detail.latest_attempt_id), "audit", lines=260, cursor=None)
        self.assertIn("-m openai/gpt-5-runtime", audit_log.content)
        self.assertIn("Provider keys: ['opencode-prod']", audit_log.content)
        self.assertNotIn("sk-runtime-secret", audit_log.content)
        self.assertNotIn("runtime-secret", audit_log.content)

    def test_opencode_cli_generates_missing_opencode_config_from_provider_fields(self) -> None:
        self.provider_details["opencode-prod"]["api_base"] = "https://generated-opencode.example.test/v1"
        self.provider_details["opencode-prod"]["api_key"] = "sk-generated-opencode"
        self.provider_details["opencode-prod"]["model"] = "openai/gpt-5-generated"
        self.provider_details["opencode-prod"]["env_bindings"] = {}
        self.provider_details["opencode-prod"]["file_bindings"] = [
            {
                "name": "auth.json",
                "path": "/root/.codex/auth.json",
                "content": "{\"token\":\"other-executor-only\"}",
                "enabled": True,
            }
        ]
        self._set_env("FAKE_OPENCODE_EXPECT_OPENAI_API_KEY", "sk-generated-opencode")
        self._set_env("FAKE_OPENCODE_EXPECT_OPENCODE_PROVIDER", "openai")

        task = get_task_service().create_task(
            TaskCreateRequest(
                title="generated-opencode-provider",
                workspace_id="oh61-main",
                pipeline_mode="audit_only",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                executor_mode="opencode_cli",
                provider_keys=["opencode-prod"],
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

        provider_root = self.state_root / "tasks" / task.task_id / "attempts" / str(detail.latest_attempt_id) / "runtime" / "provider"
        config_text = (provider_root / "xdg-config" / "opencode" / "opencode.json").read_text(encoding="utf-8")
        self.assertIn('"openai"', config_text)
        self.assertIn('"https://generated-opencode.example.test/v1"', config_text)
        self.assertIn('"sk-generated-opencode"', config_text)
        self.assertIn('"model": "openai/gpt-5-generated"', config_text)

    def _write_fake_opencode(self) -> None:
        script = "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "",
                "args = sys.argv[1:]",
                "json_output = False",
                "model = None",
                "session_id = None",
                "for index, value in enumerate(args):",
                "    if value == '--format' and index + 1 < len(args):",
                "        json_output = args[index + 1] == 'json'",
                "    if value == '-m' and index + 1 < len(args):",
                "        model = args[index + 1]",
                "    if value == '--session' and index + 1 < len(args):",
                "        session_id = args[index + 1]",
                "prompt = args[-1]",
                "",
                "xdg_data_home = os.environ.get('XDG_DATA_HOME', '')",
                "expected_prefix = os.environ.get('FAKE_OPENCODE_EXPECT_XDG_PREFIX', '')",
                "if expected_prefix and not xdg_data_home.startswith(expected_prefix):",
                "    raise SystemExit(f'unexpected XDG_DATA_HOME: {xdg_data_home}')",
                "if 'runtime/provider/xdg-data' not in xdg_data_home:",
                "    raise SystemExit(f'missing isolated opencode XDG_DATA_HOME: {xdg_data_home}')",
                "xdg_config_home = os.environ.get('XDG_CONFIG_HOME', '')",
                "expected_config_prefix = os.environ.get('FAKE_OPENCODE_EXPECT_XDG_CONFIG_PREFIX', '')",
                "if expected_config_prefix and not xdg_config_home.startswith(expected_config_prefix):",
                "    raise SystemExit(f'unexpected XDG_CONFIG_HOME: {xdg_config_home}')",
                "expected_openai_key = os.environ.get('FAKE_OPENCODE_EXPECT_OPENAI_API_KEY', '')",
                "if expected_openai_key and os.environ.get('OPENAI_API_KEY') != expected_openai_key:",
                "    raise SystemExit('unexpected OPENAI_API_KEY')",
                "expected_provider = os.environ.get('FAKE_OPENCODE_EXPECT_OPENCODE_PROVIDER', '')",
                "if expected_provider:",
                "    provider_file = Path(xdg_config_home) / 'opencode' / 'opencode.json'",
                "    if expected_provider not in provider_file.read_text(encoding='utf-8'):",
                "        raise SystemExit(f'opencode.json missing expected provider: {provider_file}')",
                "",
                "if os.environ.get('FAKE_OPENCODE_ERROR_FIRST') == '1' and session_id is None:",
                "    events = [",
                "        {'type': 'step_start', 'sessionID': 'ses_fake_error_retry', 'part': {'type': 'step-start', 'sessionID': 'ses_fake_error_retry'}},",
                "        {'type': 'error', 'sessionID': 'ses_fake_error_retry', 'error': {'name': 'UnknownError', 'data': {'message': 'SSE read timed out'}}},",
                "    ]",
                "    for event in events:",
                "        sys.stdout.write(json.dumps(event, ensure_ascii=False) + '\\n')",
                "    sys.stdout.flush()",
                "    raise SystemExit(1)",
                "",
                "if os.environ.get('FAKE_OPENCODE_EMPTY_FIRST') == '1' and session_id is None:",
                "    event = {'type': 'step_start', 'sessionID': 'ses_fake_retry', 'part': {'type': 'step-start', 'sessionID': 'ses_fake_retry'}}",
                "    sys.stdout.write(json.dumps(event, ensure_ascii=False) + '\\n')",
                "    sys.stdout.flush()",
                "    raise SystemExit(0)",
                "",
                "def extract(*prefixes: str) -> Path:",
                "    for line in prompt.splitlines():",
                "        for prefix in prefixes:",
                "            if line.startswith(prefix):",
                "                return Path(line.split(': ', 1)[1].strip())",
                "    raise SystemExit(f'missing prompt field: {prefixes}')",
                "",
                "if 'Output audited result json path:' in prompt or 'Required output audited result json path:' in prompt:",
                "    report_path = extract('Output PoC report path:', 'Required output PoC report path:')",
                "    json_path = extract('Output audited result json path:', 'Required output audited result json path:')",
                "    report_path.parent.mkdir(parents=True, exist_ok=True)",
                "    json_path.parent.mkdir(parents=True, exist_ok=True)",
                "    report_path.write_text('# Fake PoC Report\\n', encoding='utf-8')",
                "    json_path.write_text(json.dumps({'ok': True}, ensure_ascii=False) + '\\n', encoding='utf-8')",
                "    final_message = '# Fake PoC Message\\n'",
                "    stage = 'poc'",
                "else:",
                "    report_path = extract('Output report path:', 'Required output report path:')",
                "    report_path.parent.mkdir(parents=True, exist_ok=True)",
                "    report_path.write_text('# Fake Audit Report\\n', encoding='utf-8')",
                "    final_message = '# Fake Audit Message\\n'",
                "    stage = 'audit'",
                "",
                "events = [",
                "    {'type': 'status', 'message': f'{stage} started'},",
                "    {'type': 'status', 'message': f'xdg data {xdg_data_home}'},",
                "    {",
                "        'type': 'assistant_message',",
                "        'stage': stage,",
                "        'model': model,",
                "        'content': [{'type': 'text', 'text': final_message.strip()}],",
                "    },",
                "]",
                "if json_output:",
                "    for event in events:",
                "        sys.stdout.write(json.dumps(event, ensure_ascii=False) + '\\n')",
                "else:",
                "    sys.stdout.write(final_message)",
                "sys.stdout.flush()",
                "raise SystemExit(0)",
            ]
        )
        self.fake_opencode.write_text(script + "\n", encoding="utf-8")
        self.fake_opencode.chmod(0o755)

    def _stage_context(self, *, task_id: str, attempt_id: str) -> StageContext:
        attempt_root = self.state_root / "tasks" / task_id / "attempts" / attempt_id
        return StageContext(
            task_id=task_id,
            attempt_id=attempt_id,
            workspace_id="oh61-main",
            stage_name="audit",
            input_kind="custom_project",
            pipeline_mode="audit_only",
            project_path="foundation/demo/service",
            report_path=None,
            repo_root=self.repo_root,
            attempt_root=attempt_root,
            runtime_root=attempt_root / "runtime",
            logs_dir=attempt_root / "logs",
            artifacts_dir=attempt_root / "artifacts",
            scratch_dir=attempt_root / "scratch",
            effective_config={"executor_mode": "opencode_cli"},
        )

    @staticmethod
    def _set_env(key: str, value: str) -> None:
        os.environ[key] = value

    def _install_provider_client(self) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(self.provider_details)

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
        import app.services.task_service as task_module
        import app.services.workspace_service as workspace_module
        import app.workers.scheduler as scheduler_module

        config_module._config = None
        database_module._database = None
        artifact_module._artifact_service = None
        catalog_module._catalog_service = None
        event_module._event_service = None
        execution_module._execution_service = None
        provider_client_module._provider_client = None
        provider_runtime_module._provider_runtime_service = None
        task_module._task_service = None
        workspace_module._workspace_service = None
        scheduler_module._scheduler_service = None


if __name__ == "__main__":
    unittest.main()
