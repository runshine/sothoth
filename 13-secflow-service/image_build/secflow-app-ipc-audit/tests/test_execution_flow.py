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


class ExecutionFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-repo-")
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-state-")
        self.repo_root = Path(self.repo_dir.name)
        self.state_root = Path(self.state_dir.name)
        self.project_dir = self.repo_root / "foundation" / "demo" / "service"
        self.project_dir.mkdir(parents=True)
        (self.project_dir / "bundle.json").write_text("{}\n", encoding="utf-8")
        (self.project_dir / "iface.idl").write_text("interface Demo {}\n", encoding="utf-8")
        report_dir = self.repo_root / ".audit" / "ipc" / "project_reports"
        report_dir.mkdir(parents=True)
        (report_dir / "demo.md").write_text("# existing report\n", encoding="utf-8")

        self._reset_singletons()
        self._set_env("IPC_AUDIT_DATABASE_URL", f"sqlite:///{self.state_root / 'ipc-audit.db'}")
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_EXECUTION_MODE", "mock")
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
                    },
                    {
                        "workspace_id": "locked",
                        "display_name": "Locked Workspace",
                        "repo_root": str(self.repo_root),
                        "entries_file": ".audit/ipc_entries.txt",
                        "bundle_scan_roots": ["base", "foundation"],
                        "allow_custom_project_path": False,
                        "supports_poc": False,
                        "default_pipeline_mode": "audit_only",
                        "is_default": False,
                    }
                ]
            ),
        )
        load_config()
        init_database()
        self.subject = Subject(username="tester")

    def tearDown(self) -> None:
        self._clear_env("IPC_AUDIT_DATABASE_URL")
        self._clear_env("IPC_AUDIT_STATE_ROOT")
        self._clear_env("IPC_AUDIT_EXECUTION_MODE")
        self._clear_env("IPC_AUDIT_POC_ENABLED")
        self._clear_env("IPC_AUDIT_POC_RUNTIME_AVAILABLE")
        self._clear_env("IPC_AUDIT_WORKSPACES_JSON")
        self._reset_singletons()
        self.repo_dir.cleanup()
        self.state_dir.cleanup()

    def test_full_mock_pipeline_publishes_session_and_manifest_artifacts(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_then_poc",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        artifacts = get_task_service().list_artifacts(task.task_id, str(detail.latest_attempt_id))
        sessions = get_task_service().list_stage_sessions(task.task_id, str(detail.latest_attempt_id), "audit")

        self.assertEqual(detail.status, "succeeded")
        self.assertEqual(attempt.status, "succeeded")
        self.assertEqual({item.stage_name: item.status for item in attempt.stage_runs}, {"audit": "succeeded", "poc": "succeeded"})
        self.assertIn("runtime_manifest", [item.artifact_kind for item in artifacts.items])
        self.assertIn("session_file", [item.artifact_kind for item in artifacts.items])
        self.assertCountEqual(
            [item["path"] for item in sessions],
            [
                "runtime/audit/prompt.txt",
                "runtime/audit/events.jsonl",
                "runtime/audit/last-message.md",
            ],
        )

    def test_poc_only_accepts_dot_audit_report_path(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-report",
                workspace_id="oh61-main",
                pipeline_mode="poc_only",
                input_ref=InputRef(kind="existing_audit_report", report_path=".audit/ipc/project_reports/demo.md"),
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)
        get_execution_service().run_attempt(str(attempt_id))

        detail = get_task_service().get_task(task.task_id)
        attempt = get_task_service().get_attempt(task.task_id, str(detail.latest_attempt_id))
        artifacts = get_task_service().list_artifacts(task.task_id, str(detail.latest_attempt_id))

        self.assertEqual(detail.status, "succeeded")
        self.assertEqual(attempt.status, "succeeded")
        self.assertEqual({item.stage_name: item.status for item in attempt.stage_runs}, {"audit": "skipped", "poc": "succeeded"})
        self.assertIn("poc_report", [item.artifact_kind for item in artifacts.items])
        self.assertIn("runtime_manifest", [item.artifact_kind for item in artifacts.items])

    def test_custom_project_is_rejected_when_workspace_disallows_it(self) -> None:
        with self.assertRaisesRegex(Exception, "custom project path is not allowed"):
            get_task_service().create_task(
                TaskCreateRequest(
                    title="locked-service",
                    workspace_id="locked",
                    pipeline_mode="audit_only",
                    input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                ),
                self.subject,
            )

    @staticmethod
    def _set_env(key: str, value: str) -> None:
        os.environ[key] = value

    @staticmethod
    def _clear_env(key: str) -> None:
        os.environ.pop(key, None)

    @staticmethod
    def _reset_singletons() -> None:
        import app.core.config as config_module
        import app.db.database as database_module
        import app.services.artifact_service as artifact_module
        import app.services.catalog_service as catalog_module
        import app.services.event_service as event_module
        import app.services.execution_service as execution_module
        import app.workers.scheduler as scheduler_module
        import app.services.task_service as task_module
        import app.services.workspace_service as workspace_module

        config_module._config = None
        database_module._database = None
        artifact_module._artifact_service = None
        catalog_module._catalog_service = None
        event_module._event_service = None
        execution_module._execution_service = None
        scheduler_module._scheduler_service = None
        task_module._task_service = None
        workspace_module._workspace_service = None


if __name__ == "__main__":
    unittest.main()
