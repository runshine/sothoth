from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

from app.core.auth import Subject
from app.core.config import load_config
from app.db.database import init_database
from app.schemas import InputRef, TaskCreateRequest
from app.services.provider_client import ProviderNotFoundError
from app.services.task_service import get_task_service


class FakeProviderClient:
    def __init__(self, details: dict[str, dict], default_provider_key: str | None = None) -> None:
        self.details = details
        self.default_provider_key = default_provider_key

    def list_providers(self) -> dict:
        return {
            "total": len(self.details),
            "default_provider_key": self.default_provider_key,
            "items": list(self.details.values()),
        }

    def get_provider_detail(self, provider_key: str) -> dict:
        if provider_key not in self.details:
            raise ProviderNotFoundError(f"provider not found: {provider_key}")
        return self.details[provider_key]


class TaskProviderBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-repo-")
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-state-")
        self.repo_root = Path(self.repo_dir.name)
        self.state_root = Path(self.state_dir.name)
        project_dir = self.repo_root / "foundation" / "demo" / "service"
        project_dir.mkdir(parents=True)
        (project_dir / "bundle.json").write_text("{}\n", encoding="utf-8")
        (project_dir / "iface.idl").write_text("interface Demo {}\n", encoding="utf-8")

        self._reset_singletons()
        self._set_env("IPC_AUDIT_DATABASE_URL", f"sqlite:///{self.state_root / 'ipc-audit.db'}")
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_EXECUTION_MODE", "mock")
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
        self._install_provider_client(
            {
                "anthropic-prod": {
                    "provider_key": "anthropic-prod",
                    "display_name": "Anthropic Prod",
                    "provider_type": "anthropic",
                    "enabled": True,
                    "is_default": True,
                    "api_base": "https://api.anthropic.com",
                    "model": "claude-sonnet-4-20250514",
                    "updated_at": "2026-05-12T00:00:00Z",
                    "api_key": "anthropic-secret",
                    "env_bindings": {
                        "ANTHROPIC_API_KEY": "sk-anthropic-secret",
                        "SHARED_PROVIDER_FLAG": "anthropic",
                    },
                    "file_bindings": [
                        {
                            "name": "codex-auth.json",
                            "path": "/root/.codex/auth.json",
                            "content": "{\"token\":\"anthropic-secret\"}",
                            "enabled": True,
                        }
                    ],
                },
                "opencode-prod": {
                    "provider_key": "opencode-prod",
                    "display_name": "OpenCode Prod",
                    "provider_type": "openai",
                    "enabled": True,
                    "is_default": False,
                    "api_base": "https://api.openai.com/v1",
                    "model": "openai/gpt-5",
                    "updated_at": "2026-05-12T00:00:01Z",
                    "api_key": "openai-secret",
                    "env_bindings": {
                        "OPENAI_API_KEY": "sk-openai-secret",
                        "SHARED_PROVIDER_FLAG": "opencode",
                    },
                    "file_bindings": [
                        {
                            "name": "opencode.json",
                            "path": "/root/.config/opencode/opencode.json",
                            "content": "{\"provider\":\"opencode-secret\"}",
                            "enabled": True,
                        }
                    ],
                },
            }
        )

    def tearDown(self) -> None:
        for key in (
            "IPC_AUDIT_DATABASE_URL",
            "IPC_AUDIT_STATE_ROOT",
            "IPC_AUDIT_EXECUTION_MODE",
            "IPC_AUDIT_WORKSPACES_JSON",
        ):
            os.environ.pop(key, None)
        self._reset_singletons()
        self.repo_dir.cleanup()
        self.state_dir.cleanup()

    def test_task_create_persists_sanitized_provider_metadata(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="demo-service",
                workspace_id="oh61-main",
                pipeline_mode="audit_only",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                provider_keys=["anthropic-prod", "opencode-prod", "anthropic-prod"],
            ),
            self.subject,
        )

        attempt = get_task_service().get_attempt(task.task_id, str(task.latest_attempt_id))
        effective_config = attempt.effective_config
        serialized = json.dumps(effective_config, ensure_ascii=False)

        self.assertEqual(effective_config["provider_keys"], ["anthropic-prod", "opencode-prod"])
        self.assertEqual(effective_config["provider_source_backend"], "configcenter")
        self.assertEqual(effective_config["model"], "openai/gpt-5")
        self.assertIsNone(effective_config["task_model"])
        self.assertEqual(
            [item["provider_key"] for item in effective_config["provider_snapshots"]],
            ["anthropic-prod", "opencode-prod"],
        )
        self.assertIn("ANTHROPIC_API_KEY", effective_config["provider_snapshots"][0]["mapped_env_keys"])
        self.assertIn("/root/.config/opencode/opencode.json", effective_config["provider_snapshots"][1]["mapped_file_paths"])
        self.assertNotIn("sk-openai-secret", serialized)
        self.assertNotIn("sk-anthropic-secret", serialized)
        self.assertNotIn("opencode-secret", serialized)
        self.assertNotIn("anthropic-secret", serialized)

    def test_missing_provider_returns_422(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            get_task_service().create_task(
                TaskCreateRequest(
                    title="missing-provider",
                    workspace_id="oh61-main",
                    pipeline_mode="audit_only",
                    input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                    provider_keys=["missing-provider"],
                ),
                self.subject,
            )
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn("missing-provider", str(ctx.exception.detail))

    def test_explicit_model_overrides_provider_default_model(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="explicit-model",
                workspace_id="oh61-main",
                pipeline_mode="audit_only",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service"),
                provider_keys=["anthropic-prod", "opencode-prod"],
                model="manual/override-model",
            ),
            self.subject,
        )
        attempt = get_task_service().get_attempt(task.task_id, str(task.latest_attempt_id))
        self.assertEqual(attempt.effective_config["model"], "manual/override-model")
        self.assertEqual(attempt.effective_config["task_model"], "manual/override-model")

    def _install_provider_client(self, details: dict[str, dict]) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(details, default_provider_key="anthropic-prod")

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
