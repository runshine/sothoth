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
from app.schemas import TaskTemplateCreateRequest, TaskTemplateUpdateRequest
from app.services.provider_client import ProviderNotFoundError
from app.services.template_service import get_template_service


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


class TemplateServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-template-repo-")
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-template-state-")
        self.repo_root = Path(self.repo_dir.name)
        self.state_root = Path(self.state_dir.name)

        project_dir = self.repo_root / "foundation" / "demo" / "service"
        project_dir.mkdir(parents=True)
        (project_dir / "bundle.json").write_text("{}\n", encoding="utf-8")

        self._reset_singletons()
        self._set_env("IPC_AUDIT_DATABASE_URL", f"sqlite:///{self.state_root / 'ipc-audit.db'}")
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_EXECUTION_MODE", "codex_cli")
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
                    },
                    "file_bindings": [],
                },
                "openai-prod": {
                    "provider_key": "openai-prod",
                    "display_name": "OpenAI Prod",
                    "provider_type": "openai",
                    "enabled": True,
                    "is_default": False,
                    "api_base": "https://api.openai.com/v1",
                    "model": "openai/gpt-5",
                    "updated_at": "2026-05-12T00:00:01Z",
                    "api_key": "openai-secret",
                    "env_bindings": {
                        "OPENAI_API_KEY": "sk-openai-secret",
                    },
                    "file_bindings": [],
                },
            }
        )
        self.subject = Subject(username="tester")

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

    def test_create_update_list_and_delete_template(self) -> None:
        created = get_template_service().create_template(
            TaskTemplateCreateRequest(
                workspace_id="oh61-main",
                name="dynamic-four-stage",
                description="initial template",
                config={
                    "pipeline_mode": "custom_graph",
                    "executor_mode": "agentflow_cli",
                    "model": "gpt-5-codex",
                    "provider_keys": ["anthropic-prod", "anthropic-prod", "openai-prod"],
                    "graph_source": {
                        "type": "inline_json",
                        "content": {
                            "nodes": [
                                {"id": "stage1", "prompt": "write {{ report_outputs.stage1_report.absolute_path }}"},
                                {"id": "stage2", "depends_on": ["stage1"], "prompt": "write {{ report_outputs.stage2_report.absolute_path }}"},
                            ]
                        },
                    },
                    "report_outputs": [
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
                    "notes": "template-notes",
                },
            ),
            self.subject,
        )
        self.assertEqual(created.name, "dynamic-four-stage")
        self.assertEqual(created.config.pipeline_mode, "custom_graph")
        self.assertEqual(created.config.executor_mode, "agentflow_cli")
        self.assertEqual(created.config.model, "gpt-5-codex")
        self.assertEqual(created.config.provider_keys, ["anthropic-prod", "openai-prod"])
        self.assertEqual([item.output_id for item in created.config.report_outputs], ["stage1_report", "stage2_report"])

        listed = get_template_service().list_templates(workspace_id="oh61-main")
        self.assertEqual([item.template_id for item in listed], [created.template_id])

        updated = get_template_service().update_template(
            created.template_id,
            TaskTemplateUpdateRequest(
                name="audit-only-template",
                description="updated template",
                config={
                    "pipeline_mode": "audit_only",
                    "executor_mode": "codex_cli",
                    "model": "gpt-5-mini",
                    "provider_keys": ["openai-prod"],
                    "report_outputs": [],
                    "notes": "updated-notes",
                },
            ),
            self.subject,
        )
        self.assertEqual(updated.name, "audit-only-template")
        self.assertEqual(updated.description, "updated template")
        self.assertEqual(updated.config.pipeline_mode, "audit_only")
        self.assertEqual(updated.config.executor_mode, "codex_cli")
        self.assertEqual(updated.config.graph_source, None)
        self.assertEqual(updated.config.provider_keys, ["openai-prod"])
        self.assertEqual([item.output_id for item in updated.config.report_outputs], ["audit_report"])
        self.assertEqual(updated.config.report_outputs[0].path, "exports/audit-report.md")

        fetched = get_template_service().get_template(created.template_id)
        self.assertEqual(fetched.template_id, created.template_id)
        self.assertEqual(fetched.name, "audit-only-template")

        get_template_service().delete_template(created.template_id)
        self.assertEqual(get_template_service().list_templates(workspace_id="oh61-main"), [])

    def test_duplicate_template_name_in_same_workspace_is_rejected(self) -> None:
        payload = TaskTemplateCreateRequest(
            workspace_id="oh61-main",
            name="duplicate-name",
            config={
                "pipeline_mode": "custom_graph",
                "executor_mode": "agentflow_cli",
                "graph_source": {
                    "type": "inline_json",
                    "content": {"nodes": [{"id": "stage1", "prompt": "hello"}]},
                },
                "report_outputs": [
                    {
                        "output_id": "stage1_report",
                        "node_id": "stage1",
                        "title": "Stage 1 Report",
                        "path": "exports/stage1-report.md",
                        "format": "markdown",
                        "required": True,
                        "order": 10,
                    }
                ],
            },
        )
        get_template_service().create_template(payload, self.subject)
        with self.assertRaises(HTTPException) as context:
            get_template_service().create_template(payload, self.subject)
        self.assertEqual(context.exception.status_code, 409)

    @staticmethod
    def _set_env(key: str, value: str) -> None:
        os.environ[key] = value

    @staticmethod
    def _install_provider_client(details: dict[str, dict]) -> None:
        import app.services.provider_client as provider_client_module

        provider_client_module._provider_client = FakeProviderClient(details, default_provider_key="anthropic-prod")

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
        import app.services.runtime_config_service as runtime_config_module
        import app.services.task_service as task_module
        import app.services.template_service as template_module
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
        runtime_config_module._runtime_config_service = None
        scheduler_module._scheduler_service = None
        task_module._task_service = None
        template_module._template_service = None
        workspace_module._workspace_service = None


if __name__ == "__main__":
    unittest.main()
