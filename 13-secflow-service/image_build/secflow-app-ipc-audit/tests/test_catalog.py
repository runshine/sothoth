from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from app.services.catalog_service import get_catalog_service


class CatalogRefreshAsyncTest(unittest.TestCase):
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
        os.environ["IPC_AUDIT_DATABASE_URL"] = f"sqlite:///{self.state_root / 'ipc-audit.db'}"
        os.environ["IPC_AUDIT_STATE_ROOT"] = str(self.state_root)
        os.environ["IPC_AUDIT_WORKSPACES_JSON"] = json.dumps(
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
        )

        from app.core.config import load_config
        from app.db.database import init_database

        load_config()
        init_database()

    def tearDown(self) -> None:
        os.environ.pop("IPC_AUDIT_DATABASE_URL", None)
        os.environ.pop("IPC_AUDIT_STATE_ROOT", None)
        os.environ.pop("IPC_AUDIT_WORKSPACES_JSON", None)
        self._reset_singletons()
        self.repo_dir.cleanup()
        self.state_dir.cleanup()

    def test_refresh_projects_runs_in_background_and_populates_catalog(self) -> None:
        started = time.monotonic()
        job = get_catalog_service().refresh_projects(
            workspace_id="oh61-main",
            source="bundle_scan",
            write_entries_file=True,
            requested_by="tester",
        )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.5)
        self.assertIn(job.status, {"queued", "running"})

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            current = get_catalog_service().get_refresh_job(job.refresh_job_id)
            if current.status == "succeeded":
                break
            self.assertNotEqual(current.status, "failed")
            time.sleep(0.05)
        else:
            self.fail("catalog refresh job did not succeed before timeout")

        projects = get_catalog_service().list_projects(
            workspace_id="oh61-main",
            keyword=None,
            source="all",
            has_idl=None,
            has_on_remote_request_cpp=None,
            page=1,
            per_page=20,
        )
        self.assertEqual(projects.total, 1)
        self.assertEqual(projects.items[0].project_path, "foundation/demo/service")
        entries_file = self.repo_root / ".audit" / "ipc_entries.txt"
        self.assertTrue(entries_file.exists())
        self.assertIn("foundation/demo/service", entries_file.read_text(encoding="utf-8"))

    @staticmethod
    def _reset_singletons() -> None:
        import app.core.config as config_module
        import app.db.database as database_module
        import app.services.catalog_service as catalog_module
        import app.services.provider_client as provider_client_module
        import app.services.provider_runtime as provider_runtime_module
        import app.services.workspace_service as workspace_module

        config_module._config = None
        database_module._database = None
        catalog_module._catalog_service = None
        provider_client_module._provider_client = None
        provider_runtime_module._provider_runtime_service = None
        workspace_module._workspace_service = None


if __name__ == "__main__":
    unittest.main()
