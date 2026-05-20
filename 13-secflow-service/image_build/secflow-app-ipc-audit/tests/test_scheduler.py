from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from app.core.auth import Subject
from app.core.config import load_config
from app.db.database import init_database
from app.schemas import InputRef, TaskCreateRequest
from app.services.task_service import get_task_service
from app.workers.scheduler import get_scheduler_service
from app.db.database import get_database


class SchedulerParallelismTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-repo-")
        self.state_dir = tempfile.TemporaryDirectory(prefix="ipc-audit-state-")
        self.repo_root = Path(self.repo_dir.name)
        self.state_root = Path(self.state_dir.name)
        self.project_a = self.repo_root / "foundation" / "demo" / "service_a"
        self.project_b = self.repo_root / "foundation" / "demo" / "service_b"
        self.project_c = self.repo_root / "foundation" / "demo" / "service_c"
        for project in (self.project_a, self.project_b, self.project_c):
            project.mkdir(parents=True)
            (project / "bundle.json").write_text("{}\n", encoding="utf-8")
            (project / "iface.idl").write_text("interface Demo {}\n", encoding="utf-8")

        self._reset_singletons()
        self._set_env("IPC_AUDIT_DATABASE_URL", f"sqlite:///{self.state_root / 'ipc-audit.db'}")
        self._set_env("IPC_AUDIT_STATE_ROOT", str(self.state_root))
        self._set_env("IPC_AUDIT_EXECUTION_MODE", "mock")
        self._set_env("IPC_AUDIT_POC_ENABLED", "true")
        self._set_env("IPC_AUDIT_POC_RUNTIME_AVAILABLE", "true")
        self._set_env("IPC_AUDIT_MAX_PARALLEL_TASKS", "2")
        self._set_env("IPC_AUDIT_SCHEDULER_TICK_INTERVAL_SECONDS", "0.1")
        self._set_env("IPC_AUDIT_MOCK_STAGE_DELAY_SECONDS", "1.0")
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
        try:
            asyncio.run(get_scheduler_service().stop())
        except Exception:
            pass
        for key in (
            "IPC_AUDIT_DATABASE_URL",
            "IPC_AUDIT_STATE_ROOT",
            "IPC_AUDIT_EXECUTION_MODE",
            "IPC_AUDIT_POC_ENABLED",
            "IPC_AUDIT_POC_RUNTIME_AVAILABLE",
            "IPC_AUDIT_MAX_PARALLEL_TASKS",
            "IPC_AUDIT_SCHEDULER_TICK_INTERVAL_SECONDS",
            "IPC_AUDIT_MOCK_STAGE_DELAY_SECONDS",
            "IPC_AUDIT_WORKSPACES_JSON",
        ):
            os.environ.pop(key, None)
        self._reset_singletons()
        self.repo_dir.cleanup()
        self.state_dir.cleanup()

    def test_scheduler_honors_parallel_limit(self) -> None:
        tasks = []
        for project_path in ("foundation/demo/service_a", "foundation/demo/service_b"):
            tasks.append(
                get_task_service().create_task(
                    TaskCreateRequest(
                        title=project_path,
                        workspace_id="oh61-main",
                        pipeline_mode="audit_only",
                        input_ref=InputRef(kind="custom_project", project_path=project_path),
                    ),
                    self.subject,
                )
            )

        started = time.monotonic()
        asyncio.run(get_scheduler_service().start())
        self._wait_for_all_terminal([item.task_id for item in tasks], timeout_seconds=5.0)
        elapsed = time.monotonic() - started
        asyncio.run(get_scheduler_service().stop())

        statuses = [get_task_service().get_task(item.task_id).status for item in tasks]
        self.assertEqual(statuses, ["succeeded", "succeeded"])
        self.assertLess(elapsed, 1.8)

    def test_scheduler_applies_runtime_parallel_limit_update(self) -> None:
        from app.services.runtime_config_service import get_runtime_config_service

        runtime_config = get_runtime_config_service().update_max_parallel_tasks(1, updated_by="tester")
        self.assertEqual(runtime_config.max_parallel_tasks, 1)

        tasks = []
        for project_path in (
            "foundation/demo/service_a",
            "foundation/demo/service_b",
            "foundation/demo/service_c",
        ):
            tasks.append(
                get_task_service().create_task(
                    TaskCreateRequest(
                        title=project_path,
                        workspace_id="oh61-main",
                        pipeline_mode="audit_only",
                        input_ref=InputRef(kind="custom_project", project_path=project_path),
                    ),
                    self.subject,
                )
            )

        started = time.monotonic()
        asyncio.run(get_scheduler_service().start())
        time.sleep(0.2)
        runtime_config = get_runtime_config_service().update_max_parallel_tasks(2, updated_by="tester")
        self.assertEqual(runtime_config.max_parallel_tasks, 2)
        self._wait_for_all_terminal([item.task_id for item in tasks], timeout_seconds=5.0)
        elapsed = time.monotonic() - started
        asyncio.run(get_scheduler_service().stop())

        statuses = [get_task_service().get_task(item.task_id).status for item in tasks]
        self.assertEqual(statuses, ["succeeded", "succeeded", "succeeded"])
        self.assertLess(elapsed, 2.8)

    def test_recover_expired_attempts_skips_scheduler_active_future(self) -> None:
        task = get_task_service().create_task(
            TaskCreateRequest(
                title="foundation/demo/service_a",
                workspace_id="oh61-main",
                pipeline_mode="audit_only",
                input_ref=InputRef(kind="custom_project", project_path="foundation/demo/service_a"),
            ),
            self.subject,
        )
        attempt_id = get_task_service().claim_next_attempt("tester-worker")
        self.assertIsNotNone(attempt_id)

        scheduler = get_scheduler_service()
        scheduler._futures = {}  # type: ignore[attr-defined]  # noqa: SLF001

        class _FakeFuture:
            def done(self) -> bool:
                return False

        fake_future = _FakeFuture()
        scheduler._futures_lock.acquire()  # type: ignore[attr-defined]  # noqa: SLF001
        try:
            scheduler._futures[fake_future] = str(attempt_id)  # type: ignore[index,attr-defined]  # noqa: SLF001
        finally:
            scheduler._futures_lock.release()  # type: ignore[attr-defined]  # noqa: SLF001

        with get_database().connect() as conn:
            conn.execute(
                """
                update ipc_audit_task_attempts
                set status = 'running', heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                where attempt_id = ?
                """,
                (
                    "2026-05-20T01:00:00Z",
                    "2026-05-20T01:00:00Z",
                    "2026-05-20T01:00:00Z",
                    str(attempt_id),
                ),
            )

        recovered = get_task_service().recover_expired_attempts(
            excluded_attempt_ids=scheduler._active_attempt_ids(),  # type: ignore[attr-defined]  # noqa: SLF001
        )
        self.assertEqual(recovered, 0)
        attempt = get_task_service().get_attempt(task.task_id, str(attempt_id))
        self.assertEqual(attempt.status, "running")

    def _wait_for_all_terminal(self, task_ids: list[str], *, timeout_seconds: float) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            states = [get_task_service().get_task(task_id).status for task_id in task_ids]
            if all(status in {"succeeded", "partial_success", "failed", "cancelled", "needs_attention"} for status in states):
                return
            time.sleep(0.05)
        self.fail("tasks did not reach terminal state before timeout")

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
        import app.services.runtime_config_service as runtime_config_module
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
        runtime_config_module._runtime_config_service = None
        task_module._task_service = None
        workspace_module._workspace_service = None
        scheduler_module._scheduler_service = None


if __name__ == "__main__":
    unittest.main()
