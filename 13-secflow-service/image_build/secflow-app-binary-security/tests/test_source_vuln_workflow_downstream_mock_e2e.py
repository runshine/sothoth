import asyncio
from contextlib import ExitStack, contextmanager
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import AsyncMock, patch

import httpx

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityTask,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_SOURCE,
)
from app.service import downstream_base as downstream_base_module
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _FakeTaskSyncQueue


def _source_task(*, project_root: Path, runtime_root: Path) -> BinarySecurityTask:
    task_suffix = uuid.uuid4().hex[:12]
    task = BinarySecurityTask(
        id=f"task-source-mock-e2e-{task_suffix}",
        project_id="project-mock-e2e",
        name="source-vuln-mock-e2e",
        status="running",
        task_type=TASK_TYPE_SOURCE,
        current_stage="system_analysis",
        firmware_source="project_filesystem",
        firmware_path=str(project_root),
        output_root=str(runtime_root / "output"),
        workspace_root=str(runtime_root / "workspace"),
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        started_at=_now(),
    )
    task.summary = {"input_dir": str(project_root)}
    return task


class _MockDownstreamAsyncClient:
    def __init__(self, service: "_MockGaiaSourceDownstreamService"):
        self._service = service
        self.is_closed = False

    async def get(self, url, headers=None, params=None):
        return self._service.handle("GET", url, headers=headers, params=params)

    async def post(self, url, headers=None, json=None):
        return self._service.handle("POST", url, headers=headers, json_body=json)

    async def delete(self, url, headers=None):
        return self._service.handle("DELETE", url, headers=headers)

    async def aclose(self):
        self.is_closed = True


class _MockGaiaSourceDownstreamService:
    def __init__(self, root: Path, project_root: Path):
        self.root = root
        self.project_root = project_root
        self.calls: list[dict[str, object]] = []
        self.created_tasks: list[dict[str, object]] = []
        self._status_sequences: dict[str, list[str]] = {}
        self._task_payloads: dict[str, dict[str, object]] = {}
        self._system_results: dict[str, dict[str, object]] = {}
        self._entry_modules: dict[str, dict[str, object]] = {}
        self._one_shot_overrides: dict[tuple[str, str], list[object]] = {}

    def _response(self, method: str, url: str, payload: dict[str, object], status_code: int = 200) -> httpx.Response:
        return httpx.Response(status_code, json=payload, request=httpx.Request(method, url))

    def _record(self, method: str, path: str, *, headers=None, params=None, json_body=None) -> None:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "headers": dict(headers or {}),
                "params": dict(params or {}),
                "json_body": dict(json_body or {}),
            }
        )

    def queue_override(self, method: str, path: str, override: object) -> None:
        key = (method.upper(), path)
        self._one_shot_overrides.setdefault(key, []).append(override)

    def _pop_override(self, method: str, path: str, url: str) -> httpx.Response | None:
        key = (method.upper(), path)
        overrides = self._one_shot_overrides.get(key) or []
        if not overrides:
            return None
        override = overrides.pop(0)
        if callable(override):
            override = override(url)
        if isinstance(override, Exception):
            raise override
        if isinstance(override, httpx.Response):
            return override
        raise AssertionError(f"unsupported override payload: {override!r}")

    def _next_status(self, task_id: str) -> str:
        sequence = self._status_sequences.setdefault(task_id, ["passed"])
        if len(sequence) > 1:
            return sequence.pop(0)
        return sequence[0]

    def _build_system_output(self, task_id: str) -> tuple[Path, dict[str, object]]:
        output_dir = self.root / "system-analyse" / task_id / "output"
        module_dir = output_dir / "modules" / "mod-a"
        module_dir.mkdir(parents=True, exist_ok=True)
        (module_dir / "files.list").write_text("mod-a.c\n", encoding="utf-8")
        (module_dir / "module_report.md").write_text("# mod-a\n", encoding="utf-8")
        result = {
            "modules": [
                {
                    "module_name": "mod-a",
                    "module_dir_path": str(module_dir),
                    "files_list_path": str(module_dir / "files.list"),
                    "module_report_path": str(module_dir / "module_report.md"),
                    "risk_level": "高",
                    "risk_score": 95,
                    "rank": 1,
                }
            ]
        }
        (output_dir / "system-result.json").write_text(json.dumps(result), encoding="utf-8")
        return output_dir, result

    def _build_entry_output(self, task_id: str, module_name: str) -> tuple[Path, dict[str, object]]:
        output_dir = self.root / "entry-analyse" / task_id / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        entry_payload = {
            "entries": [
                {
                    "function_name": "mod_a_entry",
                    "file_name": "mod-a.c",
                    "line_no": "12",
                    "definition_file": "mod-a.c",
                    "definition_line": "12",
                    "taint_params": ["request"],
                    "function_description": "entry point",
                    "entry_reason": "reachable external input",
                    "module_name": module_name,
                }
            ]
        }
        (output_dir / "entry-details.json").write_text(json.dumps(entry_payload), encoding="utf-8")
        return output_dir, entry_payload

    def _build_dataflow_output(self, task_id: str) -> Path:
        output_dir = self.root / "dataflow-vuln-scan" / task_id / "output" / "dataflow"
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "final_report.md").write_text(
            "# Dataflow Result\n\n- reachable taint path found\n",
            encoding="utf-8",
        )
        return output_dir.parent

    def handle(self, method: str, url: str, *, headers=None, params=None, json_body=None) -> httpx.Response:
        path = urlsplit(url).path
        self._record(method, path, headers=headers, params=params, json_body=json_body)
        overridden = self._pop_override(method, path, url)
        if overridden is not None:
            return overridden

        if method == "POST" and path == "/api/app/system-analyse/tasks":
            task_id = f"sa-{len(self.created_tasks) + 1}"
            output_dir, result = self._build_system_output(task_id)
            payload = {
                "task_id": task_id,
                "status": "pending",
                "output_path": str(output_dir),
            }
            self._status_sequences[task_id] = ["running", "passed"]
            self._task_payloads[task_id] = payload
            self._system_results[task_id] = result
            self.created_tasks.append({"service": "system_analyse", "task_id": task_id, "request": dict(json_body or {})})
            return self._response(method, url, payload)

        if method == "GET" and path.startswith("/api/app/system-analyse/tasks/") and path.endswith("/result"):
            task_id = path.split("/")[-2]
            return self._response(method, url, self._system_results[task_id])

        if method == "GET" and path.startswith("/api/app/system-analyse/tasks/"):
            task_id = path.rsplit("/", 1)[-1]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = self._next_status(task_id)
            return self._response(method, url, payload)

        if method == "POST" and path == "/api/app/entry-analyse/tasks":
            task_id = f"ea-{len(self.created_tasks) + 1}"
            module_name = str((json_body or {}).get("module_name") or "module")
            output_dir, entry_payload = self._build_entry_output(task_id, module_name)
            payload = {
                "task_id": task_id,
                "status": "pending",
                "output_path": str(output_dir),
            }
            self._status_sequences[task_id] = ["running", "passed"]
            self._task_payloads[task_id] = payload
            self._entry_modules[task_id] = entry_payload
            self.created_tasks.append({"service": "entry_analyse", "task_id": task_id, "request": dict(json_body or {})})
            return self._response(method, url, payload)

        if method == "GET" and path.startswith("/api/app/entry-analyse/tasks/"):
            task_id = path.rsplit("/", 1)[-1]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = self._next_status(task_id)
            return self._response(method, url, payload)

        if method == "POST" and path == "/api/app/dataflow-vuln-scan/tasks":
            task_id = f"dfa-{len(self.created_tasks) + 1}"
            output_dir = self._build_dataflow_output(task_id)
            payload = {
                "task_id": task_id,
                "status": "pending",
                "output_path": str(output_dir),
                "analysis_status": "queued",
            }
            self._status_sequences[task_id] = ["running", "passed"]
            self._task_payloads[task_id] = payload
            self.created_tasks.append({"service": "dataflow_vuln_scan", "task_id": task_id, "request": dict(json_body or {})})
            return self._response(method, url, payload)

        if method == "GET" and path.startswith("/api/app/dataflow-vuln-scan/tasks/"):
            task_id = path.rsplit("/", 1)[-1]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = self._next_status(task_id)
            payload["analysis_status"] = "finished"
            return self._response(method, url, payload)

        return self._response(method, url, {"error": f"unexpected downstream request: {method} {path}"}, status_code=404)


class SourceWorkflowDownstreamMockE2ETests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.manager.instance_id = "worker-mock-e2e"
        self.manager._enqueue_task = lambda *_args, **_kwargs: None

    def _refresh_stage_summary(self, db, task, stage_name: str) -> None:
        handler = self.manager._stage_handler(stage_name)
        if handler is not None:
            handler.refresh_summary_from_items(self.manager, db, task)

    async def _queue_archive_passthrough(self, db, task, item, *, payload, mapped_status, before_status):
        del before_status
        candidates = self.manager._resolve_downstream_output_sources(
            payload,
            downstream_task_id=item.downstream_task_id,
            task=task,
            downstream_service=item.downstream_service,
        )
        artifact_root = next((path for path in candidates if path.exists()), None)
        archive_job = BinarySecurityArchiveJob(
            id=f"archive-{item.id}",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=item.stage_name,
            item_id=item.id,
            item_key=item.item_key,
            downstream_service=item.downstream_service,
            downstream_task_id=item.downstream_task_id,
            archive_status="archived" if artifact_root is not None else "failed",
        )
        archive_job.payload = {
            "mapped_status": mapped_status,
            "downstream_payload": dict(payload or {}),
            "artifact_root": str(artifact_root) if artifact_root is not None else None,
        }
        db.archive_jobs.append(archive_job)
        return artifact_root, archive_job

    def _build_source_project(self, root: Path) -> Path:
        project_root = root / "source-project"
        module_dir = project_root / "mod-a"
        module_dir.mkdir(parents=True, exist_ok=True)
        (module_dir / "mod-a.c").write_text(
            "int mod_a_entry(int request) { return request; }\n",
            encoding="utf-8",
        )
        (module_dir / "files.list").write_text("mod-a.c\n", encoding="utf-8")
        return project_root

    def _build_runtime_fixture(self):
        tmpdir = tempfile.TemporaryDirectory()
        root = Path(tmpdir.name)
        project_root = self._build_source_project(root)
        runtime_root = root / "runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        task = _source_task(project_root=project_root, runtime_root=runtime_root)
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[], stage_items=[], archive_jobs=[], events=[])
        queue = _FakeTaskSyncQueue()
        downstream = _MockGaiaSourceDownstreamService(root / "mock-downstream", project_root)
        http_client = _MockDownstreamAsyncClient(downstream)
        firmware = {
            "firmware_key": "source-project",
            "firmware_name": "source-project",
            "filename": "source-project",
            "unpacked_root": str(project_root),
            "source_root": str(project_root),
            "task_type": TASK_TYPE_SOURCE,
        }
        return tmpdir, root, task, db, queue, downstream, http_client, firmware

    def _runtime_patches(self, db, queue, http_client):
        return [
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: db),
            patch.object(task_manager_module, "get_task_queue", return_value=queue),
            patch.object(downstream_base_module, "get_shared_async_client", new=AsyncMock(return_value=http_client)),
            patch.object(downstream_base_module, "invalidate_shared_async_client", new=AsyncMock(return_value=True)),
            patch.object(self.manager, "_ensure_task_execution_current_async", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_drain_owner_inbox_during_polling", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_touch_task_heartbeat_async", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_is_task_cancelled_async", new=AsyncMock(return_value=False)),
            patch.object(self.manager, "_downstream_child_sync_interval_seconds", return_value=0),
            patch.object(self.manager, "_stage_downstream_sync_backoff_base_seconds", return_value=0),
            patch.object(self.manager, "_queue_archive_and_wait", new=AsyncMock(side_effect=self._queue_archive_passthrough)),
            patch.object(self.manager, "_streaming_mode_enabled", return_value=False),
        ]

    @contextmanager
    def _patched_runtime(self, db, queue, http_client, *, extra_patches=None):
        with ExitStack() as stack:
            for item in self._runtime_patches(db, queue, http_client):
                stack.enter_context(item)
            for item in list(extra_patches or []):
                stack.enter_context(item)
            yield

    def test_source_workflow_runtime_uses_real_downstream_contracts_with_mocked_db_fs_and_redis(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            with self._patched_runtime(db, queue, http_client):
                system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
                system_result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))
                system_item = self.manager._stage_items(db, task.id, "system_analysis")[0]
                entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
                module_payload = dict((system_result.get("item") or {}).get("modules")[0])
                entry_result = asyncio.run(self.manager._run_entry_item(task, entry_run, module_payload, token="mock-token"))
                entry_item = self.manager._stage_items(db, task.id, "entry_analysis")[0]

                dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
                entry_payload = dict((entry_result.get("item") or {}).get("entries")[0])
                dataflow_result = asyncio.run(self.manager._run_dataflow_item(task, dataflow_run, entry_payload, token="mock-token"))
                dataflow_item = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")[0]

            self._refresh_stage_summary(db, task, "system_analysis")
            self._refresh_stage_summary(db, task, "entry_analysis")
            self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
            self.manager._refresh_system_analysis_stage_from_synced_items(db, task)
            self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
            self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
            self.manager._refresh_task_status_after_sync(db, task)
            detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertEqual("success", system_result["status"])
        self.assertEqual("success", entry_result["status"])
        self.assertEqual("success", dataflow_result["status"])
        self.assertEqual("success", system_item.status)
        self.assertEqual("success", entry_item.status)
        self.assertEqual("success", dataflow_item.status)
        self.assertEqual(["system_analyse", "entry_analyse", "dataflow_vuln_scan"], [row["service"] for row in downstream.created_tasks])
        self.assertEqual(3, len(db.archive_jobs))
        self.assertTrue((system_result.get("item") or {}).get("modules"))
        self.assertTrue((entry_result.get("item") or {}).get("entries"))
        self.assertTrue((dataflow_result.get("item") or {}).get("dataflow_dir"))
        self.assertTrue((task.summary or {}).get("entry_results"))
        self.assertTrue((task.summary or {}).get("dataflow_results"))
        self.assertIn(detail.status, {"running", "success"})
        self.assertIn(
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "system_analysis"),
            {"running", "success"},
        )
        self.assertIn(
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "entry_analysis"),
            {"running", "success"},
        )
        self.assertIn(
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
            {"running", "success"},
        )
        get_paths = [row["path"] for row in downstream.calls if row["method"] == "GET"]
        self.assertTrue(any(path.endswith("/result") for path in get_paths))
        self.assertGreaterEqual(
            len([row for row in downstream.calls if row["method"] == "POST"]),
            3,
        )

    def test_source_workflow_mock_e2e_system_create_transport_error_defers_parent_without_child_binding(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            request = httpx.Request("POST", "http://system/api/app/system-analyse/tasks")
            downstream.queue_override(
                "POST",
                "/api/app/system-analyse/tasks",
                httpx.ConnectError("All connection attempts failed", request=request),
            )
            with self._patched_runtime(db, queue, http_client):
                system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
                result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))
                system_item = self.manager._stage_items(db, task.id, "system_analysis")[0]

        self.assertEqual("pending", result["status"])
        self.assertEqual("pending", system_item.status)
        self.assertFalse(bool(system_item.downstream_task_id))
        self.assertIn("无法连接下游服务", str(result.get("error") or ""))
        self.assertEqual(0, len(db.archive_jobs))

    def test_source_workflow_mock_e2e_system_success_tolerates_result_fetch_failure(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            request = httpx.Request("GET", "http://system/api/app/system-analyse/tasks/sa-1/result")
            downstream.queue_override(
                "GET",
                "/api/app/system-analyse/tasks/sa-1/result",
                httpx.ReadTimeout("timed out", request=request),
            )
            with self._patched_runtime(db, queue, http_client):
                system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
                result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))

        self.assertEqual("success", result["status"])
        self.assertTrue((result.get("item") or {}).get("modules"))
        self.assertEqual(1, len(db.archive_jobs))

    def test_source_workflow_mock_e2e_entry_poll_transport_error_recovers_and_succeeds(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            request = httpx.Request("GET", "http://entry/api/app/entry-analyse/tasks/ea-2")
            downstream.queue_override(
                "GET",
                "/api/app/entry-analyse/tasks/ea-2",
                httpx.RemoteProtocolError("Server disconnected without sending a response", request=request),
            )
            with self._patched_runtime(db, queue, http_client):
                system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
                system_result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))
                entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
                result = asyncio.run(
                    self.manager._run_entry_item(
                        task,
                        entry_run,
                        dict((system_result.get("item") or {}).get("modules")[0]),
                        token="mock-token",
                    )
                )

        self.assertEqual("success", result["status"])
        self.assertGreaterEqual(len([row for row in downstream.calls if row["path"] == "/api/app/entry-analyse/tasks/ea-2"]), 2)

    def test_source_workflow_mock_e2e_entry_authoritative_child_404_becomes_downstream_missing(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            with self._patched_runtime(db, queue, http_client):
                system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
                system_result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))
                entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
                created_item = self.manager._upsert_stage_item(
                    db,
                    task=task,
                    stage_run=entry_run,
                    stage_name="entry_analysis",
                    item_key="source-project-mod-a",
                    item_name="mod-a",
                    parent_key="source-project",
                    downstream_service="entry_analyse",
                    input_ref=dict((system_result.get("item") or {}).get("modules")[0]),
                    retrying=False,
                    auto_retrying=False,
                )
                created_item.downstream_task_id = "ea-404"
                downstream.queue_override(
                    "GET",
                    "/api/app/entry-analyse/tasks/ea-404",
                    httpx.Response(
                        200,
                        json={"task_id": "ea-404", "status": "running"},
                        request=httpx.Request("GET", "http://entry/api/app/entry-analyse/tasks/ea-404"),
                    ),
                )
                downstream.queue_override(
                    "GET",
                    "/api/app/entry-analyse/tasks/ea-404",
                    httpx.Response(
                        404,
                        json={"detail": "missing"},
                        request=httpx.Request("GET", "http://entry/api/app/entry-analyse/tasks/ea-404"),
                    ),
                )
                result = asyncio.run(
                    self.manager._run_entry_item(
                        task,
                        entry_run,
                        dict((system_result.get("item") or {}).get("modules")[0]),
                        token="mock-token",
                    )
                )

        self.assertEqual("downstream_missing", result["status"])
        self.assertEqual("downstream_missing", created_item.status)
        self.assertEqual(2, len(db.archive_jobs))

    def test_source_workflow_mock_e2e_dataflow_invalid_input_fails_without_recovery(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            with self._patched_runtime(db, queue, http_client):
                system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
                system_result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))
                entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
                entry_result = asyncio.run(
                    self.manager._run_entry_item(
                        task,
                        entry_run,
                        dict((system_result.get("item") or {}).get("modules")[0]),
                        token="mock-token",
                    )
                )
                downstream.queue_override(
                    "GET",
                    "/api/app/dataflow-vuln-scan/tasks/dfa-3",
                    httpx.Response(
                        200,
                        json={"task_id": "dfa-3", "status": "invalid_input", "analysis_status": "invalid_input"},
                        request=httpx.Request("GET", "http://dfa/api/app/dataflow-vuln-scan/tasks/dfa-3"),
                    ),
                )
                dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
                result = asyncio.run(
                    self.manager._run_dataflow_item(
                        task,
                        dataflow_run,
                        dict((entry_result.get("item") or {}).get("entries")[0]),
                        token="mock-token",
                    )
                )
                item = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")[0]

        self.assertEqual("failed", result["status"])
        self.assertEqual("failed", item.status)
        self.assertEqual(3, len(db.archive_jobs))

    def test_source_workflow_mock_e2e_archive_blocked_when_downstream_output_missing(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            async def _missing_archive(db_arg, task_arg, item_arg, *, payload, mapped_status, before_status):
                del db_arg, task_arg, before_status
                archive_job = BinarySecurityArchiveJob(
                    id=f"archive-missing-{item_arg.id}",
                    task_id=task.id,
                    project_id=task.project_id,
                    stage_name=item_arg.stage_name,
                    item_id=item_arg.id,
                    item_key=item_arg.item_key,
                    downstream_service=item_arg.downstream_service,
                    downstream_task_id=item_arg.downstream_task_id,
                    archive_status="failed",
                    error_message="artifact root missing",
                )
                archive_job.payload = {"mapped_status": mapped_status, "downstream_payload": dict(payload or {})}
                db.archive_jobs.append(archive_job)
                return None, archive_job

            with self._patched_runtime(
                db,
                queue,
                http_client,
                extra_patches=[
                    patch.object(self.manager, "_queue_archive_and_wait", new=AsyncMock(side_effect=_missing_archive)),
                ],
            ):
                system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
                result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))

        self.assertEqual("archive_blocked", result["status"])
        self.assertTrue(result["archive_blocked"])
        self.assertEqual("artifact root missing", result["error"])
