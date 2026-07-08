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
from app.service.task_manager import TaskManager, UpstreamError, _now
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

    @staticmethod
    def _origin_fields(json_body: dict[str, object] | None) -> dict[str, object]:
        payload = dict(json_body or {})
        return {
            "task_origin_type": payload.get("task_origin_type"),
            "parent_project_id": payload.get("parent_project_id"),
            "parent_task_id": payload.get("parent_task_id"),
            "parent_task_type": payload.get("parent_task_type"),
            "parent_stage_name": payload.get("parent_stage_name"),
            "parent_stage_item_id": payload.get("parent_stage_item_id"),
            "parent_stage_item_key": payload.get("parent_stage_item_key"),
            "create_dedupe_key": payload.get("create_dedupe_key"),
        }

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

    def _resolve_service_by_task_id(self, task_id: str) -> str:
        if task_id.startswith("sa-"):
            return "system_analyse"
        if task_id.startswith("ea-"):
            return "entry_analyse"
        if task_id.startswith("dfa-"):
            return "dataflow_vuln_scan"
        raise AssertionError(f"unknown mock downstream task_id: {task_id}")

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
                **self._origin_fields(json_body),
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
                **self._origin_fields(json_body),
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
                **self._origin_fields(json_body),
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

        if method == "POST" and path.startswith("/api/app/system-analyse/tasks/") and path.endswith("/restart"):
            task_id = path.split("/")[-2]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = "pending"
            self._status_sequences[task_id] = ["dispatching", "running", "passed"]
            return self._response(method, url, payload, status_code=201)

        if method == "POST" and path.startswith("/api/app/entry-analyse/tasks/") and path.endswith("/restart"):
            task_id = path.split("/")[-2]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = "pending"
            self._status_sequences[task_id] = ["dispatching", "running", "passed"]
            return self._response(method, url, payload, status_code=201)

        if method == "POST" and path.startswith("/api/app/dataflow-vuln-scan/tasks/") and path.endswith("/restart"):
            task_id = path.split("/")[-2]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = "pending"
            payload["analysis_status"] = "queued"
            self._status_sequences[task_id] = ["dispatching", "running", "passed"]
            return self._response(method, url, payload, status_code=201)

        if method == "POST" and path.startswith("/api/app/system-analyse/tasks/") and path.endswith("/cancel"):
            task_id = path.split("/")[-2]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = "cancelling"
            self._status_sequences[task_id] = ["cancelling", "cancelled"]
            return self._response(method, url, payload)

        if method == "POST" and path.startswith("/api/app/entry-analyse/tasks/") and path.endswith("/cancel"):
            task_id = path.split("/")[-2]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = "cancelling"
            self._status_sequences[task_id] = ["cancelling", "cancelled"]
            return self._response(method, url, payload)

        if method == "POST" and path.startswith("/api/app/dataflow-vuln-scan/tasks/") and path.endswith("/cancel"):
            task_id = path.split("/")[-2]
            payload = dict(self._task_payloads[task_id])
            payload["status"] = "cancelling"
            payload["analysis_status"] = "cancelling"
            self._status_sequences[task_id] = ["cancelling", "cancelled"]
            return self._response(method, url, payload)

        if method == "DELETE" and (
            path.startswith("/api/app/system-analyse/tasks/")
            or path.startswith("/api/app/entry-analyse/tasks/")
            or path.startswith("/api/app/dataflow-vuln-scan/tasks/")
        ):
            task_id = path.rsplit("/", 1)[-1]
            service = self._resolve_service_by_task_id(task_id)
            payload = {
                "task_id": task_id,
                "status": "deleted",
                "service": service,
            }
            self._task_payloads.pop(task_id, None)
            self._status_sequences.pop(task_id, None)
            self._system_results.pop(task_id, None)
            self._entry_modules.pop(task_id, None)
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
            archive_root=str(artifact_root) if artifact_root is not None else None,
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
        original_poll_item_helper = self.manager._poll_item_until_local_terminal_or_defer

        async def _poll_item_via_mock_downstream(
            session,
            task,
            item,
            *,
            operation: str,
            response_item: dict[str, object],
            fetcher,
            success_statuses: set[str],
            failure_statuses: set[str],
        ):
            del session, operation, response_item
            status, payload = await self.manager._poll_until_terminal(
                fetcher,
                success_statuses=success_statuses,
                failure_statuses=failure_statuses,
                task=task,
                item=None,
            )
            return status, payload, None

        return [
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: db),
            patch.object(task_manager_module, "get_task_queue", return_value=queue),
            patch.object(downstream_base_module, "get_shared_async_client", new=AsyncMock(return_value=http_client)),
            patch.object(downstream_base_module, "invalidate_shared_async_client", new=AsyncMock(return_value=True)),
            patch.object(self.manager, "_ensure_task_execution_current_async", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_ensure_task_write_ownership", return_value=None),
            patch.object(self.manager, "_drain_owner_inbox_during_polling", new=AsyncMock(return_value=None)),
            patch.object(self.manager, "_is_task_cancelled_async", new=AsyncMock(return_value=False)),
            patch.object(self.manager, "_downstream_child_sync_interval_seconds", return_value=0),
            patch.object(self.manager, "_stage_downstream_sync_backoff_base_seconds", return_value=0),
            patch.object(self.manager, "_queue_archive_and_wait", new=AsyncMock(side_effect=self._queue_archive_passthrough)),
            patch.object(self.manager, "_streaming_mode_enabled", return_value=False),
            patch.object(self.manager, "_poll_item_until_local_terminal_or_defer", side_effect=_poll_item_via_mock_downstream),
        ]

    @contextmanager
    def _patched_runtime(self, db, queue, http_client, *, extra_patches=None):
        with ExitStack() as stack:
            for item in self._runtime_patches(db, queue, http_client):
                stack.enter_context(item)
            for item in list(extra_patches or []):
                stack.enter_context(item)
            yield

    def _drain_created_child_and_sync(self, db, task, item, *, max_sync_rounds: int = 4):
        asyncio.run(
            self.manager._create_downstream_children(
                db,
                project_id=task.project_id,
                task_id=task.id,
                stage_name=item.stage_name,
                item_ids=[str(item.id)],
                force=True,
            )
        )
        for _ in range(max(1, int(max_sync_rounds))):
            asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    stage_name=item.stage_name,
                    item_ids=[str(item.id)],
                    apply_state=True,
                    force=True,
                    record_request_event=False,
                )
            )
            normalized_status = str(getattr(item, "status", "") or "").strip().lower()
            active_error = bool(
                self.manager._string_or_none(dict(getattr(item, "result", {}) or {}).get("last_sync_error_message"))
                or self.manager._string_or_none(dict(dict(getattr(item, "result", {}) or {}).get("sync_observation") or {}).get("error_message"))
            )
            if normalized_status in {
                "success",
                "failed",
                "cancelled",
                "downstream_missing",
                "partial_success",
            } and not active_error:
                break

    def _run_system_item_via_sync_maintenance(self, db, task, firmware):
        system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
        queued_result = asyncio.run(self.manager._run_system_analysis_item(task, system_run, firmware))
        system_item = self.manager._stage_items(db, task.id, "system_analysis")[0]
        self._drain_created_child_and_sync(db, task, system_item)
        return queued_result, self.manager._stage_item_response(task, system_item), system_item, system_run

    def _run_entry_item_via_sync_maintenance(self, db, task, module_payload):
        entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
        queued_result = asyncio.run(self.manager._run_entry_item(task, entry_run, dict(module_payload), token="mock-token"))
        entry_item = self.manager._stage_items(db, task.id, "entry_analysis")[0]
        self._drain_created_child_and_sync(db, task, entry_item)
        return queued_result, self.manager._stage_item_response(task, entry_item), entry_item, entry_run

    def _run_dataflow_item_via_sync_maintenance(self, db, task, entry_payload):
        dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
        queued_result = asyncio.run(self.manager._run_dataflow_item(task, dataflow_run, dict(entry_payload), token="mock-token"))
        dataflow_item = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")[0]
        self._drain_created_child_and_sync(db, task, dataflow_item)
        return queued_result, self.manager._stage_item_response(task, dataflow_item), dataflow_item, dataflow_run

    @staticmethod
    def _response_payload(response):
        if hasattr(response, "model_dump"):
            return response.model_dump(mode="python")
        return dict(response or {})

    @staticmethod
    def _downstream_module_payload(downstream, system_item):
        return dict(downstream._system_results[str(system_item.downstream_task_id or "")]["modules"][0])

    @staticmethod
    def _downstream_entry_payload(downstream, entry_item):
        return dict(downstream._entry_modules[str(entry_item.downstream_task_id or "")]["entries"][0])

    def _normalized_system_module_payload(self, task, item, firmware, downstream) -> dict[str, object]:
        artifact_root = self.manager._service_output_dir(
            task,
            item.downstream_service or item.stage_name,
            item.item_key,
            item.downstream_task_id,
        )
        modules = self.manager._parse_system_analysis_modules(
            artifact_root,
            firmware,
            downstream._system_results[str(item.downstream_task_id or "")],
        )
        return dict(modules[0])

    def _normalized_entry_payload(self, downstream, entry_item) -> dict[str, object]:
        del downstream
        return dict(entry_item.result or {})

    def test_source_workflow_runtime_uses_real_downstream_contracts_with_mocked_db_fs_and_redis(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            with self._patched_runtime(db, queue, http_client):
                _queued_system, system_result, system_item, system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
                module_payload = self._normalized_system_module_payload(task, system_item, firmware, downstream)
                _queued_entry, entry_result, entry_item, entry_run = self._run_entry_item_via_sync_maintenance(db, task, module_payload)
                entry_payload = self._normalized_entry_payload(downstream, entry_item)
                _queued_dataflow, dataflow_result, dataflow_item, _dataflow_run = self._run_dataflow_item_via_sync_maintenance(db, task, entry_payload)

            self._refresh_stage_summary(db, task, "system_analysis")
            self._refresh_stage_summary(db, task, "entry_analysis")
            self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
            self.manager._refresh_system_analysis_stage_from_synced_items(db, task)
            self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
            self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
            self.manager._refresh_task_status_after_sync(db, task)
            detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertEqual("success", system_result.status)
        self.assertEqual("success", entry_result.status)
        self.assertEqual("success", dataflow_result.status)
        self.assertEqual("success", system_item.status)
        self.assertEqual("success", entry_item.status)
        self.assertEqual("success", dataflow_item.status)
        self.assertTrue(bool(system_item.downstream_task_id))
        self.assertTrue(bool(entry_item.downstream_task_id))
        self.assertTrue(bool(dataflow_item.downstream_task_id))
        self.assertEqual(["system_analyse", "entry_analyse", "dataflow_vuln_scan"], [row["service"] for row in downstream.created_tasks])
        self.assertEqual(3, len(db.archive_jobs))
        self.assertTrue(downstream._system_results[str(system_item.downstream_task_id or "")]["modules"])
        self.assertTrue(downstream._entry_modules[str(entry_item.downstream_task_id or "")]["entries"])
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
                with self.assertRaises(UpstreamError):
                    self._drain_created_child_and_sync(db, task, system_item)

        self.assertEqual("queued", result["status"])
        self.assertEqual("queued", system_item.status)
        self.assertFalse(bool(system_item.downstream_task_id))
        observation = dict((system_item.result or {}).get("sync_observation") or {})
        self.assertEqual("UpstreamError", observation.get("error_type"))
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
                _queued_result, result, _system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)

        self.assertEqual("success", result.status)
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
                _queued_system, _system_result, system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
                _queued_entry, result, _entry_item, _entry_run = self._run_entry_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_system_module_payload(task, system_item, firmware, downstream),
                )

        self.assertEqual("success", result.status)
        self.assertGreaterEqual(len([row for row in downstream.calls if row["path"] == "/api/app/entry-analyse/tasks/ea-2"]), 2)

    def test_source_workflow_mock_e2e_entry_authoritative_child_404_becomes_downstream_missing(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            with self._patched_runtime(db, queue, http_client):
                _queued_system, _system_result, system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
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
                    input_ref=self._normalized_system_module_payload(task, system_item, firmware, downstream),
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
                        self._normalized_system_module_payload(task, system_item, firmware, downstream),
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
                _queued_system, _system_result, system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
                _queued_entry, _entry_result, entry_item, _entry_run = self._run_entry_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_system_module_payload(task, system_item, firmware, downstream),
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
                        self._normalized_entry_payload(downstream, entry_item),
                        token="mock-token",
                    )
                )
                item = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")[0]
                self._drain_created_child_and_sync(db, task, item)

        self.assertEqual("queued", result["status"])
        self.assertEqual("failed", item.status)
        self.assertEqual(2, len(db.archive_jobs))

    def test_source_workflow_mock_e2e_dataflow_create_transport_error_defers_without_child_binding(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            request = httpx.Request("POST", "http://dfa/api/app/dataflow-vuln-scan/tasks")
            downstream.queue_override(
                "POST",
                "/api/app/dataflow-vuln-scan/tasks",
                httpx.ConnectError("All connection attempts failed", request=request),
            )
            with self._patched_runtime(db, queue, http_client):
                _queued_system, _system_result, system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
                _queued_entry, _entry_result, entry_item, _entry_run = self._run_entry_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_system_module_payload(task, system_item, firmware, downstream),
                )
                dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
                result = asyncio.run(
                    self.manager._run_dataflow_item(
                        task,
                        dataflow_run,
                        self._normalized_entry_payload(downstream, entry_item),
                        token="mock-token",
                    )
                )
                item = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")[0]
                with self.assertRaises(UpstreamError):
                    self._drain_created_child_and_sync(db, task, item)

        self.assertEqual("queued", result["status"])
        self.assertEqual("queued", item.status)
        self.assertFalse(bool(item.downstream_task_id))
        observation = dict((item.result or {}).get("sync_observation") or {})
        self.assertEqual("UpstreamError", observation.get("error_type"))
        self.assertEqual(2, len(db.archive_jobs))

    def test_source_workflow_mock_e2e_dataflow_poll_transport_error_recovers_and_succeeds(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            request = httpx.Request("GET", "http://dfa/api/app/dataflow-vuln-scan/tasks/dfa-3")
            downstream.queue_override(
                "GET",
                "/api/app/dataflow-vuln-scan/tasks/dfa-3",
                httpx.RemoteProtocolError("Server disconnected without sending a response", request=request),
            )
            with self._patched_runtime(db, queue, http_client):
                _queued_system, _system_result, system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
                _queued_entry, _entry_result, entry_item, _entry_run = self._run_entry_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_system_module_payload(task, system_item, firmware, downstream),
                )
                _queued_dataflow, result, _dataflow_item, _dataflow_run = self._run_dataflow_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_entry_payload(downstream, entry_item),
                )

        self.assertEqual("success", result.status)
        self.assertGreaterEqual(len([row for row in downstream.calls if row["path"] == "/api/app/dataflow-vuln-scan/tasks/dfa-3"]), 2)

    def test_source_workflow_mock_e2e_dataflow_authoritative_child_404_becomes_downstream_missing(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            with self._patched_runtime(db, queue, http_client):
                _queued_system, _system_result, system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
                _queued_entry, _entry_result, entry_item, _entry_run = self._run_entry_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_system_module_payload(task, system_item, firmware, downstream),
                )
                dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
                entry_payload = self._normalized_entry_payload(downstream, entry_item)
                created_item = self.manager._upsert_stage_item(
                    db,
                    task=task,
                    stage_run=dataflow_run,
                    stage_name="dataflow_vuln_scan",
                    item_key=str(entry_payload.get("entry_key") or ""),
                    item_name=str(entry_payload.get("function_name") or ""),
                    parent_key=str(entry_payload.get("module_key") or ""),
                    downstream_service="dataflow_vuln_scan",
                    input_ref=dict(entry_payload),
                    retrying=False,
                    auto_retrying=False,
                )
                created_item.downstream_task_id = "dfa-404"
                downstream.queue_override(
                    "GET",
                    "/api/app/dataflow-vuln-scan/tasks/dfa-404",
                    httpx.Response(
                        200,
                        json={"task_id": "dfa-404", "status": "running", "analysis_status": "running"},
                        request=httpx.Request("GET", "http://dfa/api/app/dataflow-vuln-scan/tasks/dfa-404"),
                    ),
                )
                downstream.queue_override(
                    "GET",
                    "/api/app/dataflow-vuln-scan/tasks/dfa-404",
                    httpx.Response(
                        404,
                        json={"detail": "missing"},
                        request=httpx.Request("GET", "http://dfa/api/app/dataflow-vuln-scan/tasks/dfa-404"),
                    ),
                )
                result = asyncio.run(
                    self.manager._run_dataflow_item(
                        task,
                        dataflow_run,
                        dict(entry_payload),
                        token="mock-token",
                    )
                )

        self.assertEqual("downstream_missing", result["status"])
        self.assertEqual("downstream_missing", created_item.status)
        self.assertGreaterEqual(len(db.archive_jobs), 2)

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
                item = self.manager._stage_items(db, task.id, "system_analysis")[0]
                self._drain_created_child_and_sync(db, task, item)

        self.assertEqual("queued", result["status"])
        self.assertIn(item.status, {"running", "queued"})
        self.assertTrue(any(getattr(job, "archive_status", "") == "failed" for job in db.archive_jobs))

    def test_source_workflow_mock_e2e_control_paths_use_real_downstream_http_contracts(self):
        tmpdir, _root, task, db, queue, downstream, http_client, firmware = self._build_runtime_fixture()
        with tmpdir:
            with self._patched_runtime(db, queue, http_client):
                _queued_system, _system_result, system_item, _system_run = self._run_system_item_via_sync_maintenance(db, task, firmware)
                _queued_entry, _entry_result, entry_item, _entry_run = self._run_entry_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_system_module_payload(task, system_item, firmware, downstream),
                )
                _queued_dataflow, dataflow_result, dataflow_item, _dataflow_run = self._run_dataflow_item_via_sync_maintenance(
                    db,
                    task,
                    self._normalized_entry_payload(downstream, entry_item),
                )

                control = asyncio.run(
                    self.manager._downstream_tasks().control_existing_child(
                        db,
                        stage_name="dataflow_vuln_scan",
                        task=task,
                        item=dataflow_item,
                        token="mock-token",
                    )
                )
                cancelled = asyncio.run(
                    self.manager._downstream_cancel_refs(
                        db,
                        task,
                        [
                            {
                                "service": "entry_analyse",
                                "project_id": task.project_id,
                                "task_id": str(entry_item.downstream_task_id or ""),
                                "stage_name": "entry_analysis",
                            }
                        ],
                        "mock-token",
                    )
                )
                deleted = asyncio.run(
                    self.manager._downstream_delete_refs(
                        db,
                        task,
                        [
                            {
                                "service": "system_analyse",
                                "project_id": task.project_id,
                                "task_id": str(system_item.downstream_task_id or ""),
                                "stage_name": "system_analysis",
                            }
                        ],
                        "mock-token",
                    )
                )

        self.assertEqual("accepted", control["outcome"])
        self.assertEqual("success", dataflow_result.status)
        self.assertEqual(1, cancelled)
        self.assertEqual(1, deleted)
        post_paths = [row["path"] for row in downstream.calls if row["method"] == "POST"]
        delete_paths = [row["path"] for row in downstream.calls if row["method"] == "DELETE"]
        self.assertIn(f"/api/app/dataflow-vuln-scan/tasks/{dataflow_item.downstream_task_id}/restart", post_paths)
        self.assertIn(f"/api/app/entry-analyse/tasks/{entry_item.downstream_task_id}/cancel", post_paths)
        self.assertIn(f"/api/app/system-analyse/tasks/{system_item.downstream_task_id}", delete_paths)
        event_types = [getattr(event, "event_type", "") for event in db.events]
        self.assertIn("child_task_retry_requested", event_types)
        self.assertIn("child_task_retry_accepted", event_types)
        self.assertIn("child_task_cancel_requested", event_types)
        self.assertIn("child_task_cancel_succeeded", event_types)
        self.assertIn("child_task_delete_requested", event_types)
        self.assertIn("child_task_delete_succeeded", event_types)
