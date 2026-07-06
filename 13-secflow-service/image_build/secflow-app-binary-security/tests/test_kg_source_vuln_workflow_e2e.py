import asyncio
import json
import os
import shutil
import tempfile
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from app.exception import NotFoundError
from app.model import (
    PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from tests.test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


def _kg_source_task(*, summary=None, policy_json=None) -> BinarySecurityTask:
    task_suffix = uuid.uuid4().hex[:12]
    task = BinarySecurityTask(
        id=f"task-kg-source-e2e-{task_suffix}",
        project_id="project-1",
        name="kg-source-vuln-e2e",
        status="running",
        task_type=TASK_TYPE_SOURCE,
        current_stage="knowledge_graph_entry_fetch",
        firmware_source="project_filesystem",
        firmware_path="/tmp/source-project",
        output_root=f"/tmp/bs-kg-out-{task_suffix}",
        workspace_root=f"/tmp/bs-kg-ws-{task_suffix}",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        started_at=_now(),
    )
    task.summary = dict(summary or {})
    if policy_json is not None:
        task.policy_json = policy_json
    return task


class KgSourceWorkflowE2ETests(unittest.TestCase):
    def setUp(self):
        self._original_workspace_guard_env = os.environ.get("BINARY_SECURITY_DISABLE_WORKSPACE_DELETE_GUARD_DB_LOOKUP")
        os.environ["BINARY_SECURITY_DISABLE_WORKSPACE_DELETE_GUARD_DB_LOOKUP"] = "1"
        self.manager = TaskManager()
        self.manager.instance_id = "worker-a"
        self.manager._enqueue_task = lambda *_args, **_kwargs: None

    def tearDown(self):
        if self._original_workspace_guard_env is None:
            os.environ.pop("BINARY_SECURITY_DISABLE_WORKSPACE_DELETE_GUARD_DB_LOOKUP", None)
        else:
            os.environ["BINARY_SECURITY_DISABLE_WORKSPACE_DELETE_GUARD_DB_LOOKUP"] = self._original_workspace_guard_env

    def _make_archive_job(
        self,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        downstream_service: str,
        downstream_task_id: str,
        mapped_status: str = "success",
    ) -> BinarySecurityArchiveJob:
        job = BinarySecurityArchiveJob(
            id=f"aj-{item.id}",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=item.stage_name,
            item_id=item.id,
            item_key=item.item_key,
            downstream_service=downstream_service,
            downstream_task_id=downstream_task_id,
            archive_status="archived",
        )
        job.payload = {
            "mapped_status": mapped_status,
            "bound_downstream_task_id": downstream_task_id,
            "downstream_payload": {"task_id": downstream_task_id, "status": mapped_status},
        }
        return job

    def _noop_manager_side_effects(self):
        async def _noop_write(*_args, **_kwargs):
            return None

        async def _noop_refresh_terminal(*_args, **_kwargs):
            return None

        return _noop_write, _noop_refresh_terminal

    def _apply_archive_and_reconcile(self, db: _ModelAwareDb, task: BinarySecurityTask, archive_job: BinarySecurityArchiveJob):
        signal_snapshots: list[dict[str, object]] = []
        original_write = self.manager._write_task_metadata_async
        original_refresh = self.manager._refresh_terminal_item_result_from_downstream
        noop_write, noop_refresh = self._noop_manager_side_effects()
        self.manager._write_task_metadata_async = noop_write
        self.manager._refresh_terminal_item_result_from_downstream = noop_refresh
        try:
            asyncio.run(self.manager._apply_archive_job_status_locked(db, archive_job.id, f"/tmp/{archive_job.id}"))
            runtime_workset = dict((task.summary or {}).get("runtime_workset") or {})
            signal = dict(runtime_workset.get("pending_task_layer_reconcile") or {})
            if signal:
                signal_snapshots.append(dict(signal))
                asyncio.run(self.manager._run_task_layer_reconcile_signal(db, task, signal=signal))
        finally:
            self.manager._write_task_metadata_async = original_write
            self.manager._refresh_terminal_item_result_from_downstream = original_refresh
        return signal_snapshots

    def _persist_stage_item_result(self, item: BinarySecurityStageItem, *, payload: dict):
        item.result = dict(payload)

    def _refresh_stage_summary(self, db: _ModelAwareDb, task: BinarySecurityTask, stage_name: str) -> None:
        handler = self.manager._stage_handler(stage_name)
        if handler is not None:
            handler.refresh_summary_from_items(self.manager, db, task)

    def _kg_fetch_task(self, input_dir: str) -> BinarySecurityTask:
        task = _kg_source_task(
            summary={
                "input_dir": input_dir,
                "pipeline_profile": PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
            },
            policy_json=json.dumps(
                {
                    "pipeline_mode": "mixed_streaming",
                    "pipeline_profile": PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
                    "knowledge_graph_upload_id": "upload-e2e-1",
                    "entry_selection_mode": "auto",
                    "entry_auto_selection_strategy": "all",
                }
            ),
        )
        task.policy = {
            "pipeline_mode": "mixed_streaming",
            "pipeline_profile": PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
            "knowledge_graph_upload_id": "upload-e2e-1",
            "entry_selection_mode": "auto",
            "entry_auto_selection_strategy": "all",
        }
        return task

    def _kg_entries(self, input_dir: Path) -> list[dict]:
        return [
            {
                "entry_key": "src-1",
                "source_id": "src-1",
                "function_name": "sink",
                "raw_function_name": "sink",
                "source_file": "src/main.c",
                "definition_file": "src/main.c",
                "definition_line": 42,
                "line_no": 42,
                "definition_kind": "unknown",
                "is_definition_found": True,
                "source_file_exists": True,
                "entry_execution_status": "ready",
                "entry_execution_reason": "source file is accessible",
                "function_description": "sink",
                "entry_reason": "channel=http",
                "module_key": "knowledge_graph_source_project",
                "module_name": "source-project",
                "source_root_path": str(input_dir),
                "source_root": str(input_dir),
                "source_dir": str(input_dir),
                "module_input_path": str(input_dir),
                "module_dir": str(input_dir),
                "descriptor_root": str(input_dir),
                "task_type": TASK_TYPE_SOURCE,
                "taint_params": [],
                "taint_details": [],
                "confidence": "high",
            },
            {
                "entry_key": "src-2",
                "source_id": "src-2",
                "function_name": "helper",
                "raw_function_name": "helper",
                "source_file": "src/main.c",
                "definition_file": "src/main.c",
                "definition_line": 18,
                "line_no": 18,
                "definition_kind": "unknown",
                "is_definition_found": True,
                "source_file_exists": True,
                "entry_execution_status": "ready",
                "entry_execution_reason": "source file is accessible",
                "function_description": "helper",
                "entry_reason": "channel=http",
                "module_key": "knowledge_graph_source_project",
                "module_name": "source-project",
                "source_root_path": str(input_dir),
                "source_root": str(input_dir),
                "source_dir": str(input_dir),
                "module_input_path": str(input_dir),
                "module_dir": str(input_dir),
                "descriptor_root": str(input_dir),
                "task_type": TASK_TYPE_SOURCE,
                "taint_params": [],
                "taint_details": [],
                "confidence": "medium",
            },
        ]

    def _kg_meta(self, **overrides) -> dict:
        base = {
            "entries_url": "http://codemap-manager.secflow-ns.svc.cluster.local:8090/uploads/upload-e2e-1/audit/sources",
            "lookup_mode": "upload_id",
            "upload_id": "upload-e2e-1",
            "db_name": None,
            "graph_status": "active",
            "identification_state": "done",
            "attack_status": "ok",
            "analysis": {"total": 2, "identified": 2, "pending": 0, "confirmed": 0, "rejected": 0},
            "raw_entry_count": 2,
            "selected_entry_count": 2,
            "filtered_out_count": 0,
            "returned_item_count": 2,
            "duration_ms": 25,
        }
        base.update(overrides)
        return base

    def _materialize_dataflow_items(self, db: _ModelAwareDb, task: BinarySecurityTask, dataflow_run: BinarySecurityStageRun) -> list[BinarySecurityStageItem]:
        for entry in self.manager._effective_entry_inputs(task, db):
            self.manager._upsert_stage_item(
                db,
                task=task,
                stage_run=dataflow_run,
                stage_name="dataflow_vuln_scan",
                item_key=str(entry.get("entry_key") or "").strip(),
                item_name=str(entry.get("function_name") or "").strip() or None,
                parent_key=str(entry.get("module_key") or "").strip() or None,
                downstream_service="dataflow_vuln_scan",
                input_ref=dict(entry),
                retrying=False,
                auto_retrying=False,
            )
        return self.manager._stage_items(db, task.id, "dataflow_vuln_scan")

    def _finalize_dataflow_success(self, db: _ModelAwareDb, task: BinarySecurityTask, dataflow_run: BinarySecurityStageRun) -> None:
        for item in self.manager._stage_items(db, task.id, "dataflow_vuln_scan"):
            item.status = "success"
            item.downstream_task_id = f"df-{item.item_key}"
            item.downstream_service = "dataflow_vuln_scan"
            self._persist_stage_item_result(
                item,
                payload={
                    "entry_key": item.item_key,
                    "function_name": item.item_name,
                    "module_key": str(item.parent_key or "").strip() or "knowledge_graph_source_project",
                    "module_name": "source-project",
                    "verdict": "clean",
                    "vulns": [],
                },
            )
            db.archive_jobs.append(
                self._make_archive_job(
                    task=task,
                    item=item,
                    downstream_service="dataflow_vuln_scan",
                    downstream_task_id=f"df-{item.item_key}",
                )
            )
        for job in [row for row in db.archive_jobs if row.stage_name == "dataflow_vuln_scan"]:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                self._apply_archive_and_reconcile(db, task, job)
        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "knowledge_graph_entry_fetch")
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

    def test_kg_source_vuln_workflow_e2e_happy_path(self):
        workspace_root = Path(tempfile.mkdtemp(prefix="kg-source-workflow-e2e-"))
        try:
            input_dir = workspace_root / "input"
            (input_dir / "src").mkdir(parents=True, exist_ok=True)
            (input_dir / "src" / "main.c").write_text("int sink(void) { return 0; }\nint helper(void) { return 1; }\n", encoding="utf-8")

            task = self._kg_fetch_task(str(input_dir))

            kg_run = BinarySecurityStageRun(
                id="sr-kg-e2e",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="knowledge_graph_entry_fetch",
                sequence_no=1,
                status="running",
                started_at=_now(),
            )
            db = _ModelAwareDb(tasks=[task], stage_runs=[kg_run], stage_items=[], archive_jobs=[], events=[])

            async def _fake_fetch(_task):
                return self._kg_entries(input_dir), self._kg_meta()

            self.manager._fetch_knowledge_graph_entry_results = _fake_fetch

            kg_status, kg_summary = asyncio.run(
                self.manager._stage_knowledge_graph_entry_fetch(db, task, kg_run, token=None, retry_existing=False)
            )

            self.assertEqual("success", kg_status)
            self.assertEqual(2, kg_summary["success_count"])
            self.assertEqual(2, task.metrics["knowledge_graph_selected_entry_count"])
            self.assertEqual(2, task.metrics["entry_count"])
            self.assertEqual("success", task.summary["entry_results"][0]["completion_state"])
            self.assertEqual("knowledge_graph_module", task.summary["entry_results"][0]["module_kind"])
            self.assertEqual(
                ["src-1", "src-2"],
                [entry["entry_key"] for entry in self.manager._effective_entry_inputs(task, db)],
            )

            kg_run.status = "success"
            kg_run.finished_at = _now()
            task.current_stage = "dataflow_vuln_scan"

            dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
            dataflow_items = self._materialize_dataflow_items(db, task, dataflow_run)
            self.assertEqual(2, len(dataflow_items))
            self._finalize_dataflow_success(db, task, dataflow_run)

            detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
            self.assertEqual("success", task.status)
            self.assertEqual(task.status, detail.status)
            self.assertEqual("terminal", task.runtime_phase)
            self.assertEqual(2, len((task.summary or {}).get("knowledge_graph_entry_results") or []))
            self.assertEqual(1, len((task.summary or {}).get("entry_results") or []))
            self.assertEqual(2, len((task.summary or {}).get("dataflow_results") or []))
            self.assertEqual(2, len((task.summary or {}).get("vuln_results") or []))
            self.assertTrue(any(event.event_type == "knowledge_graph_entry_fetch_succeeded" for event in db.events))
            self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
            self.assertEqual(
                "success",
                next(summary.status for summary in detail.stage_summaries if summary.stage_name == "knowledge_graph_entry_fetch"),
            )
            self.assertEqual(
                "success",
                next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
            )
        finally:
            shutil.rmtree(workspace_root, ignore_errors=True)

    def test_kg_source_vuln_workflow_e2e_waits_for_graph_then_resumes_success(self):
        workspace_root = Path(tempfile.mkdtemp(prefix="kg-source-workflow-wait-"))
        try:
            input_dir = workspace_root / "input"
            (input_dir / "src").mkdir(parents=True, exist_ok=True)
            (input_dir / "src" / "main.c").write_text("int sink(void) { return 0; }\n", encoding="utf-8")
            task = self._kg_fetch_task(str(input_dir))
            kg_run = BinarySecurityStageRun(
                id="sr-kg-wait-e2e",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="knowledge_graph_entry_fetch",
                sequence_no=1,
                status="running",
                started_at=_now(),
            )
            db = _ModelAwareDb(tasks=[task], stage_runs=[kg_run], stage_items=[], archive_jobs=[], events=[])
            responses = iter(
                [
                    (
                        [],
                        self._kg_meta(
                            graph_status="building",
                            identification_state="running",
                            attack_status="running",
                            analysis={"total": 0, "identified": 0, "pending": 0, "confirmed": 0, "rejected": 0},
                            raw_entry_count=0,
                            selected_entry_count=0,
                            returned_item_count=0,
                        ),
                    ),
                    (self._kg_entries(input_dir), self._kg_meta()),
                ]
            )

            async def _fake_fetch(_task):
                return next(responses)

            self.manager._fetch_knowledge_graph_entry_results = _fake_fetch
            sleep_calls: list[int] = []

            async def _fake_sleep(seconds):
                sleep_calls.append(int(seconds))

            with patch("app.service.task_manager.asyncio.sleep", new=_fake_sleep):
                first_status, first_summary = asyncio.run(
                    self.manager._stage_knowledge_graph_entry_fetch(db, task, kg_run, token=None, retry_existing=False)
                )
            self.assertEqual("success", first_status)
            self.assertEqual(2, first_summary["success_count"])
            self.assertEqual([20], sleep_calls)
            event_types = [event.event_type for event in db.events]
            self.assertIn("knowledge_graph_entry_fetch_retry_scheduled", event_types)
            kg_run.status = "success"
            kg_run.finished_at = _now()
            task.current_stage = "dataflow_vuln_scan"
            dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
            self.assertEqual(2, len(self._materialize_dataflow_items(db, task, dataflow_run)))
        finally:
            shutil.rmtree(workspace_root, ignore_errors=True)

    def test_kg_source_vuln_workflow_e2e_empty_entries_fail_without_starting_dataflow(self):
        task = self._kg_fetch_task("/tmp/kg-empty")
        kg_run = BinarySecurityStageRun(
            id="sr-kg-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[kg_run], stage_items=[], archive_jobs=[], events=[])

        async def _fake_fetch(_task):
            return [], self._kg_meta(selected_entry_count=0, filtered_out_count=2, returned_item_count=0)

        self.manager._fetch_knowledge_graph_entry_results = _fake_fetch
        self.manager._knowledge_graph_entry_fetch_max_attempts = lambda: 1
        status, summary = asyncio.run(
            self.manager._stage_knowledge_graph_entry_fetch(db, task, kg_run, token=None, retry_existing=False)
        )
        self.assertEqual("failed", status)
        self.assertIn("没有可用入口", summary["error"])
        kg_run.status = "failed"
        kg_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "knowledge_graph_entry_fetch")
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertIn(task.status, {"running", "failed"})
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertEqual("failed", task.summary["entry_results"][0]["completion_state"])
        self.assertEqual(
            "failed",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "knowledge_graph_entry_fetch"),
        )
        self.assertTrue(any(event.event_type == "knowledge_graph_entry_fetch_empty_after_done" for event in db.events))

    def test_kg_source_workflow_e2e_failed_fetch_surfaces_authoritative_stage_summary(self):
        task = self._kg_fetch_task("/tmp/kg-stage-failed")
        task.current_stage = "knowledge_graph_entry_fetch"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "failed",
                    "completion_ready": True,
                    "entries": [],
                    "entry_count": 0,
                    "error_message": "知识图谱入口识别完成，但没有可用入口",
                }
            ],
        }
        kg_run = BinarySecurityStageRun(
            id="sr-kg-stage-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1, "error": "知识图谱入口识别完成，但没有可用入口"},
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-kg-stage-failed-shell",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[kg_run, dataflow_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
        )

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        by_stage = {summary.stage_name: summary for summary in detail.stage_summaries}

        self.assertEqual("knowledge_graph_entry_fetch", task.current_stage)
        self.assertEqual("failed", by_stage["knowledge_graph_entry_fetch"].status)
        self.assertIn(by_stage["dataflow_vuln_scan"].status, {"pending", "queued"})
        self.assertEqual("knowledge_graph_entry_fetch", next(summary.stage_name for summary in detail.stage_summaries if summary.status == "failed"))

    def test_kg_source_vuln_workflow_e2e_dataflow_downstream_missing_keeps_parent_active(self):
        task = self._kg_fetch_task("/tmp/kg-missing")
        task.current_stage = "dataflow_vuln_scan"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [
                        {
                            "entry_key": "src-1",
                            "module_key": "knowledge-graph-source-project",
                            "module_name": "source-project",
                            "function_name": "sink",
                        }
                    ],
                    "entry_count": 1,
                }
            ],
        }
        dataflow_run = BinarySecurityStageRun(
            id="sr-kg-dataflow-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-kg-dataflow-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-1",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            item_identity_key="src-1::knowledge-graph-source-project",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-missing",
            error_message="下游子任务不存在",
            result={"downstream_status": "downstream_missing"},
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-a",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[dataflow_run],
            stage_items=[dataflow_item],
            runtime_leases=[runtime_lease],
            events=[],
        )

        async def _raise_not_found(_task, _item, _token):
            raise NotFoundError("downstream task not found")

        async def _noop_write(*_args, **_kwargs):
            return None

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task
        try:
            self.manager._fetch_downstream_task_payload = _raise_not_found
            self.manager._write_task_metadata_async = _noop_write
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    stage_name="dataflow_vuln_scan",
                    apply_state=True,
                    force=True,
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("running", task.status)
        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("downstream_missing", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)

    def test_kg_source_vuln_workflow_e2e_dataflow_downstream_missing_recovers_on_next_owner_prepare(self):
        entry = {
            "entry_key": "src-1",
            "module_key": "knowledge-graph-source-project",
            "module_name": "source-project",
            "function_name": "sink",
        }
        task = self._kg_fetch_task("/tmp/kg-missing-owner")
        task.current_stage = "dataflow_vuln_scan"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [dict(entry)],
                    "entry_count": 1,
                }
            ],
        }
        dataflow_run = BinarySecurityStageRun(
            id="sr-kg-dataflow-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-kg-dataflow-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-1",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            item_identity_key="src-1::knowledge-graph-source-project",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-missing-owner",
            error_message="下游子任务不存在",
            result={
                "downstream_status": "downstream_missing",
                "sync_observation": {
                    "sync_status": "synced",
                    "error_type": "not_found",
                    "error_message": "下游子任务不存在",
                    "consecutive_error_count": 20,
                    "budget_exhausted": True,
                },
            },
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-a",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[dataflow_run],
            stage_items=[dataflow_item],
            runtime_leases=[runtime_lease],
            events=[],
        )

        async def _raise_not_found(_task, _item, _token):
            raise NotFoundError("downstream task not found")

        async def _noop_write(*_args, **_kwargs):
            return None

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task
        try:
            self.manager._fetch_downstream_task_payload = _raise_not_found
            self.manager._write_task_metadata_async = _noop_write
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    stage_name="dataflow_vuln_scan",
                    apply_state=True,
                    force=True,
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("running", task.status)
        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("downstream_missing", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)
        observation = dict((dataflow_item.result or {}).get("sync_observation") or {})
        self.assertEqual("not_found", observation.get("error_type"))

        executable = self.manager._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=dataflow_run,
            inputs=[dict(entry)],
            downstream_service="dataflow_vuln_scan",
            identity=lambda current: (
                current["entry_key"],
                current["function_name"],
                current.get("module_key"),
                current,
            ),
            output_ref=lambda _current: {},
        )

        self.assertEqual([dict(entry)], executable)
        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("df-missing-owner", dataflow_item.downstream_task_id)

    def test_kg_source_workflow_e2e_force_reset_to_pending_clears_control_state_and_requeues(self):
        now = _now()
        task = self._kg_fetch_task("/tmp/kg-force-reset")
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.current_operation_id = "op-force-reset-kg"
        task.last_error = "dataflow failed"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [{"entry_key": "src-1", "function_name": "sink", "module_key": "knowledge-graph-source-project"}],
                    "entry_count": 1,
                }
            ],
            "failure_code": "dataflow_failed",
            "failure_message": "dataflow failed",
            "runtime_workset": {"pending_task_layer_reconcile": {"reason": "retry_after_failure"}},
        }
        kg_run = BinarySecurityStageRun(
            id="sr-kg-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-df-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-df-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-1",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            status="failed",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-force-reset",
            error_message="dataflow failed",
        )
        self._persist_stage_item_result(
            dataflow_item,
            payload={"entry_key": "src-1", "module_key": "knowledge-graph-source-project", "error": "dataflow failed"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-force-reset-kg",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="force_reset_to_pending",
            target_stage="dataflow_vuln_scan",
            status="running",
            current_step="collect_cleanup_plan",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-a",
            heartbeat_at=now,
            lease_expires_at=now + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            operations=[operation],
            stage_runs=[kg_run, dataflow_run],
            stage_items=[dataflow_item],
            runtime_leases=[runtime_lease],
            events=[],
        )
        queued: list[str] = []
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([task.id], queued)
        self.assertEqual("pending", task.status)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertIsNone(task.last_error)
        self.assertEqual({}, dict((task.summary or {}).get("runtime_workset") or {}))
        self.assertEqual("pending", detail.status)
        self.assertIn("task_force_reset_to_pending", [event.event_type for event in db.events])

    def test_kg_source_workflow_e2e_cancel_owner_handoff_terminalizes_task(self):
        task = self._kg_fetch_task("/tmp/kg-cancel")
        task.status = "cancelling"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-cancel-kg"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        operation = BinarySecurityTaskOperation(
            id="op-cancel-kg",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage=task.current_stage,
            status="running",
            current_step=task_manager_module.TASK_OPERATION_STEP_VERIFY_DOWNSTREAM_QUIESCED,
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[], runtime_leases=[])
        manager_a = TaskManager()
        manager_a.instance_id = "worker-a"
        manager_b = TaskManager()
        manager_b.instance_id = "worker-b"

        original_factory = task_manager_module.get_session_factory
        original_runner_a = manager_a._run_task_operation_steps
        original_runner_b = manager_b._run_task_operation_steps
        original_prepare_cancel_b = manager_b._prepare_cancel_task
        original_write_metadata_b = manager_b._write_task_metadata_async
        original_ensure_a = manager_a._ensure_task_write_ownership
        original_ensure_b = manager_b._ensure_task_write_ownership
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _stale_before_finalize(_db, current_task, current_operation):
                current_task.status = "cancelling"
                current_task.current_operation_id = current_operation.id
                raise task_manager_module.StaleTaskExecution("kg owner handoff before finalize")

            async def _noop_prepare_cancel(_db, _task):
                return []

            async def _noop_write(*_args, **_kwargs):
                return None

            async def _atomic_finalize_on_takeover(_db, current_task, current_operation):
                current_task.status = "cancelled"
                current_task.runtime_phase = TASK_RUNTIME_PHASE_TERMINAL
                current_task.current_operation_id = None
                current_operation.status = "succeeded"
                current_operation.current_step = task_manager_module.TASK_OPERATION_STEP_SUCCEEDED
                return {"operation_finalized": True, "task_status": "cancelled"}

            manager_a._ensure_task_write_ownership = lambda *args, **kwargs: None
            manager_b._ensure_task_write_ownership = lambda *args, **kwargs: None
            manager_a._run_task_operation_steps = _stale_before_finalize
            first_changed = asyncio.run(manager_a._run_current_task_operation(task.id))
            self.assertFalse(first_changed)
            self.assertEqual("cancelling", task.status)
            self.assertEqual(operation.id, task.current_operation_id)

            db.runtime_leases = [
                BinarySecurityTaskRuntimeLease(
                    task_id=task.id,
                    owner_instance_id="worker-b",
                    heartbeat_at=_now(),
                    lease_expires_at=_now(),
                )
            ]
            manager_b._prepare_cancel_task = _noop_prepare_cancel
            manager_b._write_task_metadata_async = _noop_write
            manager_b._run_task_operation_steps = _atomic_finalize_on_takeover
            second_changed = asyncio.run(manager_b._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager_a._run_task_operation_steps = original_runner_a
            manager_b._run_task_operation_steps = original_runner_b
            manager_b._prepare_cancel_task = original_prepare_cancel_b
            manager_b._write_task_metadata_async = original_write_metadata_b
            manager_a._ensure_task_write_ownership = original_ensure_a
            manager_b._ensure_task_write_ownership = original_ensure_b

        self.assertTrue(second_changed)
        self.assertEqual("cancelled", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertEqual("succeeded", operation.status)

    def test_kg_source_workflow_e2e_delete_force_delete_fallback(self):
        task = self._kg_fetch_task("/tmp/kg-delete-fallback")
        task.current_operation_id = "op-delete-fallback-kg"
        operation = BinarySecurityTaskOperation(
            id="op-delete-fallback-kg",
            task_id=task.id,
            project_id=task.project_id,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            target_stage="dataflow_vuln_scan",
            status="queued",
            request_payload={"force": False, "force_delete": False},
        )
        db = _ModelAwareDb(tasks=[task], operations=[operation], events=[], runtime_leases=[])
        manager = TaskManager()
        manager.instance_id = "worker-a"

        original_factory = task_manager_module.get_session_factory
        original_wait = manager._wait_for_task_workspace_quiesce
        original_cleanup = manager._cleanup_task_workspace
        original_archive_cleanup = manager._delete_archive_children_for_stages
        original_stage_item_cleanup = manager._delete_stage_items_for_stages
        original_stage_run_cleanup = manager._delete_stage_run_rows
        original_state_event_cleanup = manager._delete_task_state_event_rows
        original_release_runtime = manager._release_task_delete_runtime_state
        original_cancel_local = manager._request_local_worker_cancel
        original_ensure = manager._ensure_task_write_ownership
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)

            async def _wait_true(_db, _task):
                return True

            async def _cleanup_force_fallback(_task, *, token=None):
                del token
                return "recreated_during_delete"

            async def _cancel_local(*_args, **_kwargs):
                return None

            manager._wait_for_task_workspace_quiesce = _wait_true
            manager._cleanup_task_workspace = _cleanup_force_fallback
            manager._delete_archive_children_for_stages = lambda *_args, **_kwargs: 0
            manager._delete_stage_items_for_stages = lambda *_args, **_kwargs: 0
            manager._delete_stage_run_rows = lambda *_args, **_kwargs: 0
            manager._delete_task_state_event_rows = lambda *_args, **_kwargs: 0
            manager._release_task_delete_runtime_state = lambda *_args, **_kwargs: None
            manager._request_local_worker_cancel = _cancel_local
            manager._ensure_task_write_ownership = lambda *args, **kwargs: None

            changed = asyncio.run(manager._run_current_task_operation(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            manager._wait_for_task_workspace_quiesce = original_wait
            manager._cleanup_task_workspace = original_cleanup
            manager._delete_archive_children_for_stages = original_archive_cleanup
            manager._delete_stage_items_for_stages = original_stage_item_cleanup
            manager._delete_stage_run_rows = original_stage_run_cleanup
            manager._delete_task_state_event_rows = original_state_event_cleanup
            manager._release_task_delete_runtime_state = original_release_runtime
            manager._request_local_worker_cancel = original_cancel_local
            manager._ensure_task_write_ownership = original_ensure

        self.assertTrue(changed)
        self.assertFalse(any(row.id == task.id for row in db.tasks))
        self.assertEqual("succeeded", operation.status)
        self.assertEqual(task_manager_module.TASK_OPERATION_STEP_SUCCEEDED, operation.current_step)
        self.assertTrue(bool(dict(operation.request_payload or {}).get("force_delete")))
        self.assertTrue(bool(dict(operation.request_payload or {}).get("auto_force_delete_fallback")))
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_delete_auto_force_delete_fallback", event_types)
        self.assertIn("control_operation_terminal_finalize_committed", event_types)

    def test_kg_source_workflow_e2e_retry_stage_full_requeues_failed_dataflow_in_place(self):
        now = _now()
        task = self._kg_fetch_task("/tmp/kg-retry-stage-full")
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "dataflow failed"
        task.summary = {
            **(task.summary or {}),
            "failure_code": "dataflow_failed",
            "failure_message": "dataflow failed",
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [{"entry_key": "src-1", "function_name": "sink", "module_key": "knowledge-graph-source-project"}],
                    "entry_count": 1,
                }
            ],
        }
        kg_run = BinarySecurityStageRun(
            id="sr-kg-retry-stage-full",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-df-retry-stage-full",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-df-retry-stage-full",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-1",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            status="failed",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-retry-stage-full",
            error_message="dataflow failed",
        )
        self._persist_stage_item_result(
            dataflow_item,
            payload={"entry_key": "src-1", "module_key": "knowledge-graph-source-project", "error": "dataflow failed"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-stage-full-kg",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="dataflow_vuln_scan",
            status="running",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-a",
            heartbeat_at=now,
            lease_expires_at=now + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            operations=[operation],
            stage_runs=[kg_run, dataflow_run],
            stage_items=[dataflow_item],
            runtime_leases=[runtime_lease],
            events=[],
        )

        original_instance_id = self.manager.instance_id
        original_enqueue = self.manager._enqueue_task
        original_should_auto = self.manager._should_auto_advance_to_stage
        queued: list[str] = []
        self.manager.instance_id = "worker-a"
        self.manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
        self.manager._should_auto_advance_to_stage = lambda *_args, **_kwargs: True
        self.manager._register_task_execution_owner(task.id, "primary_task_worker")
        try:
            self.manager._requeue_task_after_retry_operation(
                db,
                task,
                target_stage="dataflow_vuln_scan",
                operation=operation,
            )
        finally:
            self.manager._release_task_execution_owner(task.id, "primary_task_worker")
            self.manager.instance_id = original_instance_id
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([], queued)
        self.assertEqual("running", task.status)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual("worker-a", db.runtime_leases[0].owner_instance_id)
        self.assertEqual("dataflow failed", task.last_error)
        self.assertNotIn("failure_code", dict(task.summary or {}))
        self.assertNotIn("failure_message", dict(task.summary or {}))
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("requested")))
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("in_place_runtime_resume")))
        self.assertFalse(bool((operation.result_payload or {}).get("requeue", {}).get("owner_release_and_requeue")))
        self.assertEqual("running", detail.status)
        event_types = [event.event_type for event in db.events]
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertIn("operation_requeue_applied", event_types)

    def test_kg_source_workflow_e2e_retry_failed_items_recreates_abnormal_dataflow_child_inside_operation(self):
        task = self._kg_fetch_task("/tmp/kg-retry-failed-items")
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-retry-failed-items-kg"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [
                        {"entry_key": "src-1", "function_name": "sink", "module_key": "knowledge-graph-source-project"},
                        {"entry_key": "src-2", "function_name": "helper", "module_key": "knowledge-graph-source-project"},
                    ],
                    "entry_count": 2,
                }
            ],
            "vuln_results": [{"entry_key": "src-1"}, {"entry_key": "src-2"}],
            "retry_plan": {
                "target_stage": "dataflow_vuln_scan",
                "mode": "retry_failed_items",
                "retry_item_keys": ["src-1::knowledge-graph-source-project"],
            },
        }
        kg_run = BinarySecurityStageRun(
            id="sr-kg-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-df-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="failed",
        )
        df_abnormal = BinarySecurityStageItem(
            id="si-df-retry-failed-items-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-1",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            item_identity_key="src-1::knowledge-graph-source-project",
            status="cancelled",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-old-a",
        )
        df_abnormal.input_ref = {
            "entry_key": "src-1",
            "function_name": "sink",
            "module_key": "knowledge-graph-source-project",
        }
        df_success = BinarySecurityStageItem(
            id="si-df-retry-failed-items-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-2",
            item_name="helper",
            parent_key="knowledge-graph-source-project",
            item_identity_key="src-2::knowledge-graph-source-project",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-keep-b",
        )
        df_success.input_ref = {
            "entry_key": "src-2",
            "function_name": "helper",
            "module_key": "knowledge-graph-source-project",
        }
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-kg",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_failed_items",
            target_stage="dataflow_vuln_scan",
            status="running",
            current_step="collect_cleanup_plan",
        )
        operation.resume_cursor = {"current_step": "collect_cleanup_plan"}
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[kg_run, dataflow_run],
            stage_items=[df_abnormal, df_success],
            archive_jobs=[],
            operations=[operation],
            events=[],
        )
        cleanup_refs: list[dict[str, object]] = []
        create_calls: list[dict[str, object]] = []

        async def _noop_sync(*_args, **_kwargs):
            return None

        async def _noop_active_payload(*_args, **_kwargs):
            return None

        async def _fake_cleanup_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            cleanup_refs.extend(dict(ref) for ref in refs_arg)
            return len(refs_arg)

        async def _fake_delete_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            cleanup_refs.extend(dict(ref) for ref in refs_arg)
            return len(refs_arg)

        async def _fake_create(db_arg, task_arg, item_arg, *, service, token, payload):
            del db_arg, task_arg, token
            create_calls.append({"service": service, "item_id": item_arg.id, "payload": dict(payload)})
            return {"task_id": "df-new-a", "status": "pending"}

        original_sync = self.manager.sync_downstream_status
        original_active_payload = self.manager._active_downstream_payload
        original_cleanup_refs = self.manager._cleanup_downstream_refs
        original_delete_refs = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        try:
            self.manager.sync_downstream_status = _noop_sync
            self.manager._active_downstream_payload = _noop_active_payload
            self.manager._cleanup_downstream_refs = _fake_cleanup_refs
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.sync_downstream_status = original_sync
            self.manager._active_downstream_payload = original_active_payload
            self.manager._cleanup_downstream_refs = original_cleanup_refs
            self.manager._delete_downstream_refs = original_delete_refs
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual({"df-old-a"}, {ref["task_id"] for ref in cleanup_refs})
        self.assertEqual(["dataflow_vuln_scan"], [row["service"] for row in create_calls])
        self.assertEqual("df-new-a", df_abnormal.downstream_task_id)
        self.assertEqual("success", df_success.status)
        self.assertEqual("df-keep-b", df_success.downstream_task_id)
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        self.assertEqual("running", operation.status)
        self.assertEqual("failed", detail.status)
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        self.assertEqual("recreate_from_abnormal", action_rows["si-df-retry-failed-items-a"]["strategy"])
        self.assertEqual("df-old-a", action_rows["si-df-retry-failed-items-a"]["old_downstream_task_id"])
        self.assertEqual("df-new-a", action_rows["si-df-retry-failed-items-a"]["new_downstream_task_id"])
        self.assertNotIn("si-df-retry-failed-items-b", action_rows)

    def test_kg_source_workflow_e2e_retry_failed_items_adopts_active_dataflow_child_inside_operation(self):
        task = self._kg_fetch_task("/tmp/kg-retry-adopt")
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-retry-failed-items-kg-adopt"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [
                        {"entry_key": "src-active", "function_name": "sink", "module_key": "knowledge-graph-source-project"},
                    ],
                    "entry_count": 1,
                }
            ],
            "retry_plan": {
                "target_stage": "dataflow_vuln_scan",
                "mode": "retry_failed_items",
                "retry_item_keys": ["src-active::knowledge-graph-source-project"],
            },
        }
        dataflow_run = BinarySecurityStageRun(
            id="sr-df-retry-adopt",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="failed",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-df-retry-adopt",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-active",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            item_identity_key="src-active::knowledge-graph-source-project",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-live-kg",
        )
        dataflow_item.input_ref = {
            "entry_key": "src-active",
            "function_name": "sink",
            "module_key": "knowledge-graph-source-project",
        }
        dataflow_item.result = {
            "downstream_status": "running",
            "sync_observation": {"downstream_status": "running", "state_applied": True},
        }
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-kg-adopt",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_failed_items",
            target_stage="dataflow_vuln_scan",
            status="running",
            current_step="collect_cleanup_plan",
        )
        operation.resume_cursor = {"current_step": "collect_cleanup_plan"}
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[dataflow_run],
            stage_items=[dataflow_item],
            operations=[operation],
            events=[],
        )
        cleanup_refs: list[dict[str, object]] = []
        create_calls: list[dict[str, object]] = []
        queued: list[str] = []

        async def _fake_active_payload(task_arg, item_arg, token_arg):
            del task_arg, token_arg
            if item_arg.id == dataflow_item.id:
                return {"task_id": "df-live-kg", "status": "running"}
            return None

        async def _noop_sync(*_args, **_kwargs):
            return None

        async def _fake_delete_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            cleanup_refs.extend(dict(ref) for ref in refs_arg)
            return len(refs_arg)

        async def _fake_create(db_arg, task_arg, item_arg, *, service, token, payload):
            del db_arg, task_arg, item_arg, service, token, payload
            create_calls.append({"unexpected": True})
            return {"task_id": "unexpected-new-child", "status": "pending"}

        original_active_payload = self.manager._active_downstream_payload
        original_sync = self.manager.sync_downstream_status
        original_delete_refs = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        try:
            self.manager._active_downstream_payload = _fake_active_payload
            self.manager.sync_downstream_status = _noop_sync
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager._active_downstream_payload = original_active_payload
            self.manager.sync_downstream_status = original_sync
            self.manager._delete_downstream_refs = original_delete_refs
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue

        self.assertEqual([], cleanup_refs)
        self.assertEqual([], create_calls)
        self.assertEqual([], queued)
        self.assertEqual("df-live-kg", dataflow_item.downstream_task_id)
        self.assertEqual("running", dataflow_item.status)
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        action = action_rows["si-df-retry-adopt"]
        self.assertEqual("adopt_active", action["strategy"])
        self.assertEqual("running", action["observed_status"])
        self.assertEqual("df-live-kg", action["old_downstream_task_id"])
        self.assertFalse(bool(action.get("cleanup_performed")))
        self.assertFalse(bool(action.get("create_required")))
        self.assertEqual("succeeded", action.get("verification_status"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("child_task_dispatch_deferred", event_types)
        self.assertIn("operation_requeue_applied", event_types)
        self.assertIn("retry_in_place_resume_applied", event_types)

    def test_kg_source_workflow_e2e_retry_failed_items_archive_only_failure_upgrades_to_archive_retry(self):
        task = self._kg_fetch_task("/tmp/kg-archive-only-retry")
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [{"entry_key": "src-1", "function_name": "sink", "module_key": "knowledge-graph-source-project"}],
                    "entry_count": 1,
                }
            ],
        }
        task.status = "failed"
        task.current_stage = "knowledge_graph_entry_fetch"
        task.finished_at = _now()
        kg_run = BinarySecurityStageRun(
            id="sr-kg-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="failed",
            last_error="总任务产物归档失败",
        )
        kg_item = BinarySecurityStageItem(
            id="si-kg-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=kg_run.id,
            stage_name="knowledge_graph_entry_fetch",
            item_key="knowledge-graph-source-project",
            item_name="source-project",
            parent_key="knowledge-graph-source-project",
            item_identity_key="knowledge-graph-source-project::knowledge-graph-source-project",
            status="failed",
            downstream_service="knowledge_graph_audit_sources",
            downstream_task_id="kg-success-a",
            error_message="总任务产物归档失败",
        )
        kg_item.result = {
            "last_sync_result": "downstream_archive_failed_manual_intervention",
            "sync_observation": {
                "last_result": "downstream_archive_failed_manual_intervention",
            },
        }
        archive_job = BinarySecurityArchiveJob(
            id="aj-kg-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            item_id=kg_item.id,
            item_key=kg_item.item_key,
            archive_status="failed",
            error_message="copy failed",
        )
        archive_job.payload = {
            "mapped_status": "success",
            "downstream_payload": {"task_id": "kg-success-a", "status": "success"},
        }
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[kg_run],
            stage_items=[kg_item],
            archive_jobs=[archive_job],
            events=[],
        )

        original_enqueue = self.manager._enqueue_task
        try:
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            operation = self.manager.retry_failed_items(db, project_id=task.project_id, task_id=task.id)
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("retry_archive_full", operation.operation_type)
        self.assertEqual("knowledge_graph_entry_fetch", operation.target_stage)
        self.assertEqual(operation.id, task.current_operation_id)
        self.assertEqual("task_retry_failed_items_archive_full_accepted", getattr(db.added[-1], "event_type", ""))

    def test_kg_source_vuln_workflow_e2e_dataflow_partial_success_keeps_parent_active(self):
        task = self._kg_fetch_task("/tmp/kg-partial-success-active")
        task.current_stage = "dataflow_vuln_scan"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [
                        {"entry_key": "src-a", "module_key": "knowledge-graph-source-project", "module_name": "source-project", "function_name": "sink"},
                        {"entry_key": "src-b", "module_key": "knowledge-graph-source-project", "module_name": "source-project", "function_name": "helper"},
                    ],
                    "entry_count": 2,
                }
            ],
            "dataflow_results": [
                {"entry_key": "src-a", "module_key": "knowledge-graph-source-project", "vulns": [{"id": "v-a"}]},
                {"entry_key": "src-b", "module_key": "knowledge-graph-source-project", "error": "analysis failed"},
            ],
        }
        dataflow_run = BinarySecurityStageRun(
            id="sr-kg-dataflow-partial-success-active",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="partial_success",
            finished_at=_now(),
            output_summary={"success_count": 1, "failed_count": 1},
        )
        success_item = BinarySecurityStageItem(
            id="si-kg-dataflow-partial-success-active",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-a",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-kg-a",
        )
        failed_item = BinarySecurityStageItem(
            id="si-kg-dataflow-partial-failed-active",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-b",
            item_name="helper",
            parent_key="knowledge-graph-source-project",
            status="failed",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-kg-b",
            error_message="analysis failed",
        )
        self._persist_stage_item_result(success_item, payload={"entry_key": "src-a", "module_key": "knowledge-graph-source-project", "vulns": [{"id": "v-a"}]})
        self._persist_stage_item_result(failed_item, payload={"entry_key": "src-b", "module_key": "knowledge-graph-source-project", "error": "analysis failed"})
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[dataflow_run],
            stage_items=[success_item, failed_item],
            archive_jobs=[],
            events=[],
        )

        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertEqual(
            "partial_success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )

    def test_kg_source_workflow_e2e_owner_restart_recovery_preserves_authoritative_state(self):
        task = self._kg_fetch_task("/tmp/kg-owner-recover")
        task.current_stage = "dataflow_vuln_scan"
        task.status = "running"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [
                        {
                            "entry_key": "src-1",
                            "module_key": "knowledge-graph-source-project",
                            "module_name": "source-project",
                            "function_name": "sink",
                        }
                    ],
                    "entry_count": 1,
                }
            ],
        }
        kg_run = BinarySecurityStageRun(
            id="sr-kg-recover",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="success",
            started_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-df-kg-recover",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="success",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-df-kg-recover",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-1",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-kg-recover",
        )
        self._persist_stage_item_result(
            dataflow_item,
            payload={
                "entry_key": "src-1",
                "module_key": "knowledge-graph-source-project",
                "vulns": [{"id": "v-kg-recover", "severity": "high"}],
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[kg_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
        )

        recovering_manager = TaskManager()
        recovering_manager.instance_id = "worker-b"
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-b",
            heartbeat_at=_now(),
            lease_expires_at=_now(),
        )
        db.runtime_leases.append(runtime_lease)

        original_factory = task_manager_module.get_session_factory
        original_write = recovering_manager._write_task_metadata_async

        async def _noop_write(*_args, **_kwargs):
            return None

        task_manager_module.get_session_factory = lambda: (lambda: db)
        recovering_manager._write_task_metadata_async = _noop_write
        try:
            asyncio.run(recovering_manager._sync_streaming_task_tail_state(task.id))
        finally:
            task_manager_module.get_session_factory = original_factory
            recovering_manager._write_task_metadata_async = original_write

        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-b", db.runtime_leases[0].owner_instance_id)
        detail = recovering_manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", detail.status)
        kg_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "knowledge_graph_entry_fetch")
        self.assertEqual("success", kg_summary.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("success", dataflow_summary.status)

    def test_kg_source_workflow_e2e_dataflow_partial_success_archive_terminalizes_parent_success(self):
        task = self._kg_fetch_task("/tmp/kg-ps-archive")
        task.current_stage = "dataflow_vuln_scan"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "knowledge-graph-source-project",
                    "module_name": "source-project",
                    "module_kind": "knowledge_graph_module",
                    "source_stage": "knowledge_graph_entry_fetch",
                    "execution_epoch": 0,
                    "completion_state": "success",
                    "completion_ready": True,
                    "entries": [
                        {"entry_key": "src-a", "module_key": "knowledge-graph-source-project", "module_name": "source-project", "function_name": "sink"},
                        {"entry_key": "src-b", "module_key": "knowledge-graph-source-project", "module_name": "source-project", "function_name": "helper"},
                    ],
                    "entry_count": 2,
                }
            ],
        }
        kg_run = BinarySecurityStageRun(
            id="sr-kg-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="knowledge_graph_entry_fetch",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-df-kg-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        success_item = BinarySecurityStageItem(
            id="si-df-kg-ps-archive-success",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-a",
            item_name="sink",
            parent_key="knowledge-graph-source-project",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-kg-ps-a",
        )
        partial_item = BinarySecurityStageItem(
            id="si-df-kg-ps-archive-partial",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="src-b",
            item_name="helper",
            parent_key="knowledge-graph-source-project",
            status="partial_success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-kg-ps-b",
        )
        self._persist_stage_item_result(
            success_item,
            payload={"entry_key": "src-a", "module_key": "knowledge-graph-source-project", "vulns": [{"id": "v-a"}]},
        )
        self._persist_stage_item_result(
            partial_item,
            payload={"entry_key": "src-b", "module_key": "knowledge-graph-source-project", "vulns": [], "status": "partial_success"},
        )
        success_archive = self._make_archive_job(
            task=task,
            item=success_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-kg-ps-a",
            mapped_status="success",
        )
        partial_archive = self._make_archive_job(
            task=task,
            item=partial_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="df-kg-ps-b",
            mapped_status="partial_success",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[kg_run, dataflow_run],
            stage_items=[success_item, partial_item],
            archive_jobs=[success_archive, partial_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            first_signals = self._apply_archive_and_reconcile(db, task, success_archive)
            second_signals = self._apply_archive_and_reconcile(db, task, partial_archive)

        dataflow_run.status = "partial_success"
        dataflow_run.finished_at = _now()
        dataflow_run.output_summary = {"success_count": 1, "partial_success_count": 1}
        self._refresh_stage_summary(db, task, "knowledge_graph_entry_fetch")
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(first_signals)
        self.assertTrue(second_signals)
        self.assertEqual("archive_apply", str(second_signals[-1].get("reconcile_reason") or ""))
        self.assertEqual("success", task.status)
        self.assertEqual("success", detail.status)
        self.assertEqual(
            "partial_success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )
        self.assertTrue((task.summary or {}).get("dataflow_results"))
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertIsNotNone(detail.abnormal_reason)
        self.assertEqual("dataflow_partial_success", detail.abnormal_reason.code)
