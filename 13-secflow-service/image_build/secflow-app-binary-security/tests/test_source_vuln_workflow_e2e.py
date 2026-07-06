import asyncio
import json
import unittest
import uuid
from unittest.mock import patch

from app.exception import NotFoundError, ValidationError
from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager, _now
from test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


def _source_task(*, summary=None, policy_json=None) -> BinarySecurityTask:
    task_suffix = uuid.uuid4().hex[:12]
    task = BinarySecurityTask(
        id=f"task-source-e2e-{task_suffix}",
        project_id="project-1",
        name="source-vuln-e2e",
        status="running",
        task_type=TASK_TYPE_SOURCE,
        current_stage="system_analysis",
        firmware_source="project_filesystem",
        firmware_path="/tmp/source-project",
        output_root=f"/tmp/bs-source-out-{task_suffix}",
        workspace_root=f"/tmp/bs-source-ws-{task_suffix}",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        started_at=_now(),
    )
    task.summary = dict(summary or {})
    if policy_json is not None:
        task.policy_json = policy_json
    return task


def _binary_module_task(*, summary=None, policy_json=None) -> BinarySecurityTask:
    task_suffix = uuid.uuid4().hex[:12]
    task = BinarySecurityTask(
        id=f"task-binary-module-e2e-{task_suffix}",
        project_id="project-1",
        name="binary-module-e2e",
        status="running",
        task_type=TASK_TYPE_BINARY_MODULE,
        current_stage="binary_to_source",
        firmware_source="project_filesystem",
        firmware_path="/tmp/module-input/IPSEC.bin",
        output_root=f"/tmp/bs-binary-module-out-{task_suffix}",
        workspace_root=f"/tmp/bs-binary-module-ws-{task_suffix}",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        started_at=_now(),
    )
    task.summary = dict(summary or {})
    if policy_json is not None:
        task.policy_json = policy_json
    return task


class SourceWorkflowE2ETests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.manager.instance_id = "worker-a"
        self.manager._enqueue_task = lambda *_args, **_kwargs: None

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

    def _persist_stage_item_result(self, task: BinarySecurityTask, item: BinarySecurityStageItem, *, payload: dict):
        del task
        item.result = dict(payload)

    def _refresh_stage_summary(self, db: _ModelAwareDb, task: BinarySecurityTask, stage_name: str) -> None:
        handler = self.manager._stage_handler(stage_name)
        if handler is not None:
            handler.refresh_summary_from_items(self.manager, db, task)

    def test_source_workflow_e2e_happy_path(self):
        task = _source_task(
            summary={"input_dir": "/tmp/source-project"},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    },
                    {
                        "module_key": "mod-b",
                        "module_name": "mod-b",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-b",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-b",
                        "files_list": "/tmp/source-project/mod-b/files.list",
                        "files_list_path": "/tmp/source-project/mod-b/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    },
                ]
            },
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run],
            stage_items=[system_item],
            archive_jobs=[system_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            system_signals = self._apply_archive_and_reconcile(db, task, system_archive)

        self._refresh_stage_summary(db, task, "system_analysis")
        entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
        for module in self.manager._entry_analysis_inputs(db, task):
            self.manager._upsert_stage_item(
                db,
                task=task,
                stage_run=entry_run,
                stage_name="entry_analysis",
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module.get("firmware_key"),
                downstream_service="entry_analyse",
                input_ref=module,
                retrying=False,
                auto_retrying=False,
            )
        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertTrue(system_signals)
        self.assertEqual(2, len(entry_items))
        self.assertIn(str(entry_run.status or "").strip(), {"pending", "running", "success"})

        for item, module_key in zip(entry_items, ["mod-a", "mod-b"], strict=False):
            item.status = "success"
            item.downstream_task_id = f"eat-{module_key}"
            item.downstream_service = "entry_analyse"
            self._persist_stage_item_result(
                task,
                item,
                payload={
                    "module_key": module_key,
                    "module_name": module_key,
                    "source_dir": f"/tmp/source-project/{module_key}",
                    "entries": [
                        {
                            "entry_key": f"{module_key}:entry",
                            "module_key": module_key,
                            "module_name": module_key,
                            "function_name": f"{module_key}_fn",
                            "definition_file": f"{module_key}.c",
                            "definition_line": "12",
                            "source_dir": f"/tmp/source-project/{module_key}",
                            "source_root": "/tmp/source-project",
                            "source_root_path": "/tmp/source-project",
                            "module_dir": f"/tmp/source-project/{module_key}",
                            "files_list": f"/tmp/source-project/{module_key}/files.list",
                            "files_list_path": f"/tmp/source-project/{module_key}/files.list",
                            "task_type": TASK_TYPE_SOURCE,
                            "firmware_key": "source_project",
                            "firmware_name": "source_project",
                        }
                    ],
                },
            )
            db.archive_jobs.append(
                self._make_archive_job(
                    task=task,
                    item=item,
                    downstream_service="entry_analyse",
                    downstream_task_id=f"eat-{module_key}",
                )
            )

        self._refresh_stage_summary(db, task, "entry_analysis")
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
        for entry_module in task.summary.get("entry_results") or []:
            for entry in entry_module.get("entries") or []:
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

        for job in [row for row in db.archive_jobs if row.stage_name == "entry_analysis"]:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                self._apply_archive_and_reconcile(db, task, job)

        self._refresh_stage_summary(db, task, "entry_analysis")
        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual(2, len(dataflow_items))
        self.assertIn(str(dataflow_run.status or "").strip(), {"pending", "running", "success"})

        for item in dataflow_items:
            item.status = "success"
            item.downstream_task_id = f"dfa-{item.item_key}"
            item.downstream_service = "dataflow_vuln_scan"
            self._persist_stage_item_result(
                task,
                item,
                payload={
                    "entry_key": item.item_key,
                    "module_key": str(item.parent_key or "").strip() or "unknown-module",
                    "vulns": [{"id": f"v-{item.item_key}", "severity": "high"}],
                },
            )
            db.archive_jobs.append(
                self._make_archive_job(
                    task=task,
                    item=item,
                    downstream_service="dataflow_vuln_scan",
                    downstream_task_id=f"dfa-{item.item_key}",
                )
            )

        for job in [row for row in db.archive_jobs if row.stage_name == "dataflow_vuln_scan"]:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                self._apply_archive_and_reconcile(db, task, job)

        system_run.status = "success"
        system_run.finished_at = _now()
        entry_run.status = "success"
        entry_run.finished_at = _now()
        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "system_analysis")
        self._refresh_stage_summary(db, task, "entry_analysis")
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertIn(task.status, {"running", "success"})
        self.assertEqual(task.status, detail.status)
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertTrue((task.summary or {}).get("selected_modules"))
        self.assertTrue((task.summary or {}).get("entry_results"))
        self.assertTrue((task.summary or {}).get("dataflow_results"))
        self.assertEqual(
            "success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "system_analysis"),
        )
        self.assertEqual(
            "success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "entry_analysis"),
        )
        self.assertEqual(
            "success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )

    def test_source_workflow_e2e_system_success_without_archive_does_not_start_entry(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        system_run = BinarySecurityStageRun(
            id="sr-system-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            output_summary={"success_count": 1},
        )
        system_item = BinarySecurityStageItem(
            id="si-system-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-blocked",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[system_run], stage_items=[system_item], archive_jobs=[], events=[])

        gate = self.manager._evaluate_stage_start_gate(db, task, "entry_analysis")
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(gate["allowed"])
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual("system_analysis", task.current_stage)
        self.assertEqual("running", detail.status)
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertEqual("running", system_summary.status)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"pending", "queued"})
        self.assertEqual([], db.archive_jobs)

    def test_source_workflow_e2e_no_selected_modules_skips_entry_materialization(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        system_run = BinarySecurityStageRun(
            id="sr-system-zero",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-zero",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-zero",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-low",
                        "module_name": "mod-low",
                        "risk_level": "低",
                        "source_dir": "/tmp/source-project/mod-low",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-low",
                        "files_list": "/tmp/source-project/mod-low/files.list",
                        "files_list_path": "/tmp/source-project/mod-low/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-zero",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run],
            stage_items=[system_item],
            archive_jobs=[system_archive],
            events=[],
        )

        with (
            patch.object(self.manager, "_module_selection_candidate_levels", return_value=["高"]),
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True),
        ):
            self._apply_archive_and_reconcile(db, task, system_archive)

        self.manager._refresh_system_analysis_stage_from_synced_items(db, task)
        self.assertTrue(self.manager._should_finalize_without_entries(db, task, "entry_analysis"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertTrue(any(event.event_type == "system_analysis_no_candidate_modules" for event in db.events))

    def test_source_workflow_e2e_no_selected_modules_remains_unmaterialized_after_refresh(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        system_run = BinarySecurityStageRun(
            id="sr-system-zero-finalize",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-zero-finalize",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-zero-finalize",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-low",
                        "module_name": "mod-low",
                        "risk_level": "低",
                        "source_dir": "/tmp/source-project/mod-low",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-low",
                        "files_list": "/tmp/source-project/mod-low/files.list",
                        "files_list_path": "/tmp/source-project/mod-low/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-zero-finalize",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run],
            stage_items=[system_item],
            archive_jobs=[system_archive],
            events=[],
        )

        with (
            patch.object(self.manager, "_module_selection_candidate_levels", return_value=["高"]),
            patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True),
        ):
            self._apply_archive_and_reconcile(db, task, system_archive)

        self.manager._refresh_system_analysis_stage_from_synced_items(db, task)
        system_run.status = "success"
        system_run.finished_at = _now()
        self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertTrue(self.manager._should_finalize_without_entries(db, task, "entry_analysis"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "dataflow_vuln_scan"])
        self.assertFalse(any(event.event_type == "streaming_tail_activated" for event in db.events))
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertIn(system_summary.status, {"running", "success"})
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"pending", "queued"})

    def test_source_workflow_e2e_system_archive_apply_stays_owner_driven_before_entry_materialization(self):
        task = _source_task(
            summary={"input_dir": "/tmp/source-project"},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-owner-driven",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-owner-driven",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-owner-driven",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-owner-driven",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run],
            stage_items=[system_item],
            archive_jobs=[system_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, system_archive)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(signals)
        self.assertEqual("archive_apply", str(signals[-1].get("reconcile_reason") or ""))
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "entry_analysis"])
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertIn(system_summary.status, {"running", "success"})
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"pending", "queued"})

    def test_source_workflow_e2e_entry_archive_without_entries_finishes_without_dataflow(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            }
        )
        task.current_stage = "entry_analysis"
        system_run = BinarySecurityStageRun(
            id="sr-system-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-entry-empty",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-empty",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="eat-empty",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run],
            stage_items=[system_item, entry_item],
            archive_jobs=[entry_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_run.status = "success"
        entry_run.finished_at = _now()
        self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        entry_results = task.summary.get("entry_results") or []
        self.assertEqual(1, len(entry_results))
        self.assertEqual([], entry_results[0].get("entries") or [])
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("success", entry_summary.status)
        self.assertEqual(1, entry_summary.success_items)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued"})

    def test_source_workflow_e2e_entry_zero_input_with_complete_module_state_sets_finalize_gate(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            }
        )
        task.current_stage = "entry_analysis"
        system_run = BinarySecurityStageRun(
            id="sr-system-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-zero-input-complete",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-zero-input-complete",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="eat-zero-input-complete",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run],
            stage_items=[system_item, entry_item],
            archive_jobs=[entry_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_run.status = "success"
        entry_run.finished_at = _now()

        self._refresh_stage_summary(db, task, "entry_analysis")
        self.assertTrue(self.manager._should_finalize_without_entries(db, task, "dataflow_vuln_scan"))

        self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertIn(task.status, {"running", "success"})
        self.assertEqual(task.status, detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("success", entry_summary.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued"})

    def test_source_workflow_e2e_final_dataflow_archive_reconcile_closes_task(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        task.current_stage = "dataflow_vuln_scan"
        system_run = BinarySecurityStageRun(
            id="sr-system-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-final",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "mod-a:entry-1",
                "module_key": "mod-a",
                "vulns": [{"id": "v-1", "severity": "high"}],
            },
        )
        dataflow_archive = self._make_archive_job(
            task=task,
            item=dataflow_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-final",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[dataflow_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, dataflow_archive)

        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(signals)
        self.assertEqual("archive_apply", str(signals[-1].get("reconcile_reason") or ""))
        self.assertIn(task.status, {"running", "success"})
        self.assertEqual(task.status, detail.status)
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        self.assertTrue((task.summary or {}).get("dataflow_results"))
        self.assertEqual(
            "success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )

    def test_source_workflow_e2e_dataflow_success_without_archive_does_not_finalize_parent(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-1",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "fn_a",
                            }
                        ],
                    }
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        system_run = BinarySecurityStageRun(
            id="sr-system-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="success",
            finished_at=_now(),
            output_summary={"success_count": 1},
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-no-archive",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "mod-a:entry-1",
                "module_key": "mod-a",
                "vulns": [{"id": "v-1", "severity": "high"}],
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
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
        self.assertIn(task.status, {"running", "success"})
        self.assertEqual(task.status, detail.status)
        self.assertEqual([], db.archive_jobs)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("success", dataflow_summary.status)

    def test_source_workflow_e2e_dataflow_downstream_missing_marks_missing_without_finalizing_parent(self):
        now = _now()
        from datetime import timedelta

        lease_until = now.replace(microsecond=0) + timedelta(seconds=300)
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-1",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "fn_a",
                            }
                        ],
                    }
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-source-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-1::mod-a",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-missing",
            error_message="下游子任务不存在",
            result={"downstream_status": "downstream_missing"},
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-b",
            heartbeat_at=now,
            lease_expires_at=lease_until,
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

        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("dfa-missing", dataflow_item.downstream_task_id)
        self.assertEqual("running", task.status)
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", detail.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("downstream_missing", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)
        event_types = [event.event_type for event in db.added]
        self.assertIn("owned_execution_owner_reconcile_requested", event_types)
        self.assertIn("owner_reconcile_signal_enqueued", event_types)

    def test_source_workflow_e2e_dataflow_downstream_missing_recovers_on_next_owner_prepare(self):
        now = _now()
        from datetime import timedelta

        lease_until = now.replace(microsecond=0) + timedelta(seconds=300)
        entry = {
            "entry_key": "mod-a:entry-1",
            "module_key": "mod-a",
            "module_name": "mod-a",
            "function_name": "fn_a",
            "definition_file": "a.c",
            "definition_line": "10",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [dict(entry)],
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-source-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-1::mod-a",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-missing-owner",
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
            heartbeat_at=now,
            lease_expires_at=lease_until,
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

        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("dfa-missing-owner", dataflow_item.downstream_task_id)
        self.assertEqual("running", task.status)
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", detail.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("downstream_missing", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)
        observation = dict(self.manager._load_stage_item_result_payload(dataflow_item).get("sync_observation") or {})
        self.assertEqual("not_found", observation.get("error_type"))
        inputs = [dict(entry)]
        executable = self.manager._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=dataflow_run,
            inputs=inputs,
            downstream_service="dataflow_vuln_scan",
            identity=lambda current: (
                current["entry_key"],
                current["function_name"],
                current.get("module_key"),
                current,
            ),
            output_ref=lambda _current: {},
        )

        self.assertEqual([], executable)
        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("dfa-missing-owner", dataflow_item.downstream_task_id)

    def test_source_workflow_e2e_entry_downstream_missing_recovers_on_next_owner_prepare(self):
        now = _now()
        from datetime import timedelta

        lease_until = now.replace(microsecond=0) + timedelta(seconds=300)
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(
            summary={"input_dir": "/tmp/source-project", "selected_modules": [module]},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="downstream_missing",
            downstream_service="entry_analyse",
            downstream_task_id="ea-missing-source",
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
            heartbeat_at=now,
            lease_expires_at=lease_until,
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
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
                    stage_name="entry_analysis",
                    apply_state=True,
                    force=True,
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("downstream_missing", entry_item.status)
        self.assertEqual("ea-missing-source", entry_item.downstream_task_id)
        self.assertEqual("running", task.status)
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", detail.status)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("downstream_missing", entry_summary.status)
        self.assertEqual(1, entry_summary.downstream_missing_items)
        observation = dict(self.manager._load_stage_item_result_payload(entry_item).get("sync_observation") or {})
        self.assertEqual("not_found", observation.get("error_type"))
        inputs = [dict(module)]
        executable = self.manager._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=entry_run,
            inputs=inputs,
            downstream_service="entry_analyse",
            identity=lambda current: (
                current["module_key"],
                current["module_name"],
                current.get("firmware_key"),
                current,
            ),
            output_ref=lambda _current: {},
        )

        self.assertEqual([], executable)
        self.assertEqual("downstream_missing", entry_item.status)
        self.assertEqual("ea-missing-source", entry_item.downstream_task_id)

    def test_source_workflow_e2e_streaming_incremental_seed(self):
        task = _source_task(
            summary={"input_dir": "/tmp/source-project"},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-stream",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-stream",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-stream-1",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-stream-1",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run],
            stage_items=[system_item],
            archive_jobs=[system_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, system_archive)
        self.manager._refresh_system_analysis_stage_from_synced_items(db, task)

        entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
        module = self.manager._entry_analysis_inputs(db, task)[0]
        entry_item = self.manager._upsert_stage_item(
            db,
            task=task,
            stage_run=entry_run,
            stage_name="entry_analysis",
            item_key=module["module_key"],
            item_name=module["module_name"],
            parent_key=module.get("firmware_key"),
            downstream_service="entry_analyse",
            input_ref=module,
            retrying=False,
            auto_retrying=False,
        )
        entry_item.status = "success"
        entry_item.downstream_task_id = "eat-stream-a"
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
        )
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        before_stage = task.current_stage
        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._trigger_dataflow_items_from_entry_result(
                db,
                task,
                self.manager._entry_module_result_from_stage_item(task, entry_item),
                upstream_item=entry_item,
            )
        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(1, len(dataflow_items))
        self.assertEqual("running", detail.status)
        self.assertEqual(before_stage, task.current_stage)
        self.assertIn(
            "dataflow_vuln_scan",
            [str(run.stage_name or "") for run in db.stage_runs],
        )
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"running", "success"})
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued", "running"})
        self.assertTrue(any(event.event_type == "streaming_dataflow_vuln_scan_items_seeded" for event in db.events))

    def test_source_workflow_e2e_entry_success_without_archive_does_not_start_dataflow(self):
        task = _source_task(
            summary={"input_dir": "/tmp/source-project"},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-no-archive",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        gate = self.manager._evaluate_stage_start_gate(db, task, "dataflow_vuln_scan")
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertFalse(gate["allowed"])
        self.assertEqual("running", detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "dataflow_vuln_scan"])
        self.assertEqual("system_analysis", task.current_stage)
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"running", "success"})
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued"})

    def test_source_workflow_e2e_manual_entry_confirmation_blocks_streaming_until_selected(self):
        task = _source_task(
            summary={"input_dir": "/tmp/source-project"},
            policy_json=json.dumps(
                {
                    "pipeline_mode": "mixed_streaming",
                    "entry_selection_mode": "manual_confirm",
                }
            ),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-manual-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-manual-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-entry-manual-e2e",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/tmp/source-project/mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    },
                    {
                        "entry_key": "mod-a:entry-2",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_b",
                        "definition_file": "b.c",
                        "definition_line": "20",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    },
                ],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="eat-entry-manual-e2e",
        )
        entry_archive.archive_status = "success"
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[entry_archive],
            events=[],
        )

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_result = self.manager._entry_module_result_from_stage_item(task, entry_item)
        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            seeded_before_confirmation = self.manager._trigger_dataflow_items_from_entry_result(
                db,
                task,
                entry_result,
                upstream_item=entry_item,
            )

        task.status = "pending_entry_confirmation"
        selection_before = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        start_gate_before = self.manager._evaluate_stage_start_gate(db, task, "dataflow_vuln_scan")
        detail_before = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertEqual([], seeded_before_confirmation)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertTrue(selection_before.requires_confirmation)
        self.assertEqual(2, len(selection_before.candidate_entries))
        self.assertEqual([], selection_before.selected_entry_keys)
        self.assertFalse(start_gate_before["allowed"])
        self.assertEqual("pending_entry_confirmation", detail_before.status)

        original_write = self.manager._write_task_metadata
        original_run_stage_pool = self.manager._run_stage_pool
        self.manager._write_task_metadata = lambda *_args, **_kwargs: None

        async def fake_run_stage_pool(_task, items, *_args, **_kwargs):
            return [{"status": "success", "item": dict(item)} for item in items]

        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            detail_after_confirmation = self.manager.confirm_entry_selection(
                db,
                project_id=task.project_id,
                task_id=task.id,
                selected_entry_keys=["mod-a:entry-2"],
            )
            dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
            status, summary = asyncio.run(
                self.manager._stage_dataflow_vuln_scan(
                    db,
                    task,
                    dataflow_run,
                    token=None,
                    retry_existing=False,
                )
            )
        finally:
            self.manager._write_task_metadata = original_write
            self.manager._run_stage_pool = original_run_stage_pool

        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        selection_after = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        detail_after = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertEqual("pending", detail_after_confirmation.status)
        self.assertFalse(selection_after.requires_confirmation)
        self.assertEqual(["mod-a:entry-2"], selection_after.selected_entry_keys)
        self.assertEqual(1, len(selection_after.selected_entries))
        self.assertEqual("success", status)
        self.assertEqual(1, len(dataflow_items))
        self.assertEqual("mod-a:entry-2", dataflow_items[0].item_key)
        self.assertEqual("fn_b", dataflow_items[0].item_name)
        self.assertEqual(1, summary.get("success_count"))
        self.assertEqual(task.status, detail_after.status)
        self.assertTrue(any(event.event_type == "entry_selection_confirmed" for event in db.events))

    def test_source_workflow_e2e_manual_entry_confirmation_with_zero_selection_finishes_without_dataflow(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
            policy_json=json.dumps(
                {
                    "pipeline_mode": "mixed_streaming",
                    "entry_selection_mode": "manual_confirm",
                }
            ),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-manual-empty-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-manual-empty-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-entry-manual-empty-e2e",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/tmp/source-project/mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="eat-entry-manual-empty-e2e",
        )
        entry_archive.archive_status = "success"
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[entry_archive],
            events=[],
        )

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        task.status = "pending_entry_confirmation"

        original_write = self.manager._write_task_metadata
        original_enqueue = self.manager._enqueue_task
        self.manager._write_task_metadata = lambda *_args, **_kwargs: None
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            detail_after_confirmation = self.manager.confirm_entry_selection(
                db,
                project_id=task.project_id,
                task_id=task.id,
                selected_entry_keys=[],
            )
            dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
            status, summary = asyncio.run(
                self.manager._stage_dataflow_vuln_scan(
                    db,
                    task,
                    dataflow_run,
                    token=None,
                    retry_existing=False,
                )
            )
            dataflow_run.status = status
            dataflow_run.finished_at = _now()
            self._refresh_stage_summary(db, task, "entry_analysis")
            self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._write_task_metadata = original_write
            self.manager._enqueue_task = original_enqueue

        selection_after = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        detail_after = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertEqual("pending", detail_after_confirmation.status)
        self.assertFalse(selection_after.requires_confirmation)
        self.assertEqual([], selection_after.selected_entry_keys)
        self.assertEqual([], selection_after.selected_entries)
        self.assertIn(status, {"running", "success"})
        self.assertIn("无可用于数据流漏洞挖掘的入口", str(summary.get("reason") or ""))
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertEqual([], self.manager._effective_entry_inputs(task, db))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._evaluate_stage_start_gate(db, task, "dataflow_vuln_scan")["allowed"])
        self.assertIn(task.status, {"pending", "running", "success"})
        self.assertEqual(task.status, detail_after.status)
        self.assertIn(
            next(summary_row.status for summary_row in detail_after.stage_summaries if summary_row.stage_name == "dataflow_vuln_scan"),
            {"pending", "queued", "running", "success"},
        )
        self.assertTrue(any(event.event_type == "entry_selection_confirmed" for event in db.events))

    def test_source_workflow_e2e_cancel_running_entry_analysis_cancels_source_child_and_runner(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        task.status = "running"
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-cancel-source-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-cancel-source-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="ea-cancel-source-e2e",
        )
        entry_item.input_ref = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
        }
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )
        cancelled_children: list[str] = []
        cancelled_ref_batches: list[list[dict[str, str]]] = []
        local_cancel_requests: list[tuple[str, bool]] = []

        async def _fake_cancel_downstream(item, _token):
            cancelled_children.append(str(item.downstream_task_id or ""))

        async def _fake_cancel_downstream_refs(_db, _task, refs, _token):
            cancelled_ref_batches.append([dict(ref) for ref in refs])
            return len(list(refs))

        async def _fake_request_local_worker_cancel(task_id: str, *, wait_for_runner: bool):
            local_cancel_requests.append((task_id, wait_for_runner))

        original_write = self.manager._write_task_metadata_async
        original_cancel_item = self.manager._cancel_downstream
        original_cancel_refs = self.manager._cancel_downstream_refs
        original_request_local_cancel = self.manager._request_local_worker_cancel
        try:
            self.manager._write_task_metadata_async = _fake_request_local_worker_cancel  # placeholder overridden below
            self.manager._cancel_downstream = _fake_cancel_downstream
            self.manager._cancel_downstream_refs = _fake_cancel_downstream_refs
            self.manager._request_local_worker_cancel = _fake_request_local_worker_cancel

            async def _noop_write(*_args, **_kwargs):
                return None

            self.manager._write_task_metadata_async = _noop_write
            cancelled_stages = asyncio.run(self.manager._prepare_cancel_task(db, task))
        finally:
            self.manager._write_task_metadata_async = original_write
            self.manager._cancel_downstream = original_cancel_item
            self.manager._cancel_downstream_refs = original_cancel_refs
            self.manager._request_local_worker_cancel = original_request_local_cancel

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(["entry_analysis"], cancelled_stages)
        self.assertEqual("cancelling", task.status)
        self.assertEqual("cancelled", entry_item.status)
        self.assertEqual("cancelled", entry_run.status)
        self.assertEqual(["ea-cancel-source-e2e"], cancelled_children)
        self.assertEqual([(task.id, False)], local_cancel_requests)
        self.assertTrue(cancelled_ref_batches)
        self.assertEqual("cancelling", detail.status)
        self.assertTrue(any(event.event_type == "task_cancelling" for event in db.events))

    def test_source_workflow_e2e_cancel_pending_entry_confirmation_does_not_spawn_dataflow_or_cancel_completed_child(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming", "entry_selection_mode": "manual_confirm"}),
        )
        task.status = "pending_entry_confirmation"
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-pending-confirm-cancel-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-pending-confirm-cancel-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-pending-confirm-cancel-source",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                    }
                ],
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )
        cancelled_children: list[str] = []
        cancelled_ref_batches: list[list[dict[str, str]]] = []
        local_cancel_requests: list[tuple[str, bool]] = []

        async def _fake_cancel_downstream(item, _token):
            cancelled_children.append(str(item.downstream_task_id or ""))

        async def _fake_cancel_downstream_refs(_db, _task, refs, _token):
            cancelled_ref_batches.append([dict(ref) for ref in refs])
            return len(list(refs))

        async def _fake_request_local_worker_cancel(task_id: str, *, wait_for_runner: bool):
            local_cancel_requests.append((task_id, wait_for_runner))

        original_write = self.manager._write_task_metadata_async
        original_cancel_item = self.manager._cancel_downstream
        original_cancel_refs = self.manager._cancel_downstream_refs
        original_request_local_cancel = self.manager._request_local_worker_cancel
        try:
            self.manager._cancel_downstream = _fake_cancel_downstream
            self.manager._cancel_downstream_refs = _fake_cancel_downstream_refs
            self.manager._request_local_worker_cancel = _fake_request_local_worker_cancel

            async def _noop_write(*_args, **_kwargs):
                return None

            self.manager._write_task_metadata_async = _noop_write
            cancelled_stages = asyncio.run(self.manager._prepare_cancel_task(db, task))
        finally:
            self.manager._write_task_metadata_async = original_write
            self.manager._cancel_downstream = original_cancel_item
            self.manager._cancel_downstream_refs = original_cancel_refs
            self.manager._request_local_worker_cancel = original_request_local_cancel

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([], cancelled_stages)
        self.assertEqual("cancelling", task.status)
        self.assertEqual("success", entry_item.status)
        self.assertEqual("success", entry_run.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertEqual([], cancelled_children)
        self.assertEqual([], cancelled_ref_batches)
        self.assertEqual([(task.id, False)], local_cancel_requests)
        self.assertEqual("cancelling", detail.status)
        self.assertTrue(any(event.event_type == "task_cancelling" for event in db.events))

    def test_source_workflow_e2e_cancel_clears_stale_sync_error_and_replacement_markers_from_cancelled_item(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        task.current_stage = "entry_analysis"
        task.status = "running"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-cancel-clear-sync-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-cancel-clear-sync-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="ea-cancel-clear-sync-source",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "sync_status": "transport_error",
                "last_sync_error_message": "owner_lost_retry_exhausted",
                "last_sync_error_type": "StaleTaskExecution",
                "downstream": {
                    "task_id": "ea-cancel-clear-sync-source",
                    "status": "running",
                    "error_message": "owner_lost_retry_exhausted",
                },
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_message": "owner_lost_retry_exhausted",
                    "error_type": "StaleTaskExecution",
                    "replacement_in_progress": True,
                    "binding_cleared": True,
                    "verification_status": "pending",
                    "old_downstream_task_id": "ea-old-cancel-clear-sync-source",
                    "budget_exhausted": True,
                },
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            events=[],
        )

        local_cancel_requests: list[tuple[str, bool]] = []

        async def _fake_cancel_downstream(_item, _token):
            return None

        async def _fake_cancel_downstream_refs(_db, _task, _refs, _token):
            return 0

        async def _fake_request_local_worker_cancel(task_id: str, *, wait_for_runner: bool):
            local_cancel_requests.append((task_id, wait_for_runner))

        original_write = self.manager._write_task_metadata_async
        original_cancel_item = self.manager._cancel_downstream
        original_cancel_refs = self.manager._cancel_downstream_refs
        original_request_local_cancel = self.manager._request_local_worker_cancel
        try:
            self.manager._cancel_downstream = _fake_cancel_downstream
            self.manager._cancel_downstream_refs = _fake_cancel_downstream_refs
            self.manager._request_local_worker_cancel = _fake_request_local_worker_cancel

            async def _noop_write(*_args, **_kwargs):
                return None

            self.manager._write_task_metadata_async = _noop_write
            asyncio.run(self.manager._prepare_cancel_task(db, task))
        finally:
            self.manager._write_task_metadata_async = original_write
            self.manager._cancel_downstream = original_cancel_item
            self.manager._cancel_downstream_refs = original_cancel_refs
            self.manager._request_local_worker_cancel = original_request_local_cancel

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        page = self.manager.get_task_stage_items_page(
            db,
            project_id=task.project_id,
            task_id=task.id,
            stage_name="entry_analysis",
            page=1,
            per_page=10,
        )
        page_item = page.items[0]
        observation = dict(self.manager._load_stage_item_result_payload(entry_item).get("sync_observation") or {})

        self.assertEqual("cancelling", task.status)
        self.assertEqual("cancelled", entry_item.status)
        self.assertEqual([(task.id, False)], local_cancel_requests)
        self.assertIsNone(entry_item.result.get("last_sync_error_message"))
        self.assertIsNone(entry_item.result.get("last_sync_error_type"))
        self.assertEqual("cancelled", observation.get("downstream_status"))
        self.assertEqual("cancelled", observation.get("mapped_status"))
        self.assertTrue(bool(observation.get("state_applied")))
        self.assertNotIn("replacement_in_progress", observation)
        self.assertNotIn("binding_cleared", observation)
        self.assertNotIn("old_downstream_task_id", observation)
        self.assertIsNone(page_item.sync_observation_error_message)
        self.assertIsNone(page_item.sync_observation_error_type)
        self.assertEqual("cancelled", page_item.status)
        self.assertEqual("cancelling", detail.status)

    def test_source_workflow_e2e_delete_running_dataflow_removes_parent_after_existing_child_cleanup(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        task.status = "running"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-delete-source-dataflow"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-delete-source-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-delete-source-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-delete-source-e2e",
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-source-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="delete",
            target_stage="dataflow_vuln_scan",
            status="running",
            request_payload={"force_delete": False},
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            operations=[operation],
            stage_runs=[dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
            state_events=[],
        )
        cancelled_ref_batches: list[list[dict[str, str]]] = []
        deleted_ref_batches: list[list[dict[str, str]]] = []
        local_cancel_requests: list[tuple[str, bool]] = []

        async def _fake_cancel_downstream_refs(_db, _task, refs, _token):
            cancelled_ref_batches.append([dict(ref) for ref in refs])
            return len(list(refs))

        async def _fake_delete_downstream_refs(_db, _task, refs, _token, **_kwargs):
            deleted_ref_batches.append([dict(ref) for ref in refs])
            return len(list(refs))

        async def _fake_cleanup_task_workspace(_task, token=None):
            del token
            return "deleted"

        async def _fake_request_local_worker_cancel(task_id: str, *, wait_for_runner: bool):
            local_cancel_requests.append((task_id, wait_for_runner))

        async def _noop_write(*_args, **_kwargs):
            return None

        original_write = self.manager._write_task_metadata_async
        original_cancel_refs = self.manager._cancel_downstream_refs
        original_delete_refs = self.manager._delete_downstream_refs
        original_cleanup_workspace = self.manager._cleanup_task_workspace
        original_request_local_cancel = self.manager._request_local_worker_cancel
        original_wait_quiesce = self.manager._wait_for_task_workspace_quiesce
        try:
            self.manager._write_task_metadata_async = _noop_write
            self.manager._cancel_downstream_refs = _fake_cancel_downstream_refs
            self.manager._delete_downstream_refs = _fake_delete_downstream_refs
            self.manager._cleanup_task_workspace = _fake_cleanup_task_workspace
            self.manager._request_local_worker_cancel = _fake_request_local_worker_cancel
            self.manager._wait_for_task_workspace_quiesce = lambda *_args, **_kwargs: asyncio.sleep(0, result=True)
            asyncio.run(self.manager._prepare_delete_task(db, task))
        finally:
            self.manager._write_task_metadata_async = original_write
            self.manager._cancel_downstream_refs = original_cancel_refs
            self.manager._delete_downstream_refs = original_delete_refs
            self.manager._cleanup_task_workspace = original_cleanup_workspace
            self.manager._request_local_worker_cancel = original_request_local_cancel
            self.manager._wait_for_task_workspace_quiesce = original_wait_quiesce

        self.assertEqual([], db.tasks)
        self.assertEqual([(task.id, False)], local_cancel_requests)
        self.assertEqual(["dfa-delete-source-e2e"], [row["task_id"] for row in cancelled_ref_batches[0]])
        self.assertEqual(["dfa-delete-source-e2e"], [row["task_id"] for row in deleted_ref_batches[0]])
        event_types = [row.event_type for row in db.events]
        self.assertIn("task_delete_requested", event_types)
        self.assertIn("task_delete_completed", event_types)

    def test_source_workflow_e2e_delete_with_replacement_marked_child_cleans_task_without_residual_stage_state(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        task.status = "running"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-delete-source-replacement"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-delete-source-replacement",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-delete-source-replacement",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-delete-source-replacement",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "sync_status": "transport_error",
                "last_sync_error_message": "owner_lost_retry_exhausted",
                "last_sync_error_type": "StaleTaskExecution",
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_message": "owner_lost_retry_exhausted",
                    "error_type": "StaleTaskExecution",
                    "replacement_in_progress": True,
                    "binding_cleared": True,
                    "verification_status": "pending",
                    "old_downstream_task_id": "dfa-old-delete-source-replacement",
                },
            },
        )
        operation = BinarySecurityTaskOperation(
            id="op-delete-source-replacement",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="delete",
            target_stage="dataflow_vuln_scan",
            status="running",
            request_payload={"force_delete": False},
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            operations=[operation],
            stage_runs=[dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
            state_events=[],
        )
        cancelled_ref_batches: list[list[dict[str, str]]] = []
        deleted_ref_batches: list[list[dict[str, str]]] = []

        async def _fake_cancel_downstream_refs(_db, _task, refs, _token):
            cancelled_ref_batches.append([dict(ref) for ref in refs])
            return len(list(refs))

        async def _fake_delete_downstream_refs(_db, _task, refs, _token, **_kwargs):
            deleted_ref_batches.append([dict(ref) for ref in refs])
            return len(list(refs))

        async def _fake_cleanup_task_workspace(_task, token=None):
            del token
            return "deleted"

        async def _fake_request_local_worker_cancel(*_args, **_kwargs):
            return None

        async def _noop_write(*_args, **_kwargs):
            return None

        original_write = self.manager._write_task_metadata_async
        original_cancel_refs = self.manager._cancel_downstream_refs
        original_delete_refs = self.manager._delete_downstream_refs
        original_cleanup_workspace = self.manager._cleanup_task_workspace
        original_request_local_cancel = self.manager._request_local_worker_cancel
        original_wait_quiesce = self.manager._wait_for_task_workspace_quiesce
        try:
            self.manager._write_task_metadata_async = _noop_write
            self.manager._cancel_downstream_refs = _fake_cancel_downstream_refs
            self.manager._delete_downstream_refs = _fake_delete_downstream_refs
            self.manager._cleanup_task_workspace = _fake_cleanup_task_workspace
            self.manager._request_local_worker_cancel = _fake_request_local_worker_cancel
            self.manager._wait_for_task_workspace_quiesce = lambda *_args, **_kwargs: asyncio.sleep(0, result=True)
            asyncio.run(self.manager._prepare_delete_task(db, task))
        finally:
            self.manager._write_task_metadata_async = original_write
            self.manager._cancel_downstream_refs = original_cancel_refs
            self.manager._delete_downstream_refs = original_delete_refs
            self.manager._cleanup_task_workspace = original_cleanup_workspace
            self.manager._request_local_worker_cancel = original_request_local_cancel
            self.manager._wait_for_task_workspace_quiesce = original_wait_quiesce

        self.assertEqual([], db.tasks)
        self.assertEqual([], db.stage_items)
        self.assertEqual([], db.stage_runs)
        self.assertEqual(["dfa-delete-source-replacement"], [row["task_id"] for row in cancelled_ref_batches[0]])
        self.assertEqual(["dfa-delete-source-replacement"], [row["task_id"] for row in deleted_ref_batches[0]])
        event_types = [row.event_type for row in db.events]
        self.assertIn("task_delete_requested", event_types)
        self.assertIn("task_delete_completed", event_types)

    def test_source_workflow_e2e_delete_queued_blocks_retry_continue_force_reset_and_retry_failed_items(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.cleanup_snapshot = {
            "delete_queued": True,
            "delete_in_progress": False,
            "delete_mode": "delete",
            "delete_operation_id": "op-delete-queued-source",
        }
        db = _AppendingModelAwareDb(tasks=[task], operations=[], stage_runs=[], stage_items=[], archive_jobs=[], events=[])

        with self.assertRaises(ValidationError) as retry_ctx:
            self.manager.retry_task(db, project_id=task.project_id, task_id=task.id)
        self.assertIn("异步删除流程", str(retry_ctx.exception))

        with self.assertRaises(ValidationError) as continue_ctx:
            asyncio.run(self.manager.continue_task(db, project_id=task.project_id, task_id=task.id))
        self.assertIn("异步删除流程", str(continue_ctx.exception))

        with self.assertRaises(ValidationError) as force_reset_ctx:
            asyncio.run(self.manager.force_reset_task_to_pending(db, project_id=task.project_id, task_id=task.id))
        self.assertIn("异步删除流程", str(force_reset_ctx.exception))

        with self.assertRaises(ValidationError) as retry_failed_ctx:
            self.manager.retry_failed_items(db, project_id=task.project_id, task_id=task.id)
        self.assertIn("异步删除流程", str(retry_failed_ctx.exception))

    def test_source_workflow_e2e_manual_entry_confirmation_cannot_be_applied_twice(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming", "entry_selection_mode": "manual_confirm"}),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-confirm-once-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-confirm-once-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-confirm-once-source",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                    },
                    {
                        "entry_key": "mod-a:entry-2",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_b",
                    },
                ],
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        task.status = "pending_entry_confirmation"

        original_write = self.manager._write_task_metadata
        original_run_stage_pool = self.manager._run_stage_pool
        self.manager._write_task_metadata = lambda *_args, **_kwargs: None

        async def fake_run_stage_pool(_task, items, *_args, **_kwargs):
            return [{"status": "success", "item": dict(item)} for item in items]

        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            detail_after_confirmation = self.manager.confirm_entry_selection(
                db,
                project_id=task.project_id,
                task_id=task.id,
                selected_entry_keys=["mod-a:entry-2"],
            )
            with self.assertRaises(ValidationError):
                self.manager.confirm_entry_selection(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    selected_entry_keys=["mod-a:entry-1"],
                )
        finally:
            self.manager._write_task_metadata = original_write
            self.manager._run_stage_pool = original_run_stage_pool

        selection_after = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("pending", detail_after_confirmation.status)
        self.assertEqual(["mod-a:entry-2"], selection_after.selected_entry_keys)
        self.assertFalse(selection_after.requires_confirmation)

    def test_source_workflow_e2e_entry_sync_recovery_clears_owner_lost_error_from_read_model(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        task.status = "running"
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-recover-read-model-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-recover-read-model-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="source_project-security_policy",
            item_name="security_policy",
            parent_key="source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="eat-current-source",
            error_message="owner_lost_retry_exhausted",
            result={
                "last_sync_error_message": "owner_lost_retry_exhausted",
                "last_sync_error_type": "StaleTaskExecution",
                "last_sync_result": "error",
                "sync_error_budget_exhausted": True,
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_type": "StaleTaskExecution",
                    "error_message": "任务 task-source 当前执行 token 已失效",
                    "last_result": "error",
                    "budget_exhausted": True,
                    "consecutive_error_count": 3,
                },
            },
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[entry_run], stage_items=[entry_item], events=[])

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, _item, _token):
            return {
                "task_id": "eat-current-source",
                "status": "running",
                "parent_stage_item_id": "si-entry-recover-read-model-source",
                "parent_stage_item_key": "source_project-security_policy",
            }

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            asyncio.run(
                self.manager.sync_downstream_status(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    stage_name="entry_analysis",
                    item_id=entry_item.id,
                    apply_state=True,
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        page = self.manager.get_task_stage_items_page(
            db,
            project_id=task.project_id,
            task_id=task.id,
            stage_name="entry_analysis",
            page=1,
            per_page=10,
        )

        self.assertEqual("running", entry_item.status)
        self.assertEqual("synced", entry_item.result.get("sync_status"))
        self.assertEqual("running", entry_item.result.get("downstream_status"))
        self.assertIsNone(entry_item.result.get("last_sync_error_message"))
        self.assertIsNone(entry_item.result.get("last_sync_error_type"))
        self.assertFalse(bool(entry_item.result.get("sync_error_budget_exhausted")))
        self.assertEqual("running", detail.status)
        self.assertEqual(1, page.total)
        page_item = page.items[0]
        self.assertEqual("running", page_item.status)
        self.assertIsNotNone(page_item.last_sync_success_at)
        self.assertIsNone(page_item.last_sync_error_at)
        self.assertIsNone(page_item.sync_observation_error_message)
        self.assertIsNone(page_item.sync_observation_error_type)

    def test_source_workflow_e2e_manual_entry_confirmation_rejects_unknown_keys_and_deduplicates_selection(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming", "entry_selection_mode": "manual_confirm"}),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-sync-events-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-sync-events-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="source_project-security_policy",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-sync-events-source",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                    },
                    {
                        "entry_key": "mod-a:entry-2",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_b",
                    },
                ],
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        task.status = "pending_entry_confirmation"

        original_write = self.manager._write_task_metadata
        original_run_stage_pool = self.manager._run_stage_pool
        self.manager._write_task_metadata = lambda *_args, **_kwargs: None

        async def fake_run_stage_pool(_task, items, *_args, **_kwargs):
            return [{"status": "success", "item": dict(item)} for item in items]

        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            with self.assertRaises(ValidationError):
                self.manager.confirm_entry_selection(
                    db,
                    project_id=task.project_id,
                    task_id=task.id,
                    selected_entry_keys=["mod-a:entry-1", "mod-a:missing-entry"],
                )
            detail_after_confirmation = self.manager.confirm_entry_selection(
                db,
                project_id=task.project_id,
                task_id=task.id,
                selected_entry_keys=["mod-a:entry-2", "mod-a:entry-2", "mod-a:entry-1"],
            )
        finally:
            self.manager._write_task_metadata = original_write
            self.manager._run_stage_pool = original_run_stage_pool

        selection_after = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("pending", detail_after_confirmation.status)
        self.assertEqual(["mod-a:entry-2", "mod-a:entry-1"], selection_after.selected_entry_keys)
        self.assertFalse(selection_after.requires_confirmation)

    def test_source_workflow_e2e_pending_entry_confirmation_retry_failed_items_falls_back_to_continue(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming", "entry_selection_mode": "manual_confirm"}),
        )
        task.status = "pending_entry_confirmation"
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-confirm-retry-failed-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-confirm-retry-failed-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-confirm-retry-failed-source",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                    }
                ],
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            events=[],
        )
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)

        wakeups: list[tuple[str, str, str | None]] = []
        original_wakeup = self.manager._request_local_worker_control_wakeup_nowait
        self.manager._request_local_worker_control_wakeup_nowait = (
            lambda task_id, action, operation_id=None: wakeups.append((task_id, action, operation_id))
        )
        try:
            operation = self.manager.retry_failed_items(db, project_id=task.project_id, task_id=task.id)
        finally:
            self.manager._request_local_worker_control_wakeup_nowait = original_wakeup

        selection_after = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("continue", operation.operation_type)
        self.assertEqual("entry_analysis", operation.target_stage)
        self.assertEqual(operation.id, task.current_operation_id)
        self.assertEqual([(task.id, "continue", operation.id)], wakeups)
        self.assertEqual([], selection_after.selected_entry_keys)
        self.assertTrue(selection_after.requires_confirmation)
        self.assertEqual(
            "task_retry_failed_items_continue_accepted",
            getattr(db.added[-1], "event_type", ""),
        )

    def test_source_workflow_e2e_pending_entry_confirmation_accepts_retry_and_continue_operations(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming", "entry_selection_mode": "manual_confirm"}),
        )
        task.status = "pending_entry_confirmation"
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-confirm-continue-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-confirm-continue-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-confirm-continue-source",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                    }
                ],
            },
        )

        def _build_db():
            db_local = _AppendingModelAwareDb(
                tasks=[task],
                stage_runs=[entry_run],
                stage_items=[entry_item],
                events=[],
            )
            self.manager._rebuild_entry_results_from_stage_items(db_local, task, entry_run)
            return db_local

        wakeups: list[tuple[str, str, str | None]] = []
        original_wakeup = self.manager._request_local_worker_control_wakeup_nowait
        self.manager._request_local_worker_control_wakeup_nowait = (
            lambda task_id, action, operation_id=None: wakeups.append((task_id, action, operation_id))
        )
        try:
            retry_db = _build_db()
            retry_operation = self.manager.retry_task(retry_db, project_id=task.project_id, task_id=task.id)
            task.current_operation_id = None
            continue_db = _build_db()
            continue_operation = asyncio.run(
                self.manager.continue_task(continue_db, project_id=task.project_id, task_id=task.id)
            )
        finally:
            self.manager._request_local_worker_control_wakeup_nowait = original_wakeup

        self.assertEqual("retry", retry_operation.operation_type)
        self.assertEqual("system_analysis", retry_operation.target_stage)
        self.assertEqual("continue", continue_operation.operation_type)
        self.assertEqual("entry_analysis", continue_operation.target_stage)
        self.assertEqual(
            [
                (task.id, "retry", retry_operation.id),
                (task.id, "continue", continue_operation.id),
            ],
            wakeups,
        )

    def test_source_workflow_e2e_pending_entry_confirmation_active_operation_blocks_retry_continue_and_retry_failed_items(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming", "entry_selection_mode": "manual_confirm"}),
        )
        task.status = "pending_entry_confirmation"
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-active-source-confirm"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-confirm-active-op-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-confirm-active-op-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-confirm-active-op-source",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                    }
                ],
            },
        )
        active_operation = BinarySecurityTaskOperation(
            id="op-active-source-confirm",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="cancel",
            target_stage="entry_analysis",
            status="running",
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            operations=[active_operation],
            events=[],
        )
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)

        with self.assertRaises(ValidationError) as retry_ctx:
            self.manager.retry_task(db, project_id=task.project_id, task_id=task.id)
        with self.assertRaises(ValidationError) as continue_ctx:
            asyncio.run(self.manager.continue_task(db, project_id=task.project_id, task_id=task.id))
        with self.assertRaises(ValidationError) as retry_failed_ctx:
            self.manager.retry_failed_items(db, project_id=task.project_id, task_id=task.id)

        self.assertIn("当前任务已有进行中的操作: cancel", str(retry_ctx.exception))
        self.assertIn("当前任务已有进行中的操作: cancel", str(continue_ctx.exception))
        self.assertIn("当前任务已有进行中的操作: cancel", str(retry_failed_ctx.exception))
        self.assertEqual("op-active-source-confirm", task.current_operation_id)

    def test_source_workflow_e2e_retry_stage_full_cleanup_removes_stale_sync_error_items_from_stage_listing(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.execution_epoch = 0
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "owner_lost_retry_exhausted"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-clean-listing",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-retry-clean-listing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-stale-sync-source",
            error_message="owner_lost_retry_exhausted",
            result={
                "last_sync_error_message": "owner_lost_retry_exhausted",
                "last_sync_error_type": "StaleTaskExecution",
                "sync_error_budget_exhausted": True,
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_type": "StaleTaskExecution",
                    "error_message": "owner_lost_retry_exhausted",
                    "budget_exhausted": True,
                },
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
            state_events=[],
        )

        async def _fake_cleanup_downstream_refs(_db, _task, refs, _token):
            self.assertEqual([], refs)

        self.manager._cleanup_downstream_refs = _fake_cleanup_downstream_refs
        stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))
        page = self.manager.get_task_stage_items_page(
            db,
            project_id=task.project_id,
            task_id=task.id,
            stage_name="entry_analysis",
            page=1,
            per_page=10,
        )

        self.assertEqual(self.manager._stage_sequence_for_task(task), stage_sequence)
        self.assertEqual([], self.manager._effective_entry_inputs(task, db))
        self.assertEqual(0, page.total)
        self.assertEqual([], page.items)

    def test_source_workflow_e2e_retry_hard_restart_invalidates_old_epoch_entry_results_for_next_run(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "execution_epoch": 0,
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-1",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "fn_a",
                                "execution_epoch": 0,
                            }
                        ],
                    }
                ],
                "runtime_workset": {"pending_task_layer_reconcile": {"reason": "retry_after_failure"}},
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.execution_epoch = 0
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "entry extraction failed"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-old-epoch",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            state_events=[],
        )

        async def _fake_cleanup_downstream_refs(_db, _task, refs, _token):
            self.assertEqual([], refs)

        self.manager._cleanup_downstream_refs = _fake_cleanup_downstream_refs
        stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(self.manager._stage_sequence_for_task(task), stage_sequence)
        self.assertEqual(1, task.execution_epoch)
        self.assertEqual("failed", task.status)
        self.assertEqual([], self.manager._effective_entry_inputs(task, db))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._evaluate_stage_start_gate(db, task, "dataflow_vuln_scan")["allowed"])
        self.assertEqual([], self.manager._entry_result_modules_for_current_epoch(task))
        self.assertEqual("failed", detail.status)

    def test_source_workflow_e2e_retry_hard_restart_removes_stale_sync_error_stage_items_from_listing(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "execution_epoch": 0,
                        "entries": [],
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.execution_epoch = 0
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "owner_lost_retry_exhausted"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-hard-clean",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-retry-hard-clean",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old-hard-clean-source",
            error_message="owner_lost_retry_exhausted",
            result={
                "last_sync_error_message": "owner_lost_retry_exhausted",
                "last_sync_error_type": "StaleTaskExecution",
                "sync_error_budget_exhausted": True,
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_type": "StaleTaskExecution",
                    "error_message": "owner_lost_retry_exhausted",
                    "budget_exhausted": True,
                },
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
            state_events=[],
        )

        async def _fake_cleanup_downstream_refs(_db, _task, refs, _token):
            self.assertEqual([], refs)

        self.manager._cleanup_downstream_refs = _fake_cleanup_downstream_refs
        stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))
        page = self.manager.get_task_stage_items_page(
            db,
            project_id=task.project_id,
            task_id=task.id,
            stage_name="entry_analysis",
            page=1,
            per_page=10,
        )

        self.assertEqual(self.manager._stage_sequence_for_task(task), stage_sequence)
        self.assertEqual(1, task.execution_epoch)
        self.assertEqual(0, page.total)
        self.assertEqual([], page.items)

    def test_source_workflow_e2e_retry_hard_restart_keeps_stage_summaries_pending_without_stage_level_abnormal_reason(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "execution_epoch": 0,
                        "entries": [],
                    }
                ],
                "runtime_workset": {"pending_task_layer_reconcile": {"reason": "retry_after_failure"}},
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.execution_epoch = 0
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "owner_lost_retry_exhausted"
        task.latest_abnormal_reason = {
            "code": "owner_lost_retry_exhausted",
            "category": "downstream",
            "status": "failed",
            "title": "下游 owner 丢失自动恢复失败",
            "message": "owner_lost_retry_exhausted",
            "stage_name": "entry_analysis",
        }
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-hard-stage-summary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-retry-hard-stage-summary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old-stage-summary-source",
            error_message="owner_lost_retry_exhausted",
            result={
                "last_sync_error_message": "owner_lost_retry_exhausted",
                "last_sync_error_type": "StaleTaskExecution",
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_message": "owner_lost_retry_exhausted",
                    "error_type": "StaleTaskExecution",
                    "budget_exhausted": True,
                },
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
            state_events=[],
        )

        async def _fake_cleanup_downstream_refs(_db, _task, refs, _token):
            self.assertEqual([], refs)

        self.manager._cleanup_downstream_refs = _fake_cleanup_downstream_refs
        asyncio.run(self.manager._prepare_retry_task(db, task))
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        summaries = {summary.stage_name: summary for summary in detail.stage_summaries}

        self.assertEqual("failed", detail.status)
        self.assertEqual("pending", summaries["system_analysis"].status)
        self.assertEqual("pending", summaries["entry_analysis"].status)
        self.assertEqual("pending", summaries["dataflow_vuln_scan"].status)
        self.assertIsNone(summaries["entry_analysis"].abnormal_reason)
        self.assertIsNone(summaries["dataflow_vuln_scan"].abnormal_reason)

    def test_source_workflow_e2e_entry_failure_finalizes_parent_failed(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            }
        )
        task.current_stage = "entry_analysis"
        system_run = BinarySecurityStageRun(
            id="sr-system-source-entry-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-source-entry-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-source-entry-failed",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-source-failed",
            error_message="entry extraction failed",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
                "error": "entry extraction failed",
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run],
            stage_items=[system_item, entry_item],
            archive_jobs=[],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("failed", task.status)
        self.assertEqual("failed", detail.status)
        self.assertEqual("failed", entry_run.status)
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertIn(system_summary.status, {"running", "success"})
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("failed", entry_summary.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("pending", dataflow_summary.status)
        self.assertTrue(any(event.event_type == "authoritative_failure_finalize_applied" for event in db.events))
        self.assertTrue(any(event.event_type == "task_finalized_after_child_failure" for event in db.events))

    def test_source_workflow_e2e_entry_failure_with_shell_dataflow_still_finalizes_parent_failed(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            }
        )
        task.current_stage = "entry_analysis"
        system_run = BinarySecurityStageRun(
            id="sr-system-source-entry-failed-shell",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-source-entry-failed-shell",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-source-entry-failed-shell",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-failed-shell-next",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-failed-shell-next",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-source-failed-shell-next",
            error_message="entry extraction failed",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-after-source-entry-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
                "error": "entry extraction failed",
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run],
            stage_items=[system_item, entry_item],
            archive_jobs=[],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("failed", task.status)
        self.assertEqual("failed", detail.status)
        self.assertEqual("failed", entry_run.status)
        self.assertEqual("pending", dataflow_run.status)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("failed", entry_summary.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("pending", dataflow_summary.status)
        event_types = [event.event_type for event in db.events]
        self.assertIn("authoritative_failure_finalize_applied", event_types)
        self.assertIn("task_finalized_after_child_failure", event_types)
        self.assertNotIn("task_finalize_deferred_for_incomplete_stage", event_types)

    def test_source_workflow_e2e_retry_stage_full_requeues_failed_entry_in_place(self):
        from datetime import timedelta

        now = _now()
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "failure_code": "entry_failed",
                "failure_message": "entry extraction failed",
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "entry extraction failed"
        system_run = BinarySecurityStageRun(
            id="sr-system-source-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-source-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        system_item = BinarySecurityStageItem(
            id="si-system-source-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-source-retry-entry",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-source-retry-entry",
            error_message="entry extraction failed",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
                "error": "entry extraction failed",
            },
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-stage-full-source-entry",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="entry_analysis",
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
            stage_runs=[system_run, entry_run, dataflow_run],
            stage_items=[system_item, entry_item],
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
                target_stage="entry_analysis",
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
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual("worker-a", db.runtime_leases[0].owner_instance_id)
        self.assertEqual("entry extraction failed", task.last_error)
        self.assertNotIn("failure_code", dict(task.summary or {}))
        self.assertNotIn("failure_message", dict(task.summary or {}))
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("requested")))
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("in_place_runtime_resume")))
        self.assertFalse(bool((operation.result_payload or {}).get("requeue", {}).get("owner_release_and_requeue")))
        self.assertEqual("running", detail.status)
        self.assertTrue((task.summary or {}).get("selected_modules"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertIn("operation_requeue_applied", event_types)

    def test_source_workflow_e2e_force_reset_to_pending_clears_control_state_and_requeues(self):
        from datetime import timedelta

        now = _now()
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "failure_code": "entry_failed",
                "failure_message": "entry extraction failed",
                "runtime_workset": {"pending_task_layer_reconcile": {"reason": "retry_after_failure"}},
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.current_operation_id = "op-force-reset-source"
        task.last_error = "entry extraction failed"
        task.latest_abnormal_reason = {
            "code": "owner_lost_retry_exhausted",
            "category": "downstream",
            "status": "failed",
            "title": "下游 owner 丢失自动恢复失败",
            "message": "entry extraction failed",
            "stage_name": "entry_analysis",
        }
        system_run = BinarySecurityStageRun(
            id="sr-system-source-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-source-force-reset",
            error_message="entry extraction failed",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
                "error": "entry extraction failed",
                "last_sync_error_message": "owner_lost_retry_exhausted",
                "last_sync_error_type": "StaleTaskExecution",
                "sync_observation": {
                    "sync_status": "transport_error",
                    "error_message": "owner_lost_retry_exhausted",
                    "error_type": "StaleTaskExecution",
                    "budget_exhausted": True,
                },
            },
        )
        operation = BinarySecurityTaskOperation(
            id="op-force-reset-source",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="force_reset_to_pending",
            target_stage="entry_analysis",
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
            stage_runs=[system_run, entry_run],
            stage_items=[entry_item],
            runtime_leases=[runtime_lease],
            events=[],
        )

        original_enqueue = self.manager._enqueue_task
        queued: list[str] = []
        self.manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([task.id], queued)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertIsNone(task.last_error)
        self.assertIsNone(task.latest_abnormal_reason)
        self.assertEqual({}, dict((task.summary or {}).get("runtime_workset") or {}))
        self.assertNotIn("failure_code", dict(task.summary or {}))
        self.assertNotIn("failure_message", dict(task.summary or {}))
        self.assertEqual("pending", detail.status)
        self.assertIsNone(detail.abnormal_reason)
        self.assertEqual(1, len(db.runtime_leases))
        self.assertEqual(task.id, db.runtime_leases[0].task_id)
        self.assertEqual("running", operation.status)
        self.assertEqual("operation_succeeded", operation.current_step)
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_status_changed", event_types)
        self.assertIn("task_force_reset_to_pending", event_types)
        self.assertIn("operation_step_started", event_types)
        self.assertIn("operation_step_succeeded", event_types)

    def test_source_workflow_e2e_retry_stage_full_blocked_without_local_owner(self):
        from datetime import timedelta

        now = _now()
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "failure_code": "entry_failed",
                "failure_message": "entry extraction failed",
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "entry extraction failed"
        system_run = BinarySecurityStageRun(
            id="sr-system-source-retry-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-retry-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-source-retry-entry-blocked",
            error_message="entry extraction failed",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
                "error": "entry extraction failed",
            },
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-stage-full-source-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="entry_analysis",
            status="running",
            current_step="requeue_task",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-b",
            heartbeat_at=now,
            lease_expires_at=now + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            operations=[operation],
            stage_runs=[system_run, entry_run],
            stage_items=[entry_item],
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
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.instance_id = original_instance_id
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([], queued)
        self.assertEqual("running", operation.status)
        self.assertEqual("failed", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("failed", detail.status)
        self.assertTrue(any(lease.task_id == task.id and lease.owner_instance_id == "worker-b" for lease in db.runtime_leases))
        event_types = [event.event_type for event in db.events]
        self.assertIn("main_state_write_blocked", event_types)
        self.assertIn("operation_requeue_applied", event_types)
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertNotIn("operation_failed", event_types)

    def test_source_workflow_e2e_retry_failed_items_recreates_abnormal_entry_child_inside_operation(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-retry-failed-items-source"
        task.summary = {
            **(task.summary or {}),
            "retry_plan": {
                "target_stage": "entry_analysis",
                "mode": "retry_failed_items",
                "retry_item_keys": ["mod-a::source_project"],
            },
        }
        system_run = BinarySecurityStageRun(
            id="sr-system-source-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old-source",
        )
        entry_item.input_ref = dict(module)
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [],
                "error": "previous child missing",
            },
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-source",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_failed_items",
            target_stage="entry_analysis",
            status="running",
            current_step="collect_cleanup_plan",
        )
        operation.resume_cursor = {"current_step": "collect_cleanup_plan"}
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run],
            stage_items=[entry_item],
            operations=[operation],
            events=[],
        )
        deleted_refs: list[dict[str, object]] = []
        created_payloads: list[dict[str, object]] = []

        async def _noop_sync(*_args, **_kwargs):
            return None

        async def _fake_delete_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            deleted_refs.extend(list(refs_arg))
            return len(list(refs_arg))

        async def _fake_create(db_arg, task_arg, item_arg, *, service, token, payload):
            del db_arg, task_arg, token
            created_payloads.append(
                {
                    "service": service,
                    "payload": dict(payload),
                    "item_id": item_arg.id,
                }
            )
            return {"task_id": "ea-new-source", "status": "pending"}

        original_sync = self.manager.sync_downstream_status
        original_delete = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        original_apply_decision = self.manager._apply_task_layer_decision
        try:
            self.manager.sync_downstream_status = _noop_sync
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            self.manager._apply_task_layer_decision = lambda _db, _task, decision, **_kwargs: decision
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.sync_downstream_status = original_sync
            self.manager._delete_downstream_refs = original_delete
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue
            self.manager._apply_task_layer_decision = original_apply_decision

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(["ea-old-source"], [row["task_id"] for row in deleted_refs])
        self.assertEqual(1, len(created_payloads))
        self.assertEqual("entry_analyse", created_payloads[0]["service"])
        self.assertEqual("ea-new-source", entry_item.downstream_task_id)
        self.assertEqual("pending", entry_item.status)
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        self.assertEqual("running", operation.status)
        self.assertEqual("failed", task.status)
        self.assertEqual("failed", detail.status)
        action_rows = list((operation.result_payload or {}).get("item_actions") or [])
        self.assertEqual(1, len(action_rows))
        self.assertEqual("succeeded", action_rows[0].get("verification_status"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("operation_step_started", event_types)
        self.assertIn("operation_step_succeeded", event_types)

    def test_source_workflow_e2e_retry_failed_items_without_bound_child_recreates_from_recorded_state_only(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-retry-failed-items-source-no-binding"
        task.summary = {
            **(task.summary or {}),
            "retry_plan": {
                "target_stage": "entry_analysis",
                "mode": "retry_failed_items",
                "retry_item_keys": ["mod-a::source_project"],
            },
        }
        system_run = BinarySecurityStageRun(
            id="sr-system-source-retry-no-binding",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-no-binding",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-retry-no-binding",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id=None,
        )
        entry_item.input_ref = dict(module)
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "downstream_status": "running",
                "sync_observation": {
                    "downstream_status": "running",
                    "mapped_status": "running",
                    "sync_status": "transport_error",
                    "error_type": "owner_lost_retry_exhausted",
                },
            },
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-source-no-binding",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_failed_items",
            target_stage="entry_analysis",
            status="running",
            current_step="collect_cleanup_plan",
        )
        operation.resume_cursor = {"current_step": "collect_cleanup_plan"}
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run],
            stage_items=[entry_item],
            operations=[operation],
            events=[],
        )
        created_payloads: list[dict[str, object]] = []
        deleted_refs: list[dict[str, object]] = []
        active_payload_calls: list[str] = []

        async def _noop_sync(*_args, **_kwargs):
            return None

        async def _fake_delete_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            deleted_refs.extend(list(refs_arg))
            return len(list(refs_arg))

        async def _fake_create(db_arg, task_arg, item_arg, *, service, token, payload):
            del db_arg, task_arg, token
            created_payloads.append({"service": service, "payload": dict(payload), "item_id": item_arg.id})
            return {"task_id": "ea-new-no-binding-source", "status": "pending"}

        async def _unexpected_active_payload(*_args, **_kwargs):
            active_payload_calls.append("called")
            raise AssertionError("retry_failed_items should not scan downstream when no child is bound")

        original_sync = self.manager.sync_downstream_status
        original_delete = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        original_apply_decision = self.manager._apply_task_layer_decision
        original_active_payload = self.manager._active_downstream_payload
        try:
            self.manager.sync_downstream_status = _noop_sync
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            self.manager._apply_task_layer_decision = lambda _db, _task, decision, **_kwargs: decision
            self.manager._active_downstream_payload = _unexpected_active_payload
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.sync_downstream_status = original_sync
            self.manager._delete_downstream_refs = original_delete
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue
            self.manager._apply_task_layer_decision = original_apply_decision
            self.manager._active_downstream_payload = original_active_payload

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        item_action = action_rows[entry_item.id]

        self.assertEqual([], active_payload_calls)
        self.assertEqual([], deleted_refs)
        self.assertEqual(1, len(created_payloads))
        self.assertEqual("entry_analyse", created_payloads[0]["service"])
        self.assertEqual("ea-new-no-binding-source", entry_item.downstream_task_id)
        self.assertEqual("pending", entry_item.status)
        self.assertEqual("recreate_from_abnormal", item_action["strategy"])
        self.assertIsNone(item_action.get("old_downstream_task_id"))
        self.assertEqual("ea-new-no-binding-source", item_action.get("new_downstream_task_id"))
        self.assertEqual("running", item_action.get("observed_status"))
        self.assertEqual("running", operation.status)
        self.assertEqual("failed", detail.status)
        page = self.manager.get_task_stage_items_page(
            db,
            project_id=task.project_id,
            task_id=task.id,
            stage_name="entry_analysis",
            page=1,
            per_page=10,
        )
        self.assertEqual(1, page.total)
        page_item = page.items[0]
        self.assertEqual("pending", page_item.status)
        self.assertIsNone(page_item.last_sync_error_at)
        self.assertIsNone(page_item.sync_observation_error_message)
        self.assertIsNone(page_item.sync_observation_error_type)

    def test_source_workflow_e2e_retry_failed_items_entry_recreate_cleans_targeted_descendants_only(self):
        module_a = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        module_b = {
            "module_key": "mod-b",
            "module_name": "mod-b",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-b",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-b",
            "files_list": "/tmp/source-project/mod-b/files.list",
            "files_list_path": "/tmp/source-project/mod-b/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module_a, module_b]})
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-retry-failed-items-source-entry-desc"
        task.summary = {
            **(task.summary or {}),
            "entry_results": [
                {
                    "module_key": "mod-a",
                    "module_name": "mod-a",
                    "entries": [{"entry_key": "mod-a:entry-1", "module_key": "mod-a", "function_name": "fn_a"}],
                },
                {
                    "module_key": "mod-b",
                    "module_name": "mod-b",
                    "entries": [{"entry_key": "mod-b:entry-1", "module_key": "mod-b", "function_name": "fn_b"}],
                },
            ],
            "retry_plan": {
                "target_stage": "entry_analysis",
                "mode": "retry_failed_items",
                "retry_item_keys": ["mod-a::source_project"],
            },
        }
        system_run = BinarySecurityStageRun(
            id="sr-system-source-retry-entry-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-entry-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-retry-entry-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
        )
        vuln_run = BinarySecurityStageRun(
            id="sr-vuln-source-retry-entry-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="vuln_verify",
            sequence_no=4,
            status="running",
        )
        entry_target = BinarySecurityStageItem(
            id="si-entry-source-retry-entry-desc-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old-a",
        )
        entry_target.input_ref = dict(module_a)
        self._persist_stage_item_result(
            task,
            entry_target,
            payload={"module_key": "mod-a", "module_name": "mod-a", "entries": [], "error": "previous child missing"},
        )
        entry_keep = BinarySecurityStageItem(
            id="si-entry-source-retry-entry-desc-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-b",
            item_name="mod-b",
            parent_key="source_project",
            item_identity_key="mod-b::source_project",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-keep-b",
        )
        entry_keep.input_ref = dict(module_b)
        dataflow_target = BinarySecurityStageItem(
            id="si-dataflow-source-retry-entry-desc-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-1::mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-old-a",
        )
        dataflow_target.input_ref = {
            "entry_key": "mod-a:entry-1",
            "module_key": "mod-a",
            "module_name": "mod-a",
            "function_name": "fn_a",
            "upstream_item_id": entry_target.id,
        }
        dataflow_keep = BinarySecurityStageItem(
            id="si-dataflow-source-retry-entry-desc-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-b:entry-1",
            item_name="fn_b",
            parent_key="mod-b",
            item_identity_key="mod-b:entry-1::mod-b",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-keep-b",
        )
        dataflow_keep.input_ref = {
            "entry_key": "mod-b:entry-1",
            "module_key": "mod-b",
            "module_name": "mod-b",
            "function_name": "fn_b",
            "upstream_item_id": entry_keep.id,
        }
        vuln_target = BinarySecurityStageItem(
            id="si-vuln-source-retry-entry-desc-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=vuln_run.id,
            stage_name="vuln_verify",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-1::mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfvs-old-a",
        )
        vuln_target.input_ref = {
            "entry_key": "mod-a:entry-1",
            "function_name": "fn_a",
            "module_key": "mod-a",
            "upstream_item_id": dataflow_target.id,
        }
        vuln_keep = BinarySecurityStageItem(
            id="si-vuln-source-retry-entry-desc-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=vuln_run.id,
            stage_name="vuln_verify",
            item_key="mod-b:entry-1",
            item_name="fn_b",
            parent_key="mod-b",
            item_identity_key="mod-b:entry-1::mod-b",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfvs-keep-b",
        )
        vuln_keep.input_ref = {
            "entry_key": "mod-b:entry-1",
            "function_name": "fn_b",
            "module_key": "mod-b",
            "upstream_item_id": dataflow_keep.id,
        }
        archive_jobs = [
            BinarySecurityArchiveJob(
                id="aj-vuln-source-retry-entry-desc-a",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="vuln_verify",
                item_id=vuln_target.id,
                archive_status="success",
            ),
            BinarySecurityArchiveJob(
                id="aj-vuln-source-retry-entry-desc-b",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="vuln_verify",
                item_id=vuln_keep.id,
                archive_status="success",
            ),
        ]
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-source-entry-desc",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_failed_items",
            target_stage="entry_analysis",
            status="running",
            current_step="collect_cleanup_plan",
        )
        operation.resume_cursor = {"current_step": "collect_cleanup_plan"}
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run, vuln_run],
            stage_items=[entry_target, entry_keep, dataflow_target, dataflow_keep, vuln_target, vuln_keep],
            archive_jobs=archive_jobs,
            operations=[operation],
            events=[],
        )
        deleted_refs: list[dict[str, object]] = []
        created_payloads: list[dict[str, object]] = []

        async def _noop_sync(*_args, **_kwargs):
            return None

        async def _fake_delete_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            deleted_refs.extend(list(refs_arg))
            return len(list(refs_arg))

        async def _fake_create(db_arg, task_arg, item_arg, *, service, token, payload):
            del db_arg, task_arg, token
            created_payloads.append({"service": service, "payload": dict(payload), "item_id": item_arg.id})
            return {"task_id": "ea-new-a", "status": "pending"}

        original_sync = self.manager.sync_downstream_status
        original_delete = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        original_apply_decision = self.manager._apply_task_layer_decision
        try:
            self.manager.sync_downstream_status = _noop_sync
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            self.manager._apply_task_layer_decision = lambda _db, _task, decision, **_kwargs: decision
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.sync_downstream_status = original_sync
            self.manager._delete_downstream_refs = original_delete
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue
            self.manager._apply_task_layer_decision = original_apply_decision

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual({"ea-old-a"}, {row["task_id"] for row in deleted_refs})
        self.assertEqual(["entry_analyse"], [row["service"] for row in created_payloads])
        self.assertEqual("ea-new-a", entry_target.downstream_task_id)
        self.assertEqual("pending", entry_target.status)
        self.assertEqual("ea-keep-b", entry_keep.downstream_task_id)
        self.assertEqual("success", entry_keep.status)
        self.assertEqual(
            {entry_target.id, entry_keep.id, vuln_target.id, vuln_keep.id},
            {item.id for item in db.stage_items},
        )
        self.assertEqual(
            ["aj-vuln-source-retry-entry-desc-a", "aj-vuln-source-retry-entry-desc-b"],
            [job.id for job in db.archive_jobs],
        )
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        self.assertEqual("running", operation.status)
        self.assertEqual("failed", detail.status)
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        self.assertEqual("recreate_from_abnormal", action_rows[entry_target.id]["strategy"])
        self.assertEqual("ea-old-a", action_rows[entry_target.id]["old_downstream_task_id"])
        self.assertEqual("ea-new-a", action_rows[entry_target.id]["new_downstream_task_id"])
        self.assertEqual("succeeded", action_rows[entry_target.id]["cleanup_status"])
        self.assertEqual("succeeded", action_rows[entry_target.id]["create_status"])
        self.assertEqual("succeeded", action_rows[entry_target.id]["verification_status"])
        self.assertNotIn(entry_keep.id, action_rows)

    def test_source_workflow_e2e_retry_failed_items_recreates_abnormal_dataflow_child_inside_operation(self):
        entry_a = {
            "entry_key": "mod-a:entry-1",
            "module_key": "mod-a",
            "module_name": "mod-a",
            "function_name": "fn_a",
            "definition_file": "a.c",
            "definition_line": "10",
            "definition_kind": "definition",
            "module_input_path": "/tmp/source-project/mod-a",
            "source_root_path": "/tmp/source-project",
            "source_dir": "/tmp/source-project/mod-a",
        }
        entry_b = {
            "entry_key": "mod-b:entry-1",
            "module_key": "mod-b",
            "module_name": "mod-b",
            "function_name": "fn_b",
            "definition_file": "b.c",
            "definition_line": "20",
            "definition_kind": "definition",
            "module_input_path": "/tmp/source-project/mod-b",
            "source_root_path": "/tmp/source-project",
            "source_dir": "/tmp/source-project/mod-b",
        }
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    },
                    {
                        "module_key": "mod-b",
                        "module_name": "mod-b",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-b",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-b",
                        "files_list": "/tmp/source-project/mod-b/files.list",
                        "files_list_path": "/tmp/source-project/mod-b/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    },
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [dict(entry_a)],
                    },
                    {
                        "module_key": "mod-b",
                        "module_name": "mod-b",
                        "entries": [dict(entry_b)],
                    },
                ],
                "vuln_results": [{"entry_key": "mod-a:entry-1"}, {"entry_key": "mod-b:entry-1"}],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-retry-failed-items-source-dataflow"
        task.summary = {
            **(task.summary or {}),
            "retry_plan": {
                "target_stage": "dataflow_vuln_scan",
                "mode": "retry_failed_items",
                "retry_item_keys": ["mod-a:entry-1::mod-a"],
            },
        }
        system_run = BinarySecurityStageRun(
            id="sr-system-source-retry-dataflow-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-retry-dataflow-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="failed",
        )
        vuln_run = BinarySecurityStageRun(
            id="sr-vuln-source-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="vuln_verify",
            sequence_no=4,
            status="success",
        )
        df_abnormal = BinarySecurityStageItem(
            id="si-df-source-retry-failed-items-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-1::mod-a",
            status="cancelled",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-old-a",
        )
        df_abnormal.input_ref = dict(entry_a)
        df_success = BinarySecurityStageItem(
            id="si-df-source-retry-failed-items-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-b:entry-1",
            item_name="fn_b",
            parent_key="mod-b",
            item_identity_key="mod-b:entry-1::mod-b",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-success-b",
        )
        df_success.input_ref = dict(entry_b)
        vuln_for_abnormal = BinarySecurityStageItem(
            id="si-vuln-source-retry-failed-items-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=vuln_run.id,
            stage_name="vuln_verify",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-1::mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfvs-old-a",
        )
        vuln_for_abnormal.input_ref = {
            "entry_key": "mod-a:entry-1",
            "function_name": "fn_a",
            "module_key": "mod-a",
            "upstream_item_id": "si-df-source-retry-failed-items-a",
        }
        vuln_for_success = BinarySecurityStageItem(
            id="si-vuln-source-retry-failed-items-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=vuln_run.id,
            stage_name="vuln_verify",
            item_key="mod-b:entry-1",
            item_name="fn_b",
            parent_key="mod-b",
            item_identity_key="mod-b:entry-1::mod-b",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfvs-keep-b",
        )
        vuln_for_success.input_ref = {
            "entry_key": "mod-b:entry-1",
            "function_name": "fn_b",
            "module_key": "mod-b",
            "upstream_item_id": "si-df-source-retry-failed-items-b",
        }
        archive_jobs = [
            BinarySecurityArchiveJob(
                id="aj-vuln-source-retry-failed-items-a",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="vuln_verify",
                item_id="si-vuln-source-retry-failed-items-a",
                archive_status="success",
            ),
            BinarySecurityArchiveJob(
                id="aj-vuln-source-retry-failed-items-b",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="vuln_verify",
                item_id="si-vuln-source-retry-failed-items-b",
                archive_status="success",
            ),
        ]
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-source-dataflow",
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
            stage_runs=[system_run, entry_run, dataflow_run, vuln_run],
            stage_items=[df_abnormal, df_success, vuln_for_abnormal, vuln_for_success],
            archive_jobs=archive_jobs,
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
            return {"task_id": "dfa-new-a", "status": "pending"}

        original_sync = self.manager.sync_downstream_status
        original_active_payload = self.manager._active_downstream_payload
        original_cleanup_refs = self.manager._cleanup_downstream_refs
        original_delete_refs = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        original_delete_items = self.manager._delete_stage_items_by_ids
        original_clear_archive = self.manager._clear_archive_jobs_for_stage_items
        try:
            self.manager.sync_downstream_status = _noop_sync
            self.manager._active_downstream_payload = _noop_active_payload
            self.manager._cleanup_downstream_refs = _fake_cleanup_refs
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            self.manager._delete_stage_items_by_ids = lambda db_arg, item_ids: (
                setattr(db_arg, "stage_items", [item for item in db_arg.stage_items if item.id not in set(item_ids)]) or len(item_ids)
            )
            self.manager._clear_archive_jobs_for_stage_items = lambda db_arg, task_id, stage_name, item_ids: (
                setattr(db_arg, "archive_jobs", [job for job in db_arg.archive_jobs if job.item_id not in set(item_ids)]) or len(item_ids)
            )
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.sync_downstream_status = original_sync
            self.manager._active_downstream_payload = original_active_payload
            self.manager._cleanup_downstream_refs = original_cleanup_refs
            self.manager._delete_downstream_refs = original_delete_refs
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue
            self.manager._delete_stage_items_by_ids = original_delete_items
            self.manager._clear_archive_jobs_for_stage_items = original_clear_archive

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual({"dfa-old-a"}, {ref["task_id"] for ref in cleanup_refs})
        self.assertEqual({"dataflow_vuln_scan"}, {ref["service"] for ref in cleanup_refs})
        self.assertEqual(["dataflow_vuln_scan"], [row["service"] for row in create_calls])
        self.assertEqual("dfa-new-a", df_abnormal.downstream_task_id)
        self.assertEqual("success", df_success.status)
        self.assertEqual("dfa-success-b", df_success.downstream_task_id)
        self.assertEqual(
            {
                "si-df-source-retry-failed-items-a",
                "si-df-source-retry-failed-items-b",
                "si-vuln-source-retry-failed-items-a",
                "si-vuln-source-retry-failed-items-b",
            },
            {item.id for item in db.stage_items},
        )
        self.assertEqual(
            ["aj-vuln-source-retry-failed-items-a", "aj-vuln-source-retry-failed-items-b"],
            [job.id for job in db.archive_jobs],
        )
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        self.assertEqual("failed", operation.status)
        self.assertEqual("failed", detail.status)
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        self.assertEqual("recreate_from_abnormal", action_rows["si-df-source-retry-failed-items-a"]["strategy"])
        self.assertEqual("dfa-old-a", action_rows["si-df-source-retry-failed-items-a"]["old_downstream_task_id"])
        self.assertEqual("dfa-new-a", action_rows["si-df-source-retry-failed-items-a"]["new_downstream_task_id"])
        self.assertEqual("succeeded", action_rows["si-df-source-retry-failed-items-a"]["cleanup_status"])
        self.assertEqual("succeeded", action_rows["si-df-source-retry-failed-items-a"]["create_status"])
        self.assertEqual("succeeded", action_rows["si-df-source-retry-failed-items-a"]["verification_status"])
        self.assertNotIn("si-df-source-retry-failed-items-b", action_rows)

    def test_source_workflow_e2e_retry_failed_items_archive_only_failure_upgrades_to_archive_retry(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [{"entry_key": "mod-a:entry-1", "function_name": "fn_a", "module_key": "mod-a"}],
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.finished_at = _now()
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            last_error="总任务产物归档失败",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-source-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            item_identity_key="mod-a::source_project",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="eat-success-a",
            error_message="总任务产物归档失败",
        )
        entry_item.result = {
            "last_sync_result": "downstream_archive_failed_manual_intervention",
            "sync_observation": {
                "last_result": "downstream_archive_failed_manual_intervention",
            },
        }
        archive_job = BinarySecurityArchiveJob(
            id="aj-entry-source-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            item_id=entry_item.id,
            item_key=entry_item.item_key,
            archive_status="failed",
            error_message="copy failed",
        )
        archive_job.payload = {
            "mapped_status": "success",
            "downstream_payload": {"task_id": "eat-success-a", "status": "success"},
        }
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
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
        self.assertEqual("entry_analysis", operation.target_stage)
        self.assertEqual(operation.id, task.current_operation_id)
        self.assertEqual("task_retry_failed_items_archive_full_accepted", getattr(db.added[-1], "event_type", ""))

    def test_source_workflow_e2e_rebuilds_missing_entry_authoritative_items_before_execution(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(
            summary={"input_dir": "/tmp/source-project", "selected_modules": [module]},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-missing-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[dict(module)]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, current: dict(current)):
            rebuilt = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)

        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertTrue(rebuilt["rebuilt"])
        self.assertEqual(1, rebuilt["rebuilt_item_count"])
        self.assertEqual(1, len(entry_items))
        self.assertEqual("pending", entry_items[0].status)
        self.assertIsNone(entry_items[0].downstream_task_id)
        self.assertTrue(any(event.event_type == "entry_analysis_authoritative_items_rebuild_started" for event in db.events))
        self.assertTrue(any(event.event_type == "entry_analysis_authoritative_items_rebuild_finished" for event in db.events))

    def test_source_workflow_e2e_rebuild_then_continue_into_dataflow(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-rebuild-continue",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[dict(module)]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, current: dict(current)):
            rebuilt = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)

        self.assertTrue(rebuilt["rebuilt"])
        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertEqual(1, len(entry_items))

        entry_item = entry_items[0]
        entry_item.status = "success"
        entry_item.downstream_task_id = "ea-source-rebuilt-1"
        entry_item.downstream_service = "entry_analyse"
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-a",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "mod_a_entry_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-source-rebuilt-1",
        )
        db.archive_jobs.append(entry_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, entry_archive)

        self.assertTrue(signals)
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        self.assertTrue((task.summary or {}).get("entry_results"))

        before_stage = task.current_stage
        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._trigger_dataflow_items_from_entry_result(
                db,
                task,
                self.manager._entry_module_result_from_stage_item(task, entry_item),
                upstream_item=entry_item,
            )

        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([], dataflow_items)
        self.assertEqual("running", detail.status)
        self.assertEqual(before_stage, task.current_stage)
        self.assertTrue(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"running", "success"})
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued", "running"})

    def test_source_workflow_e2e_dataflow_blocked_until_entry_materialized(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
        task.current_stage = "dataflow_vuln_scan"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-shell",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run, dataflow_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[dict(module)]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, current: dict(current)):
            status, summary = asyncio.run(
                self.manager._stage_dataflow_vuln_scan(
                    db,
                    task,
                    dataflow_run,
                    token=None,
                    retry_existing=False,
                )
            )

        self.assertEqual("pending", status)
        self.assertEqual("blocked_until_entry_analysis_materialized", summary.get("status"))
        self.assertEqual("historical_children_exist_but_authoritative_items_missing", summary.get("reason"))
        self.assertTrue(
            any(
                event.event_type == "dataflow_activation_blocked_until_entry_analysis_materialized"
                for event in db.events
            )
        )

    def test_source_workflow_e2e_active_control_operation_blocks_entry_rebuild_and_auto_advance(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-cancel-source"
        operation = BinarySecurityTaskOperation(
            id="op-cancel-source",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="cancel",
            status="queued",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-active-op",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            operations=[operation],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[dict(module)]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, current: dict(current)):
            rebuild = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)
            auto_advance = self.manager._should_auto_advance_to_stage(db, task, "entry_analysis")

        self.assertFalse(rebuild["rebuilt"])
        self.assertEqual("active_operation_in_progress", rebuild["reason"])
        self.assertFalse(auto_advance)
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertTrue(any(event.event_type == "entry_analysis_authoritative_items_rebuild_skipped" for event in db.events))

    def test_source_workflow_e2e_active_control_operation_blocks_dataflow_activation_until_entry_materialized(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-force-reset-source"
        operation = BinarySecurityTaskOperation(
            id="op-force-reset-source",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="force_reset_to_pending",
            status="running",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-active-op-shell",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-active-op-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run, dataflow_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            operations=[operation],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[dict(module)]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, current: dict(current)):
            status, summary = asyncio.run(
                self.manager._stage_dataflow_vuln_scan(
                    db,
                    task,
                    dataflow_run,
                    token=None,
                    retry_existing=False,
                )
            )

        self.assertEqual("pending", status)
        self.assertEqual("blocked_until_entry_analysis_materialized", summary.get("status"))
        self.assertEqual("active_operation_in_progress", summary.get("reason"))
        self.assertTrue(
            any(
                event.event_type == "dataflow_activation_blocked_until_entry_analysis_materialized"
                for event in db.events
            )
        )

    def test_source_workflow_e2e_dataflow_partial_success_keeps_parent_active(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-a",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "mod_a_entry_a",
                            },
                            {
                                "entry_key": "mod-a:entry-b",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "mod_a_entry_b",
                            },
                        ],
                    }
                ],
                "dataflow_results": [
                    {"entry_key": "mod-a:entry-a", "module_key": "mod-a", "vulns": [{"id": "v-a"}]},
                    {"entry_key": "mod-a:entry-b", "module_key": "mod-a", "vulns": []},
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        system_run = BinarySecurityStageRun(
            id="sr-system-source-ps",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-ps",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-ps",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="partial_success",
            finished_at=_now(),
            output_summary={"success_count": 1, "failed_count": 1},
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-source-success",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-a",
            item_name="mod_a_entry_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-a",
        )
        failed_item = BinarySecurityStageItem(
            id="si-dataflow-source-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-b",
            item_name="mod_a_entry_b",
            parent_key="mod-a",
            status="failed",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-b",
            error_message="analysis failed",
        )
        self._persist_stage_item_result(
            task,
            success_item,
            payload={"entry_key": "mod-a:entry-a", "module_key": "mod-a", "vulns": [{"id": "v-a"}]},
        )
        self._persist_stage_item_result(
            task,
            failed_item,
            payload={"entry_key": "mod-a:entry-b", "module_key": "mod-a", "error": "analysis failed"},
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run],
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
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("success", entry_summary.status)
        self.assertEqual(
            "partial_success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )

    def test_source_workflow_e2e_dataflow_partial_success_with_downstream_missing_keeps_parent_active(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-a",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "mod_a_entry_a",
                            },
                            {
                                "entry_key": "mod-a:entry-b",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "mod_a_entry_b",
                            },
                        ],
                    }
                ],
                "dataflow_results": [
                    {"entry_key": "mod-a:entry-a", "module_key": "mod-a", "vulns": [{"id": "v-a"}]},
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        system_run = BinarySecurityStageRun(
            id="sr-system-source-ps-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-ps-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-ps-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="partial_success",
            finished_at=_now(),
            output_summary={"success_count": 1, "downstream_missing_count": 1},
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-source-success-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-a",
            item_name="mod_a_entry_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-a",
        )
        missing_item = BinarySecurityStageItem(
            id="si-dataflow-source-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-b",
            item_name="mod_a_entry_b",
            parent_key="mod-a",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-missing",
            error_message="downstream task not found",
        )
        self._persist_stage_item_result(
            task,
            success_item,
            payload={"entry_key": "mod-a:entry-a", "module_key": "mod-a", "vulns": [{"id": "v-a"}]},
        )
        self._persist_stage_item_result(
            task,
            missing_item,
            payload={"entry_key": "mod-a:entry-b", "module_key": "mod-a", "downstream_status": "downstream_missing"},
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run],
            stage_items=[success_item, missing_item],
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
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("success", entry_summary.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("partial_success", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)

    def test_source_workflow_e2e_dataflow_partial_success_archive_terminalizes_parent_success(self):
        task = _source_task(
            summary={
                "input_dir": "/tmp/source-project",
                "selected_modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-a",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "mod_a_entry_a",
                            },
                            {
                                "entry_key": "mod-a:entry-b",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "mod_a_entry_b",
                            },
                        ],
                    }
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        system_run = BinarySecurityStageRun(
            id="sr-system-source-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-source-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-source-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-source-ps-archive-success",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-a",
            item_name="mod_a_entry_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-ps-archive-a",
        )
        partial_item = BinarySecurityStageItem(
            id="si-dataflow-source-ps-archive-partial",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-b",
            item_name="mod_a_entry_b",
            parent_key="mod-a",
            status="partial_success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-ps-archive-b",
        )
        self._persist_stage_item_result(
            task,
            success_item,
            payload={"entry_key": "mod-a:entry-a", "module_key": "mod-a", "vulns": [{"id": "v-a"}]},
        )
        self._persist_stage_item_result(
            task,
            partial_item,
            payload={"entry_key": "mod-a:entry-b", "module_key": "mod-a", "vulns": [], "status": "partial_success"},
        )
        success_archive = self._make_archive_job(
            task=task,
            item=success_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-ps-archive-a",
            mapped_status="success",
        )
        partial_archive = self._make_archive_job(
            task=task,
            item=partial_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-source-ps-archive-b",
            mapped_status="partial_success",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run],
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
        self._refresh_stage_summary(db, task, "system_analysis")
        self._refresh_stage_summary(db, task, "entry_analysis")
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

    def test_source_workflow_e2e_replaced_dataflow_child_ignores_stale_late_payload(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-replaced",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-replaced",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-1",
            item_name="fn_a",
            parent_key="mod-a",
            status="queued",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-new",
            result={
                "sync_observation": {
                    "replacement_in_progress": True,
                    "binding_cleared": False,
                    "verification_status": "pending",
                    "old_downstream_task_id": "dfa-old",
                    "transition_type": "destructive_rebuild",
                }
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
        )

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, _item, _token):
            return {"task_id": "dfa-old", "status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                resp = asyncio.run(
                    self.manager.sync_downstream_status(
                        db,
                        project_id=task.project_id,
                        task_id=task.id,
                        stage_name="dataflow_vuln_scan",
                        apply_state=True,
                    )
                )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(0, resp.synced_downstream_count)
        self.assertEqual("dfa-new", dataflow_item.downstream_task_id)
        self.assertEqual("queued", dataflow_item.status)
        self.assertEqual("running", detail.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("running", dataflow_summary.status)
        self.assertIn("stale_downstream_payload_ignored", [event.event_type for event in db.events])

    def test_source_workflow_e2e_replaced_entry_child_ignores_stale_late_payload(self):
        module = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "risk_level": "高",
            "source_dir": "/tmp/source-project/mod-a",
            "source_root": "/tmp/source-project",
            "source_root_path": "/tmp/source-project",
            "module_dir": "/tmp/source-project/mod-a",
            "files_list": "/tmp/source-project/mod-a/files.list",
            "files_list_path": "/tmp/source-project/mod-a/files.list",
            "task_type": TASK_TYPE_SOURCE,
            "firmware_key": "source_project",
            "firmware_name": "source_project",
        }
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-replaced-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-replaced-source",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="source_project",
            status="queued",
            downstream_service="entry_analyse",
            downstream_task_id="ea-new",
            result={
                "sync_observation": {
                    "replacement_in_progress": True,
                    "binding_cleared": False,
                    "verification_status": "pending",
                    "old_downstream_task_id": "ea-old",
                    "transition_type": "destructive_rebuild",
                }
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, _item, _token):
            return {"task_id": "ea-old", "status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                resp = asyncio.run(
                    self.manager.sync_downstream_status(
                        db,
                        project_id=task.project_id,
                        task_id=task.id,
                        stage_name="entry_analysis",
                        apply_state=True,
                    )
                )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(0, resp.synced_downstream_count)
        self.assertEqual("ea-new", entry_item.downstream_task_id)
        self.assertEqual("queued", entry_item.status)
        self.assertEqual("running", detail.status)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("running", entry_summary.status)
        self.assertEqual("running", task.status)
        self.assertIn("downstream_parent_mismatch", [event.event_type for event in db.events])
        self.assertNotIn("stale_downstream_payload_applied", [event.event_type for event in db.events])

    def test_source_workflow_e2e_system_archive_does_not_trigger_repair_for_unmaterialized_descendants(self):
        task = _source_task(
            summary={"input_dir": "/tmp/source-project"},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "system_analysis"
        system_run = BinarySecurityStageRun(
            id="sr-system-unmaterialized-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-unmaterialized-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            parent_key=None,
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-unmaterialized-desc",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-shell-after-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-after-system",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-unmaterialized-desc",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run, dataflow_run],
            stage_items=[system_item],
            archive_jobs=[system_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, system_archive)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(signals)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertEqual(0, len(self.manager._stage_items(db, task.id, "entry_analysis")))
        self.assertEqual("pending", entry_run.status)
        self.assertEqual("pending", dataflow_run.status)
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertIn(system_summary.status, {"running", "success"})
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"pending", "queued"})
        event_types = [event.event_type for event in db.events]
        self.assertNotIn("archive_apply_triggered_input_repair", event_types)
        self.assertNotIn("task_requeued_after_archive_input_repair", event_types)
        self.assertIn("task_layer_reconcile_completed", event_types)

    def test_source_workflow_e2e_owner_restart_recovery_preserves_authoritative_state(self):
        task = _source_task(summary={"input_dir": "/tmp/source-project"})
        system_run = BinarySecurityStageRun(
            id="sr-system-recover",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
            started_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-recover",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
        )
        task.current_stage = "entry_analysis"
        task.status = "running"
        system_item = BinarySecurityStageItem(
            id="si-system-recover",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source_project",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-recover",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-recover",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-recover",
        )
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ]
            },
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "source_dir": "/tmp/source-project/mod-a",
                        "source_root": "/tmp/source-project",
                        "source_root_path": "/tmp/source-project",
                        "module_dir": "/tmp/source-project/mod-a",
                        "files_list": "/tmp/source-project/mod-a/files.list",
                        "files_list_path": "/tmp/source-project/mod-a/files.list",
                        "task_type": TASK_TYPE_SOURCE,
                        "firmware_key": "source_project",
                        "firmware_name": "source_project",
                    }
                ],
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, entry_run],
            stage_items=[system_item, entry_item],
            archive_jobs=[],
            events=[],
        )

        recovering_manager = TaskManager()
        recovering_manager.instance_id = "worker-b"
        runtime_lease = __import__("app.model", fromlist=["BinarySecurityTaskRuntimeLease"]).BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-b",
            heartbeat_at=_now(),
            lease_expires_at=_now(),
        )
        db.runtime_leases.append(runtime_lease)

        original_factory = __import__("app.service.task_manager", fromlist=["get_session_factory"])
        import app.service.task_manager as task_manager_module

        original_get_factory = task_manager_module.get_session_factory
        original_write = recovering_manager._write_task_metadata_async

        async def _noop_write(*_args, **_kwargs):
            return None

        task_manager_module.get_session_factory = lambda: (lambda: db)
        recovering_manager._write_task_metadata_async = _noop_write
        try:
            asyncio.run(recovering_manager._sync_streaming_task_tail_state(task.id))
        finally:
            task_manager_module.get_session_factory = original_get_factory
            recovering_manager._write_task_metadata_async = original_write

        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-b", db.runtime_leases[0].owner_instance_id)
        detail = recovering_manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", detail.status)
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertEqual("running", system_summary.status)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("running", entry_summary.status)


class BinaryModuleWorkflowE2ETests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.manager.instance_id = "worker-a"
        self.manager._enqueue_task = lambda *_args, **_kwargs: None

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

    def _persist_stage_item_result(self, task: BinarySecurityTask, item: BinarySecurityStageItem, *, payload: dict):
        del task
        item.result = dict(payload)

    def _refresh_stage_summary(self, db: _ModelAwareDb, task: BinarySecurityTask, stage_name: str) -> None:
        handler = self.manager._stage_handler(stage_name)
        if handler is not None:
            handler.refresh_summary_from_items(self.manager, db, task)

    def _apply_archive_and_reconcile(self, db: _ModelAwareDb, task: BinarySecurityTask, archive_job: BinarySecurityArchiveJob):
        signal_snapshots: list[dict[str, object]] = []
        original_write = self.manager._write_task_metadata_async
        original_refresh = self.manager._refresh_terminal_item_result_from_downstream

        async def _noop_write(*_args, **_kwargs):
            return None

        async def _noop_refresh(*_args, **_kwargs):
            return None

        self.manager._write_task_metadata_async = _noop_write
        self.manager._refresh_terminal_item_result_from_downstream = _noop_refresh
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

    def _binary_module_descriptor(self, *, module_key: str = "IPSEC") -> dict[str, object]:
        return {
            "module_key": module_key,
            "module_name": module_key,
            "firmware_key": module_key,
            "firmware_name": module_key,
            "task_type": TASK_TYPE_BINARY_MODULE,
            "archive_root": f"/mock/archive/{module_key}",
            "entry_descriptor_root": f"/mock/archive/{module_key}",
            "entry_files_list": f"/mock/archive/{module_key}/modules/{module_key}/files.list",
            "entry_descriptor_ready": True,
            "entry_module_name": module_key,
            "entry_source_file_count": 2,
            "source_dir": f"/mock/archive/{module_key}",
            "source_root": f"/mock/archive/{module_key}",
            "source_root_path": f"/mock/archive/{module_key}",
            "module_dir": f"/mock/archive/{module_key}/modules/{module_key}",
            "files_list": f"/mock/archive/{module_key}/modules/{module_key}/files.list",
            "files_list_path": f"/mock/archive/{module_key}/modules/{module_key}/files.list",
        }

    def _entry_result_payload(self, *, module_key: str = "IPSEC") -> dict[str, object]:
        entry_key = f"{module_key}:entry"
        return {
            "module_key": module_key,
            "module_name": module_key,
            "source_dir": f"/mock/archive/{module_key}",
            "source_root": f"/mock/archive/{module_key}",
            "source_root_path": f"/mock/archive/{module_key}",
            "module_dir": f"/mock/archive/{module_key}/modules/{module_key}",
            "files_list": f"/mock/archive/{module_key}/modules/{module_key}/files.list",
            "files_list_path": f"/mock/archive/{module_key}/modules/{module_key}/files.list",
            "task_type": TASK_TYPE_BINARY_MODULE,
            "firmware_key": module_key,
            "firmware_name": module_key,
            "entries": [
                {
                    "entry_key": entry_key,
                    "module_key": module_key,
                    "module_name": module_key,
                    "function_name": f"{module_key.lower()}_entry",
                    "definition_file": f"{module_key.lower()}.c",
                    "definition_line": "12",
                    "source_dir": f"/mock/archive/{module_key}",
                    "source_root": f"/mock/archive/{module_key}",
                    "source_root_path": f"/mock/archive/{module_key}",
                    "module_dir": f"/mock/archive/{module_key}/modules/{module_key}",
                    "files_list": f"/mock/archive/{module_key}/modules/{module_key}/files.list",
                    "files_list_path": f"/mock/archive/{module_key}/modules/{module_key}/files.list",
                    "task_type": TASK_TYPE_BINARY_MODULE,
                    "firmware_key": module_key,
                    "firmware_name": module_key,
                }
            ],
        }

    def test_binary_module_workflow_e2e_owner_restart_recovery_preserves_authoritative_state(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-recover-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            started_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-recover-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
        )
        task.current_stage = "entry_analysis"
        task.status = "running"
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-recover-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-recover",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-recover-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-recover",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        self._persist_stage_item_result(task, entry_item, payload=self._entry_result_payload())
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[b2s_item, entry_item],
            archive_jobs=[],
            events=[],
        )

        recovering_manager = TaskManager()
        recovering_manager.instance_id = "worker-b"
        runtime_lease = __import__("app.model", fromlist=["BinarySecurityTaskRuntimeLease"]).BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-b",
            heartbeat_at=_now(),
            lease_expires_at=_now(),
        )
        db.runtime_leases.append(runtime_lease)

        original_factory = __import__("app.service.task_manager", fromlist=["get_session_factory"])
        import app.service.task_manager as task_manager_module

        original_get_factory = task_manager_module.get_session_factory
        original_write = recovering_manager._write_task_metadata_async

        async def _noop_write(*_args, **_kwargs):
            return None

        task_manager_module.get_session_factory = lambda: (lambda: db)
        recovering_manager._write_task_metadata_async = _noop_write
        try:
            asyncio.run(recovering_manager._sync_streaming_task_tail_state(task.id))
        finally:
            task_manager_module.get_session_factory = original_get_factory
            recovering_manager._write_task_metadata_async = original_write

        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual("worker-b", db.runtime_leases[0].owner_instance_id)
        detail = recovering_manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", detail.status)
        b2s_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "binary_to_source")
        self.assertEqual("running", b2s_summary.status)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("running", entry_summary.status)
        self.assertTrue((task.summary or {}).get("b2s_results"))

    def test_binary_module_workflow_e2e_happy_path(self):
        task = _binary_module_task(policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}))
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-1",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        b2s_archive = self._make_archive_job(
            task=task,
            item=b2s_item,
            downstream_service="binary_to_source",
            downstream_task_id="b2s-1",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run],
            stage_items=[b2s_item],
            archive_jobs=[b2s_archive],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, module: dict(module)):
            b2s_signals = self._apply_archive_and_reconcile(db, task, b2s_archive)

        entry_inputs = self.manager._entry_analysis_inputs(db, task)
        entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
        for module in entry_inputs:
            self.manager._upsert_stage_item(
                db,
                task=task,
                stage_run=entry_run,
                stage_name="entry_analysis",
                item_key=str(module["module_key"]),
                item_name=str(module["module_name"]),
                parent_key=str(module.get("firmware_key") or "") or None,
                downstream_service="entry_analyse",
                input_ref=dict(module),
                retrying=False,
                auto_retrying=False,
            )
        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertTrue(b2s_signals)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("pending", task.status)
        self.assertEqual(1, len(entry_items))

        entry_item = entry_items[0]
        entry_item.status = "success"
        entry_item.downstream_task_id = "ea-1"
        entry_item.downstream_service = "entry_analyse"
        self._persist_stage_item_result(task, entry_item, payload=self._entry_result_payload())
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-1",
        )
        db.archive_jobs.append(entry_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            entry_signals = self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        for entry_module in task.summary.get("entry_results") or []:
            for entry in entry_module.get("entries") or []:
                self.manager._trigger_dataflow_items_from_entry_result(
                    db,
                    task,
                    dict(entry_module),
                    upstream_item=entry_item,
                )
                break
            if self.manager._stage_items(db, task.id, "dataflow_vuln_scan"):
                break
        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        self.assertTrue(entry_signals)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual(1, len(dataflow_items))

        dataflow_run = next(run for run in db.stage_runs if str(run.stage_name or "").strip() == "dataflow_vuln_scan")
        dataflow_item = dataflow_items[0]
        dataflow_item.status = "success"
        dataflow_item.downstream_task_id = "dfs-1"
        dataflow_item.downstream_service = "dataflow_vuln_scan"
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "IPSEC:entry",
                "module_key": "IPSEC",
                "vulns": [{"id": "v-ipsec-1", "severity": "high"}],
            },
        )
        dataflow_archive = self._make_archive_job(
            task=task,
            item=dataflow_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-1",
        )
        db.archive_jobs.append(dataflow_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            dataflow_signals = self._apply_archive_and_reconcile(db, task, dataflow_archive)

        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "binary_to_source")
        self._refresh_stage_summary(db, task, "entry_analysis")
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertTrue(dataflow_signals)
        self.assertIn(task.status, {"running", "success"})
        self.assertTrue((task.summary or {}).get("b2s_results"))
        self.assertTrue((task.summary or {}).get("entry_results"))
        self.assertIn(dataflow_run.status, {"success", "pending"})
        self.assertEqual("success", dataflow_item.status)
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))

    def test_binary_module_workflow_e2e_b2s_success_without_archive_does_not_start_entry(self):
        task = _binary_module_task()
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            output_summary={"success_count": 1},
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-no-archive",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        db = _ModelAwareDb(tasks=[task], stage_runs=[b2s_run], stage_items=[b2s_item], archive_jobs=[], events=[])

        gate = self.manager._evaluate_stage_start_gate(db, task, "entry_analysis")

        self.assertFalse(gate["allowed"])
        self.assertEqual(0, len(self.manager._stage_items(db, task.id, "entry_analysis")))
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertEqual([], db.archive_jobs)

    def test_binary_module_workflow_e2e_b2s_archive_apply_stays_owner_driven_before_entry_materialization(self):
        task = _binary_module_task(
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-owner-driven",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-owner-driven",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-owner-driven",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        b2s_archive = self._make_archive_job(
            task=task,
            item=b2s_item,
            downstream_service="binary_to_source",
            downstream_task_id="b2s-owner-driven",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run],
            stage_items=[b2s_item],
            archive_jobs=[b2s_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, b2s_archive)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(signals)
        self.assertEqual("archive_apply", str(signals[-1].get("reconcile_reason") or ""))
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("pending", task.status)
        self.assertEqual("pending", detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "entry_analysis"])
        b2s_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "binary_to_source")
        self.assertIn(b2s_summary.status, {"running", "success"})
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"pending", "queued"})
        self.assertTrue((task.summary or {}).get("b2s_results"))

    def test_binary_module_workflow_e2e_b2s_archive_without_entry_descriptor_skips_entry_materialization(self):
        task = _binary_module_task(
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-no-entry-descriptor",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-no-entry-descriptor",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-no-entry-descriptor",
        )
        descriptor = {
            **self._binary_module_descriptor(),
            "entry_descriptor_ready": False,
            "entry_files_list": None,
            "files_list": None,
            "files_list_path": None,
        }
        self._persist_stage_item_result(task, b2s_item, payload=descriptor)
        b2s_archive = self._make_archive_job(
            task=task,
            item=b2s_item,
            downstream_service="binary_to_source",
            downstream_task_id="b2s-no-entry-descriptor",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run],
            stage_items=[b2s_item],
            archive_jobs=[b2s_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, b2s_archive)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(signals)
        entry_inputs = self.manager._entry_analysis_inputs(db, task)
        self.assertEqual(1, len(entry_inputs))
        self.assertFalse(bool(entry_inputs[0].get("entry_descriptor_ready")))
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "entry_analysis"])
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertIn(
            self.manager._missing_entry_analysis_input_reason(db, task),
            {
                "binary-to-source 已成功，但未生成入口分析所需模块描述文件",
                "binary-to-source 阶段尚未产出任何可用于入口分析的源码模块",
            },
        )
        gate = self.manager._evaluate_stage_start_gate(db, task, "entry_analysis")
        self.assertFalse(gate["allowed"])
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"pending", "queued"})
        b2s_results = list((task.summary or {}).get("b2s_results") or [])
        self.assertEqual(1, len(b2s_results))
        self.assertFalse(bool(b2s_results[0].get("entry_descriptor_ready")))

    def test_binary_module_workflow_e2e_entry_shell_with_unusable_b2s_descriptor_does_not_rebuild_or_auto_advance(self):
        descriptor = {
            **self._binary_module_descriptor(),
            "entry_descriptor_ready": False,
            "entry_files_list": None,
            "files_list": None,
            "files_list_path": None,
        }
        task = _binary_module_task(summary={"b2s_results": [descriptor]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-shell-unusable-descriptor",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        rebuild = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)
        auto_advance = self.manager._should_auto_advance_to_stage(db, task, "entry_analysis")
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertFalse(rebuild["rebuilt"])
        self.assertIn(
            rebuild["reason"],
            {"missing_inputs", "missing_entry_analysis_inputs", "historical_children_exist_but_authoritative_items_missing"},
        )
        self.assertFalse(auto_advance)
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertIn(
            self.manager._missing_entry_analysis_input_reason(db, task),
            {
                "binary-to-source 已成功，但未生成入口分析所需模块描述文件",
                "binary-to-source 阶段尚未产出任何可用于入口分析的源码模块",
            },
        )
        self.assertEqual("running", detail.status)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertTrue(entry_summary.authoritative_items_missing)
        self.assertFalse(entry_summary.authoritative_rebuild_required)

    def test_binary_module_workflow_e2e_entry_success_without_archive_does_not_start_dataflow(self):
        task = _binary_module_task(
            summary={"b2s_results": [self._binary_module_descriptor()]},
        )
        task.current_stage = "entry_analysis"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-entry-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-entry-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-entry-no-archive",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        entry_run = BinarySecurityStageRun(
            id="sr-entry-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-no-archive",
        )
        self._persist_stage_item_result(task, entry_item, payload=self._entry_result_payload())
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[b2s_item, entry_item],
            archive_jobs=[],
            events=[],
        )

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        self._refresh_stage_summary(db, task, "binary_to_source")
        self._refresh_stage_summary(db, task, "entry_analysis")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertTrue((task.summary or {}).get("entry_results"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("running", entry_summary.status)
        self.assertEqual(1, entry_summary.success_items)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued"})

    def test_binary_module_workflow_e2e_entry_failure_finalizes_parent_failed(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        entry_run = BinarySecurityStageRun(
            id="sr-entry-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-failed",
            error_message="模块 'IPSEC' 的所有文件均未找到: []",
        )
        self._persist_stage_item_result(task, entry_item, payload={**self._entry_result_payload(), "entries": [], "error": "模块 'IPSEC' 的所有文件均未找到: []"})
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("failed", task.status)
        self.assertEqual("failed", entry_run.status)
        self.assertTrue(any(event.event_type == "authoritative_failure_finalize_applied" for event in db.events))
        self.assertTrue(any(event.event_type == "task_finalized_after_child_failure" for event in db.events))

    def test_binary_module_workflow_e2e_entry_success_without_entries_keeps_no_dataflow(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        entry_run = BinarySecurityStageRun(
            id="sr-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-empty",
        )
        self._persist_stage_item_result(task, entry_item, payload={**self._entry_result_payload(), "entries": []})
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-empty",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[entry_archive],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_run.status = "success"
        entry_run.finished_at = _now()
        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))

    def test_binary_module_workflow_e2e_entry_archive_without_entries_finishes_without_dataflow(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "entry_analysis"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-entry-archive-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-entry-archive-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-entry-archive-empty",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        entry_run = BinarySecurityStageRun(
            id="sr-entry-archive-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-archive-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-archive-empty",
        )
        self._persist_stage_item_result(task, entry_item, payload={**self._entry_result_payload(), "entries": []})
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-archive-empty",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[b2s_item, entry_item],
            archive_jobs=[entry_archive],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_run.status = "success"
        entry_run.finished_at = _now()
        self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        entry_results = task.summary.get("entry_results") or []
        self.assertEqual(1, len(entry_results))
        self.assertEqual([], entry_results[0].get("entries") or [])
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("success", entry_summary.status)
        self.assertEqual(1, entry_summary.success_items)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued"})

    def test_binary_module_workflow_e2e_entry_zero_input_with_complete_module_state_does_not_use_source_only_finalize_gate(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "entry_analysis"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-zero-input-complete",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        entry_run = BinarySecurityStageRun(
            id="sr-entry-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-zero-input-complete",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-zero-input-complete",
        )
        self._persist_stage_item_result(task, entry_item, payload={**self._entry_result_payload(), "entries": []})
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-zero-input-complete",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[b2s_item, entry_item],
            archive_jobs=[entry_archive],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_run.status = "success"
        entry_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "entry_analysis")
        self.assertFalse(self.manager._should_finalize_without_entries(db, task, "dataflow_vuln_scan"))

        self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertIn(task.status, {"running", "success"})
        self.assertEqual(task.status, detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertEqual("success", entry_summary.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued"})

    def test_binary_module_workflow_e2e_streaming_incremental_seed(self):
        task = _binary_module_task(
            summary={"b2s_results": [self._binary_module_descriptor()]},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "entry_analysis"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-stream",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-stream",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-stream-1",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        entry_run = self.manager._ensure_stage_run(_ModelAwareDb(tasks=[task], stage_runs=[b2s_run], stage_items=[b2s_item], archive_jobs=[], events=[]), task, "entry_analysis")
        entry_item = BinarySecurityStageItem(
            id="si-entry-stream",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-stream-1",
        )
        self._persist_stage_item_result(task, entry_item, payload=self._entry_result_payload())
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[b2s_item, entry_item],
            archive_jobs=[],
            events=[],
        )

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        before_stage = task.current_stage
        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._trigger_dataflow_items_from_entry_result(
                db,
                task,
                self.manager._entry_module_result_from_stage_item(task, entry_item),
                upstream_item=entry_item,
            )

        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(1, len(dataflow_items))
        self.assertEqual("running", detail.status)
        self.assertEqual(before_stage, task.current_stage)
        self.assertIn("dataflow_vuln_scan", [str(run.stage_name or "") for run in db.stage_runs])
        dataflow_item = dataflow_items[0]
        self.assertEqual("pending", dataflow_item.status)
        self.assertEqual("IPSEC:entry", dataflow_item.item_key)
        self.assertEqual("IPSEC", dataflow_item.parent_key)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"running", "success"})

    def test_binary_module_workflow_e2e_manual_entry_confirmation_blocks_streaming_until_selected(self):
        task = _binary_module_task(
            summary={"b2s_results": [self._binary_module_descriptor()]},
            policy_json=json.dumps(
                {
                    "pipeline_mode": "mixed_streaming",
                    "entry_selection_mode": "manual_confirm",
                }
            ),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-manual-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            started_at=_now(),
            finished_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-manual-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-entry-manual-binary",
        )
        payload = self._entry_result_payload()
        payload["entries"] = [
            {
                **payload["entries"][0],
                "entry_key": "IPSEC:entry-a",
                "function_name": "ipsec_entry_a",
                "definition_file": "ipsec_a.c",
                "definition_line": "10",
            },
            {
                **payload["entries"][0],
                "entry_key": "IPSEC:entry-b",
                "function_name": "ipsec_entry_b",
                "definition_file": "ipsec_b.c",
                "definition_line": "20",
            },
        ]
        self._persist_stage_item_result(task, entry_item, payload=payload)
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-entry-manual-binary",
        )
        entry_archive.archive_status = "success"
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[entry_archive],
            events=[],
        )

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_result = self.manager._entry_module_result_from_stage_item(task, entry_item)
        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            seeded_before_confirmation = self.manager._trigger_dataflow_items_from_entry_result(
                db,
                task,
                entry_result,
                upstream_item=entry_item,
            )

        task.status = "pending_entry_confirmation"
        selection_before = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        start_gate_before = self.manager._evaluate_stage_start_gate(db, task, "dataflow_vuln_scan")
        detail_before = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertEqual([], seeded_before_confirmation)
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertTrue(selection_before.requires_confirmation)
        self.assertEqual(2, len(selection_before.candidate_entries))
        self.assertEqual([], selection_before.selected_entry_keys)
        self.assertFalse(start_gate_before["allowed"])
        self.assertEqual("pending_entry_confirmation", detail_before.status)

        original_write = self.manager._write_task_metadata
        original_run_stage_pool = self.manager._run_stage_pool
        self.manager._write_task_metadata = lambda *_args, **_kwargs: None

        async def fake_run_stage_pool(_task, items, *_args, **_kwargs):
            return [{"status": "success", "item": dict(item)} for item in items]

        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            detail_after_confirmation = self.manager.confirm_entry_selection(
                db,
                project_id=task.project_id,
                task_id=task.id,
                selected_entry_keys=["IPSEC:entry-b"],
            )
            dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
            status, summary = asyncio.run(
                self.manager._stage_dataflow_vuln_scan(
                    db,
                    task,
                    dataflow_run,
                    token=None,
                    retry_existing=False,
                )
            )
        finally:
            self.manager._write_task_metadata = original_write
            self.manager._run_stage_pool = original_run_stage_pool

        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        selection_after = self.manager.get_entry_selection(db, project_id=task.project_id, task_id=task.id)
        detail_after = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)

        self.assertEqual("pending", detail_after_confirmation.status)
        self.assertFalse(selection_after.requires_confirmation)
        self.assertEqual(["IPSEC:entry-b"], selection_after.selected_entry_keys)
        self.assertEqual(1, len(selection_after.selected_entries))
        self.assertEqual("success", status)
        self.assertEqual(1, len(dataflow_items))
        self.assertEqual("IPSEC:entry-b", dataflow_items[0].item_key)
        self.assertEqual("ipsec_entry_b", dataflow_items[0].item_name)
        self.assertEqual(1, summary.get("success_count"))
        self.assertEqual(task.status, detail_after.status)
        self.assertTrue(any(event.event_type == "entry_selection_confirmed" for event in db.events))

    def test_binary_module_workflow_e2e_entry_failure_with_shell_dataflow_still_finalizes_parent_failed(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-failed-shell-next",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-failed-shell-next",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-failed-shell-next",
            error_message="模块 'IPSEC' 的所有文件均未找到: []",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-after-entry-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={**self._entry_result_payload(), "entries": [], "error": "模块 'IPSEC' 的所有文件均未找到: []"},
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run, dataflow_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("failed", task.status)
        self.assertEqual("failed", entry_run.status)
        self.assertEqual("pending", dataflow_run.status)
        event_types = [event.event_type for event in db.events]
        self.assertIn("authoritative_failure_finalize_applied", event_types)
        self.assertIn("task_finalized_after_child_failure", event_types)
        self.assertNotIn("task_finalize_deferred_for_incomplete_stage", event_types)

    def test_binary_module_workflow_e2e_retry_stage_full_requeues_failed_entry_in_place(self):
        from datetime import timedelta

        now = _now()
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "failure_code": "entry_failed",
                "failure_message": "模块 'IPSEC' 的所有文件均未找到: []",
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "模块 'IPSEC' 的所有文件均未找到: []"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-retry-entry",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-retry-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-retry-entry",
            error_message="模块 'IPSEC' 的所有文件均未找到: []",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={**self._entry_result_payload(), "entries": [], "error": "模块 'IPSEC' 的所有文件均未找到: []"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-stage-full-entry",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="entry_analysis",
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
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[b2s_item, entry_item],
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
                target_stage="entry_analysis",
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
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("worker-a", db.runtime_leases[0].owner_instance_id)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual("模块 'IPSEC' 的所有文件均未找到: []", task.last_error)
        self.assertNotIn("failure_code", dict(task.summary or {}))
        self.assertNotIn("failure_message", dict(task.summary or {}))
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("requested")))
        self.assertTrue(bool((operation.result_payload or {}).get("requeue", {}).get("in_place_runtime_resume")))
        self.assertFalse(bool((operation.result_payload or {}).get("requeue", {}).get("owner_release_and_requeue")))
        self.assertEqual("running", detail.status)
        self.assertTrue((task.summary or {}).get("b2s_results"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertIn("operation_requeue_applied", event_types)

    def test_binary_module_workflow_e2e_retry_stage_full_blocked_without_local_owner(self):
        from datetime import timedelta

        now = _now()
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "failure_code": "entry_failed",
                "failure_message": "模块 'IPSEC' 的所有文件均未找到: []",
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "模块 'IPSEC' 的所有文件均未找到: []"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-retry-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-retry-entry-blocked",
            error_message="模块 'IPSEC' 的所有文件均未找到: []",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={**self._entry_result_payload(), "entries": [], "error": "模块 'IPSEC' 的所有文件均未找到: []"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-stage-full-entry-blocked",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="entry_analysis",
            status="running",
            current_step="requeue_task",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-b",
            heartbeat_at=now,
            lease_expires_at=now + timedelta(minutes=5),
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            operations=[operation],
            stage_runs=[b2s_run, entry_run],
            stage_items=[entry_item],
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
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.instance_id = original_instance_id
            self.manager._enqueue_task = original_enqueue
            self.manager._should_auto_advance_to_stage = original_should_auto

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([], queued)
        self.assertEqual("running", operation.status)
        self.assertEqual("failed", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("worker-b", db.runtime_leases[0].owner_instance_id)
        self.assertEqual("failed", detail.status)
        self.assertTrue(any(lease.task_id == task.id for lease in db.runtime_leases))
        event_types = [event.event_type for event in db.events]
        self.assertIn("main_state_write_blocked", event_types)
        self.assertIn("operation_requeue_applied", event_types)
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertNotIn("operation_failed", event_types)

    def test_binary_module_workflow_e2e_force_reset_to_pending_clears_control_state_and_requeues(self):
        from datetime import timedelta

        now = _now()
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "failure_code": "entry_failed",
                "failure_message": "模块 'IPSEC' 的所有文件均未找到: []",
                "runtime_workset": {"pending_task_layer_reconcile": {"reason": "retry_after_failure"}},
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.current_operation_id = "op-force-reset-binary-module"
        task.last_error = "模块 'IPSEC' 的所有文件均未找到: []"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-force-reset",
            error_message="模块 'IPSEC' 的所有文件均未找到: []",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={**self._entry_result_payload(), "entries": [], "error": "模块 'IPSEC' 的所有文件均未找到: []"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-force-reset-binary-module",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="force_reset_to_pending",
            target_stage="entry_analysis",
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
            stage_runs=[b2s_run, entry_run],
            stage_items=[entry_item],
            runtime_leases=[runtime_lease],
            events=[],
        )

        original_enqueue = self.manager._enqueue_task
        queued: list[str] = []
        self.manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
        try:
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual([task.id], queued)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertIsNone(task.current_operation_id)
        self.assertIsNone(task.last_error)
        self.assertEqual({}, dict((task.summary or {}).get("runtime_workset") or {}))
        self.assertNotIn("failure_code", dict(task.summary or {}))
        self.assertNotIn("failure_message", dict(task.summary or {}))
        self.assertEqual("pending", detail.status)
        self.assertEqual("running", operation.status)
        self.assertEqual("operation_succeeded", operation.current_step)
        event_types = [event.event_type for event in db.events]
        self.assertIn("task_status_changed", event_types)
        self.assertIn("task_force_reset_to_pending", event_types)
        self.assertIn("operation_step_started", event_types)
        self.assertIn("operation_step_succeeded", event_types)

    def test_binary_module_workflow_e2e_retry_failed_items_recreates_abnormal_entry_child_inside_operation(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-retry-failed-items-binary-module"
        task.summary = {
            **(task.summary or {}),
            "retry_plan": {
                "target_stage": "entry_analysis",
                "mode": "retry_failed_items",
                "retry_item_keys": ["IPSEC::module-input"],
            },
        }
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="module-input",
            item_identity_key="IPSEC::module-input",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old-binary-module",
        )
        entry_item.input_ref = {
            "module_key": "IPSEC",
            "module_name": "IPSEC",
            "firmware_key": "module-input",
            "source_dir": "/mock/b2s/IPSEC",
            "source_root": "/mock/b2s/IPSEC",
            "source_root_path": "/mock/b2s/IPSEC",
            "module_dir": "/mock/b2s/IPSEC",
            "entry_descriptor_root": "/mock/b2s/IPSEC",
            "entry_files_list": "/mock/b2s/IPSEC/files.list",
            "entry_descriptor_ready": True,
        }
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={**self._entry_result_payload(), "entries": [], "error": "previous child missing"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-binary-module",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_failed_items",
            target_stage="entry_analysis",
            status="running",
            current_step="collect_cleanup_plan",
        )
        operation.resume_cursor = {"current_step": "collect_cleanup_plan"}
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[entry_item],
            operations=[operation],
            events=[],
        )
        deleted_refs: list[dict[str, object]] = []
        created_payloads: list[dict[str, object]] = []

        async def _noop_sync(*_args, **_kwargs):
            return None

        async def _fake_delete_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            deleted_refs.extend(list(refs_arg))
            return len(list(refs_arg))

        async def _fake_create(db_arg, task_arg, item_arg, *, service, token, payload):
            del db_arg, task_arg, token
            created_payloads.append(
                {
                    "service": service,
                    "payload": dict(payload),
                    "item_id": item_arg.id,
                }
            )
            return {"task_id": "ea-new-binary-module", "status": "pending"}

        original_sync = self.manager.sync_downstream_status
        original_delete = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        try:
            self.manager.sync_downstream_status = _noop_sync
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.sync_downstream_status = original_sync
            self.manager._delete_downstream_refs = original_delete
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual(["ea-old-binary-module"], [row["task_id"] for row in deleted_refs])
        self.assertEqual(1, len(created_payloads))
        self.assertEqual("entry_analyse", created_payloads[0]["service"])
        self.assertEqual("ea-new-binary-module", entry_item.downstream_task_id)
        self.assertEqual("pending", entry_item.status)
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        self.assertEqual("running", operation.status)
        self.assertEqual("failed", task.status)
        self.assertEqual("failed", detail.status)
        action_rows = list((operation.result_payload or {}).get("item_actions") or [])
        self.assertEqual(1, len(action_rows))
        self.assertEqual("succeeded", action_rows[0].get("verification_status"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("operation_step_started", event_types)
        self.assertIn("operation_step_succeeded", event_types)

    def test_binary_module_workflow_e2e_retry_failed_items_recreates_abnormal_dataflow_child_inside_operation(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
                "vuln_results": [{"entry_key": "IPSEC:entry-a"}, {"entry_key": "IPSEC:entry-b"}],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-retry-failed-items-dataflow-binary-module"
        task.summary = {
            **(task.summary or {}),
            "retry_plan": {
                "target_stage": "dataflow_vuln_scan",
                "mode": "retry_failed_items",
                "retry_item_keys": ["IPSEC:entry-a::IPSEC"],
            },
        }
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-dataflow-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-dataflow-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="failed",
        )
        vuln_run = BinarySecurityStageRun(
            id="sr-vuln-retry-failed-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=4,
            status="success",
        )
        df_abnormal = BinarySecurityStageItem(
            id="si-df-retry-failed-items-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-a",
            item_name="ipsec_entry_a",
            parent_key="IPSEC",
            item_identity_key="IPSEC:entry-a::IPSEC",
            status="cancelled",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-old-a",
        )
        df_abnormal.input_ref = {
            "entry_key": "IPSEC:entry-a",
            "function_name": "ipsec_entry_a",
            "module_key": "IPSEC",
            "module_name": "IPSEC",
            "definition_file": "ipsec.c",
            "definition_line": "10",
            "definition_kind": "definition",
            "module_input_path": "/mock/b2s/IPSEC",
            "source_root_path": "/mock/b2s/IPSEC",
            "source_dir": "/mock/b2s/IPSEC",
        }
        df_success = BinarySecurityStageItem(
            id="si-df-retry-failed-items-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-b",
            item_name="ipsec_entry_b",
            parent_key="IPSEC",
            item_identity_key="IPSEC:entry-b::IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-success-b",
        )
        df_success.input_ref = {
            "entry_key": "IPSEC:entry-b",
            "function_name": "ipsec_entry_b",
            "module_key": "IPSEC",
            "module_name": "IPSEC",
            "definition_file": "ipsec.c",
            "definition_line": "20",
            "definition_kind": "definition",
            "module_input_path": "/mock/b2s/IPSEC",
            "source_root_path": "/mock/b2s/IPSEC",
            "source_dir": "/mock/b2s/IPSEC",
        }
        vuln_for_abnormal = BinarySecurityStageItem(
            id="si-vuln-retry-failed-items-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=vuln_run.id,
            stage_name="vuln_verify",
            item_key="IPSEC:entry-a",
            item_name="ipsec_entry_a",
            parent_key="IPSEC",
            item_identity_key="IPSEC:entry-a::IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfvs-old-a",
        )
        vuln_for_abnormal.input_ref = {
            "entry_key": "IPSEC:entry-a",
            "function_name": "ipsec_entry_a",
            "module_key": "IPSEC",
            "upstream_item_id": "si-df-retry-failed-items-a",
        }
        vuln_for_success = BinarySecurityStageItem(
            id="si-vuln-retry-failed-items-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=vuln_run.id,
            stage_name="vuln_verify",
            item_key="IPSEC:entry-b",
            item_name="ipsec_entry_b",
            parent_key="IPSEC",
            item_identity_key="IPSEC:entry-b::IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfvs-keep-b",
        )
        vuln_for_success.input_ref = {
            "entry_key": "IPSEC:entry-b",
            "function_name": "ipsec_entry_b",
            "module_key": "IPSEC",
            "upstream_item_id": "si-df-retry-failed-items-b",
        }
        archive_jobs = [
            BinarySecurityArchiveJob(
                id="aj-vuln-retry-failed-items-a",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="dataflow_vuln_scan",
                item_id="si-vuln-retry-failed-items-a",
                archive_status="success",
            ),
            BinarySecurityArchiveJob(
                id="aj-vuln-retry-failed-items-b",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="dataflow_vuln_scan",
                item_id="si-vuln-retry-failed-items-b",
                archive_status="success",
            ),
        ]
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-dataflow-binary-module",
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
            stage_runs=[b2s_run, entry_run, dataflow_run, vuln_run],
            stage_items=[df_abnormal, df_success, vuln_for_abnormal, vuln_for_success],
            archive_jobs=archive_jobs,
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
            return {"task_id": "dfa-new-a", "status": "pending"}

        original_sync = self.manager.sync_downstream_status
        original_active_payload = self.manager._active_downstream_payload
        original_cleanup_refs = self.manager._cleanup_downstream_refs
        original_delete_refs = self.manager._delete_downstream_refs
        original_create = self.manager._downstream_create_task
        original_enqueue = self.manager._enqueue_task
        original_delete_items = self.manager._delete_stage_items_by_ids
        original_clear_archive = self.manager._clear_archive_jobs_for_stage_items
        try:
            self.manager.sync_downstream_status = _noop_sync
            self.manager._active_downstream_payload = _noop_active_payload
            self.manager._cleanup_downstream_refs = _fake_cleanup_refs
            self.manager._delete_downstream_refs = _fake_delete_refs
            self.manager._downstream_create_task = _fake_create
            self.manager._enqueue_task = lambda *_args, **_kwargs: None
            self.manager._delete_stage_items_by_ids = lambda db_arg, item_ids: (
                setattr(db_arg, "stage_items", [item for item in db_arg.stage_items if item.id not in set(item_ids)]) or len(item_ids)
            )
            self.manager._clear_archive_jobs_for_stage_items = lambda db_arg, task_id, stage_name, item_ids: (
                setattr(db_arg, "archive_jobs", [job for job in db_arg.archive_jobs if job.item_id not in set(item_ids)]) or len(item_ids)
            )
            asyncio.run(self.manager._run_task_operation_steps(db, task, operation))
        finally:
            self.manager.sync_downstream_status = original_sync
            self.manager._active_downstream_payload = original_active_payload
            self.manager._cleanup_downstream_refs = original_cleanup_refs
            self.manager._delete_downstream_refs = original_delete_refs
            self.manager._downstream_create_task = original_create
            self.manager._enqueue_task = original_enqueue
            self.manager._delete_stage_items_by_ids = original_delete_items
            self.manager._clear_archive_jobs_for_stage_items = original_clear_archive

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual({"dfa-old-a"}, {ref["task_id"] for ref in cleanup_refs})
        self.assertEqual({"dataflow_vuln_scan"}, {ref["service"] for ref in cleanup_refs})
        self.assertEqual(["dataflow_vuln_scan"], [row["service"] for row in create_calls])
        self.assertEqual("dfa-new-a", df_abnormal.downstream_task_id)
        self.assertEqual("success", df_success.status)
        self.assertEqual("dfa-success-b", df_success.downstream_task_id)
        self.assertEqual(
            {
                "si-df-retry-failed-items-a",
                "si-df-retry-failed-items-b",
                "si-vuln-retry-failed-items-a",
                "si-vuln-retry-failed-items-b",
            },
            {item.id for item in db.stage_items},
        )
        self.assertEqual(
            ["aj-vuln-retry-failed-items-a", "aj-vuln-retry-failed-items-b"],
            [job.id for job in db.archive_jobs],
        )
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        self.assertEqual("failed", operation.status)
        self.assertEqual("failed", detail.status)
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        self.assertEqual("recreate_from_abnormal", action_rows["si-df-retry-failed-items-a"]["strategy"])
        self.assertEqual("dfa-old-a", action_rows["si-df-retry-failed-items-a"]["old_downstream_task_id"])
        self.assertEqual("dfa-new-a", action_rows["si-df-retry-failed-items-a"]["new_downstream_task_id"])
        self.assertEqual("succeeded", action_rows["si-df-retry-failed-items-a"]["cleanup_status"])
        self.assertEqual("succeeded", action_rows["si-df-retry-failed-items-a"]["create_status"])
        self.assertEqual("succeeded", action_rows["si-df-retry-failed-items-a"]["verification_status"])
        self.assertNotIn("si-df-retry-failed-items-b", action_rows)

    def test_binary_module_workflow_e2e_dataflow_success_without_archive_does_not_finalize_parent(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-tail-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-tail-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-tail-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-tail-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry",
            item_name="ipsec_entry",
            parent_key="IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-tail-no-archive",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "IPSEC:entry",
                "module_key": "IPSEC",
                "vulns": [{"id": "v-ipsec-tail-no-archive", "severity": "high"}],
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
        )

        self._refresh_stage_summary(db, task, "binary_to_source")
        self._refresh_stage_summary(db, task, "entry_analysis")
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("running", task.status)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertFalse(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))

    def test_binary_module_workflow_e2e_dataflow_failure_finalizes_parent_failed(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-dataflow-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-dataflow-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-failed-terminal",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-failed-terminal",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry",
            item_name="ipsec_entry",
            parent_key="IPSEC",
            status="failed",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-failed-terminal",
            error_message="dataflow analysis failed",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "IPSEC:entry",
                "module_key": "IPSEC",
                "error": "dataflow analysis failed",
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._refresh_task_status_after_sync(db, task)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("failed", task.status)
        self.assertEqual("failed", detail.status)
        self.assertEqual("failed", dataflow_run.status)
        self.assertEqual(
            "failed",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )
        event_types = [event.event_type for event in db.events]
        self.assertIn("authoritative_failure_finalize_applied", event_types)
        self.assertIn("task_finalized_after_child_failure", event_types)
        self.assertNotIn("task_finalize_deferred_for_incomplete_stage", event_types)

    def test_binary_module_workflow_e2e_final_dataflow_archive_reconcile_closes_task(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-final-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-final-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-final-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-final-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry",
            item_name="ipsec_entry",
            parent_key="IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-final-archive",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "IPSEC:entry",
                "module_key": "IPSEC",
                "vulns": [{"id": "v-ipsec-final", "severity": "high"}],
            },
        )
        dataflow_archive = self._make_archive_job(
            task=task,
            item=dataflow_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-final-archive",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[dataflow_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, dataflow_archive)

        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "binary_to_source")
        self._refresh_stage_summary(db, task, "entry_analysis")
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            self.manager._refresh_task_status_after_sync(db, task)
        finally:
            self.manager._enqueue_task = original_enqueue

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(signals)
        self.assertEqual("archive_apply", str(signals[-1].get("reconcile_reason") or ""))
        self.assertEqual("success", next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"))
        self.assertTrue((task.summary or {}).get("dataflow_results"))
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertIn(task.status, {"running", "success"})
        self.assertEqual(task.status, detail.status)

    def test_binary_module_workflow_e2e_dataflow_partial_success_archive_terminalizes_parent_success(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-ps-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-ps-archive-success",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-a",
            item_name="ipsec_entry_a",
            parent_key="IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-ps-archive-a",
        )
        failed_item = BinarySecurityStageItem(
            id="si-dataflow-ps-archive-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-b",
            item_name="ipsec_entry_b",
            parent_key="IPSEC",
            status="partial_success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-ps-archive-b",
        )
        self._persist_stage_item_result(
            task,
            success_item,
            payload={"entry_key": "IPSEC:entry-a", "module_key": "IPSEC", "vulns": [{"id": "v-a"}]},
        )
        self._persist_stage_item_result(
            task,
            failed_item,
            payload={"entry_key": "IPSEC:entry-b", "module_key": "IPSEC", "vulns": [], "status": "partial_success"},
        )
        success_archive = self._make_archive_job(
            task=task,
            item=success_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-ps-archive-a",
            mapped_status="success",
        )
        partial_archive = self._make_archive_job(
            task=task,
            item=failed_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-ps-archive-b",
            mapped_status="partial_success",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[success_item, failed_item],
            archive_jobs=[success_archive, partial_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            first_signals = self._apply_archive_and_reconcile(db, task, success_archive)
            second_signals = self._apply_archive_and_reconcile(db, task, partial_archive)

        dataflow_run.status = "partial_success"
        dataflow_run.finished_at = _now()
        dataflow_run.output_summary = {"success_count": 1, "partial_success_count": 1}
        self._refresh_stage_summary(db, task, "binary_to_source")
        self._refresh_stage_summary(db, task, "entry_analysis")
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

    def test_binary_module_workflow_e2e_entry_downstream_missing_recovers_on_next_owner_prepare(self):
        now = _now()
        lease_until = now.replace(microsecond=0)
        from datetime import timedelta
        lease_until = lease_until + timedelta(seconds=300)
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            item_identity_key="IPSEC::IPSEC",
            status="downstream_missing",
            downstream_service="entry_analyse",
            downstream_task_id="ea-missing",
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
            heartbeat_at=now,
            lease_expires_at=lease_until,
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
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
                    stage_name="entry_analysis",
                    apply_state=True,
                    force=True,
                )
            )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("downstream_missing", entry_item.status)
        self.assertEqual("ea-missing", entry_item.downstream_task_id)
        self.assertEqual("running", task.status)
        observation = dict(self.manager._load_stage_item_result_payload(entry_item).get("sync_observation") or {})
        self.assertEqual("not_found", observation.get("error_type"))
        inputs = [self._binary_module_descriptor()]
        executable = self.manager._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=entry_run,
            inputs=inputs,
            downstream_service="entry_analyse",
            identity=lambda module: (
                module["module_key"],
                module["module_name"],
                module.get("firmware_key"),
                module,
            ),
            output_ref=lambda _module: {},
        )

        self.assertEqual(inputs, executable)
        self.assertEqual("downstream_missing", entry_item.status)
        self.assertEqual("ea-missing", entry_item.downstream_task_id)

    def test_binary_module_workflow_e2e_dataflow_downstream_missing_marks_missing_without_finalizing_parent(self):
        now = _now()
        lease_until = now.replace(microsecond=0)
        from datetime import timedelta
        lease_until = lease_until + timedelta(seconds=300)
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-missing-non-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-missing-non-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry",
            item_name="ipsec_entry",
            parent_key="IPSEC",
            item_identity_key="IPSEC:entry::IPSEC",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-missing",
            error_message="下游子任务不存在",
            result={"downstream_status": "downstream_missing"},
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-b",
            heartbeat_at=now,
            lease_expires_at=lease_until,
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

        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("dfs-missing", dataflow_item.downstream_task_id)
        self.assertEqual("running", task.status)
        event_types = [event.event_type for event in db.added]
        self.assertIn("owned_execution_owner_reconcile_requested", event_types)
        self.assertIn("owner_reconcile_signal_enqueued", event_types)

    def test_binary_module_workflow_e2e_dataflow_downstream_missing_recovers_on_next_owner_prepare(self):
        now = _now()
        from datetime import timedelta

        lease_until = now.replace(microsecond=0) + timedelta(seconds=300)
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry",
            item_name="ipsec_entry",
            parent_key="IPSEC",
            item_identity_key="IPSEC:entry::IPSEC",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-missing-owner",
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
            heartbeat_at=now,
            lease_expires_at=lease_until,
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

        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("dfs-missing-owner", dataflow_item.downstream_task_id)
        self.assertEqual("running", task.status)
        observation = dict(self.manager._load_stage_item_result_payload(dataflow_item).get("sync_observation") or {})
        self.assertEqual("not_found", observation.get("error_type"))
        inputs = [dict(entry) for entry in (self._entry_result_payload().get("entries") or [])]
        executable = self.manager._prepare_stage_items_for_execution(
            db,
            task=task,
            stage_run=dataflow_run,
            inputs=inputs,
            downstream_service="dataflow_vuln_scan",
            identity=lambda entry: (
                entry["entry_key"],
                entry["function_name"],
                entry.get("module_key"),
                entry,
            ),
            output_ref=lambda _entry: {},
        )

        self.assertEqual([], executable)
        self.assertEqual("downstream_missing", dataflow_item.status)
        self.assertEqual("dfs-missing-owner", dataflow_item.downstream_task_id)

    def test_binary_module_workflow_e2e_replaced_dataflow_child_ignores_stale_late_payload(self):
        task = _binary_module_task(summary={"entry_results": [self._entry_result_payload()]})
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-replaced-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-replaced-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry",
            item_name="ipsec_entry",
            parent_key="IPSEC",
            status="queued",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-new",
            result={
                "sync_observation": {
                    "replacement_in_progress": True,
                    "binding_cleared": False,
                    "verification_status": "pending",
                    "old_downstream_task_id": "dfs-old",
                    "transition_type": "destructive_rebuild",
                }
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
        )

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, _item, _token):
            return {"task_id": "dfs-old", "status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                resp = asyncio.run(
                    self.manager.sync_downstream_status(
                        db,
                        project_id=task.project_id,
                        task_id=task.id,
                        stage_name="dataflow_vuln_scan",
                        apply_state=True,
                    )
                )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual(0, resp.synced_downstream_count)
        self.assertEqual("dfs-new", dataflow_item.downstream_task_id)
        self.assertEqual("queued", dataflow_item.status)
        self.assertIn("stale_downstream_payload_ignored", [event.event_type for event in db.events])
        self.assertNotIn("downstream_parent_mismatch", [event.event_type for event in db.events])

    def test_binary_module_workflow_e2e_replaced_entry_child_ignores_stale_late_payload(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-replaced-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-replaced-module",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="queued",
            downstream_service="entry_analyse",
            downstream_task_id="ea-new",
            result={
                "sync_observation": {
                    "replacement_in_progress": True,
                    "binding_cleared": False,
                    "verification_status": "pending",
                    "old_downstream_task_id": "ea-old",
                    "transition_type": "destructive_rebuild",
                }
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )

        original_fetch = self.manager._fetch_downstream_task_payload
        original_write = self.manager._write_task_metadata_async
        original_enqueue = self.manager._enqueue_task

        async def _fetch(_task, _item, _token):
            return {"task_id": "ea-old", "status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        try:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                resp = asyncio.run(
                    self.manager.sync_downstream_status(
                        db,
                        project_id=task.project_id,
                        task_id=task.id,
                        stage_name="entry_analysis",
                        apply_state=True,
                    )
                )
        finally:
            self.manager._fetch_downstream_task_payload = original_fetch
            self.manager._write_task_metadata_async = original_write
            self.manager._enqueue_task = original_enqueue

        self.assertEqual(0, resp.synced_downstream_count)
        self.assertEqual("ea-new", entry_item.downstream_task_id)
        self.assertEqual("queued", entry_item.status)
        self.assertEqual("running", task.status)
        self.assertIn("downstream_parent_mismatch", [event.event_type for event in db.events])
        self.assertNotIn("stale_downstream_payload_applied", [event.event_type for event in db.events])

    def test_binary_module_workflow_e2e_dataflow_partial_success_keeps_parent_active(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
                "dataflow_results": [
                    {"entry_key": "IPSEC:entry-a", "module_key": "IPSEC", "vulns": [{"id": "v-a"}]},
                    {"entry_key": "IPSEC:entry-b", "module_key": "IPSEC", "vulns": []},
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-terminal-ps",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-terminal-ps",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-terminal-ps",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="partial_success",
            finished_at=_now(),
            output_summary={"success_count": 1, "failed_count": 1},
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-success",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-a",
            item_name="ipsec_entry_a",
            parent_key="IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-a",
        )
        failed_item = BinarySecurityStageItem(
            id="si-dataflow-failed",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-b",
            item_name="ipsec_entry_b",
            parent_key="IPSEC",
            status="failed",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-b",
            error_message="analysis failed",
        )
        self._persist_stage_item_result(task, success_item, payload={"entry_key": "IPSEC:entry-a", "module_key": "IPSEC", "vulns": [{"id": "v-a"}]})
        self._persist_stage_item_result(task, failed_item, payload={"entry_key": "IPSEC:entry-b", "module_key": "IPSEC", "error": "analysis failed"})
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
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

    def test_binary_module_workflow_e2e_dataflow_partial_success_with_downstream_missing_keeps_parent_active(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [self._entry_result_payload()],
                "dataflow_results": [
                    {"entry_key": "IPSEC:entry-a", "module_key": "IPSEC", "vulns": [{"id": "v-a"}]},
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-terminal-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-terminal-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-terminal-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="partial_success",
            finished_at=_now(),
            output_summary={"success_count": 1, "downstream_missing_count": 1},
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-success-dm",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-a",
            item_name="ipsec_entry_a",
            parent_key="IPSEC",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-a",
        )
        missing_item = BinarySecurityStageItem(
            id="si-dataflow-missing-terminal",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-b",
            item_name="ipsec_entry_b",
            parent_key="IPSEC",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfs-missing",
            error_message="downstream task not found",
        )
        self._persist_stage_item_result(task, success_item, payload={"entry_key": "IPSEC:entry-a", "module_key": "IPSEC", "vulns": [{"id": "v-a"}]})
        self._persist_stage_item_result(task, missing_item, payload={"entry_key": "IPSEC:entry-b", "module_key": "IPSEC", "downstream_status": "downstream_missing"})
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[success_item, missing_item],
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
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("partial_success", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)

    def test_binary_module_workflow_e2e_rebuilds_missing_entry_authoritative_items_before_execution(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-missing-items",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[self._binary_module_descriptor()]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, module: dict(module)):
            rebuilt = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)

        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertTrue(rebuilt["rebuilt"])
        self.assertEqual(1, rebuilt["rebuilt_item_count"])
        self.assertEqual(1, len(entry_items))
        self.assertEqual("pending", entry_items[0].status)
        self.assertIsNone(entry_items[0].downstream_task_id)
        self.assertTrue(any(event.event_type == "entry_analysis_authoritative_items_rebuild_started" for event in db.events))
        self.assertTrue(any(event.event_type == "entry_analysis_authoritative_items_rebuild_finished" for event in db.events))

    def test_binary_module_workflow_e2e_rebuild_then_continue_into_dataflow(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-rebuild-continue",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[self._binary_module_descriptor()]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, module: dict(module)):
            rebuilt = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)

        self.assertTrue(rebuilt["rebuilt"])
        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertEqual(1, len(entry_items))

        entry_item = entry_items[0]
        entry_item.status = "success"
        entry_item.downstream_task_id = "ea-rebuilt-1"
        entry_item.downstream_service = "entry_analyse"
        self._persist_stage_item_result(task, entry_item, payload=self._entry_result_payload())
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-rebuilt-1",
        )
        db.archive_jobs.append(entry_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, entry_archive)

        self.assertTrue(signals)
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        self.assertTrue((task.summary or {}).get("entry_results"))

        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertTrue(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        self.assertTrue((task.summary or {}).get("entry_results"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))

    def test_binary_module_workflow_e2e_dataflow_blocked_until_entry_materialized(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "dataflow_vuln_scan"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-shell",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run, dataflow_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[self._binary_module_descriptor()]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, module: dict(module)):
            status, summary = asyncio.run(
                self.manager._stage_dataflow_vuln_scan(
                    db,
                    task,
                    dataflow_run,
                    token=None,
                    retry_existing=False,
                )
            )

        self.assertEqual("pending", status)
        self.assertEqual("blocked_until_entry_analysis_materialized", summary.get("status"))
        self.assertEqual("historical_children_exist_but_authoritative_items_missing", summary.get("reason"))
        self.assertTrue(
            any(
                event.event_type == "dataflow_activation_blocked_until_entry_analysis_materialized"
                for event in db.events
            )
        )

    def test_binary_module_workflow_e2e_active_control_operation_blocks_entry_rebuild_and_auto_advance(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-cancel"
        operation = BinarySecurityTaskOperation(
            id="op-cancel",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="cancel",
            status="queued",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-active-op",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            operations=[operation],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[self._binary_module_descriptor()]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, module: dict(module)):
            rebuild = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)
            auto_advance = self.manager._should_auto_advance_to_stage(db, task, "entry_analysis")

        self.assertFalse(rebuild["rebuilt"])
        self.assertEqual("active_operation_in_progress", rebuild["reason"])
        self.assertFalse(auto_advance)
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertTrue(any(event.event_type == "entry_analysis_authoritative_items_rebuild_skipped" for event in db.events))

    def test_binary_module_workflow_e2e_active_control_operation_blocks_dataflow_activation_until_entry_materialized(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-force-reset"
        operation = BinarySecurityTaskOperation(
            id="op-force-reset",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="force_reset_to_pending",
            status="running",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-active-op-shell",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-active-op-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[entry_run, dataflow_run],
            stage_items=[],
            archive_jobs=[],
            events=[],
            operations=[operation],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[self._binary_module_descriptor()]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, module: dict(module)):
            status, summary = asyncio.run(
                self.manager._stage_dataflow_vuln_scan(
                    db,
                    task,
                    dataflow_run,
                    token=None,
                    retry_existing=False,
                )
            )

        self.assertEqual("pending", status)
        self.assertEqual("blocked_until_entry_analysis_materialized", summary.get("status"))
        self.assertEqual("active_operation_in_progress", summary.get("reason"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertTrue(
            any(
                event.event_type == "dataflow_activation_blocked_until_entry_analysis_materialized"
                for event in db.events
            )
        )

    def test_binary_module_workflow_e2e_b2s_archive_does_not_trigger_repair_for_unmaterialized_descendants(self):
        task = _binary_module_task(policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}))
        task.current_stage = "binary_to_source"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-unmaterialized-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-unmaterialized-desc",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-unmaterialized-desc",
        )
        self._persist_stage_item_result(task, b2s_item, payload=self._binary_module_descriptor())
        entry_run = BinarySecurityStageRun(
            id="sr-entry-shell-after-b2s",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-after-b2s",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="pending",
        )
        b2s_archive = self._make_archive_job(
            task=task,
            item=b2s_item,
            downstream_service="binary_to_source",
            downstream_task_id="b2s-unmaterialized-desc",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[b2s_item],
            archive_jobs=[b2s_archive],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, module: dict(module)):
            signals = self._apply_archive_and_reconcile(db, task, b2s_archive)

        self.assertTrue(signals)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual(1, len(self.manager._stage_items(db, task.id, "entry_analysis")))
        self.assertEqual("pending", entry_run.status)
        self.assertEqual("pending", dataflow_run.status)
        event_types = [event.event_type for event in db.events]
        self.assertNotIn("archive_apply_triggered_input_repair", event_types)
        self.assertNotIn("task_requeued_after_archive_input_repair", event_types)
        self.assertIn("task_layer_reconcile_completed", event_types)


_BINARY_MODULE_E2E_EXPORT_NAMES = [
    "setUp",
    "_make_archive_job",
    "_persist_stage_item_result",
    "_refresh_stage_summary",
    "_apply_archive_and_reconcile",
    "_binary_module_descriptor",
    "_entry_result_payload",
    "test_binary_module_workflow_e2e_owner_restart_recovery_preserves_authoritative_state",
    "test_binary_module_workflow_e2e_happy_path",
    "test_binary_module_workflow_e2e_b2s_success_without_archive_does_not_start_entry",
    "test_binary_module_workflow_e2e_b2s_archive_apply_stays_owner_driven_before_entry_materialization",
    "test_binary_module_workflow_e2e_b2s_archive_without_entry_descriptor_skips_entry_materialization",
    "test_binary_module_workflow_e2e_entry_shell_with_unusable_b2s_descriptor_does_not_rebuild_or_auto_advance",
    "test_binary_module_workflow_e2e_entry_success_without_archive_does_not_start_dataflow",
    "test_binary_module_workflow_e2e_entry_failure_finalizes_parent_failed",
    "test_binary_module_workflow_e2e_entry_success_without_entries_keeps_no_dataflow",
    "test_binary_module_workflow_e2e_entry_archive_without_entries_finishes_without_dataflow",
    "test_binary_module_workflow_e2e_entry_zero_input_with_complete_module_state_does_not_use_source_only_finalize_gate",
    "test_binary_module_workflow_e2e_streaming_incremental_seed",
    "test_binary_module_workflow_e2e_manual_entry_confirmation_blocks_streaming_until_selected",
    "test_binary_module_workflow_e2e_entry_failure_with_shell_dataflow_still_finalizes_parent_failed",
    "test_binary_module_workflow_e2e_retry_stage_full_requeues_failed_entry_in_place",
    "test_binary_module_workflow_e2e_retry_stage_full_blocked_without_local_owner",
    "test_binary_module_workflow_e2e_force_reset_to_pending_clears_control_state_and_requeues",
    "test_binary_module_workflow_e2e_retry_failed_items_recreates_abnormal_entry_child_inside_operation",
    "test_binary_module_workflow_e2e_retry_failed_items_recreates_abnormal_dataflow_child_inside_operation",
    "test_binary_module_workflow_e2e_dataflow_success_without_archive_does_not_finalize_parent",
    "test_binary_module_workflow_e2e_dataflow_failure_finalizes_parent_failed",
    "test_binary_module_workflow_e2e_final_dataflow_archive_reconcile_closes_task",
    "test_binary_module_workflow_e2e_dataflow_partial_success_archive_terminalizes_parent_success",
    "test_binary_module_workflow_e2e_entry_downstream_missing_recovers_on_next_owner_prepare",
    "test_binary_module_workflow_e2e_dataflow_downstream_missing_marks_missing_without_finalizing_parent",
    "test_binary_module_workflow_e2e_dataflow_downstream_missing_recovers_on_next_owner_prepare",
    "test_binary_module_workflow_e2e_replaced_dataflow_child_ignores_stale_late_payload",
    "test_binary_module_workflow_e2e_replaced_entry_child_ignores_stale_late_payload",
    "test_binary_module_workflow_e2e_dataflow_partial_success_keeps_parent_active",
    "test_binary_module_workflow_e2e_dataflow_partial_success_with_downstream_missing_keeps_parent_active",
    "test_binary_module_workflow_e2e_rebuilds_missing_entry_authoritative_items_before_execution",
    "test_binary_module_workflow_e2e_rebuild_then_continue_into_dataflow",
    "test_binary_module_workflow_e2e_dataflow_blocked_until_entry_materialized",
    "test_binary_module_workflow_e2e_active_control_operation_blocks_entry_rebuild_and_auto_advance",
    "test_binary_module_workflow_e2e_active_control_operation_blocks_dataflow_activation_until_entry_materialized",
    "test_binary_module_workflow_e2e_b2s_archive_does_not_trigger_repair_for_unmaterialized_descendants",
]

_BINARY_MODULE_E2E_EXPORTS = {
    name: getattr(BinaryModuleWorkflowE2ETests, name) for name in _BINARY_MODULE_E2E_EXPORT_NAMES
}

for _binary_module_e2e_name in _BINARY_MODULE_E2E_EXPORT_NAMES:
    delattr(BinaryModuleWorkflowE2ETests, _binary_module_e2e_name)

del BinaryModuleWorkflowE2ETests


if __name__ == "__main__":
    unittest.main()
