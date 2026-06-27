import asyncio
import json
import unittest
import uuid
from unittest.mock import patch

from app.exception import NotFoundError
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
        dispatcher_instance_id="worker-a",
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
        dispatcher_instance_id="worker-a",
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
        self.assertTrue(gate["allowed"])
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual("system_analysis", task.current_stage)
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

        self.assertEqual("running", task.status)
        self.assertTrue(self.manager._should_finalize_without_entries(db, task, "entry_analysis"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "dataflow_vuln_scan"])
        self.assertFalse(any(event.event_type == "streaming_tail_activated" for event in db.events))

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

        self.assertTrue(signals)
        self.assertEqual("archive_apply", str(signals[-1].get("reconcile_reason") or ""))
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "entry_analysis"])

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

        self.assertIn(task.status, {"running", "success"})
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))

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

        self.assertIn(task.status, {"running", "success"})
        self.assertEqual([], db.archive_jobs)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)

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
        task.dispatcher_instance_id = "worker-b"
        task.dispatch_started_at = now
        task.lease_expires_at = lease_until
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
        self.assertIn("streaming_stage_item_requeued_after_downstream_missing", event_types)
        self.assertIn("owned_execution_takeover_requeued", event_types)

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
        task.dispatch_started_at = now
        task.lease_expires_at = lease_until
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
        observation = dict(self.manager._load_stage_item_result_payload(entry_item).get("sync_observation") or {})
        self.assertEqual("not_found", observation.get("error_type"))
        event_types = [event.event_type for event in db.added]
        self.assertIn("streaming_stage_item_requeued_after_downstream_missing", event_types)

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

        self.assertEqual(inputs, executable)
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
        self.assertEqual(1, len(dataflow_items))
        self.assertEqual(before_stage, task.current_stage)
        self.assertIn(
            "dataflow_vuln_scan",
            [str(run.stage_name or "") for run in db.stage_runs],
        )
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

        self.assertFalse(gate["allowed"])
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "dataflow_vuln_scan"])
        self.assertEqual("system_analysis", task.current_stage)
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))

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

        self.assertEqual("failed", task.status)
        self.assertEqual("failed", entry_run.status)
        self.assertTrue(any(event.event_type == "authoritative_failure_finalize_applied" for event in db.events))
        self.assertTrue(any(event.event_type == "task_finalized_after_child_failure" for event in db.events))

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
        task = _source_task(summary={"input_dir": "/tmp/source-project", "selected_modules": [module]})
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
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("partial_success", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)

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

        self.assertEqual(0, resp.synced_downstream_count)
        self.assertEqual("dfa-new", dataflow_item.downstream_task_id)
        self.assertEqual("queued", dataflow_item.status)
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

        self.assertTrue(signals)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual(0, len(self.manager._stage_items(db, task.id, "entry_analysis")))
        self.assertEqual("pending", entry_run.status)
        self.assertEqual("pending", dataflow_run.status)
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
        self.assertEqual("worker-a", task.dispatcher_instance_id)


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
        self.assertEqual("running", task.status)
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
        task.dispatch_started_at = now
        task.lease_expires_at = lease_until
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
        event_types = [event.event_type for event in db.added]
        self.assertIn("streaming_stage_item_requeued_after_downstream_missing", event_types)

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
        task.dispatcher_instance_id = "worker-b"
        task.dispatch_started_at = now
        task.lease_expires_at = lease_until
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
        self.assertIn("streaming_stage_item_requeued_after_downstream_missing", event_types)
        self.assertIn("owned_execution_takeover_requeued", event_types)

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
        task.dispatch_started_at = now
        task.lease_expires_at = lease_until
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
        event_types = [event.event_type for event in db.added]
        self.assertIn("streaming_stage_item_requeued_after_downstream_missing", event_types)

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

        self.assertEqual(inputs, executable)
        self.assertEqual("queued", dataflow_item.status)
        self.assertIsNone(dataflow_item.downstream_task_id)

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


if __name__ == "__main__":
    unittest.main()
