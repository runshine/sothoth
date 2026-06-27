import asyncio
import json
import unittest
from unittest.mock import patch

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_BINARY,
)
from app.service.task_manager import TaskManager, _now
from tests.test_task_manager import _ModelAwareDb


def _binary_task(*, summary=None, policy_json=None) -> BinarySecurityTask:
    task = BinarySecurityTask(
        id="task-binary-e2e",
        project_id="project-1",
        name="firmware-e2e",
        status="running",
        task_type=TASK_TYPE_BINARY,
        current_stage="firmware_unpack",
        firmware_source="project_filesystem",
        firmware_path="/tmp/fw.bin",
        output_root="/tmp/out",
        workspace_root="/tmp/ws",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        started_at=_now(),
        dispatcher_instance_id="worker-a",
    )
    task.summary = dict(summary or {})
    if policy_json is not None:
        task.policy_json = policy_json
    return task


class BinaryFirmwareWorkflowE2ETests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.manager.instance_id = "worker-a"
        self.manager._enqueue_task = lambda *_args, **_kwargs: None
        if not hasattr(self.manager, "_terminal_stage_for_task"):
            self.manager._terminal_stage_for_task = lambda task: (
                self.manager._stage_sequence_for_task(task)[-1]
                if self.manager._stage_sequence_for_task(task)
                else None
            )

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

    def test_binary_firmware_workflow_e2e_happy_path(self):
        task = _binary_task(policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}))
        firmware_run = BinarySecurityStageRun(
            id="sr-fw",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        firmware_item = BinarySecurityStageItem(
            id="si-fw",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=firmware_run.id,
            stage_name="firmware_unpack",
            item_key="fw-1",
            item_name="fw.bin",
            status="success",
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-1",
        )
        self._persist_stage_item_result(
            task,
            firmware_item,
            payload={
                "firmware_key": "fw-1",
                "firmware_name": "fw-1",
                "filename": "fw.bin",
                "input_path": "/tmp/fw.bin",
                "unpacked_root": "/tmp/archive/fw-1",
                "source_root": "/tmp/archive/fw-1",
                "task_type": TASK_TYPE_BINARY,
            },
        )
        firmware_archive = self._make_archive_job(
            task=task,
            item=firmware_item,
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-1",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run],
            stage_items=[firmware_item],
            archive_jobs=[firmware_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            firmware_signals = self._apply_archive_and_reconcile(db, task, firmware_archive)

        self._refresh_stage_summary(db, task, "firmware_unpack")
        system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
        for firmware in self.manager._system_analysis_inputs(task, db=db):
            self.manager._upsert_stage_item(
                db,
                task=task,
                stage_run=system_run,
                stage_name="system_analysis",
                item_key=str(firmware.get("firmware_key") or "").strip(),
                item_name=str(firmware.get("filename") or firmware.get("firmware_name") or "").strip() or None,
                parent_key=str(firmware.get("firmware_key") or "").strip() or None,
                downstream_service="system_analyse",
                input_ref=firmware,
                retrying=False,
                auto_retrying=False,
            )

        system_items = self.manager._stage_items(db, task.id, "system_analysis")
        self.assertTrue(firmware_signals)
        self.assertIn(str(task.current_stage or ""), {"system_analysis", "binary_to_source", "entry_analysis"})
        self.assertEqual(1, len(system_items))

        system_item = system_items[0]
        system_item.status = "success"
        system_item.downstream_task_id = "sat-1"
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "risk_score": 95,
                        "source_dir": "/tmp/archive/fw-1/mod-a",
                        "source_root": "/tmp/archive/fw-1",
                        "source_root_path": "/tmp/archive/fw-1",
                        "module_dir": "/tmp/archive/fw-1/mod-a",
                        "files_list": "/tmp/archive/fw-1/mod-a/files.list",
                        "files_list_path": "/tmp/archive/fw-1/mod-a/files.list",
                        "task_type": TASK_TYPE_BINARY,
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/archive/fw-1",
                    }
                ]
            },
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-1",
        )
        db.archive_jobs.append(system_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, system_archive)

        self._refresh_stage_summary(db, task, "system_analysis")
        b2s_run = self.manager._ensure_stage_run(db, task, "binary_to_source")
        for module in list((task.summary or {}).get("selected_modules") or []):
            self.manager._upsert_stage_item(
                db,
                task=task,
                stage_run=b2s_run,
                stage_name="binary_to_source",
                item_key=str(module.get("module_key") or "").strip(),
                item_name=str(module.get("module_name") or "").strip() or None,
                parent_key=str(module.get("firmware_key") or "").strip() or None,
                downstream_service="binary_to_source",
                input_ref=module,
                retrying=False,
                auto_retrying=False,
            )

        b2s_items = self.manager._stage_items(db, task.id, "binary_to_source")
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertEqual(1, len(b2s_items))

        b2s_item = b2s_items[0]
        b2s_item.status = "success"
        b2s_item.downstream_task_id = "b2s-1"
        self._persist_stage_item_result(
            task,
            b2s_item,
            payload={
                "firmware_key": "fw-1",
                "firmware_name": "fw-1",
                "filename": "fw.bin",
                "unpacked_root": "/tmp/archive/fw-1",
                "source_root": "/tmp/archive/fw-1",
                "task_type": TASK_TYPE_BINARY,
                "module_key": "mod-a",
                "module_name": "mod-a",
                "module_dir": "/tmp/archive/fw-1/mod-a",
                "source_dir": "/tmp/archive/fw-1/mod-a",
                "entry_module_name": "mod-a-entry",
                "entry_descriptor_root": "/mock/descriptors/mod-a",
                "entry_files_list": "/mock/descriptors/mod-a/files.list",
                "entry_descriptor_ready": True,
            },
        )
        b2s_archive = self._make_archive_job(
            task=task,
            item=b2s_item,
            downstream_service="binary_to_source",
            downstream_task_id="b2s-1",
        )
        db.archive_jobs.append(b2s_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, b2s_archive)

        with patch.object(self.manager, "_is_entry_descriptor_usable", return_value=True):
            self._refresh_stage_summary(db, task, "binary_to_source")
            entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
            for module in self.manager._entry_analysis_inputs(db, task):
                self.manager._upsert_stage_item(
                    db,
                    task=task,
                    stage_run=entry_run,
                    stage_name="entry_analysis",
                    item_key=str(module.get("module_key") or "").strip(),
                    item_name=str(module.get("module_name") or "").strip() or None,
                    parent_key=str(module.get("firmware_key") or "").strip() or None,
                    downstream_service="entry_analyse",
                    input_ref=module,
                    retrying=False,
                    auto_retrying=False,
                )

        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(1, len(entry_items))

        entry_item = entry_items[0]
        entry_item.status = "success"
        entry_item.downstream_task_id = "ea-1"
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/mock/descriptors/mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-main",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "main",
                        "definition_file": "main.c",
                        "definition_line": "18",
                        "source_dir": "/mock/descriptors/mod-a",
                        "source_root": "/mock/descriptors/mod-a",
                        "source_root_path": "/mock/descriptors/mod-a",
                        "module_dir": "/tmp/archive/fw-1/mod-a",
                        "files_list": "/mock/descriptors/mod-a/files.list",
                        "files_list_path": "/mock/descriptors/mod-a/files.list",
                        "task_type": TASK_TYPE_BINARY,
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                    }
                ],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-1",
        )
        db.archive_jobs.append(entry_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
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
                input_ref=entry,
                retrying=False,
                auto_retrying=False,
            )

        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual(1, len(dataflow_items))

        dataflow_item = dataflow_items[0]
        dataflow_item.status = "success"
        dataflow_item.downstream_task_id = "dfa-1"
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "mod-a:entry-main",
                "module_key": "mod-a",
                "vulns": [{"id": "v-1", "severity": "high"}],
            },
        )
        dataflow_archive = self._make_archive_job(
            task=task,
            item=dataflow_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-1",
        )
        db.archive_jobs.append(dataflow_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, dataflow_archive)

        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "firmware_unpack")
        self._refresh_stage_summary(db, task, "system_analysis")
        self._refresh_stage_summary(db, task, "binary_to_source")
        self._refresh_stage_summary(db, task, "entry_analysis")
        self._refresh_stage_summary(db, task, "dataflow_vuln_scan")
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        self.manager._refresh_task_status_after_sync(db, task)
        self.assertIn(task.status, {"pending", "running", "success"})
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertTrue((task.summary or {}).get("b2s_results"))
        self.assertTrue(dataflow_items)
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))

    def test_binary_firmware_workflow_e2e_multi_module_happy_path(self):
        task = _binary_task(policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}))
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-multi",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="running",
            started_at=_now(),
        )
        firmware_item = BinarySecurityStageItem(
            id="si-fw-multi",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=firmware_run.id,
            stage_name="firmware_unpack",
            item_key="fw-1",
            item_name="fw.bin",
            status="success",
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-multi-1",
        )
        self._persist_stage_item_result(
            task,
            firmware_item,
            payload={
                "firmware_key": "fw-1",
                "firmware_name": "fw-1",
                "filename": "fw.bin",
                "input_path": "/tmp/fw.bin",
                "unpacked_root": "/tmp/archive/fw-1",
                "source_root": "/tmp/archive/fw-1",
                "task_type": TASK_TYPE_BINARY,
            },
        )
        firmware_archive = self._make_archive_job(
            task=task,
            item=firmware_item,
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-multi-1",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run],
            stage_items=[firmware_item],
            archive_jobs=[firmware_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, firmware_archive)

        self._refresh_stage_summary(db, task, "firmware_unpack")
        system_run = self.manager._ensure_stage_run(db, task, "system_analysis")
        for firmware in self.manager._system_analysis_inputs(task, db=db):
            self.manager._upsert_stage_item(
                db,
                task=task,
                stage_run=system_run,
                stage_name="system_analysis",
                item_key=str(firmware.get("firmware_key") or "").strip(),
                item_name=str(firmware.get("filename") or firmware.get("firmware_name") or "").strip() or None,
                parent_key=str(firmware.get("firmware_key") or "").strip() or None,
                downstream_service="system_analyse",
                input_ref=firmware,
                retrying=False,
                auto_retrying=False,
            )

        system_item = self.manager._stage_items(db, task.id, "system_analysis")[0]
        system_item.status = "success"
        system_item.downstream_task_id = "sat-multi-1"
        self._persist_stage_item_result(
            task,
            system_item,
            payload={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "risk_level": "高",
                        "risk_score": 95,
                        "source_dir": "/tmp/archive/fw-1/mod-a",
                        "source_root": "/tmp/archive/fw-1",
                        "source_root_path": "/tmp/archive/fw-1",
                        "module_dir": "/tmp/archive/fw-1/mod-a",
                        "files_list": "/tmp/archive/fw-1/mod-a/files.list",
                        "files_list_path": "/tmp/archive/fw-1/mod-a/files.list",
                        "task_type": TASK_TYPE_BINARY,
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/archive/fw-1",
                    },
                    {
                        "module_key": "mod-b",
                        "module_name": "mod-b",
                        "risk_level": "高",
                        "risk_score": 88,
                        "source_dir": "/tmp/archive/fw-1/mod-b",
                        "source_root": "/tmp/archive/fw-1",
                        "source_root_path": "/tmp/archive/fw-1",
                        "module_dir": "/tmp/archive/fw-1/mod-b",
                        "files_list": "/tmp/archive/fw-1/mod-b/files.list",
                        "files_list_path": "/tmp/archive/fw-1/mod-b/files.list",
                        "task_type": TASK_TYPE_BINARY,
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/archive/fw-1",
                    },
                ]
            },
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-multi-1",
        )
        db.archive_jobs.append(system_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, system_archive)

        self._refresh_stage_summary(db, task, "system_analysis")
        self.assertEqual(2, len((task.summary or {}).get("selected_modules") or []))

        b2s_run = self.manager._ensure_stage_run(db, task, "binary_to_source")
        for module in list((task.summary or {}).get("selected_modules") or []):
            self.manager._upsert_stage_item(
                db,
                task=task,
                stage_run=b2s_run,
                stage_name="binary_to_source",
                item_key=str(module.get("module_key") or "").strip(),
                item_name=str(module.get("module_name") or "").strip() or None,
                parent_key=str(module.get("firmware_key") or "").strip() or None,
                downstream_service="binary_to_source",
                input_ref=module,
                retrying=False,
                auto_retrying=False,
            )
        b2s_items = self.manager._stage_items(db, task.id, "binary_to_source")
        self.assertEqual(2, len(b2s_items))

        for item, module_key in zip(b2s_items, ["mod-a", "mod-b"], strict=False):
            item.status = "success"
            item.downstream_task_id = f"b2s-{module_key}"
            self._persist_stage_item_result(
                task,
                item,
                payload={
                    "firmware_key": "fw-1",
                    "firmware_name": "fw-1",
                    "filename": "fw.bin",
                    "unpacked_root": "/tmp/archive/fw-1",
                    "source_root": "/tmp/archive/fw-1",
                    "task_type": TASK_TYPE_BINARY,
                    "module_key": module_key,
                    "module_name": module_key,
                    "module_dir": f"/tmp/archive/fw-1/{module_key}",
                    "source_dir": f"/tmp/archive/fw-1/{module_key}",
                    "entry_module_name": f"{module_key}-entry",
                    "entry_descriptor_root": f"/mock/descriptors/{module_key}",
                    "entry_files_list": f"/mock/descriptors/{module_key}/files.list",
                    "entry_descriptor_ready": True,
                },
            )
            db.archive_jobs.append(
                self._make_archive_job(
                    task=task,
                    item=item,
                    downstream_service="binary_to_source",
                    downstream_task_id=f"b2s-{module_key}",
                )
            )

        for job in [row for row in db.archive_jobs if row.stage_name == "binary_to_source"]:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                self._apply_archive_and_reconcile(db, task, job)

        with patch.object(self.manager, "_is_entry_descriptor_usable", return_value=True):
            self._refresh_stage_summary(db, task, "binary_to_source")
            entry_run = self.manager._ensure_stage_run(db, task, "entry_analysis")
            for module in self.manager._entry_analysis_inputs(db, task):
                self.manager._upsert_stage_item(
                    db,
                    task=task,
                    stage_run=entry_run,
                    stage_name="entry_analysis",
                    item_key=str(module.get("module_key") or "").strip(),
                    item_name=str(module.get("module_name") or "").strip() or None,
                    parent_key=str(module.get("firmware_key") or "").strip() or None,
                    downstream_service="entry_analyse",
                    input_ref=module,
                    retrying=False,
                    auto_retrying=False,
                )
        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertEqual(2, len(entry_items))

        for item, module_key in zip(entry_items, ["mod-a", "mod-b"], strict=False):
            item.status = "success"
            item.downstream_task_id = f"ea-{module_key}"
            self._persist_stage_item_result(
                task,
                item,
                payload={
                    "module_key": module_key,
                    "module_name": module_key,
                    "source_dir": f"/mock/descriptors/{module_key}",
                    "entries": [
                        {
                            "entry_key": f"{module_key}:entry-main",
                            "module_key": module_key,
                            "module_name": module_key,
                            "function_name": f"{module_key}_main",
                            "definition_file": f"{module_key}.c",
                            "definition_line": "18",
                            "source_dir": f"/mock/descriptors/{module_key}",
                            "source_root": f"/mock/descriptors/{module_key}",
                            "source_root_path": f"/mock/descriptors/{module_key}",
                            "module_dir": f"/tmp/archive/fw-1/{module_key}",
                            "files_list": f"/mock/descriptors/{module_key}/files.list",
                            "files_list_path": f"/mock/descriptors/{module_key}/files.list",
                            "task_type": TASK_TYPE_BINARY,
                            "firmware_key": "fw-1",
                            "firmware_name": "fw-1",
                        }
                    ],
                },
            )
            db.archive_jobs.append(
                self._make_archive_job(
                    task=task,
                    item=item,
                    downstream_service="entry_analyse",
                    downstream_task_id=f"ea-{module_key}",
                )
            )

        for job in [row for row in db.archive_jobs if row.stage_name == "entry_analysis"]:
            with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
                self._apply_archive_and_reconcile(db, task, job)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        self.assertGreaterEqual(len((task.summary or {}).get("entry_results") or []), 0)

        dataflow_run = self.manager._ensure_stage_run(db, task, "dataflow_vuln_scan")
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
                input_ref=entry,
                retrying=False,
                auto_retrying=False,
            )
        dataflow_items = self.manager._stage_items(db, task.id, "dataflow_vuln_scan")
        self.assertEqual(2, len(dataflow_items))

        for item in dataflow_items:
            item.status = "success"
            item.downstream_task_id = f"dfa-{item.item_key}"
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

        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "firmware_unpack")
        self._refresh_stage_summary(db, task, "binary_to_source")
        self.manager._refresh_task_status_after_sync(db, task)

        self.assertIn(task.status, {"pending", "running", "success"})
        self.assertEqual(2, len((task.summary or {}).get("b2s_results") or []))
        self.assertGreaterEqual(len((task.summary or {}).get("entry_results") or []), 0)
        self.assertGreaterEqual(len((task.summary or {}).get("dataflow_results") or []), 0)


    def test_binary_firmware_workflow_e2e_firmware_success_without_archive_does_not_start_system_analysis(self):
        task = _binary_task()
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            output_summary={"success_count": 1},
        )
        firmware_item = BinarySecurityStageItem(
            id="si-fw-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=firmware_run.id,
            stage_name="firmware_unpack",
            item_key="fw-1",
            item_name="fw.bin",
            status="success",
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-no-archive",
        )
        self._persist_stage_item_result(
            task,
            firmware_item,
            payload={
                "firmware_key": "fw-1",
                "firmware_name": "fw-1",
                "filename": "fw.bin",
                "unpacked_root": "/tmp/archive/fw-1",
                "source_root": "/tmp/archive/fw-1",
                "task_type": TASK_TYPE_BINARY,
            },
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[firmware_run], stage_items=[firmware_item], archive_jobs=[], events=[])

        gate = self.manager._evaluate_stage_start_gate(db, task, "system_analysis")
        self.assertFalse(gate["allowed"])
        self.assertEqual([], self.manager._system_analysis_inputs(task, db=db))
        self.assertEqual([], self.manager._stage_items(db, task.id, "system_analysis"))
        self.assertEqual("firmware_unpack", task.current_stage)

    def test_binary_firmware_workflow_e2e_binary_to_source_success_without_archive_does_not_start_entry_analysis(self):
        task = _binary_task(summary={"firmware_unpack_results": [{"firmware_key": "fw-1"}]})
        task.current_stage = "binary_to_source"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-pre-b2s-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-pre-b2s-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-blocked",
            result={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/tmp/archive/fw-1/mod-a",
                "module_dir": "/tmp/archive/fw-1/mod-a",
                "source_root": "/tmp/archive/fw-1",
                "entry_descriptor_root": "/mock/descriptors/mod-a",
                "entry_files_list": "/mock/descriptors/mod-a/files.list",
                "entry_descriptor_ready": True,
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run],
            stage_items=[b2s_item],
            archive_jobs=[],
            events=[],
        )

        with patch.object(self.manager, "_is_entry_descriptor_usable", return_value=True):
            self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "entry_analysis"))
            self.assertEqual([], self.manager._entry_analysis_inputs(db, task))

        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual("binary_to_source", task.current_stage)

    def test_binary_firmware_workflow_e2e_system_success_without_archive_does_not_start_binary_to_source(self):
        task = _binary_task(summary={"firmware_unpack_results": [{"firmware_key": "fw-1"}]})
        task.current_stage = "system_analysis"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-pre-system-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="fw-1",
            item_name="fw.bin",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-no-archive",
            result={
                "modules": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "source_dir": "/tmp/archive/fw-1/mod-a",
                        "module_dir": "/tmp/archive/fw-1/mod-a",
                        "source_root": "/tmp/archive/fw-1",
                        "source_root_path": "/tmp/archive/fw-1",
                        "files_list": "/tmp/archive/fw-1/mod-a/files.list",
                        "files_list_path": "/tmp/archive/fw-1/mod-a/files.list",
                        "task_type": TASK_TYPE_BINARY,
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/archive/fw-1",
                    }
                ]
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run],
            stage_items=[system_item],
            archive_jobs=[],
            events=[],
        )

        self._refresh_stage_summary(db, task, "system_analysis")
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "binary_to_source"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "binary_to_source"))
        self.assertEqual("system_analysis", task.current_stage)

    def test_binary_firmware_workflow_e2e_binary_to_source_descriptor_unusable_blocks_entry_analysis(self):
        task = _binary_task(summary={"firmware_unpack_results": [{"firmware_key": "fw-1"}]})
        task.current_stage = "binary_to_source"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-pre-b2s-descriptor-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-pre-b2s-descriptor-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-descriptor-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-descriptor-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-descriptor-blocked",
            result={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/tmp/archive/fw-1/mod-a",
                "module_dir": "/tmp/archive/fw-1/mod-a",
                "source_root": "/tmp/archive/fw-1",
                "entry_descriptor_root": "/mock/descriptors/mod-a",
                "entry_files_list": "/mock/descriptors/mod-a/files.list",
                "entry_descriptor_ready": True,
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run],
            stage_items=[b2s_item],
            archive_jobs=[],
            events=[],
        )

        with patch.object(self.manager, "_is_entry_descriptor_usable", return_value=False):
            self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "entry_analysis"))
            self.assertEqual([], self.manager._entry_analysis_inputs(db, task))
            gate = self.manager._evaluate_stage_start_gate(db, task, "entry_analysis")

        self.assertFalse(gate["allowed"])
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertEqual("binary_to_source", task.current_stage)

    def test_binary_firmware_workflow_e2e_entry_success_without_entries_keeps_no_dataflow(self):
        task = _binary_task(
            summary={
                "firmware_unpack_results": [{"firmware_key": "fw-1"}],
                "b2s_results": [
                    {
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/archive/fw-1",
                        "source_root": "/tmp/archive/fw-1",
                        "task_type": TASK_TYPE_BINARY,
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "module_dir": "/tmp/archive/fw-1/mod-a",
                        "source_dir": "/tmp/archive/fw-1/mod-a",
                        "entry_module_name": "mod-a-entry",
                        "entry_descriptor_root": "/mock/descriptors/mod-a",
                        "entry_files_list": "/mock/descriptors/mod-a/files.list",
                        "entry_descriptor_ready": True,
                    }
                ],
            }
        )
        task.current_stage = "entry_analysis"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-empty",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
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
            parent_key="fw-1",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-empty",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/mock/descriptors/mod-a",
                "entries": [],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-empty",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run],
            stage_items=[entry_item],
            archive_jobs=[entry_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, entry_archive)

        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        entry_run.status = "success"
        entry_run.finished_at = _now()
        self.manager._refresh_task_status_after_sync(db, task)

        entry_results = list((task.summary or {}).get("entry_results") or [])
        self.assertTrue(any((row.get("entries") or []) == [] for row in entry_results))
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        self.assertEqual("running", task.status)
        self.assertEqual("system_analysis", task.current_stage)

    def test_binary_firmware_workflow_e2e_dataflow_success_without_archive_does_not_finalize_parent(self):
        task = _binary_task(
            summary={
                "firmware_unpack_results": [{"firmware_key": "fw-1"}],
                "b2s_results": [{"module_key": "mod-a", "firmware_key": "fw-1"}],
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-main",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main",
                            }
                        ],
                    }
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-no-archive",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
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
            item_key="mod-a:entry-main",
            item_name="main",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-no-archive",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "mod-a:entry-main",
                "module_key": "mod-a",
                "vulns": [{"id": "v-1", "severity": "high"}],
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[],
            events=[],
        )

        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual([], db.archive_jobs)

    def test_binary_firmware_workflow_e2e_replaced_dataflow_child_ignores_stale_late_payload(self):
        task = _binary_task(
            summary={
                "entry_results": [
                    {
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "entries": [
                            {
                                "entry_key": "mod-a:entry-main",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main",
                            }
                        ],
                    }
                ]
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-replaced-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-replaced-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-main",
            item_name="main",
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

        async def _fetch(_task, _item, _token):
            return {"task_id": "dfa-old", "status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
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

        self.assertEqual(0, resp.synced_downstream_count)
        self.assertEqual("dfa-new", dataflow_item.downstream_task_id)
        self.assertEqual("queued", dataflow_item.status)
        self.assertIn("stale_downstream_payload_ignored", [event.event_type for event in db.events])

    def test_binary_firmware_workflow_e2e_replaced_entry_child_ignores_stale_late_payload(self):
        task = _binary_task(
            summary={
                "b2s_results": [
                    {
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/archive/fw-1",
                        "source_root": "/tmp/archive/fw-1",
                        "task_type": TASK_TYPE_BINARY,
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "module_dir": "/tmp/archive/fw-1/mod-a",
                        "source_dir": "/tmp/archive/fw-1/mod-a",
                        "entry_module_name": "mod-a-entry",
                        "entry_descriptor_root": "/mock/descriptors/mod-a",
                        "entry_files_list": "/mock/descriptors/mod-a/files.list",
                        "entry_descriptor_ready": True,
                    }
                ]
            }
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-replaced-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-replaced-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
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

        async def _fetch(_task, _item, _token):
            return {"task_id": "ea-old", "status": "running"}

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._fetch_downstream_task_payload = _fetch
        self.manager._write_task_metadata_async = _noop_write
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

        self.assertEqual(0, resp.synced_downstream_count)
        self.assertEqual("ea-new", entry_item.downstream_task_id)
        self.assertEqual("queued", entry_item.status)
        self.assertEqual("running", task.status)
        self.assertIn("downstream_parent_mismatch", [event.event_type for event in db.events])
        self.assertNotIn("stale_downstream_payload_applied", [event.event_type for event in db.events])

    def test_binary_firmware_workflow_e2e_dataflow_failure_marks_task_failed(self):
        task = _binary_task(summary={"entry_results": [{"module_key": "mod-a", "entries": [{"entry_key": "mod-a:entry-main", "module_key": "mod-a"}]}]})
        task.current_stage = "dataflow_vuln_scan"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-failed-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-failed-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-failed-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-failed-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-failed-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-failed-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-main",
            item_name="main",
            parent_key="mod-a",
            status="failed",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-failed",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item,
            payload={
                "entry_key": "mod-a:entry-main",
                "module_key": "mod-a",
                "error": "analysis crashed",
            },
        )
        dataflow_archive = self._make_archive_job(
            task=task,
            item=dataflow_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-failed",
            mapped_status="failed",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[dataflow_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, dataflow_archive)

        self.manager._refresh_task_status_after_sync(db, task)
        self.assertEqual("failed", task.status)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))

    def test_binary_firmware_workflow_e2e_dataflow_partial_success_currently_finalizes_failed(self):
        task = _binary_task(summary={"entry_results": [{"module_key": "mod-a", "entries": [{"entry_key": "mod-a:entry-main", "module_key": "mod-a"}]}]})
        task.current_stage = "dataflow_vuln_scan"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-partial-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-partial-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-partial-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-partial-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-partial-tail",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="running",
            started_at=_now(),
        )
        dataflow_item_success = BinarySecurityStageItem(
            id="si-dataflow-partial-success",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-main",
            item_name="main",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-partial-success",
        )
        dataflow_item_missing = BinarySecurityStageItem(
            id="si-dataflow-partial-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-alt",
            item_name="alt",
            parent_key="mod-a",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-partial-missing",
            error_message="downstream task not found",
        )
        self._persist_stage_item_result(
            task,
            dataflow_item_success,
            payload={
                "entry_key": "mod-a:entry-main",
                "module_key": "mod-a",
                "vulns": [{"id": "v-1", "severity": "high"}],
            },
        )
        self._persist_stage_item_result(
            task,
            dataflow_item_missing,
            payload={
                "entry_key": "mod-a:entry-alt",
                "module_key": "mod-a",
                "error": "downstream task not found",
            },
        )
        dataflow_archive = self._make_archive_job(
            task=task,
            item=dataflow_item_success,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-partial-success",
            mapped_status="partial_success",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
            stage_items=[dataflow_item_success, dataflow_item_missing],
            archive_jobs=[dataflow_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self._apply_archive_and_reconcile(db, task, dataflow_archive)

        dataflow_run.status = "partial_success"
        dataflow_run.finished_at = _now()
        self.manager._rebuild_summary_results_from_stage_items(db, task, "dataflow_vuln_scan", "dataflow_results")
        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("failed", task.status)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual([], (task.summary or {}).get("dataflow_results") or [])
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))

    def test_binary_firmware_workflow_e2e_late_archive_apply_blocked_after_archive_failure(self):
        task = _binary_task()
        task.status = "failed"
        task.current_stage = "firmware_unpack"
        task.last_error = "总任务产物归档失败: payload too large"
        firmware_item = BinarySecurityStageItem(
            id="si-fw-archive-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-fw-archive-blocked",
            stage_name="firmware_unpack",
            item_key="fw-1",
            item_name="fw.bin",
            status="success",
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-archive-blocked",
        )
        later_item = BinarySecurityStageItem(
            id="si-system-archive-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-system-archive-blocked",
            stage_name="system_analysis",
            item_key="fw-1",
            item_name="fw.bin",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat-archive-blocked",
        )
        archive_job = BinarySecurityArchiveJob(
            id="aj-fw-archive-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            item_id=firmware_item.id,
            item_key=firmware_item.item_key,
            downstream_service="firmware_unpacker",
            downstream_task_id="fu-archive-blocked",
            archive_status="archived",
        )
        archive_job.payload = {
            "mapped_status": "success",
            "bound_downstream_task_id": "fu-archive-blocked",
            "downstream_payload": {"task_id": "fu-archive-blocked", "status": "success"},
        }
        db = _ModelAwareDb(
            tasks=[task],
            stage_items=[firmware_item, later_item],
            archive_jobs=[archive_job],
            events=[],
        )

        original_write = self.manager._write_task_metadata_async

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._write_task_metadata_async = _noop_write
        try:
            asyncio.run(self.manager._apply_archive_job_status_locked(db, archive_job.id, "/tmp/archive-blocked"))
        finally:
            self.manager._write_task_metadata_async = original_write

        self.assertEqual("ignored", archive_job.archive_status)
        self.assertEqual("success", firmware_item.status)
        self.assertEqual("failed", task.status)
        self.assertEqual("firmware_unpack", task.current_stage)
        self.assertIn(
            "downstream_archive_apply_blocked_by_authoritative_failure",
            [event.event_type for event in db.events],
        )
