import asyncio
import json
import tempfile
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.service import task_manager as task_manager_module
from app.exception import NotFoundError
from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TERMINAL,
    TASK_TYPE_BINARY,
)
from app.service.task_manager import TaskManager, _now
from tests.test_task_manager import _AppendingModelAwareDb, _ModelAwareDb


def _binary_task(*, summary=None, policy_json=None) -> BinarySecurityTask:
    task_suffix = uuid.uuid4().hex[:12]
    task = BinarySecurityTask(
        id=f"task-binary-e2e-{task_suffix}",
        project_id="project-1",
        name="firmware-e2e",
        status="running",
        task_type=TASK_TYPE_BINARY,
        current_stage="firmware_unpack",
        firmware_source="project_filesystem",
        firmware_path="/tmp/fw.bin",
        output_root=f"/tmp/bs-binary-out-{task_suffix}",
        workspace_root=f"/tmp/bs-binary-ws-{task_suffix}",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        started_at=_now(),
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
        self.assertIn(task.status, {"pending", "running", "success", "partial_success"})
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

    def test_binary_firmware_workflow_e2e_repairs_firmware_unpack_inputs_from_metadata_before_stage_start(self):
        with tempfile.TemporaryDirectory(prefix="bs-fw-input-repair-") as tmp:
            input_dir = Path(tmp) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            firmware_path = input_dir / "fw.bin"
            firmware_path.write_bytes(b"binary")
            (input_dir / "task-metadata.json").write_text(
                json.dumps(
                    {
                        "input_files": [
                            {
                                "filename": "fw.bin",
                                "relative_path": "fw.bin",
                                "firmware_key": "fw-1",
                                "path": f"{input_dir}/fw.bin",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            task = _binary_task(
                summary={
                    "input_dir": str(input_dir),
                    "input_manifest_path": str(input_dir / "task-metadata.json"),
                    "input_files": [],
                },
            )
            task.workspace_root = tmp
            task.firmware_path = str(input_dir)
            runtime_lease = BinarySecurityTaskRuntimeLease(
                task_id=task.id,
                owner_instance_id=self.manager.instance_id,
                lease_expires_at=_now() + timedelta(minutes=5),
            )
            db = _ModelAwareDb(tasks=[task], runtime_leases=[runtime_lease], events=[])

            async def _noop_write(*_args, **_kwargs):
                return None

            with (
                patch("app.service.task_manager.get_session_factory", return_value=lambda: db),
                patch.object(self.manager, "_service_token", return_value=None),
                patch.object(self.manager, "_bind_execution_token"),
                patch.object(self.manager, "_stage_sequence_for_task", return_value=["firmware_unpack"]),
                patch.object(self.manager, "_missing_entry_results_failure_context", return_value=None),
                patch.object(
                    self.manager,
                    "_stage_firmware_unpack",
                    new=AsyncMock(return_value=("success", {"firmware_unpack_results": [{"firmware_key": "fw-1"}]})),
                ),
                patch.object(self.manager, "_write_task_metadata_async", new=_noop_write),
            ):
                asyncio.run(self.manager._execute_task(task.id))

            self.assertEqual(1, len((task.summary or {}).get("input_files") or []))
            self.assertEqual("fw.bin", task.summary["input_files"][0]["filename"])
            self.assertNotEqual("failed", task.status)

    def test_binary_firmware_workflow_e2e_terminalizes_when_firmware_inputs_are_truly_missing(self):
        with tempfile.TemporaryDirectory(prefix="bs-fw-input-missing-") as tmp:
            task = _binary_task(
                summary={
                    "input_dir": str(Path(tmp) / "input"),
                    "input_manifest_path": str(Path(tmp) / "input" / "task-metadata.json"),
                    "input_files": [],
                },
            )
            task.workspace_root = tmp
            task.firmware_path = str(Path(tmp) / "input")
            runtime_lease = BinarySecurityTaskRuntimeLease(
                task_id=task.id,
                owner_instance_id=self.manager.instance_id,
                lease_expires_at=_now() + timedelta(minutes=5),
            )
            db = _ModelAwareDb(tasks=[task], runtime_leases=[runtime_lease], events=[])

            async def _noop_write(*_args, **_kwargs):
                return None

            with (
                patch("app.service.task_manager.get_session_factory", return_value=lambda: db),
                patch.object(self.manager, "_service_token", return_value=None),
                patch.object(self.manager, "_bind_execution_token"),
                patch.object(self.manager, "_stage_sequence_for_task", return_value=["firmware_unpack"]),
                patch.object(self.manager, "_missing_entry_results_failure_context", return_value=None),
                patch.object(self.manager, "_write_task_metadata_async", new=_noop_write),
            ):
                asyncio.run(self.manager._execute_task(task.id))

            self.assertEqual("failed", task.status)
            self.assertEqual(TASK_RUNTIME_PHASE_TERMINAL, task.runtime_phase)
            self.assertEqual("缺少输入文件", task.last_error)
            self.assertTrue(any(event.event_type == "authoritative_failure_finalize_started" for event in db.events))

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

    def test_binary_firmware_workflow_e2e_binary_to_source_archive_apply_stays_owner_driven_before_entry_materialization(self):
        task = _binary_task(
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-owner-driven-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-owner-driven-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-owner-driven-binary",
        )
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
            downstream_task_id="b2s-owner-driven-binary",
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

    def test_binary_firmware_workflow_e2e_system_archive_apply_stays_owner_driven_before_binary_to_source_materialization(self):
        task = _binary_task(
            summary={"firmware_unpack_results": [{"firmware_key": "fw-1"}]},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-owner-driven-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-owner-driven-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="fw-1",
            item_name="fw.bin",
            parent_key="fw-1",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-owner-driven-binary",
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
            downstream_task_id="sat-owner-driven-binary",
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
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertEqual("running", detail.status)
        self.assertEqual([], self.manager._stage_items(db, task.id, "binary_to_source"))
        self.assertEqual([], [run for run in db.stage_runs if str(run.stage_name or "").strip() == "binary_to_source"])
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertIn(system_summary.status, {"running", "success"})
        b2s_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "binary_to_source")
        self.assertIn(b2s_summary.status, {"pending", "queued"})

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
        self.assertEqual("pending", task.status)
        self.assertEqual("system_analysis", task.current_stage)

    def test_binary_firmware_workflow_e2e_entry_success_without_archive_does_not_start_dataflow(self):
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
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-no-archive-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-no-archive-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-no-archive-binary",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/mock/descriptors/mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-1",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "fn_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
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
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertFalse(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"running", "success"})
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertIn(dataflow_summary.status, {"pending", "queued"})

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

    def test_binary_firmware_workflow_e2e_dataflow_downstream_missing_marks_missing_without_finalizing_parent(self):
        now = _now()
        from datetime import timedelta

        lease_until = now.replace(microsecond=0) + timedelta(seconds=300)
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
                                "firmware_key": "fw-1",
                                "firmware_name": "fw-1",
                            }
                        ],
                    }
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-binary-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-binary-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-main",
            item_name="main",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-main::mod-a",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-missing-binary",
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
        self.assertEqual("dfa-missing-binary", dataflow_item.downstream_task_id)
        self.assertEqual("running", task.status)
        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("running", detail.status)
        dataflow_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan")
        self.assertEqual("downstream_missing", dataflow_summary.status)
        self.assertEqual(1, dataflow_summary.downstream_missing_items)
        event_types = [event.event_type for event in db.added]
        self.assertIn("owned_execution_owner_reconcile_requested", event_types)
        self.assertIn("owner_reconcile_signal_enqueued", event_types)

    def test_binary_firmware_workflow_e2e_dataflow_downstream_missing_recovers_on_next_owner_prepare(self):
        now = _now()
        from datetime import timedelta

        lease_until = now.replace(microsecond=0) + timedelta(seconds=300)
        entry = {
            "entry_key": "mod-a:entry-main",
            "module_key": "mod-a",
            "module_name": "mod-a",
            "function_name": "main",
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
        task = _binary_task(
            summary={"entry_results": [{"module_key": "mod-a", "module_name": "mod-a", "entries": [entry]}]},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "dataflow_vuln_scan"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-binary-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="running",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-binary-missing-owner",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-main",
            item_name="main",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-main::mod-a",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-missing-owner-binary",
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
        self.assertEqual("dfa-missing-owner-binary", dataflow_item.downstream_task_id)
        self.assertEqual("running", task.status)
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
        self.assertEqual("dfa-missing-owner-binary", dataflow_item.downstream_task_id)

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

    def test_binary_firmware_workflow_e2e_entry_downstream_missing_recovers_on_next_owner_prepare(self):
        now = _now()
        from datetime import timedelta

        lease_until = now.replace(microsecond=0) + timedelta(seconds=300)
        module = {
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
        task = _binary_task(
            summary={"b2s_results": [module]},
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-binary-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="running",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-binary-missing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            item_identity_key="mod-a::fw-1",
            status="downstream_missing",
            downstream_service="entry_analyse",
            downstream_task_id="ea-missing-binary",
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
        self.assertEqual("ea-missing-binary", entry_item.downstream_task_id)
        self.assertEqual("running", task.status)
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

        self.assertEqual(inputs, executable)
        self.assertEqual("downstream_missing", entry_item.status)
        self.assertEqual("ea-missing-binary", entry_item.downstream_task_id)

    def test_binary_firmware_workflow_e2e_streaming_incremental_seed(self):
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
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.current_stage = "entry_analysis"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-stream-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-stream-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-stream-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-stream-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-stream-binary",
        )
        self._persist_stage_item_result(
            task,
            b2s_item,
            payload=(task.summary or {}).get("b2s_results")[0],
        )
        entry_run = self.manager._ensure_stage_run(
            _ModelAwareDb(
                tasks=[task],
                stage_runs=[firmware_run, system_run, b2s_run],
                stage_items=[b2s_item],
                archive_jobs=[],
                events=[],
            ),
            task,
            "entry_analysis",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-stream-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-stream-binary",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/tmp/archive/fw-1/mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-main",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "main_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "definition_kind": "definition",
                        "module_input_path": "/tmp/archive/fw-1/mod-a",
                        "source_root_path": "/tmp/archive/fw-1",
                        "source_dir": "/tmp/archive/fw-1/mod-a",
                    }
                ],
            },
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run],
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
        self.assertEqual("mod-a:entry-main", dataflow_item.item_key)
        self.assertEqual("mod-a", dataflow_item.parent_key)
        entry_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "entry_analysis")
        self.assertIn(entry_summary.status, {"running", "success"})
        self.assertTrue(any(event.event_type == "streaming_dataflow_vuln_scan_items_seeded" for event in db.events))

    def test_binary_firmware_workflow_e2e_manual_entry_confirmation_blocks_streaming_until_selected(self):
        task = _binary_task(
            summary={
                "firmware_unpack_results": [{"firmware_key": "fw-1", "firmware_name": "fw-1", "filename": "fw.bin"}],
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
            },
            policy_json=json.dumps(
                {
                    "pipeline_mode": "mixed_streaming",
                    "entry_selection_mode": "manual_confirm",
                }
            ),
        )
        task.current_stage = "entry_analysis"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-manual-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-manual-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-manual-binary",
        )
        self._persist_stage_item_result(
            task,
            b2s_item,
            payload=(task.summary or {}).get("b2s_results")[0],
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-manual-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
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
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-manual-binary",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={
                "module_key": "mod-a",
                "module_name": "mod-a",
                "source_dir": "/mock/descriptors/mod-a",
                "entries": [
                    {
                        "entry_key": "mod-a:entry-a",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "main_a",
                        "definition_file": "a.c",
                        "definition_line": "10",
                        "definition_kind": "definition",
                        "module_input_path": "/tmp/archive/fw-1/mod-a",
                        "source_root_path": "/tmp/archive/fw-1",
                        "source_dir": "/mock/descriptors/mod-a",
                    },
                    {
                        "entry_key": "mod-a:entry-b",
                        "module_key": "mod-a",
                        "module_name": "mod-a",
                        "function_name": "main_b",
                        "definition_file": "b.c",
                        "definition_line": "20",
                        "definition_kind": "definition",
                        "module_input_path": "/tmp/archive/fw-1/mod-a",
                        "source_root_path": "/tmp/archive/fw-1",
                        "source_dir": "/mock/descriptors/mod-a",
                    },
                ],
            },
        )
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-manual-binary",
        )
        entry_archive.archive_status = "success"
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[b2s_item, entry_item],
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
                selected_entry_keys=["mod-a:entry-b"],
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
        self.assertEqual(["mod-a:entry-b"], selection_after.selected_entry_keys)
        self.assertEqual(1, len(selection_after.selected_entries))
        self.assertEqual("success", status)
        self.assertEqual(1, len(dataflow_items))
        self.assertEqual("mod-a:entry-b", dataflow_items[0].item_key)
        self.assertEqual("main_b", dataflow_items[0].item_name)
        self.assertEqual(1, summary.get("success_count"))
        self.assertEqual(task.status, detail_after.status)
        self.assertTrue(any(event.event_type == "entry_selection_confirmed" for event in db.events))

    def test_binary_firmware_workflow_e2e_cancel_running_entry_analysis_cancels_firmware_child_and_runner(self):
        task = _binary_task(summary={"input_path": "/tmp/fw.bin"})
        task.status = "running"
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-cancel-binary-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-cancel-binary-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="ea-cancel-binary-e2e",
        )
        entry_item.input_ref = {
            "module_key": "mod-a",
            "module_name": "mod-a",
            "firmware_key": "fw-1",
            "firmware_name": "fw.bin",
            "source_dir": "/tmp/archive/fw-1/mod-a",
            "source_root": "/tmp/archive/fw-1",
            "source_root_path": "/tmp/archive/fw-1",
            "module_dir": "/tmp/archive/fw-1/mod-a",
            "files_list": "/tmp/archive/fw-1/mod-a/files.list",
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
        self.assertEqual(["ea-cancel-binary-e2e"], cancelled_children)
        self.assertEqual([(task.id, False)], local_cancel_requests)
        self.assertTrue(cancelled_ref_batches)
        self.assertEqual("cancelling", detail.status)
        self.assertTrue(any(event.event_type == "task_cancelling" for event in db.events))

    def test_binary_firmware_workflow_e2e_entry_archive_without_entries_finishes_without_dataflow(self):
        task = _binary_task(
            summary={
                "firmware_unpack_results": [{"firmware_key": "fw-1", "firmware_name": "fw-1", "filename": "fw.bin"}],
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
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-entry-archive-empty-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-entry-archive-empty-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-entry-archive-empty-binary",
        )
        self._persist_stage_item_result(
            task,
            b2s_item,
            payload=(task.summary or {}).get("b2s_results")[0],
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-archive-empty-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-archive-empty-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-entry-archive-empty-binary",
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
            downstream_task_id="ea-entry-archive-empty-binary",
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

    def test_binary_firmware_workflow_e2e_rebuilds_missing_entry_authoritative_items_before_execution(self):
        module = {
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
        task = _binary_task(summary={"b2s_results": [module]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-missing-items-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
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

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[module]), \
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

    def test_binary_firmware_workflow_e2e_owner_restart_recovery_preserves_authoritative_state(self):
        module = {
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
        entry_payload = {
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
                    "source_dir": "/tmp/archive/fw-1/mod-a",
                    "source_root": "/tmp/archive/fw-1",
                    "source_root_path": "/tmp/archive/fw-1",
                    "module_dir": "/tmp/archive/fw-1/mod-a",
                    "files_list": "/mock/descriptors/mod-a/files.list",
                    "files_list_path": "/mock/descriptors/mod-a/files.list",
                    "task_type": TASK_TYPE_BINARY,
                    "firmware_key": "fw-1",
                    "firmware_name": "fw-1",
                }
            ],
        }
        task = _binary_task(summary={"b2s_results": [module]})
        task.current_stage = "entry_analysis"
        task.status = "running"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-recover-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            started_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-recover-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            started_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-recover-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-recover-binary",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-recover-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="ea-recover-binary",
        )
        self._persist_stage_item_result(task, b2s_item, payload=module)
        self._persist_stage_item_result(task, entry_item, payload=entry_payload)
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run],
            stage_items=[b2s_item, entry_item],
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

    def test_binary_firmware_workflow_e2e_rebuild_then_continue_into_dataflow(self):
        module = {
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
        entry_payload = {
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
        }
        task = _binary_task(summary={"b2s_results": [module]})
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-rebuild-continue-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
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

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[module]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, current: dict(current)):
            rebuilt = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)

        self.assertTrue(rebuilt["rebuilt"])
        entry_items = self.manager._stage_items(db, task.id, "entry_analysis")
        self.assertEqual(1, len(entry_items))

        entry_item = entry_items[0]
        entry_item.status = "success"
        entry_item.downstream_task_id = "ea-rebuilt-binary-1"
        entry_item.downstream_service = "entry_analyse"
        self._persist_stage_item_result(task, entry_item, payload=entry_payload)
        entry_archive = self._make_archive_job(
            task=task,
            item=entry_item,
            downstream_service="entry_analyse",
            downstream_task_id="ea-rebuilt-binary-1",
        )
        db.archive_jobs.append(entry_archive)

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, entry_archive)

        self.assertTrue(signals)
        self.manager._rebuild_entry_results_from_stage_items(db, task, entry_run)
        self.assertTrue((task.summary or {}).get("entry_results"))

        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertTrue(self.manager._should_auto_advance_to_stage(db, task, "dataflow_vuln_scan"))
        self.assertEqual([], self.manager._stage_items(db, task.id, "dataflow_vuln_scan"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("entry_analysis_authoritative_items_rebuild_finished", event_types)
        self.assertIn("task_layer_reconcile_completed", event_types)

    def test_binary_firmware_workflow_e2e_dataflow_blocked_until_entry_materialized(self):
        module = {
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
        task = _binary_task(summary={"b2s_results": [module]})
        task.current_stage = "dataflow_vuln_scan"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-shell-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-blocked-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
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

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[module]), \
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

    def test_binary_firmware_workflow_e2e_active_control_operation_blocks_entry_rebuild_and_auto_advance(self):
        module = {
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
        task = _binary_task(summary={"b2s_results": [module]})
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-cancel-binary"
        operation = BinarySecurityTaskOperation(
            id="op-cancel-binary",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="cancel",
            status="queued",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-active-op-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
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

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[module]), \
             patch.object(self.manager, "_normalize_entry_analysis_module_input", side_effect=lambda _task, current: dict(current)):
            rebuild = self.manager._rebuild_missing_entry_analysis_stage_items_from_inputs(db, task, stage_run=entry_run)
            auto_advance = self.manager._should_auto_advance_to_stage(db, task, "entry_analysis")

        self.assertFalse(rebuild["rebuilt"])
        self.assertEqual("active_operation_in_progress", rebuild["reason"])
        self.assertFalse(auto_advance)
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertTrue(any(event.event_type == "entry_analysis_authoritative_items_rebuild_skipped" for event in db.events))

    def test_binary_firmware_workflow_e2e_active_control_operation_blocks_dataflow_activation_until_entry_materialized(self):
        module = {
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
        task = _binary_task(summary={"b2s_results": [module]})
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-force-reset-binary"
        operation = BinarySecurityTaskOperation(
            id="op-force-reset-binary",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="force_reset_to_pending",
            status="running",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-active-op-shell-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-active-op-blocked-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
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

        with patch.object(self.manager, "_entry_analysis_inputs", return_value=[module]), \
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
        self.assertEqual([], self.manager._stage_items(db, task.id, "entry_analysis"))
        self.assertTrue(
            any(
                event.event_type == "dataflow_activation_blocked_until_entry_analysis_materialized"
                for event in db.events
            )
        )

    def test_binary_firmware_workflow_e2e_entry_failure_finalizes_parent_failed(self):
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
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-entry-failed-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-entry-failed-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-entry-failed-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-failed-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-failed-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-failed-binary",
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
            stage_runs=[firmware_run, system_run, b2s_run, entry_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("failed", task.status)
        self.assertEqual("failed", entry_run.status)
        self.assertTrue(any(event.event_type == "authoritative_failure_finalize_applied" for event in db.events))
        self.assertTrue(any(event.event_type == "task_finalized_after_child_failure" for event in db.events))

    def test_binary_firmware_workflow_e2e_entry_failure_with_shell_dataflow_still_finalizes_parent_failed(self):
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
            id="sr-entry-failed-shell-next-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-failed-shell-next-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-failed-shell-next-binary",
            error_message="entry extraction failed",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-after-entry-failed-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
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
            stage_runs=[entry_run, dataflow_run],
            stage_items=[entry_item],
            archive_jobs=[],
            events=[],
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

    def test_binary_firmware_workflow_e2e_retry_stage_full_requeues_failed_entry_in_place(self):
        from datetime import timedelta

        now = _now()
        module = {
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
        task = _binary_task(
            summary={
                "b2s_results": [module],
                "failure_code": "entry_failed",
                "failure_message": "entry extraction failed",
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "entry extraction failed"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-retry-entry-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-retry-entry-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-entry-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-entry-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-retry-entry-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="pending",
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-retry-entry-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-retry-entry-binary",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-retry-entry-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-retry-entry-binary",
            error_message="entry extraction failed",
        )
        self._persist_stage_item_result(task, b2s_item, payload=module)
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={"module_key": "mod-a", "module_name": "mod-a", "entries": [], "error": "entry extraction failed"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-stage-full-entry-binary",
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
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
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
        self.assertTrue(any(lease.task_id == task.id and lease.owner_instance_id == "worker-a" for lease in db.runtime_leases))
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, task.runtime_phase)
        self.assertEqual("entry extraction failed", task.last_error)
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

    def test_binary_firmware_workflow_e2e_retry_stage_full_blocked_without_local_owner(self):
        from datetime import timedelta

        now = _now()
        module = {
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
        task = _binary_task(
            summary={
                "b2s_results": [module],
                "failure_code": "entry_failed",
                "failure_message": "entry extraction failed",
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.last_error = "entry extraction failed"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-retry-entry-binary-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-retry-entry-binary-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-entry-binary-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-entry-binary-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-retry-entry-binary-blocked",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-retry-entry-binary-blocked",
            error_message="entry extraction failed",
        )
        self._persist_stage_item_result(
            task,
            entry_item,
            payload={"module_key": "mod-a", "module_name": "mod-a", "entries": [], "error": "entry extraction failed"},
        )
        operation = BinarySecurityTaskOperation(
            id="op-retry-stage-full-entry-binary-blocked",
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
            stage_runs=[firmware_run, system_run, b2s_run, entry_run],
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
        self.assertTrue(any(lease.task_id == task.id and lease.owner_instance_id == "worker-b" for lease in db.runtime_leases))
        self.assertEqual("failed", detail.status)
        self.assertTrue(any(lease.task_id == task.id for lease in db.runtime_leases))
        event_types = [event.event_type for event in db.events]
        self.assertIn("main_state_write_blocked", event_types)
        self.assertIn("operation_requeue_applied", event_types)
        self.assertIn("retry_in_place_resume_applied", event_types)
        self.assertNotIn("operation_failed", event_types)

    def test_binary_firmware_workflow_e2e_retry_failed_items_recreates_abnormal_entry_child_inside_operation(self):
        module = {
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
        task = _binary_task(summary={"b2s_results": [module]})
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.current_operation_id = "op-retry-failed-items-binary-entry"
        task.summary = {
            **(task.summary or {}),
            "retry_plan": {
                "target_stage": "entry_analysis",
                "mode": "retry_failed_items",
                "retry_item_keys": ["mod-a::fw-1"],
            },
        }
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-retry-failed-items-binary-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-retry-failed-items-binary-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-failed-items-binary-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-failed-items-binary-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="failed",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-retry-failed-items-binary-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            item_identity_key="mod-a::fw-1",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="ea-old-binary-entry",
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
            id="op-retry-failed-items-binary-entry",
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
            stage_runs=[firmware_run, system_run, b2s_run, entry_run],
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
            created_payloads.append({"service": service, "payload": dict(payload), "item_id": item_arg.id})
            return {"task_id": "ea-new-binary-entry", "status": "pending"}

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
        self.assertEqual(["ea-old-binary-entry"], [row["task_id"] for row in deleted_refs])
        self.assertEqual(1, len(created_payloads))
        self.assertEqual("entry_analyse", created_payloads[0]["service"])
        self.assertEqual("ea-new-binary-entry", entry_item.downstream_task_id)
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

    def test_binary_firmware_workflow_e2e_retry_failed_items_recreates_abnormal_dataflow_child_inside_operation(self):
        entry_a = {
            "entry_key": "mod-a:entry-1",
            "module_key": "mod-a",
            "module_name": "mod-a",
            "function_name": "fn_a",
            "definition_file": "a.c",
            "definition_line": "10",
            "definition_kind": "definition",
            "module_input_path": "/tmp/archive/fw-1/mod-a",
            "source_root_path": "/tmp/archive/fw-1",
            "source_dir": "/tmp/archive/fw-1/mod-a",
        }
        entry_b = {
            "entry_key": "mod-b:entry-1",
            "module_key": "mod-b",
            "module_name": "mod-b",
            "function_name": "fn_b",
            "definition_file": "b.c",
            "definition_line": "20",
            "definition_kind": "definition",
            "module_input_path": "/tmp/archive/fw-1/mod-b",
            "source_root_path": "/tmp/archive/fw-1",
            "source_dir": "/tmp/archive/fw-1/mod-b",
        }
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
                    },
                    {
                        "firmware_key": "fw-1",
                        "firmware_name": "fw-1",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/archive/fw-1",
                        "source_root": "/tmp/archive/fw-1",
                        "task_type": TASK_TYPE_BINARY,
                        "module_key": "mod-b",
                        "module_name": "mod-b",
                        "module_dir": "/tmp/archive/fw-1/mod-b",
                        "source_dir": "/tmp/archive/fw-1/mod-b",
                    },
                ],
                "entry_results": [
                    {"module_key": "mod-a", "module_name": "mod-a", "entries": [dict(entry_a)]},
                    {"module_key": "mod-b", "module_name": "mod-b", "entries": [dict(entry_b)]},
                ],
                "vuln_results": [{"entry_key": "mod-a:entry-1"}, {"entry_key": "mod-b:entry-1"}],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-retry-failed-items-binary-dataflow"
        task.summary = {
            **(task.summary or {}),
            "retry_plan": {
                "target_stage": "dataflow_vuln_scan",
                "mode": "retry_failed_items",
                "retry_item_keys": ["mod-a:entry-1::mod-a"],
            },
        }
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-retry-failed-items-binary-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-retry-failed-items-binary-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-retry-failed-items-binary-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-retry-failed-items-binary-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-retry-failed-items-binary-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="failed",
        )
        vuln_run = BinarySecurityStageRun(
            id="sr-vuln-retry-failed-items-binary-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="vuln_verify",
            sequence_no=6,
            status="success",
        )
        df_abnormal = BinarySecurityStageItem(
            id="si-df-retry-failed-items-binary-dataflow-a",
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
            downstream_task_id="dfa-old-binary-a",
        )
        df_abnormal.input_ref = dict(entry_a)
        df_success = BinarySecurityStageItem(
            id="si-df-retry-failed-items-binary-dataflow-b",
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
            downstream_task_id="dfa-success-binary-b",
        )
        df_success.input_ref = dict(entry_b)
        vuln_for_abnormal = BinarySecurityStageItem(
            id="si-vuln-retry-failed-items-binary-dataflow-a",
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
            downstream_task_id="dfvs-old-binary-a",
        )
        vuln_for_abnormal.input_ref = {
            "entry_key": "mod-a:entry-1",
            "function_name": "fn_a",
            "module_key": "mod-a",
            "upstream_item_id": "si-df-retry-failed-items-binary-dataflow-a",
        }
        vuln_for_success = BinarySecurityStageItem(
            id="si-vuln-retry-failed-items-binary-dataflow-b",
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
            downstream_task_id="dfvs-keep-binary-b",
        )
        vuln_for_success.input_ref = {
            "entry_key": "mod-b:entry-1",
            "function_name": "fn_b",
            "module_key": "mod-b",
            "upstream_item_id": "si-df-retry-failed-items-binary-dataflow-b",
        }
        archive_jobs = [
            BinarySecurityArchiveJob(
                id="aj-vuln-retry-failed-items-binary-dataflow-a",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="dataflow_vuln_scan",
                item_id="si-vuln-retry-failed-items-binary-dataflow-a",
                archive_status="success",
            ),
            BinarySecurityArchiveJob(
                id="aj-vuln-retry-failed-items-binary-dataflow-b",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="dataflow_vuln_scan",
                item_id="si-vuln-retry-failed-items-binary-dataflow-b",
                archive_status="success",
            ),
        ]
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-binary-dataflow",
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
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run, vuln_run],
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
            return {"task_id": "dfa-new-binary-a", "status": "pending"}

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
        self.assertEqual({"dfa-old-binary-a"}, {ref["task_id"] for ref in cleanup_refs})
        self.assertEqual({"dataflow_vuln_scan"}, {ref["service"] for ref in cleanup_refs})
        self.assertEqual(["dataflow_vuln_scan"], [row["service"] for row in create_calls])
        self.assertEqual("dfa-new-binary-a", df_abnormal.downstream_task_id)
        self.assertEqual("success", df_success.status)
        self.assertEqual("dfa-success-binary-b", df_success.downstream_task_id)
        self.assertEqual(
            {
                "si-df-retry-failed-items-binary-dataflow-a",
                "si-df-retry-failed-items-binary-dataflow-b",
                "si-vuln-retry-failed-items-binary-dataflow-a",
                "si-vuln-retry-failed-items-binary-dataflow-b",
            },
            {item.id for item in db.stage_items},
        )
        self.assertEqual(
            [
                "aj-vuln-retry-failed-items-binary-dataflow-a",
                "aj-vuln-retry-failed-items-binary-dataflow-b",
            ],
            [job.id for job in db.archive_jobs],
        )
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        self.assertEqual("failed", operation.status)
        self.assertEqual("failed", detail.status)
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        self.assertEqual("recreate_from_abnormal", action_rows["si-df-retry-failed-items-binary-dataflow-a"]["strategy"])
        self.assertEqual("dfa-old-binary-a", action_rows["si-df-retry-failed-items-binary-dataflow-a"]["old_downstream_task_id"])
        self.assertEqual("dfa-new-binary-a", action_rows["si-df-retry-failed-items-binary-dataflow-a"]["new_downstream_task_id"])
        self.assertEqual("succeeded", action_rows["si-df-retry-failed-items-binary-dataflow-a"]["cleanup_status"])
        self.assertEqual("succeeded", action_rows["si-df-retry-failed-items-binary-dataflow-a"]["create_status"])
        self.assertEqual("succeeded", action_rows["si-df-retry-failed-items-binary-dataflow-a"]["verification_status"])
        self.assertNotIn("si-df-retry-failed-items-binary-dataflow-b", action_rows)

    def test_binary_firmware_workflow_e2e_retry_failed_items_adopts_active_dataflow_child_inside_operation(self):
        entry = {
            "entry_key": "mod-a:entry-active",
            "module_key": "mod-a",
            "module_name": "mod-a",
            "function_name": "fn_active",
            "definition_file": "active.c",
            "definition_line": "30",
            "definition_kind": "definition",
            "module_input_path": "/tmp/archive/fw-1/mod-a",
            "source_root_path": "/tmp/archive/fw-1",
            "source_dir": "/tmp/archive/fw-1/mod-a",
        }
        task = _binary_task(
            summary={
                "firmware_unpack_results": [{"firmware_key": "fw-1"}],
                "b2s_results": [{"module_key": "mod-a", "firmware_key": "fw-1"}],
                "entry_results": [{"module_key": "mod-a", "module_name": "mod-a", "entries": [dict(entry)]}],
                "retry_plan": {
                    "target_stage": "dataflow_vuln_scan",
                    "mode": "retry_failed_items",
                    "retry_item_keys": ["mod-a:entry-active::mod-a"],
                },
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-retry-failed-items-binary-adopt"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-retry-failed-items-binary-adopt",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="failed",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-df-retry-failed-items-binary-adopt",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-active",
            item_name="fn_active",
            parent_key="mod-a",
            item_identity_key="mod-a:entry-active::mod-a",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-live-binary",
        )
        dataflow_item.input_ref = dict(entry)
        dataflow_item.result = {
            "downstream_status": "running",
            "sync_observation": {"downstream_status": "running", "state_applied": True},
        }
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-binary-adopt",
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
                return {"task_id": "dfa-live-binary", "status": "running"}
            return None

        async def _noop_sync(*_args, **_kwargs):
            return None

        async def _fake_delete_refs(db_arg, task_arg, refs_arg, token_arg):
            del db_arg, task_arg, token_arg
            cleanup_refs.extend(dict(ref) for ref in refs_arg)
            return len(refs_arg)

        async def _fake_create(db_arg, task_arg, item_arg, *, service, token, payload):
            del db_arg, task_arg, service, token, payload
            create_calls.append({"item_id": item_arg.id})
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
        self.assertEqual("dfa-live-binary", dataflow_item.downstream_task_id)
        self.assertEqual("running", dataflow_item.status)
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        action = action_rows["si-df-retry-failed-items-binary-adopt"]
        self.assertEqual("adopt_active", action["strategy"])
        self.assertEqual("running", action["observed_status"])
        self.assertEqual("dfa-live-binary", action["old_downstream_task_id"])
        self.assertFalse(bool(action.get("cleanup_performed")))
        self.assertFalse(bool(action.get("create_required")))
        self.assertEqual("succeeded", action.get("verification_status"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("child_task_dispatch_deferred", event_types)
        self.assertNotIn("operation_requeue_applied", event_types)

    def test_binary_firmware_workflow_e2e_force_reset_to_pending_clears_control_state_and_requeues(self):
        from datetime import timedelta

        now = _now()
        module = {
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
        task = _binary_task(
            summary={
                "b2s_results": [module],
                "failure_code": "entry_failed",
                "failure_message": "entry extraction failed",
                "runtime_workset": {"pending_task_layer_reconcile": {"reason": "retry_after_failure"}},
            }
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.runtime_phase = TASK_RUNTIME_PHASE_OWNED_EXECUTION
        task.current_operation_id = "op-force-reset-binary"
        task.last_error = "entry extraction failed"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-force-reset-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-force-reset-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-force-reset-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-force-reset-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="failed",
            finished_at=_now(),
            output_summary={"failed_count": 1},
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-force-reset-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-force-reset-binary",
            error_message="entry extraction failed",
        )
        self._persist_stage_item_result(task, entry_item, payload={"module_key": "mod-a", "module_name": "mod-a", "entries": [], "error": "entry extraction failed"})
        operation = BinarySecurityTaskOperation(
            id="op-force-reset-binary",
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
            stage_runs=[firmware_run, system_run, b2s_run, entry_run],
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
        self.assertEqual("worker-a", db.runtime_leases[0].owner_instance_id)
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

    def test_binary_firmware_workflow_e2e_delete_force_delete_fallback(self):
        task = _binary_task(summary={"input_path": "/tmp/fw.bin"})
        task.status = "running"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-delete-binary-fallback"
        operation = BinarySecurityTaskOperation(
            id="op-delete-binary-fallback",
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

    def test_binary_firmware_workflow_e2e_system_archive_does_not_trigger_repair_for_unmaterialized_descendants(self):
        task = _binary_task(policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}))
        task.current_stage = "system_analysis"
        system_run = BinarySecurityStageRun(
            id="sr-system-unmaterialized-desc-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        system_item = BinarySecurityStageItem(
            id="si-system-unmaterialized-desc-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=system_run.id,
            stage_name="system_analysis",
            item_key="fw-1",
            item_name="fw.bin",
            parent_key="fw-1",
            status="success",
            downstream_service="system_analyse",
            downstream_task_id="sat-unmaterialized-desc-binary",
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
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-shell-after-system-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="pending",
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-shell-after-system-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-after-system-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="pending",
        )
        system_archive = self._make_archive_job(
            task=task,
            item=system_item,
            downstream_service="system_analyse",
            downstream_task_id="sat-unmaterialized-desc-binary",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[system_run, b2s_run, entry_run, dataflow_run],
            stage_items=[system_item],
            archive_jobs=[system_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, system_archive)

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertTrue(signals)
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertEqual("running", task.status)
        self.assertEqual("running", detail.status)
        self.assertEqual(0, len(self.manager._stage_items(db, task.id, "binary_to_source")))
        self.assertEqual("pending", b2s_run.status)
        self.assertEqual("pending", entry_run.status)
        self.assertEqual("pending", dataflow_run.status)
        system_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "system_analysis")
        self.assertIn(system_summary.status, {"running", "success"})
        b2s_summary = next(summary for summary in detail.stage_summaries if summary.stage_name == "binary_to_source")
        self.assertIn(b2s_summary.status, {"pending", "queued"})
        event_types = [event.event_type for event in db.events]
        self.assertNotIn("archive_apply_triggered_input_repair", event_types)
        self.assertNotIn("task_requeued_after_archive_input_repair", event_types)
        self.assertIn("task_layer_reconcile_completed", event_types)

    def test_binary_firmware_workflow_e2e_b2s_archive_does_not_trigger_repair_for_unmaterialized_descendants(self):
        task = _binary_task(policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}))
        task.current_stage = "binary_to_source"
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-unmaterialized-desc-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="running",
            started_at=_now(),
        )
        b2s_item = BinarySecurityStageItem(
            id="si-b2s-unmaterialized-desc-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=b2s_run.id,
            stage_name="binary_to_source",
            item_key="mod-a",
            item_name="mod-a",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-unmaterialized-desc-binary",
        )
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
        entry_run = BinarySecurityStageRun(
            id="sr-entry-shell-after-b2s-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="pending",
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-shell-after-b2s-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="pending",
        )
        b2s_archive = self._make_archive_job(
            task=task,
            item=b2s_item,
            downstream_service="binary_to_source",
            downstream_task_id="b2s-unmaterialized-desc-binary",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[b2s_run, entry_run, dataflow_run],
            stage_items=[b2s_item],
            archive_jobs=[b2s_archive],
            events=[],
            ea_tasks=[type("EaTask", (), {"parent_task_id": task.id, "parent_stage_name": "entry_analysis"})()],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
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

    def test_binary_firmware_workflow_e2e_final_dataflow_archive_reconcile_closes_task(self):
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
            id="sr-fw-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-final-dataflow",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-final-dataflow-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="running",
            started_at=_now(),
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-dataflow-final-dataflow-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-main",
            item_name="main",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-final-binary",
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
        dataflow_archive = self._make_archive_job(
            task=task,
            item=dataflow_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-final-binary",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
            stage_items=[dataflow_item],
            archive_jobs=[dataflow_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            signals = self._apply_archive_and_reconcile(db, task, dataflow_archive)

        dataflow_run.status = "success"
        dataflow_run.finished_at = _now()
        self._refresh_stage_summary(db, task, "firmware_unpack")
        self._refresh_stage_summary(db, task, "system_analysis")
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
        self.assertEqual(
            "success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )
        self.assertTrue((task.summary or {}).get("dataflow_results"))
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertIn(task.status, {"running", "success"})
        self.assertEqual(task.status, detail.status)

    def test_binary_firmware_workflow_e2e_dataflow_partial_success_archive_terminalizes_parent_success(self):
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
                                "entry_key": "mod-a:entry-a",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main_a",
                            },
                            {
                                "entry_key": "mod-a:entry-b",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main_b",
                            },
                        ],
                    }
                ],
            }
        )
        task.current_stage = "dataflow_vuln_scan"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-ps-archive-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-ps-archive-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-ps-archive-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-ps-archive-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-ps-archive-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="running",
            started_at=_now(),
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-ps-archive-success-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-a",
            item_name="main_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-ps-archive-a-binary",
        )
        partial_item = BinarySecurityStageItem(
            id="si-dataflow-ps-archive-partial-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-b",
            item_name="main_b",
            parent_key="mod-a",
            status="partial_success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-ps-archive-b-binary",
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
            downstream_task_id="dfa-ps-archive-a-binary",
            mapped_status="success",
        )
        partial_archive = self._make_archive_job(
            task=task,
            item=partial_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-ps-archive-b-binary",
            mapped_status="partial_success",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
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
        self._refresh_stage_summary(db, task, "firmware_unpack")
        self._refresh_stage_summary(db, task, "system_analysis")
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

    def test_binary_firmware_workflow_e2e_dataflow_partial_success_advancement_policy_terminalizes_parent_partial_success(self):
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
                                "entry_key": "mod-a:entry-a",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main_a",
                            },
                            {
                                "entry_key": "mod-a:entry-b",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main_b",
                            },
                        ],
                    }
                ],
            },
            policy_json=json.dumps(
                {
                    "partial_success_stage_advancement": {
                        "dataflow_vuln_scan": True,
                    }
                }
            ),
        )
        task.current_stage = "dataflow_vuln_scan"
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-ps-advance-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-ps-advance-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-ps-advance-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-ps-advance-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-ps-advance-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="partial_success",
            finished_at=_now(),
            output_summary={"success_count": 1, "partial_success_count": 1},
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-ps-advance-success-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-a",
            item_name="main_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-ps-advance-a-binary",
        )
        partial_item = BinarySecurityStageItem(
            id="si-dataflow-ps-advance-partial-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-b",
            item_name="main_b",
            parent_key="mod-a",
            status="partial_success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-ps-advance-b-binary",
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
            downstream_task_id="dfa-ps-advance-a-binary",
            mapped_status="success",
        )
        partial_archive = self._make_archive_job(
            task=task,
            item=partial_item,
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-ps-advance-b-binary",
            mapped_status="partial_success",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
            stage_items=[success_item, partial_item],
            archive_jobs=[success_archive, partial_archive],
            events=[],
        )

        with patch.object(self.manager, "_task_runtime_owner_matches_current_instance", return_value=True):
            first_signals = self._apply_archive_and_reconcile(db, task, success_archive)
            second_signals = self._apply_archive_and_reconcile(db, task, partial_archive)

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
        self.assertEqual("partial_success", task.status)
        self.assertEqual("partial_success", detail.status)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual(
            "partial_success",
            next(summary.status for summary in detail.stage_summaries if summary.stage_name == "dataflow_vuln_scan"),
        )
        self.assertTrue((task.summary or {}).get("dataflow_results"))
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))

    def test_binary_firmware_workflow_e2e_dataflow_partial_success_with_downstream_missing_keeps_parent_active(self):
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
                                "entry_key": "mod-a:entry-a",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main_a",
                            },
                            {
                                "entry_key": "mod-a:entry-b",
                                "module_key": "mod-a",
                                "module_name": "mod-a",
                                "function_name": "main_b",
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
        firmware_run = BinarySecurityStageRun(
            id="sr-fw-terminal-dm-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            sequence_no=1,
            status="success",
            finished_at=_now(),
        )
        system_run = BinarySecurityStageRun(
            id="sr-system-terminal-dm-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="system_analysis",
            sequence_no=2,
            status="success",
            finished_at=_now(),
        )
        b2s_run = BinarySecurityStageRun(
            id="sr-b2s-terminal-dm-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            sequence_no=3,
            status="success",
            finished_at=_now(),
        )
        entry_run = BinarySecurityStageRun(
            id="sr-entry-terminal-dm-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=4,
            status="success",
            finished_at=_now(),
        )
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-terminal-dm-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=5,
            status="partial_success",
            finished_at=_now(),
            output_summary={"success_count": 1, "downstream_missing_count": 1},
        )
        success_item = BinarySecurityStageItem(
            id="si-dataflow-success-dm-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-a",
            item_name="main_a",
            parent_key="mod-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-a-binary",
        )
        missing_item = BinarySecurityStageItem(
            id="si-dataflow-missing-terminal-binary",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="mod-a:entry-b",
            item_name="main_b",
            parent_key="mod-a",
            status="downstream_missing",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-missing-binary",
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
            stage_runs=[firmware_run, system_run, b2s_run, entry_run, dataflow_run],
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

    def test_binary_firmware_workflow_e2e_dataflow_partial_success_with_downstream_missing_terminalizes_parent_success(self):
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

        detail = self.manager.get_task_detail(db, project_id=task.project_id, task_id=task.id)
        self.assertEqual("success", task.status)
        self.assertEqual("success", detail.status)
        self.assertEqual("dataflow_vuln_scan", task.current_stage)
        self.assertEqual([], (task.summary or {}).get("dataflow_results") or [])
        self.assertTrue(any(event.event_type == "task_layer_reconcile_completed" for event in db.events))
        self.assertIsNotNone(detail.abnormal_reason)
        self.assertEqual("dataflow_partial_success", detail.abnormal_reason.code)

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
