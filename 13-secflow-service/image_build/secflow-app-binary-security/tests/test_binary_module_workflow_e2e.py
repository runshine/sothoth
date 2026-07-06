import asyncio
import json
import unittest

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTaskOperation,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from tests.test_source_vuln_workflow_e2e import _AppendingModelAwareDb, _ModelAwareDb, _binary_module_task

from tests.test_source_vuln_workflow_e2e import _BINARY_MODULE_E2E_EXPORTS


class BinaryModuleWorkflowE2ETests(unittest.TestCase):
    """Dedicated binary_module workflow E2E coverage."""

    def test_binary_module_workflow_e2e_cancel_running_entry_analysis_cancels_module_child_and_runner(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.status = "running"
        task.current_stage = "entry_analysis"
        entry_run = BinarySecurityStageRun(
            id="sr-entry-cancel-binary-module-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
            started_at=_now(),
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-cancel-binary-module-e2e",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="IPSEC",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="ea-cancel-binary-module-e2e",
        )
        entry_item.input_ref = self._binary_module_descriptor()
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
        self.assertEqual(["ea-cancel-binary-module-e2e"], cancelled_children)
        self.assertEqual([(task.id, False)], local_cancel_requests)
        self.assertTrue(cancelled_ref_batches)
        self.assertEqual("cancelling", detail.status)
        self.assertTrue(any(event.event_type == "task_cancelling" for event in db.events))

    def test_binary_module_workflow_e2e_delete_force_delete_fallback(self):
        task = _binary_module_task(summary={"b2s_results": [self._binary_module_descriptor()]})
        task.status = "running"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-delete-binary-module-fallback"
        operation = BinarySecurityTaskOperation(
            id="op-delete-binary-module-fallback",
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

    def test_binary_module_workflow_e2e_retry_failed_items_archive_only_failure_upgrades_to_archive_retry(self):
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [
                    {
                        "module_key": "IPSEC",
                        "module_name": "IPSEC",
                        "entries": [{"entry_key": "IPSEC:entry", "function_name": "ipsec_entry", "module_key": "IPSEC"}],
                    }
                ],
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "entry_analysis"
        task.finished_at = _now()
        entry_run = BinarySecurityStageRun(
            id="sr-entry-binary-module-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
            last_error="总任务产物归档失败",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-binary-module-archive-only-retry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=entry_run.id,
            stage_name="entry_analysis",
            item_key="IPSEC",
            item_name="IPSEC",
            parent_key="module-input",
            item_identity_key="IPSEC::module-input",
            status="failed",
            downstream_service="entry_analyse",
            downstream_task_id="ea-success-binary-module",
            error_message="总任务产物归档失败",
        )
        entry_item.result = {
            "last_sync_result": "downstream_archive_failed_manual_intervention",
            "sync_observation": {
                "last_result": "downstream_archive_failed_manual_intervention",
            },
        }
        archive_job = BinarySecurityArchiveJob(
            id="aj-entry-binary-module-archive-only-retry",
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
            "downstream_payload": {"task_id": "ea-success-binary-module", "status": "success"},
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

    def test_binary_module_workflow_e2e_retry_failed_items_adopts_active_dataflow_child_inside_operation(self):
        entry = {
            "entry_key": "IPSEC:entry-active",
            "module_key": "IPSEC",
            "module_name": "IPSEC",
            "function_name": "ipsec_entry_active",
            "definition_file": "ipsec.c",
            "definition_line": "30",
            "definition_kind": "definition",
            "module_input_path": "/mock/archive/IPSEC",
            "source_root_path": "/mock/archive/IPSEC",
            "source_dir": "/mock/archive/IPSEC",
        }
        task = _binary_module_task(
            summary={
                "b2s_results": [self._binary_module_descriptor()],
                "entry_results": [{"module_key": "IPSEC", "module_name": "IPSEC", "entries": [dict(entry)]}],
                "retry_plan": {
                    "target_stage": "dataflow_vuln_scan",
                    "mode": "retry_failed_items",
                    "retry_item_keys": ["IPSEC:entry-active::IPSEC"],
                },
            },
            policy_json=json.dumps({"pipeline_mode": "mixed_streaming"}),
        )
        task.status = "failed"
        task.current_stage = "dataflow_vuln_scan"
        task.current_operation_id = "op-retry-failed-items-binary-module-adopt"
        dataflow_run = BinarySecurityStageRun(
            id="sr-dataflow-retry-failed-items-binary-module-adopt",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=3,
            status="failed",
        )
        dataflow_item = BinarySecurityStageItem(
            id="si-df-retry-failed-items-binary-module-adopt",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=dataflow_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC:entry-active",
            item_name="ipsec_entry_active",
            parent_key="IPSEC",
            item_identity_key="IPSEC:entry-active::IPSEC",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-live-binary-module",
        )
        dataflow_item.input_ref = dict(entry)
        dataflow_item.result = {
            "downstream_status": "running",
            "sync_observation": {"downstream_status": "running", "state_applied": True},
        }
        operation = BinarySecurityTaskOperation(
            id="op-retry-failed-items-binary-module-adopt",
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
                return {"task_id": "dfa-live-binary-module", "status": "running"}
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
        self.assertEqual("dfa-live-binary-module", dataflow_item.downstream_task_id)
        self.assertEqual("running", dataflow_item.status)
        self.assertEqual("operation_succeeded", dict(operation.resume_cursor or {}).get("current_step"))
        action_rows = {row["item_id"]: row for row in list((operation.result_payload or {}).get("item_actions") or [])}
        action = action_rows["si-df-retry-failed-items-binary-module-adopt"]
        self.assertEqual("adopt_active", action["strategy"])
        self.assertEqual("running", action["observed_status"])
        self.assertEqual("dfa-live-binary-module", action["old_downstream_task_id"])
        self.assertFalse(bool(action.get("cleanup_performed")))
        self.assertFalse(bool(action.get("create_required")))
        self.assertEqual("succeeded", action.get("verification_status"))
        event_types = [event.event_type for event in db.events]
        self.assertIn("child_task_dispatch_deferred", event_types)
        self.assertNotIn("operation_requeue_applied", event_types)


for _binary_module_e2e_name, _binary_module_e2e_func in _BINARY_MODULE_E2E_EXPORTS.items():
    _binary_module_e2e_func.__module__ = __name__
    setattr(BinaryModuleWorkflowE2ETests, _binary_module_e2e_name, _binary_module_e2e_func)
