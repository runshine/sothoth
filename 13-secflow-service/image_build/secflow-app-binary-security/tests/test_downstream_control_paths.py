import asyncio
import re
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service import downstream_tasks as downstream_tasks_module
from app.service import task_manager as task_manager_module
from app.service.task_manager import ConflictError, NotFoundError, TaskManager, UpstreamError, ValidationError
from test_task_manager import (
    _AppendingModelAwareDb,
    _AsyncDataflowVulnScanClientStub,
    _AsyncEntryAnalyseClientStub,
    _ModelAwareDb,
)


class DownstreamControlPathTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_manual_cancel_collects_dispatching_and_orphan_downstream_refs(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_key="m1",
            status="dispatching",
            downstream_service="system_analyse",
            downstream_task_id="sat_1",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item])
        calls: list[dict[str, object]] = []

        async def fake_write_task_metadata_async(*args, **kwargs):
            return None

        async def fake_request_local_worker_cancel(task_id: str, *, wait_for_runner: bool):
            self.assertEqual("t1", task_id)
            self.assertFalse(wait_for_runner)

        async def fake_cancel_downstream_refs(db_arg, task_arg, refs_arg, token_arg):
            calls.append(
                {
                    "db": db_arg,
                    "task_id": task_arg.id,
                    "refs": list(refs_arg),
                    "token": token_arg,
                }
            )
            return len(refs_arg)

        original_discover = self.manager._discover_parent_linked_downstream_refs
        self.manager._write_task_metadata_async = fake_write_task_metadata_async
        self.manager._request_local_worker_cancel = fake_request_local_worker_cancel
        self.manager._cancel_downstream_refs = fake_cancel_downstream_refs
        self.manager._discover_parent_linked_downstream_refs = lambda _db, _task: [
            {"service": "dataflow_vuln_scan", "task_id": "dfa_orphan", "project_id": "p1", "stage_name": "dataflow_vuln_scan"},
        ]
        try:
            asyncio.run(self.manager._prepare_cancel_task(db, task))
        finally:
            self.manager._discover_parent_linked_downstream_refs = original_discover

        self.assertEqual("cancelling", task.status)
        self.assertEqual("cancelled", item.status)
        self.assertEqual(1, len(calls))
        self.assertEqual(["sat_1"], [ref["task_id"] for ref in calls[0]["refs"]])

    def test_manual_cancel_noop_retries_orphan_downstream_cancel(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="cancelled",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_key="m1",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat_1",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item], state_events=[])
        calls: list[dict[str, object]] = []

        async def fake_cancel_downstream_refs(db_arg, task_arg, refs_arg, token_arg):
            calls.append(
                {
                    "db": db_arg,
                    "task_id": task_arg.id,
                    "refs": list(refs_arg),
                    "token": token_arg,
                }
            )
            return len(refs_arg)

        original_discover = self.manager._discover_parent_linked_downstream_refs
        self.manager._cancel_downstream_refs = fake_cancel_downstream_refs
        self.manager._discover_parent_linked_downstream_refs = lambda _db, _task: [
            {"service": "dataflow_vuln_scan", "task_id": "dfa_orphan", "project_id": "p1", "stage_name": "dataflow_vuln_scan"},
        ]
        try:
            asyncio.run(self.manager._prepare_cancel_task(db, task))
        finally:
            self.manager._discover_parent_linked_downstream_refs = original_discover

        self.assertEqual("cancelled", item.status)
        self.assertEqual(1, len(calls))
        self.assertEqual(["sat_1"], [ref["task_id"] for ref in calls[0]["refs"]])

    def test_delete_downstream_refs_treats_entry_delete_500_with_absent_task_as_success(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="eat_x",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub(delete_result=UpstreamError("500 Internal Server Error"))

        async def _missing_task(task_id, token):
            del task_id, token
            raise NotFoundError("任务不存在")

        client.get_task = _missing_task

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            deleted = asyncio.run(
                self.manager._delete_downstream_refs(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat_x", "stage_name": "entry_analysis"}],
                    "token",
                )
            )

        self.assertEqual(1, deleted)
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("child_task_delete_requested", event_types)
        self.assertIn("child_task_delete_verified_absent", event_types)
        self.assertIn("child_task_delete_failed_but_ignored", event_types)
        self.assertIn("child_task_delete_result_recorded", event_types)

    def test_delete_downstream_refs_blocks_when_entry_delete_500_and_task_still_exists(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="eat_x",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub(delete_result=UpstreamError("500 Internal Server Error"))

        async def _existing_task(task_id, token):
            del token
            return {"task_id": task_id, "status": "cancelled"}

        client.get_task = _existing_task

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            deleted = asyncio.run(
                self.manager._delete_downstream_refs(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat_x", "stage_name": "entry_analysis"}],
                    "token",
                )
            )
        self.assertEqual(1, deleted)
        cleanup_results = list(getattr(self.manager, "_last_downstream_cleanup_results", []) or [])
        self.assertEqual(1, len(cleanup_results))
        self.assertEqual("failed", cleanup_results[0]["verify_status"])
        self.assertEqual("terminal_error_state", cleanup_results[0]["ignored_reason"])
        self.assertFalse(cleanup_results[0]["blocking"])
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("child_task_delete_failed_but_ignored", event_types)

    def test_delete_downstream_refs_blocks_when_entry_delete_conflict_and_task_active(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat_x",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub(delete_result=ConflictError("任务正在运行，请先取消后再删除"))

        async def _active_task(task_id, token):
            del token
            return {"task_id": task_id, "status": "running"}

        client.get_task = _active_task

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            with self.assertRaises(ValidationError):
                asyncio.run(
                    self.manager._delete_downstream_refs(
                        db,
                        task,
                        [{"service": "entry_analyse", "task_id": "eat_x", "stage_name": "entry_analysis"}],
                        "token",
                    )
                )
        cleanup_results = list(getattr(self.manager, "_last_downstream_cleanup_results", []) or [])
        self.assertEqual(1, len(cleanup_results))
        self.assertEqual("conflict", cleanup_results[0]["delete_status"])
        self.assertEqual("failed", cleanup_results[0]["verify_status"])
        self.assertTrue(cleanup_results[0]["blocking"])

    def test_delete_downstream_refs_forwards_best_effort_and_cleanup_scope(self):
        task = BinarySecurityTask(
            id="t-forward-delete",
            project_id="p1",
            name="binary",
            status="cancelled",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        db = _AppendingModelAwareDb(tasks=[task], events=[])

        async def _run():
            with patch.object(
                self.manager,
                "_downstream_delete_refs",
                AsyncMock(return_value=1),
            ) as delete_mock:
                deleted = await self.manager._delete_downstream_refs(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat_x", "stage_name": "entry_analysis"}],
                    "token",
                    force_delete=True,
                    best_effort=True,
                    cleanup_scope="delete",
                )
                self.assertEqual(1, deleted)
                self.assertTrue(delete_mock.await_args.kwargs.get("force_delete"))
                self.assertTrue(delete_mock.await_args.kwargs.get("best_effort"))
                self.assertEqual("delete", delete_mock.await_args.kwargs.get("cleanup_scope"))

        asyncio.run(_run())

    def test_delete_downstream_refs_records_result_event_for_success(self):
        task = BinarySecurityTask(
            id="t-delete-success",
            project_id="p1",
            name="binary",
            status="cancelled",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        item = BinarySecurityStageItem(
            id="si-delete-success",
            task_id="t-delete-success",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="entry-1",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="eat-success",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub(delete_result={"success": True})

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            deleted = asyncio.run(
                self.manager._delete_downstream_refs(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat-success", "stage_name": "entry_analysis"}],
                    "token",
                )
            )

        self.assertEqual(1, deleted)
        result_events = [event for event in db.added if getattr(event, "event_type", "") == "child_task_delete_result_recorded"]
        self.assertGreaterEqual(len(result_events), 1)
        self.assertIn("succeeded", [dict(event.payload or {}).get("result_outcome") for event in result_events])

    def test_delete_downstream_refs_records_result_event_for_best_effort_cleanup(self):
        task = BinarySecurityTask(
            id="t-delete-best-effort",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        item = BinarySecurityStageItem(
            id="si-delete-best-effort",
            task_id="t-delete-best-effort",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="entry-1",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-best-effort",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])

        async def _run():
            with patch.object(
                self.manager,
                "_run_with_limits",
                AsyncMock(
                    return_value=[
                        (
                            {"service": "entry_analyse", "task_id": "eat-best-effort", "stage_name": "entry_analysis", "project_id": "p1"},
                            None,
                            TimeoutError("delete timeout"),
                        )
                    ]
                ),
            ):
                return await self.manager._delete_downstream_refs(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat-best-effort", "stage_name": "entry_analysis"}],
                    "token",
                    cleanup_scope="task_delete",
                )

        deleted = asyncio.run(_run())

        self.assertEqual(1, deleted)
        result_events = [event for event in db.added if getattr(event, "event_type", "") == "child_task_delete_result_recorded"]
        self.assertGreaterEqual(len(result_events), 1)
        payloads = [dict(event.payload or {}) for event in result_events]
        matched = [payload for payload in payloads if payload.get("result_outcome") == "deferred_best_effort"]
        self.assertTrue(matched)
        self.assertTrue(matched[0].get("deferred"))
        self.assertFalse(matched[0].get("blocking"))

    def test_delete_operation_payload_root_externalizes_under_workspace(self):
        operation = BinarySecurityTaskOperation(
            id="op-delete-payload",
            task_id="t-delete-payload",
            project_id="p1",
            operation_type="delete",
            status="running",
        )

        payload_root = self.manager._operation_payload_root(
            operation,
            workspace_root="/tmp/ws-delete-payload",
        )

        self.assertEqual(
            Path("/tmp/ws-delete-payload/run/task-operations/op-delete-payload"),
            payload_root,
        )

    def test_task_manager_does_not_access_downstream_clients_directly(self):
        source = Path(task_manager_module.__file__).read_text(encoding="utf-8")
        forbidden = re.findall(
            r"get_(?:firmware_unpacker|system_analyse|binary_to_source|entry_analyse|dataflow_vuln_scan|dataflow_vuln_scan)_client\(",
            source,
        )
        self.assertEqual([], forbidden)

    def test_downstream_controller_query_does_not_write_timeline(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="source")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub(fetched={"eat-1": {"task_id": "eat-1", "status": "passed"}})

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            payload = asyncio.run(self.manager._downstream_fetch_item_payload(task, item, "token"))

        self.assertEqual("eat-1", payload["task_id"])
        self.assertEqual([], db.added)

    def test_downstream_controller_retry_records_child_task_event(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="source")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            status="failed",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])

        controller = self.manager._downstream_tasks()

        async def fake_invoke_retry_or_restart(**kwargs):
            del kwargs
            return {"task_id": "eat-1", "status": "queued"}

        with patch.object(controller, "fetch_child_payload", new=AsyncMock(side_effect=NotFoundError("missing"))), patch.object(
            controller,
            "invoke_retry_or_restart",
            side_effect=fake_invoke_retry_or_restart,
        ):
            control = asyncio.run(
                controller.control_existing_child(
                    db,
                    stage_name="entry_analysis",
                    task=task,
                    item=item,
                    token="token",
                )
            )

        self.assertEqual("accepted", control["outcome"])
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("child_task_retry_requested", event_types)
        self.assertIn("child_task_retry_accepted", event_types)

    def test_downstream_controller_adopts_active_child_without_retry_request_event(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="source")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            status="failed",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        controller = self.manager._downstream_tasks()

        with patch.object(
            controller,
            "fetch_child_payload",
            new=AsyncMock(return_value={"task_id": "eat-1", "status": "running"}),
        ), patch.object(
            controller,
            "invoke_retry_or_restart",
            new=AsyncMock(side_effect=AssertionError("should not invoke retry_or_restart for active child")),
        ):
            control = asyncio.run(
                controller.control_existing_child(
                    db,
                    stage_name="entry_analysis",
                    task=task,
                    item=item,
                    token="token",
                )
            )

        self.assertEqual("already_running", control["outcome"])
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertNotIn("child_task_retry_requested", event_types)
        self.assertIn("child_observation_observed", event_types)

    def test_downstream_controller_control_existing_child_treats_dispatching_post_retry_check_as_already_running(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="source")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            status="failed",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        controller = self.manager._downstream_tasks()

        with patch.object(
            controller,
            "invoke_retry_or_restart",
            new=AsyncMock(side_effect=ValidationError("retry not supported")),
        ), patch.object(
            controller,
            "fetch_child_payload",
            new=AsyncMock(
                side_effect=[
                    {"task_id": "eat-1", "status": "failed"},
                    {"task_id": "eat-1", "status": "dispatching"},
                ]
            ),
        ):
            control = asyncio.run(
                controller.control_existing_child(
                    db,
                    stage_name="entry_analysis",
                    task=task,
                    item=item,
                    token="token",
                )
            )

        self.assertEqual("already_running", control["outcome"])
        self.assertEqual("invalid_transition", control["retry_outcome"])

    def test_wait_child_refs_inactive_treats_cancelling_child_as_still_active(self):
        controller = self.manager._downstream_tasks()
        self.manager.cfg.scheduler.downstream_request_timeout_seconds = 1
        self.manager.cfg.scheduler.stage_poll_interval_seconds = 0
        refs = [{"service": "entry_analyse", "project_id": "p1", "task_id": "eat-1"}]
        clock = {"value": task_manager_module._now()}

        def _fake_now_local():
            current = clock["value"]
            clock["value"] = current + timedelta(seconds=2)
            return current

        with patch.object(
            controller,
            "fetch_child_ref_payload",
            new=AsyncMock(return_value={"task_id": "eat-1", "status": "cancelling"}),
        ), patch("app.service.downstream_tasks.asyncio.sleep", new=AsyncMock(return_value=None)), patch(
            "app.service.downstream_tasks.now_local",
            side_effect=_fake_now_local,
        ):
            with self.assertRaisesRegex(ValidationError, "仍在运行"):
                asyncio.run(controller.wait_child_refs_inactive(refs, "token"))

    def test_downstream_controller_cancel_records_child_task_events(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="source")
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            status="running",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub()

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            cancelled = asyncio.run(
                self.manager._downstream_cancel_refs(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat-1", "stage_name": "entry_analysis"}],
                    "token",
                )
            )

        self.assertEqual(1, cancelled)
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("child_task_cancel_requested", event_types)
        self.assertIn("child_task_cancel_succeeded", event_types)

    def test_downstream_controller_delete_blocking_failure_records_event(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="IPSEC",
            status="cancelled",
            downstream_service="entry_analyse",
            downstream_task_id="eat_x",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub(delete_result=UpstreamError("500 Internal Server Error"))

        async def _existing_task(task_id, token=None):
            del token
            return {"task_id": task_id, "status": "cancelled"}

        client.get_task = _existing_task

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            deleted = asyncio.run(
                self.manager._downstream_delete_refs(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat_x", "stage_name": "entry_analysis"}],
                    "token",
                )
            )

        self.assertEqual(1, deleted)
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("child_task_delete_requested", event_types)
        self.assertIn("child_task_delete_failed_but_ignored", event_types)

    def test_downstream_controller_inactive_check_records_child_task_events(self):
        task = BinarySecurityTask(
            id="t-inactive",
            project_id="p1",
            name="binary",
            status="failed",
            current_operation_id="op-inactive",
        )
        item = BinarySecurityStageItem(
            id="si-inactive",
            task_id="t-inactive",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="module-1",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            status="failed",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncEntryAnalyseClientStub(fetched={"eat-1": {"task_id": "eat-1", "status": "failed"}})

        with patch.object(downstream_tasks_module, "get_entry_analyse_client", return_value=client):
            asyncio.run(
                self.manager._ensure_downstream_refs_inactive(
                    db,
                    task,
                    [{"service": "entry_analyse", "task_id": "eat-1", "project_id": "p1", "stage_name": "entry_analysis"}],
                    "token",
                )
            )

        inactive_events = [
            event
            for event in db.added
            if getattr(event, "event_type", "") in {"child_task_inactive_check_requested", "child_task_inactive_check_succeeded"}
        ]
        self.assertEqual(2, len(inactive_events))
        self.assertTrue(all(getattr(event, "operation_id", None) == "op-inactive" for event in inactive_events))

    def test_downstream_controller_delete_treats_dfa_delete_500_with_absent_task_as_success(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="t1",
            project_id="p1",
            stage_name="dataflow_vuln_scan",
            item_key="IPSEC",
            status="cancelled",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa_x",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        client = _AsyncDataflowVulnScanClientStub(delete_result=UpstreamError("500 Internal Server Error"))

        async def _missing_task(task_id):
            del task_id
            raise NotFoundError("任务不存在")

        client.get_task = _missing_task

        with patch.object(downstream_tasks_module, "get_dataflow_vuln_scan_client", return_value=client):
            deleted = asyncio.run(
                self.manager._downstream_delete_refs(
                    db,
                    task,
                    [{"service": "dataflow_vuln_scan", "task_id": "dfa_x", "project_id": "p1", "stage_name": "dataflow_vuln_scan"}],
                    "token",
                )
            )

        self.assertEqual(1, deleted)
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("child_task_delete_verified_absent", event_types)
        self.assertIn("child_task_delete_failed_but_ignored", event_types)
