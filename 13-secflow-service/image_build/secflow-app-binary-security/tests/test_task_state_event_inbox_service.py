import unittest
from unittest.mock import AsyncMock, patch

from app.model import BinarySecurityArchiveJob, BinarySecurityStateEvent, BinarySecurityTask
from app.service.task.state_event_inbox import TaskStateEventInboxServiceMixin
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskStateEventInboxServiceStructureTests(unittest.TestCase):
    def test_task_manager_state_event_inbox_methods_are_bound_to_mixin(self):
        self.assertIs(TaskManager._apply_stage_worker_start_requested_locked, TaskStateEventInboxServiceMixin._apply_stage_worker_start_requested_locked)
        self.assertIs(TaskManager._state_event_inbox_loop, TaskStateEventInboxServiceMixin._state_event_inbox_loop)
        self.assertIs(TaskManager._state_event_inbox_metrics_loop, TaskStateEventInboxServiceMixin._state_event_inbox_metrics_loop)
        self.assertIs(TaskManager._publish_state_event_inbox_metrics_snapshot, TaskStateEventInboxServiceMixin._publish_state_event_inbox_metrics_snapshot)
        self.assertIs(TaskManager._observe_state_runtime_metrics, TaskStateEventInboxServiceMixin._observe_state_runtime_metrics)
        self.assertIs(TaskManager._claim_state_event, TaskStateEventInboxServiceMixin._claim_state_event)
        self.assertIs(TaskManager._acquire_task_state_lease, TaskStateEventInboxServiceMixin._acquire_task_state_lease)
        self.assertIs(TaskManager._release_task_state_lease, TaskStateEventInboxServiceMixin._release_task_state_lease)
        self.assertIs(TaskManager._reduce_state_event, TaskStateEventInboxServiceMixin._reduce_state_event)
        self.assertIs(TaskManager._repair_retryable_state_events, TaskStateEventInboxServiceMixin._repair_retryable_state_events)


class TaskStateEventInboxServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_apply_stage_worker_start_requested_locked_updates_stage_fact_and_requests_reconcile(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="pending",
            current_stage="binary_to_source",
            task_type="binary",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
        )
        event = BinarySecurityStateEvent(
            id="evt-1",
            task_id=task.id,
            project_id=task.project_id,
            event_type="stage_worker_start_requested",
            stage_name="entry_analysis",
            payload={"stage_name": "entry_analysis"},
        )
        db = _ModelAwareDb(tasks=[task], state_events=[event], stage_runs=[], events=[])

        queued = []
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        try:
            with patch.object(self.manager, "_task_runtime_transition_guard_active", return_value=False):
                self.manager._apply_stage_worker_start_requested_locked(db, event)
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("pending", task.status)
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertEqual(0, len(db.stage_runs))
        event_types = [row.event_type for row in db.events]
        self.assertNotIn("stage_started", event_types)
        self.assertIn("main_state_write_blocked", event_types)
        self.assertIn("owned_execution_takeover_requeued", event_types)
        self.assertIn("pending_task_layer_reconcile", ((task.summary or {}).get("runtime_workset") or {}))
        takeover_event = next(row for row in db.events if row.event_type == "owned_execution_takeover_requeued")
        self.assertEqual("request_task_layer_reconcile", (takeover_event.payload or {}).get("takeover_action"))
        self.assertEqual(["task-1"], queued)

    def test_apply_stage_worker_start_requested_locked_suppresses_blocked_and_takeover_during_guard(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="pending",
            current_stage="binary_to_source",
            task_type="binary",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
            summary={
                "runtime_transition_guard": {
                    "guard_id": "guard-1",
                    "owner_instance_id": "worker-1",
                    "from_stage": "binary_to_source",
                    "to_stage": "entry_analysis",
                    "reason": "dispatch_startup_window",
                    "created_at": "2026-06-22T19:13:00+00:00",
                    "expires_at": "2099-06-22T19:13:30+00:00",
                }
            },
        )
        event = BinarySecurityStateEvent(
            id="evt-1",
            task_id=task.id,
            project_id=task.project_id,
            event_type="stage_worker_start_requested",
            stage_name="entry_analysis",
            payload={"stage_name": "entry_analysis"},
        )
        db = _ModelAwareDb(tasks=[task], state_events=[event], stage_runs=[], events=[])

        queued = []
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        try:
            with (
                patch.object(self.manager, "_task_runtime_transition_guard_active", return_value=True),
                patch.object(self.manager, "_task_runtime_transition_guard", return_value={"guard_id": "guard-1"}),
            ):
                self.manager._apply_stage_worker_start_requested_locked(db, event)
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertEqual(0, len(db.stage_runs))
        event_types = [row.event_type for row in db.events]
        self.assertIn("stage_worker_start_observed_during_guard", event_types)
        self.assertNotIn("main_state_write_blocked", event_types)
        self.assertNotIn("owned_execution_takeover_requeued", event_types)
        self.assertEqual([], queued)

    def test_task_execution_failed_locked_records_fact_and_requests_reconcile(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="entry_analysis",
            task_type="binary",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
        )
        event = BinarySecurityStateEvent(
            id="evt-fail",
            task_id=task.id,
            project_id=task.project_id,
            event_type="task_execution_failed",
            payload={"error": "boom"},
        )
        db = _ModelAwareDb(tasks=[task], state_events=[event], events=[])

        queued = []
        original_enqueue = self.manager._enqueue_task
        original_write = self.manager._write_task_metadata_async
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._write_task_metadata_async = _noop_write
        try:
            import asyncio

            asyncio.run(self.manager._apply_task_execution_failed_locked(db, event))
        finally:
            self.manager._enqueue_task = original_enqueue
            self.manager._write_task_metadata_async = original_write

        self.assertEqual("running", task.status)
        self.assertEqual(["task-1"], queued)
        event_types = [row.event_type for row in db.events]
        self.assertIn("main_state_write_blocked", event_types)
        self.assertIn("task_failed", event_types)
        self.assertIn("owned_execution_takeover_requeued", event_types)
        self.assertIn("pending_task_layer_reconcile", ((task.summary or {}).get("runtime_workset") or {}))
        takeover_event = next(row for row in db.events if row.event_type == "owned_execution_takeover_requeued")
        self.assertEqual("request_task_layer_reconcile", (takeover_event.payload or {}).get("takeover_action"))

    def test_archive_job_copy_failed_locked_records_fact_and_requests_reconcile(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="firmware_unpack",
            task_type="binary",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
        )
        job = BinarySecurityArchiveJob(
            id="job-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="firmware_unpack",
            item_id="item-1",
            item_key="item-1",
            downstream_service="firmware_unpacker",
            downstream_task_id="child-1",
            archive_status="running",
        )
        event = BinarySecurityStateEvent(
            id="evt-archive-fail",
            task_id=task.id,
            project_id=task.project_id,
            event_type="archive_job_copy_failed",
            archive_job_id=job.id,
            payload={"error": "copy failed"},
        )
        db = _ModelAwareDb(tasks=[task], archive_jobs=[job], state_events=[event], events=[])

        queued = []
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        try:
            self.manager._apply_archive_job_copy_failed_locked(db, event)
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertEqual("running", task.status)
        self.assertEqual("failed", job.archive_status)
        self.assertEqual(["task-1"], queued)
        event_types = [row.event_type for row in db.events]
        self.assertIn("main_state_write_blocked", event_types)
        self.assertIn("downstream_archive_job_copy_failed", event_types)
        self.assertIn("owned_execution_takeover_requeued", event_types)
        self.assertIn("pending_task_layer_reconcile", ((task.summary or {}).get("runtime_workset") or {}))
        takeover_event = next(row for row in db.events if row.event_type == "owned_execution_takeover_requeued")
        self.assertEqual("request_task_layer_reconcile", (takeover_event.payload or {}).get("takeover_action"))

    def test_stage_worker_terminal_observed_only_records_fact_and_reconcile_request(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="entry_analysis",
            task_type="binary",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
        )
        event = BinarySecurityStateEvent(
            id="evt-terminal",
            task_id=task.id,
            project_id=task.project_id,
            event_type="stage_worker_terminal_observed",
            stage_name="entry_analysis",
            payload={
                "stage_name": "entry_analysis",
                "status": "success",
                "summary": {"status": "success"},
            },
        )
        db = _ModelAwareDb(tasks=[task], state_events=[event], stage_runs=[], events=[])

        queued = []
        original_enqueue = self.manager._enqueue_task
        original_write = self.manager._write_task_metadata_async
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)

        async def _noop_write(*_args, **_kwargs):
            return None

        self.manager._write_task_metadata_async = _noop_write
        try:
            import asyncio

            asyncio.run(self.manager._apply_stage_worker_terminal_event_locked(db, event))
        finally:
            self.manager._enqueue_task = original_enqueue
            self.manager._write_task_metadata_async = original_write

        self.assertEqual("running", task.status)
        self.assertEqual(["task-1"], queued)
        event_types = [row.event_type for row in db.events]
        self.assertIn("owned_execution_takeover_requeued", event_types)
        self.assertNotIn("task_finished", event_types)
        takeover_event = next(row for row in db.events if row.event_type == "owned_execution_takeover_requeued")
        self.assertEqual("request_task_layer_reconcile", (takeover_event.payload or {}).get("takeover_action"))
        self.assertIn("pending_task_layer_reconcile", ((task.summary or {}).get("runtime_workset") or {}))

    def test_owned_execution_takeover_requeued_payload_distinguishes_reconcile_request(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            current_stage="entry_analysis",
            task_type="binary",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_path="/tmp/fw.bin",
        )
        db = _ModelAwareDb(tasks=[task], events=[])

        queued = []
        original_enqueue = self.manager._enqueue_task
        self.manager._enqueue_task = lambda task_id: queued.append(task_id)
        try:
            self.manager._request_task_layer_reconcile(
                db,
                task,
                stage_name="entry_analysis",
                source_event_type="downstream_status_observed",
                state_event_id="evt-1",
                reconcile_reason="test_reconcile",
                message="test reconcile request",
            )
        finally:
            self.manager._enqueue_task = original_enqueue

        self.assertEqual(["task-1"], queued)
        takeover_event = next(row for row in db.events if row.event_type == "owned_execution_takeover_requeued")
        self.assertEqual("request_task_layer_reconcile", (takeover_event.payload or {}).get("takeover_action"))
        self.assertEqual("downstream_status_observed", (takeover_event.payload or {}).get("source_event_type"))
        self.assertTrue((takeover_event.payload or {}).get("fact_applied"))

    def test_publish_state_event_inbox_metrics_snapshot_lightweight_skips_full_render(self):
        store = AsyncMock()
        with (
            patch("app.service.task_manager.render_metrics", side_effect=AssertionError("full render should be skipped")),
            patch("app.service.task_manager.get_state_event_inbox_metrics_snapshot_store", return_value=store),
        ):
            import asyncio

            asyncio.run(self.manager._publish_state_event_inbox_metrics_snapshot(lightweight=True))

        store.write_snapshot.assert_awaited_once()
        payload = store.write_snapshot.await_args.kwargs["metrics_payload"]
        self.assertIn("secflow_binary_security_state_event_inbox_bootstrap_snapshot", payload)


if __name__ == "__main__":
    unittest.main()
