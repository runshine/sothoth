import unittest
from datetime import timedelta

from app.model import BinarySecurityStageItem, BinarySecurityTask, BinarySecurityTaskRuntimeLease
from app.service.task_manager import TaskManager, UpstreamError, _now
from test_task_manager import _AppendingModelAwareDb


class DownstreamSyncDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_persist_downstream_sync_failure_records_uniform_diagnostics(self):
        task = BinarySecurityTask(
            id="task-diag-1",
            project_id="p1",
            name="diag",
            task_type="source",
            status="running",
            current_stage="entry_analysis",
            runtime_phase="owned_execution",
            dispatcher_instance_id=self.manager.instance_id,
            lease_expires_at=_now() + timedelta(minutes=5),
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="si-diag-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-diag-1",
            stage_name="entry_analysis",
            item_key="entry-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-diag-1",
            result={},
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=1,
            owner_instance_id=self.manager.instance_id,
            lease_expires_at=_now() + timedelta(minutes=5),
            heartbeat_at=_now(),
            created_at=_now(),
            updated_at=_now(),
            generation=0,
            last_renewed_at=_now(),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], runtime_leases=[lease], events=[])

        error = UpstreamError("")
        error.error_type_detail = "connection_reused_stale"
        error.transport_error_kind = "connection_reused_stale"
        persisted = self.manager._persist_downstream_sync_failure(
            db,
            task=task,
            item=item,
            error=error,
            change_source="transport_error",
            operation="downstream_sync",
            before_status="running",
        )

        self.assertTrue(persisted)
        sync_observation = dict((item.result or {}).get("sync_observation") or {})
        self.assertEqual("transport_error", sync_observation.get("sync_status"))
        self.assertEqual("connection_reused_stale", sync_observation.get("error_type"))
        self.assertEqual("UpstreamError('')", sync_observation.get("error_message"))

        sync_events = [event for event in db.sync_events if getattr(event, "item_id", None) == item.id]
        self.assertTrue(sync_events)
        latest_sync_event = sync_events[-1]
        payload = dict(latest_sync_event.payload or {})
        self.assertEqual("downstream_sync", payload.get("operation"))
        self.assertEqual("entry_analysis", payload.get("stage_name"))
        self.assertEqual("si-diag-1", payload.get("item_id"))
        self.assertEqual("entry_analyse", payload.get("downstream_service"))
        self.assertEqual("eat-diag-1", payload.get("downstream_task_id"))
        self.assertEqual("UpstreamError", payload.get("error_class"))
        self.assertEqual("connection_reused_stale", payload.get("error_type"))
        self.assertEqual("connection_reused_stale", payload.get("error_detail"))
        self.assertEqual("UpstreamError('')", payload.get("error_message"))
        self.assertEqual("UpstreamError('')", payload.get("error_repr"))
        self.assertTrue(payload.get("retryable_transport_error"))
        self.assertEqual("owned_execution", payload.get("runtime_phase"))
        self.assertEqual("running", payload.get("task_status"))
        self.assertEqual(self.manager.instance_id, payload.get("dispatcher_instance_id"))
        self.assertTrue(payload.get("runtime_lease_active"))
        self.assertEqual(self.manager.instance_id, payload.get("runtime_lease_owner"))
        self.assertFalse(payload.get("local_handle_alive"))

        timeline = [event for event in db.events if getattr(event, "event_type", None) == "child_transport_failed"]
        self.assertTrue(timeline)
        timeline_payload = dict(timeline[-1].payload or {})
        self.assertEqual("connection_reused_stale", timeline_payload.get("error_detail"))
        self.assertEqual("UpstreamError('')", timeline_payload.get("error_message"))
        self.assertEqual("UpstreamError('')", timeline_payload.get("error_repr"))
        self.assertEqual("entry_analyse", timeline_payload.get("downstream_service"))
        self.assertEqual("eat-diag-1", timeline_payload.get("downstream_task_id"))
        self.assertTrue(timeline_payload.get("runtime_lease_active"))


if __name__ == "__main__":
    unittest.main()
