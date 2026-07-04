import asyncio
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from app.model import (
    BinarySecurityEvent,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import (
    BinarySecurityTaskPolicyUpdatePayload,
    BinarySecurityTaskRuntimePolicyUpdatePayload,
    TaskManager,
    _now,
)
from test_task_manager import _AppendingModelAwareDb, _FakeTaskSyncQueue, _ModelAwareDb


class OwnerSignalPathTests(unittest.TestCase):
    def test_enqueue_task_sync_request_records_queue_entry_without_parent_wakeup(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-owner",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-owner",
        )
        fake_queue = _FakeTaskSyncQueue()
        queued = []
        original_enqueue = manager._enqueue_task
        original_get_queue = task_manager_module.get_task_queue
        try:
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            task_manager_module.get_task_queue = lambda: fake_queue
            asyncio.run(
                manager._enqueue_task_sync_request(
                    task,
                    sync_kind="downstream_status",
                    source="test",
                    reason="owner-sync",
                    stage_name="entry_analysis",
                    item_ids=["i1"],
                )
            )
        finally:
            manager._enqueue_task = original_enqueue
            task_manager_module.get_task_queue = original_get_queue

        self.assertEqual([], queued)
        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual(["i1"], entries[0]["item_ids"])

    def test_enqueue_task_sync_request_reenqueues_parent_without_healthy_owner(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-no-owner",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        fake_queue = _FakeTaskSyncQueue()
        queued = []
        original_enqueue = manager._enqueue_task
        original_get_queue = task_manager_module.get_task_queue
        try:
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            task_manager_module.get_task_queue = lambda: fake_queue
            asyncio.run(
                manager._enqueue_task_sync_request(
                    task,
                    sync_kind="downstream_status",
                    source="test",
                    reason="no-owner-sync",
                    stage_name="entry_analysis",
                    item_ids=["i1"],
                )
            )
        finally:
            manager._enqueue_task = original_enqueue
            task_manager_module.get_task_queue = original_get_queue

        self.assertEqual([task.id], queued)
        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))

    def test_enqueue_task_sync_request_with_active_runtime_lease_skips_parent_reenqueue(self):
        manager = TaskManager()
        manager.instance_id = "worker-owner"
        task = BinarySecurityTask(
            id="task-sync-active-lease",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id="worker-owner",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-owner",
            lease_expires_at=_now() + timedelta(seconds=120),
        )
        db = _AppendingModelAwareDb(tasks=[task], runtime_leases=[runtime_lease], events=[])
        fake_queue = _FakeTaskSyncQueue()
        queued = []
        original_enqueue = manager._enqueue_task
        original_get_queue = task_manager_module.get_task_queue
        try:
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            task_manager_module.get_task_queue = lambda: fake_queue
            asyncio.run(
                manager._enqueue_task_sync_request(
                    task,
                    db=db,
                    sync_kind="downstream_status",
                    source="test",
                    reason="healthy-owner-sync",
                    stage_name="entry_analysis",
                    item_ids=["i1"],
                )
            )
        finally:
            manager._enqueue_task = original_enqueue
            task_manager_module.get_task_queue = original_get_queue

        self.assertEqual([], queued)
        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))

    def test_reconcile_deferred_cleanup_task_ref_uses_owner_inbox_when_owner_present(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="t-reconcile-cleanup-pending",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="cancelled",
            current_stage="firmware_unpack",
            dispatcher_instance_id="worker-owner",
        )
        task.cleanup_snapshot = {
            "cleanup_partial_failed": True,
            "deleted_downstream_count": 0,
            "deferred_cleanup_attempts": 1,
            "deferred_cleanup_status": "partial_failed",
            "deferred_downstream_refs": [
                {"service": "firmware_unpacker", "task_id": "fw-1", "stage_name": "firmware_unpack", "deferred": True}
            ],
        }
        db = _AppendingModelAwareDb(tasks=[task], events=[])
        queued = []
        owner_signals = []

        async def _run():
            with (
                patch.object(task_manager_module, "get_session_factory", return_value=lambda: db),
                patch.object(manager, "_delete_downstream_refs", AsyncMock(return_value=0)),
            ):
                setattr(
                    manager,
                    "_last_downstream_cleanup_results",
                    [
                        {
                            "service": "firmware_unpacker",
                            "task_id": "fw-1",
                            "stage_name": "firmware_unpack",
                            "delete_status": "failed",
                            "deferred": True,
                            "error": "still busy",
                        }
                    ],
                )
                original_enqueue = manager._enqueue_task
                original_enqueue_owner_signal = manager._enqueue_owner_signal
                try:
                    manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
                    manager._enqueue_owner_signal = (
                        lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
                    )
                    await manager._reconcile_deferred_cleanup_task_ref({"project_id": "p1", "task_id": task.id}, "token")
                finally:
                    manager._enqueue_task = original_enqueue
                    manager._enqueue_owner_signal = original_enqueue_owner_signal

        asyncio.run(_run())

        self.assertEqual([task.id], queued)
        self.assertEqual([], owner_signals)
        event_types = [row.event_type for row in db.events if isinstance(row, BinarySecurityEvent)]
        self.assertIn("task_delete_cleanup_retry_deferred", event_types)

    def test_update_task_runtime_policy_uses_owner_inbox_when_owner_present(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="t-runtime-policy-owner",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY_MODULE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            runtime_phase="tail_reconciliation",
            dispatcher_instance_id="worker-owner",
        )
        task.policy = {
            "max_stage_parallelism": 4,
            "max_retries_per_item": 2,
            "continue_on_item_failure": True,
            "stage_parallelism": {"binary_to_source": 4, "entry_analysis": 4, "dataflow_vuln_scan": 4},
        }
        db = _ModelAwareDb(tasks=[task])
        queued = []
        owner_signals = []
        original_enqueue = manager._enqueue_task
        original_enqueue_owner_signal = manager._enqueue_owner_signal
        try:
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            manager._enqueue_owner_signal = (
                lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
            )
            manager.update_task_runtime_policy(
                db,
                project_id="p1",
                task_id="t-runtime-policy-owner",
                payload=BinarySecurityTaskRuntimePolicyUpdatePayload(
                    expected_version=0,
                    stage_parallelism={"entry_analysis": 2},
                    updated_by="tester",
                ),
            )
        finally:
            manager._enqueue_task = original_enqueue
            manager._enqueue_owner_signal = original_enqueue_owner_signal

        self.assertEqual([task.id], queued)
        self.assertEqual([], owner_signals)
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("task_runtime_policy_updated", event_types)

    def test_update_task_policy_falls_back_to_shared_dispatch_without_owner(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="t-policy-shared",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "max_stage_parallelism": 4,
            "max_retries_per_item": 2,
            "continue_on_item_failure": True,
            "partial_success_stage_advancement": {"binary_to_source": True, "entry_analysis": True, "dataflow_vuln_scan": True},
            "stage_parallelism": {
                "firmware_unpack": 4,
                "system_analysis": 4,
                "binary_to_source": 4,
                "entry_analysis": 4,
                "dataflow_vuln_scan": 4,
            },
            "stage_options": {"binary_to_source": {"enabled": True}},
            "module_selection_mode": "auto",
            "module_risk_levels": ["高"],
        }
        db = _ModelAwareDb(tasks=[task])
        queued = []
        owner_signals = []
        original_enqueue = manager._enqueue_task
        original_enqueue_owner_signal = manager._enqueue_owner_signal
        try:
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            manager._enqueue_owner_signal = (
                lambda owner_instance_id, task_id, **_kwargs: owner_signals.append((owner_instance_id, task_id))
            )
            manager.update_task_policy(
                db,
                project_id="p1",
                task_id="t-policy-shared",
                payload=BinarySecurityTaskPolicyUpdatePayload(
                    stage_options={"binary_to_source": {"enabled": False}},
                    max_retries_per_item=5,
                ),
            )
        finally:
            manager._enqueue_task = original_enqueue
            manager._enqueue_owner_signal = original_enqueue_owner_signal

        self.assertEqual([task.id], queued)
        self.assertEqual([], owner_signals)
        event_types = [getattr(event, "event_type", "") for event in db.added]
        self.assertIn("task_policy_updated", event_types)
        self.assertNotIn("owner_reconcile_signal_enqueued", event_types)
