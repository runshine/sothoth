import asyncio
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.model import BinarySecurityStageItem, BinarySecurityTask, TASK_TYPE_SOURCE
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, UpstreamError, _now
from test_task_manager import _AppendingModelAwareDb, _FakeTaskSyncQueue, _ModelAwareDb


class TaskSyncQueuePathTests(unittest.TestCase):
    def test_enqueue_task_sync_request_merges_same_dedupe_key(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-merge",
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
                    reason="merge-a",
                    stage_name="entry_analysis",
                    item_ids=["i1"],
                )
            )
            asyncio.run(
                manager._enqueue_task_sync_request(
                    task,
                    sync_kind="downstream_status",
                    source="test",
                    reason="merge-b",
                    stage_name="entry_analysis",
                    item_ids=["i2"],
                )
            )
        finally:
            manager._enqueue_task = original_enqueue
            task_manager_module.get_task_queue = original_get_queue

        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual(["i1", "i2"], entries[0]["item_ids"])
        self.assertEqual([task.id, task.id], queued)

    def test_repair_task_sync_queue_on_runtime_start_recovers_cross_stage_late_sync(self):
        manager = TaskManager()
        manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="task-sync-repair",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="dataflow_vuln_scan",
            runtime_phase="tail_reconciliation",
            dispatcher_instance_id=manager.instance_id,
            lease_expires_at=_now() + timedelta(minutes=5),
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json='{"pipeline_mode": "mixed_streaming"}',
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry-late",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="source_project-a",
            item_name="module-a",
            parent_key="source_project",
            item_identity_key="source_project-a::source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            result={
                "sync_observation": {
                    "sync_status": "synced",
                    "downstream_status": "success",
                    "mapped_status": "success",
                    "last_attempt_at": (_now() - timedelta(minutes=10)).isoformat(),
                },
                "downstream_status": "running",
            },
            updated_at=_now() - timedelta(minutes=10),
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[entry_item], events=[])
        fake_queue = _FakeTaskSyncQueue()
        original_get_queue = task_manager_module.get_task_queue
        original_enqueue = manager._enqueue_task
        try:
            task_manager_module.get_task_queue = lambda: fake_queue
            manager._enqueue_task = lambda *_args, **_kwargs: None
            repaired = asyncio.run(manager._repair_task_sync_queue_on_runtime_start(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._enqueue_task = original_enqueue

        self.assertEqual(1, repaired)
        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual("entry_analysis", entries[0]["stage_name"])
        self.assertEqual("late_child_terminal_sync", entries[0]["sync_kind"])
        self.assertEqual(["si-entry-late"], entries[0]["item_ids"])

    def test_drain_task_sync_queue_consumes_and_acks_entry(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-drain",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            dispatcher_instance_id=manager.instance_id,
            lease_expires_at=_now() + timedelta(minutes=5),
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task], events=[])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-1",
                "dedupe_key": "downstream_status:entry_analysis:i1:*",
                "sync_kind": "downstream_status",
                "source": "test",
                "reason": "drain",
                "source_event_type": "downstream_status_observed",
                "stage_name": "entry_analysis",
                "item_ids": ["i1"],
                "archive_job_ids": [],
                "force": True,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "next_retry_at": _now().isoformat(),
                "attempts": 0,
                "priority": 10,
                "payload": {},
            }
        ]
        calls = []
        original_get_queue = task_manager_module.get_task_queue
        original_sync = manager.sync_downstream_status
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            async def _fake_sync(_db, *, project_id, task_id, stage_name=None, item_ids=None, force=False, **kwargs):
                del _db, project_id, task_id, kwargs
                calls.append(("sync", stage_name, list(item_ids or []), force))
                return SimpleNamespace(task_id=task.id, accepted=True, status="accepted", action="sync", message="ok")

            manager.sync_downstream_status = _fake_sync
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager.sync_downstream_status = original_sync
            manager._repair_task_sync_queue_on_runtime_start = original_repair

        self.assertTrue(changed)
        self.assertEqual([("sync", "entry_analysis", ["i1"], True)], calls)
        self.assertEqual([], fake_queue.entries_by_task[task.id])

    def test_drain_task_sync_queue_retries_failed_entry(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-retry",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            dispatcher_instance_id=manager.instance_id,
            lease_expires_at=_now() + timedelta(minutes=5),
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task], events=[])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-retry-1",
                "dedupe_key": "downstream_status:entry_analysis:i1:*",
                "sync_kind": "downstream_status",
                "source": "test",
                "reason": "retry",
                "source_event_type": "downstream_status_observed",
                "stage_name": "entry_analysis",
                "item_ids": ["i1"],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "next_retry_at": _now().isoformat(),
                "attempts": 0,
                "priority": 10,
                "payload": {},
            }
        ]
        original_get_queue = task_manager_module.get_task_queue
        original_sync = manager.sync_downstream_status
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            async def _fake_sync(*_args, **_kwargs):
                raise UpstreamError("boom")

            manager.sync_downstream_status = _fake_sync
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            with self.assertRaises(UpstreamError):
                asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager.sync_downstream_status = original_sync
            manager._repair_task_sync_queue_on_runtime_start = original_repair

        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual(1, entries[0]["attempts"])
        self.assertEqual("boom", entries[0]["last_error"])

    def test_migrate_legacy_pending_downstream_sync_to_redis_queue(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-legacy",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        fake_queue = _FakeTaskSyncQueue()
        queued = []
        original_get_queue = task_manager_module.get_task_queue
        original_enqueue = manager._enqueue_task
        try:
            task_manager_module.get_task_queue = lambda: fake_queue
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            asyncio.run(
                manager._migrate_legacy_pending_sync_signal_to_redis_queue(
                    task,
                    {
                        "source": "legacy",
                        "reason": "legacy_pending_downstream_sync",
                        "stage_name": "entry_analysis",
                        "item_ids": ["i1", "i2"],
                        "force": True,
                    },
                )
            )
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._enqueue_task = original_enqueue

        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual("downstream_status", entries[0]["sync_kind"])
        self.assertEqual(["i1", "i2"], entries[0]["item_ids"])
        self.assertTrue(entries[0]["payload"]["migrated_from_runtime_workset"])
        self.assertEqual([task.id], queued)

    def test_migrate_legacy_pending_binding_repair_to_redis_queue(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-binding-legacy",
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
        original_get_queue = task_manager_module.get_task_queue
        original_enqueue = manager._enqueue_task
        try:
            task_manager_module.get_task_queue = lambda: fake_queue
            manager._enqueue_task = lambda task_id, *_args, **_kwargs: queued.append(task_id)
            asyncio.run(
                manager._migrate_legacy_pending_sync_signal_to_redis_queue(
                    task,
                    {
                        "source": "legacy",
                        "reason": "binding_repair",
                        "stage_name": "dataflow_vuln_scan",
                        "item_ids": ["i1"],
                        "force": True,
                    },
                )
            )
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._enqueue_task = original_enqueue

        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual("binding_repair", entries[0]["sync_kind"])
        self.assertEqual("legacy_pending_binding_repair", entries[0]["source_event_type"])
        self.assertEqual("binding_repair", entries[0]["payload"]["legacy_signal_kind"])
        self.assertEqual([task.id], queued)

    def test_list_tasks_with_stale_stage_item_syncs_keeps_cross_stage_tail_task(self):
        manager = TaskManager()
        manager.cfg.runtime_policy.pipeline_mode = "mixed_streaming"
        task = BinarySecurityTask(
            id="task-stale-tail-cross-stage",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="dataflow_vuln_scan",
            runtime_phase="tail_reconciliation",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json='{"pipeline_mode": "mixed_streaming"}',
        )
        entry_item = BinarySecurityStageItem(
            id="si-stale-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="source_project-a",
            item_name="module-a",
            parent_key="source_project",
            item_identity_key="source_project-a::source_project",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
            result={
                "sync_observation": {
                    "sync_status": "synced",
                    "downstream_status": "running",
                    "mapped_status": "running",
                    "last_attempt_at": (_now() - timedelta(minutes=10)).isoformat(),
                },
                "downstream_status": "running",
            },
            updated_at=_now() - timedelta(minutes=10),
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[entry_item], events=[])

        refs = manager._list_tasks_with_stale_stage_item_syncs(db)

        self.assertEqual(1, len(refs))
        self.assertEqual(task.id, refs[0]["task_id"])
        self.assertEqual("entry_analysis", refs[0]["stage_name"])
        self.assertEqual(["si-stale-entry"], refs[0]["item_ids"])
