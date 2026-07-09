import asyncio
import json
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.model import BinarySecurityArchiveJob, BinarySecurityStageItem, BinarySecurityTask, BinarySecurityTaskRuntimeLease, TASK_TYPE_SOURCE
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, UpstreamError, _now
from test_task_manager import _AppendingModelAwareDb, _FakeTaskSyncQueue, _ModelAwareDb


def _runtime_lease(task: BinarySecurityTask, owner: str, *, expires_at=None) -> BinarySecurityTaskRuntimeLease:
    return BinarySecurityTaskRuntimeLease(
        task_id=task.id,
        owner_instance_id=owner,
        heartbeat_at=_now(),
        lease_expires_at=expires_at or (_now() + timedelta(minutes=5)),
    )


class TaskSyncQueuePathTests(unittest.TestCase):
    def test_build_expected_sync_requests_from_db_limits_child_create_by_stage_parallelism(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-sync-parallelism",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"stage_parallelism": {"entry_analysis": 2}}),
        )
        active_item = BinarySecurityStageItem(
            id="si-active",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="active",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-active",
            result={},
        )
        create_item_a = BinarySecurityStageItem(
            id="si-create-a",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="create-a",
            status="pending",
            downstream_service="entry_analyse",
            downstream_task_id=None,
            input_ref={
                "module_key": "create-a",
                "module_name": "create-a",
                "source_dir": "/src/a",
                "artifact_root": "/artifact/a",
                "entry_descriptor_root": "/entry/a",
                "entry_files_list": "entries-a.json",
            },
            result={},
        )
        create_item_b = BinarySecurityStageItem(
            id="si-create-b",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="create-b",
            status="pending",
            downstream_service="entry_analyse",
            downstream_task_id=None,
            input_ref={
                "module_key": "create-b",
                "module_name": "create-b",
                "source_dir": "/src/b",
                "artifact_root": "/artifact/b",
                "entry_descriptor_root": "/entry/b",
                "entry_files_list": "entries-b.json",
            },
            result={},
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[active_item, create_item_a, create_item_b], events=[])

        expected = manager._build_expected_sync_requests_from_db(db, task)

        create_entries = [entry for entry in expected if entry["operation"] == "child_create"]
        self.assertEqual(1, len(create_entries))
        self.assertEqual(["si-create-a"], create_entries[0]["item_ids"])

    def test_build_expected_sync_requests_from_db_treats_creating_item_as_active_and_does_not_recreate(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-sync-creating",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"stage_parallelism": {"entry_analysis": 1}}),
        )
        creating_item = BinarySecurityStageItem(
            id="si-creating",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="create-a",
            status="queued",
            downstream_service="entry_analyse",
            downstream_task_id=None,
            input_ref={
                "module_key": "create-a",
                "module_name": "create-a",
                "source_dir": "/src/a",
                "artifact_root": "/artifact/a",
                "entry_descriptor_root": "/entry/a",
                "entry_files_list": "entries-a.json",
            },
            result={
                "downstream_binding": {"state": "creating", "attempts": 1},
                "sync_observation": {"binding_state": "creating"},
            },
        )
        waiting_item = BinarySecurityStageItem(
            id="si-waiting",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="create-b",
            status="pending",
            downstream_service="entry_analyse",
            downstream_task_id=None,
            input_ref={
                "module_key": "create-b",
                "module_name": "create-b",
                "source_dir": "/src/b",
                "artifact_root": "/artifact/b",
                "entry_descriptor_root": "/entry/b",
                "entry_files_list": "entries-b.json",
            },
            result={},
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[creating_item, waiting_item], events=[])

        expected = manager._build_expected_sync_requests_from_db(db, task)

        create_entries = [entry for entry in expected if entry["operation"] == "child_create"]
        self.assertEqual([], create_entries)

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
                    operation="child_sync",
                    source="test",
                    reason="merge-a",
                    stage_name="entry_analysis",
                    item_ids=["i1"],
                )
            )
            asyncio.run(
                manager._enqueue_task_sync_request(
                    task,
                    operation="child_sync",
                    source="test",
                    reason="merge-b",
                    stage_name="entry_analysis",
                    item_ids=["i1"],
                    payload={"second": True},
                )
            )
        finally:
            manager._enqueue_task = original_enqueue
            task_manager_module.get_task_queue = original_get_queue

        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual({"second": True}, entries[0]["payload"])
        self.assertEqual("merge-b", entries[0]["reason"])
        self.assertEqual("child_sync", entries[0]["operation"])
        self.assertEqual(["i1"], entries[0]["item_ids"])
        self.assertEqual([], queued)

    def test_merge_task_sync_entries_accepts_non_empty_list_and_dict_fields(self):
        merged = task_manager_module.get_task_queue()._merge_task_sync_entries(
            {
                "queue_item_id": "q1",
                "dedupe_key": "k1",
                "operation": "child_sync",
                "item_ids": ["i1"],
                "archive_job_ids": [],
                "payload": {"old": "value"},
                "reason": "old",
            },
            {
                "queue_item_id": "q1",
                "dedupe_key": "k1",
                "operation": "child_sync",
                "item_ids": ["i2"],
                "archive_job_ids": ["a1"],
                "payload": {"new": "value"},
                "reason": "new",
            },
        )

        self.assertEqual(["i1", "i2"], merged["item_ids"])
        self.assertEqual(["a1"], merged["archive_job_ids"])
        self.assertEqual({"old": "value", "new": "value"}, merged["payload"])
        self.assertEqual("new", merged["reason"])

    def test_repair_task_sync_queue_on_runtime_start_recovers_cross_stage_terminal_apply_as_child_sync(self):
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
        db = _ModelAwareDb(tasks=[task], stage_items=[entry_item], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
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
        self.assertEqual("child_sync", entries[0]["operation"])
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
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(tasks=[task], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-1",
                "dedupe_key": "child_sync:entry_analysis:i1",
                "operation": "child_sync",
                "source": "test",
                "reason": "drain",
                "source_event_type": "downstream_status_observed",
                "stage_name": "entry_analysis",
                "item_ids": ["i1"],
                "archive_job_ids": [],
                "force": True,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 10,
                "payload": {},
            }
        ]
        calls = []
        original_get_queue = task_manager_module.get_task_queue
        original_process = manager._process_task_sync_entry_blocking
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            def _fake_process(project_id, task_id, operation, stage_name=None, item_ids=None, force=False):
                del project_id, task_id
                self.assertEqual("child_sync", operation)
                calls.append(("sync", stage_name, list(item_ids or []), force))
                return None

            manager._process_task_sync_entry_blocking = _fake_process
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._process_task_sync_entry_blocking = original_process
            manager._repair_task_sync_queue_on_runtime_start = original_repair

        self.assertTrue(changed)
        self.assertEqual([("sync", "entry_analysis", ["i1"], True)], calls)
        self.assertEqual([], fake_queue.entries_by_task[task.id])

    def test_drain_task_sync_queue_records_failure_and_keeps_entry_for_future_reconcile(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-retry",
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
        db = _AppendingModelAwareDb(tasks=[task], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-retry-1",
                "dedupe_key": "child_sync:entry_analysis:i1",
                "operation": "child_sync",
                "source": "test",
                "reason": "retry",
                "source_event_type": "downstream_status_observed",
                "stage_name": "entry_analysis",
                "item_ids": ["i1"],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 10,
                "payload": {},
            }
        ]
        original_get_queue = task_manager_module.get_task_queue
        original_process = manager._process_task_sync_entry_blocking
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            def _fake_process(*_args, **_kwargs):
                raise UpstreamError("boom")

            manager._process_task_sync_entry_blocking = _fake_process
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            with self.assertRaises(UpstreamError):
                asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._process_task_sync_entry_blocking = original_process
            manager._repair_task_sync_queue_on_runtime_start = original_repair

        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        failure_events = [event for event in db.events if event.event_type == "downstream_sync_failed"]
        self.assertEqual(1, len(failure_events))
        self.assertEqual("UpstreamError", failure_events[0].payload.get("error_type"))

    def test_drain_task_sync_queue_discards_terminal_invalid_entry_and_records_event(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-terminal-discard",
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
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-terminal-1",
                "dedupe_key": "child_sync:entry_analysis:si-missing",
                "operation": "child_sync",
                "source": "runtime_start_repair",
                "reason": "repair_missing_or_stale_sync_queue_entry",
                "source_event_type": "task_sync_queue_repair",
                "stage_name": "entry_analysis",
                "item_ids": ["si-missing"],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 30,
                "payload": {},
            }
        ]
        original_get_queue = task_manager_module.get_task_queue
        original_process = manager._process_task_sync_entry_blocking
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        original_reconcile = manager._reconcile_missing_task_sync_requests
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            def _fake_process(*_args, **_kwargs):
                raise task_manager_module.NotFoundError("阶段子任务不存在")

            manager._process_task_sync_entry_blocking = _fake_process
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            manager._reconcile_missing_task_sync_requests = AsyncMock(return_value=0)
            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._process_task_sync_entry_blocking = original_process
            manager._repair_task_sync_queue_on_runtime_start = original_repair
            manager._reconcile_missing_task_sync_requests = original_reconcile

        self.assertTrue(changed)
        self.assertEqual([], fake_queue.entries_by_task[task.id])
        discard_events = [event for event in db.events if event.event_type == "task_sync_request_discarded_after_invalid_item_error"]
        self.assertEqual(1, len(discard_events))
        payload = dict(discard_events[0].payload or {})
        self.assertEqual("tsq-terminal-1", payload.get("queue_item_id"))
        self.assertEqual(["si-missing"], payload.get("item_ids"))
        self.assertEqual("repair_missing_or_stale_sync_queue_entry", payload.get("reason"))
        self.assertEqual("NotFoundError", payload.get("error_type"))
        self.assertEqual("acked_and_discarded", payload.get("disposition"))

    def test_drain_task_sync_queue_filters_missing_item_ids_and_requeues_existing_targets(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-partial-missing",
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
        stage_item = BinarySecurityStageItem(
            id="si-existing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-existing",
            stage_name="entry_analysis",
            item_key="entry-existing",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-existing",
            result={},
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[stage_item], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-partial-1",
                "dedupe_key": "child_sync:entry_analysis:si-existing,si-missing",
                "operation": "child_sync",
                "source": "runtime_start_repair",
                "reason": "repair_missing_or_stale_sync_queue_entry",
                "source_event_type": "task_sync_queue_repair",
                "stage_name": "entry_analysis",
                "item_ids": ["si-existing", "si-missing"],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 30,
                "payload": {},
            }
        ]
        original_get_queue = task_manager_module.get_task_queue
        original_process = manager._process_task_sync_entry_blocking
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        original_reconcile = manager._reconcile_missing_task_sync_requests
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            def _fake_process(*_args, **_kwargs):
                raise task_manager_module.NotFoundError("阶段子任务不存在")

            manager._process_task_sync_entry_blocking = _fake_process
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            manager._reconcile_missing_task_sync_requests = AsyncMock(return_value=0)
            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._process_task_sync_entry_blocking = original_process
            manager._repair_task_sync_queue_on_runtime_start = original_repair
            manager._reconcile_missing_task_sync_requests = original_reconcile

        self.assertTrue(changed)
        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual(["si-existing"], entries[0]["item_ids"])
        payload = dict(entries[0].get("payload") or {})
        self.assertEqual(["si-missing"], payload.get("filtered_missing_item_ids"))
        self.assertEqual(["si-existing"], payload.get("recovered_existing_item_ids"))

    def test_drain_task_sync_queue_discards_missing_single_item_id_entry(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-missing-single",
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
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-missing-single",
                "dedupe_key": "child_sync:entry_analysis:si-missing",
                "operation": "child_sync",
                "source": "test",
                "reason": "single-item-missing",
                "source_event_type": "downstream_status_observed",
                "stage_name": "entry_analysis",
                "item_id": "si-missing",
                "item_ids": [],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 10,
                "payload": {},
            }
        ]
        acked: list[tuple[str, str, str | None, str | None]] = []
        original_get_queue = task_manager_module.get_task_queue
        original_process = manager._process_task_sync_entry_blocking
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        original_reconcile = manager._reconcile_missing_task_sync_requests
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            async def _fake_ack(task_id, *, queue_item_id, dedupe_key=None, context=""):
                acked.append((task_id, queue_item_id, dedupe_key, context))
                entries = fake_queue.entries_by_task.get(task_id, [])
                fake_queue.entries_by_task[task_id] = [
                    entry for entry in entries if entry.get("queue_item_id") != queue_item_id
                ]

            fake_queue.ack_task_sync_request = _fake_ack

            def _fake_process(*args, **kwargs):
                del args, kwargs
                raise task_manager_module.NotFoundError("阶段子任务不存在")

            manager._process_task_sync_entry_blocking = _fake_process
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            manager._reconcile_missing_task_sync_requests = AsyncMock(return_value=0)

            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._process_task_sync_entry_blocking = original_process
            manager._repair_task_sync_queue_on_runtime_start = original_repair
            manager._reconcile_missing_task_sync_requests = original_reconcile

        self.assertTrue(changed)
        self.assertEqual([], fake_queue.entries_by_task[task.id])
        self.assertEqual(
            [("task-sync-missing-single", "tsq-missing-single", "child_sync:entry_analysis:si-missing", "task_sync_ack_terminal_discard")],
            acked,
        )

    def test_drain_task_sync_queue_runs_blocking_helper_via_to_thread(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-thread-helper",
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
        db = _ModelAwareDb(tasks=[task], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-thread-1",
                "dedupe_key": "child_sync:entry_analysis:i-thread",
                "operation": "child_sync",
                "source": "test",
                "reason": "thread",
                "source_event_type": "downstream_status_observed",
                "stage_name": "entry_analysis",
                "item_ids": ["i-thread"],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 10,
                "payload": {},
            }
        ]
        original_get_queue = task_manager_module.get_task_queue
        original_process = manager._process_task_sync_entry_blocking
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        original_to_thread = task_manager_module.asyncio.to_thread
        thread_calls = []
        helper_calls = []
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            async def _fake_to_thread(fn, *args, **kwargs):
                thread_calls.append(getattr(fn, "__name__", str(fn)))
                return fn(*args, **kwargs)

            def _fake_process(project_id, task_id, operation, stage_name=None, item_ids=None, force=False):
                helper_calls.append((project_id, task_id, operation, stage_name, list(item_ids or []), force))
                return None

            manager._process_task_sync_entry_blocking = _fake_process
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            task_manager_module.asyncio.to_thread = _fake_to_thread
            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._process_task_sync_entry_blocking = original_process
            manager._repair_task_sync_queue_on_runtime_start = original_repair
            task_manager_module.asyncio.to_thread = original_to_thread

        self.assertTrue(changed)
        self.assertIn("_fake_process", thread_calls)
        self.assertEqual(
            [("p1", task.id, "child_sync", "entry_analysis", ["i-thread"], False)],
            helper_calls,
        )
        self.assertEqual([], fake_queue.entries_by_task[task.id])

    def test_reconcile_missing_task_sync_requests_requeues_due_db_fact(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-reconcile",
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
        item = BinarySecurityStageItem(
            id="si-reconcile-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-reconcile-1",
            stage_name="entry_analysis",
            item_key="entry-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-reconcile-1",
            result={},
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[])
        fake_queue = _FakeTaskSyncQueue()
        original_get_queue = task_manager_module.get_task_queue
        original_enqueue = manager._enqueue_task
        try:
            task_manager_module.get_task_queue = lambda: fake_queue
            manager._enqueue_task = lambda *_args, **_kwargs: None
            repaired = asyncio.run(manager._reconcile_missing_task_sync_requests(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._enqueue_task = original_enqueue

        self.assertEqual(1, repaired)
        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual(["si-reconcile-1"], entries[0]["item_ids"])
        self.assertEqual("child_sync", entries[0]["operation"])
        self.assertIn("task_sync_request_reconcile_requeued", [event.event_type for event in db.events])
        reconcile_event = next(event for event in db.events if event.event_type == "task_sync_request_reconcile_requeued")
        payload = dict(reconcile_event.payload or {})
        self.assertTrue(payload["task_sync_queue_only"])
        self.assertFalse(payload["shared_dispatch_enqueued"])

    def test_build_periodic_sync_requests_from_db_only_includes_child_sync_candidates(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-periodic-build",
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
        stale_item = BinarySecurityStageItem(
            id="si-periodic-stale",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-periodic-stale",
            stage_name="entry_analysis",
            item_key="entry-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-periodic-stale",
            result={
                "downstream": {
                    "task_id": "eat-periodic-stale",
                    "status": "running",
                },
                "last_sync_attempt_at": (_now() - timedelta(seconds=600)).isoformat(),
                "sync_status": "synced",
            },
        )
        create_item = BinarySecurityStageItem(
            id="si-periodic-create",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-periodic-create",
            stage_name="entry_analysis",
            item_key="entry-b",
            status="pending",
            downstream_service="entry_analyse",
            downstream_task_id=None,
            result={},
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[stale_item, create_item], events=[])

        expected = manager._build_periodic_sync_requests_from_db(db, task)

        self.assertEqual(1, len(expected))
        self.assertEqual("child_sync", expected[0]["operation"])
        self.assertEqual(["si-periodic-stale"], expected[0]["item_ids"])
        self.assertEqual("periodic_runtime_sync", expected[0]["source"])
        self.assertTrue(expected[0]["payload"]["periodic_sync"])

    def test_reconcile_periodic_task_sync_requests_enqueues_without_repair_event(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-sync-periodic-reconcile",
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
        item = BinarySecurityStageItem(
            id="si-periodic-reconcile",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-periodic-reconcile",
            stage_name="entry_analysis",
            item_key="entry-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-periodic-reconcile",
            result={
                "downstream": {
                    "task_id": "eat-periodic-reconcile",
                    "status": "running",
                },
                "last_sync_attempt_at": (_now() - timedelta(seconds=600)).isoformat(),
                "sync_status": "synced",
            },
        )
        db = _AppendingModelAwareDb(
            tasks=[task],
            stage_items=[item],
            events=[],
            runtime_leases=[_runtime_lease(task, manager.instance_id)],
        )
        fake_queue = _FakeTaskSyncQueue()
        original_get_queue = task_manager_module.get_task_queue
        original_factory = task_manager_module.get_session_factory
        original_enqueue = manager._enqueue_task
        try:
            task_manager_module.get_task_queue = lambda: fake_queue
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._enqueue_task = lambda *_args, **_kwargs: None

            enqueued = asyncio.run(manager._reconcile_periodic_task_sync_requests(task.id))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            task_manager_module.get_session_factory = original_factory
            manager._enqueue_task = original_enqueue

        self.assertEqual(1, enqueued)
        entries = fake_queue.entries_by_task[task.id]
        self.assertEqual(1, len(entries))
        self.assertEqual("child_sync", entries[0]["operation"])
        self.assertEqual("periodic_runtime_sync", entries[0]["source"])
        self.assertEqual("active_child_stale_sync", entries[0]["reason"])
        self.assertFalse(any(event.event_type == "task_sync_request_reconcile_requeued" for event in db.events))

    def test_drain_task_sync_queue_empty_branch_uses_only_runtime_reconcile_not_runtime_start_repair(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-empty-reconcile-only",
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
        db = _AppendingModelAwareDb(tasks=[task], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        original_get_queue = task_manager_module.get_task_queue
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        original_reconcile = manager._reconcile_missing_task_sync_requests
        repair_mock = AsyncMock(return_value=1)
        reconcile_mock = AsyncMock(return_value=0)
        try:
            task_manager_module.get_task_queue = lambda: fake_queue
            manager._repair_task_sync_queue_on_runtime_start = repair_mock
            manager._reconcile_missing_task_sync_requests = reconcile_mock

            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._repair_task_sync_queue_on_runtime_start = original_repair
            manager._reconcile_missing_task_sync_requests = original_reconcile

        self.assertFalse(changed)
        repair_mock.assert_not_awaited()
        reconcile_mock.assert_awaited_once()

    def test_reconcile_missing_task_sync_requests_backfills_authoritative_archive_fact_instead_of_requeue(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-inline-backfill",
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
        item = BinarySecurityStageItem(
            id="si-sync-inline-backfill",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-sync-inline-backfill",
            stage_name="dataflow_vuln_scan",
            item_key="entry-a",
            status="success",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dvs-inline-backfill",
            result={
                "downstream": {
                    "task_id": "dvs-inline-backfill",
                    "status": "passed",
                },
            },
        )
        archive_job = BinarySecurityArchiveJob(
            id="aj-sync-inline-backfill",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=item.stage_name,
            item_id=item.id,
            item_key=item.item_key,
            downstream_service=item.downstream_service,
            downstream_task_id=item.downstream_task_id,
            archive_status="success",
            archive_root="/tmp/archive",
            started_at=_now(),
        )
        archive_job.payload = {
            "mapped_status": "success",
            "downstream_payload": {
                "task_id": "dvs-inline-backfill",
                "status": "passed",
            },
            "bound_downstream_task_id": "dvs-inline-backfill",
        }
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], archive_jobs=[archive_job], events=[])
        fake_queue = _FakeTaskSyncQueue()
        original_get_queue = task_manager_module.get_task_queue
        original_enqueue = manager._enqueue_task
        try:
            task_manager_module.get_task_queue = lambda: fake_queue
            manager._enqueue_task = lambda *_args, **_kwargs: None
            repaired = asyncio.run(manager._reconcile_missing_task_sync_requests(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager._enqueue_task = original_enqueue

        observation = dict(item.result.get("sync_observation") or {})
        self.assertEqual(1, repaired)
        self.assertEqual([], fake_queue.entries_by_task.get(task.id, []))
        self.assertEqual("synced", item.result.get("sync_status"))
        self.assertEqual("passed", item.result.get("downstream_status"))
        self.assertTrue(observation.get("state_applied"))
        self.assertTrue(any(event.event_type == "authoritative_archive_sync_backfilled" for event in db.events))
        self.assertFalse(any(event.event_type == "task_sync_request_reconcile_requeued" for event in db.events))

    def test_drain_task_sync_queue_failure_does_not_persist_retry_budget_state(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-retry-db-fact",
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
        item = BinarySecurityStageItem(
            id="si-retry-db-fact",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-retry-db-fact",
            stage_name="entry_analysis",
            item_key="entry-a",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-retry-db-fact",
            result={},
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[item], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-retry-db-fact",
                "dedupe_key": "child_sync:entry_analysis:si-retry-db-fact",
                "operation": "child_sync",
                "source": "test",
                "reason": "retry",
                "source_event_type": "downstream_status_observed",
                "stage_name": "entry_analysis",
                "item_ids": ["si-retry-db-fact"],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 10,
                "payload": {},
            }
        ]
        original_get_queue = task_manager_module.get_task_queue
        original_sync = manager.sync_downstream_status
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        original_reconcile = manager._reconcile_missing_task_sync_requests
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            async def _fake_sync(*_args, **_kwargs):
                raise UpstreamError("retry db fact boom")

            manager.sync_downstream_status = _fake_sync
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            manager._reconcile_missing_task_sync_requests = AsyncMock(return_value=0)
            with self.assertRaises(UpstreamError):
                asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager.sync_downstream_status = original_sync
            manager._repair_task_sync_queue_on_runtime_start = original_repair
            manager._reconcile_missing_task_sync_requests = original_reconcile

        sync_observation = dict(item.result.get("sync_observation") or {})
        self.assertIsNone(sync_observation.get("next_retry_at"))
        self.assertFalse(bool(sync_observation.get("budget_exhausted")))
        self.assertIn("downstream_sync_failed", [event.event_type for event in db.events])

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
        self.assertEqual("child_sync", entries[0]["operation"])
        self.assertEqual(["i1", "i2"], entries[0]["item_ids"])
        self.assertTrue(entries[0]["payload"]["migrated_from_runtime_workset"])
        self.assertEqual([], queued)

    def test_drain_task_sync_queue_acks_stale_existing_items_without_retry(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-sync-stale-existing",
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
        stage_item = BinarySecurityStageItem(
            id="si-stale-existing",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-stale-existing",
            stage_name="entry_analysis",
            item_key="entry-existing",
            status="success",
            downstream_service="entry_analyse",
            downstream_task_id="eat-existing",
            result={
                "sync_observation": {
                    "sync_status": "synced",
                    "downstream_status": "success",
                    "mapped_status": "success",
                }
            },
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_items=[stage_item], events=[], runtime_leases=[_runtime_lease(task, manager.instance_id)])
        fake_queue = _FakeTaskSyncQueue()
        fake_queue.entries_by_task[task.id] = [
            {
                "queue_item_id": "tsq-stale-existing",
                "dedupe_key": "child_sync:entry_analysis:si-stale-existing",
                "operation": "child_sync",
                "source": "runtime_start_repair",
                "reason": "repair_missing_or_stale_sync_queue_entry",
                "source_event_type": "task_sync_queue_repair",
                "stage_name": "entry_analysis",
                "item_ids": ["si-stale-existing"],
                "archive_job_ids": [],
                "force": False,
                "requested_at": _now().isoformat(),
                "last_requested_at": _now().isoformat(),
                "priority": 30,
                "payload": {
                    "observed_downstream_status": "success",
                },
            }
        ]
        acked: list[tuple[str, str, str | None, str | None]] = []
        original_get_queue = task_manager_module.get_task_queue
        original_sync = manager.sync_downstream_status
        original_repair = manager._repair_task_sync_queue_on_runtime_start
        original_reconcile = manager._reconcile_missing_task_sync_requests
        original_should_ack_stale = manager._should_ack_stale_task_sync_entry_without_retry
        try:
            task_manager_module.get_task_queue = lambda: fake_queue

            async def _fake_ack(task_id, *, queue_item_id, dedupe_key=None, context=""):
                acked.append((task_id, queue_item_id, dedupe_key, context))
                entries = fake_queue.entries_by_task.get(task_id, [])
                fake_queue.entries_by_task[task_id] = [
                    entry for entry in entries if entry.get("queue_item_id") != queue_item_id
                ]

            fake_queue.ack_task_sync_request = _fake_ack

            async def _fake_sync(*_args, **_kwargs):
                raise task_manager_module.NotFoundError("阶段子任务不存在")

            manager.sync_downstream_status = _fake_sync
            manager._repair_task_sync_queue_on_runtime_start = AsyncMock(return_value=0)
            manager._reconcile_missing_task_sync_requests = AsyncMock(return_value=0)
            manager._should_ack_stale_task_sync_entry_without_retry = lambda *_args, **_kwargs: (
                True,
                ["si-stale-existing"],
                [],
            )

            changed = asyncio.run(manager._drain_task_sync_queue(db, task))
        finally:
            task_manager_module.get_task_queue = original_get_queue
            manager.sync_downstream_status = original_sync
            manager._repair_task_sync_queue_on_runtime_start = original_repair
            manager._reconcile_missing_task_sync_requests = original_reconcile
            manager._should_ack_stale_task_sync_entry_without_retry = original_should_ack_stale

        self.assertTrue(changed)
        self.assertEqual([], fake_queue.entries_by_task[task.id])
        self.assertEqual(
            [("task-sync-stale-existing", "tsq-stale-existing", "child_sync:entry_analysis:si-stale-existing", "task_sync_ack_stale_noop")],
            acked,
        )
        discard_events = [event for event in db.events if event.event_type == "task_sync_request_discarded_as_stale_noop"]
        self.assertEqual(1, len(discard_events))
        self.assertEqual(["si-stale-existing"], discard_events[0].payload.get("existing_item_ids"))
        self.assertEqual("acked_as_stale_noop", discard_events[0].payload.get("disposition"))

    def test_process_task_sync_entry_blocking_creates_child_and_records_sync_events(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-sync-create-exec",
            project_id="p1",
            name="sync",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json=json.dumps({"stage_parallelism": {"entry_analysis": 2}}),
        )
        item = BinarySecurityStageItem(
            id="si-create-exec",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-a",
            item_name="module-a",
            status="pending",
            downstream_service="entry_analyse",
            downstream_task_id=None,
            input_ref={
                "module_key": "module-a",
                "module_name": "module-a",
                "source_dir": "/src/module-a",
                "artifact_root": "/artifact/module-a",
                "entry_descriptor_root": "/entry/module-a",
                "entry_files_list": "entries.json",
            },
            result={},
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_items=[item],
            events=[],
            runtime_leases=[_runtime_lease(task, manager.instance_id)],
        )

        class _FakeDownstreamTasks:
            async def create_child_task(self, _db, _task, _item, *, service, token, payload, event_payload):
                del _db, _task, _item, event_payload
                return {
                    "task_id": "eat-created-1",
                    "status": "running",
                    "service": service,
                    "token_used": token,
                    "payload": dict(payload),
                }

        original_get_session_factory = task_manager_module.get_session_factory
        original_downstream_tasks = manager._downstream_tasks
        original_active_delete_operation = manager._active_delete_operation
        original_derive_downstream_work_key = manager._derive_downstream_work_key
        original_configure_runtime_session = manager._configure_runtime_session_fast_lock_wait_timeout
        try:
            task_manager_module.get_session_factory = lambda: (lambda: db)
            manager._downstream_tasks = lambda: _FakeDownstreamTasks()
            manager._active_delete_operation = lambda *_args, **_kwargs: None
            async def _fake_derive_downstream_work_key(**_kwargs):
                return {}
            manager._derive_downstream_work_key = _fake_derive_downstream_work_key
            manager._configure_runtime_session_fast_lock_wait_timeout = lambda *_args, **_kwargs: None

            manager._process_task_sync_entry_blocking(
                task.project_id,
                task.id,
                "child_create",
                "entry_analysis",
                [item.id],
                False,
            )
        finally:
            task_manager_module.get_session_factory = original_get_session_factory
            manager._downstream_tasks = original_downstream_tasks
            manager._active_delete_operation = original_active_delete_operation
            manager._derive_downstream_work_key = original_derive_downstream_work_key
            manager._configure_runtime_session_fast_lock_wait_timeout = original_configure_runtime_session

        self.assertEqual("eat-created-1", item.downstream_task_id)
        self.assertEqual("running", item.status)
        sync_event_types = [row.event_type for row in db.sync_events]
        sync_operations = [row.operation for row in db.sync_events]
        self.assertIn("requested", sync_event_types)
        self.assertIn("applied", sync_event_types)
        self.assertTrue(all(operation == "downstream_create" for operation in sync_operations))
        self.assertEqual(2, len(sync_event_types))


if __name__ == "__main__":
    unittest.main()
