import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_BINARY,
)
from app.service import task_manager as task_manager_module
from app.service.task.runtime import TaskRuntimeServiceMixin
from app.service.task_manager import TaskManager, _now
from test_task_manager import _FakeTaskSyncQueue, _ModelAwareDb


class ParentRuntimeTakeoverRequeueTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.manager.instance_id = "worker-a"

    def _task(self, **overrides):
        data = {
            "id": "task-1",
            "project_id": "project-1",
            "name": "task",
            "status": "running",
            "task_type": TASK_TYPE_BINARY,
            "current_stage": "dataflow_vuln_scan",
            "runtime_phase": TASK_RUNTIME_PHASE_OWNED_EXECUTION,
            "summary": {},
        }
        data.update(overrides)
        return BinarySecurityTask(**data)

    def test_repair_running_lease_invariant_requeues_immediately_when_runtime_lease_missing(self):
        task = self._task()
        db = _ModelAwareDb(tasks=[task], runtime_leases=[], events=[])
        requeue_calls = []

        with (
            patch.object(
                self.manager,
                "_force_requeue_task_sync",
                lambda task_id, *, context: requeue_calls.append((task_id, context)) or True,
            ),
            patch.object(
                self.manager,
                "_acquire_parent_takeover_lock",
                return_value=task_manager_module.ParentTakeoverAttemptResult(
                    acquired=True,
                    task_id=task.id,
                    lock=task_manager_module.ParentTakeoverLock(
                        task_id=task.id,
                        lock_token="unit-test-lock",
                        ttl_seconds=60,
                        instance_id=self.manager.instance_id,
                    ),
                ),
            ),
            patch.object(self.manager, "_release_parent_takeover_lock", return_value=True),
            patch.object(self.manager, "_clear_runtime_lease") as clear_lease_mock,
        ):
            repaired = self.manager._repair_running_lease_invariant(
                db,
                task,
                reason="unit_test_release",
            )

        self.assertTrue(repaired)
        self.assertEqual([(task.id, "owned_execution_release_for_takeover")], requeue_calls)
        clear_lease_mock.assert_not_called()
        self.assertEqual("pending", task.status)
        event_types = [event.event_type for event in db.events]
        self.assertIn("running_without_active_lease_requeued", event_types)

    async def test_released_parent_takeover_reconcile_requeues_pending_task_with_progress(self):
        task = self._task(
            status="pending",
            updated_at=_now() - timedelta(minutes=2),
        )
        run = BinarySecurityStageRun(
            id="run-1",
            task_id=task.id,
            stage_name="entry_analysis",
            status="running",
        )
        item = BinarySecurityStageItem(
            id="item-1",
            task_id=task.id,
            stage_name="entry_analysis",
            status="running",
            downstream_task_id="child-1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item], runtime_leases=[], events=[])

        with patch.object(self.manager, "_enqueue_task_and_wait", AsyncMock(return_value=True)) as enqueue_mock:
            repaired = await self.manager.reconcile_released_parent_tasks_missing_takeover_enqueue(
                db,
                batch_size=5,
                actor="unit-test",
                stale_after_seconds=30,
            )

        self.assertEqual(1, repaired)
        enqueue_mock.assert_awaited()
        self.assertTrue(any(event.event_type == "released_parent_takeover_dispatch_reconciled" for event in db.events))

    async def test_released_parent_takeover_reconcile_skips_stale_candidate_after_new_owner_claim(self):
        task = self._task(
            status="pending",
            updated_at=_now() - timedelta(minutes=2),
        )
        lease = task_manager_module.BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-b",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        with patch.object(
            self.manager,
            "_peek_released_parent_task_missing_takeover_enqueue",
            return_value=task,
        ), patch.object(self.manager, "_enqueue_task_and_wait", AsyncMock(return_value=True)) as enqueue_mock:
            repaired = await self.manager.reconcile_released_parent_tasks_missing_takeover_enqueue(
                db,
                batch_size=1,
                actor="unit-test",
                stale_after_seconds=30,
            )

        self.assertEqual(0, repaired)
        enqueue_mock.assert_not_awaited()
        self.assertFalse(any(event.event_type == "released_parent_takeover_dispatch_reconciled" for event in db.events))

    async def test_reconcile_work_queues_runs_released_takeover_reconcile_before_queue_scan(self):
        db = _ModelAwareDb(tasks=[], events=[])
        queue = _FakeTaskSyncQueue()
        with patch.object(task_manager_module, "get_task_queue", return_value=queue), patch.object(
            self.manager,
            "reconcile_orphan_parent_tasks_missing_initial_enqueue",
            AsyncMock(return_value=0),
        ), patch.object(
            self.manager,
            "reconcile_released_parent_tasks_missing_takeover_enqueue",
            AsyncMock(return_value=1),
        ) as reconcile_mock:
            await TaskRuntimeServiceMixin._reconcile_work_queues_once(self.manager, db)

        reconcile_mock.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
