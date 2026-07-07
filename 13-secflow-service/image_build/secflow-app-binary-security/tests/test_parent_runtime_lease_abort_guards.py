import asyncio
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from app.model import BinarySecurityTask, BinarySecurityTaskRuntimeLease, TASK_RUNTIME_PHASE_OWNED_EXECUTION, TASK_TYPE_BINARY
from app.service.task_manager import TaskManager, _now
from test_task_manager import _ModelAwareDb


class ParentRuntimeLeaseAbortGuardTests(unittest.IsolatedAsyncioTestCase):
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

    def test_assert_active_runtime_lease_owner_detects_owner_change(self):
        task = self._task()
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-b",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        decision = self.manager._assert_active_runtime_lease_owner(
            db,
            task.id,
            expected_owner="worker-a",
        )

        self.assertFalse(decision.should_continue)
        self.assertEqual("runtime_lease_owner_changed", decision.abort_reason)
        self.assertEqual("worker-b", decision.runtime_lease_owner)

    async def test_service_local_runtime_sync_maintenance_aborts_when_lease_is_lost(self):
        task = self._task()
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id="worker-b",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])
        runner_task = asyncio.create_task(asyncio.sleep(3600))
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600))
        self.addAsyncCleanup(runner_task.cancel)
        self.addAsyncCleanup(heartbeat_task.cancel)
        handle = SimpleNamespace(
            done=lambda: False,
            cancel_requested=False,
            release_requested=False,
            takeover_observed=False,
            runner_task=runner_task,
            heartbeat_task=heartbeat_task,
            active_commit_succeeded=True,
            lease_established=True,
            sync_maintenance_in_progress=False,
            owner_active=True,
        )
        self.manager._workers[task.id] = handle

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            with self.assertRaisesRegex(Exception, "runtime lease 已失效"):
                await self.manager._service_local_runtime_sync_maintenance(task.id)

        self.assertTrue(handle.cancel_requested)
        self.assertTrue(any(event.event_type == "runtime_lease_lost_local_execution_aborted" for event in db.events))


if __name__ == "__main__":
    unittest.main()
