import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now


class TaskRuntimeSyncMaintenanceE2ETests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        pending = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task() and not task.done()
        ]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def test_heavy_sync_maintenance_does_not_block_heartbeat_e2e(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        touch_count = 0
        release_event = asyncio.Event()
        maintenance_started = asyncio.Event()
        runner_task = asyncio.create_task(asyncio.sleep(3600), name="runner")
        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=runner_task,
            heartbeat_task=None,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            active_commit_succeeded=True,
            lease_established=True,
        )
        manager._workers["task-1"] = handle

        async def _handoff(_task_id):
            return False

        def _touch(_task_id):
            nonlocal touch_count
            touch_count += 1
            if touch_count >= 3:
                release_event.set()

        async def _service(_task_id):
            maintenance_started.set()
            await release_event.wait()
            manager._running = False
            return True

        manager._handoff_active_serial_control_operation_from_runtime = _handoff
        manager._touch_task_heartbeat = _touch
        manager._service_local_runtime_sync_maintenance = _service
        manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner="worker-a",
            local_handle_alive=True,
        )

        heartbeat_task = asyncio.create_task(manager._run_task_heartbeat("task-1"), name="hb")
        sync_task = asyncio.create_task(manager._run_task_sync_maintenance("task-1"), name="sync")
        handle.heartbeat_task = heartbeat_task
        handle.sync_maintenance_task = sync_task
        try:
            with patch("app.service.task_manager.asyncio.sleep", new=AsyncMock()):
                await asyncio.wait_for(asyncio.gather(heartbeat_task, sync_task), timeout=1)
        finally:
            runner_task.cancel()
            await asyncio.gather(runner_task, return_exceptions=True)

        self.assertTrue(maintenance_started.is_set())
        self.assertGreaterEqual(touch_count, 3)

    async def test_release_then_takeover_rebuilds_sync_maintenance_worker_e2e(self):
        manager_a = TaskManager()
        manager_a._running = True
        manager_a.instance_id = "worker-a"
        manager_b = TaskManager()
        manager_b._running = True
        manager_b.instance_id = "worker-b"
        started: list[str] = []

        async def _run_task(task_id):
            started.append(f"runner:{task_id}")
            await asyncio.sleep(3600)

        async def _run_heartbeat(task_id):
            started.append(f"heartbeat:{task_id}")
            await asyncio.sleep(3600)

        async def _run_sync_maintenance(task_id):
            started.append(f"sync:{task_id}")
            await asyncio.sleep(3600)

        for manager in (manager_a, manager_b):
            manager._run_task = _run_task
            manager._run_task_heartbeat = _run_heartbeat
            manager._run_task_sync_maintenance = _run_sync_maintenance
            manager._touch_task_heartbeat = lambda *_args, **_kwargs: None

        created_a = await manager_a._start_task_runtime("task-1")
        self.assertTrue(created_a)
        await asyncio.sleep(0)
        handle_a = manager_a._workers["task-1"]
        old_sync = handle_a.sync_maintenance_task

        await manager_a._cancel_local_worker("task-1")

        created_b = await manager_b._start_task_runtime("task-1")
        self.assertTrue(created_b)
        await asyncio.sleep(0)
        handle_b = manager_b._workers["task-1"]
        try:
            self.assertIsNotNone(handle_b.sync_maintenance_task)
            self.assertIsNot(old_sync, handle_b.sync_maintenance_task)
            self.assertTrue(old_sync.cancelled())
            self.assertIn("sync:task-1", started)
        finally:
            handle_b.cancel()
            await asyncio.gather(
                handle_b.runner_task,
                handle_b.heartbeat_task,
                handle_b.sync_maintenance_task,
                return_exceptions=True,
            )

