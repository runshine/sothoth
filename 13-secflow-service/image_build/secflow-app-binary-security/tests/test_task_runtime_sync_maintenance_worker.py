import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now


class TaskRuntimeSyncMaintenanceWorkerTests(unittest.IsolatedAsyncioTestCase):
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

    async def test_task_heartbeat_does_not_invoke_sync_maintenance(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        touched = asyncio.Event()
        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=asyncio.current_task(),
            heartbeat_task=None,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            active_commit_succeeded=True,
            lease_established=True,
        )
        manager._workers["task-1"] = handle

        async def _handoff(_task_id):
            manager._running = False
            return False

        def _touch(_task_id):
            touched.set()

        manager._handoff_active_serial_control_operation_from_runtime = _handoff
        manager._touch_task_heartbeat = _touch
        manager._service_local_runtime_sync_maintenance = AsyncMock()
        manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner="worker-a",
            local_handle_alive=True,
        )

        with patch("app.service.task_manager.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            await manager._run_task_heartbeat("task-1")

        self.assertTrue(touched.is_set())
        manager._service_local_runtime_sync_maintenance.assert_not_awaited()
        sleep_mock.assert_awaited()

    async def test_sync_maintenance_worker_invokes_task_sync_maintenance(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        processed = asyncio.Event()
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="hb")
        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=asyncio.current_task(),
            heartbeat_task=heartbeat_task,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            active_commit_succeeded=True,
            lease_established=True,
        )
        manager._workers["task-1"] = handle
        manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner="worker-a",
            local_handle_alive=True,
        )

        async def _service(_task_id):
            processed.set()
            manager._running = False
            return True

        manager._service_local_runtime_sync_maintenance = _service

        try:
            with patch("app.service.task_manager.asyncio.sleep", new=AsyncMock()):
                await manager._run_task_sync_maintenance("task-1")
        finally:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)

        self.assertTrue(processed.is_set())

    async def test_sync_maintenance_worker_exits_after_lease_loss(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="hb")
        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=asyncio.current_task(),
            heartbeat_task=heartbeat_task,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            active_commit_succeeded=True,
            lease_established=True,
        )
        manager._workers["task-1"] = handle
        manager._service_local_runtime_sync_maintenance = AsyncMock()
        manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=False,
            abort_reason="runtime_lease_missing",
            runtime_lease_present=False,
            runtime_lease_active=False,
            runtime_lease_owner=None,
            local_handle_alive=True,
        )

        try:
            with patch("app.service.task_manager.asyncio.sleep", new=AsyncMock()):
                await manager._run_task_sync_maintenance("task-1")
        finally:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)

        manager._service_local_runtime_sync_maintenance.assert_not_awaited()

    async def test_cancel_local_worker_cancels_sync_maintenance_worker(self):
        manager = TaskManager()
        manager._running = True
        cancelled = asyncio.Event()

        async def _sync_maintenance():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=asyncio.create_task(asyncio.sleep(3600), name="runner"),
            heartbeat_task=asyncio.create_task(asyncio.sleep(3600), name="heartbeat"),
            sync_maintenance_task=asyncio.create_task(_sync_maintenance(), name="sync"),
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
        )
        manager._workers["task-1"] = handle
        await asyncio.sleep(0)

        await manager._cancel_local_worker("task-1")

        self.assertTrue(cancelled.is_set())
        self.assertTrue(handle.runner_task.cancelled())
        self.assertTrue(handle.heartbeat_task.cancelled())
        self.assertTrue(handle.sync_maintenance_task.cancelled())

    async def test_restart_local_runtime_for_active_owner_recreates_sync_maintenance_worker(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
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

        manager._run_task = _run_task
        manager._run_task_heartbeat = _run_heartbeat
        manager._run_task_sync_maintenance = _run_sync_maintenance

        old_runner = asyncio.create_task(asyncio.sleep(0), name="old-runner")
        await asyncio.gather(old_runner, return_exceptions=True)
        old_heartbeat = asyncio.create_task(asyncio.sleep(3600), name="old-heartbeat")
        old_sync = asyncio.create_task(asyncio.sleep(3600), name="old-sync")
        existing = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=old_runner,
            heartbeat_task=old_heartbeat,
            sync_maintenance_task=old_sync,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            cancel_requested=True,
            runner_generation=2,
        )
        manager._workers["task-1"] = existing

        try:
            restarted = await manager._restart_local_runtime_for_active_owner("task-1")
            self.assertTrue(restarted)
            handle = manager._workers["task-1"]
            await asyncio.sleep(0)
            self.assertIsNot(existing, handle)
            self.assertIsNotNone(handle.sync_maintenance_task)
            self.assertEqual("exec-1", handle.execution_token)
            self.assertEqual(3, handle.runner_generation)
            self.assertIn("runner:task-1", started)
            self.assertIn("heartbeat:task-1", started)
            self.assertIn("sync:task-1", started)
        finally:
            manager._workers["task-1"].cancel()
            await asyncio.gather(
                manager._workers["task-1"].runner_task,
                manager._workers["task-1"].heartbeat_task,
                manager._workers["task-1"].sync_maintenance_task,
                return_exceptions=True,
            )
            old_heartbeat.cancel()
            old_sync.cancel()
            await asyncio.gather(old_heartbeat, old_sync, return_exceptions=True)

    async def test_sync_maintenance_worker_exception_does_not_cancel_runner_or_block_control_handoff(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        runner_task = asyncio.create_task(asyncio.sleep(3600), name="runner")
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="heartbeat")
        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=runner_task,
            heartbeat_task=heartbeat_task,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            active_commit_succeeded=True,
            lease_established=True,
        )
        manager._workers["task-1"] = handle
        calls = {"count": 0}

        def _verify(*_args, **_kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                return task_manager_module._RuntimeLeaseOwnershipDecision(
                    should_continue=True,
                    runtime_lease_present=True,
                    runtime_lease_active=True,
                    runtime_lease_owner="worker-a",
                    local_handle_alive=True,
                )
            manager._running = False
            return task_manager_module._RuntimeLeaseOwnershipDecision(
                should_continue=False,
                abort_reason="runtime_lease_missing",
                runtime_lease_present=False,
                runtime_lease_active=False,
                runtime_lease_owner=None,
                local_handle_alive=True,
            )

        async def _service(_task_id):
            raise RuntimeError("boom")

        async def _handoff(_task_id):
            return True

        manager._verify_local_runtime_lease_or_abort = _verify
        manager._service_local_runtime_sync_maintenance = _service
        manager._handoff_active_serial_control_operation_from_runtime = _handoff
        manager._touch_task_heartbeat = lambda *_args, **_kwargs: None

        runner_cancelled_before_cleanup = None
        try:
            with patch("app.service.task_manager.asyncio.sleep", new=AsyncMock()):
                await manager._run_task_sync_maintenance("task-1")
            handed_off = await manager._handoff_active_serial_control_operation_from_runtime("task-1")
            runner_cancelled_before_cleanup = handle.runner_task.cancelled()
        finally:
            runner_task.cancel()
            heartbeat_task.cancel()
            await asyncio.gather(runner_task, heartbeat_task, return_exceptions=True)

        self.assertTrue(handed_off)
        self.assertFalse(handle.cancel_requested)
        self.assertFalse(bool(runner_cancelled_before_cleanup))
