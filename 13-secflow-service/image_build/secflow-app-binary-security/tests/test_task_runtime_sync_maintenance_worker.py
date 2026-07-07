import asyncio
import threading
import unittest
from unittest.mock import AsyncMock, patch

from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now


class _FakeSyncMaintenanceThreadHandle:
    def __init__(self, name: str = "sync-thread"):
        self._name = name
        self._done = False
        self._cancelled = False
        self.thread = type("_Thread", (), {"start": lambda _self: None})()

    def done(self):
        return self._done

    def cancel(self):
        self._cancelled = True
        self._done = True

    def cancelled(self):
        return self._cancelled

    def get_name(self):
        return self._name

    def join(self, timeout=None):
        self._done = True
        return None


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

    async def test_task_heartbeat_does_not_invoke_sync_maintenance_or_write_lease(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        verify_calls: list[str] = []
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

        def _verify(_task_id, source):
            verify_calls.append(source)
            return task_manager_module._RuntimeLeaseOwnershipDecision(
                should_continue=True,
                runtime_lease_present=True,
                runtime_lease_active=True,
                runtime_lease_owner="worker-a",
                local_handle_alive=True,
            )

        manager._handoff_active_serial_control_operation_from_runtime = _handoff
        manager._service_local_runtime_sync_maintenance = AsyncMock()
        manager._verify_local_runtime_lease_or_abort = _verify
        manager._touch_task_heartbeat = lambda *_args, **_kwargs: self.fail("heartbeat should not write lease directly")

        with patch("app.service.task_manager.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            await manager._run_task_heartbeat("task-1")

        self.assertEqual(["heartbeat_verify"], verify_calls)
        manager._service_local_runtime_sync_maintenance.assert_not_awaited()
        sleep_mock.assert_awaited()

    async def test_sync_maintenance_worker_thread_invokes_task_sync_maintenance(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        processed = threading.Event()
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

        def _service(_task_id):
            processed.set()
            manager._running = False
            return True

        manager._service_local_runtime_sync_maintenance_blocking = _service

        try:
            await asyncio.to_thread(
                manager._run_task_sync_maintenance_thread_worker,
                "task-1",
                threading.Event(),
            )
        finally:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)

        self.assertTrue(processed.is_set())

    async def test_process_task_sync_entry_blocking_runs_child_sync_with_thread_owned_session(self):
        manager = TaskManager()
        calls: list[tuple[str, str, str | None, list[str], bool]] = []

        class _FakeSession:
            def close(self):
                return None

        async def _fake_sync(
            _db,
            *,
            project_id,
            task_id,
            stage_name=None,
            item_ids=None,
            force=False,
            **kwargs,
        ):
            del _db, kwargs
            calls.append((project_id, task_id, stage_name, list(item_ids or []), force))
            return None

        manager.sync_downstream_status = _fake_sync
        with patch("app.service.task_manager.get_session_factory", return_value=lambda: _FakeSession()):
            await asyncio.to_thread(
                manager._process_task_sync_entry_blocking,
                "project-1",
                "task-1",
                "child_sync",
                "entry_analysis",
                ["item-1"],
                True,
            )

        self.assertEqual(
            [("project-1", "task-1", "entry_analysis", ["item-1"], True)],
            calls,
        )

    async def test_sync_maintenance_worker_exits_after_lease_loss(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        runner_task = asyncio.create_task(asyncio.sleep(3600), name="runner")
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="hb")
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
            await asyncio.to_thread(
                manager._run_task_sync_maintenance_thread_worker,
                "task-1",
                threading.Event(),
            )
        finally:
            runner_task.cancel()
            heartbeat_task.cancel()
            await asyncio.gather(runner_task, heartbeat_task, return_exceptions=True)

        manager._service_local_runtime_sync_maintenance.assert_not_awaited()

    async def test_cancel_local_worker_cancels_sync_maintenance_worker(self):
        manager = TaskManager()
        manager._running = True
        sync_handle = _FakeSyncMaintenanceThreadHandle()

        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=asyncio.create_task(asyncio.sleep(3600), name="runner"),
            heartbeat_task=asyncio.create_task(asyncio.sleep(3600), name="heartbeat"),
            sync_maintenance_task=sync_handle,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
        )
        manager._workers["task-1"] = handle
        await asyncio.sleep(0)

        await manager._cancel_local_worker("task-1")

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

        manager._build_runtime_sync_maintenance_thread = lambda task_id: (
            started.append(f"sync:{task_id}") or _FakeSyncMaintenanceThreadHandle(name=f"sync:{task_id}")
        )

        manager._run_task = _run_task
        manager._run_task_heartbeat = _run_heartbeat

        old_runner = asyncio.create_task(asyncio.sleep(0), name="old-runner")
        await asyncio.gather(old_runner, return_exceptions=True)
        old_heartbeat = asyncio.create_task(asyncio.sleep(3600), name="old-heartbeat")
        old_sync = _FakeSyncMaintenanceThreadHandle(name="old-sync")
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
                return_exceptions=True,
            )
            manager._workers["task-1"].sync_maintenance_task.join()
            old_heartbeat.cancel()
            old_sync.cancel()
            await asyncio.gather(old_heartbeat, return_exceptions=True)

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

        def _service(_task_id):
            raise RuntimeError("boom")

        async def _handoff(_task_id):
            return True

        manager._verify_local_runtime_lease_or_abort = _verify
        manager._service_local_runtime_sync_maintenance_blocking = _service
        manager._handoff_active_serial_control_operation_from_runtime = _handoff
        manager._touch_task_heartbeat = lambda *_args, **_kwargs: None

        runner_cancelled_before_cleanup = None
        try:
            stop_event = threading.Event()
            with patch.object(stop_event, "wait", side_effect=lambda _timeout=None: setattr(manager, "_running", False) or False):
                await asyncio.to_thread(
                    manager._run_task_sync_maintenance_thread_worker,
                    "task-1",
                    stop_event,
                )
            handed_off = await manager._handoff_active_serial_control_operation_from_runtime("task-1")
            runner_cancelled_before_cleanup = handle.runner_task.cancelled()
        finally:
            runner_task.cancel()
            heartbeat_task.cancel()
            await asyncio.gather(runner_task, heartbeat_task, return_exceptions=True)

        self.assertTrue(handed_off)
        self.assertFalse(handle.cancel_requested)
        self.assertFalse(bool(runner_cancelled_before_cleanup))
