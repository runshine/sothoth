import asyncio
import threading
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from app.service import task_manager as task_manager_module
from app.service import http_client as http_client_module
from app.model import BinarySecurityTask, BinarySecurityTaskRuntimeLease, TASK_RUNTIME_PHASE_OWNED_EXECUTION, TASK_TYPE_SOURCE
from app.service.task_manager import TaskManager, _now
from test_task_manager import _ModelAwareDb


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

    async def test_task_heartbeat_stops_local_keepalive_for_pending_owned_execution_with_live_local_lease(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        runner_task = asyncio.create_task(asyncio.sleep(3600), name="runner-live")
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="heartbeat-live")
        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=runner_task,
            heartbeat_task=heartbeat_task,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
            active_commit_succeeded=True,
            lease_established=True,
            owner_active=True,
        )
        manager._workers["task-1"] = handle
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="pending",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws-heartbeat-invalid",
            runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id="task-1",
            owner_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], runtime_leases=[lease], events=[])

        async def _handoff(_task_id):
            return False

        def _verify(_task_id, source):
            return task_manager_module._RuntimeLeaseOwnershipDecision(
                should_continue=True,
                runtime_lease_present=True,
                runtime_lease_active=True,
                runtime_lease_owner="worker-a",
                local_handle_alive=True,
                verification_error=None,
            )

        manager._handoff_active_serial_control_operation_from_runtime = _handoff
        manager._verify_local_runtime_lease_or_abort = _verify

        try:
            with (
                patch("app.service.task_manager.get_session_factory", return_value=lambda: db),
                patch("app.service.task_manager.asyncio.sleep", new=AsyncMock()),
            ):
                await manager._run_task_heartbeat("task-1")
        finally:
            runner_task.cancel()
            heartbeat_task.cancel()
            await asyncio.gather(runner_task, return_exceptions=True)
            await asyncio.gather(heartbeat_task, return_exceptions=True)

        self.assertTrue(handle.cancel_requested)
        self.assertEqual("invalid_owned_execution_state", handle.cancel_requested_reason)
        event_types = [row.event_type for row in db.events]
        self.assertIn("runtime_invalid_owned_execution_state_detected", event_types)
        self.assertIn("runtime_invalid_owned_execution_state_local_keepalive_stopped", event_types)

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

    async def test_sync_maintenance_services_periodic_db_fact_reconcile_before_queue_drain(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
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
        manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner="worker-a",
            local_handle_alive=True,
        )
        calls: list[str] = []

        async def _reconcile(_task_id):
            calls.append("reconcile")
            return 1

        async def _drain(*_args, **_kwargs):
            calls.append("drain")
            return False

        manager._reconcile_periodic_task_sync_requests = _reconcile
        manager._drain_local_runtime_sync_queue_once = _drain

        fake_queue = type(
            "_FakeQueue",
            (),
            {
                "consume_owner_signal": AsyncMock(return_value=None),
                "has_due_task_sync_request": AsyncMock(return_value=False),
            },
        )()
        with patch("app.service.task_manager.get_task_queue", return_value=fake_queue):
            processed = await manager._service_local_runtime_sync_maintenance("task-1")

        self.assertTrue(processed)
        self.assertEqual(["reconcile", "drain"], calls)

    async def test_sync_maintenance_skips_empty_high_frequency_pass_without_signal_due_or_periodic_reconcile(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
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
        handle.last_sync_maintenance_progress_at = _now()
        manager._workers["task-1"] = handle
        manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner="worker-a",
            local_handle_alive=True,
        )

        reconcile = AsyncMock(return_value=0)
        drain = AsyncMock(return_value=False)
        manager._reconcile_periodic_task_sync_requests = reconcile
        manager._drain_local_runtime_sync_queue_once = drain

        fake_queue = type(
            "_FakeQueue",
            (),
            {
                "consume_owner_signal": AsyncMock(return_value=None),
                "has_due_task_sync_request": AsyncMock(return_value=False),
            },
        )()
        with patch("app.service.task_manager.get_task_queue", return_value=fake_queue):
            processed = await manager._service_local_runtime_sync_maintenance("task-1")

        self.assertFalse(processed)
        reconcile.assert_not_awaited()
        drain.assert_not_awaited()
        fake_queue.has_due_task_sync_request.assert_awaited_once()

    async def test_sync_maintenance_worker_thread_does_not_exit_only_because_runner_task_is_done(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        runner_task = asyncio.create_task(asyncio.sleep(0), name="runner-done")
        await asyncio.gather(runner_task, return_exceptions=True)
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
        manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner="worker-a",
            local_handle_alive=True,
        )
        processed_calls = {"count": 0}

        def _service(_task_id):
            processed_calls["count"] += 1
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

        self.assertEqual(1, processed_calls["count"])

    async def test_sync_maintenance_thread_reuses_single_loop_for_multiple_passes(self):
        manager = TaskManager()
        manager._running = True
        manager.instance_id = "worker-a"
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="hb")
        stop_event = threading.Event()
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
        loop_ids: list[int] = []
        call_count = {"count": 0}

        async def _local_service(_task_id: str) -> bool:
            call_count["count"] += 1
            client = await http_client_module.get_shared_async_client("sync-maint-test", timeout=3)
            self.assertFalse(client.is_closed)
            loop_ids.append(id(asyncio.get_running_loop()))
            if call_count["count"] >= 2:
                manager._running = False
                stop_event.set()
            return True

        manager._service_local_runtime_sync_maintenance = _local_service

        try:
            await asyncio.to_thread(
                manager._run_task_sync_maintenance_thread_worker,
                "task-1",
                stop_event,
            )
        finally:
            stop_event.set()
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)

        self.assertGreaterEqual(len(loop_ids), 2)
        self.assertEqual(1, len(set(loop_ids)))

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

    async def test_process_task_sync_entry_blocking_uses_async_bridge_instead_of_direct_asyncio_run(self):
        manager = TaskManager()
        bridge_calls: list[str] = []

        class _FakeSession:
            def close(self):
                return None

        async def _fake_sync(*_args, **_kwargs):
            return None

        def _fake_bridge(coro):
            bridge_calls.append(type(coro).__name__)
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

        manager.sync_downstream_status = _fake_sync
        manager._run_async_blocking = _fake_bridge
        with patch("app.service.task_manager.get_session_factory", return_value=lambda: _FakeSession()):
            await asyncio.to_thread(
                manager._process_task_sync_entry_blocking,
                "project-1",
                "task-1",
                "child_sync",
                "entry_analysis",
                ["item-1"],
                False,
            )

        self.assertEqual(["coroutine"], bridge_calls)

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
