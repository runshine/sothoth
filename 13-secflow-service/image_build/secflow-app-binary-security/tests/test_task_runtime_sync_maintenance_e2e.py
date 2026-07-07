import asyncio
import unittest
from unittest.mock import patch

from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now
from test_task_manager import _FakeTaskSyncQueue


class TaskRuntimeSyncMaintenanceE2ETests(unittest.TestCase):
    def test_heavy_sync_maintenance_does_not_block_watchdog_lease_refresh_e2e(self):
        async def _exercise():
            manager = TaskManager()
            manager._running = True
            manager.instance_id = "worker-a"
            manager._runtime_loop = asyncio.get_running_loop()
            refresh_count = 0
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

            async def _service(_task_id):
                maintenance_started.set()
                await release_event.wait()
                manager._running = False
                return True

            manager._service_local_runtime_sync_maintenance = _service
            manager._runtime_watchdog_interval_seconds = lambda: 1
            manager._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
                should_continue=True,
                runtime_lease_present=True,
                runtime_lease_active=True,
                runtime_lease_owner="worker-a",
                local_handle_alive=True,
            )
            manager._assert_active_runtime_lease_owner = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
                should_continue=True,
                runtime_lease_present=True,
                runtime_lease_active=True,
                runtime_lease_owner="worker-a",
                local_handle_alive=True,
            )
            class _FakeQuery:
                def filter(self, *_args, **_kwargs):
                    return self

                def first(self):
                    return task_manager_module.BinarySecurityTask(
                        id="task-1",
                        project_id="project-1",
                        name="task",
                        status="running",
                        current_stage="entry_analysis",
                        task_type="binary",
                        workspace_root="/tmp/ws",
                        output_root="/tmp/out",
                    )

            class _FakeSession:
                def query(self, *_args, **_kwargs):
                    return _FakeQuery()

                def close(self):
                    return None

                def commit(self):
                    return None

                def rollback(self):
                    return None

            def _write(_db, _task_id, **_kwargs):
                nonlocal refresh_count
                refresh_count += 1
                handle.last_lease_refresh_at = _now()
                if refresh_count >= 2:
                    manager._runtime_loop.call_soon_threadsafe(release_event.set)
                return True

            sync_task = asyncio.create_task(manager._run_task_sync_maintenance("task-1"), name="sync")
            handle.sync_maintenance_task = sync_task
            try:
                manager._write_task_heartbeat = _write
                with patch("app.service.task_manager.get_session_factory", return_value=lambda: _FakeSession()):
                    manager._start_runtime_lease_watchdog()
                    await asyncio.wait_for(release_event.wait(), timeout=3)
            finally:
                manager._running = False
                manager._lease_watchdog_stop_event.set()
                await asyncio.to_thread(manager._stop_runtime_lease_watchdog)
                release_event.set()
                for task in (sync_task, runner_task):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(sync_task, runner_task, return_exceptions=True)
            return maintenance_started.is_set(), refresh_count

        maintenance_started, refresh_count = asyncio.run(_exercise())
        self.assertTrue(maintenance_started)
        self.assertGreaterEqual(refresh_count, 2)

    def test_release_then_takeover_rebuilds_sync_maintenance_worker_e2e(self):
        async def _exercise():
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
            await asyncio.sleep(0)
            handle_a = manager_a._workers["task-1"]
            old_sync = handle_a.sync_maintenance_task

            await manager_a._cancel_local_worker("task-1")

            created_b = await manager_b._start_task_runtime("task-1")
            await asyncio.sleep(0)
            handle_b = manager_b._workers["task-1"]
            try:
                return (
                    created_a,
                    created_b,
                    old_sync.cancelled(),
                    handle_b.sync_maintenance_task is not None,
                    old_sync is not handle_b.sync_maintenance_task,
                    list(started),
                    handle_b,
                )
            finally:
                handle_b.cancel()
                await asyncio.gather(
                    handle_b.runner_task,
                    handle_b.heartbeat_task,
                    handle_b.sync_maintenance_task,
                    return_exceptions=True,
                )

        created_a, created_b, old_sync_cancelled, new_sync_present, new_sync_distinct, started, _handle_b = asyncio.run(_exercise())
        self.assertTrue(created_a)
        self.assertTrue(created_b)
        self.assertTrue(old_sync_cancelled)
        self.assertTrue(new_sync_present)
        self.assertTrue(new_sync_distinct)
        self.assertIn("sync:task-1", started)

    def test_takeover_runtime_sync_maintenance_consumes_existing_owner_signal_e2e(self):
        async def _exercise():
            manager_a = TaskManager()
            manager_a._running = True
            manager_a.instance_id = "worker-a"
            manager_b = TaskManager()
            manager_b._running = True
            manager_b.instance_id = "worker-b"
            fake_queue = _FakeTaskSyncQueue()
            drain_calls: list[tuple[str, str, int]] = []

            async def _run_task(_task_id):
                await asyncio.sleep(3600)

            async def _run_heartbeat(_task_id):
                await asyncio.sleep(3600)

            async def _run_sync_maintenance(_task_id):
                await asyncio.sleep(3600)

            for manager in (manager_a, manager_b):
                manager._run_task = _run_task
                manager._run_task_heartbeat = _run_heartbeat
                manager._run_task_sync_maintenance = _run_sync_maintenance
                manager._touch_task_heartbeat = lambda *_args, **_kwargs: None

            async def _fake_drain(task_id, *, reason, max_passes=1):
                drain_calls.append((str(task_id), str(reason), int(max_passes)))
                return True

            manager_b._drain_local_runtime_sync_queue_once = _fake_drain
            manager_b._verify_local_runtime_lease_or_abort = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
                should_continue=True,
                runtime_lease_present=True,
                runtime_lease_active=True,
                runtime_lease_owner="worker-b",
                local_handle_alive=True,
            )

            with patch.object(task_manager_module, "get_task_queue", return_value=fake_queue):
                created_a = await manager_a._start_task_runtime("task-source-1")
                await asyncio.sleep(0)
                await manager_a._cancel_local_worker("task-source-1")
                created_b = await manager_b._start_task_runtime("task-source-1")
                await asyncio.sleep(0)
                handle_b = manager_b._workers["task-source-1"]
                handle_b.active_commit_succeeded = True
                handle_b.lease_established = True
                await fake_queue.push_owner_signal("worker-b", "task-source-1", context="owner_reconcile_signal_enqueue")
                processed = await manager_b._service_local_runtime_sync_maintenance("task-source-1")
                handle_b.cancel()
                await asyncio.gather(
                    handle_b.runner_task,
                    handle_b.heartbeat_task,
                    handle_b.sync_maintenance_task,
                    return_exceptions=True,
                )
            return created_a, created_b, processed, list(drain_calls), fake_queue

        created_a, created_b, processed, drain_calls, fake_queue = asyncio.run(_exercise())
        self.assertTrue(created_a)
        self.assertTrue(created_b)
        self.assertTrue(processed)
        self.assertEqual([("task-source-1", "owner_reconcile_signal_enqueue", 1)], drain_calls)
        self.assertNotIn(("worker-b", "task-source-1"), fake_queue.owner_signals)

    def test_watchdog_forces_local_abort_after_lease_loss_e2e(self):
        async def _exercise():
            manager = TaskManager()
            manager._running = True
            manager.instance_id = "worker-a"
            manager._runtime_loop = asyncio.get_running_loop()
            abort_seen = asyncio.Event()
            task = task_manager_module.BinarySecurityTask(
                id="task-1",
                project_id="project-1",
                name="task",
                status="running",
                current_stage="entry_analysis",
                task_type="binary",
                workspace_root="/tmp/ws",
                output_root="/tmp/out",
            )
            runner_task = asyncio.create_task(asyncio.sleep(3600), name="runner")
            heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="heartbeat")
            sync_task = asyncio.create_task(asyncio.sleep(3600), name="sync")
            handle = task_manager_module.TaskRuntimeHandle(
                task_id="task-1",
                runner_task=runner_task,
                heartbeat_task=heartbeat_task,
                sync_maintenance_task=sync_task,
                claimed_at=_now(),
                execution_token="exec-1",
                lease_owner_instance_id="worker-a",
                active_commit_succeeded=True,
                lease_established=True,
            )
            manager._workers["task-1"] = handle
            manager._runtime_watchdog_interval_seconds = lambda: 1
            states = [
                task_manager_module._RuntimeLeaseOwnershipDecision(
                    should_continue=True,
                    runtime_lease_present=True,
                    runtime_lease_active=True,
                    runtime_lease_owner="worker-a",
                    local_handle_alive=True,
                ),
                task_manager_module._RuntimeLeaseOwnershipDecision(
                    should_continue=False,
                    abort_reason="runtime_lease_missing",
                    runtime_lease_present=False,
                    runtime_lease_active=False,
                    runtime_lease_owner=None,
                    local_handle_alive=True,
                ),
            ]

            def _assert(*_args, **_kwargs):
                return states[0] if len(states) == 1 else states.pop(0)

            class _FakeQuery:
                def filter(self, *_args, **_kwargs):
                    return self

                def first(self):
                    return task

            class _FakeSession:
                def query(self, *_args, **_kwargs):
                    return _FakeQuery()

                def close(self):
                    return None

                def commit(self):
                    return None

                def rollback(self):
                    return None

            manager._assert_active_runtime_lease_owner = _assert
            manager._write_task_heartbeat = lambda *_args, **_kwargs: True
            manager._record_event = lambda *_args, **_kwargs: None
            original_verify = manager._verify_local_runtime_lease_or_abort

            def _verify(task_id, source):
                decision = original_verify(task_id, source)
                if not decision.should_continue:
                    manager._runtime_loop.call_soon_threadsafe(abort_seen.set)
                return decision

            manager._verify_local_runtime_lease_or_abort = _verify
            try:
                with patch("app.service.task_manager.get_session_factory", return_value=lambda: _FakeSession()):
                    manager._start_runtime_lease_watchdog()
                    await asyncio.wait_for(abort_seen.wait(), timeout=3)
                    await asyncio.sleep(0)
            finally:
                manager._running = False
                manager._lease_watchdog_stop_event.set()
                await asyncio.to_thread(manager._stop_runtime_lease_watchdog)
                await asyncio.gather(runner_task, heartbeat_task, sync_task, return_exceptions=True)
            return runner_task.cancelled(), heartbeat_task.cancelled(), sync_task.cancelled()

        runner_cancelled, heartbeat_cancelled, sync_cancelled = asyncio.run(_exercise())
        self.assertTrue(runner_cancelled)
        self.assertTrue(heartbeat_cancelled)
        self.assertTrue(sync_cancelled)
