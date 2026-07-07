import asyncio
import unittest
from unittest.mock import patch

from app import runtime_health
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now


class _FakeSyncMaintenanceThreadHandle:
    def __init__(self, name: str = "sync-thread"):
        self._name = name
        self._done = False
        self._cancelled = False

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


class _FakeQuery:
    def __init__(self, task):
        self._task = task

    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        return self._task


class _FakeSession:
    def __init__(self, task):
        self._task = task
        self.executed = []

    def query(self, *_args, **_kwargs):
        return _FakeQuery(self._task)

    def execute(self, statement, params=None):
        self.executed.append((str(statement), dict(params or {})))
        return None

    def close(self):
        return None

    def commit(self):
        return None

    def rollback(self):
        return None


class TaskRuntimeLeaseWatchdogTests(unittest.IsolatedAsyncioTestCase):
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

    async def test_watchdog_starts_and_stops(self):
        manager = TaskManager()
        manager._running = True
        manager._runtime_loop = asyncio.get_running_loop()

        manager._start_runtime_lease_watchdog()
        await asyncio.sleep(0.05)
        snapshot = manager._lease_watchdog_status_snapshot()
        self.assertTrue(snapshot["alive"])
        self.assertIsNotNone(snapshot["last_tick_at"])

        manager._running = False
        manager._lease_watchdog_stop_event.set()
        await asyncio.to_thread(manager._stop_runtime_lease_watchdog)
        self.assertFalse(manager._lease_watchdog_alive())

    async def test_runtime_session_fast_lock_timeout_is_best_effort(self):
        manager = TaskManager()
        session = _FakeSession(task=None)

        manager._configure_runtime_session_fast_lock_wait_timeout(session)
        manager._configure_runtime_session_fast_lock_wait_timeout(object())

        self.assertEqual(1, len(session.executed))
        statement, params = session.executed[0]
        self.assertIn("innodb_lock_wait_timeout", statement)
        self.assertEqual(3, params["seconds"])

    async def test_watchdog_refreshes_runtime_lease_without_per_task_heartbeat_write(self):
        manager = TaskManager()
        manager._running = True
        manager._runtime_loop = asyncio.get_running_loop()
        manager.instance_id = "worker-a"
        refreshed = asyncio.Event()
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
        sync_task = _FakeSyncMaintenanceThreadHandle(name="sync")
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
        manager._assert_active_runtime_lease_owner = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=True,
            runtime_lease_present=True,
            runtime_lease_active=True,
            runtime_lease_owner="worker-a",
            local_handle_alive=True,
        )

        def _write(_db, task_id, **_kwargs):
            self.assertEqual("task-1", task_id)
            handle.last_lease_refresh_at = _now()
            refreshed.set()
            return True

        manager._write_task_heartbeat = _write

        try:
            with patch("app.service.task_manager.get_session_factory", return_value=lambda: _FakeSession(task)):
                manager._start_runtime_lease_watchdog()
                await asyncio.wait_for(refreshed.wait(), timeout=1)
        finally:
            manager._running = False
            manager._lease_watchdog_stop_event.set()
            await asyncio.to_thread(manager._stop_runtime_lease_watchdog)
            handle.cancel()
            await asyncio.gather(runner_task, heartbeat_task, return_exceptions=True)

        self.assertIsNotNone(handle.last_lease_refresh_at)

    async def test_verify_runtime_lease_abort_cancels_runner_heartbeat_and_sync_tasks(self):
        manager = TaskManager()
        manager._running = True
        manager._runtime_loop = asyncio.get_running_loop()
        manager.instance_id = "worker-a"
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
        events: list[tuple[str, dict]] = []
        runner_task = asyncio.create_task(asyncio.sleep(3600), name="runner")
        heartbeat_task = asyncio.create_task(asyncio.sleep(3600), name="heartbeat")
        sync_task = _FakeSyncMaintenanceThreadHandle(name="sync")
        handle = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=runner_task,
            heartbeat_task=heartbeat_task,
            sync_maintenance_task=sync_task,
            claimed_at=_now(),
            execution_token="exec-1",
            lease_owner_instance_id="worker-a",
        )
        manager._workers["task-1"] = handle
        manager._assert_active_runtime_lease_owner = lambda *_args, **_kwargs: task_manager_module._RuntimeLeaseOwnershipDecision(
            should_continue=False,
            abort_reason="runtime_lease_missing",
            runtime_lease_present=False,
            runtime_lease_active=False,
            runtime_lease_owner=None,
            local_handle_alive=True,
        )
        manager._record_event = lambda _db, _task, event_type, _message, **kwargs: events.append((event_type, dict(kwargs.get("payload") or {})))

        try:
            with patch("app.service.task_manager.get_session_factory", return_value=lambda: _FakeSession(task)):
                decision = manager._verify_local_runtime_lease_or_abort("task-1", "runtime_lease_watchdog")
                await asyncio.sleep(0)
        finally:
            await asyncio.gather(runner_task, heartbeat_task, return_exceptions=True)

        self.assertEqual("runtime_lease_missing", decision.abort_reason)
        self.assertTrue(handle.cancel_requested)
        self.assertTrue(runner_task.cancelled())
        self.assertTrue(heartbeat_task.cancelled())
        self.assertTrue(sync_task.cancelled())
        self.assertEqual("runtime_lease_lost_local_execution_aborted", events[-1][0])
        self.assertIn("watchdog_thread_alive", events[-1][1])
        self.assertIn("sync_maintenance_done", events[-1][1])

    def test_runtime_health_owner_readiness_requires_live_non_stale_watchdog(self):
        fake_runtime = {
            "running": True,
            "loops": {},
            "loop_details": {},
            "lease_auditor_active": True,
            "lease_watchdog_alive": True,
            "lease_watchdog_stale": False,
            "event_loop_lag_seconds": 0.2,
        }
        with patch("app.runtime_health.get_config") as mock_get_config, patch(
            "app.runtime_health.get_task_manager"
        ) as mock_get_task_manager:
            mock_get_config.return_value.scheduler.enabled = True
            mock_get_task_manager.return_value.runtime_status.return_value = fake_runtime
            ok, detail = runtime_health._owner_readiness()
        self.assertTrue(ok)
        self.assertTrue(detail["lease_watchdog_alive"])
        self.assertFalse(detail["lease_watchdog_stale"])
