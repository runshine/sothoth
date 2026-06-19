import asyncio
import unittest
from datetime import timedelta
from contextlib import suppress
from unittest.mock import patch

from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskOperation,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import StaleTaskExecution, TaskManager, _now
from test_task_manager import _ModelAwareDb


class TaskManagerRuntimeStatusTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_task_runtime_phase_defaults_to_owned_execution_for_streaming_task_without_explicit_phase(self):
        task = BinarySecurityTask(
            id="task-phase-default",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            status="pending",
            current_stage="dataflow_vuln_scan",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id=None,
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}

        self.assertEqual("owned_execution", self.manager._task_runtime_phase(task))

    def test_runtime_status_reports_reducer_snapshot_loop(self):
        self.manager._running = True

        class _Task:
            def __init__(self, done):
                self._done = done

            def done(self):
                return self._done

        self.manager._loop_task = _Task(False)
        self.manager._operation_loop_task = _Task(False)
        self.manager._archive_loop_task = _Task(True)
        self.manager._stage_item_loop_task = _Task(False)
        self.manager._downstream_reconcile_task = _Task(False)
        self.manager._readless_reconcile_task = _Task(False)
        self.manager._state_reducer_loop_task = _Task(False)
        self.manager._reducer_metrics_snapshot_loop_task = _Task(False)

        status = self.manager.runtime_status()

        self.assertTrue(status["running"])
        self.assertEqual(
            {
                "task_dispatch": True,
                "archive_dispatch": False,
                "stage_item_dispatch": True,
                "state_reducer": True,
                "reducer_metrics_snapshot": True,
            },
            status["loops"],
        )
        self.assertEqual(0, status["workers"]["stage_item_workers"])

    def test_runtime_status_marks_stale_loop_details(self):
        self.manager._running = True

        class _Task:
            def done(self):
                return False

        self.manager._archive_loop_task = _Task()
        self.manager.cfg.scheduler.worker_ready_loop_stale_seconds = 30
        self.manager.cfg.queue.block_timeout_seconds = 5
        self.manager._loop_heartbeats["archive_dispatch"] = _now() - timedelta(seconds=60)

        status = self.manager.runtime_status()

        self.assertTrue(status["loops"]["archive_dispatch"])
        self.assertTrue(status["loop_details"]["archive_dispatch"]["stale"])

    def test_runtime_status_uses_recent_heartbeat_when_task_handle_is_done(self):
        self.manager._running = True

        class _Task:
            def done(self):
                return True

        self.manager._archive_loop_task = _Task()
        self.manager.cfg.scheduler.worker_ready_loop_stale_seconds = 30
        self.manager._loop_heartbeats["archive_dispatch"] = _now()

        status = self.manager.runtime_status()

        self.assertTrue(status["loops"]["archive_dispatch"])
        self.assertFalse(status["loop_details"]["archive_dispatch"]["stale"])
        self.assertFalse(status["loop_details"]["archive_dispatch"]["task_running"])
        self.assertTrue(status["loop_details"]["archive_dispatch"]["heartbeat_alive"])

    def test_runtime_status_marks_tail_reconcile_capable_for_live_reducer_loops(self):
        self.manager._running = True

        class _Task:
            def __init__(self, done=False):
                self._done = done

            def done(self):
                return self._done

        self.manager._state_reducer_loop_task = _Task(False)
        self.manager._reducer_metrics_snapshot_loop_task = _Task(False)
        self.manager._service_role = lambda: "reducer"

        status = self.manager.runtime_status()

        self.assertTrue(status["tail_reconcile_active"])

    def test_task_operation_lock_uses_short_configured_ttl(self):
        self.manager.cfg.scheduler.task_operation_lock_ttl_seconds = 60
        now_value = _now()
        expires_at = self.manager._task_operation_lock_expires_at(now_value=now_value)
        self.assertEqual(60, int((expires_at - now_value).total_seconds()))


class TaskManagerDispatchLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_task_runtime_creates_runner_and_heartbeat_handle(self):
        manager = TaskManager()
        started: list[str] = []
        heartbeat_started = asyncio.Event()

        async def _run_task(task_id):
            started.append(f"runner:{task_id}")
            await asyncio.sleep(0)

        async def _run_heartbeat(task_id):
            started.append(f"heartbeat:{task_id}")
            heartbeat_started.set()
            await asyncio.sleep(3600)

        manager._run_task = _run_task
        manager._run_task_heartbeat = _run_heartbeat

        created = await manager._start_task_runtime("task-1")
        self.assertTrue(created)
        await asyncio.wait_for(heartbeat_started.wait(), timeout=1)

        handle = manager._workers.get("task-1")
        self.assertIsNotNone(handle)
        self.assertIsNotNone(handle.runner_task)
        self.assertIsNotNone(handle.heartbeat_task)
        self.assertIn("runner:task-1", started)
        self.assertIn("heartbeat:task-1", started)

        handle.cancel()
        await asyncio.gather(handle.runner_task, handle.heartbeat_task, return_exceptions=True)
        manager._workers.pop("task-1", None)

    async def test_run_task_finally_cancels_paired_heartbeat(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="dispatching",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        db = _ModelAwareDb(tasks=[task], events=[])
        heartbeat_cancelled = asyncio.Event()

        async def _heartbeat():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                heartbeat_cancelled.set()
                raise

        manager._workers["task-1"] = task_manager_module.TaskRuntimeHandle(
            task_id="task-1",
            runner_task=asyncio.current_task(),
            heartbeat_task=asyncio.create_task(_heartbeat()),
            claimed_at=_now(),
            execution_token=None,
            lease_owner_instance_id="worker-a",
        )
        manager._run_current_task_operation = lambda *_args, **_kwargs: asyncio.sleep(0, result=False)
        manager._run_task_runtime_signals = lambda *_args, **_kwargs: asyncio.sleep(0, result=False)
        manager._execute_task = lambda *_args, **_kwargs: asyncio.sleep(0)

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            with suppress(asyncio.CancelledError):
                await manager._run_task("task-1")

        self.assertTrue(heartbeat_cancelled.is_set())
        self.assertNotIn("task-1", manager._workers)

    def test_recover_loop_db_error_disposes_engine_for_operational_and_timeout_errors(self):
        manager = TaskManager()

        class _Db:
            def __init__(self):
                self.rolled_back = False
                self.closed = False

            def rollback(self):
                self.rolled_back = True

            def close(self):
                self.closed = True

        operational = OperationalError("stmt", {}, RuntimeError("lost connection"))
        pool_timeout = SATimeoutError("pool timeout")

        for exc in (operational, pool_timeout):
            db = _Db()
            with patch("app.service.task_manager.get_engine") as mock_get_engine:
                manager._recover_loop_db_error("operation_dispatch", db, exc)
            self.assertTrue(db.rolled_back)
            self.assertTrue(db.closed)
            mock_get_engine.return_value.dispose.assert_called_once()

    async def test_dispatch_loop_reconciles_queues_even_when_task_queue_is_busy(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.queue.enabled = True
        manager.cfg.queue.block_timeout_seconds = 1
        popped = False
        reconcile_calls = []

        class _Queue:
            async def pop_task(self, _timeout_seconds):
                nonlocal popped
                if not popped:
                    popped = True
                    return "task-1"
                manager._running = False
                return None

        def _dispatch_task_by_id(_db, task_id):
            return task_id

        async def _reconcile(_db):
            reconcile_calls.append("called")

        async def _observe(_db):
            return None

        manager._dispatch_task_by_id = _dispatch_task_by_id
        manager._start_task_runtime = lambda _task_id: asyncio.sleep(0, result=True)
        manager._reconcile_work_queues = _reconcile
        manager._observe_runtime_metrics = _observe

        class _Db:
            class _Query:
                def filter(self, *args, **kwargs):
                    return self

                def first(self):
                    return None

            def query(self, *args, **kwargs):
                return self._Query()

            def close(self):
                return None

        with patch("app.service.task_manager.get_task_queue", return_value=_Queue()):
            with patch("app.service.task_manager.get_session_factory", return_value=lambda: _Db()):
                await manager._dispatch_loop()

        self.assertEqual(["called", "called"], reconcile_calls)

    async def test_dispatch_loop_does_not_log_crash_for_redis_timeout_empty_poll(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.queue.enabled = True
        manager.cfg.queue.block_timeout_seconds = 1
        reconcile_calls = []

        class _Queue:
            async def pop_task(self, _timeout_seconds):
                if not reconcile_calls:
                    return None
                manager._running = False
                return None

        async def _reconcile(_db):
            reconcile_calls.append("called")

        async def _observe(_db):
            return None

        manager._reconcile_work_queues = _reconcile
        manager._observe_runtime_metrics = _observe

        with patch("app.service.task_manager.get_task_queue", return_value=_Queue()), patch(
            "app.service.task_manager.logger.exception"
        ) as logger_exception:
            await manager._dispatch_loop()

        self.assertEqual(["called", "called"], reconcile_calls)
        logger_exception.assert_not_called()

    async def test_run_current_task_operation_repairs_missing_binding_to_latest_active_operation(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        older = BinarySecurityTaskOperation(
            id="op-old",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="continue",
            target_stage="system_analysis",
            status="accepted",
            created_at=_now() - timedelta(minutes=2),
            updated_at=_now() - timedelta(minutes=2),
        )
        newer = BinarySecurityTaskOperation(
            id="op-new",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="system_analysis",
            status="queued",
            created_at=_now() - timedelta(minutes=1),
            updated_at=_now() - timedelta(minutes=1),
        )
        db = _ModelAwareDb(tasks=[task], operations=[older, newer], events=[])

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            repaired = await manager._run_current_task_operation(task.id)

        self.assertTrue(repaired)
        self.assertEqual("op-new", task.current_operation_id)
        self.assertEqual("superseded", older.status)
        self.assertEqual("op-new", older.superseded_by_operation_id)
        self.assertIn("task_operation_binding_repaired", [event.event_type for event in db.events])

    async def test_run_task_runtime_signals_consumes_pending_tail_finalize(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-tail",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        task.summary = {
            "runtime_workset": {
                "pending_tail_finalize": {
                    "requested_at": _now().isoformat(),
                    "source": "task_owner",
                    "reason": "finalize_requested",
                }
            }
        }
        db = _ModelAwareDb(tasks=[task], events=[])
        finalized = []

        def _finalize(_db, _task):
            finalized.append(_task.id)
            _task.status = "success"

        manager._finalize_task = _finalize

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            changed = await manager._run_task_runtime_signals(task.id)

        self.assertTrue(changed)
        self.assertEqual(["task-tail"], finalized)
        self.assertEqual({}, task.summary.get("runtime_workset") or {})

    async def test_operation_progress_heartbeat_keeps_legacy_operation_lease_fields_cleared(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        operation = BinarySecurityTaskOperation(
            id="op-1",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="retry_stage_full",
            target_stage="system_analysis",
            status="running",
            current_step="prepare",
        )

        class _Db:
            def __init__(self):
                self.commits = 0

            def commit(self):
                self.commits += 1

        db = _Db()

        await manager._operation_progress_heartbeat(
            db,
            task,
            operation,
            step_name="prepare",
            payload={"phase": "resume"},
        )

        self.assertEqual(1, db.commits)
        self.assertEqual("running", operation.step_payload["prepare"]["status"])

    async def test_repair_replacement_binding_state_preserves_in_place_restart_binding_for_same_child_id(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-bind",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        item = BinarySecurityStageItem(
            id="item-bind",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            item_key="module-a",
            downstream_service="entry_analyse",
            downstream_task_id="child-old",
            result={
                "sync_observation": {
                    "replacement_in_progress": True,
                    "binding_cleared": False,
                    "verification_status": "pending",
                    "old_downstream_task_id": "child-old",
                    "transition_type": "in_place_restart",
                }
            },
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item], events=[])

        changed = manager._repair_replacement_binding_state_for_task(db, task)

        self.assertTrue(changed)
        state = manager._replacement_in_progress_state(item)
        self.assertTrue(state["replacement_in_progress"])
        self.assertFalse(state["binding_cleared"])
        self.assertEqual("pending", state["verification_status"])
        self.assertEqual(manager.CHILD_TRANSITION_IN_PLACE_RESTART, state["transition_type"])

    async def test_run_task_runtime_signals_repairs_replacement_binding_by_clearing_stale_flag_after_new_child_bound(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-bind-new",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        task.summary = {
            "runtime_workset": {
                "pending_binding_repair": {
                    "requested_at": _now().isoformat(),
                    "source": "lease_auditor_signal",
                    "reason": "replacement_repair",
                }
            }
        }
        item = BinarySecurityStageItem(
            id="item-bind-new",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            item_key="module-b",
            downstream_service="entry_analyse",
            downstream_task_id="child-new",
            result={
                "sync_observation": {
                    "replacement_in_progress": True,
                    "binding_cleared": False,
                    "verification_status": "pending",
                    "old_downstream_task_id": "child-old",
                }
            },
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item], events=[])

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            changed = await manager._run_task_runtime_signals(task.id)

        self.assertTrue(changed)
        state = manager._replacement_in_progress_state(item)
        self.assertFalse(state["replacement_in_progress"])
        self.assertFalse(state["binding_cleared"])
        self.assertIsNone(state["verification_status"])
        self.assertEqual({}, task.summary.get("runtime_workset") or {})

    async def test_run_task_runtime_signals_consumes_archive_rebuild_before_tail_finalize(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-archive-first",
            project_id="project-1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        task.summary = {
            "runtime_workset": {
                "pending_archive_rebuild": {
                    "requested_at": _now().isoformat(),
                    "source": "lease_auditor_signal",
                    "reason": "stale_running_archive_job",
                    "stage_name": "system_analysis",
                },
                "pending_tail_finalize": {
                    "requested_at": _now().isoformat(),
                    "source": "task_owner",
                    "reason": "finalize_requested",
                },
            }
        }
        db = _ModelAwareDb(tasks=[task], events=[])
        rebuilt = []
        finalized = []

        async def _prepare_archive_retry_full(_db, _task, stage_name):
            rebuilt.append(stage_name)
            return [stage_name]

        def _finalize(_db, _task):
            finalized.append(_task.id)

        manager._prepare_archive_retry_full = _prepare_archive_retry_full
        manager._finalize_task = _finalize

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            first = await manager._run_task_runtime_signals(task.id)
            second = await manager._run_task_runtime_signals(task.id)

        self.assertTrue(first)
        self.assertTrue(second)
        self.assertEqual(["system_analysis"], rebuilt)
        self.assertEqual(["task-archive-first"], finalized)
        self.assertEqual({}, task.summary.get("runtime_workset") or {})

    async def test_run_task_processes_operation_before_runtime_signals(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-run-order",
            project_id="project-1",
            name="task",
            status="dispatching",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=_now() + timedelta(minutes=5),
            dispatch_started_at=_now(),
        )
        db = _ModelAwareDb(tasks=[task], events=[])
        order = []

        async def _run_current_task_operation(_task_id):
            order.append("operation")
            if order.count("operation") == 1:
                return True
            return False

        async def _run_task_runtime_signals(_task_id):
            order.append("signal")
            if order.count("signal") == 1:
                return True
            return False

        async def _execute_task(_task_id):
            order.append("execute")
            return None

        manager._run_current_task_operation = _run_current_task_operation
        manager._run_task_runtime_signals = _run_task_runtime_signals
        manager._execute_task = _execute_task
        manager._task_execution_owners = {}
        manager._register_task_execution_owner = lambda *_args, **_kwargs: True
        manager._release_task_execution_owner = lambda *_args, **_kwargs: None
        manager._service_role = lambda: "worker"
        manager._lease_is_active = lambda *_args, **_kwargs: True
        manager._next_lease_expiry = lambda *_args, **_kwargs: _now() + timedelta(minutes=5)
        manager._upsert_runtime_lease = lambda *_args, **_kwargs: None
        manager._clear_task_abnormal_reason_snapshot = lambda *_args, **_kwargs: None
        manager._bind_execution_token = lambda *_args, **_kwargs: None
        manager._streaming_tail_active_context = lambda *_args, **_kwargs: (None, 0, False)
        manager._is_streaming_tail_stage = lambda *_args, **_kwargs: False

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: db):
            await manager._run_task(task.id)

        self.assertEqual(["operation", "operation", "signal", "signal", "execute"], order)


class StreamingTailTakeoverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_tail_stage_work_summary_prefers_execution_takeover_for_unbound_items(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            status="pending",
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
            current_stage="dataflow_vuln_scan",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}
        stage_item = BinarySecurityStageItem(
            id="item-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-1",
            stage_name="dataflow_vuln_scan",
            item_key="entry-1",
            status="queued",
            downstream_service="dataflow_vuln_scan",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[stage_item])

        summary = self.manager._tail_stage_work_summary(db, task)

        self.assertEqual("execution_takeover", summary["tail_control_mode"])
        self.assertTrue(summary["has_runnable_unbound_items"])
        self.assertEqual(1, summary["unbound_runnable_item_count"])
        self.assertEqual(0, summary["bound_active_item_count"])
        self.assertTrue(self.manager._tail_requires_execution_takeover(db, task))
        self.assertFalse(self.manager._should_enter_tail_reconciliation(db, task))

    def test_refresh_task_status_keeps_owned_execution_when_tail_has_unbound_items(self):
        task = BinarySecurityTask(
            id="task-2",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            status="pending",
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
            current_stage="dataflow_vuln_scan",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}
        stage_run = BinarySecurityStageRun(
            id="sr-2",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=1,
            status="pending",
        )
        stage_item = BinarySecurityStageItem(
            id="item-2",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-2",
            status="queued",
            downstream_service="dataflow_vuln_scan",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[stage_item])

        with (
            patch.object(self.manager, "_ensure_task_remains_cancelling", return_value=None),
            patch.object(self.manager, "_recover_failed_cancelled_task_state", return_value=False),
            patch.object(self.manager, "_active_operation", return_value=None),
            patch.object(self.manager, "_refresh_stage_from_authoritative_items", side_effect=lambda *_args, **_kwargs: None),
            patch.object(self.manager, "_release_tail_reconcile_owner", side_effect=lambda *_args, **_kwargs: None),
            patch.object(self.manager, "_clear_task_abnormal_reason_snapshot", side_effect=lambda *_args, **_kwargs: None),
            patch.object(self.manager, "_activate_tail_reconciliation", side_effect=AssertionError("should not enter tail reconciliation")),
        ):
            self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_OWNED_EXECUTION, self.manager._task_runtime_phase(task))
        self.assertEqual("idle", task.tail_reconcile_state)

    def test_tail_stage_work_summary_marks_incomplete_stage_as_execution_takeover(self):
        task = BinarySecurityTask(
            id="task-3",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
            current_stage="dataflow_vuln_scan",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}
        stage_run = BinarySecurityStageRun(
            id="sr-3",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=1,
            status="running",
        )
        bound_item = BinarySecurityStageItem(
            id="item-3",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-3",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dvs-1",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[bound_item])

        summary = self.manager._tail_stage_work_summary(db, task)

        self.assertEqual("reconciliation", summary["tail_control_mode"])
        self.assertFalse(summary["takeover_required"])
        self.assertIsNone(summary["takeover_reason"])
        self.assertEqual(1, summary["bound_active_item_count"])

    def test_refresh_task_status_keeps_owned_execution_for_incomplete_tail_stage_without_unbound_items(self):
        task = BinarySecurityTask(
            id="task-4",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            status="running",
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
            current_stage="dataflow_vuln_scan",
            firmware_path="/tmp/fw.bin",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
        )
        task.policy = {"pipeline_mode": "mixed_streaming"}
        stage_run = BinarySecurityStageRun(
            id="sr-4",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            sequence_no=1,
            status="running",
        )
        bound_item = BinarySecurityStageItem(
            id="item-4",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-4",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dvs-4",
        )
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[bound_item])

        with (
            patch.object(self.manager, "_ensure_task_remains_cancelling", return_value=None),
            patch.object(self.manager, "_recover_failed_cancelled_task_state", return_value=False),
            patch.object(self.manager, "_active_operation", return_value=None),
            patch.object(self.manager, "_refresh_stage_from_authoritative_items", side_effect=lambda *_args, **_kwargs: None),
            patch.object(self.manager, "_release_tail_reconcile_owner", side_effect=lambda *_args, **_kwargs: None),
            patch.object(self.manager, "_clear_task_abnormal_reason_snapshot", side_effect=lambda *_args, **_kwargs: None),
        ):
            self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("running", task.status)
        self.assertEqual(TASK_RUNTIME_PHASE_TAIL_RECONCILIATION, self.manager._task_runtime_phase(task))
        self.assertEqual("active", task.tail_reconcile_state)

    async def test_retry_target_stage_sync_batches_specific_item_ids(self):
        manager = TaskManager()
        manager.cfg.scheduler.operation_step_batch_size = 2
        task = BinarySecurityTask(id="task-1", project_id="project-1")
        task.summary = {
            "retry_plan": {
                "item_actions": [
                    {"item_id": "item-1"},
                    {"item_id": "item-2"},
                    {"item_id": "item-3"},
                ]
            }
        }
        operation = task_manager_module.BinarySecurityTaskOperation(
            id="op-1",
            task_id=task.id,
            project_id=task.project_id,
            operation_type="stage_retry_failed_items",
            target_stage="entry_analysis",
            operation_token="token-1",
            status="running",
        )

        class _Db:
            def __init__(self):
                self.commits = 0

            def commit(self):
                self.commits += 1

        db = _Db()
        calls = []
        heartbeats = []

        async def _sync_downstream_status(_db, **kwargs):
            calls.append(kwargs["item_ids"])
            return None

        async def _heartbeat(_db, _task, _operation, **kwargs):
            heartbeats.append(kwargs)
            _operation.resume_cursor = dict(kwargs.get("resume_cursor") or {})
            return None

        manager.sync_downstream_status = _sync_downstream_status
        manager._operation_progress_heartbeat = _heartbeat

        payload = await manager._operation_sync_retry_target_stage_state(db, task, operation)

        self.assertEqual([["item-1", "item-2"], ["item-3"]], calls)
        self.assertEqual(3, payload["synced_items"])
        self.assertEqual(3, payload["total_items"])
        self.assertEqual(2, len(heartbeats))
        self.assertEqual(
            3,
            operation.resume_cursor["sync_target_stage_state"]["processed_count"],
        )

    async def test_state_reducer_loop_recovers_from_observe_failure(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.scheduler.poll_interval_seconds = 1
        observe_calls = []
        sleep_calls = []

        def _observe_state_runtime_metrics(_db):
            observe_calls.append("called")
            raise RuntimeError("boom")

        async def _sleep(_seconds):
            sleep_calls.append(_seconds)
            manager._running = False

        manager._observe_state_runtime_metrics = _observe_state_runtime_metrics

        with (
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
            patch("app.service.task_manager.logger.exception") as logger_exception,
            patch("app.service.task.reducer.observe_state_reducer_health") as observe_health,
        ):
            await manager._state_reducer_loop()

        self.assertEqual(["called"], observe_calls)
        self.assertGreaterEqual(len(sleep_calls), 1)
        self.assertTrue(all(seconds == 1 for seconds in sleep_calls))
        logger_exception.assert_called_once()
        observe_health.assert_called_once()
        self.assertEqual(1, manager._state_reducer_consecutive_crash_count)

    async def test_state_reducer_loop_records_healthy_heartbeat_after_iteration(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.scheduler.poll_interval_seconds = 1
        sleep_calls = []

        async def _sleep(_seconds):
            sleep_calls.append(_seconds)
            manager._running = False

        manager._observe_state_runtime_metrics = lambda _db: None
        manager._claim_state_event = lambda _db: None
        async def _observe_runtime_metrics(_db):
            return None
        manager._observe_runtime_metrics = _observe_runtime_metrics
        manager._state_reducer_consecutive_crash_count = 3

        with (
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
            patch("app.service.task.reducer.observe_state_reducer_health") as observe_health,
        ):
            await manager._state_reducer_loop()

        self.assertGreaterEqual(len(sleep_calls), 1)
        self.assertEqual(0, manager._state_reducer_consecutive_crash_count)
        observe_health.assert_called_once()
        self.assertEqual(0, observe_health.call_args.kwargs["consecutive_crash_count"])

    async def test_downstream_reconcile_loop_recovers_from_runtime_metrics_failure(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.scheduler.downstream_reconcile_interval_seconds = 5
        sleep_calls = []
        observed_candidates = []

        class _Db:
            def rollback(self):
                return None

            def close(self):
                return None

        async def _sleep(seconds):
            sleep_calls.append(seconds)
            if seconds == 1:
                manager._running = False

        async def _observe_runtime_metrics(_db, reconcile_candidates=0):
            observed_candidates.append(reconcile_candidates)
            raise RuntimeError("boom")

        async def _run_with_limits(refs, func, concurrency, timeout_seconds):
            del refs, func, concurrency, timeout_seconds
            return []

        manager._list_tasks_needing_downstream_sync = lambda _db: []
        manager._list_tasks_with_deferred_cleanup = lambda _db: []
        manager._run_with_limits = _run_with_limits
        manager._observe_runtime_metrics = _observe_runtime_metrics

        with (
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
            patch("app.service.task_manager.get_session_factory", return_value=lambda: _Db()),
            patch("app.service.task_manager.logger.exception") as logger_exception,
        ):
            await manager._downstream_reconcile_loop()

        self.assertEqual([0], observed_candidates)
        self.assertIn(1, sleep_calls)
        logger_exception.assert_called_once()

    async def test_stage_item_sync_reconcile_loop_recovers_from_runtime_failure(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.scheduler.stage_item_sync_reconcile_interval_seconds = 5
        sleep_calls = []

        async def _sleep(seconds):
            sleep_calls.append(seconds)
            if seconds == 1:
                manager._running = False

        async def _run_with_limits(refs, func, concurrency, timeout_seconds):
            del refs, func, concurrency, timeout_seconds
            return []

        manager._list_tasks_with_stale_stage_item_syncs = lambda _db: (_ for _ in ()).throw(RuntimeError("boom"))
        manager._run_with_limits = _run_with_limits

        with (
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
            patch("app.service.task_manager.logger.exception") as logger_exception,
        ):
            await manager._stage_item_sync_reconcile_loop()

        self.assertIn(1, sleep_calls)
        logger_exception.assert_called_once()

    async def test_readless_reconcile_loop_commits_per_task_and_stops_after_sleep(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.scheduler.readless_reconcile_interval_seconds = 300

        refresh_calls = []
        observe_calls = []
        sleep_calls = []

        async def _process_one(task_id):
            refresh_calls.append(task_id)
            return True, True

        def _observe(**kwargs):
            observe_calls.append(kwargs)

        async def _sleep(seconds):
            sleep_calls.append(seconds)
            manager._running = False

        with (
            patch.object(manager, "_load_readless_reconcile_candidate_ids", return_value=["t1"]),
            patch.object(manager, "_process_readless_reconcile_task", side_effect=_process_one),
            patch("app.service.task.item_sync.observe_task_readless_reconcile", side_effect=_observe),
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
        ):
            await manager._readless_reconcile_loop()

        self.assertEqual(["t1"], refresh_calls)
        self.assertEqual(1, len(observe_calls))
        self.assertEqual(1, observe_calls[0]["attempted"])
        self.assertEqual(1, observe_calls[0]["changed"])
        self.assertEqual(0, observe_calls[0]["failed"])
        self.assertEqual(1, observe_calls[0]["candidates"])
        self.assertGreaterEqual(len(sleep_calls), 1)
        self.assertEqual(300, sleep_calls[0])

    async def test_readless_reconcile_skips_active_leased_task_without_refreshing(self):
        manager = TaskManager()
        lease_expires_at = _now() + timedelta(minutes=5)
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="demo",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
            dispatcher_instance_id="worker-a",
            lease_expires_at=lease_expires_at,
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
        )

        class _TaskSession:
            def __init__(self):
                self.task = task
                self.commits = 0
                self.rollbacks = 0

            def query(self, model):
                del model
                return self

            def filter(self, *args, **kwargs):
                del args, kwargs
                return self

            def first(self):
                return self.task

            def commit(self):
                self.commits += 1

            def rollback(self):
                self.rollbacks += 1

            def close(self):
                return None

        task_session = _TaskSession()
        refresh_calls = []

        def _refresh(_session, _task):
            refresh_calls.append("called")

        manager._refresh_task_status_after_sync = _refresh

        with (
            patch.object(manager, "_readless_reconcile_item_layer", return_value=set()),
            patch.object(manager, "_readless_reconcile_stage_layer", return_value=set()),
            patch.object(manager, "_readless_reconcile_task_layer", return_value=manager._task_state_snapshot(task)),
            patch.object(manager, "_readless_reconcile_tail_takeover", return_value=None),
            patch.object(task_manager_module, "get_session_factory", return_value=lambda: task_session),
        ):
            attempted, changed = await manager._process_readless_reconcile_task("t1")

        self.assertTrue(attempted)
        self.assertFalse(changed)
        self.assertEqual([], refresh_calls)
        self.assertEqual(1, task_session.rollbacks)

    async def test_observe_runtime_metrics_collects_db_snapshot_in_thread(self):
        manager = TaskManager()
        manager._workers = {"t1": type("Task", (), {"done": lambda self: False})()}
        manager._operation_workers = {"o1": type("Task", (), {"done": lambda self: False})()}

        async def _snapshot():
            return {
                "task_queue": {"length": 2, "oldest_age_seconds": 11.0},
                "operation_queue": {"length": 0, "oldest_age_seconds": 0.0, "enabled": 0},
            }

        collected = []

        def _collect_sync():
            collected.append("called")
            return {
                "pending_tasks": 4,
                "running_tasks": 5,
                "archive_pending_jobs": 6,
                "archive_running_jobs": 7,
                "archive_applying_jobs": 8,
                "leased_tasks": 9,
                "task_capacity": 10,
            }

        manager._collect_runtime_metrics_snapshot_sync = _collect_sync

        class _Queue:
            async def snapshot(self):
                return await _snapshot()

        with (
            patch("app.service.task_manager.get_task_queue", return_value=_Queue()),
            patch("app.service.task_manager.observe_queue_depths") as observe_queue_depths,
            patch("app.service.task_manager.observe_slot_usage") as observe_slot_usage,
        ):
            await manager._observe_runtime_metrics(db=None, reconcile_candidates=12)

        self.assertEqual(["called"], collected)
        observe_queue_depths.assert_called_once()
        self.assertEqual(4, observe_queue_depths.call_args.kwargs["pending_tasks"])
        self.assertEqual(12, observe_queue_depths.call_args.kwargs["reconcile_candidates"])
        observe_slot_usage.assert_called_once()
        self.assertEqual(10, observe_slot_usage.call_args.kwargs["task_capacity"])
        self.assertEqual(1, observe_slot_usage.call_args.kwargs["task_active"])
        self.assertEqual(0, observe_slot_usage.call_args.kwargs["action_active"])

    async def test_claim_state_event_returns_none_on_retryable_lock_conflict(self):
        manager = TaskManager()

        class _Query:
            def filter(self, *args, **kwargs):
                del args, kwargs
                return self

            def order_by(self, *args, **kwargs):
                del args, kwargs
                return self

            def first(self):
                raise task_manager_module.OperationalError(
                    "SELECT ... FROM secflow_binary_security_state_event",
                    {},
                    Exception(1205, "Lock wait timeout exceeded; try restarting transaction"),
                )

        class _Session:
            def __init__(self):
                self.rollbacks = 0

            def query(self, _model):
                return _Query()

            def rollback(self):
                self.rollbacks += 1

        session = _Session()

        event_id = manager._claim_state_event(session)

        self.assertIsNone(event_id)
        self.assertEqual(1, session.rollbacks)

    async def test_claim_state_event_sets_processing_metadata(self):
        manager = TaskManager()
        event = type(
            "Event",
            (),
            {
                "id": "sev-1",
                "attempts": 0,
            },
        )()
        captured = {}

        class _Query:
            def __init__(self, rows):
                self._rows = rows

            def filter(self, *args, **kwargs):
                del args, kwargs
                return self

            def order_by(self, *args, **kwargs):
                del args, kwargs
                return self

            def first(self):
                return self._rows[0] if self._rows else None

            def update(self, values, synchronize_session=False):
                del synchronize_session
                captured.update({getattr(key, "name", str(key)): value for key, value in values.items()})
                return 1

        class _Session:
            def __init__(self):
                self.commits = 0

            def query(self, _model):
                return _Query([event])

            def commit(self):
                self.commits += 1

            def rollback(self):
                return None

        session = _Session()

        event_id = manager._claim_state_event(session)

        self.assertEqual("sev-1", event_id)
        self.assertEqual("processing", captured.get("status"))
        self.assertEqual(manager.instance_id, captured.get("processed_by"))
        self.assertEqual("processing", captured.get("processing_result"))

    def test_refresh_stage_from_authoritative_items_retries_retryable_lock_error(self):
        manager = TaskManager()
        task = BinarySecurityTask(id="task-1", project_id="project-1")
        expected_run = BinarySecurityStageRun(
            id="sr-1",
            task_id="task-1",
            project_id="project-1",
            stage_name="entry_analysis",
            sequence_no=1,
            status="running",
        )

        class _Query:
            def __init__(self, rows):
                self._rows = rows

            def filter(self, *args, **kwargs):
                del args, kwargs
                return self

            def first(self):
                return self._rows[0] if self._rows else None

        class _Session:
            def __init__(self, rows):
                self.rollbacks = 0
                self._rows = rows

            def rollback(self):
                self.rollbacks += 1

            def query(self, _model):
                return _Query(self._rows)

        session = _Session([task])
        error = task_manager_module.OperationalError(
            "UPDATE secflow_binary_security_task SET stage_summary_json = ...",
            {},
            Exception(1205, "Lock wait timeout exceeded; try restarting transaction"),
        )

        with (
            patch.object(manager, "_refresh_stage_from_authoritative_items_once", side_effect=[error, expected_run]) as refresh_once,
            patch.object(manager, "_sleep_after_retryable_lock_error", side_effect=lambda attempt: None) as sleep_retry,
        ):
            result = manager._refresh_stage_from_authoritative_items(session, task, "entry_analysis", operation="unit_test")

        self.assertIs(result, expected_run)
        self.assertEqual(2, refresh_once.call_count)
        self.assertEqual(1, session.rollbacks)
        sleep_retry.assert_called_once_with(1)

    async def test_poll_until_terminal_survives_operational_error_and_records_failure(self):
        manager = TaskManager()
        task = BinarySecurityTask(id="task-1", project_id="project-1")
        item = type("Item", (), {"id": "item-1", "downstream_task_id": "child-1"})()
        calls = {"count": 0}
        failures = []

        async def _ensure(_task):
            return None

        async def _touch(_task_id):
            return None

        async def _cancelled(_task_id):
            return False

        def _record_failure(**kwargs):
            failures.append(kwargs)

        async def _sleep(_seconds):
            return None

        async def _fetch():
            calls["count"] += 1
            if calls["count"] == 1:
                raise OperationalError("stmt", {}, RuntimeError("connection refused"))
            return {"status": "success"}

        manager._ensure_task_execution_current_async = _ensure
        manager._touch_task_heartbeat_async = _touch
        manager._is_task_cancelled_async = _cancelled
        manager._record_polled_child_sync_failure = _record_failure

        with patch("app.service.task_manager.asyncio.sleep", _sleep):
            status, payload = await manager._poll_until_terminal(
                _fetch,
                success_statuses={"success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )

        self.assertEqual("success", status)
        self.assertEqual({"status": "success"}, payload)
        self.assertEqual(2, calls["count"])
        self.assertEqual(1, len(failures))
        self.assertEqual("db_connection_refused", failures[0]["error_type"])

    async def test_poll_until_terminal_raises_immediately_when_owned_execution_owner_changes(self):
        manager = TaskManager()
        task = BinarySecurityTask(id="task-1", project_id="project-1")
        item = type("Item", (), {"id": "item-1", "downstream_task_id": "child-1"})()
        failures = []

        async def _ensure(_task):
            return None

        async def _touch(_task_id):
            return None

        def _record_failure(**kwargs):
            failures.append(kwargs)

        async def _fetch():
            raise RuntimeError("任务 task-1 当前 owned_execution runtime lease owner 已变更")

        manager._ensure_task_execution_current_async = _ensure
        manager._touch_task_heartbeat_async = _touch
        manager._record_polled_child_sync_failure = _record_failure

        with self.assertRaises(StaleTaskExecution):
            await manager._poll_until_terminal(
                _fetch,
                success_statuses={"success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )

        self.assertEqual([], failures)

    async def test_ensure_task_execution_current_async_uses_tail_runtime_lease(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-tail-1",
            project_id="project-1",
            name="tail",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json='{"pipeline_mode": "mixed_streaming"}',
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
        )
        item = BinarySecurityStageItem(
            id="item-tail-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-entry",
            stage_name="entry_analysis",
            item_key="module-a",
            item_identity_key="module-a::source",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-1",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-a",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(seconds=120),
        )

        class _Query:
            def __init__(self, rows):
                self._rows = rows

            def filter(self, *args, **kwargs):
                del args, kwargs
                return self

            def order_by(self, *args, **kwargs):
                del args, kwargs
                return self

            def all(self):
                return list(self._rows)

            def first(self):
                return self._rows[0] if self._rows else None

        class _Session:
            def query(self, model):
                name = getattr(model, "__name__", "")
                if name == "BinarySecurityTask":
                    return _Query([task])
                if name == "BinarySecurityTaskRuntimeLease":
                    return _Query([lease])
                if name == "BinarySecurityStageItem":
                    return _Query([item])
                return _Query([])

            def close(self):
                return None

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: _Session()):
            await manager._ensure_task_execution_current_async(task)

    async def test_ensure_task_execution_current_async_rejects_tail_runtime_lease_owner_takeover(self):
        manager = TaskManager()
        manager.instance_id = "worker-a"
        task = BinarySecurityTask(
            id="task-tail-2",
            project_id="project-1",
            name="tail",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_vuln_scan",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            policy_json='{"pipeline_mode": "mixed_streaming"}',
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
        )
        item = BinarySecurityStageItem(
            id="item-tail-2",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id="sr-df",
            stage_name="dataflow_vuln_scan",
            item_key="entry-a",
            parent_key="module-a",
            item_identity_key="entry-a::module-a",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="dfa-1",
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="worker-b",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(seconds=120),
        )

        class _Query:
            def __init__(self, rows):
                self._rows = rows

            def filter(self, *args, **kwargs):
                del args, kwargs
                return self

            def order_by(self, *args, **kwargs):
                del args, kwargs
                return self

            def all(self):
                return list(self._rows)

            def first(self):
                return self._rows[0] if self._rows else None

        class _Session:
            def query(self, model):
                name = getattr(model, "__name__", "")
                if name == "BinarySecurityTask":
                    return _Query([task])
                if name == "BinarySecurityTaskRuntimeLease":
                    return _Query([lease])
                if name == "BinarySecurityStageItem":
                    return _Query([item])
                return _Query([])

            def close(self):
                return None

        with patch("app.service.task_manager.get_session_factory", return_value=lambda: _Session()):
            with self.assertRaises(StaleTaskExecution):
                await manager._ensure_task_execution_current_async(task)

    def test_stage_item_stale_uses_last_attempt_instead_of_last_success(self):
        manager = TaskManager()
        manager.cfg.scheduler.stage_item_sync_stale_seconds = 300
        item = type(
            "Item",
            (),
            {
                "status": "running",
                "downstream_task_id": "child-1",
                "result": {
                    "downstream_status_synced_at": (_now() - timedelta(hours=1)).isoformat(),
                    "last_sync_attempt_at": (_now() - timedelta(seconds=30)).isoformat(),
                    "sync_observation": {
                        "last_attempt_at": (_now() - timedelta(seconds=30)).isoformat(),
                        "last_success_at": (_now() - timedelta(hours=1)).isoformat(),
                    },
                },
            },
        )()
        self.assertFalse(manager._item_downstream_sync_stale(item))

    def test_aggregate_stage_items_holds_pending_when_sync_degraded(self):
        manager = TaskManager()
        task = BinarySecurityTask(id="task-1", project_id="project-1", summary={})

        class _Db:
            def commit(self):
                return None

        status, _summary = manager._aggregate_stage_items(
            _Db(),
            task,
            [
                {"status": "success", "item": {"id": "a"}},
                {"status": "pending", "item": {"id": "b"}, "sync_degraded": True, "deferred_mode": "reconcile"},
            ],
            "entry_results",
        )
        self.assertEqual("running", status)

    def test_defer_item_after_orchestration_error_records_observation(self):
        manager = TaskManager()
        task = BinarySecurityTask(id="task-1", project_id="project-1")
        item = type(
            "Item",
            (),
            {
                "id": "item-1",
                "stage_name": "entry_analysis",
                "status": "dispatching",
                "downstream_task_id": "",
                "result": {},
                "error_message": None,
                "finished_at": None,
            },
        )()

        class _Db:
            def __init__(self):
                self.commits = 0

            def add(self, _event):
                return None

            def commit(self):
                self.commits += 1

        db = _Db()
        response = manager._defer_item_after_orchestration_error(
            db,
            task,
            item,
            operation="entry_analysis",
            exc=OperationalError("stmt", {}, RuntimeError("lost connection")),
            response_item={"id": "m1"},
        )
        self.assertEqual("pending", response["status"])
        self.assertTrue(response["orchestration_degraded"])
        self.assertEqual("error", item.result["orchestration_observation"]["last_result"])
        self.assertIsNotNone(item.result.get("next_orchestration_retry_at"))
        self.assertEqual(1, db.commits)


if __name__ == "__main__":
    unittest.main()
