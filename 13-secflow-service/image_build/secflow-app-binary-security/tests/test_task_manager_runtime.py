import unittest
from datetime import timedelta
from unittest.mock import patch

from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import StaleTaskExecution, TaskManager, _now


class TaskManagerRuntimeStatusTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

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
                "operation_dispatch": True,
                "archive_dispatch": False,
                "stage_item_dispatch": True,
                "downstream_reconcile": True,
                "stage_item_sync_reconcile": False,
                "archive_runtime_reconcile": False,
                "state_repair_reconcile": False,
                "readless_reconcile": True,
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

        self.manager._operation_loop_task = _Task()
        self.manager.cfg.scheduler.worker_ready_loop_stale_seconds = 30
        self.manager.cfg.queue.block_timeout_seconds = 5
        self.manager._loop_heartbeats["operation_dispatch"] = _now() - timedelta(seconds=60)

        status = self.manager.runtime_status()

        self.assertTrue(status["loops"]["operation_dispatch"])
        self.assertTrue(status["loop_details"]["operation_dispatch"]["stale"])

    def test_runtime_status_uses_recent_heartbeat_when_task_handle_is_done(self):
        self.manager._running = True

        class _Task:
            def done(self):
                return True

        self.manager._operation_loop_task = _Task()
        self.manager.cfg.scheduler.worker_ready_loop_stale_seconds = 30
        self.manager._loop_heartbeats["operation_dispatch"] = _now()

        status = self.manager.runtime_status()

        self.assertTrue(status["loops"]["operation_dispatch"])
        self.assertFalse(status["loop_details"]["operation_dispatch"]["stale"])
        self.assertFalse(status["loop_details"]["operation_dispatch"]["task_running"])
        self.assertTrue(status["loop_details"]["operation_dispatch"]["heartbeat_alive"])

    def test_operation_lease_uses_short_configured_ttl(self):
        self.manager.cfg.scheduler.operation_lease_ttl_seconds = 60
        now_value = _now()
        expires_at = self.manager._operation_lease_expires_at(now_value=now_value)
        self.assertEqual(60, int((expires_at - now_value).total_seconds()))

    def test_maybe_upsert_runtime_lease_returns_existing_on_conflict(self):
        manager = TaskManager()
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="tail",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            runtime_phase=TASK_RUNTIME_PHASE_TAIL_RECONCILIATION,
        )
        lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            execution_epoch=0,
            owner_instance_id="other-reducer",
            heartbeat_at=_now(),
            lease_expires_at=_now() + timedelta(seconds=120),
        )

        class _Session:
            def __init__(self):
                self.runtime_leases = [lease]

            def query(self, model):
                name = getattr(model, "__name__", "")

                class _Query:
                    def __init__(self, rows):
                        self._rows = rows

                    def filter(self, *args, **kwargs):
                        del args, kwargs
                        return self

                    def first(self):
                        return self._rows[0] if self._rows else None

                if name == "BinarySecurityTaskRuntimeLease":
                    return _Query(self.runtime_leases)
                return _Query([])

        session = _Session()
        returned = manager._maybe_upsert_runtime_lease(session, task, now_value=_now(), owner_instance_id="this-reducer")
        self.assertIs(returned, lease)


class TaskManagerDispatchLoopTests(unittest.IsolatedAsyncioTestCase):
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

        async def _run_task(_task_id):
            return None

        async def _reconcile(_db):
            reconcile_calls.append("called")

        async def _observe(_db):
            return None

        manager._dispatch_task_by_id = _dispatch_task_by_id
        manager._run_task = _run_task
        manager._reconcile_work_queues = _reconcile
        manager._observe_runtime_metrics = _observe

        with patch("app.service.task_manager.get_task_queue", return_value=_Queue()):
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

    async def test_operation_dispatch_loop_does_not_log_crash_for_redis_timeout_empty_poll(self):
        manager = TaskManager()
        manager._running = True
        manager.cfg.queue.enabled = True
        manager.cfg.queue.block_timeout_seconds = 1
        pop_calls = []

        class _Queue:
            async def pop_operation(self, _timeout_seconds):
                pop_calls.append("called")
                if len(pop_calls) == 1:
                    return None
                manager._running = False
                return None

        async def _observe(_db):
            return None

        manager._observe_runtime_metrics = _observe
        manager._requeue_stale_operations = lambda _db: False

        with patch("app.service.task_manager.get_task_queue", return_value=_Queue()), patch(
            "app.service.task_manager.logger.exception"
        ) as logger_exception:
            await manager._operation_dispatch_loop()

        self.assertEqual(["called", "called"], pop_calls)
        logger_exception.assert_not_called()

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

        async def _sync_downstream_status(_db, **kwargs):
            calls.append(kwargs["item_ids"])
            return None

        manager.sync_downstream_status = _sync_downstream_status

        payload = await manager._operation_sync_retry_target_stage_state(db, task, operation)

        self.assertEqual([["item-1", "item-2"], ["item-3"]], calls)
        self.assertEqual(3, payload["synced_items"])
        self.assertEqual(3, payload["total_items"])
        self.assertEqual(2, db.commits)
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
            patch("app.service.task_manager.observe_state_reducer_health") as observe_health,
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
            patch("app.service.task_manager.observe_state_reducer_health") as observe_health,
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

        class _CandidateSession:
            def query(self, model):
                del model
                return self

            def filter(self, *args, **kwargs):
                del args, kwargs
                return self

            def order_by(self, *args, **kwargs):
                del args, kwargs
                return self

            def limit(self, *args, **kwargs):
                del args, kwargs
                return self

            def all(self):
                return [("t1",)]

            def close(self):
                return None

        class _TaskSession:
            def __init__(self):
                self.task = type("Task", (), {"id": "t1", "status": "pending", "current_stage": "system_analysis"})()
                self.commits = 0
                self.rollbacks = 0

            def query(self, model):
                name = getattr(model, "__name__", "")

                class _Query:
                    def __init__(self, row):
                        self._row = row

                    def filter(self, *args, **kwargs):
                        del args, kwargs
                        return self

                    def first(self):
                        return self._row

                if name == "BinarySecurityTask":
                    return _Query(self.task)
                if name == "BinarySecurityTaskRuntimeLease":
                    return _Query(None)
                return _Query(None)

            def commit(self):
                self.commits += 1

            def rollback(self):
                self.rollbacks += 1

            def close(self):
                return None

        task_session = _TaskSession()
        sessions = [_CandidateSession(), task_session]

        def _session_factory():
            return sessions.pop(0)

        refresh_calls = []
        observe_calls = []
        sleep_calls = []

        def _refresh(_session, task):
            refresh_calls.append(task.id)
            task.status = "running"

        def _observe(**kwargs):
            observe_calls.append(kwargs)

        async def _sleep(seconds):
            sleep_calls.append(seconds)
            manager._running = False

        manager._refresh_task_status_after_sync = _refresh
        manager._claim_or_refresh_runtime_lease = lambda *args, **kwargs: type("LeaseClaim", (), {"result": "claimed", "lease": None})()

        with (
            patch("app.service.task_manager.get_session_factory", return_value=_session_factory),
            patch("app.service.task_manager.observe_task_readless_reconcile", side_effect=_observe),
            patch("app.service.task_manager.asyncio.sleep", new=_sleep),
        ):
            await manager._readless_reconcile_loop()

        self.assertEqual(["t1"], refresh_calls)
        self.assertEqual(1, task_session.commits)
        self.assertEqual(0, task_session.rollbacks)
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

        class _TaskSession:
            def __init__(self):
                self.task = BinarySecurityTask(
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
                )
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

        with patch.object(task_manager_module, "get_session_factory", return_value=lambda: task_session):
            attempted, changed = await manager._process_readless_reconcile_task("t1")

        self.assertTrue(attempted)
        self.assertFalse(changed)
        self.assertEqual([], refresh_calls)
        self.assertEqual(0, task_session.commits)
        self.assertEqual(1, task_session.rollbacks)

    async def test_observe_runtime_metrics_collects_db_snapshot_in_thread(self):
        manager = TaskManager()
        manager._workers = {"t1": type("Task", (), {"done": lambda self: False})()}
        manager._operation_workers = {"o1": type("Task", (), {"done": lambda self: False})()}

        async def _snapshot():
            return {
                "task_queue": {"length": 2, "oldest_age_seconds": 11.0},
                "operation_queue": {"length": 3, "oldest_age_seconds": 7.0},
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
        self.assertEqual(1, observe_slot_usage.call_args.kwargs["action_active"])

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
