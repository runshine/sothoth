import unittest
from datetime import timedelta
from unittest.mock import patch

from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError

from app.model import BinarySecurityTask, TASK_TYPE_BINARY
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now


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
                    current_stage="vuln_scan",
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
        self.assertIsNotNone(captured.get("processing_started_at"))
        self.assertEqual(1, session.commits)


if __name__ == "__main__":
    unittest.main()
