import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import yaml

from app.config import reload_config
from app.model import TaskStatus, UnpackTask, UnpackTaskEvent, WorkerInstance, WorkspaceCleanupJob, get_db_session, init_database
import app.model as model_module
import app.unpacker_engine as unpacker_engine_module
import app.services.task_events as task_events_module
import app.services.task_manager as task_manager_module
from app.api.firmware import _agent_runtime_payload_from_snapshot, _submit_task
from app.exception import ValidationError
from app.model import ServiceConfig
from app.schemas import UnpackRequest
from app.services.task_manager import prepare_task_workspace, resolve_task_runtime_paths, submit_unpack_task
from app.services.task_events import list_task_events, record_task_event
from app.time_utils import now_local


class _StubStream:
    def __iter__(self):
        return iter(())

    def readline(self):
        return ""


class _StubStdin:
    def write(self, _data):
        return None

    def flush(self):
        return None

    def close(self):
        return None


class _StubProc:
    def __init__(self):
        self.stdin = _StubStdin()
        self.stdout = _StubStream()
        self.stderr = _StubStream()
        self.pid = 4321
        self._poll = None

    def poll(self):
        return self._poll

    def terminate(self):
        self._poll = 0

    def wait(self, timeout=None):
        self._poll = 0
        return 0

    def kill(self):
        self._poll = -9


class TaskManagerWorkspaceTests(unittest.TestCase):
    def test_agent_runtime_payload_from_snapshot_handles_missing_and_valid_task_key(self):
        self.assertEqual(
            {
                "has_agent_task_key": False,
                "agent_task_key_id": None,
                "agent_task_key_prefix": None,
                "agent_runtime_mode": None,
            },
            _agent_runtime_payload_from_snapshot(None),
        )
        self.assertEqual(
            {
                "has_agent_task_key": True,
                "agent_task_key_id": "tk-1",
                "agent_task_key_prefix": "tsk_x",
                "agent_runtime_mode": "schedule_dispatch",
            },
            _agent_runtime_payload_from_snapshot(
                {
                    "agent_task_key": {
                        "id": "tk-1",
                        "prefix": "tsk_x",
                        "secret": "hidden",
                        "source": "schedule_dispatch",
                    }
                }
            ),
        )

    def test_prepare_task_workspace_writes_manifest_without_copying_firmware(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"firmware")

            with patch("app.services.task_manager.PROJECT_FILES_ROOT", root / "data"):
                prepared = prepare_task_workspace("p1", "t1", str(firmware))

            input_dir = root / "data" / "p1" / "app/secflow-app-firmware-unpacker" / "t1" / "input"
            manifest_path = input_dir / "task.json"
            copied_firmware = input_dir / firmware.name

            self.assertEqual(str(firmware), prepared["input_path"])
            self.assertTrue(manifest_path.is_file())
            self.assertFalse(copied_firmware.exists())
            self.assertEqual(
                {
                    "input_path": str(firmware),
                    "output_path": prepared["output_path"],
                    "run_path": prepared["run_path"],
                    "log_path": str(Path(prepared["run_path"]) / "tool.log"),
                    "log_file_path": str(Path(prepared["run_path"]) / "tool.log"),
                },
                json.loads(manifest_path.read_text(encoding="utf-8")),
            )

    def test_http_429_error_is_logged_as_rate_limited_without_exception_stack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            db_path = root / "tasks.db"
            config_path.write_text(
                yaml.safe_dump(
                    {
                        "database": {
                            "type": "sqlite",
                            "path": str(db_path),
                            "table_prefix": "secflow_app_firmware_unpacker_",
                        }
                    }
                ),
                encoding="utf-8",
            )
            reload_config(str(config_path))
            model_module._engine = None
            model_module._SessionFactory = None
            init_database()
            db = get_db_session()
            try:
                db.add(
                    UnpackTask(
                        id="task-429",
                        project_id="p1",
                        firmware_path="/tmp/in",
                        output_path="/tmp/out",
                        status=TaskStatus.RUNNING.value,
                        owner_id="owner-1",
                        current_stage="llm_unpack",
                        run_token="rt",
                    )
                )
                db.commit()
            finally:
                db.close()

            run_unpack_side_effects = [
                RuntimeError("429 No deployments available for selected model, Try again in 5 seconds."),
                {"status": "success"},
            ]
            with patch.object(task_manager_module.logger, "warning") as warning_mock, \
                 patch.object(task_manager_module.logger, "exception") as exception_mock, \
                 patch.object(task_manager_module, "_update_task_error") as update_error_mock, \
                 patch.object(task_manager_module, "_update_task_result") as update_result_mock, \
                 patch.object(task_manager_module, "_record_task_event") as record_event_mock, \
                 patch.object(task_manager_module, "_register_cancel_hook"), \
                 patch.object(task_manager_module, "_update_task_progress_for_owner"), \
                 patch.object(task_manager_module, "_should_cancel_run", return_value=False), \
                 patch.object(task_manager_module, "_freeze_task_llm_binding_snapshot", return_value={}), \
                 patch.object(task_manager_module, "resolve_task_runtime_paths", return_value={"input_path": "/tmp/in", "output_path": "/tmp/out"}), \
                 patch.object(task_manager_module.time, "sleep", return_value=None), \
                 patch.object(unpacker_engine_module, "run_unpack", side_effect=run_unpack_side_effects):
                task_manager_module.run_claimed_task_process("task-429", owner_id="owner-1", run_token="rt")

            warning_mock.assert_called()
            exception_mock.assert_not_called()
            update_error_mock.assert_not_called()
            update_result_mock.assert_called_once()
            self.assertTrue(
                any(
                    kwargs.get("event_type") == "task_rate_limited_retrying"
                    for _, kwargs in record_event_mock.call_args_list
                )
            )

    def test_resolve_task_runtime_paths_refreshes_manifest_and_uses_original_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            firmware = root / "fw.bin"
            firmware.write_bytes(b"x")

            with patch("app.services.task_manager.PROJECT_FILES_ROOT", root / "data"):
                prepare_task_workspace("p1", "t1", str(firmware))
                resolved = resolve_task_runtime_paths("t1", "p1", str(firmware), "/ignored/output")

            manifest_path = root / "data" / "p1" / "app/secflow-app-firmware-unpacker" / "t1" / "input" / "task.json"
            self.assertEqual(str(firmware), resolved["input_path"])
            self.assertTrue(manifest_path.is_file())
            self.assertEqual(str(root / "data" / "p1" / "app/secflow-app-firmware-unpacker" / "t1" / "output"), resolved["output_path"])

    def test_submit_task_surfaces_value_error_as_validation_error(self):
        request = UnpackRequest(
            firmware_path="/tmp/firmware.bin",
            project_id="p1",
        )

        with patch("app.api.firmware.os.path.exists", return_value=True), \
             patch("app.api.firmware.submit_unpack_task", side_effect=ValueError("未配置角色 executor 的 LLM Provider")):
            with self.assertRaisesRegex(ValidationError, "未配置角色 executor 的 LLM Provider"):
                _submit_task("p1", request)


class TaskManagerLeaseTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.root = root
        config_path = root / "config.yaml"
        db_path = root / "tasks.db"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "database": {
                        "type": "sqlite",
                        "path": str(db_path),
                        "table_prefix": "secflow_app_firmware_unpacker_",
                    },
                    "worker": {
                        "heartbeat_interval_seconds": 15,
                        "dead_threshold_seconds": 90,
                        "claim_interval_seconds": 1,
                        "claim_batch_size": 4,
                        "task_lease_seconds": 45,
                        "task_lease_renew_interval_seconds": 10,
                        "cancel_timeout_seconds": 120,
                    },
                }
            ),
            encoding="utf-8",
        )
        reload_config(str(config_path))
        model_module._engine = None
        model_module._SessionFactory = None
        model_module._OWNER_ID = "pod-a:123:owner"
        init_database()

    def tearDown(self):
        task_manager_module.shutdown()
        model_module._engine = None
        model_module._SessionFactory = None
        model_module._OWNER_ID = None
        self._tmp.cleanup()

    def _add_task(
        self,
        task_id: str,
        *,
        status: str,
        owner_id: str | None = None,
        assigned_worker_id: str | None = None,
        dispatch_token: str | None = None,
        takeover_count: int = 0,
        cancel_requested_at=None,
        lease_expires_at=None,
        last_progress_at=None,
    ):
        db = get_db_session()
        try:
            db.add(
                UnpackTask(
                    id=task_id,
                    project_id="p1",
                    firmware_path="/tmp/fw.bin",
                    output_path="/tmp/output",
                    status=status,
                    owner_id=owner_id,
                    assigned_worker_id=assigned_worker_id,
                    dispatch_token=dispatch_token,
                    takeover_count=takeover_count,
                    current_stage="llm_unpack",
                    cancel_requested_at=cancel_requested_at,
                    lease_expires_at=lease_expires_at,
                    last_progress_at=last_progress_at,
                )
            )
            db.commit()
        finally:
            db.close()

    def _add_worker(self, owner_id: str, *, is_alive: bool = True, last_heartbeat=None):
        from datetime import datetime

        db = get_db_session()
        try:
            db.add(
                WorkerInstance(
                    worker_id=owner_id,
                    hostname="pod-a",
                    pod_ip="127.0.0.1",
                    started_at=datetime.utcnow(),
                    last_heartbeat=last_heartbeat or datetime.utcnow(),
                    is_alive=is_alive,
                    active_tasks=0,
                )
            )
            db.commit()
        finally:
            db.close()

    def test_claim_task_sets_owner_without_task_lease(self):
        self._add_task("t-claim", status=TaskStatus.PENDING.value)

        claimed = task_manager_module._claim_task("t-claim")

        self.assertTrue(claimed)
        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-claim").first()
            self.assertEqual(TaskStatus.CLAIMED.value, task.status)
            self.assertEqual("pod-a:123:owner", task.owner_id)
            self.assertEqual("queued", task.current_stage)
            self.assertIsNone(task.lease_expires_at)
            events = db.query(UnpackTaskEvent).filter(UnpackTaskEvent.task_id == "t-claim").all()
            self.assertTrue(any(event.event_type == "task_claimed" for event in events))
        finally:
            db.close()

    def test_schedule_pending_task_starts_subprocess_runner(self):
        self._add_task(
            "t-spawn",
            status=TaskStatus.ASSIGNED.value,
            owner_id="pod-a:123:owner",
            assigned_worker_id="pod-a:123:owner",
            dispatch_token="dispatch-token-1",
        )

        class _FakePopen:
            def __init__(self, args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                self.pid = 4321

        launched = []

        def _fake_popen(args, **kwargs):
            proc = _FakePopen(args, **kwargs)
            launched.append(proc)
            return proc

        with patch("app.services.task_manager.subprocess.Popen", side_effect=_fake_popen):
            task_manager_module._dispatcher_start_assigned_task()

        self.assertEqual(1, len(launched))
        self.assertIn("-m", launched[0].args)
        self.assertIn("app.task_runner", launched[0].args)
        self.assertTrue(launched[0].kwargs.get("start_new_session"))

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-spawn").first()
            self.assertEqual(TaskStatus.RUNNING.value, task.status)
            self.assertEqual("pod-a:123:owner", task.owner_id)
            self.assertEqual(4321, task.runner_pid)
            self.assertIsNotNone(task.runner_started_at)
            self.assertIsNotNone(task.runner_heartbeat_at)
            self.assertIsNotNone(task.run_token)
        finally:
            db.close()

    def test_retry_success_task_enqueues_async_workspace_reset(self):
        self._add_task("t-success-retry", status=TaskStatus.SUCCESS.value)

        ok, retried_task_id, message = task_manager_module.retry_task("t-success-retry")

        self.assertTrue(ok)
        self.assertEqual("t-success-retry", retried_task_id)
        self.assertIn("重试", message)
        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-success-retry").first()
            self.assertEqual(TaskStatus.RETRY_PREPARING.value, task.status)
            self.assertEqual("retry_preparing", task.current_stage)
            self.assertIsNone(task.owner_id)
            job = db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.task_id == "t-success-retry").first()
            self.assertIsNotNone(job)
            self.assertEqual("task_retry_reset", job.reason)
            event = (
                db.query(UnpackTaskEvent)
                .filter(UnpackTaskEvent.task_id == "t-success-retry")
                .order_by(UnpackTaskEvent.created_at.desc())
                .first()
            )
            self.assertEqual("task_retry_requested", event.event_type)
        finally:
            db.close()

    def test_cancel_running_task_sets_deadlines_and_signals_runner(self):
        db = get_db_session()
        try:
            db.add(
                UnpackTask(
                    id="t-cancel-running",
                    project_id="p1",
                    firmware_path="/tmp/fw.bin",
                    output_path="/tmp/output",
                    status=TaskStatus.RUNNING.value,
                    owner_id="pod-a:123:owner",
                    current_stage="llm_unpack",
                    runner_pid=4321,
                    run_token="token-new",
                )
            )
            db.commit()
        finally:
            db.close()

        with patch("app.services.task_manager._signal_runner_process", return_value=True) as mocked_signal:
            ok, message = task_manager_module.cancel_task("t-cancel-running")

        self.assertTrue(ok)
        self.assertIn("取消", message)
        mocked_signal.assert_called_with(4321, task_manager_module.signal.SIGTERM)

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-cancel-running").first()
            self.assertEqual(TaskStatus.CANCELLING.value, task.status)
            self.assertIsNotNone(task.cancel_requested_at)
            self.assertIsNotNone(task.cancel_grace_deadline)
            self.assertIsNotNone(task.cancel_force_deadline)
        finally:
            db.close()

    def test_finalize_orphaned_running_task_owner_lost_moves_to_awaiting_takeover(self):
        self._add_task(
            "t-owner-lost",
            status=TaskStatus.RUNNING.value,
            owner_id="pod-a:123:owner",
            assigned_worker_id="pod-a:123:owner",
            dispatch_token="dispatch-token-1",
        )

        task_manager_module._finalize_orphaned_task("t-owner-lost", reason="Task owner pod lost", owner_lost=True)

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-owner-lost").first()
            self.assertEqual(TaskStatus.AWAITING_TAKEOVER.value, task.status)
            self.assertEqual("awaiting_takeover", task.current_stage)
            self.assertIsNone(task.result_status)
            self.assertIsNone(task.result_message)
            self.assertIsNone(task.error_message)
            self.assertEqual(1, int(task.takeover_count or 0))
            events = db.query(UnpackTaskEvent).filter(UnpackTaskEvent.task_id == "t-owner-lost").all()
            event_types = [event.event_type for event in events]
            self.assertIn("owner_lost", event_types)
            self.assertIn("owner_lost_detected", event_types)
            self.assertIn("owner_lost_requeue_scheduled", event_types)
            self.assertIn("orphan_recovered", event_types)
            self.assertNotIn("task_failed", event_types)
        finally:
            db.close()

    def test_finalize_orphaned_running_task_owner_lost_fails_after_retry_budget_exhausted(self):
        self._add_task(
            "t-owner-lost-exhausted",
            status=TaskStatus.RUNNING.value,
            owner_id="pod-a:123:owner",
            assigned_worker_id="pod-a:123:owner",
            dispatch_token="dispatch-token-2",
            takeover_count=3,
        )

        with patch("app.services.task_manager.get_max_retries", return_value=3):
            task_manager_module._finalize_orphaned_task(
                "t-owner-lost-exhausted",
                reason="Task owner pod lost",
                owner_lost=True,
            )

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-owner-lost-exhausted").first()
            self.assertEqual(TaskStatus.FAILED.value, task.status)
            self.assertEqual("awaiting_takeover", task.current_stage)
            self.assertEqual("failed", task.result_status)
            self.assertEqual("owner_lost_retry_exhausted", task.error_message)
            self.assertEqual(4, int(task.takeover_count or 0))
            events = db.query(UnpackTaskEvent).filter(UnpackTaskEvent.task_id == "t-owner-lost-exhausted").all()
            event_types = [event.event_type for event in events]
            self.assertIn("owner_lost_detected", event_types)
            self.assertIn("owner_lost_retry_exhausted", event_types)
            self.assertIn("task_failed", event_types)
        finally:
            db.close()

    def test_stale_run_token_cannot_overwrite_current_task(self):
        db = get_db_session()
        try:
            db.add(
                UnpackTask(
                    id="t-token-guard",
                    project_id="p1",
                    firmware_path="/tmp/fw.bin",
                    output_path="/tmp/output",
                    status=TaskStatus.RUNNING.value,
                    owner_id="pod-a:123:owner",
                    current_stage="llm_unpack",
                    run_token="token-current",
                )
            )
            db.commit()
        finally:
            db.close()

        task_manager_module._update_task_result(
            "t-token-guard",
            {"status": "success", "message": "should be ignored"},
            run_token="token-stale",
        )

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-token-guard").first()
            self.assertEqual(TaskStatus.RUNNING.value, task.status)
            self.assertEqual("token-current", task.run_token)
            self.assertIsNone(task.completed_at)
        finally:
            db.close()

    def test_recover_orphaned_running_task_moves_to_awaiting_takeover(self):
        from datetime import datetime, timedelta

        self._add_task(
            "t-orphan",
            status=TaskStatus.RUNNING.value,
            owner_id="dead-owner",
            lease_expires_at=datetime.utcnow() - timedelta(seconds=5),
            last_progress_at=datetime.utcnow() - timedelta(seconds=5),
        )

        task_manager_module.recover_orphaned_tasks()

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-orphan").first()
            self.assertEqual(TaskStatus.AWAITING_TAKEOVER.value, task.status)
            self.assertIsNone(task.owner_id)
            self.assertIsNone(task.error_message)
        finally:
            db.close()

    def test_recover_recent_running_task_with_missing_owner_keeps_running_during_startup_grace(self):
        recent = now_local() - timedelta(seconds=30)
        self._add_task(
            "t-recent-running",
            status=TaskStatus.RUNNING.value,
            owner_id="dead-owner",
            lease_expires_at=recent - timedelta(seconds=5),
            last_progress_at=recent,
        )
        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-recent-running").first()
            task.dispatch_claimed_at = recent
            task.started_at = recent
            task.runner_started_at = recent
            db.commit()
        finally:
            db.close()

        task_manager_module.recover_orphaned_tasks()

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-recent-running").first()
            self.assertEqual(TaskStatus.RUNNING.value, task.status)
            self.assertEqual("dead-owner", task.owner_id)
        finally:
            db.close()

    def test_recover_running_task_ignores_expired_task_lease_when_runner_alive(self):
        from datetime import timedelta

        self._add_worker("pod-a:123:owner", is_alive=True, last_heartbeat=now_local())
        self._add_task(
            "t-running-alive",
            status=TaskStatus.RUNNING.value,
            owner_id="pod-a:123:owner",
            lease_expires_at=now_local() - timedelta(seconds=300),
            last_progress_at=now_local() - timedelta(seconds=300),
        )
        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-running-alive").first()
            task.runner_pid = 43210
            task.run_token = "token-current"
            task.started_at = now_local() - timedelta(seconds=300)
            db.commit()
        finally:
            db.close()

        with patch("app.services.task_manager._is_process_alive", return_value=True):
            task_manager_module.recover_orphaned_tasks()

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-running-alive").first()
            self.assertEqual(TaskStatus.RUNNING.value, task.status)
            self.assertEqual("pod-a:123:owner", task.owner_id)
            self.assertIsNotNone(task.runner_heartbeat_at)
        finally:
            db.close()

    def test_recover_cancelling_timeout_marks_cancelled(self):
        from datetime import datetime, timedelta

        self._add_worker("alive-owner", is_alive=True)
        self._add_task(
            "t-cancel",
            status=TaskStatus.CANCELLING.value,
            owner_id="alive-owner",
            cancel_requested_at=datetime.utcnow() - timedelta(seconds=300),
            lease_expires_at=datetime.utcnow() + timedelta(seconds=30),
            last_progress_at=datetime.utcnow() - timedelta(seconds=300),
        )

        task_manager_module.recover_orphaned_tasks()

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-cancel").first()
            self.assertEqual(TaskStatus.CANCELLED.value, task.status)
            self.assertEqual("cancelled", task.result_status)
            self.assertIsNone(task.owner_id)
        finally:
            db.close()

    def test_recover_stale_owned_task_without_future_marks_cancelled(self):
        from datetime import datetime, timedelta

        self._add_task(
            "t-stale",
            status=TaskStatus.CANCELLING.value,
            owner_id="pod-a:123:owner",
            cancel_requested_at=datetime.utcnow() - timedelta(seconds=30),
            lease_expires_at=datetime.utcnow() + timedelta(seconds=30),
            last_progress_at=datetime.utcnow(),
        )

        task_manager_module.recover_stale_owned_tasks()

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-stale").first()
            self.assertEqual(TaskStatus.CANCELLED.value, task.status)
            self.assertIn("owner restarted", task.result_message or "")
        finally:
            db.close()

    def test_delete_task_enqueues_cleanup_job_without_removing_workspace_inline(self):
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"firmware")
        workspace_root = self.root / "data"
        outside_file = self.root / "outside.txt"
        outside_file.write_text("keep", encoding="utf-8")

        with patch("app.services.task_manager.PROJECT_FILES_ROOT", workspace_root):
            prepared = prepare_task_workspace("p1", "t-delete", str(firmware))

            db = get_db_session()
            try:
                db.add(
                    UnpackTask(
                        id="t-delete",
                        project_id="p1",
                        firmware_path=str(firmware),
                        output_path=prepared["output_path"],
                        status=TaskStatus.SUCCESS.value,
                        current_stage="cleanup",
                    )
                )
                db.commit()
            finally:
                db.close()

            with patch("app.services.task_manager.remove_task_workspace") as mocked_remove:
                deleted_count, skipped_ids = task_manager_module.delete_tasks(["t-delete"])

            self.assertEqual(1, deleted_count)
            self.assertEqual([], skipped_ids)
            mocked_remove.assert_not_called()
            self.assertTrue(outside_file.exists())

            db = get_db_session()
            try:
                task = db.query(UnpackTask).filter(UnpackTask.id == "t-delete").first()
                self.assertIsNone(task)
                jobs = db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.task_id == "t-delete").all()
                self.assertEqual(1, len(jobs))
                self.assertEqual("pending", jobs[0].status)
                self.assertEqual("task_deleted", jobs[0].reason)
            finally:
                db.close()

    def test_process_workspace_cleanup_jobs_removes_only_task_workspace(self):
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"firmware")
        workspace_root = self.root / "data"
        outside_file = self.root / "outside.txt"
        outside_file.write_text("keep", encoding="utf-8")

        with patch("app.services.task_manager.PROJECT_FILES_ROOT", workspace_root):
            prepared = prepare_task_workspace("p1", "t-clean", str(firmware))
            task_base_dir = Path(prepared["output_path"]).parent
            self.assertTrue(task_base_dir.exists())

            task_manager_module.enqueue_workspace_cleanup(
                "t-clean",
                "p1",
                reason="task_deleted",
                created_by="test",
            )
            processed = task_manager_module.process_workspace_cleanup_jobs(limit=1)

            self.assertEqual(1, processed)
            self.assertFalse(task_base_dir.exists())
            self.assertTrue(outside_file.exists())

            db = get_db_session()
            try:
                job = db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.task_id == "t-clean").first()
                self.assertIsNotNone(job)
                self.assertEqual("success", job.status)
                self.assertIsNotNone(job.completed_at)
            finally:
                db.close()

    def test_request_task_result_cache_refresh_enqueues_background_job(self):
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"firmware")
        workspace_root = self.root / "data"

        with patch("app.services.task_manager.PROJECT_FILES_ROOT", workspace_root):
            prepared = prepare_task_workspace("p1", "t-refresh-cache", str(firmware))

        db = get_db_session()
        try:
            db.add(
                UnpackTask(
                    id="t-refresh-cache",
                    project_id="p1",
                    firmware_path=str(firmware),
                    output_path=prepared["output_path"],
                    status=TaskStatus.SUCCESS.value,
                    current_stage="cleanup",
                )
            )
            db.commit()
        finally:
            db.close()

        class _FakeExecutor:
            def __init__(self):
                self.calls = []

            def submit(self, fn, *args, **kwargs):
                self.calls.append((fn, args, kwargs))
                class _FakeFuture:
                    def done(self):
                        return False
                return _FakeFuture()

        fake_executor = _FakeExecutor()
        with patch("app.services.task_manager.get_executor", return_value=fake_executor), \
             patch("app.services.task_manager._write_task_result_cache", side_effect=AssertionError("should not run inline")):
            ok, message = task_manager_module.request_task_result_cache_refresh("t-refresh-cache")

        self.assertTrue(ok)
        self.assertIn("后台", message)
        self.assertEqual(1, len(fake_executor.calls))
        self.assertEqual("t-refresh-cache", fake_executor.calls[0][1][0])


class TaskManagerMaxRetriesReachedActionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        config_path = root / "config.yaml"
        db_path = root / "tasks.db"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "database": {
                        "type": "sqlite",
                        "path": str(db_path),
                        "table_prefix": "secflow_app_firmware_unpacker_",
                    },
                }
            ),
            encoding="utf-8",
        )
        reload_config(str(config_path))
        model_module._engine = None
        model_module._SessionFactory = None
        init_database()

    def tearDown(self):
        model_module._engine = None
        model_module._SessionFactory = None
        self._tmp.cleanup()

    def _add_task(self, task_id: str):
        db = get_db_session()
        try:
            db.add(
                UnpackTask(
                    id=task_id,
                    project_id="p1",
                    firmware_path="/tmp/fw.bin",
                    output_path="/tmp/output",
                    status=TaskStatus.RUNNING.value,
                    owner_id="pod-a:123:owner",
                    current_stage="review",
                )
            )
            db.commit()
        finally:
            db.close()

    def _set_action(self, action: str):
        db = get_db_session()
        try:
            row = db.query(ServiceConfig).filter(ServiceConfig.key == "max_retries_reached_action").first()
            if row is None:
                row = ServiceConfig(
                    key="max_retries_reached_action",
                    value=action,
                    value_type="string",
                    description="",
                )
                db.add(row)
            else:
                row.value = action
            db.commit()
        finally:
            db.close()

    def test_max_retries_reached_can_be_treated_as_success(self):
        self._add_task("t-pass")
        self._set_action("success")

        task_manager_module._update_task_result(
            "t-pass",
            {
                "status": "max_retries_reached",
                "message": "Max retries reached. Last reason: none",
                "rounds": 5,
            },
        )

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-pass").first()
            self.assertEqual(TaskStatus.SUCCESS.value, task.status)
            self.assertEqual("max_retries_reached", task.result_status)
            event = db.query(UnpackTaskEvent).filter(UnpackTaskEvent.task_id == "t-pass").order_by(UnpackTaskEvent.created_at.desc()).first()
            self.assertEqual("task_succeeded", event.event_type)
        finally:
            db.close()

    def test_max_retries_reached_can_be_treated_as_failed(self):
        self._add_task("t-fail")
        self._set_action("failed")

        task_manager_module._update_task_result(
            "t-fail",
            {
                "status": "max_retries_reached",
                "message": "Max retries reached. Last reason: none",
                "rounds": 5,
            },
        )

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-fail").first()
            self.assertEqual(TaskStatus.FAILED.value, task.status)
            self.assertEqual("max_retries_reached", task.result_status)
            event = db.query(UnpackTaskEvent).filter(UnpackTaskEvent.task_id == "t-fail").order_by(UnpackTaskEvent.created_at.desc()).first()
            self.assertEqual("task_failed", event.event_type)
        finally:
            db.close()


class TaskManagerLlmSnapshotTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.root = root
        self.firmware = root / "firmware.bin"
        self.firmware.write_bytes(b"firmware")
        config_path = root / "config.yaml"
        db_path = root / "tasks.db"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "database": {
                        "type": "sqlite",
                        "path": str(db_path),
                        "table_prefix": "secflow_app_firmware_unpacker_",
                    },
                    "configcenter_service": {
                        "enabled": True,
                        "base_url": "http://configcenter/api/configcenter",
                        "timeout": 30,
                    },
                }
            ),
            encoding="utf-8",
        )
        reload_config(str(config_path))
        model_module._engine = None
        model_module._SessionFactory = None
        init_database()

    def tearDown(self):
        model_module._engine = None
        model_module._SessionFactory = None
        self._tmp.cleanup()

    def test_submit_task_freezes_llm_binding_snapshot_immediately(self):
        provider_keys = {
            "llm_config_file_key_executor": "provider-executor-v1",
            "llm_config_file_key_reviewer": "provider-reviewer-v1",
            "llm_config_file_key_cleaner": "provider-cleaner-v1",
            "llm_config_file_key_skill_author": "provider-author-v1",
            "llm_config_file_key_skill_executor": "provider-skill-v1",
            "llm_config_file_key_evolution_improver": "provider-evolution-v1",
        }
        provider_payloads = {
            provider_key: {
                "provider_key": provider_key,
                "provider_type": "openai-compatible",
                "api_base": f"http://llm.local/{provider_key}",
                "api_key": f"secret-{provider_key}",
                "model": f"model-{provider_key}",
                "env_bindings": {"TRACE_ID": provider_key},
                "updated_at": "2026-05-08T00:00:00",
            }
            for provider_key in provider_keys.values()
        }

        class _FakeClient:
            def get_llm_config_file(self, config_file_key: str):
                payload = provider_payloads[config_file_key]
                return {
                    "config_file_key": config_file_key,
                    "display_name": config_file_key,
                    "default_model": f"{config_file_key}/{payload['model']}",
                    "updated_at": payload["updated_at"],
                    "models_json": {
                        "providers": {
                            config_file_key: {
                                "type": "openai-compatible",
                                "baseURL": payload["api_base"],
                                "apiKeyEnv": "OPENAI_API_KEY",
                                "models": [payload["model"]],
                            }
                        }
                    },
                }

        db = get_db_session()
        try:
            for key, value in provider_keys.items():
                row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
                if row is None:
                    row = ServiceConfig(key=key, value="", value_type="string", description="")
                    db.add(row)
                row.value = value
            db.commit()
        finally:
            db.close()

        with patch("app.services.task_manager.PROJECT_FILES_ROOT", self.root / "data"), \
             patch("app.services.configcenter.get_configcenter_client", return_value=_FakeClient()):
            created = submit_unpack_task(
                firmware_path=str(self.firmware),
                project_id="p1",
            )

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == created["task_id"]).first()
            snapshot = json.loads(task.llm_binding_snapshot)
            self.assertEqual("provider-executor-v1", snapshot["roles"]["executor"]["provider_key"])
            self.assertEqual("provider-reviewer-v1", snapshot["roles"]["reviewer"]["provider_key"])
            created_events = db.query(UnpackTaskEvent).filter(UnpackTaskEvent.task_id == created["task_id"]).all()
            self.assertTrue(any(event.event_type == "task_created" for event in created_events))

            row = db.query(ServiceConfig).filter(ServiceConfig.key == "llm_config_file_key_executor").first()
            row.value = "provider-executor-v2"
            db.commit()
        finally:
            db.close()

        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == created["task_id"]).first()
            snapshot = json.loads(task.llm_binding_snapshot)
            self.assertEqual("provider-executor-v1", snapshot["roles"]["executor"]["provider_key"])
        finally:
            db.close()

    def test_record_task_event_auto_trims_oldest_events_when_limit_exceeded(self):
        task_id = "t-event-trim"
        db = get_db_session()
        try:
            db.add(
                UnpackTask(
                    id=task_id,
                    project_id="p1",
                    firmware_path=str(self.firmware),
                    output_path=str(self.root / "output"),
                    status=TaskStatus.RUNNING.value,
                )
            )
            db.commit()
        finally:
            db.close()

        with patch.object(task_events_module, "DB_TIMELINE_EVENT_LIMIT", 3):
            for idx in range(4):
                record_task_event(
                    task_id,
                    project_id="p1",
                    event_type=f"progress_{idx}",
                    summary=f"event {idx}",
                )

        db = get_db_session()
        try:
            rows = (
                db.query(UnpackTaskEvent)
                .filter(UnpackTaskEvent.task_id == task_id)
                .order_by(UnpackTaskEvent.created_at.asc(), UnpackTaskEvent.id.asc())
                .all()
            )
            self.assertEqual(3, len(rows))
            self.assertEqual(
                ["progress_1", "progress_2", "progress_3"],
                [row.event_type for row in rows],
            )
        finally:
            db.close()

    def test_cancel_task_records_cancel_requested_event(self):
        provider_keys = {
            "llm_config_file_key_executor": "provider-executor-v1",
            "llm_config_file_key_reviewer": "provider-reviewer-v1",
            "llm_config_file_key_cleaner": "provider-cleaner-v1",
            "llm_config_file_key_skill_author": "provider-author-v1",
            "llm_config_file_key_skill_executor": "provider-skill-v1",
            "llm_config_file_key_evolution_improver": "provider-evolution-v1",
        }

        class _FakeClient:
            def get_llm_config_file(self, config_file_key: str):
                return {
                    "config_file_key": config_file_key,
                    "display_name": config_file_key,
                    "default_model": f"{config_file_key}/model-default",
                    "updated_at": "2026-05-08T00:00:00",
                    "models_json": {
                        "providers": {
                            config_file_key: {
                                "type": "openai-compatible",
                                "baseURL": f"http://llm.local/{config_file_key}",
                                "apiKeyEnv": "OPENAI_API_KEY",
                                "models": ["model-default"],
                            }
                        }
                    },
                }

        db = get_db_session()
        try:
            for key, value in provider_keys.items():
                row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
                if row is None:
                    row = ServiceConfig(key=key, value="", value_type="string", description="")
                    db.add(row)
                row.value = value
            db.commit()
        finally:
            db.close()

        with patch("app.services.task_manager.PROJECT_FILES_ROOT", self.root / "data"), \
             patch("app.services.configcenter.get_configcenter_client", return_value=_FakeClient()):
            created = submit_unpack_task(
                firmware_path=str(self.firmware),
                project_id="p1",
            )

        ok, _ = task_manager_module.cancel_task(created["task_id"])
        self.assertTrue(ok)
        events = list_task_events(created["task_id"])
        event_types = [item["event_type"] for item in events["items"]]
        self.assertIn("cancel_requested", event_types)
        self.assertIn("task_cancelled", event_types)


class PiSessionRecordingTests(unittest.TestCase):
    def test_build_args_include_session_flags(self):
        args = unpacker_engine_module.PiRpcClient.build_args(
            model="demo-model",
            tools=["read", "bash"],
            session_dir="/tmp/sessions",
            session_path="/tmp/sessions/executor.round-1.session.jsonl",
        )

        self.assertIn("--session-dir", args)
        self.assertIn("/tmp/sessions", args)
        self.assertIn("--session", args)
        self.assertIn("/tmp/sessions/executor.round-1.session.jsonl", args)
        self.assertNotIn("--no-session", args)

    def test_session_index_tracks_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "run"
            log_dir.mkdir(parents=True, exist_ok=True)
            session = unpacker_engine_module.build_session_artifacts(
                log_dir,
                role="executor",
                name="round-1",
                provider_role="executor",
                phase="llm_unpack",
                round_id=1,
            )
            unpacker_engine_module.update_session_index(
                session["session_dir"],
                role=session["session_role"],
                name=session["session_name"],
                session_file=session["session_path"].name,
                provider_role=session["provider_role"],
                phase=session["phase"],
                status="created",
                round_id=session["round"],
                skill_name=session["skill_name"],
            )
            unpacker_engine_module.update_session_index(
                session["session_dir"],
                role=session["session_role"],
                name=session["session_name"],
                session_file=session["session_path"].name,
                provider_role=session["provider_role"],
                phase=session["phase"],
                status="running",
                round_id=session["round"],
                skill_name=session["skill_name"],
            )
            unpacker_engine_module.update_session_index(
                session["session_dir"],
                role=session["session_role"],
                name=session["session_name"],
                session_file=session["session_path"].name,
                provider_role=session["provider_role"],
                phase=session["phase"],
                status="closed",
                round_id=session["round"],
                skill_name=session["skill_name"],
            )

            payload = json.loads((log_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(1, payload["version"])
            self.assertEqual(1, len(payload["items"]))
            item = payload["items"][0]
            self.assertEqual("executor", item["role"])
            self.assertEqual("round-1", item["name"])
            self.assertEqual("executor.round-1.session.jsonl", item["session_file"])
            self.assertEqual("closed", item["status"])
            self.assertEqual(1, item["round"])
            self.assertIsNotNone(item["closed_at"])

    def test_pi_rpc_client_marks_failed_when_startup_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "run"
            log_dir.mkdir(parents=True, exist_ok=True)
            session = unpacker_engine_module.build_session_artifacts(
                log_dir,
                role="cleaner",
                name="default",
                provider_role="cleaner",
                phase="cleanup",
            )

            with patch("app.unpacker_engine.subprocess.Popen", side_effect=RuntimeError("boom")):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    unpacker_engine_module.PiRpcClient(
                        provider_role=None,
                        session_dir=session["session_dir"],
                        session_path=session["session_path"],
                        session_role=session["session_role"],
                        session_name=session["session_name"],
                        session_phase=session["phase"],
                        session_round=session["round"],
                        session_skill_name=session["skill_name"],
                    )

            payload = json.loads((log_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
            item = payload["items"][0]
            self.assertEqual("failed", item["status"])
            self.assertIsNotNone(item["closed_at"])

    def test_run_reviewer_uses_role_and_round_session_name(self):
        captured = {}

        class _FakePi:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def prompt(self, *_args, **_kwargs):
                return '{"result":"success"}'

            def get_messages(self):
                return []

            def get_token_stats(self):
                return {"tokens": {}}

            def close(self):
                return None

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "run"
            log_dir.mkdir(parents=True, exist_ok=True)
            with patch("app.unpacker_engine.PiRpcClient", _FakePi):
                passed, _review, _meta = unpacker_engine_module._run_reviewer(
                    "task-1",
                    "/tmp/fw.bin",
                    "/tmp/output",
                    log_dir,
                    log_dir / "round_002",
                    "round_2",
                    {"model": "demo", "tools": []},
                    "/tmp/reviewer.md",
                )

        self.assertTrue(passed)
        self.assertEqual("reviewer", captured["session_role"])
        self.assertEqual("round-2", captured["session_name"])
        self.assertEqual("review", captured["session_phase"])
        self.assertEqual(2, captured["session_round"])
        self.assertEqual("reviewer.round-2.session.jsonl", captured["session_path"].name)

    def test_run_skill_unpack_uses_skill_executor_session_name(self):
        captured = {}

        class _FakePi:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def prompt(self, *_args, **_kwargs):
                return "ok"

            def get_messages(self):
                return []

            def get_token_stats(self):
                return {"tokens": {}}

            def close(self):
                return None

        skill_meta = {
            "path": "/tmp/tools/vendor-router.md",
            "system_prompt": "system",
            "model": "demo",
            "tools": [],
            "family_id": "family",
            "skill_version": 1,
            "filename": "vendor-router.md",
        }

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "run"
            log_dir.mkdir(parents=True, exist_ok=True)
            with patch("app.unpacker_engine.PiRpcClient", _FakePi), \
                 patch("app.unpacker_engine._run_reviewer", return_value=(True, '{"result":"success"}', {})):
                result = unpacker_engine_module._run_skill_unpack(
                    "task-1",
                    skill_meta,
                    "/tmp/fw.bin",
                    "/tmp/output",
                    log_dir,
                    {"model": "demo", "tools": []},
                    "/tmp/reviewer.md",
                )

        self.assertTrue(result["success"])
        self.assertEqual("skill-executor", captured["session_role"])
        self.assertEqual("vendor-router", captured["session_name"])
        self.assertEqual("tool_match", captured["session_phase"])
        self.assertEqual("vendor-router", captured["session_skill_name"])
        self.assertEqual("skill-executor.vendor-router.session.jsonl", captured["session_path"].name)


if __name__ == "__main__":
    unittest.main()
