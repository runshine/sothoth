import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from app.config import reload_config
from app.model import TaskStatus, UnpackTask, WorkerInstance, get_db_session, init_database
import app.model as model_module
import app.services.task_manager as task_manager_module
from app.model import ServiceConfig
from app.services.task_manager import prepare_task_workspace, resolve_task_runtime_paths, submit_unpack_task


class TaskManagerWorkspaceTests(unittest.TestCase):
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
                    "log_path": prepared["run_path"],
                },
                json.loads(manifest_path.read_text(encoding="utf-8")),
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
        model_module._engine = None
        model_module._SessionFactory = None
        model_module._OWNER_ID = None
        self._tmp.cleanup()

    def _add_task(self, task_id: str, *, status: str, owner_id: str | None = None, cancel_requested_at=None, lease_expires_at=None, last_progress_at=None):
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

    def test_claim_task_sets_owner_and_lease(self):
        self._add_task("t-claim", status=TaskStatus.PENDING.value)

        claimed = task_manager_module._claim_task("t-claim")

        self.assertTrue(claimed)
        db = get_db_session()
        try:
            task = db.query(UnpackTask).filter(UnpackTask.id == "t-claim").first()
            self.assertEqual(TaskStatus.RUNNING.value, task.status)
            self.assertEqual("pod-a:123:owner", task.owner_id)
            self.assertEqual("queued", task.current_stage)
            self.assertIsNotNone(task.lease_expires_at)
        finally:
            db.close()

    def test_recover_orphaned_running_task_marks_failed(self):
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
            self.assertEqual(TaskStatus.FAILED.value, task.status)
            self.assertIsNone(task.owner_id)
            self.assertIn("owner lost", (task.result_message or "") + (task.error_message or ""))
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
            "llm_provider_key_executor": "provider-executor-v1",
            "llm_provider_key_reviewer": "provider-reviewer-v1",
            "llm_provider_key_cleaner": "provider-cleaner-v1",
            "llm_provider_key_skill_author": "provider-author-v1",
            "llm_provider_key_skill_executor": "provider-skill-v1",
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
            def get_llm_provider(self, provider_key: str):
                return provider_payloads[provider_key]

        db = get_db_session()
        try:
            for key, value in provider_keys.items():
                row = db.query(ServiceConfig).filter(ServiceConfig.key == key).first()
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

            row = db.query(ServiceConfig).filter(ServiceConfig.key == "llm_provider_key_executor").first()
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


if __name__ == "__main__":
    unittest.main()
