import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import yaml

from app.config import reload_config
from app.model import WorkerInstance, WorkspaceCleanupJob, get_db_session, init_database
import app.model as model_module
import app.services.worker as worker_module
from app.time_utils import now_local


class WorkerMaintenanceTests(unittest.TestCase):
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
                    "service": {
                        "worker_history_retention_days": 7,
                        "cleanup_job_retention_days": 7,
                    },
                    "worker": {
                        "dead_threshold_seconds": 90,
                    },
                }
            ),
            encoding="utf-8",
        )
        reload_config(str(config_path))
        model_module._engine = None
        model_module._SessionFactory = None
        model_module._OWNER_ID = "worker-under-test"
        init_database()

    def tearDown(self):
        model_module._engine = None
        model_module._SessionFactory = None
        model_module._OWNER_ID = None
        self._tmp.cleanup()

    def test_reclaim_orphaned_tasks_marks_only_currently_alive_stale_workers(self):
        cutoff_time = now_local() - timedelta(minutes=30)
        db = get_db_session()
        try:
            db.add(
                WorkerInstance(
                    worker_id="alive-stale",
                    hostname="pod-a",
                    pod_ip="127.0.0.1",
                    started_at=cutoff_time,
                    last_heartbeat=cutoff_time,
                    is_alive=True,
                    active_tasks=2,
                )
            )
            db.add(
                WorkerInstance(
                    worker_id="already-dead",
                    hostname="pod-b",
                    pod_ip="127.0.0.2",
                    started_at=cutoff_time,
                    last_heartbeat=cutoff_time,
                    is_alive=False,
                    active_tasks=0,
                )
            )
            db.commit()
        finally:
            db.close()

        with unittest.mock.patch("app.services.worker.recover_orphaned_tasks") as mocked_recover:
            worker_module.reclaim_orphaned_tasks()

        mocked_recover.assert_called_once()
        db = get_db_session()
        try:
            alive_stale = db.query(WorkerInstance).filter(WorkerInstance.worker_id == "alive-stale").first()
            already_dead = db.query(WorkerInstance).filter(WorkerInstance.worker_id == "already-dead").first()
            self.assertFalse(alive_stale.is_alive)
            self.assertEqual(0, alive_stale.active_tasks)
            self.assertFalse(already_dead.is_alive)
            self.assertEqual(0, already_dead.active_tasks)
        finally:
            db.close()

    def test_prune_worker_history_deletes_old_inactive_rows(self):
        old_time = now_local() - timedelta(days=10)
        fresh_time = now_local() - timedelta(days=1)
        db = get_db_session()
        try:
            db.add(
                WorkerInstance(
                    worker_id="old-dead",
                    hostname="pod-a",
                    pod_ip="127.0.0.1",
                    started_at=old_time,
                    last_heartbeat=old_time,
                    is_alive=False,
                    active_tasks=0,
                )
            )
            db.add(
                WorkerInstance(
                    worker_id="fresh-dead",
                    hostname="pod-b",
                    pod_ip="127.0.0.2",
                    started_at=fresh_time,
                    last_heartbeat=fresh_time,
                    is_alive=False,
                    active_tasks=0,
                )
            )
            db.add(
                WorkerInstance(
                    worker_id="old-alive",
                    hostname="pod-c",
                    pod_ip="127.0.0.3",
                    started_at=old_time,
                    last_heartbeat=old_time,
                    is_alive=True,
                    active_tasks=0,
                )
            )
            db.commit()
        finally:
            db.close()

        deleted = worker_module.prune_worker_history()

        self.assertEqual(1, deleted)
        db = get_db_session()
        try:
            self.assertIsNone(db.query(WorkerInstance).filter(WorkerInstance.worker_id == "old-dead").first())
            self.assertIsNotNone(db.query(WorkerInstance).filter(WorkerInstance.worker_id == "fresh-dead").first())
            self.assertIsNotNone(db.query(WorkerInstance).filter(WorkerInstance.worker_id == "old-alive").first())
        finally:
            db.close()

    def test_prune_finished_cleanup_jobs_deletes_only_old_completed_rows(self):
        old_time = now_local() - timedelta(days=10)
        fresh_time = now_local() - timedelta(days=1)
        db = get_db_session()
        try:
            db.add(
                WorkspaceCleanupJob(
                    id="job-old-success",
                    task_id="t1",
                    project_id="p1",
                    status="success",
                    completed_at=old_time,
                )
            )
            db.add(
                WorkspaceCleanupJob(
                    id="job-old-failed",
                    task_id="t2",
                    project_id="p1",
                    status="failed",
                    completed_at=old_time,
                )
            )
            db.add(
                WorkspaceCleanupJob(
                    id="job-fresh-success",
                    task_id="t3",
                    project_id="p1",
                    status="success",
                    completed_at=fresh_time,
                )
            )
            db.add(
                WorkspaceCleanupJob(
                    id="job-running",
                    task_id="t4",
                    project_id="p1",
                    status="running",
                    completed_at=old_time,
                )
            )
            db.commit()
        finally:
            db.close()

        deleted = worker_module.prune_finished_cleanup_jobs()

        self.assertEqual(2, deleted)
        db = get_db_session()
        try:
            self.assertIsNone(db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.id == "job-old-success").first())
            self.assertIsNone(db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.id == "job-old-failed").first())
            self.assertIsNotNone(db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.id == "job-fresh-success").first())
            self.assertIsNotNone(db.query(WorkspaceCleanupJob).filter(WorkspaceCleanupJob.id == "job-running").first())
        finally:
            db.close()
