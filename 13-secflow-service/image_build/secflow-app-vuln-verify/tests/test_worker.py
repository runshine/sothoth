import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.model import Base, VulnVerifyTask, VulnVerifyTaskEvent
from app.service.worker import VulnVerifyWorker
from app.time_utils import now_local


class VulnVerifyWorkerRateLimitTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    def _create_task(self, db, *, task_id: str, output_dir: str, worker_id: str) -> VulnVerifyTask:
        task = VulnVerifyTask(
            id=task_id,
            project_id="p1",
            name="rate limit task",
            status="running",
            reports_dir=output_dir,
            source_root=output_dir,
            binary_root=output_dir,
            threat_path=str(Path(output_dir) / "threat.md"),
            output_dir=output_dir,
            model="test-model",
            concurrency=1,
            resume=0,
            worker_id=worker_id,
            created_at=now_local(),
            updated_at=now_local(),
            started_at=now_local(),
        )
        db.add(task)
        db.commit()
        return task

    def test_run_one_retries_http_429_then_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "threat.md").write_text("threat", encoding="utf-8")
            db = self.SessionLocal()
            worker = VulnVerifyWorker()
            worker.owner_id = "worker-test"
            try:
                self._create_task(
                    db,
                    task_id="vv_429",
                    output_dir=str(tmp_path),
                    worker_id=worker.owner_id,
                )
            finally:
                db.close()

            class FakeProcess:
                def __init__(self, pid: int, return_code: int):
                    self.pid = pid
                    self._return_code = return_code

                def poll(self):
                    return self._return_code

            popen_calls = {"count": 0, "cmds": []}

            def fake_popen(cmd, **kwargs):
                popen_calls["count"] += 1
                popen_calls["cmds"].append(list(cmd))
                if popen_calls["count"] == 1:
                    kwargs["stderr"].write(b"429 too many requests\n")
                    kwargs["stderr"].flush()
                    return FakeProcess(101, 1)
                kwargs["stdout"].write(b"ok\n")
                kwargs["stdout"].flush()
                return FakeProcess(102, 0)

            cfg = SimpleNamespace(
                worker=SimpleNamespace(
                    lease_seconds=300,
                    heartbeat_interval_seconds=2,
                    task_timeout_seconds=0,
                )
            )

            with patch("app.service.worker.get_db_session", side_effect=self.SessionLocal):
                with patch("app.service.worker.get_config", return_value=cfg):
                    with patch("app.service.worker.subprocess.Popen", side_effect=fake_popen):
                        with patch("app.service.worker.summarize_results", return_value={"result_count": 1}):
                            with patch("app.service.worker.asyncio.sleep", new=AsyncMock()) as mock_sleep:
                                asyncio.run(worker._run_one("vv_429"))

            final_db = self.SessionLocal()
            try:
                task = final_db.query(VulnVerifyTask).filter_by(id="vv_429").first()
                events = (
                    final_db.query(VulnVerifyTaskEvent)
                    .filter(VulnVerifyTaskEvent.task_id == "vv_429")
                    .order_by(VulnVerifyTaskEvent.created_at.asc())
                    .all()
                )
                self.assertIsNotNone(task)
                self.assertEqual("success", task.status)
                self.assertIsNone(task.error_reason)
                self.assertEqual(0, task.return_code)
                self.assertEqual(2, popen_calls["count"])
                first_cmd = popen_calls["cmds"][0]
                self.assertIn("--session-dir", first_cmd)
                self.assertEqual(str(tmp_path / "run"), first_cmd[first_cmd.index("--session-dir") + 1])
                self.assertTrue((tmp_path / "run").is_dir())
                mock_sleep.assert_awaited_once_with(30)
                rate_limit_events = [event for event in events if event.event_type == "task_rate_limited_retrying"]
                self.assertEqual(1, len(rate_limit_events))
                self.assertEqual(429, rate_limit_events[0].payload.get("http_status"))
                self.assertEqual(30, rate_limit_events[0].payload.get("retry_delay_seconds"))
                self.assertEqual(1, rate_limit_events[0].payload.get("consecutive_rate_limit_count"))
            finally:
                final_db.close()
