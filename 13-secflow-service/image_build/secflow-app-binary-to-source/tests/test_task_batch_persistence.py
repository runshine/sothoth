from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.model import Base, B2STask, B2STaskBatch, B2STaskItem
from app.service import task_service
from app.time_utils import now_local


def _item() -> B2STaskItem:
    return B2STaskItem(
        id="item-1",
        task_id="task-1",
        project_id="project-1",
        sequence_no=1,
        elf_path="/tmp/demo.elf",
        output_dir="/tmp/out",
        status="running",
        phase="body",
        updated_at=now_local(),
    )


class TaskBatchPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        self.Session = sessionmaker(bind=engine)
        self.db = self.Session()
        self.task = B2STask(id="task-1", project_id="project-1", name="demo", status="running")
        self.item = _item()
        self.db.add(self.task)
        self.db.add(self.item)
        self.db.flush()

    def tearDown(self) -> None:
        self.db.close()

    def test_sync_batch_records_upserts_running_and_finalizes(self) -> None:
        previous = {
            "progress": {
                "current_batch": 1,
                "current_attempt": 1,
                "current_function": "sub_401000",
                "completed_batches": 0,
            }
        }
        self.item.progress = {
            "current_batch": 1,
            "current_attempt": 2,
            "current_function": "sub_402000",
            "completed_batches": 1,
        }
        self.item.updated_at = now_local()

        task_service.sync_batch_records_from_progress(self.db, item=self.item, previous=previous)
        self.db.commit()

        row = self.db.query(B2STaskBatch).filter_by(task_id="task-1", item_id="item-1", batch_no=1).one()
        self.assertEqual("running", row.status)
        self.assertEqual(2, row.attempt_count)
        self.assertEqual(2, row.current_attempt_no)
        self.assertEqual("sub_402000", row.current_function)

        self.item.status = "success"
        self.item.progress = {
            "current_batch": 1,
            "current_attempt": 2,
            "completed_batches": 1,
        }
        self.item.updated_at = now_local()
        task_service.sync_batch_records_from_progress(self.db, item=self.item, previous={
            "progress": {
                "current_batch": 1,
                "current_attempt": 2,
                "current_function": "sub_402000",
                "completed_batches": 0,
            }
        })
        self.db.commit()

        row = self.db.query(B2STaskBatch).filter_by(task_id="task-1", item_id="item-1", batch_no=1).one()
        self.assertEqual("passed", row.status)
        self.assertIsNotNone(row.finished_at)
        self.assertGreaterEqual(int(row.duration_ms or 0), 0)

    def test_rerun_task_clears_batch_rows(self) -> None:
        self.db.add(
            B2STaskBatch(
                id="batch-1",
                task_id="task-1",
                project_id="project-1",
                item_id="item-1",
                sequence_no=1,
                batch_no=1,
                status="passed",
            )
        )
        self.db.commit()

        with mock.patch.object(task_service, "materialize_llm_provider", return_value=None), \
            mock.patch.object(task_service, "get_config", return_value=mock.Mock(configcenter_service=mock.Mock(enabled=False))), \
            mock.patch.object(task_service, "get_pi_client") as mocked_pi_client, \
            mock.patch.object(task_service, "clean_item_output_dir", return_value=Path("/tmp/out")), \
            mock.patch.object(task_service, "_restart_llm_provider_key", return_value=None):
            mocked_pi_client.return_value.cancel_job = mock.AsyncMock()
            self.item.pi_job_id = None
            self.item.status = "running"
            self.item.extra_metadata = {}
            self.item.output_dir = str(Path(tempfile.gettempdir()) / "out")
            self.item.updated_at = now_local()
            asyncio_rerun = task_service.rerun_task(self.db, self.task)
            if hasattr(asyncio_rerun, "__await__"):
                import asyncio

                asyncio.run(asyncio_rerun)

        self.assertEqual([], self.db.query(B2STaskBatch).all())


if __name__ == "__main__":
    unittest.main()
