from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from app.api import tasks as task_api
from app.model import B2STask, B2STaskItem
from app.service.pi_cluster import PiWorkerActiveJobSnapshot, PiWorkerSnapshot


class PiClusterApiTests(unittest.TestCase):
    def test_build_active_job_response_maps_b2s_task_item(self) -> None:
        task = B2STask(
            id="task-1",
            project_id="project-1",
            name="demo-task",
            task_origin_type="binary_security",
            parent_task_id="parent-1",
            status="running",
        )
        item = B2STaskItem(
            id="item-1",
            task_id="task-1",
            project_id="project-1",
            sequence_no=2,
            elf_path="/data/files/demo.elf",
            output_dir="/tmp/out",
            pi_job_id="job-1",
            status="running",
        )
        response = task_api._build_active_job_response(
            PiWorkerActiveJobSnapshot(
                pi_job_id="job-1",
                status="running",
                phase="body_generation",
                worker_id="pi-1",
                elf_path="/tmp/upstream-demo.elf",
                elf_name="upstream-demo.elf",
                current_batch=3,
                current_attempt=1,
                current_function="demo_func",
                started_at="2026-05-20T10:00:00",
                updated_at="2026-05-20T10:05:00",
            ),
            item_by_job_id={"job-1": item},
            task_by_id={"task-1": task},
        )

        self.assertTrue(response.mapped)
        self.assertEqual("matched_item", response.mapping_reason)
        self.assertEqual("task-1", response.task_id)
        self.assertEqual("demo-task", response.task_name)
        self.assertEqual("parent-1", response.parent_task_id)
        self.assertEqual("/data/files/demo.elf", response.elf_path)
        self.assertEqual("demo.elf", response.elf_name)
        self.assertEqual(2, response.sequence_no)

    def test_build_active_job_response_keeps_orphan_job(self) -> None:
        response = task_api._build_active_job_response(
            PiWorkerActiveJobSnapshot(
                pi_job_id="job-orphan",
                status="running",
                phase="header_synthesis",
                worker_id="pi-2",
                elf_path="/tmp/orphan.elf",
                elf_name="orphan.elf",
                current_batch=None,
                current_attempt=None,
                current_function=None,
                started_at="2026-05-20T10:00:00",
                updated_at="2026-05-20T10:03:00",
            ),
            item_by_job_id={},
            task_by_id={},
        )

        self.assertFalse(response.mapped)
        self.assertEqual("orphan_pi_job", response.mapping_reason)
        self.assertEqual("/tmp/orphan.elf", response.elf_path)
        self.assertEqual("orphan.elf", response.elf_name)
        self.assertIsNone(response.task_id)

    def test_load_worker_active_jobs_downgrades_single_worker_error(self) -> None:
        healthy = PiWorkerSnapshot(
            worker_id="pi-1",
            url="http://pi-1:8000",
            healthy=True,
            max_concurrent_jobs=3,
        )
        unhealthy = PiWorkerSnapshot(
            worker_id="pi-2",
            url="http://pi-2:8000",
            healthy=False,
            max_concurrent_jobs=3,
            error="down",
        )

        async def _run():
            with mock.patch.object(task_api, "fetch_worker_active_jobs", side_effect=RuntimeError("detail boom")):
                return await task_api._load_worker_active_jobs([healthy, unhealthy])

        active_jobs_by_worker, worker_errors = asyncio.run(_run())

        self.assertEqual([], active_jobs_by_worker["pi-1"])
        self.assertEqual([], active_jobs_by_worker["pi-2"])
        self.assertEqual("detail boom", worker_errors["pi-1"])
        self.assertNotIn("pi-2", worker_errors)


if __name__ == "__main__":
    unittest.main()
