from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from app.model import B2STask, B2STaskItem
from app.service import task_service


def _task(task_id: str = "task-1", status: str = "pending") -> B2STask:
    return B2STask(
        id=task_id,
        project_id="project-1",
        name="demo",
        status=status,
    )


def _item(sequence_no: int, status: str) -> B2STaskItem:
    return B2STaskItem(
        id=f"item-{sequence_no}",
        task_id="task-1",
        project_id="project-1",
        sequence_no=sequence_no,
        elf_path=f"/tmp/demo-{sequence_no}.elf",
        output_dir=f"/tmp/out-{sequence_no}",
        status=status,
    )


class RecomputeTaskStatusTests(unittest.TestCase):
    def test_event_dedupe_key_caps_length_for_long_error_messages(self) -> None:
        long_message = "400 litellm.BadRequestError: " + ("Hosted_vllmException|" * 40)

        key = task_service._event_dedupe_key(
            "task-1",
            "",
            "abnormal_reason_recorded",
            "downstream_failed",
            "failed",
            long_message,
        )

        self.assertLessEqual(len(key), 255)
        self.assertEqual(key, task_service._event_dedupe_key(
            "task-1",
            "",
            "abnormal_reason_recorded",
            "downstream_failed",
            "failed",
            long_message,
        ))

    def test_all_pending_items_stay_pending(self) -> None:
        task = _task()
        items = [_item(1, "pending"), _item(2, "pending")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("pending", task.status)

    def test_started_task_with_completed_and_pending_items_is_running(self) -> None:
        task = _task()
        items = [_item(1, "success"), _item(2, "pending"), _item(3, "pending")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("running", task.status)

    def test_queued_items_are_running(self) -> None:
        task = _task()
        items = [_item(1, "queued"), _item(2, "pending")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("running", task.status)

    def test_mixed_terminal_results_become_partial(self) -> None:
        task = _task()
        items = [_item(1, "success"), _item(2, "failed")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("failed", task.status)

    def test_partial_status_requires_final_partial_items_without_failed_or_cancelled(self) -> None:
        task = _task()
        items = [_item(1, "success"), _item(2, "partial")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("partial", task.status)

    def test_all_success_items_complete_task(self) -> None:
        task = _task()
        items = [_item(1, "success"), _item(2, "success")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("completed", task.status)

    def test_cancelling_items_make_task_cancelling_until_all_cancelled(self) -> None:
        task = _task(status="running")
        items = [_item(1, "cancelling"), _item(2, "cancelled")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("cancelling", task.status)


class OverallProgressTests(unittest.TestCase):
    def test_progress_falls_back_to_bytes_when_function_coverage_is_partial(self) -> None:
        item1 = _item(1, "success")
        item1.progress = {
            "total_functions": 10,
            "completed_functions": 10,
            "total_bytes": 100,
            "completed_bytes": 100,
        }
        item2 = _item(2, "pending")
        item2.progress = {
            "total_bytes": 300,
            "completed_bytes": 0,
        }

        overall = task_service.build_overall_progress([item1, item2])

        self.assertEqual(2, overall.total_items)
        self.assertEqual(1, overall.completed_items)
        self.assertEqual("bytes", overall.percent_basis)
        self.assertEqual(100.0, overall.completed_bytes)
        self.assertEqual(400.0, float(overall.total_bytes or 0))
        self.assertAlmostEqual(25.0, float(overall.percent or 0.0))

    def test_progress_falls_back_to_items_when_no_shared_metric_exists(self) -> None:
        item1 = _item(1, "success")
        item1.progress = {"total_functions": 8, "completed_functions": 8}
        item2 = _item(2, "pending")
        item2.progress = {}

        overall = task_service.build_overall_progress([item1, item2])

        self.assertEqual("items", overall.percent_basis)
        self.assertAlmostEqual(50.0, float(overall.percent or 0.0))


class SyncTaskStatusTests(unittest.TestCase):
    def test_sync_task_recomputes_aggregate_status_even_without_item_changes(self) -> None:
        task = _task(status="pending")
        items = [_item(1, "success"), _item(2, "pending")]

        class _FakeDb:
            def __init__(self) -> None:
                self.committed = 0
                self.refreshed = 0

            def commit(self) -> None:
                self.committed += 1

            def refresh(self, _obj) -> None:
                self.refreshed += 1

        fake_db = _FakeDb()
        with mock.patch.object(task_service, "query_items", return_value=items):
            asyncio_run = __import__("asyncio").run
            asyncio_run(task_service.sync_task(fake_db, task))

        self.assertEqual("running", task.status)
        self.assertEqual(1, fake_db.committed)
        self.assertEqual(1, fake_db.refreshed)

    def test_sync_task_tolerates_unexpected_upstream_exception(self) -> None:
        task = _task(status="running")
        item = _item(1, "running")
        item.pi_job_id = "job-1"
        item.extra_metadata = {"pi_worker_url": "http://bad-worker"}

        class _FakeDb:
            def __init__(self) -> None:
                self.committed = 0
                self.refreshed = 0

            def commit(self) -> None:
                self.committed += 1

            def refresh(self, _obj) -> None:
                self.refreshed += 1

        class _BrokenPiClient:
            async def get_job(self, _job_id):
                raise RuntimeError("invalid upstream endpoint")

        fake_db = _FakeDb()
        with (
            mock.patch.object(task_service, "query_items", return_value=[item]),
            mock.patch.object(task_service, "get_pi_client", return_value=_BrokenPiClient()),
        ):
            asyncio_run = __import__("asyncio").run
            asyncio_run(task_service.sync_task(fake_db, task))

        self.assertEqual("running", task.status)
        self.assertEqual("pi-re-agent", item.failure_type)
        self.assertIn("unexpected error", str(item.error_reason))
        self.assertEqual(1, fake_db.committed)
        self.assertGreaterEqual(fake_db.refreshed, 1)

    def test_sync_task_terminal_item_backfills_cancelled_runtime_metrics(self) -> None:
        task = _task(status="cancelled")
        item = _item(1, "cancelled")
        item.pi_job_id = "job-1"
        item.phase = "cancelled"
        item.extra_metadata = {
            "pi_worker_url": "http://worker",
            "pi_runtime_metrics": {
                "status": "running",
                "started_at": "2026-05-20T12:00:00Z",
                "finished_at": None,
            },
        }

        class _FakeDb:
            def __init__(self) -> None:
                self.committed = 0
                self.refreshed = 0

            def commit(self) -> None:
                self.committed += 1

            def refresh(self, _obj) -> None:
                self.refreshed += 1

        class _PiClient:
            async def get_job(self, _job_id):
                return {
                    "id": "job-1",
                    "status": "cancelled",
                    "phase": "processing",
                    "updated_at": "2026-05-20T12:15:39Z",
                    "progress": {
                        "runtime_metrics": {
                            "status": "running",
                            "started_at": "2026-05-20T12:00:00Z",
                            "finished_at": None,
                        },
                    },
                }

        fake_db = _FakeDb()
        with (
            mock.patch.object(task_service, "query_items", return_value=[item]),
            mock.patch.object(task_service, "get_pi_client", return_value=_PiClient()),
            mock.patch.object(task_service, "_sync_task_abnormal_reason", return_value=None),
        ):
            asyncio.run(task_service.sync_task(fake_db, task))

        metrics = item.extra_metadata["pi_runtime_metrics"]
        self.assertEqual("cancelled", metrics["status"])
        self.assertIsNotNone(metrics["finished_at"])
        self.assertEqual("cancelled", item.status)
        self.assertEqual(1, fake_db.committed)

    def test_terminate_task_marks_items_cancelling_before_upstream_confirms_cancel(self) -> None:
        task = _task(status="running")
        item = _item(1, "running")
        item.pi_job_id = "job-1"
        item.phase = "body"
        item.progress = {"message": "running"}
        item.extra_metadata = {"pi_worker_url": "http://worker"}

        class _FakeDb:
            def commit(self) -> None:
                return None

        class _PiClient:
            async def cancel_job(self, _job_id):
                return None

        with (
            mock.patch.object(task_service, "query_items", return_value=[item]),
            mock.patch.object(task_service, "get_pi_client", return_value=_PiClient()),
            mock.patch.object(task_service, "_record_task_status_event", return_value=None),
        ):
            asyncio.run(task_service.terminate_task(_FakeDb(), task))

        self.assertEqual("cancelling", item.status)
        self.assertEqual("cancelling", item.phase)
        self.assertIsNone(item.finished_at)
        self.assertEqual("cancelling", task.status)

    def test_recover_stale_pi_job_uses_defaults_when_config_lacks_threshold_fields(self) -> None:
        item = _item(1, "queued")
        observed_job_id = "job-1"
        job = {
            "status": "queued",
            "created_at": "2026-05-19T14:00:00",
            "updated_at": "2026-05-19T14:00:00",
        }

        async def _fake_requeue(db, item_arg, job_arg, *, reason, observed_pi_job_id):
            del db, item_arg, job_arg, reason, observed_pi_job_id
            return True

        fake_cfg = mock.Mock()
        fake_cfg.pi_re_agent = mock.Mock(spec=[])

        with (
            mock.patch.object(task_service, "get_config", return_value=fake_cfg),
            mock.patch.object(task_service, "now_local", return_value=__import__("datetime").datetime(2026, 5, 19, 15, 0, 1)),
            mock.patch.object(task_service, "_requeue_stale_pi_job", side_effect=_fake_requeue),
        ):
            recovered = asyncio.run(
                task_service._recover_stale_pi_job(mock.Mock(), item, job, observed_job_id)
            )

        self.assertTrue(recovered)
