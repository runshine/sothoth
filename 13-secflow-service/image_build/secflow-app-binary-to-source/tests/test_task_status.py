from __future__ import annotations

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

        self.assertEqual("partial", task.status)

    def test_all_success_items_complete_task(self) -> None:
        task = _task()
        items = [_item(1, "success"), _item(2, "success")]

        with mock.patch.object(task_service, "query_items", return_value=items):
            task_service.recompute_task_status(db=mock.Mock(), task=task)

        self.assertEqual("completed", task.status)
