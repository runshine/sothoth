from app.model import BinaryToSourceTask, BinaryToSourceTaskItem, ItemTaskStatus, ParentTaskStatus
from app.services.task_service import refresh_parent_status


def _make_task(item_statuses):
    task = BinaryToSourceTask(id="t1", project_id="p1", name="n", priority=5, status=ParentTaskStatus.PENDING)
    task.items = []
    for idx, st in enumerate(item_statuses, start=1):
        task.items.append(
            BinaryToSourceTaskItem(
                id=f"i{idx}",
                parent_task_id="t1",
                project_id="p1",
                sequence_no=idx,
                elf_path="/tmp/a.elf",
                output_dir="/tmp/out",
                status=st,
            )
        )
    return task


def test_completed_when_all_success():
    task = _make_task([ItemTaskStatus.SUCCESS, ItemTaskStatus.SUCCESS])
    refresh_parent_status(task)
    assert task.status == ParentTaskStatus.COMPLETED


def test_partial_when_mixed_failed_success():
    task = _make_task([ItemTaskStatus.SUCCESS, ItemTaskStatus.FAILED])
    refresh_parent_status(task)
    assert task.status == ParentTaskStatus.PARTIAL_SUCCESS
