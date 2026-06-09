from app.model import BinarySecurityStageRun, BinarySecurityTask, TASK_TYPE_SOURCE
from app.service.task_manager import TaskManager
from tests.test_task_manager import _AppendingModelAwareDb


def test_source_task_does_not_skip_entry_analysis_when_system_analysis_has_no_entry_count():
    manager = TaskManager()
    task = BinarySecurityTask(
        id="task-source-entry-gate",
        project_id="p1",
        name="source-task",
        status="running",
        task_type=TASK_TYPE_SOURCE,
        current_stage="system_analysis",
        firmware_source="project_filesystem",
        firmware_path="/src",
        output_root="/o",
        workspace_root="/w",
    )
    task.summary = {
        "selected_modules": [
            {
                "firmware_key": "source_project",
                "module_key": "m1",
                "module_name": "module-1",
                "source_dir": "/src/module-1",
            }
        ]
    }
    task.metrics = {"entry_count": 0, "selected_module_count": 1}
    system_run = BinarySecurityStageRun(
        id="sr-system-success",
        task_id=task.id,
        project_id=task.project_id,
        stage_name="system_analysis",
        sequence_no=1,
        status="success",
    )
    db = _AppendingModelAwareDb(tasks=[task], stage_runs=[system_run], stage_items=[], events=[])

    should_skip = manager._should_finalize_without_entries(db, task, "entry_analysis")
    next_stage = manager._next_incomplete_stage(db, task)

    assert should_skip is False
    assert next_stage == "entry_analysis"
