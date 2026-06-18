from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, TASK_TYPE_SOURCE
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
                "source_root": "/src",
                "source_root_path": "/src",
                "source_dir": "/src/module-1",
                "module_dir": "/src/module-1",
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


def test_source_task_skips_entry_analysis_when_system_analysis_has_no_selected_modules():
    manager = TaskManager()
    task = BinarySecurityTask(
        id="task-source-no-modules",
        project_id="p1",
        name="source-task",
        status="failed",
        task_type=TASK_TYPE_SOURCE,
        current_stage="system_analysis",
        firmware_source="project_filesystem",
        firmware_path="/src",
        output_root="/o",
        workspace_root="/w",
    )
    task.summary = {
        "selected_modules": [],
        "candidate_modules": [],
        "failure_code": "no_candidate_modules",
    }
    task.metrics = {"entry_count": 0, "selected_module_count": 0, "candidate_module_count": 0}
    system_run = BinarySecurityStageRun(
        id="sr-system-empty",
        task_id=task.id,
        project_id=task.project_id,
        stage_name="system_analysis",
        sequence_no=1,
        status="success",
    )
    db = _AppendingModelAwareDb(tasks=[task], stage_runs=[system_run], stage_items=[], events=[])

    should_skip = manager._should_finalize_without_entries(db, task, "entry_analysis")
    next_stage = manager._next_incomplete_stage(db, task)

    assert should_skip is True
    assert next_stage is None


def test_source_task_does_not_advance_to_dataflow_when_selected_modules_are_missing():
    manager = TaskManager()
    task = BinarySecurityTask(
        id="task-source-no-entry-results",
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
        "selected_modules": [],
        "entry_results": [],
    }
    system_run = BinarySecurityStageRun(
        id="sr-system-only",
        task_id=task.id,
        project_id=task.project_id,
        stage_name="system_analysis",
        sequence_no=1,
        status="success",
    )
    entry_run = BinarySecurityStageRun(
        id="sr-entry-empty",
        task_id=task.id,
        project_id=task.project_id,
        stage_name="entry_analysis",
        sequence_no=2,
        status="success",
    )
    db = _AppendingModelAwareDb(tasks=[task], stage_runs=[system_run, entry_run], stage_items=[], events=[])

    should_skip = manager._should_finalize_without_entries(db, task, "dataflow_vuln_scan")
    next_stage = manager._next_incomplete_stage(db, task)

    assert should_skip is True
    assert next_stage is None


def test_source_system_analysis_rebuild_restores_entry_analysis_input_contract_fields():
    manager = TaskManager()
    task = BinarySecurityTask(
        id="task-source-summary-rebuild",
        project_id="p1",
        name="source-task",
        status="dispatching",
        task_type=TASK_TYPE_SOURCE,
        current_stage="dataflow_vuln_scan",
        firmware_source="project_filesystem",
        firmware_path="/src",
        output_root="/o",
        workspace_root="/w",
    )
    task.summary = {}
    stage_run = BinarySecurityStageRun(
        id="sr-system",
        task_id=task.id,
        project_id=task.project_id,
        stage_name="system_analysis",
        sequence_no=1,
        status="success",
    )
    system_item = BinarySecurityStageItem(
        id="si-system",
        task_id=task.id,
        project_id=task.project_id,
        stage_run_id=stage_run.id,
        stage_name="system_analysis",
        item_key="source_project",
        item_name="source-project",
        status="success",
        downstream_service="system_analyse",
        downstream_task_id="sat-demo",
    )
    system_item.input_ref = {"input_path": "/w/input", "firmware_key": "source_project", "task_type": TASK_TYPE_SOURCE}
    system_item.result = {
        "firmware_key": "source_project",
        "firmware_name": "demo",
        "filename": "source-project",
        "unpacked_root": "/w/input",
        "source_root": "/w/input",
        "task_type": TASK_TYPE_SOURCE,
        "modules": [
            {
                "module_key": "m1",
                "module_name": "module-1",
                "risk_level": "高",
                "risk_score": 90,
            }
        ],
    }
    db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[system_item], events=[])

    manager._refresh_system_analysis_stage_from_synced_items(db, task)

    selected = task.summary["selected_modules"][0]
    assert selected["firmware_key"] == "source_project"
    assert selected["source_root"] == "/w/input"
    assert selected["source_root_path"] == "/w/input"
    assert selected["source_dir"] == "/w/input"
    assert selected["module_dir"] == "/w/input"


def test_source_entry_analysis_inputs_refreshes_legacy_selected_modules_missing_contract_fields():
    manager = TaskManager()
    task = BinarySecurityTask(
        id="task-source-entry-input-refresh",
        project_id="p1",
        name="source-task",
        status="dispatching",
        task_type=TASK_TYPE_SOURCE,
        current_stage="entry_analysis",
        firmware_source="project_filesystem",
        firmware_path="/src",
        output_root="/o",
        workspace_root="/w",
    )
    task.summary = {
        "selected_modules": [
            {
                "module_key": "source_project-dns",
                "module_name": "dns",
                "risk_level": "高",
                "risk_score": 78,
            }
        ]
    }
    stage_run = BinarySecurityStageRun(
        id="sr-system-refresh",
        task_id=task.id,
        project_id=task.project_id,
        stage_name="system_analysis",
        sequence_no=1,
        status="success",
    )
    system_item = BinarySecurityStageItem(
        id="si-system-refresh",
        task_id=task.id,
        project_id=task.project_id,
        stage_run_id=stage_run.id,
        stage_name="system_analysis",
        item_key="source_project",
        item_name="source-project",
        status="success",
        downstream_service="system_analyse",
        downstream_task_id="sat-demo",
    )
    system_item.input_ref = {"input_path": "/w/input", "firmware_key": "source_project", "task_type": TASK_TYPE_SOURCE}
    system_item.result = {
        "firmware_key": "source_project",
        "firmware_name": "demo",
        "filename": "source-project",
        "unpacked_root": "/w/input",
        "source_root": "/w/input",
        "task_type": TASK_TYPE_SOURCE,
        "modules": [
            {
                "module_key": "source_project-dns",
                "module_name": "dns",
                "risk_level": "高",
                "risk_score": 78,
            }
        ],
    }
    db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[system_item], events=[])

    inputs = manager._entry_analysis_inputs(db, task)

    assert inputs[0]["firmware_key"] == "source_project"
    assert inputs[0]["source_root"] == "/w/input"
    assert inputs[0]["source_dir"] == "/w/input"
