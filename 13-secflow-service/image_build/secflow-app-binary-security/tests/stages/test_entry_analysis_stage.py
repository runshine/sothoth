import unittest

from sqlalchemy.sql import operators

from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, TASK_TYPE_BINARY_MODULE, TASK_TYPE_SOURCE
from app.service.stages.entry_analysis import EntryAnalysisStageHandler
from app.service.task_manager import TaskManager


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        del kwargs
        rows = list(self._rows)
        for criterion in args:
            left = getattr(criterion, "left", None)
            operator = getattr(criterion, "operator", None)
            right = getattr(criterion, "right", None)
            field_name = getattr(left, "name", None)
            if not field_name or operator is None:
                continue
            if operator is operators.eq:
                expected = getattr(right, "value", right)
                rows = [row for row in rows if getattr(row, field_name, None) == expected]
        return _FakeQuery(rows)

    def order_by(self, *args, **kwargs):
        del args, kwargs
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        rows = self.all()
        return rows[0] if rows else None


class _ModelAwareDb:
    def __init__(self, *, tasks=None, stage_runs=None, stage_items=None):
        self.tasks = list(tasks or [])
        self.stage_runs = list(stage_runs or [])
        self.stage_items = list(stage_items or [])

    def query(self, model, *args, **kwargs):
        del args, kwargs
        model_name = getattr(model, "__name__", "")
        if model_name == "BinarySecurityTask":
            return _FakeQuery(self.tasks)
        if model_name == "BinarySecurityStageRun":
            return _FakeQuery(self.stage_runs)
        if model_name == "BinarySecurityStageItem":
            return _FakeQuery(self.stage_items)
        return _FakeQuery([])

    def commit(self):
        pass


class EntryAnalysisStageHandlerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.handler = EntryAnalysisStageHandler()

    def test_build_inputs_returns_selected_modules_for_source_task(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_SOURCE, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {"selected_modules": [{"module_key": "m1", "source_root": "/src", "source_dir": "/src/mod"}]}

        rows = self.handler.build_inputs(self.manager, _ModelAwareDb(tasks=[task]), task)

        self.assertEqual(["m1"], [row["module_key"] for row in rows])

    def test_continue_stage_input_error_reports_missing_binary_to_source_inputs(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_BINARY_MODULE, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {}
        db = _ModelAwareDb(tasks=[task])

        reason = self.handler.continue_stage_input_error(self.manager, db, task)

        self.assertIn("binary-to-source", reason)

    def test_archive_input_signature_counts_effective_entries(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_SOURCE, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {
            "entry_results": [
                {
                    "module_key": "m1",
                    "entries": [
                        {"entry_key": "e1"},
                        {"entry_key": "e2"},
                    ],
                }
            ]
        }

        signature = self.handler.archive_input_signature(self.manager, _ModelAwareDb(tasks=[task]), task)

        self.assertEqual("entry_analysis", signature["stage_name"])
        self.assertEqual(2, signature["entry_count"])
        self.assertEqual(["e1", "e2"], signature["entry_keys"])

    def test_refresh_summary_from_items_rebuilds_entry_results(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_SOURCE, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {}
        stage_run = BinarySecurityStageRun(id="run-1", task_id=task.id, project_id=task.project_id, stage_name="entry_analysis", sequence_no=1, status="running")
        item = BinarySecurityStageItem(
            id="item-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="entry_analysis",
            item_key="m1",
            item_name="module-1",
            status="success",
        )
        item.input_ref = {
            "firmware_key": "fw1",
            "firmware_name": "fw1",
            "filename": "fw1.bin",
            "module_key": "m1",
            "module_name": "module-1",
            "source_root": "/src",
            "source_dir": "/src/module-1",
            "module_dir": "/src/module-1",
        }
        item.result = {
            "entries": [
                {"entry_key": "e1", "function_name": "main", "file_name": "main.c", "module_key": "m1", "module_name": "module-1"},
            ]
        }
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

        self.handler.refresh_summary_from_items(self.manager, db, task)

        self.assertEqual("success", stage_run.status)
        self.assertEqual(1, len(task.summary["entry_results"]))
        self.assertEqual("e1", task.summary["entry_results"][0]["entries"][0]["entry_key"])
