import unittest

from sqlalchemy.sql import operators

from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask
from app.service.stages.dataflow_vuln_scan import DataflowVulnScanStageHandler
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


class DataflowVulnScanStageHandlerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.handler = DataflowVulnScanStageHandler()

    def test_build_inputs_flattens_and_deduplicates_entries(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {
            "entry_results": [
                {"entries": [{"entry_key": "e1"}, {"entry_key": "e2"}]},
                {"entries": [{"entry_key": "e1"}]},
            ]
        }

        rows = self.handler.build_inputs(self.manager, _ModelAwareDb(tasks=[task]), task)

        self.assertEqual(["e1", "e2"], [row["entry_key"] for row in rows])

    def test_continue_stage_input_error_reports_missing_entries(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {}

        reason = self.handler.continue_stage_input_error(self.manager, _ModelAwareDb(tasks=[task]), task)

        self.assertIn("数据流漏洞挖掘", reason)

    def test_refresh_summary_from_items_rebuilds_dataflow_and_vuln_results(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {}
        stage_run = BinarySecurityStageRun(id="run-1", task_id=task.id, project_id=task.project_id, stage_name="dataflow_vuln_scan", sequence_no=1, status="running")
        item = BinarySecurityStageItem(
            id="item-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="dataflow_vuln_scan",
            item_key="e1",
            item_name="main",
            status="success",
        )
        item.input_ref = {
            "entry_key": "e1",
            "module_key": "m1",
            "module_name": "module-1",
            "file_name": "main.c",
            "function_name": "main",
        }
        item.result = {
            "entry_key": "e1",
            "module_key": "m1",
            "module_name": "module-1",
            "file_name": "main.c",
            "function_name": "main",
            "data_flow_file": "/tmp/dataflow.json",
        }
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

        self.handler.refresh_summary_from_items(self.manager, db, task)

        self.assertEqual("success", stage_run.status)
        self.assertEqual("e1", task.summary["dataflow_results"][0]["entry_key"])
        self.assertEqual(task.summary["dataflow_results"], task.summary["vuln_results"])
