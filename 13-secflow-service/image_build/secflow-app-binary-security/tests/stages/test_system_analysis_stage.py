import tempfile
import unittest
from pathlib import Path

from sqlalchemy.sql import operators

from app.model import BinarySecurityArchiveJob, BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, TASK_TYPE_BINARY
from app.service.stages.system_analysis import SystemAnalysisStageHandler
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
    def __init__(self, *, tasks=None, stage_runs=None, stage_items=None, archive_jobs=None):
        self.tasks = list(tasks or [])
        self.stage_runs = list(stage_runs or [])
        self.stage_items = list(stage_items or [])
        self.archive_jobs = list(archive_jobs or [])
        self.added = []

    def query(self, model, *args, **kwargs):
        del args, kwargs
        model_name = getattr(model, "__name__", "")
        if model_name == "BinarySecurityTask":
            return _FakeQuery(self.tasks)
        if model_name == "BinarySecurityStageRun":
            return _FakeQuery(self.stage_runs)
        if model_name == "BinarySecurityStageItem":
            return _FakeQuery(self.stage_items)
        if model_name == "BinarySecurityArchiveJob":
            return _FakeQuery(self.archive_jobs)
        return _FakeQuery([])

    def add(self, obj):
        self.added.append(obj)


class SystemAnalysisStageHandlerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.handler = SystemAnalysisStageHandler()

    def test_build_inputs_and_continue_stage_input_error_follow_manager_inputs(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw.bin",
            workspace_root="/workspace",
            output_root="/output",
        )
        task.summary = {}
        db = _ModelAwareDb(tasks=[task])

        self.assertEqual([], self.handler.build_inputs(self.manager, db, task))
        self.assertEqual("系统分析缺少可执行输入，不能继续", self.handler.continue_stage_input_error(self.manager, db, task))

    def test_archive_signature_reflects_selected_and_candidate_modules(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw.bin",
            workspace_root="/workspace",
            output_root="/output",
        )
        task.summary = {
            "selected_modules": [{"module_key": "m1"}, {"module_key": "m2"}],
            "candidate_modules": [{"module_key": "m1"}, {"module_key": "m2"}, {"module_key": "m3"}],
        }
        signature = self.handler.archive_input_signature(self.manager, _ModelAwareDb(tasks=[task]), task)

        self.assertEqual("system_analysis", signature["stage_name"])
        self.assertEqual(2, signature["selected_module_count"])
        self.assertEqual(["m1", "m2"], signature["selected_module_keys"])
        self.assertEqual(3, signature["candidate_module_count"])
        self.assertTrue(self.handler.archive_signature_has_runnable_inputs(signature))
        self.assertFalse(self.handler.archive_signature_has_runnable_inputs({"stage_name": "system_analysis", "selected_module_count": 0}))

    def test_has_authoritative_success_payload_detects_success_item(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task")
        success_item = BinarySecurityStageItem(
            id="item-1",
            task_id="task-1",
            project_id="project-1",
            stage_name="system_analysis",
            item_key="fw1",
            status="success",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[success_item])

        self.assertTrue(self.handler.has_authoritative_success_payload(self.manager, db, task))

    def test_refresh_summary_from_items_rebuilds_selected_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            artifact_root = output_root / "system-analyse" / "fw1__sat1"
            artifact_root.mkdir(parents=True, exist_ok=True)
            task = BinarySecurityTask(
                id="task-1",
                project_id="project-1",
                name="task",
                status="running",
                task_type=TASK_TYPE_BINARY,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw.bin",
                workspace_root=str(workspace),
                output_root=str(output_root),
            )
            task.policy = {"module_selection_mode": "auto", "module_risk_levels": ["高", "中"]}
            stage_run = BinarySecurityStageRun(
                id="run-1",
                task_id=task.id,
                project_id=task.project_id,
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            item = BinarySecurityStageItem(
                id="item-1",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name="system_analysis",
                item_key="fw1",
                item_name="fw1",
                status="success",
                downstream_service="system_analyse",
                downstream_task_id="sat1",
            )
            item.result = {
                "firmware_key": "fw1",
                "firmware_name": "fw1",
                "filename": "fw1.bin",
                "unpacked_root": str(workspace / "input"),
                "source_root": str(workspace / "input"),
                "task_type": TASK_TYPE_BINARY,
                "artifact_root": str(artifact_root),
                "archive_root": str(artifact_root),
                "modules": [
                    {"module_key": "m-high", "module_name": "high", "risk_level": "高", "risk_score": 90},
                    {"module_key": "m-low", "module_name": "low", "risk_level": "低", "risk_score": 10},
                ],
            }
            item.output_ref = {"archive_root": str(artifact_root)}
            db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

            self.handler.refresh_summary_from_items(self.manager, db, task)

            self.assertEqual("success", stage_run.status)
            self.assertEqual(["m-high"], [row["module_key"] for row in task.summary["selected_modules"]])
            self.assertEqual(2, task.summary["system_analysis_module_count"])


if __name__ == "__main__":
    unittest.main()
