import unittest
from pathlib import Path

from sqlalchemy.sql import operators

from app.model import BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask, TASK_TYPE_BINARY
from app.service.stages.firmware_unpack import FirmwareUnpackStageHandler
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


class FirmwareUnpackStageHandlerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()
        self.handler = FirmwareUnpackStageHandler()

    def test_has_runnable_inputs_uses_task_input_files(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_BINARY, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {
            "input_files": [
                {"filename": "fw1.bin", "firmware_key": "fw1", "path": "/tmp/fw1.bin"},
            ]
        }

        self.assertTrue(self.handler.has_runnable_inputs(self.manager, _ModelAwareDb(tasks=[task]), task))
        self.assertEqual(
            [{"filename": "fw1.bin", "firmware_key": "fw1", "path": "/tmp/fw1.bin"}],
            self.handler.build_inputs(self.manager, _ModelAwareDb(tasks=[task]), task),
        )

    def test_continue_stage_input_error_reports_missing_input_files(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_BINARY, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {}

        self.assertEqual("缺少输入文件", self.handler.continue_stage_input_error(self.manager, _ModelAwareDb(tasks=[task]), task))

    def test_repair_firmware_unpack_inputs_from_workspace_recovers_from_metadata(self):
        workspace_root = Path("/tmp/ws-recover-meta").resolve()
        input_dir = workspace_root / "input"
        input_dir.mkdir(parents=True, exist_ok=True)
        firmware_path = input_dir / "fw.bin"
        firmware_path.write_bytes(b"binary")
        (input_dir / "task-metadata.json").write_text(
            '{"input_files":[{"filename":"fw.bin","relative_path":"fw.bin","firmware_key":"fw","path":"%s/fw.bin"}]}' % str(input_dir),
            encoding="utf-8",
        )
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="task",
            task_type=TASK_TYPE_BINARY,
            workspace_root=str(workspace_root),
            output_root="/tmp/out",
        )
        task.summary = {"input_dir": str(input_dir), "input_manifest_path": str(input_dir / "task-metadata.json")}

        try:
            changed = self.manager._repair_firmware_unpack_inputs_from_workspace(task)
        finally:
            import shutil
            shutil.rmtree(workspace_root, ignore_errors=True)

        self.assertTrue(changed)
        self.assertEqual(1, len(task.summary.get("input_files") or []))
        self.assertEqual("fw.bin", task.summary["input_files"][0]["filename"])

    def test_archive_signature_uses_system_analysis_inputs(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_BINARY, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {
            "firmware_unpack_results": [
                {"firmware_key": "fw1"},
                {"firmware_key": "fw2"},
            ]
        }

        signature = self.handler.archive_input_signature(self.manager, _ModelAwareDb(tasks=[task]), task)

        self.assertEqual("firmware_unpack", signature["stage_name"])
        self.assertEqual(2, signature["system_input_count"])
        self.assertEqual(["fw1", "fw2"], signature["firmware_keys"])

    def test_refresh_summary_from_items_rebuilds_firmware_unpack_results(self):
        task = BinarySecurityTask(id="task-1", project_id="project-1", name="task", task_type=TASK_TYPE_BINARY, workspace_root="/tmp/ws", output_root="/tmp/out")
        task.summary = {}
        stage_run = BinarySecurityStageRun(id="run-1", task_id=task.id, project_id=task.project_id, stage_name="firmware_unpack", sequence_no=1, status="running")
        item = BinarySecurityStageItem(
            id="item-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name="firmware_unpack",
            item_key="fw1",
            item_name="fw1.bin",
            status="success",
        )
        item.input_ref = {"path": "/tmp/fw1.bin", "filename": "fw1.bin"}
        item.result = {
            "firmware_key": "fw1",
            "firmware_name": "fw1",
            "filename": "fw1.bin",
            "unpacked_root": "/tmp/fw1",
            "source_root": "/tmp/fw1",
        }
        db = _ModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

        self.handler.refresh_summary_from_items(self.manager, db, task)

        self.assertEqual("success", stage_run.status)
        self.assertEqual("fw1", task.summary["firmware_unpack_results"][0]["firmware_key"])
