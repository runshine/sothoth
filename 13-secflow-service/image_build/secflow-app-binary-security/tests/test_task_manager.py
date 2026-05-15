import asyncio
import tempfile
import unittest
import zipfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityEvent,
    BinarySecurityProjectConfig,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.exception import ValidationError
from app.schemas import BinarySecurityServiceConfigPayload
from app.schemas import (
    BinarySecurityProjectConfigPayload,
    BinarySecurityArchiveJobResponse,
    BinarySecurityTaskConcurrencyUpdatePayload,
    BinarySecurityTaskPolicyUpdatePayload,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager, _now


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def options(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        del args, kwargs
        return self

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None

    def scalar(self):
        row = self.first()
        if isinstance(row, (list, tuple)):
            return row[0] if row else None
        return row

    def delete(self, synchronize_session=False):
        count = len(self._rows)
        self._rows.clear()
        return count

    def update(self, values, synchronize_session=False):
        for row in self._rows:
            for key, value in (values or {}).items():
                name = getattr(key, "name", None)
                if name and hasattr(row, name):
                    setattr(row, name, value)
        return len(self._rows)


class _FakeDb:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.added = []
        self.commits = 0

    def query(self, *args, **kwargs):
        return _FakeQuery(self.rows)

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.commits += 1

    def flush(self):
        pass


class _ModelAwareDb:
    def __init__(self, *, tasks=None, stage_runs=None, stage_items=None, archive_jobs=None):
        self.tasks = list(tasks or [])
        self.stage_runs = list(stage_runs or [])
        self.stage_items = list(stage_items or [])
        self.archive_jobs = list(archive_jobs or [])
        self.added = []

    def query(self, model, *args, **kwargs):
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

    def commit(self):
        pass

    def flush(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _FakeConnection:
    def __init__(self, lock_result=True):
        self.lock_result = lock_result
        self.calls = []
        self.closed = False

    def execute(self, statement, params=None):
        self.calls.append((str(statement), dict(params or {})))
        sql = str(statement)
        if "GET_LOCK" in sql:
            return _ScalarResult(1 if self.lock_result else 0)
        return _ScalarResult(1)

    def close(self):
        self.closed = True


class _LockingDb(_ModelAwareDb):
    def __init__(self, connection):
        super().__init__()
        self._connection = connection

    def connection(self):
        return self._connection


class _AppendingModelAwareDb(_ModelAwareDb):
    def add(self, obj):
        super().add(obj)
        model_name = obj.__class__.__name__
        if model_name == "BinarySecurityStageItem":
            self.stage_items.append(obj)
        elif model_name == "BinarySecurityStageRun":
            self.stage_runs.append(obj)
        elif model_name == "BinarySecurityArchiveJob":
            self.archive_jobs.append(obj)
        elif model_name == "BinarySecurityTask":
            self.tasks.append(obj)


class _StageRun:
    def __init__(self, stage_name, status):
        self.stage_name = stage_name
        self.status = status


class TaskManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _finish_continue_prepare(self, db, task, target_stage: str) -> None:
        asyncio.run(self.manager._prepare_continue_task(db, task, target_stage))
        task.status = "pending"
        task.current_stage = target_stage
        task.execution_mode = "task_retry"
        task.target_stage_name = target_stage
        task.pending_action = None

    def _finish_retry_prepare(self, db, task) -> None:
        stage_sequence = asyncio.run(self.manager._prepare_retry_task(db, task))
        task.status = "pending"
        task.current_stage = stage_sequence[0]
        task.execution_mode = None
        task.target_stage_name = None
        task.pending_action = None

    def test_task_summary_is_written_to_task_workspace_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="n",
                status="pending",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root="/o",
                workspace_root=tmp,
            )

            task.summary = {"selected_modules": [{"module_key": "m1"}]}

            summary_path = Path(tmp) / BinarySecurityTask.SUMMARY_FILENAME
            self.assertTrue(summary_path.is_file())
            self.assertIsNone(task.summary_json)
            self.assertEqual({"selected_modules": [{"module_key": "m1"}]}, task.summary)

    def test_task_summary_falls_back_to_db_before_workspace_is_available(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="pending",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="",
        )

        task.summary = {"status": "created"}

        self.assertIsNotNone(task.summary_json)
        self.assertEqual({"status": "created"}, task.summary)

    def test_parse_system_analysis_modules_from_modules_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modules_dir = root / "modules"
            (modules_dir / "busybox").mkdir(parents=True)
            (modules_dir / "dropbear").mkdir(parents=True)
            (root / "modules.list").write_text("busybox\ndropbear\n", encoding="utf-8")

            modules = self.manager._parse_system_analysis_modules(root, {
                "firmware_key": "fw1",
                "firmware_name": "fw1",
                "filename": "fw1.bin",
                "unpacked_root": str(root),
                "task_type": TASK_TYPE_BINARY,
            })

            self.assertEqual(2, len(modules))
            self.assertEqual("busybox", modules[0]["module_name"])
            self.assertTrue((root / "high_risk_modules.json").is_file())
            self.assertEqual(str((modules_dir / "busybox")), modules[0]["source_dir"])

    def test_parse_entries_prefers_json_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "result.json").write_text(
                '{"entries":[{"file_name":"main.c","function_name":"int handle_req(int argc, char **argv)","line_no":12}]}',
                encoding="utf-8",
            )

            rows = self.manager._parse_entries(root, {"module_key": "mod", "module_name": "mod", "source_dir": "/src"})

            self.assertEqual(1, len(rows))
            self.assertEqual("handle_req", rows[0]["function_name"])
            self.assertEqual("main.c", rows[0]["file_name"])
            self.assertEqual(["argc", "argv"], rows[0]["signature_params"])

    def test_parse_entries_falls_back_to_markdown_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "entry-list.md").write_text(
                "| idx | no | file | function | line | desc | risk |\n| --- | --- | --- | --- | --- | --- | --- |\n| 1 | 1 | app.c | parse_input | 99 | d | h |\n",
                encoding="utf-8",
            )

            rows = self.manager._parse_entries(root, {"module_key": "mod", "module_name": "mod", "source_dir": "/src"})

            self.assertEqual(1, len(rows))
            self.assertEqual("parse_input", rows[0]["function_name"])

    def test_build_stage_summaries_aggregates_downstream_statuses(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="task", firmware_path="/tmp/in", output_root="/tmp/out", workspace_root="/tmp/ws", status="running", current_stage="firmware_unpack")
        stage_run = BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="pending")
        items = [
            BinarySecurityStageItem(id="i1", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="firmware_unpack", item_key="fw1", status="success"),
            BinarySecurityStageItem(id="i2", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="firmware_unpack", item_key="fw2", status="failed"),
        ]

        summaries = self.manager._build_stage_summaries(
            _ModelAwareDb(stage_runs=[stage_run], stage_items=items),
            task,
            ["firmware_unpack"],
            [stage_run],
            items,
        )

        self.assertEqual(1, len(summaries))
        self.assertEqual("partial_success", summaries[0].status)
        self.assertEqual(2, summaries[0].total_items)
        self.assertEqual(1, summaries[0].success_items)
        self.assertEqual(1, summaries[0].failed_items)

    def test_task_operation_lock_uses_bound_text_query_and_releases_lock(self):
        connection = _FakeConnection(lock_result=True)
        db = _LockingDb(connection)
        with self.manager._task_operation_lock(db, "task-1", operation="unit_test"):
            pass

        self.assertEqual(2, len(connection.calls))
        self.assertIn("GET_LOCK", connection.calls[0][0])
        self.assertEqual("secflow_binary_security_task_lock:task-1", connection.calls[0][1]["name"])
        self.assertIn("RELEASE_LOCK", connection.calls[1][0])

    def test_task_operation_lock_rejects_when_named_lock_not_acquired(self):
        connection = _FakeConnection(lock_result=False)
        db = _LockingDb(connection)
        with self.assertRaises(ValidationError):
            with self.manager._task_operation_lock(db, "task-1", operation="unit_test"):
                pass

    def test_runtime_status_reports_dispatch_loops(self):
        self.manager._running = True

        class _Task:
            def __init__(self, done):
                self._done = done

            def done(self):
                return self._done

        self.manager._loop_task = _Task(False)
        self.manager._action_loop_task = _Task(False)
        self.manager._archive_loop_task = _Task(True)
        self.manager._downstream_reconcile_task = _Task(False)

        status = self.manager.runtime_status()

        self.assertTrue(status["running"])
        self.assertEqual(
            {
                "task_dispatch": True,
                "action_dispatch": True,
                "archive_dispatch": False,
                "downstream_reconcile": True,
            },
            status["loops"],
        )

    def test_aggregate_archive_stage_status_supports_applying(self):
        self.assertEqual("pending", self.manager._aggregate_archive_stage_status([]))
        self.assertEqual("running", self.manager._aggregate_archive_stage_status(["pending", "running"]))
        self.assertEqual("applying", self.manager._aggregate_archive_stage_status(["archived"]))
        self.assertEqual("failed", self.manager._aggregate_archive_stage_status(["failed"]))
        self.assertEqual("success", self.manager._aggregate_archive_stage_status(["success", "success"]))

    def test_build_stage_overview_nodes_returns_business_then_archive(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="task", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/tmp/in", output_root="/tmp/out", workspace_root="/tmp/ws", status="running")
        summaries = [
            self.manager._build_stage_summaries(
                _ModelAwareDb(),
                task,
                ["firmware_unpack"],
                [BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success")],
                [BinarySecurityStageItem(id="i1", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="firmware_unpack", item_key="fw1", status="success")],
            )[0]
        ]
        archive_jobs = [
            BinarySecurityArchiveJobResponse(
                id="aj1",
                stage_name="firmware_unpack",
                item_id="i1",
                item_key="fw1",
                archive_status="running",
            )
        ]

        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="firmware_unpack",
                item_key="fw1",
                status="success",
                downstream_service="firmware_unpacker",
                downstream_task_id="d1",
            )
        ]
        nodes = self.manager._build_stage_overview_nodes(task, summaries, archive_jobs, stage_items)

        self.assertEqual("business:firmware_unpack", nodes[0].node_id)
        self.assertEqual("archive:firmware_unpack", nodes[1].node_id)
        self.assertEqual("success", nodes[0].status)
        self.assertEqual("running", nodes[1].status)
        self.assertEqual("fw1", nodes[0].detail.representative_item_key)
        self.assertEqual("d1", nodes[0].detail.representative_downstream_task_id)
        self.assertEqual(["firmware_unpacker"], nodes[0].detail.downstream_services)

    def test_build_stage_overview_nodes_keeps_archive_pending_when_some_items_not_terminal(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/tmp/in",
            output_root="/tmp/out",
            workspace_root="/tmp/ws",
            status="running",
        )
        summaries = [
            self.manager._build_stage_summaries(
                _ModelAwareDb(),
                task,
                ["entry_analysis"],
                [BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="running")],
                [
                    BinarySecurityStageItem(id="i1", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="entry_analysis", item_key="m1", status="success"),
                    BinarySecurityStageItem(id="i2", task_id="t1", project_id="p1", stage_run_id="sr1", stage_name="entry_analysis", item_key="m2", status="running"),
                ],
            )[0]
        ]
        archive_jobs = [
            BinarySecurityArchiveJobResponse(
                id="aj1",
                stage_name="entry_analysis",
                item_id="i1",
                item_key="m1",
                archive_status="success",
            )
        ]
        stage_items = [
            BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key="m1",
                status="success",
                downstream_service="entry_analyse",
                downstream_task_id="d1",
            ),
            BinarySecurityStageItem(
                id="i2",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key="m2",
                status="running",
                downstream_service="entry_analyse",
                downstream_task_id="d2",
            ),
        ]

        nodes = self.manager._build_stage_overview_nodes(task, summaries, archive_jobs, stage_items)
        by_node_id = {node.node_id: node for node in nodes}

        self.assertEqual("pending", by_node_id["archive:entry_analysis"].status)

    def test_choose_module_binary_handles_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unpacked = root / "unpacked"
            module_dir = unpacked / "modules" / "openssl"
            module_dir.mkdir(parents=True)
            target = unpacked / "bin" / "openssl.elf"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"elf")
            (module_dir / "files.list").write_text("bin/openssl.elf\n", encoding="utf-8")

            path = self.manager._choose_module_binary(
                {
                    "module_name": "openssl",
                    "module_dir": str(module_dir),
                    "files_list": str(module_dir / "files.list"),
                    "unpacked_root": str(unpacked),
                }
            )

            self.assertEqual(str(target.resolve()), path)

    def test_build_project_stats_aggregates_task_metrics(self):
        success = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="success",
            status="success",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw1",
            output_root="/o1",
            workspace_root="/w1",
        )
        success.metrics = {
            "firmware_item_count": 2,
            "unpacked_firmware_count": 2,
            "failed_firmware_count": 0,
            "selected_module_count": 3,
            "candidate_module_count": 5,
            "high_risk_module_count": 1,
            "entry_count": 7,
            "vuln_result_count": 11,
        }
        running = BinarySecurityTask(
            id="t2",
            project_id="p1",
            name="running",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw2",
            output_root="/o2",
            workspace_root="/w2",
        )
        running.metrics = {
            "firmware_item_count": 1,
            "unpacked_firmware_count": 0,
            "failed_firmware_count": 1,
            "selected_module_count": 2,
            "candidate_module_count": 4,
            "high_risk_module_count": 2,
            "entry_count": 6,
            "vuln_result_count": 10,
        }

        stats = self.manager._build_project_stats([success, running])

        self.assertEqual(2, stats.total)
        self.assertEqual(1, stats.success)
        self.assertEqual(1, stats.running)
        self.assertEqual(3, stats.input_count)
        self.assertEqual(2, stats.unpacked_firmware_count)
        self.assertEqual(1, stats.failed_firmware_count)
        self.assertEqual(5, stats.selected_module_count)
        self.assertEqual(9, stats.candidate_module_count)
        self.assertEqual(3, stats.high_risk_module_count)
        self.assertEqual(13, stats.entry_count)
        self.assertEqual(21, stats.vuln_result_count)

    def test_build_project_stage_aggregates_includes_binary_stage_defaults(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                SimpleNamespace(task_id="t1", stage_name="firmware_unpack"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis"),
            ],
            stage_items=[
                SimpleNamespace(task_id="t1", stage_name="firmware_unpack", status="success"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", status="failed"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", status="running"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", status="cancelled"),
            ],
            archive_jobs=[
                SimpleNamespace(task_id="t1", stage_name="firmware_unpack", archive_status="success"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="applying"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="pending"),
                SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="failed"),
            ],
        )

        aggregates = self.manager._build_project_stage_aggregates(db, [task], TASK_TYPE_BINARY)
        by_stage = {item.stage_name: item for item in aggregates}

        self.assertEqual(
            ["firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            [item.stage_name for item in aggregates],
        )
        self.assertEqual(1, by_stage["system_analysis"].business.task_count)
        self.assertEqual(3, by_stage["system_analysis"].business.total_items)
        self.assertEqual(1, by_stage["system_analysis"].business.failed_items)
        self.assertEqual(1, by_stage["system_analysis"].business.running_items)
        self.assertEqual(1, by_stage["system_analysis"].business.cancelled_items)
        self.assertEqual({"failed": 1, "running": 1, "cancelled": 1}, by_stage["system_analysis"].business.status_counts)
        self.assertEqual(3, by_stage["system_analysis"].archive.job_count)
        self.assertEqual(1, by_stage["system_analysis"].archive.failed_count)
        self.assertEqual(1, by_stage["system_analysis"].archive.applying_count)
        self.assertEqual(1, by_stage["system_analysis"].archive.pending_count)
        self.assertEqual(0, by_stage["binary_to_source"].business.total_items)
        self.assertEqual(0, by_stage["binary_to_source"].archive.job_count)

    def test_build_project_stage_aggregates_uses_source_stage_sequence(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src.zip",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[SimpleNamespace(task_id="t1", stage_name="system_analysis")],
            stage_items=[SimpleNamespace(task_id="t1", stage_name="system_analysis", status="success")],
            archive_jobs=[SimpleNamespace(task_id="t1", stage_name="system_analysis", archive_status="success")],
        )

        aggregates = self.manager._build_project_stage_aggregates(db, [task], TASK_TYPE_SOURCE)

        self.assertEqual(
            ["system_analysis", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            [item.stage_name for item in aggregates],
        )
        self.assertNotIn("firmware_unpack", [item.stage_name for item in aggregates])
        self.assertEqual(1, aggregates[0].business.success_items)
        self.assertEqual(1, aggregates[0].archive.success_count)

    def test_aggregate_stage_items_marks_partial_success(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "firmware_key": "fw1",
                        "firmware_name": "fw.bin",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/unpacked",
                        "source_root": "/tmp/unpacked",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "module_dir": "/tmp/unpacked/modules/openssl",
                        "source_dir": "/tmp/archive/openssl",
                    },
                },
                {"status": "failed", "item": {"id": "b"}, "error": "boom"},
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("partial_success", status)
        self.assertEqual(1, summary["success_count"])
        self.assertEqual(1, summary["failed_count"])
        self.assertEqual(
            [
                {
                    "firmware_key": "fw1",
                    "firmware_name": "fw.bin",
                    "filename": "fw.bin",
                    "unpacked_root": "/tmp/unpacked",
                    "source_root": "/tmp/unpacked",
                    "task_type": None,
                    "module_key": "m1",
                    "module_name": "openssl",
                    "module_dir": "/tmp/unpacked/modules/openssl",
                    "source_dir": "/tmp/archive/openssl",
                    "module_report": None,
                    "files_list": None,
                }
            ],
            task.summary["b2s_results"],
        )
        self.assertEqual(1, db.commits)

    def test_aggregate_stage_items_compacts_b2s_results_for_summary_storage(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "firmware_key": "fw1",
                        "firmware_name": "fw.bin",
                        "filename": "fw.bin",
                        "unpacked_root": "/tmp/unpacked",
                        "source_root": "/tmp/unpacked",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "module_dir": "/tmp/unpacked/modules/openssl",
                        "source_dir": "/tmp/archive/openssl",
                        "module_report": "/tmp/archive/openssl/report.md",
                        "files_list": "/tmp/archive/openssl/files.list",
                        "generated_files": [f"/tmp/archive/openssl/{idx}.c" for idx in range(100)],
                        "downstream": {"items": [{"huge": "x" * 1000} for _ in range(100)]},
                    },
                }
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("success", status)
        stored = task.summary["b2s_results"][0]
        self.assertEqual("m1", stored["module_key"])
        self.assertEqual("/tmp/archive/openssl", stored["source_dir"])
        self.assertNotIn("generated_files", stored)
        self.assertNotIn("downstream", stored)
        self.assertEqual(stored, summary["items"][0])

    def test_entry_results_keep_entries_but_drop_downstream_payload(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        _, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "module_key": "m1",
                        "module_name": "openssl",
                        "source_dir": "/tmp/archive/openssl",
                        "artifact_root": "/tmp/archive/openssl/entry",
                        "entries": [
                            {
                                "entry_key": "e1",
                                "module_key": "m1",
                                "module_name": "openssl",
                                "file_name": "main.c",
                                "function_name": "main",
                                "raw_function_name": "main",
                                "line_no": "10",
                                "definition_file": "src/main.c",
                                "definition_line": "42",
                                "is_definition_found": True,
                                "taint_params": ["argv", ""],
                                "signature_params": ["argc", "argv"],
                                "source_dir": "/tmp/archive/openssl",
                                "extra_blob": "x" * 4000,
                            }
                        ],
                        "downstream": {"result": {"entries": [{"blob": "y" * 4000}]}},
                    },
                }
            ],
            summary_key="entry_results",
        )

        stored = task.summary["entry_results"][0]
        self.assertEqual("e1", stored["entries"][0]["entry_key"])
        self.assertEqual("src/main.c", stored["entries"][0]["definition_file"])
        self.assertEqual("42", stored["entries"][0]["definition_line"])
        self.assertTrue(stored["entries"][0]["is_definition_found"])
        self.assertEqual(["argv"], stored["entries"][0]["taint_params"])
        self.assertEqual(["argc", "argv"], stored["entries"][0]["signature_params"])
        self.assertNotIn("extra_blob", stored["entries"][0])
        self.assertNotIn("downstream", stored)
        self.assertEqual(1, summary["entry_count"])
        self.assertNotIn("entries", summary["items"][0])
        self.assertEqual("e1", summary["items"][0]["entries_preview"][0]["entry_key"])
        self.assertEqual(["argv"], summary["items"][0]["entries_preview"][0]["taint_params"])

    def test_entry_results_default_missing_taints_to_all_signature_params(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "module_key": "m1",
                        "module_name": "openssl",
                        "source_dir": "/tmp/archive/openssl",
                        "entries": [
                            {
                                "entry_key": "e1",
                                "module_key": "m1",
                                "module_name": "openssl",
                                "file_name": "main.c",
                                "function_name": "main",
                                "raw_function_name": "int main(int argc, char **argv)",
                                "line_no": "10",
                                "signature_params": ["argc", "argv"],
                                "source_dir": "/tmp/archive/openssl",
                            }
                        ],
                    },
                }
            ],
            summary_key="entry_results",
        )

        stored = task.summary["entry_results"][0]["entries"][0]
        self.assertEqual(["argc", "argv"], stored["signature_params"])
        self.assertEqual(["argc", "argv"], stored["taint_params"])

    def test_rebuild_entry_results_from_synced_stage_items_uses_archive_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            artifact = workspace / "output" / "entry"
            artifact.mkdir(parents=True)
            (artifact / "functions.list").write_text(
                """[
  {"file": "main.c", "line": 10, "function": "main(int argc, char **argv)", "taints": ["argv"]}
]""",
                encoding="utf-8",
            )
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="success",
            )
            stage_run.counts = {"total_items": 1, "success_items": 1, "failed_items": 0, "cancelled_items": 0}
            item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="entry_analysis",
                item_key="mod1",
                item_name="mod",
                status="success",
            )
            item.input_ref = {"module_key": "mod1", "module_name": "mod", "source_dir": "/src/mod", "task_type": TASK_TYPE_SOURCE}
            item.output_ref = {"artifact_root": str(artifact)}
            db = _ModelAwareDb(stage_runs=[stage_run], stage_items=[item])

            rebuilt = self.manager._rebuild_entry_results_from_stage_items(db, task, stage_run)

            self.assertEqual(1, len(rebuilt))
            self.assertEqual(1, len(task.summary["entry_results"][0]["entries"]))
            self.assertEqual("main", task.summary["entry_results"][0]["entries"][0]["function_name"])
            self.assertEqual(1, task.metrics["entry_count"])
            self.assertEqual(1, stage_run.output_summary["entry_count"])

    def test_dataflow_stage_backfills_missing_entry_results_before_failing_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            artifact = workspace / "output" / "entry"
            artifact.mkdir(parents=True)
            (artifact / "functions.list").write_text(
                '[{"file":"main.c","line":10,"function":"main(int argc, char **argv)","taints":["argv"]}]',
                encoding="utf-8",
            )
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {}
            entry_run = BinarySecurityStageRun(id="sr-entry", task_id="t1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="success")
            dataflow_run = BinarySecurityStageRun(id="sr-df", task_id="t1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="running")
            item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr-entry",
                stage_name="entry_analysis",
                item_key="mod1",
                item_name="mod",
                status="success",
            )
            item.input_ref = {"module_key": "mod1", "module_name": "mod", "source_dir": "/src/mod", "task_type": TASK_TYPE_SOURCE}
            item.output_ref = {"artifact_root": str(artifact)}
            db = _AppendingModelAwareDb(stage_runs=[entry_run, dataflow_run], stage_items=[item])
            captured = {}

            def fake_prepare(*args, **kwargs):
                return None

            async def fake_run_stage_pool(task_arg, entries, parallelism, runner, retries=0, initial_retry=False):
                captured["entries"] = entries
                return [{"status": "success", "item": {**entries[0], "data_flow_file": "/tmp/df.md"}}]

            self.manager._prepare_stage_items_for_execution = fake_prepare
            self.manager._run_stage_pool = fake_run_stage_pool

            status, summary = asyncio.run(self.manager._stage_dataflow_analysis(db, task, dataflow_run, token=None))

            self.assertEqual("success", status)
            self.assertEqual("main", captured["entries"][0]["function_name"])
            self.assertEqual(1, summary["success_count"])

    def test_dataflow_results_keep_vuln_inputs_but_drop_downstream_payload(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "entry_key": "e1",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "file_name": "main.c",
                        "function_name": "main",
                        "line_no": "10",
                        "source_dir": "/tmp/archive/openssl",
                        "data_flow_file": "/tmp/archive/openssl/dataflow.md",
                        "artifact_root": "/tmp/archive/openssl/dataflow",
                        "downstream": {"items": [{"blob": "z" * 4000}]},
                    },
                }
            ],
            summary_key="dataflow_results",
        )

        stored = task.summary["dataflow_results"][0]
        self.assertEqual("/tmp/archive/openssl/dataflow.md", stored["data_flow_file"])
        self.assertEqual("/tmp/archive/openssl", stored["source_dir"])
        self.assertNotIn("downstream", stored)

    def test_vuln_results_store_only_archive_summary(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {
                    "status": "success",
                    "item": {
                        "entry_key": "e1",
                        "module_key": "m1",
                        "module_name": "openssl",
                        "function_name": "main",
                        "source_dir": "/tmp/archive/openssl",
                        "data_flow_file": "/tmp/archive/openssl/dataflow.md",
                        "workspace_root": "/tmp/workspace",
                        "archive_root": "/tmp/archive/scan",
                        "artifact_files": [f"/tmp/archive/scan/{idx}.json" for idx in range(50)],
                        "artifacts": {"files": [{"blob": "x" * 4000}]},
                        "downstream": {"result": {"blob": "y" * 4000}},
                    },
                }
            ],
            summary_key="vuln_results",
        )

        stored = task.summary["vuln_results"][0]
        self.assertEqual(50, stored["artifact_file_count"])
        self.assertEqual("/tmp/archive/scan", stored["archive_root"])
        self.assertNotIn("artifact_files", stored)
        self.assertNotIn("artifacts", stored)
        self.assertNotIn("downstream", stored)

    def test_finalize_task_prefers_partial_success_after_vuln_stage(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        db = _FakeDb(rows=[_StageRun("binary_to_source", "failed"), _StageRun("vuln_scan", "partial_success")])

        self.manager._finalize_task(db, task)

        self.assertEqual("partial_success", task.status)
        self.assertIsNotNone(task.finished_at)
        self.assertTrue(any(isinstance(obj, BinarySecurityEvent) for obj in db.added))

    def test_finalize_task_does_not_mark_success_when_enabled_stage_missing(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_options": {
                "firmware_unpack": {"enabled": True},
                "system_analysis": {"enabled": True},
                "binary_to_source": {"enabled": True},
                "entry_analysis": {"enabled": True},
                "dataflow_analysis": {"enabled": True},
                "vuln_scan": {"enabled": True},
            }
        }
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
            ],
        )

        self.manager._finalize_task(db, task)

        self.assertEqual("partial_success", task.status)
        self.assertEqual("binary_to_source", task.current_stage)

    def test_next_incomplete_stage_skips_disabled_stages(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_options": {
                "firmware_unpack": {"enabled": True},
                "system_analysis": {"enabled": True},
                "binary_to_source": {"enabled": False},
                "entry_analysis": {"enabled": False},
                "dataflow_analysis": {"enabled": False},
                "vuln_scan": {"enabled": False},
            }
        }
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
            ],
        )

        self.assertIsNone(self.manager._next_incomplete_stage(db, task))

    def test_next_incomplete_stage_treats_partial_success_as_completed(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="partial_success"),
            ],
        )

        self.assertEqual("entry_analysis", self.manager._next_incomplete_stage(db, task))

    def test_next_incomplete_stage_blocks_partial_success_when_stage_advancement_disabled(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": True,
            }
        }
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="partial_success"),
            ],
        )

        self.assertEqual("binary_to_source", self.manager._next_incomplete_stage(db, task))

    def test_task_continue_support_targets_current_stage_when_partial_success_advancement_disabled(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="partial_success",
            task_type=TASK_TYPE_BINARY,
            current_stage="binary_to_source",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "selected_modules": [{"module_key": "m1", "module_name": "m1", "firmware_key": "fw1"}],
        }
        task.policy = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": True,
            }
        }
        db = _ModelAwareDb(
            stage_runs=[
                BinarySecurityStageRun(id="sr1", task_id="t1", project_id="p1", stage_name="firmware_unpack", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="t1", project_id="p1", stage_name="system_analysis", sequence_no=2, status="success"),
                BinarySecurityStageRun(id="sr3", task_id="t1", project_id="p1", stage_name="binary_to_source", sequence_no=3, status="partial_success"),
            ],
        )

        supported, reason, target_stage = self.manager._task_continue_support(db, task)

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual("binary_to_source", target_stage)

    def test_refresh_task_status_after_sync_requeues_next_stage(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(stage_runs=[run])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)

    def test_refresh_task_status_after_sync_requeues_next_stage_for_task_retry_mode(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            execution_mode="task_retry",
            target_stage_name="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="firmware_unpack",
                sequence_no=1,
                status="success",
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=2,
                status="success",
            ),
        ]
        db = _ModelAwareDb(tasks=[task], stage_runs=runs)

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("pending", task.status)
        self.assertEqual("binary_to_source", task.current_stage)
        self.assertIsNone(task.execution_mode)
        self.assertIsNone(task.target_stage_name)
        self.assertIsNone(task.dispatcher_instance_id)
        self.assertIsNone(task.dispatch_started_at)

    def test_refresh_task_status_after_sync_does_not_auto_retry_failed_stage(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            ),
            BinarySecurityStageRun(
                id="sr3",
                task_id="s1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            ),
        ]
        db = _ModelAwareDb(stage_runs=runs)

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("partial_success", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNotNone(task.finished_at)

    def test_continue_task_starts_after_last_successful_stage(self):
        workspace = Path(tempfile.mkdtemp())
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root=str(workspace / "output"),
            workspace_root=str(workspace),
        )
        task.summary = {
            "selected_modules": [{"module_key": "m1"}],
            "entry_results": [{"entry_key": "e1"}],
            "stale_stages": ["entry_analysis"],
        }
        task.metrics = {"entry_count": 1, "vuln_result_count": 1}
        task.stage_summary = {"system_analysis": {"status": "success"}, "entry_analysis": {"status": "failed"}}
        runs = [
            BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="success",
            ),
            BinarySecurityStageRun(
                id="sr2",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
                last_error="boom",
            ),
            BinarySecurityStageRun(
                id="sr3",
                task_id="s1",
                project_id="p1",
                stage_name="dataflow_analysis",
                sequence_no=3,
                status="pending",
            ),
        ]
        db = _ModelAwareDb(
            tasks=[task],
            stage_runs=runs,
            stage_items=[BinarySecurityStageItem(id="i1", task_id="s1", project_id="p1", stage_name="entry_analysis", item_key="m1")],
        )

        async def fake_delete_downstream_refs(*args, **kwargs):
            return 0

        self.manager._delete_downstream_refs = fake_delete_downstream_refs

        target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))

        self.assertEqual("entry_analysis", target_stage)
        self.assertEqual("continue_preparing", task.status)
        self.assertEqual("continue", task.pending_action)
        self._finish_continue_prepare(db, task, target_stage)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.finished_at)
        self.assertNotIn("entry_results", task.summary)
        self.assertNotIn("stale_stages", task.summary)
        self.assertEqual("pending", runs[1].status)
        self.assertEqual({}, runs[1].output_summary)

    def test_continue_task_clears_archive_jobs_for_affected_stages(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="partial_success",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {"selected_modules": [{"module_key": "m1", "source_dir": "/src/m1"}]}
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="failed"),
            ]
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="s1",
                    project_id="p1",
                    stage_name="entry_analysis",
                    item_id="i1",
                    archive_status="success",
                )
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs, archive_jobs=archive_jobs)

            async def fake_delete_downstream_refs(*args, **kwargs):
                return 0

            self.manager._delete_downstream_refs = fake_delete_downstream_refs

            target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))
            self._finish_continue_prepare(db, task, target_stage)

            self.assertEqual([], db.archive_jobs)

    def test_persist_stage_run_output_summary_externalizes_full_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="demo",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="running",
            )
            full_summary = {
                "items": [
                    {
                        "module_key": "m1",
                        "module_name": "module-1",
                        "source_dir": "/src/module-1",
                        "artifact_root": "/out/module-1",
                        "entries": [
                            {"entry_key": f"e{i}", "function_name": f"fn{i}", "file_name": "a.c", "line_no": i}
                            for i in range(20)
                        ],
                    }
                ],
                "success_count": 1,
                "failed_count": 0,
                "entry_count": 20,
            }

            compact = self.manager._persist_stage_run_output_summary(task, stage_run, full_summary)

            summary_file = workspace / "run" / "stage-summaries" / "02_entry_analysis.json"
            self.assertTrue(summary_file.is_file())
            self.assertEqual(full_summary["entry_count"], compact["entry_count"])
            self.assertTrue(compact["summary_externalized"])
            self.assertEqual(str(summary_file), compact["summary_file"])
            self.assertEqual(1, compact["item_count"])
            self.assertEqual(20, compact["items_preview"][0]["entry_count"])
            self.assertLessEqual(len(compact["items_preview"][0]["entries_preview"]), 5)

    def test_update_task_concurrency_updates_binary_stage_parallelism(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="success",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "max_stage_parallelism": 4,
            "max_retries_per_item": 3,
            "continue_on_item_failure": False,
            "stage_parallelism": {
                "firmware_unpack": 4,
                "system_analysis": 4,
                "binary_to_source": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            },
        }
        db = _ModelAwareDb(tasks=[task])

        detail = self.manager.update_task_concurrency(
            db,
            project_id="p1",
            task_id="t1",
            payload=BinarySecurityTaskConcurrencyUpdatePayload(
                stage_parallelism={"firmware_unpack": 2, "vuln_scan": 8}
            ),
        )

        self.assertEqual(8, detail.policy["max_stage_parallelism"])
        self.assertEqual(2, detail.policy["stage_parallelism"]["firmware_unpack"])
        self.assertEqual(8, detail.policy["stage_parallelism"]["vuln_scan"])
        self.assertEqual(4, detail.policy["stage_parallelism"]["system_analysis"])
        self.assertEqual(3, detail.policy["max_retries_per_item"])
        self.assertFalse(detail.policy["continue_on_item_failure"])

    def test_update_task_concurrency_rejects_stages_outside_source_flow(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {"stage_parallelism": {"system_analysis": 4, "entry_analysis": 4, "dataflow_analysis": 4, "vuln_scan": 4}}
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "阶段不属于当前任务流程"):
            self.manager.update_task_concurrency(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskConcurrencyUpdatePayload(stage_parallelism={"firmware_unpack": 2}),
            )

    def test_update_task_concurrency_rejects_invalid_parallelism_value(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {"stage_parallelism": {"system_analysis": 4, "entry_analysis": 4, "dataflow_analysis": 4, "vuln_scan": 4}}
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "并发必须是 1 到 32 之间的整数"):
            self.manager.update_task_concurrency(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskConcurrencyUpdatePayload(stage_parallelism={"system_analysis": 33}),
            )

    def test_update_task_policy_merges_fields_and_records_event(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "max_stage_parallelism": 4,
            "max_retries_per_item": 2,
            "continue_on_item_failure": True,
            "partial_success_stage_advancement": {
                "binary_to_source": True,
                "entry_analysis": True,
                "dataflow_analysis": True,
            },
            "stage_parallelism": {
                "firmware_unpack": 4,
                "system_analysis": 4,
                "binary_to_source": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            },
            "stage_options": {
                "binary_to_source": {"enabled": True},
            },
            "module_selection_mode": "auto",
            "module_risk_levels": ["高"],
        }
        db = _ModelAwareDb(tasks=[task])

        detail = self.manager.update_task_policy(
            db,
            project_id="p1",
            task_id="t1",
            payload=BinarySecurityTaskPolicyUpdatePayload(
                stage_options={"binary_to_source": {"enabled": False}},
                max_retries_per_item=5,
                continue_on_item_failure=False,
                partial_success_stage_advancement={"binary_to_source": False, "entry_analysis": True},
                stage_parallelism={"vuln_scan": 8},
                module_selection_mode="manual_confirm",
                module_risk_levels=["高", "中"],
            ),
        )

        self.assertEqual(8, detail.policy["max_stage_parallelism"])
        self.assertEqual(5, detail.policy["max_retries_per_item"])
        self.assertFalse(detail.policy["continue_on_item_failure"])
        self.assertFalse(detail.policy["partial_success_stage_advancement"]["binary_to_source"])
        self.assertTrue(detail.policy["partial_success_stage_advancement"]["entry_analysis"])
        self.assertEqual(8, detail.policy["stage_parallelism"]["vuln_scan"])
        self.assertEqual(4, detail.policy["stage_parallelism"]["firmware_unpack"])
        self.assertFalse(detail.policy["stage_options"]["binary_to_source"]["enabled"])
        self.assertEqual("manual_confirm", detail.policy["module_selection_mode"])
        self.assertEqual(["高", "中"], detail.policy["module_risk_levels"])
        self.assertTrue(any(isinstance(obj, BinarySecurityEvent) and obj.event_type == "task_policy_updated" for obj in db.added))

    def test_update_task_policy_rejects_stage_outside_source_flow(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_parallelism": {
                "system_analysis": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            }
        }
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "阶段不属于当前任务流程"):
            self.manager.update_task_policy(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskPolicyUpdatePayload(stage_options={"firmware_unpack": {"enabled": False}}),
            )

    def test_update_task_policy_rejects_partial_success_stage_outside_source_flow(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {}
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "阶段不属于当前任务流程: binary_to_source"):
            self.manager.update_task_policy(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskPolicyUpdatePayload(
                    partial_success_stage_advancement={"binary_to_source": False}
                ),
            )

    def test_update_task_policy_rejects_running_task(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="binary",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {
            "stage_parallelism": {
                "firmware_unpack": 4,
                "system_analysis": 4,
                "binary_to_source": 4,
                "entry_analysis": 4,
                "dataflow_analysis": 4,
                "vuln_scan": 4,
            }
        }
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "不允许修改任务策略"):
            self.manager.update_task_policy(
                db,
                project_id="p1",
                task_id="t1",
                payload=BinarySecurityTaskPolicyUpdatePayload(stage_parallelism={"vuln_scan": 8}),
            )

    def test_continue_task_deletes_archive_child_outputs_for_affected_stages(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            system_output = output_root / "system-analyse"
            entry_output = output_root / "entry-analyse"
            system_output.mkdir(parents=True)
            entry_output.mkdir(parents=True)
            (system_output / "kept.txt").write_text("old", encoding="utf-8")
            (entry_output / "stale.txt").write_text("old", encoding="utf-8")
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="partial_success",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            task.summary = {"selected_modules": [{"module_key": "m1", "source_dir": "/src/m1"}]}
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="failed"),
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs)

            async def fake_delete_downstream_refs(*args, **kwargs):
                return 0

            self.manager._delete_downstream_refs = fake_delete_downstream_refs

            target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))
            self._finish_continue_prepare(db, task, target_stage)

            self.assertTrue(system_output.exists())
            self.assertFalse(entry_output.exists())

    def test_continue_task_deletes_affected_downstream_tasks_before_requeue(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "input").mkdir(parents=True)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="failed"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="pending"),
            ]
            items = [
                BinarySecurityStageItem(
                    id="i1",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr1",
                    stage_name="system_analysis",
                    item_key="m1",
                    parent_key="m1",
                    downstream_service="system_analyse",
                    downstream_task_id="sat_1",
                    status="failed",
                ),
                BinarySecurityStageItem(
                    id="i2",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr2",
                    stage_name="entry_analysis",
                    item_key="m1",
                    parent_key="m1",
                    downstream_service="entry_analyse",
                    downstream_task_id="eat_1",
                    status="pending",
                ),
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs, stage_items=items)
            deleted_refs: list[dict[str, str]] = []

            async def fake_delete_downstream_refs(_db, _task, refs, _token):
                deleted_refs.extend(refs)
                return len(refs)

            self.manager._delete_downstream_refs = fake_delete_downstream_refs

            target_stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="s1"))

            self.assertEqual("system_analysis", target_stage)
            self._finish_continue_prepare(db, task, target_stage)
            self.assertEqual(
                [
                    {"service": "system_analyse", "task_id": "sat_1", "project_id": "p1", "stage_name": "system_analysis"},
                    {"service": "entry_analyse", "task_id": "eat_1", "project_id": "p1", "stage_name": "entry_analysis"},
                ],
                deleted_refs,
            )
            self.assertEqual([], db.stage_items)

    def test_cancel_task_cancels_local_worker(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_key="m1",
            status="running",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item])
        cancelled: list[str] = []

        async def fake_write_task_metadata_async(*args, **kwargs):
            return None

        async def fake_cancel_local_worker(task_id: str):
            cancelled.append(task_id)

        self.manager._write_task_metadata_async = fake_write_task_metadata_async
        self.manager._cancel_local_worker = fake_cancel_local_worker

        asyncio.run(self.manager.cancel_task(db, project_id="p1", task_id="t1"))

        self.assertEqual(["t1"], cancelled)
        self.assertEqual("cancelled", task.status)
        self.assertEqual("cancelled", item.status)

    def test_cancel_task_holds_lock_during_async_cleanup(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="i1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            item_key="m1",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat_1",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item])
        order: list[str] = []

        from contextlib import contextmanager

        @contextmanager
        def fake_task_operation_lock(_db, _task_id, *, operation, ttl_seconds=1800):
            del _db, _task_id, operation, ttl_seconds
            order.append("lock_enter")
            try:
                yield
            finally:
                order.append("lock_exit")

        async def fake_write_task_metadata_async(*args, **kwargs):
            del args, kwargs
            order.append("write_metadata")

        async def fake_cancel_local_worker(task_id: str):
            self.assertEqual("t1", task_id)
            self.assertNotIn("lock_exit", order)
            order.append("cancel_worker")

        async def fake_cancel_downstream(downstream_item, token):
            del token
            self.assertEqual("sat_1", downstream_item.downstream_task_id)
            self.assertNotIn("lock_exit", order)
            order.append("cancel_downstream")

        self.manager._task_operation_lock = fake_task_operation_lock
        self.manager._write_task_metadata_async = fake_write_task_metadata_async
        self.manager._cancel_local_worker = fake_cancel_local_worker
        self.manager._cancel_downstream = fake_cancel_downstream

        asyncio.run(self.manager.cancel_task(db, project_id="p1", task_id="t1"))

        self.assertEqual(
            ["lock_enter", "write_metadata", "cancel_worker", "cancel_downstream", "lock_exit"],
            order,
        )

    def test_retry_task_clears_archive_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="vuln_scan",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="t1",
                    project_id="p1",
                    stage_name="vuln_scan",
                    item_id="i1",
                    archive_status="success",
                )
            ]
            db = _ModelAwareDb(tasks=[task], archive_jobs=archive_jobs)

            self.manager.retry_task(db, project_id="p1", task_id="t1")
            self.assertEqual("retry_preparing", task.status)
            self.assertEqual("retry", task.pending_action)
            self._finish_retry_prepare(db, task)

            self.assertEqual("pending", task.status)
            self.assertEqual([], db.archive_jobs)

    def test_retry_task_clears_stage_output_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            system_output = output_root / "system-analyse"
            entry_output = output_root / "entry-analyse"
            system_output.mkdir(parents=True)
            entry_output.mkdir(parents=True)
            (system_output / "stale.txt").write_text("old", encoding="utf-8")
            (entry_output / "stale.txt").write_text("old", encoding="utf-8")
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            db = _ModelAwareDb(tasks=[task])

            self.manager.retry_task(db, project_id="p1", task_id="t1")
            self._finish_retry_prepare(db, task)

            self.assertFalse(system_output.exists())
            self.assertFalse(entry_output.exists())

    def test_binary_to_source_existing_retry_uses_rerun_api(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = BinarySecurityStageItem(
            id="item1",
            task_id="task1",
            project_id="p1",
            stage_name="binary_to_source",
            item_key="module1",
            item_name="mod.so",
            parent_key="fw1",
            downstream_service="binary_to_source",
            downstream_task_id="b2s-1",
            status="failed",
        )

        class _FakeB2SClient:
            def __init__(self):
                self.calls = []

            async def rerun_task(self, project_id, task_id, token, *, clean_output=True, cancel_running=True):
                self.calls.append(
                    {
                        "project_id": project_id,
                        "task_id": task_id,
                        "token": token,
                        "clean_output": clean_output,
                        "cancel_running": cancel_running,
                    }
                )
                return {"status": "ok"}

        fake_client = _FakeB2SClient()
        original = task_manager_module.get_binary_to_source_client
        task_manager_module.get_binary_to_source_client = lambda: fake_client
        try:
            result = asyncio.run(
                self.manager._invoke_existing_downstream_retry(
                    "binary_to_source",
                    task=task,
                    item=item,
                    token="tok",
                )
            )
        finally:
            task_manager_module.get_binary_to_source_client = original

        self.assertEqual({"status": "ok"}, result)
        self.assertEqual(
            [
                {
                    "project_id": "p1",
                    "task_id": "b2s-1",
                    "token": "tok",
                    "clean_output": True,
                    "cancel_running": True,
                }
            ],
            fake_client.calls,
        )

    def test_retry_task_full_restart_cleans_existing_downstream_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
            )
            item = BinarySecurityStageItem(
                id="item1",
                task_id="task1",
                project_id="p1",
                stage_name="system_analysis",
                item_key="fw1",
                item_name="fw1",
                parent_key="fw1",
                downstream_service="system_analyse",
                downstream_task_id="sa-1",
                status="failed",
            )
            db = _ModelAwareDb(tasks=[task], stage_items=[item])
            calls = []

            async def fake_cleanup(db_arg, task_arg, refs_arg, token_arg):
                calls.append(
                    {
                        "db": db_arg,
                        "task_id": task_arg.id,
                        "refs": refs_arg,
                        "token": token_arg,
                    }
                )

            original_cleanup = self.manager._cleanup_downstream_refs
            self.manager._cleanup_downstream_refs = fake_cleanup
            try:
                self.manager.retry_task(db, project_id="p1", task_id="task1")
                self._finish_retry_prepare(db, task)
            finally:
                self.manager._cleanup_downstream_refs = original_cleanup

            self.assertEqual(1, len(calls))
            self.assertEqual("task1", calls[0]["task_id"])
            self.assertEqual("sa-1", calls[0]["refs"][0]["task_id"])

    def test_cleanup_downstream_refs_waits_for_system_analyse_to_stop_before_delete(self):
        refs = [{"service": "system_analyse", "task_id": "sat-1", "project_id": "p1", "stage_name": "system_analysis"}]
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
        )
        db = _ModelAwareDb(tasks=[task])
        calls = []
        responses = iter([
            {"status": "running"},
            {"status": "cancelled"},
        ])

        async def fake_cancel(*args, **kwargs):
            calls.append("cancel")
            return 1

        async def fake_delete(*args, **kwargs):
            calls.append("delete")
            return 1

        async def fake_fetch(*args, **kwargs):
            calls.append("fetch")
            return next(responses)

        async def fake_sleep(*args, **kwargs):
            return None

        original_cancel = self.manager._cancel_downstream_refs
        original_delete = self.manager._delete_downstream_refs
        original_fetch = self.manager._fetch_downstream_ref_payload
        original_sleep = task_manager_module.asyncio.sleep
        self.manager._cancel_downstream_refs = fake_cancel
        self.manager._delete_downstream_refs = fake_delete
        self.manager._fetch_downstream_ref_payload = fake_fetch
        task_manager_module.asyncio.sleep = fake_sleep
        try:
            asyncio.run(self.manager._cleanup_downstream_refs(db, task, refs, None))
        finally:
            self.manager._cancel_downstream_refs = original_cancel
            self.manager._delete_downstream_refs = original_delete
            self.manager._fetch_downstream_ref_payload = original_fetch
            task_manager_module.asyncio.sleep = original_sleep

        self.assertEqual(["cancel", "fetch", "fetch", "delete"], calls)

    def test_cleanup_downstream_refs_raises_when_system_analyse_stays_running(self):
        refs = [{"service": "system_analyse", "task_id": "sat-1", "project_id": "p1", "stage_name": "system_analysis"}]
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
        )
        db = _ModelAwareDb(tasks=[task])

        async def fake_cancel(*args, **kwargs):
            return 1

        async def fake_fetch(*args, **kwargs):
            return {"status": "running"}

        async def fake_sleep(*args, **kwargs):
            return None

        original_cancel = self.manager._cancel_downstream_refs
        original_fetch = self.manager._fetch_downstream_ref_payload
        original_sleep = task_manager_module.asyncio.sleep
        self.manager._cancel_downstream_refs = fake_cancel
        self.manager._fetch_downstream_ref_payload = fake_fetch
        task_manager_module.asyncio.sleep = fake_sleep
        self.manager.cfg.scheduler.downstream_request_timeout_seconds = 0
        self.manager.cfg.scheduler.stage_poll_interval_seconds = 0
        try:
            with self.assertRaises(ValidationError):
                asyncio.run(self.manager._cleanup_downstream_refs(db, task, refs, None))
        finally:
            self.manager._cancel_downstream_refs = original_cancel
            self.manager._fetch_downstream_ref_payload = original_fetch
            task_manager_module.asyncio.sleep = original_sleep

    def test_continue_task_prefers_existing_downstream_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root="/o",
                workspace_root=tmp,
            )
            task.summary = {
                "firmware_unpack_results": [{"firmware_key": "fw1"}],
                "selected_modules": [{"module_key": "m1"}],
                "entry_results": [{"entry_key": "e1"}],
            }
            stage_runs = [
                SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="success"),
                BinarySecurityStageRun(id="sr1", task_id="task1", stage_name="system_analysis", status="failed"),
                BinarySecurityStageRun(id="sr2", task_id="task1", stage_name="binary_to_source", status="pending"),
            ]
            item = BinarySecurityStageItem(
                id="item1",
                task_id="task1",
                project_id="p1",
                stage_name="system_analysis",
                item_key="fw1",
                item_name="fw1",
                parent_key="fw1",
                downstream_service="system_analyse",
                downstream_task_id="sa-1",
                status="failed",
            )
            db = _ModelAwareDb(tasks=[task], stage_runs=stage_runs, stage_items=[item])

            stage = asyncio.run(self.manager.continue_task(db, project_id="p1", task_id="task1"))

            self.assertEqual("system_analysis", stage)
            self._finish_continue_prepare(db, task, stage)
            self.assertEqual("task_retry", task.execution_mode)
            self.assertEqual("system_analysis", task.target_stage_name)
            self.assertEqual(1, len(db.stage_items))

    def test_retry_stage_requeues_failed_archive_job_and_marks_task_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="binary",
                status="failed",
                task_type=TASK_TYPE_BINARY,
                current_stage="firmware_unpack",
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
                last_error="归档失败",
                finished_at=_now(),
            )
            run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="firmware_unpack",
                sequence_no=1,
                status="failed",
                last_error="归档失败",
            )
            item = BinarySecurityStageItem(
                id="i1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="firmware_unpack",
                item_key="fw1",
                item_name="fw.bin",
                status="failed",
                downstream_service="firmware_unpacker",
                downstream_task_id="ut1",
                error_message="归档失败",
            )
            item.input_ref = {"filename": "fw.bin", "path": "/input/fw.bin"}
            job = BinarySecurityArchiveJob(
                id="aj1",
                task_id="t1",
                project_id="p1",
                stage_name="firmware_unpack",
                item_id="i1",
                item_key="fw1",
                downstream_service="firmware_unpacker",
                downstream_task_id="ut1",
                archive_status="failed",
                owner_id="old-worker",
                archive_root=str(workspace / "old-archive"),
                error_message="copy failed",
            )
            job.payload = {"mapped_status": "success"}
            db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=[item], archive_jobs=[job])

            self.manager.retry_stage(db, project_id="p1", task_id="t1", stage_name="firmware_unpack")

            self.assertEqual("running", task.status)
            self.assertEqual("firmware_unpack", task.current_stage)
            self.assertIsNone(task.last_error)
            self.assertIsNone(task.finished_at)
            self.assertEqual("pending", job.archive_status)
            self.assertIsNone(job.owner_id)
            self.assertIsNone(job.archive_root)
            self.assertEqual("success", item.status)
            event_types = [getattr(event, "event_type", "") for event in db.added]
            self.assertIn("task_archive_retry_requeued", event_types)

    def test_retry_stage_clears_archive_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="entry_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            run = BinarySecurityStageRun(
                id="sr1",
                task_id="s1",
                project_id="p1",
                stage_name="entry_analysis",
                sequence_no=2,
                status="failed",
            )
            archive_jobs = [
                BinarySecurityArchiveJob(
                    id="aj1",
                    task_id="s1",
                    project_id="p1",
                    stage_name="entry_analysis",
                    item_id="i1",
                    archive_status="failed",
                )
            ]
            stage_items = [
                BinarySecurityStageItem(
                    id="i1",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr1",
                    stage_name="entry_analysis",
                    item_key="module-1",
                    status="failed",
                )
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=[run], stage_items=stage_items, archive_jobs=archive_jobs)

            self.manager.retry_stage(db, project_id="p1", task_id="s1", stage_name="entry_analysis")

            self.assertEqual("pending", task.status)
            self.assertEqual([], db.archive_jobs)

    def test_retry_stage_deletes_affected_downstream_tasks_before_requeue(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source",
                status="failed",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            runs = [
                BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="failed"),
                BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="pending"),
            ]
            items = [
                BinarySecurityStageItem(
                    id="i1",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr1",
                    stage_name="system_analysis",
                    item_key="source_project",
                    parent_key="source_project",
                    downstream_service="system_analyse",
                    downstream_task_id="sat_1",
                    status="running",
                ),
                BinarySecurityStageItem(
                    id="i2",
                    task_id="s1",
                    project_id="p1",
                    stage_run_id="sr2",
                    stage_name="entry_analysis",
                    item_key="m1",
                    parent_key="m1",
                    downstream_service="entry_analyse",
                    downstream_task_id="eat_1",
                    status="queued",
                ),
            ]
            db = _ModelAwareDb(tasks=[task], stage_runs=runs, stage_items=items)
            deleted_refs: list[dict[str, str]] = []
            cancelled_refs: list[dict[str, str]] = []

            async def fake_cancel_downstream_refs(_db, _task, refs, _token):
                cancelled_refs.extend(refs)
                return len(refs)

            async def fake_delete_downstream_refs(_db, _task, refs, _token):
                deleted_refs.extend(refs)
                return len(refs)

            original_cancel = self.manager._cancel_downstream_refs
            original_delete = self.manager._delete_downstream_refs
            original_retry_support = self.manager._stage_retry_support
            try:
                self.manager._cancel_downstream_refs = fake_cancel_downstream_refs
                self.manager._delete_downstream_refs = fake_delete_downstream_refs
                self.manager._stage_retry_support = lambda _db, _task, _stage_name: (True, None)
                self.manager.retry_stage(db, project_id="p1", task_id="s1", stage_name="system_analysis")
            finally:
                self.manager._cancel_downstream_refs = original_cancel
                self.manager._delete_downstream_refs = original_delete
                self.manager._stage_retry_support = original_retry_support

            expected_refs = [
                {"service": "system_analyse", "task_id": "sat_1", "project_id": "p1", "stage_name": "system_analysis"},
                {"service": "entry_analyse", "task_id": "eat_1", "project_id": "p1", "stage_name": "entry_analysis"},
            ]
            self.assertEqual(expected_refs, cancelled_refs)
            self.assertEqual(expected_refs, deleted_refs)
            self.assertEqual([], db.stage_items)
            self.assertEqual("pending", task.status)

    def test_refresh_task_status_after_stage_retry_requeues_downstream_stage(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
            execution_mode="stage_retry",
            target_stage_name="system_analysis",
        )
        task.summary = {"stale_stages": ["entry_analysis"], "stage_retry_context": {"system_analysis": {}}}
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="success",
        )
        db = _ModelAwareDb(stage_runs=[run])

        self.manager._refresh_task_status_after_sync(db, task)

        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.execution_mode)
        self.assertIsNone(task.target_stage_name)
        self.assertNotIn("stage_retry_context", task.summary)

    def test_stage_retry_support_allows_missing_downstream_task_id(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            downstream_service="entry_analyse",
            downstream_task_id=None,
        )
        db = _ModelAwareDb(stage_runs=[run], stage_items=[item])

        supported, reason = self.manager._stage_retry_support(db, task, "entry_analysis")

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertFalse(self.manager._has_retryable_downstream_task(item))

    def test_stage_retry_support_still_rejects_downstream_service_mismatch(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="failed",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            parent_key="source_project",
            downstream_service="system_analyse",
            downstream_task_id=None,
        )
        db = _ModelAwareDb(stage_runs=[run], stage_items=[item])

        supported, reason = self.manager._stage_retry_support(db, task, "entry_analysis")

        self.assertFalse(supported)
        self.assertIn("下游服务不匹配", reason or "")

    def test_stage_retry_support_allows_failed_stage_without_items_when_inputs_can_be_rebuilt(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {}
        run = BinarySecurityStageRun(
            id="sr3",
            task_id="s1",
            project_id="p1",
            stage_name="dataflow_analysis",
            sequence_no=3,
            status="failed",
        )
        entry_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            item_name="m1",
            status="success",
        )
        entry_item.result = {
            "module_key": "m1",
            "module_name": "m1",
            "source_dir": "/src/m1",
            "entries_preview": [{"entry_key": "e1", "function_name": "main", "file_name": "main.c", "line_no": 1}],
        }
        db = _ModelAwareDb(stage_runs=[run])
        original_stage_items = self.manager._stage_items

        def fake_stage_items(_db, _task_id, stage_name):
            return [entry_item] if stage_name == "entry_analysis" else []

        self.manager._stage_items = fake_stage_items
        try:
            supported, reason = self.manager._stage_retry_support(db, task, "dataflow_analysis")
        finally:
            self.manager._stage_items = original_stage_items

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual(1, len(task.summary["entry_results"]))

    def test_task_continue_support_rebuilds_dataflow_inputs_from_entry_stage_items(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="dataflow_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {}
        runs = [
            BinarySecurityStageRun(id="sr1", task_id="s1", project_id="p1", stage_name="system_analysis", sequence_no=1, status="success"),
            BinarySecurityStageRun(id="sr2", task_id="s1", project_id="p1", stage_name="entry_analysis", sequence_no=2, status="success"),
            BinarySecurityStageRun(id="sr3", task_id="s1", project_id="p1", stage_name="dataflow_analysis", sequence_no=3, status="failed"),
            BinarySecurityStageRun(id="sr4", task_id="s1", project_id="p1", stage_name="vuln_scan", sequence_no=4, status="pending"),
        ]
        entry_item = BinarySecurityStageItem(
            id="si-entry",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            item_key="m1",
            item_name="m1",
            status="success",
        )
        entry_item.result = {
            "module_key": "m1",
            "module_name": "m1",
            "source_dir": "/src/m1",
            "entries_preview": [{"entry_key": "e1", "function_name": "main", "file_name": "main.c", "line_no": 1}],
        }
        db = _ModelAwareDb(stage_runs=runs, stage_items=[entry_item])

        supported, reason, target_stage = self.manager._task_continue_support(db, task)

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual("dataflow_analysis", target_stage)
        self.assertEqual(1, len(task.summary["entry_results"]))

    def test_stage_retry_clears_only_target_stage_outputs(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="partial_success",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "selected_modules": [{"module_key": "m1"}],
            "entry_results": [{"entry_key": "e1"}],
            "dataflow_results": [{"entry_key": "e1"}],
            "vuln_results": [{"entry_key": "e1"}],
            "stale_stages": ["dataflow_analysis"],
            "stale_from_stage": "entry_analysis",
        }
        task.metrics = {"entry_count": 1, "vuln_result_count": 1}
        task.stage_summary = {
            "system_analysis": {"status": "success"},
            "entry_analysis": {"status": "failed"},
            "dataflow_analysis": {"status": "success"},
        }

        self.manager._clear_single_stage_outputs(task, "entry_analysis")

        self.assertNotIn("entry_results", task.summary)
        self.assertIn("dataflow_results", task.summary)
        self.assertIn("vuln_results", task.summary)
        self.assertIn("stale_stages", task.summary)
        self.assertEqual(0, task.metrics["entry_count"])
        self.assertEqual(1, task.metrics["vuln_result_count"])
        self.assertNotIn("entry_analysis", task.stage_summary)
        self.assertIn("dataflow_analysis", task.stage_summary)

    def test_upsert_stage_item_creates_missing_item_during_retry(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="running",
        )
        db = _ModelAwareDb(stage_runs=[run], stage_items=[])

        item = self.manager._upsert_stage_item(
            db,
            task=task,
            stage_run=run,
            stage_name="entry_analysis",
            item_key="m1",
            item_name="module1",
            parent_key="source_project",
            downstream_service="entry_analyse",
            input_ref={"module_key": "m1"},
            retrying=True,
        )

        self.assertEqual("m1", item.item_key)
        self.assertEqual(1, item.retry_count)
        self.assertEqual("running", item.status)
        self.assertEqual(1, len(db.added))

    def test_stage_enabled_uses_policy_override(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.policy = {"stage_options": {"vuln_scan": {"enabled": False}}}

        self.assertFalse(self.manager._stage_enabled(task, "vuln_scan"))
        self.assertTrue(self.manager._stage_enabled(task, "entry_analysis"))

    def test_stage_sequence_uses_task_type(self):
        binary_task = BinarySecurityTask(id="b1", project_id="p1", name="binary", task_type=TASK_TYPE_BINARY, status="pending", firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        source_task = BinarySecurityTask(id="s1", project_id="p1", name="source", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root="/o", workspace_root="/w")

        self.assertEqual(
            ["firmware_unpack", "system_analysis", "binary_to_source", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            self.manager._stage_sequence_for_task(binary_task),
        )
        self.assertEqual(
            ["system_analysis", "entry_analysis", "dataflow_analysis", "vuln_scan"],
            self.manager._stage_sequence_for_task(source_task),
        )

    def test_source_system_analysis_inputs_use_workspace_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "input").mkdir()
            task = BinarySecurityTask(id="s1", project_id="p1", name="source-task", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root=str(workspace / "output"), workspace_root=str(workspace))

            rows = self.manager._system_analysis_inputs(task)

            self.assertEqual(1, len(rows))
            self.assertEqual(TASK_TYPE_SOURCE, rows[0]["task_type"])
            self.assertEqual(str(workspace / "input"), rows[0]["unpacked_root"])
            self.assertEqual(str(workspace / "input"), rows[0]["source_root"])

    def test_source_entry_analysis_inputs_come_from_high_risk_modules(self):
        task = BinarySecurityTask(id="s1", project_id="p1", name="source-task", task_type=TASK_TYPE_SOURCE, status="pending", firmware_source="project_filesystem", firmware_path="/src", output_root="/o", workspace_root="/w")
        task.summary = {
            "selected_modules": [
                {"module_key": "m1", "module_name": "module1", "source_dir": "/src/module1"},
            ],
            "b2s_results": [
                {"module_key": "legacy", "module_name": "legacy", "source_dir": "/legacy"},
            ],
        }

        rows = self.manager._entry_analysis_inputs(task)

        self.assertEqual(1, len(rows))
        self.assertEqual("m1", rows[0]["module_key"])

    def test_stage_entry_analysis_precreates_all_selected_modules_as_queued_items(self):
        task = BinarySecurityTask(
            id="s1",
            project_id="p1",
            name="source-task",
            task_type=TASK_TYPE_SOURCE,
            status="pending",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "selected_modules": [
                {"module_key": "m1", "module_name": "module1", "firmware_key": "source_project_1", "source_dir": "/src/module1"},
                {"module_key": "m2", "module_name": "module2", "firmware_key": "source_project_2", "source_dir": "/src/module2"},
                {"module_key": "m3", "module_name": "module3", "firmware_key": "source_project_3", "source_dir": "/src/module3"},
            ]
        }
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="s1",
            project_id="p1",
            stage_name="entry_analysis",
            sequence_no=2,
            status="pending",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

        async def fake_run_stage_pool(current_task, items, concurrency, runner, retries=0, initial_retry=False):
            queued_items = [
                obj for obj in db.added
                if isinstance(obj, BinarySecurityStageItem) and obj.stage_name == "entry_analysis"
            ]
            self.assertEqual(task, current_task)
            self.assertEqual(3, len(items))
            self.assertEqual(3, len(queued_items))
            self.assertEqual(["m1", "m2", "m3"], [item.item_key for item in queued_items])
            self.assertTrue(all(item.status == "queued" for item in queued_items))
            self.assertTrue(all(item.started_at is None for item in queued_items))
            return [
                {"status": "cancelled", "item": module, "error": "cancelled"}
                for module in items
            ]

        self.manager._run_stage_pool = fake_run_stage_pool

        status, summary = asyncio.run(self.manager._stage_entry_analysis(db, task, stage_run, token=None, retry_existing=False))

        self.assertEqual("cancelled", status)
        self.assertEqual(3, summary["cancelled_count"])

    def test_filter_candidate_modules_by_risk_levels(self):
        modules = [
            {"module_key": "h1", "risk_level": "高"},
            {"module_key": "m1", "risk_level": "中"},
            {"module_key": "l1", "risk_level": "低"},
        ]

        rows = self.manager._filter_candidate_modules(modules, ["高", "中"])

        self.assertEqual(["h1", "m1"], [row["module_key"] for row in rows])

    def test_stage_system_analysis_marks_no_candidate_modules_as_business_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source-task",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.policy = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            (workspace / "input").mkdir(parents=True, exist_ok=True)
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

            original_prepare = self.manager._prepare_stage_items_for_execution
            original_run_stage_pool = self.manager._run_stage_pool
            self.manager._prepare_stage_items_for_execution = lambda *args, **kwargs: None

            async def fake_run_stage_pool(current_task, items, concurrency, runner, retries=0, initial_retry=False):
                del current_task, items, concurrency, runner, retries, initial_retry
                return [
                    {
                        "status": "success",
                        "item": {
                            "firmware_key": "source_project",
                            "firmware_name": "source-task",
                            "filename": "source-project",
                            "unpacked_root": str(workspace / "input"),
                            "source_root": str(workspace / "input"),
                            "task_type": TASK_TYPE_SOURCE,
                        },
                        "modules": [{"module_key": "m1", "module_name": "m1", "risk_level": "中", "risk_score": 50}],
                    }
                ]

            self.manager._run_stage_pool = fake_run_stage_pool
            try:
                status, summary = asyncio.run(
                    self.manager._stage_system_analysis(db, task, stage_run, token=None, retry_existing=False)
                )
            finally:
                self.manager._prepare_stage_items_for_execution = original_prepare
                self.manager._run_stage_pool = original_run_stage_pool

            self.assertEqual("failed", status)
            self.assertEqual("no_candidate_modules", summary["failure_code"])
            self.assertEqual("business", summary["failure_category"])
            self.assertIn("未发现匹配所选风险等级的风险模块", summary["failure_message"])
            self.assertEqual(summary["failure_message"], task.last_error)
            self.assertEqual("no_candidate_modules", task.summary["failure_code"])
            event_types = [getattr(event, "event_type", "") for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertIn("system_analysis_no_candidate_modules", event_types)

    def test_refresh_system_analysis_stage_from_synced_items_marks_no_candidate_modules_as_business_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output_root = workspace / "output"
            artifact_root = output_root / "system-analyse" / "source_project__sat1"
            artifact_root.mkdir(parents=True, exist_ok=True)
            task = BinarySecurityTask(
                id="t1",
                project_id="p1",
                name="source-task",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                current_stage="system_analysis",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(output_root),
                workspace_root=str(workspace),
            )
            task.policy = {}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="t1",
                project_id="p1",
                stage_name="system_analysis",
                sequence_no=1,
                status="running",
            )
            item = BinarySecurityStageItem(
                id="si1",
                task_id="t1",
                project_id="p1",
                stage_run_id="sr1",
                stage_name="system_analysis",
                item_key="source_project",
                item_name="source-project",
                status="success",
                downstream_service="system_analyse",
                downstream_task_id="sat1",
            )
            item.result = {
                "firmware_key": "source_project",
                "firmware_name": "source-task",
                "filename": "source-project",
                "unpacked_root": str(workspace / "input"),
                "source_root": str(workspace / "input"),
                "task_type": TASK_TYPE_SOURCE,
                "artifact_root": str(artifact_root),
                "archive_root": str(artifact_root),
                "modules": [{"module_key": "m1", "module_name": "m1", "risk_level": "", "risk_score": 0}],
            }
            item.output_ref = {"archive_root": str(artifact_root)}
            db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[item])

            self.manager._refresh_system_analysis_stage_from_synced_items(db, task)

            self.assertEqual("failed", stage_run.status)
            self.assertEqual("系统分析已完成，但未发现匹配所选风险等级的风险模块", stage_run.last_error)
            self.assertEqual(stage_run.last_error, task.last_error)
            self.assertEqual("no_candidate_modules", task.summary["failure_code"])
            self.assertEqual("business", task.summary["failure_category"])
            self.assertEqual("no_candidate_modules", stage_run.output_summary["failure_code"])
            event_types = [getattr(event, "event_type", "") for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertIn("system_analysis_no_candidate_modules", event_types)

    def test_stage_system_analysis_success_clears_stale_failure_fields(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            status="running",
            task_type=TASK_TYPE_BINARY,
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.policy = {"module_risk_levels": ["高"]}
        task.summary = {
            "failure_code": "no_candidate_modules",
            "failure_category": "business",
            "failure_message": "stale",
            "error": "stale",
            "firmware_unpack_results": [{
                "firmware_key": "fw1",
                "firmware_name": "fw1",
                "filename": "fw1.bin",
                "unpacked_root": "/tmp/fw1",
                "source_root": "/tmp/fw1",
                "task_type": TASK_TYPE_BINARY,
            }],
        }
        task.last_error = "stale"
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="t1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run])

        original_prepare = self.manager._prepare_stage_items_for_execution
        original_run_stage_pool = self.manager._run_stage_pool
        self.manager._prepare_stage_items_for_execution = lambda *args, **kwargs: None

        async def fake_run_stage_pool(*args, **kwargs):
            return [{
                "status": "success",
                "item": {
                    "firmware_key": "fw1",
                    "firmware_name": "fw1",
                    "filename": "fw1.bin",
                    "modules": [{
                        "module_key": "m1",
                        "module_name": "m1",
                        "risk_level": "高",
                        "risk_score": 90,
                    }],
                },
            }]

        self.manager._run_stage_pool = fake_run_stage_pool
        try:
            status, summary = asyncio.run(
                self.manager._stage_system_analysis(db, task, stage_run, token=None, retry_existing=False)
            )
        finally:
            self.manager._prepare_stage_items_for_execution = original_prepare
            self.manager._run_stage_pool = original_run_stage_pool

        self.assertEqual("success", status)
        self.assertEqual(1, summary["candidate_module_count"])
        self.assertEqual(1, len(task.summary["selected_modules"]))
        self.assertNotIn("failure_code", task.summary)
        self.assertNotIn("failure_category", task.summary)
        self.assertNotIn("failure_message", task.summary)
        self.assertNotIn("error", task.summary)
        self.assertIsNone(task.last_error)

    def test_confirm_module_selection_updates_task(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="task",
            task_type=TASK_TYPE_SOURCE,
            status="pending_module_confirmation",
            current_stage="system_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        task.summary = {
            "candidate_modules": [
                {"module_key": "m1", "module_name": "module1", "risk_level": "高"},
                {"module_key": "m2", "module_name": "module2", "risk_level": "中"},
            ],
            "selected_modules": [],
        }
        task.policy = {"module_selection_mode": "manual_confirm", "module_risk_levels": ["高", "中"]}

        class _TaskDb(_FakeDb):
            def __init__(self, task_row):
                super().__init__([task_row])
                self.task_row = task_row

            def query(self, model, *args, **kwargs):
                class _Query(_FakeQuery):
                    def filter(self, *args, **kwargs):
                        return self
                    def order_by(self, *args, **kwargs):
                        return self
                if getattr(model, "__name__", "") == "BinarySecurityTask":
                    return _Query([self.task_row])
                if getattr(model, "__name__", "") == "BinarySecurityStageRun":
                    return _Query([])
                return _Query([])

        db = _TaskDb(task)
        detail = self.manager.confirm_module_selection(
            db,
            project_id="p1",
            task_id="t1",
            selected_module_keys=["m2"],
        )

        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertEqual(1, task.metrics["selected_module_count"])
        self.assertEqual(["m2"], [item["module_key"] for item in task.summary["selected_modules"]])
        self.assertEqual(1, detail.selected_module_count)

    def test_normalize_source_input_files_rejects_duplicate_relative_paths(self):
        with self.assertRaisesRegex(Exception, "重复文件名"):
            self.manager._normalize_input_files(
                [
                    {"filename": "src.zip", "relative_path": "src/a.c"},
                    {"filename": "src.zip", "relative_path": "src/b.c"},
                ],
                task_type=TASK_TYPE_SOURCE,
            )

    def test_normalize_source_input_files_rejects_non_archive(self):
        with self.assertRaisesRegex(Exception, "仅支持常见压缩文件"):
            self.manager._normalize_input_files(
                [
                    {"filename": "main.c"},
                ],
                task_type=TASK_TYPE_SOURCE,
            )

    def test_materialize_source_archives_extracts_into_input_and_cleans_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            input_dir = workspace / "input"
            temp_dir = workspace / "run" / "upload-tmp"
            input_dir.mkdir(parents=True)
            temp_dir.mkdir(parents=True)
            archive_path = temp_dir / "source.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("src/main.c", "int main() { return 0; }\n")
                archive.writestr("README.md", "# demo\n")
            task = BinarySecurityTask(
                id="s1",
                project_id="p1",
                name="source-task",
                task_type=TASK_TYPE_SOURCE,
                status="pending_upload",
                firmware_source="project_filesystem",
                firmware_path="/src",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            task.summary = {
                "input_dir": "/app/secflow-app-binary-security/s1/input",
                "temp_upload_dir": "/app/secflow-app-binary-security/s1/run/upload-tmp",
            }

            files, total_bytes, extracted_count = asyncio.run(
                self.manager._materialize_source_archives(
                    task,
                    [{"filename": "source.zip", "relative_path": "source.zip"}],
                )
            )

            self.assertEqual(1, len(files))
            self.assertGreater(total_bytes, 0)
            self.assertEqual(2, extracted_count)
            self.assertTrue((input_dir / "src" / "main.c").is_file())
            self.assertTrue((input_dir / "README.md").is_file())
            self.assertFalse(archive_path.exists())

    def test_resolve_downstream_output_sources_prefers_output_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"workspace_root": str(workspace)},
                downstream_task_id="t123",
            )

            self.assertEqual(output_dir, rows[0])

    def test_archive_downstream_output_copies_output_contents_without_output_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "result.json").write_text("{}", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type("Item", (), {
                "downstream_service": "system_analyse",
                "stage_name": "system_analysis",
                "downstream_task_id": "down1",
                "item_key": "fw1",
                "id": "si1",
            })()
            db = _FakeDb()

            target = self.manager._archive_downstream_output(
                db,
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertIsNotNone(target)
            assert target is not None
            self.assertTrue((target / "result.json").is_file())
            self.assertFalse((target / "output").exists())
            self.assertEqual("system-analyse", target.parent.name)
            self.assertEqual("fw1__down1", target.name)

    def test_resolve_downstream_output_sources_reads_nested_result_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "service" / "down1" / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"result": {"output_root": str(root / "service")}},
                downstream_task_id="down1",
            )

            self.assertEqual(output_dir, rows[0])

    def test_archive_downstream_output_uses_standard_service_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "app" / "secflow-app-binary-security" / "task1"
            source_output = root / "app" / "secflow-app-firmware-unpacker" / "down1" / "output"
            source_output.mkdir(parents=True)
            (source_output / "summary.md").write_text("ok", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(workspace / "output"),
                workspace_root=str(workspace),
            )
            item = type("Item", (), {
                "downstream_service": "firmware_unpacker",
                "stage_name": "firmware_unpack",
                "downstream_task_id": "down1",
                "item_key": "fw1",
                "id": "si1",
            })()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"output_path": str(workspace / "run" / "firmware-unpacker" / "fw1")},
            )

            self.assertIsNotNone(target)
            assert target is not None
            self.assertTrue((target / "summary.md").is_file())
            self.assertEqual("firmware-unpacker", target.parent.name)

    def test_archive_downstream_output_skips_empty_sources_without_creating_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            empty_output = workspace / "output"
            empty_output.mkdir(parents=True)
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type("Item", (), {
                "downstream_service": "system_analyse",
                "stage_name": "system_analysis",
                "downstream_task_id": "down1",
                "item_key": "fw1",
                "id": "si1",
            })()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertIsNone(target)
            self.assertFalse((root / "task-output" / "system-analyse" / "fw1__down1").exists())

    def test_archive_job_payload_uses_compact_downstream_payload(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        item = type("Item", (), {
            "id": "si1",
            "stage_name": "system_analysis",
            "item_key": "source_project",
            "downstream_service": "system_analyse",
            "downstream_task_id": "sat1",
        })()
        db = _ModelAwareDb()

        job = self.manager._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload={
                "task_id": "sat1",
                "status": "success",
                "workspace_root": "/tmp/system-analysis/sat1",
                "modules": [{"name": f"module-{idx}", "blob": "x" * 1000} for idx in range(100)],
                "result": {
                    "output_root": "/tmp/system-analysis/sat1/output",
                    "modules": [{"name": f"nested-{idx}", "blob": "y" * 1000} for idx in range(100)],
                },
            },
            mapped_status="success",
            before_status="running",
        )

        payload = job.payload
        downstream_payload = payload["downstream_payload"]
        self.assertEqual("sat1", downstream_payload["task_id"])
        self.assertEqual("/tmp/system-analysis/sat1", downstream_payload["workspace_root"])
        self.assertEqual("/tmp/system-analysis/sat1/output", downstream_payload["result"]["output_root"])
        self.assertNotIn("modules", downstream_payload)
        self.assertNotIn("modules", downstream_payload["result"])
        self.assertLess(len(job.payload_json or ""), 2048)

    def test_collect_downstream_refs_dedupes_same_service_and_task_id(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        items = []
        for item_id, task_id in [("i1", "down1"), ("i2", "down1"), ("i3", "down2")]:
            item = type("Item", (), {})()
            item.id = item_id
            item.downstream_service = "entry_analyse"
            item.downstream_task_id = task_id
            item.project_id = "p1"
            item.stage_name = "entry_analysis"
            items.append(item)

        refs = self.manager._collect_downstream_refs(task, items)

        self.assertEqual(2, len(refs))
        self.assertEqual(
            [
                {"service": "entry_analyse", "task_id": "down1", "project_id": "p1", "stage_name": "entry_analysis"},
                {"service": "entry_analyse", "task_id": "down2", "project_id": "p1", "stage_name": "entry_analysis"},
            ],
            refs,
        )

    def test_stage_retry_support_allows_missing_downstream_task_id_for_recreate(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="failed")
        stage_item = SimpleNamespace(
            task_id="task1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id=None,
            created_at=1,
        )

        supported, reason = self.manager._stage_retry_support(
            _ModelAwareDb(stage_runs=[stage_run], stage_items=[stage_item]),
            task,
            "firmware_unpack",
        )

        self.assertTrue(supported)
        self.assertIsNone(reason)

    def test_stage_retry_support_rejects_duplicate_history_items(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="failed")
        item1 = SimpleNamespace(
            task_id="task1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id="down-1",
            created_at=1,
        )
        item2 = SimpleNamespace(
            task_id="task1",
            stage_name="firmware_unpack",
            item_key="fw1",
            parent_key="fw1",
            downstream_service="firmware_unpacker",
            downstream_task_id="down-2",
            created_at=2,
        )

        supported, reason = self.manager._stage_retry_support(
            _ModelAwareDb(stage_runs=[stage_run], stage_items=[item1, item2]),
            task,
            "firmware_unpack",
        )

        self.assertFalse(supported)
        self.assertIn("重复历史 item", reason or "")

    def test_task_retry_support_targets_first_stage_for_full_restart(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="failed",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        stage_runs = [
            SimpleNamespace(task_id="task1", stage_name="firmware_unpack", status="success"),
            SimpleNamespace(task_id="task1", stage_name="system_analysis", status="failed"),
        ]
        stage_items = [
            SimpleNamespace(
                task_id="task1",
                stage_name="system_analysis",
                item_key="fw1",
                parent_key="fw1",
                downstream_service="system_analyse",
                downstream_task_id="sa-1",
                created_at=1,
            ),
        ]

        supported, reason, stage_name = self.manager._task_retry_support(
            _ModelAwareDb(stage_runs=stage_runs, stage_items=stage_items),
            task,
        )

        self.assertTrue(supported)
        self.assertIsNone(reason)
        self.assertEqual("firmware_unpack", stage_name)

    def test_reclaim_stale_running_task_marks_stage_and_items_failed(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            current_stage="firmware_unpack",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )
        task.dispatch_started_at = _now()
        task.updated_at = task.dispatch_started_at - timedelta(seconds=360)
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="task1",
            project_id="p1",
            stage_name="firmware_unpack",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="firmware_unpack",
            item_key="fw1",
            status="running",
        )

        class _ReclaimDb(_FakeDb):
            def query(self, model, *args, **kwargs):
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if model_name == "BinarySecurityStageRun":
                    return _FakeQuery([stage_run])
                if model_name == "BinarySecurityStageItem":
                    return _FakeQuery([item])
                return _FakeQuery([])

            def flush(self):
                pass

        original_loader = self.manager._load_service_config
        self.manager._load_service_config = lambda db: SimpleNamespace(dispatch_timeout_seconds=60)
        try:
            reclaimed = self.manager._reclaim_stale_running_locked(_ReclaimDb())
        finally:
            self.manager._load_service_config = original_loader

        self.assertTrue(reclaimed)
        self.assertEqual("failed", task.status)
        self.assertEqual("failed", stage_run.status)
        self.assertEqual("failed", item.status)
        self.assertIsNotNone(task.finished_at)
        self.assertIn("心跳超时", task.last_error or "")

    def test_run_task_ignores_stale_worker_failure_after_retry(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="dispatching",
            current_stage="firmware_unpack",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id=self.manager.instance_id,
        )
        task.dispatch_started_at = _now()
        original_token = task.dispatch_started_at

        class _RunTaskDb(_ModelAwareDb):
            def __init__(self, current_task):
                super().__init__(tasks=[current_task])
                self.current_task = current_task
                self.commits = 0
                self.closed = False

            def commit(self):
                self.commits += 1

            def close(self):
                self.closed = True

        db = _RunTaskDb(task)
        original_factory = task_manager_module.get_session_factory
        original_execute_task = self.manager._execute_task

        async def fake_execute_task(task_id: str):
            task.dispatch_started_at = original_token + timedelta(seconds=1)
            raise RuntimeError("stale worker boom")

        task_manager_module.get_session_factory = lambda: (lambda: db)
        self.manager._execute_task = fake_execute_task
        try:
            asyncio.run(self.manager._run_task("task1"))
        finally:
            task_manager_module.get_session_factory = original_factory
            self.manager._execute_task = original_execute_task

        self.assertEqual("running", task.status)
        self.assertIsNone(task.last_error)
        self.assertTrue(db.closed)

    def test_execute_task_failed_stage_does_not_requeue_same_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                current_stage="binary_to_source",
                task_type=TASK_TYPE_BINARY,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(Path(tmp) / "output"),
                workspace_root=tmp,
                dispatcher_instance_id=self.manager.instance_id,
            )
            task.summary = {"selected_modules": [{"module_key": "m1", "module_name": "m1"}]}
            stage_run = BinarySecurityStageRun(
                id="sr1",
                task_id="task1",
                project_id="p1",
                stage_name="binary_to_source",
                sequence_no=3,
                status="queued",
            )
            prev_runs = [
                BinarySecurityStageRun(
                    id="sr-fw",
                    task_id="task1",
                    project_id="p1",
                    stage_name="firmware_unpack",
                    sequence_no=1,
                    status="success",
                ),
                BinarySecurityStageRun(
                    id="sr-sa",
                    task_id="task1",
                    project_id="p1",
                    stage_name="system_analysis",
                    sequence_no=2,
                    status="success",
                ),
            ]

            class _ExecuteTaskDb(_ModelAwareDb):
                def __init__(self, current_task, current_stage_run):
                    super().__init__(tasks=[current_task], stage_runs=[*prev_runs, current_stage_run])
                    self.closed = False

                def refresh(self, obj):
                    del obj

                def close(self):
                    self.closed = True

            db = _ExecuteTaskDb(task, stage_run)
            original_factory = task_manager_module.get_session_factory
            original_handler = self.manager._stage_binary_to_source
            original_counts = self.manager._stage_counts
            original_persist = self.manager._persist_stage_run_output_summary_async
            original_write_meta = self.manager._write_task_metadata_async

            async def fake_stage_handler(db_arg, task_arg, stage_run_arg, token, retry_existing):
                del db_arg, task_arg, stage_run_arg, token, retry_existing
                return "failed", {"error": "无法连接下游服务: [Errno -2] Name or service not known"}

            async def fake_persist(task_arg, stage_run_arg, payload):
                del task_arg, stage_run_arg
                return payload

            async def fake_write_meta(task_arg, path, status=None):
                del task_arg, path, status

            task_manager_module.get_session_factory = lambda: (lambda: db)
            self.manager._stage_binary_to_source = fake_stage_handler
            self.manager._stage_counts = lambda db_arg, stage_run_arg: {}
            self.manager._persist_stage_run_output_summary_async = fake_persist
            self.manager._write_task_metadata_async = fake_write_meta
            try:
                asyncio.run(self.manager._execute_task("task1"))
            finally:
                task_manager_module.get_session_factory = original_factory
                self.manager._stage_binary_to_source = original_handler
                self.manager._stage_counts = original_counts
                self.manager._persist_stage_run_output_summary_async = original_persist
                self.manager._write_task_metadata_async = original_write_meta

            event_types = [event.event_type for event in db.added if isinstance(event, BinarySecurityEvent)]
            self.assertEqual("partial_success", task.status)
            self.assertIn("stage_failed", event_types)
            self.assertNotIn("task_requeued_after_stage_completion", event_types)
            self.assertTrue(db.closed)

    def test_run_stage_pool_retries_existing_path_after_first_failure(self):
        calls: list[bool] = []

        async def runner(item, retrying=False):
            del item
            calls.append(bool(retrying))
            if len(calls) < 3:
                return {"status": "failed"}
            return {"status": "success"}

        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
        )

        original_is_cancelled = self.manager._is_task_cancelled
        self.manager._is_task_cancelled = lambda task_id: False
        results = asyncio.run(self.manager._run_stage_pool(task, [{"id": 1}], 1, runner, retries=2))
        self.manager._is_task_cancelled = original_is_cancelled

        self.assertEqual("success", results[0]["status"])
        self.assertEqual([False, True, True], calls)

    def test_run_stage_pool_stops_when_execution_token_is_invalidated(self):
        async def runner(item, retrying=False):
            del item, retrying
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            return {"status": "success"}

        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/w",
            dispatcher_instance_id=self.manager.instance_id,
            dispatch_started_at=_now(),
        )
        self.manager._bind_execution_token(task)
        db = _ModelAwareDb(tasks=[task])
        original_factory = task_manager_module.get_session_factory
        original_is_cancelled = self.manager._is_task_cancelled
        task_manager_module.get_session_factory = lambda: (lambda: db)
        self.manager._is_task_cancelled = lambda task_id: False
        try:
            with self.assertRaises(task_manager_module.StaleTaskExecution):
                asyncio.run(self.manager._run_stage_pool(task, [{"id": 1}], 1, runner))
        finally:
            task_manager_module.get_session_factory = original_factory
            self.manager._is_task_cancelled = original_is_cancelled

    def test_run_stage_pool_respects_concurrency_limit_for_retry_mode(self):
        active = 0
        max_active = 0

        async def runner(item, retrying=False):
            nonlocal active, max_active
            self.assertTrue(retrying)
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            return {"status": "success", "item": item}

        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="n",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )

        original_is_cancelled = self.manager._is_task_cancelled
        self.manager._is_task_cancelled = lambda task_id: False
        try:
            results = asyncio.run(
                self.manager._run_stage_pool(
                    task,
                    [{"id": idx} for idx in range(6)],
                    2,
                    runner,
                    initial_retry=True,
                )
            )
        finally:
            self.manager._is_task_cancelled = original_is_cancelled

        self.assertEqual(6, len(results))
        self.assertEqual(2, max_active)

    def test_run_system_analysis_item_reuses_existing_active_downstream_task(self):
        task = BinarySecurityTask(
            id="task1",
            project_id="p1",
            name="source",
            status="running",
            task_type=TASK_TYPE_SOURCE,
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/w",
        )
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="task1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=1,
            status="running",
        )
        existing_item = BinarySecurityStageItem(
            id="i1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr0",
            stage_name="system_analysis",
            item_key="source_project",
            item_name="source-project",
            parent_key="source_project",
            downstream_service="system_analyse",
            downstream_task_id="sat_existing",
            status="running",
        )

        class _SessionDb(_ModelAwareDb):
            def __init__(self):
                super().__init__(tasks=[task], stage_runs=[stage_run], stage_items=[existing_item])
                self.commits = 0
                self.closed = False

            def commit(self):
                self.commits += 1

            def close(self):
                self.closed = True

        db = _SessionDb()
        firmware = {
            "firmware_key": "source_project",
            "firmware_name": "source",
            "filename": "source-project",
            "unpacked_root": "/w/input",
            "source_root": "/w/input",
            "task_type": TASK_TYPE_SOURCE,
        }

        class _FakeSystemAnalyseClient:
            def __init__(self):
                self.create_calls = 0
                self.get_calls = 0

            async def create_task(self, *args, **kwargs):
                self.create_calls += 1
                return {"task_id": "sat_new"}

            async def get_task(self, task_id):
                self.get_calls += 1
                if self.get_calls == 1:
                    return {"task_id": task_id, "status": "running"}
                return {"task_id": task_id, "status": "success"}

            async def get_task_result(self, task_id):
                return {"task_id": task_id}

        fake_client = _FakeSystemAnalyseClient()
        original_factory = task_manager_module.get_session_factory
        original_client = task_manager_module.get_system_analyse_client
        original_queue_archive = self.manager._queue_archive_and_wait
        original_parse_modules = self.manager._parse_system_analysis_modules
        original_is_cancelled = self.manager._is_task_cancelled
        task_manager_module.get_session_factory = lambda: (lambda: db)
        task_manager_module.get_system_analyse_client = lambda: fake_client
        self.manager._is_task_cancelled = lambda task_id: False

        async def fake_queue_archive_and_wait(session, task_arg, item_arg, payload, mapped_status, before_status):
            del session, task_arg, item_arg, payload, mapped_status, before_status
            return Path("/tmp/archive"), SimpleNamespace(error_message=None)

        self.manager._queue_archive_and_wait = fake_queue_archive_and_wait
        self.manager._parse_system_analysis_modules = lambda archive_root, firmware_arg, result_payload=None: []

        try:
            result = asyncio.run(self.manager._run_system_analysis_item(task, stage_run, firmware, retrying=False))
        finally:
            task_manager_module.get_session_factory = original_factory
            task_manager_module.get_system_analyse_client = original_client
            self.manager._queue_archive_and_wait = original_queue_archive
            self.manager._parse_system_analysis_modules = original_parse_modules
            self.manager._is_task_cancelled = original_is_cancelled

        self.assertEqual(0, fake_client.create_calls)
        self.assertEqual("sat_existing", existing_item.downstream_task_id)
        self.assertEqual("success", result["status"])

    def test_stage_item_supports_identity_key_field(self):
        item = BinarySecurityStageItem(
            id="i1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="module1",
            item_identity_key="module1::root",
            status="pending",
        )

        self.assertEqual("module1::root", item.item_identity_key)

    def test_run_with_limits_respects_concurrency(self):
        active = 0
        max_active = 0

        async def worker(value):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            return value * 2

        results = asyncio.run(
            self.manager._run_with_limits(
                [1, 2, 3, 4],
                worker,
                concurrency=2,
                timeout_seconds=1,
            )
        )

        self.assertEqual(2, max_active)
        self.assertEqual([(1, 2, None), (2, 4, None), (3, 6, None), (4, 8, None)], results)

    def test_run_with_limits_captures_timeout(self):
        async def worker(value):
            await asyncio.sleep(0.05)
            return value

        results = asyncio.run(
            self.manager._run_with_limits(
                [1],
                worker,
                concurrency=1,
                timeout_seconds=0.01,
            )
        )

        self.assertEqual(1, len(results))
        row, payload, exc = results[0]
        self.assertEqual(1, row)
        self.assertIsNone(payload)
        self.assertIsInstance(exc, TimeoutError)

    def test_list_artifact_page_returns_paged_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(5):
                path = root / f"dir-{index}" / f"file-{index}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"payload-{index}", encoding="utf-8")

            page = self.manager._list_artifact_page(root, limit=2, offset=1)

        self.assertEqual(5, page["total"])
        self.assertEqual(2, page["limit"])
        self.assertEqual(1, page["offset"])
        self.assertTrue(page["has_more"])
        self.assertEqual(
            ["dir-1/file-1.txt", "dir-2/file-2.txt"],
            [entry["path"] for entry in page["files"]],
        )

    def test_safe_extract_archive_rejects_excessive_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = TaskManager()
            manager.cfg.storage.max_source_extract_files = 1
            archive_path = Path(tmp) / "source.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("a.txt", "a")
                archive.writestr("b.txt", "b")
            with self.assertRaises(ValidationError):
                manager._safe_extract_archive(archive_path, Path(tmp) / "out")

    def test_validate_uploaded_archive_size_rejects_oversized_source_archive(self):
        manager = TaskManager()
        manager.cfg.storage.max_upload_file_bytes = 10
        manager.cfg.storage.max_source_archive_bytes = 8
        with self.assertRaises(ValidationError):
            manager._validate_uploaded_archive_size("archive.zip", 11, source_task=True)

    def test_service_config_includes_lease_timeout_default(self):
        payload = BinarySecurityServiceConfigPayload()
        self.assertEqual(90, payload.lease_timeout_seconds)

    def test_project_config_includes_partial_success_stage_advancement_defaults(self):
        payload = BinarySecurityProjectConfigPayload()
        self.assertEqual(
            {
                "binary_to_source": True,
                "entry_analysis": True,
                "dataflow_analysis": True,
            },
            payload.partial_success_stage_advancement,
        )

    def test_merge_policy_merges_partial_success_stage_advancement(self):
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": False,
            }
        }
        policy = self.manager._merge_policy(
            _FakeDb(rows=[row]),
            "p1",
            {
                "task_type": TASK_TYPE_BINARY,
                "partial_success_stage_advancement": {
                    "entry_analysis": False,
                },
            },
            {},
        )

        self.assertEqual(
            {
                "binary_to_source": False,
                "entry_analysis": False,
                "dataflow_analysis": False,
            },
            policy["partial_success_stage_advancement"],
        )

    def test_merge_policy_prunes_binary_to_source_partial_success_advancement_for_source_tasks(self):
        row = BinarySecurityProjectConfig(project_id="p1")
        row.config = {
            "partial_success_stage_advancement": {
                "binary_to_source": False,
                "entry_analysis": True,
                "dataflow_analysis": False,
            }
        }
        policy = self.manager._merge_policy(
            _FakeDb(rows=[row]),
            "p1",
            {
                "task_type": TASK_TYPE_SOURCE,
            },
            {},
        )

        self.assertEqual(
            {
                "entry_analysis": True,
                "dataflow_analysis": False,
            },
            policy["partial_success_stage_advancement"],
        )

    def test_claim_pending_tasks_reclaims_expired_lease(self):
        task = BinarySecurityTask(
            id="t1",
            project_id="p1",
            name="n",
            status="pending",
            task_type=TASK_TYPE_BINARY,
            firmware_source="project_filesystem",
            firmware_path="/fw",
            output_root="/o",
            workspace_root="/tmp/ws",
        )
        task.dispatcher_instance_id = "other-worker"
        task.dispatch_started_at = _now() - timedelta(minutes=10)
        task.lease_expires_at = _now() - timedelta(seconds=1)

        class _ClaimPendingDb(_ModelAwareDb):
            def query(self, model, *args, **kwargs):
                del args, kwargs
                model_name = getattr(model, "__name__", "")
                if model_name == "BinarySecurityTask":
                    return _FakeQuery([task])
                if getattr(model, "name", None) == "id":
                    return _FakeQuery([("t1",)])
                return _FakeQuery([])

        db = _ClaimPendingDb(tasks=[task])

        claimed = self.manager._claim_pending_tasks(db, 1)

        self.assertEqual(["t1"], claimed)
        self.assertEqual(self.manager.instance_id, task.dispatcher_instance_id)
        self.assertIsNotNone(task.lease_expires_at)


if __name__ == "__main__":
    unittest.main()
