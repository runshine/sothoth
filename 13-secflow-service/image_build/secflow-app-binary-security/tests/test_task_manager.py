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
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
)
from app.schemas import BinarySecurityArchiveJobResponse
from app.service.task_manager import TaskManager, _now


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
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


class _StageRun:
    def __init__(self, stage_name, status):
        self.stage_name = stage_name
        self.status = status


class TaskManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

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
                '{"entries":[{"file_name":"main.c","function_name":"handle_req","line_no":12}]}',
                encoding="utf-8",
            )

            rows = self.manager._parse_entries(root, {"module_key": "mod", "module_name": "mod", "source_dir": "/src"})

            self.assertEqual(1, len(rows))
            self.assertEqual("handle_req", rows[0]["function_name"])
            self.assertEqual("main.c", rows[0]["file_name"])

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

    def test_aggregate_stage_items_marks_partial_success(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        task.summary = {}
        db = _FakeDb()

        status, summary = self.manager._aggregate_stage_items(
            db,
            task,
            results=[
                {"status": "success", "item": {"id": "a"}},
                {"status": "failed", "item": {"id": "b"}, "error": "boom"},
            ],
            summary_key="b2s_results",
        )

        self.assertEqual("partial_success", status)
        self.assertEqual(1, summary["success_count"])
        self.assertEqual(1, summary["failed_count"])
        self.assertEqual([{"id": "a"}], task.summary["b2s_results"])
        self.assertEqual(1, db.commits)

    def test_finalize_task_prefers_partial_success_after_vuln_stage(self):
        task = BinarySecurityTask(id="t1", project_id="p1", name="n", status="running", task_type=TASK_TYPE_BINARY, firmware_source="project_filesystem", firmware_path="/fw", output_root="/o", workspace_root="/w")
        db = _FakeDb(rows=[_StageRun("binary_to_source", "failed"), _StageRun("vuln_scan", "partial_success")])

        self.manager._finalize_task(db, task)

        self.assertEqual("partial_success", task.status)
        self.assertIsNotNone(task.finished_at)
        self.assertTrue(any(isinstance(obj, BinarySecurityEvent) for obj in db.added))

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

        target_stage = self.manager.continue_task(db, project_id="p1", task_id="s1")

        self.assertEqual("entry_analysis", target_stage)
        self.assertEqual("pending", task.status)
        self.assertEqual("entry_analysis", task.current_stage)
        self.assertIsNone(task.finished_at)
        self.assertNotIn("entry_results", task.summary)
        self.assertNotIn("stale_stages", task.summary)
        self.assertEqual("pending", runs[1].status)
        self.assertEqual({}, runs[1].output_summary)

    def test_refresh_task_status_after_stage_retry_finalizes_without_advancing(self):
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

        self.assertEqual("partial_success", task.status)
        self.assertEqual("system_analysis", task.current_stage)
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

    def test_filter_candidate_modules_by_risk_levels(self):
        modules = [
            {"module_key": "h1", "risk_level": "高"},
            {"module_key": "m1", "risk_level": "中"},
            {"module_key": "l1", "risk_level": "低"},
        ]

        rows = self.manager._filter_candidate_modules(modules, ["高", "中"])

        self.assertEqual(["h1", "m1"], [row["module_key"] for row in rows])

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

    def test_run_stage_pool_ignores_concurrency_limit_for_retry_mode(self):
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
        self.assertEqual(6, max_active)


if __name__ == "__main__":
    unittest.main()
