import asyncio
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    TASK_TYPE_BINARY,
    TASK_TYPE_BINARY_MODULE,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager
from test_task_manager import _AppendingModelAwareDb, _FakeConnection, _FakeDb, _LockingDb, _ModelAwareDb


class TaskArchiveOutputPathTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def test_normalize_source_input_files_rejects_duplicate_relative_paths(self):
        with self.assertRaisesRegex(Exception, "重复路径"):
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

            with patch.object(self.manager, "_check_storage_free_space", return_value=None):
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
            item = type(
                "Item",
                (),
                {
                    "downstream_service": "system_analyse",
                    "stage_name": "system_analysis",
                    "downstream_task_id": "down1",
                    "item_key": "fw1",
                    "id": "si1",
                },
            )()
            db = _FakeDb()

            target = self.manager._archive_downstream_output(
                db,
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertEqual("archived", target.status)
            assert target.target_dir is not None
            self.assertTrue((target.target_dir / "result.json").is_file())
            self.assertFalse((target.target_dir / "output").exists())
            self.assertEqual("system-analyse", target.target_dir.parent.name)
            self.assertEqual("fw1__down1", target.target_dir.name)

    def test_archive_downstream_output_filters_b2s_runtime_temp_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "libipsec.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            (output_dir / "libipsec.h").write_text("#pragma once\n", encoding="utf-8")
            artifacts_dir = output_dir / "artifacts"
            artifacts_dir.mkdir(parents=True)
            (artifacts_dir / "index.json").write_text("{}", encoding="utf-8")
            legacy_dir = output_dir / ".re_work_libipsec"
            legacy_dir.mkdir(parents=True)
            (legacy_dir / "legacy.txt").write_text("legacy\n", encoding="utf-8")
            run_dir = output_dir / "run" / "runs" / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "trace.log").write_text("trace\n", encoding="utf-8")

            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY_MODULE,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type(
                "Item",
                (),
                {
                    "downstream_service": "binary_to_source",
                    "stage_name": "binary_to_source",
                    "downstream_task_id": "down1",
                    "item_key": "fw1",
                    "id": "si1",
                },
            )()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertEqual("archived", target.status)
            assert target.target_dir is not None
            self.assertTrue((target.target_dir / "libipsec.c").is_file())
            self.assertTrue((target.target_dir / "libipsec.h").is_file())
            self.assertTrue((target.target_dir / "artifacts" / "index.json").is_file())
            self.assertFalse((target.target_dir / ".re_work_libipsec").exists())
            self.assertFalse((target.target_dir / "run").exists())

    def test_archive_downstream_output_replaces_existing_archive_dir_for_b2s(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            output_dir = workspace / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "libipsec.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            artifacts_dir = output_dir / "artifacts"
            artifacts_dir.mkdir(parents=True)
            (artifacts_dir / "index.json").write_text("{}", encoding="utf-8")

            task_output_root = root / "task-output"
            stale_target = task_output_root / "binary-to-source" / "fw1__down1" / "1" / "output" / ".re_work_libipsec"
            stale_target.mkdir(parents=True)
            (stale_target / "legacy.txt").write_text("legacy\n", encoding="utf-8")

            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_BINARY_MODULE,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(task_output_root),
                workspace_root=str(root / "workspace-root"),
            )
            item = type(
                "Item",
                (),
                {
                    "downstream_service": "binary_to_source",
                    "stage_name": "binary_to_source",
                    "downstream_task_id": "down1",
                    "item_key": "fw1",
                    "id": "si1",
                },
            )()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertEqual("archived", target.status)
            assert target.target_dir is not None
            self.assertTrue((target.target_dir / "libipsec.c").is_file())
            self.assertTrue((target.target_dir / "artifacts" / "index.json").is_file())
            self.assertFalse((target.target_dir / ".re_work_libipsec").exists())

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

    def test_resolve_downstream_output_sources_reads_artifacts_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "service" / "down1" / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"artifacts": {"output_root": str(output_dir)}},
                downstream_task_id="down1",
            )

            self.assertEqual(output_dir, rows[0])

    def test_resolve_downstream_output_sources_prefers_task_scoped_output_over_service_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "service"
            other_output = service_root / "other-task" / "output"
            task_output = service_root / "down1" / "output"
            other_output.mkdir(parents=True)
            task_output.mkdir(parents=True)
            (other_output / "other.md").write_text("other", encoding="utf-8")
            (task_output / "report.md").write_text("ok", encoding="utf-8")

            rows = self.manager._resolve_downstream_output_sources(
                {"output_path": str(service_root)},
                downstream_task_id="down1",
            )

            self.assertEqual(task_output, rows[0])
            self.assertIn(service_root, rows)

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
            item = type(
                "Item",
                (),
                {
                    "downstream_service": "firmware_unpacker",
                    "stage_name": "firmware_unpack",
                    "downstream_task_id": "down1",
                    "item_key": "fw1",
                    "id": "si1",
                },
            )()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"output_path": str(workspace / "run" / "firmware-unpacker" / "fw1")},
            )

            self.assertEqual("archived", target.status)
            assert target.target_dir is not None
            self.assertTrue((target.target_dir / "summary.md").is_file())
            self.assertEqual("firmware-unpacker", target.target_dir.parent.name)

    def test_archive_downstream_output_does_not_copy_other_downstream_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "secflow-app-entry-analyse"
            current_output = service_root / "eat_current" / "output"
            other_output = service_root / "eat_other" / "output"
            current_output.mkdir(parents=True)
            other_output.mkdir(parents=True)
            (current_output / "entry-details.json").write_text("[]", encoding="utf-8")
            (other_output / "foreign.txt").write_text("x", encoding="utf-8")
            task = BinarySecurityTask(
                id="task1",
                project_id="p1",
                name="n",
                status="running",
                task_type=TASK_TYPE_SOURCE,
                firmware_source="project_filesystem",
                firmware_path="/fw",
                output_root=str(root / "task-output"),
                workspace_root=str(root / "workspace-root"),
            )
            item = type(
                "Item",
                (),
                {
                    "downstream_service": "entry_analyse",
                    "stage_name": "entry_analysis",
                    "downstream_task_id": "eat_current",
                    "item_key": "source_project-image",
                    "id": "si1",
                },
            )()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="source_project-image",
                payload={"output_path": str(service_root)},
            )

            self.assertEqual("archived", target.status)
            assert target.target_dir is not None
            self.assertTrue((target.target_dir / "entry-details.json").is_file())
            self.assertFalse((target.target_dir / "eat_other").exists())
            self.assertFalse((target.target_dir / "foreign.txt").exists())

    def test_archive_downstream_output_uses_bound_downstream_task_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_root = root / "secflow-app-firmware-unpacker"
            bound_output = service_root / "child_old" / "output"
            current_output = service_root / "child_new" / "output"
            bound_output.mkdir(parents=True)
            current_output.mkdir(parents=True)
            (bound_output / "summary.md").write_text("old", encoding="utf-8")
            (current_output / "summary.md").write_text("new", encoding="utf-8")
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
            item = type(
                "Item",
                (),
                {
                    "downstream_service": "firmware_unpacker",
                    "stage_name": "firmware_unpack",
                    "downstream_task_id": "child_new",
                    "item_key": "fw1",
                    "id": "si1",
                    "output_ref": {},
                },
            )()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                bound_downstream_task_id="child_old",
                payload={"output_path": str(service_root)},
            )

            self.assertEqual("archived", target.status)
            assert target.target_dir is not None
            self.assertEqual("old", (target.target_dir / "summary.md").read_text(encoding="utf-8"))

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
            item = type(
                "Item",
                (),
                {
                    "downstream_service": "system_analyse",
                    "stage_name": "system_analysis",
                    "downstream_task_id": "down1",
                    "item_key": "fw1",
                    "id": "si1",
                },
            )()

            target = self.manager._archive_downstream_output(
                _FakeDb(),
                task,
                item,
                semantic_key="fw1",
                payload={"workspace_root": str(workspace)},
            )

            self.assertEqual("source_not_ready", target.status)
            self.assertIsNone(target.target_dir)
            self.assertGreaterEqual(len(target.source_candidates), 1)
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
        item = type(
            "Item",
            (),
            {
                "id": "si1",
                "stage_name": "system_analysis",
                "item_key": "source_project",
                "downstream_service": "system_analyse",
                "downstream_task_id": "sat1",
            },
        )()
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
        self.assertNotIn("workspace_root", downstream_payload)
        self.assertEqual("/tmp/system-analysis/sat1/output", downstream_payload["result"]["output_root"])
        self.assertNotIn("modules", downstream_payload)
        self.assertNotIn("modules", downstream_payload["result"])
        self.assertLess(len(job.payload_json or ""), 2048)

    def test_archive_job_payload_does_not_persist_bound_output_path(self):
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
        item = type(
            "Item",
            (),
            {
                "id": "si1",
                "stage_name": "entry_analysis",
                "item_key": "source_project-images",
                "downstream_service": "entry_analyse",
                "downstream_task_id": "eat_1",
            },
        )()
        db = _ModelAwareDb()

        long_output_path = "/data/files/" + "/".join(f"segment-{idx:04d}" for idx in range(2048))
        job = self.manager._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload={
                "task_id": "eat_1",
                "status": "success",
                "workspace_root": "/tmp/entry/eat_1",
                "output_path": long_output_path,
            },
            mapped_status="success",
            before_status="running",
        )

        payload = job.payload
        self.assertNotIn("bound_output_path", payload)
        self.assertEqual("eat_1", payload["bound_downstream_task_id"])
        self.assertNotIn("output_path", payload["downstream_payload"])
        self.assertLess(len(job.payload_json or ""), len(long_output_path))

    def test_suppress_later_stage_items_after_archive_blocked_marks_future_items_skipped(self):
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
        stage_run = BinarySecurityStageRun(
            id="sr1",
            task_id="task1",
            project_id="p1",
            stage_name="system_analysis",
            sequence_no=2,
            status="running",
        )
        running_item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="system_analysis",
            item_key="fw1",
            item_name="fw1",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id="sat1",
        )
        queued_item = BinarySecurityStageItem(
            id="si2",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="mod1",
            item_name="mod1",
            parent_key="fw1",
            status="queued",
            downstream_service="entry_analyse",
            downstream_task_id="eat1",
        )
        db = _AppendingModelAwareDb(tasks=[task], stage_runs=[stage_run], stage_items=[running_item, queued_item], events=[])

        blocked = self.manager._suppress_later_stage_items_after_archive_blocked(
            db,
            task,
            stage_name="firmware_unpack",
            error_message="总任务产物归档失败",
            archive_job_id="aj1",
            downstream_task_id="child1",
        )

        self.assertEqual({"si1", "si2"}, set(blocked))
        self.assertEqual("skipped", running_item.status)
        self.assertEqual("skipped", queued_item.status)
        self.assertEqual("总任务产物归档失败", running_item.error_message)
        self.assertTrue(self.manager._load_stage_item_result_payload(running_item).get("blocked_by_upstream_archive_failure"))
        self.assertTrue(any(event.event_type == "downstream_stage_item_blocked_after_archive_failure" for event in db.events))

    def test_ensure_downstream_archive_job_keeps_success_job_when_downstream_payload_changes(self):
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
        item = BinarySecurityStageItem(
            id="si1",
            task_id="task1",
            project_id="p1",
            stage_run_id="sr1",
            stage_name="entry_analysis",
            item_key="source_project-images",
            item_name="images",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
            status="failed",
        )
        job = BinarySecurityArchiveJob(
            id="aj1",
            task_id="task1",
            project_id="p1",
            stage_name="entry_analysis",
            item_id="si1",
            item_key="source_project-images",
            downstream_service="entry_analyse",
            downstream_task_id="eat_1",
            job_dedupe_key="si1::eat_1",
            archive_status="success",
            archive_root="/old/archive",
        )
        job.payload = {
            "mapped_status": "failed",
            "before_status": "running",
            "force": False,
            "downstream_payload": {
                "task_id": "eat_1",
                "status": "failed",
                "updated_at": "2026-05-15T20:05:39+08:00",
                "error": "old failed",
            },
            "extra_paths": [],
            "archive_copy_stats": {"copied_files": 10},
        }
        db = _LockingDb(_FakeConnection(lock_result=True))
        db.tasks.append(task)
        db.stage_items.append(item)
        db.archive_jobs.append(job)

        refreshed = self.manager._ensure_downstream_archive_job(
            db,
            task,
            item,
            payload={
                "task_id": "eat_1",
                "status": "passed",
                "updated_at": "2026-05-15T21:18:53+08:00",
                "finished_at": "2026-05-15T21:18:53+08:00",
                "output_path": "/data/files/p1/app/secflow-app-entry-analyse",
            },
            mapped_status="success",
            before_status="failed",
        )

        self.assertIs(job, refreshed)
        self.assertEqual("success", refreshed.archive_status)
        self.assertEqual("/old/archive", refreshed.archive_root)
        self.assertEqual("failed", refreshed.payload["mapped_status"])
        self.assertEqual("failed", refreshed.payload["downstream_payload"]["status"])
        self.assertIn("archive_copy_stats", refreshed.payload)
