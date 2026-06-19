import tempfile
import unittest
from unittest.mock import AsyncMock
from pathlib import Path

from app.exception import ValidationError
from app.model import BinarySecurityArchiveJob, BinarySecurityStageItem, BinarySecurityStageRun, BinarySecurityTask
from app.service.task.downstream import TaskDownstreamServiceMixin
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb


class TaskDownstreamServiceStructureTests(unittest.TestCase):
    def test_task_manager_downstream_methods_are_bound_to_downstream_mixin(self):
        self.assertIs(TaskManager._trigger_entry_items_from_b2s_result, TaskDownstreamServiceMixin._trigger_entry_items_from_b2s_result)
        self.assertIs(TaskManager._prepare_stage_items_for_execution, TaskDownstreamServiceMixin._prepare_stage_items_for_execution)
        self.assertIs(TaskManager._replace_active_child_binding, TaskDownstreamServiceMixin._replace_active_child_binding)
        self.assertIs(TaskManager._may_queue_archive_for_current_binding, TaskDownstreamServiceMixin._may_queue_archive_for_current_binding)


class TaskDownstreamServiceBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _task(self):
        task = BinarySecurityTask(
            id="task-1",
            project_id="project-1",
            name="demo",
            status="running",
            current_stage="binary_to_source",
            task_type="binary_module",
            workspace_root="/tmp/ws",
            output_root="/tmp/out",
            firmware_source="project_filesystem",
            firmware_path="/tmp/fw.bin",
        )
        task.policy_json = '{"pipeline_mode":"mixed_streaming"}'
        return task

    def test_trigger_entry_items_from_b2s_result_creates_pending_entry_item_in_streaming_mode(self):
        task = self._task()
        upstream = BinarySecurityStageItem(
            id="item-b2s",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            item_key="module-1",
            item_name="module-1",
            parent_key="fw-1",
            status="success",
            downstream_service="binary_to_source",
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[upstream])

        seeded = self.manager._trigger_entry_items_from_b2s_result(
            db,
            task,
            {
                "module_key": "module-1",
                "module_name": "module-1",
                "source_dir": "/tmp/src",
                "module_dir": "/tmp/src",
                "files_list_path": "/tmp/src/files.list",
                "source_root": "/tmp/src",
                "source_root_path": "/tmp/src",
            },
            upstream_item=upstream,
        )

        self.assertIsNotNone(seeded)
        self.assertEqual("entry_analysis", seeded.stage_name)
        self.assertEqual("pending", seeded.status)

    def test_prepare_stage_items_for_execution_rejects_empty_item_key(self):
        task = self._task()
        stage_run = BinarySecurityStageRun(
            id="sr-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=1,
            status="running",
        )
        db = _ModelAwareDb(tasks=[task])

        with self.assertRaisesRegex(Exception, "item_key 为空"):
            self.manager._prepare_stage_items_for_execution(
                db,
                task=task,
                stage_run=stage_run,
                inputs=[{"name": "bad"}],
                downstream_service="entry_analyse",
                identity=lambda row: ("", row["name"], None, row),
                output_ref=lambda _row: {},
            )

    def test_replace_active_child_binding_supersedes_old_archive_jobs(self):
        task = self._task()
        item = BinarySecurityStageItem(
            id="item-1",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="dataflow_vuln_scan",
            item_key="entry-1",
            item_name="entry-1",
            status="running",
            downstream_service="dataflow_vuln_scan",
            downstream_task_id="child-old",
        )
        job = BinarySecurityArchiveJob(
            id="job-1",
            task_id=task.id,
            project_id=task.project_id,
            item_id=item.id,
            stage_name=item.stage_name,
            archive_status="pending",
            job_dedupe_key="dedupe-1",
            payload={"bound_downstream_task_id": "child-old"},
        )
        db = _ModelAwareDb(tasks=[task], stage_items=[item], archive_jobs=[job])

        async def _run():
            return await self.manager._replace_active_child_binding(
                db,
                task,
                item,
                new_downstream_task_id="child-new",
                token=None,
                reason="test",
            )

        self.manager._downstream_cancel_refs = unittest.mock.AsyncMock(return_value=0)
        self.manager._delete_downstream_refs = unittest.mock.AsyncMock(return_value=None)
        result = __import__("asyncio").run(_run())

        self.assertEqual("child-old", result)
        self.assertEqual("child-new", item.downstream_task_id)
        self.assertEqual("superseded", job.archive_status)

    def test_may_queue_archive_for_current_binding_rejects_stale_payload(self):
        item = BinarySecurityStageItem(
            id="item-1",
            task_id="task-1",
            project_id="project-1",
            stage_name="entry_analysis",
            item_key="module-1",
            item_name="module-1",
            status="running",
            downstream_task_id="child-current",
        )

        allowed, reason = self.manager._may_queue_archive_for_current_binding(
            item,
            payload={"task_id": "child-stale"},
            mapped_status="success",
        )

        self.assertFalse(allowed)
        self.assertEqual("stale_child_payload", reason)

    def test_downstream_create_task_rejects_when_delete_operation_is_active(self):
        task = self._task()
        item = BinarySecurityStageItem(
            id="item-delete-guard",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="binary_to_source",
            item_key="module-1",
            item_name="module-1",
            status="pending",
            downstream_service="binary_to_source",
        )
        delete_operation = type(
            "DeleteOperation",
            (),
            {"id": "op-delete", "operation_type": "delete"},
        )()
        db = _ModelAwareDb(tasks=[task], stage_items=[item])
        self.manager._active_delete_operation = lambda _db, _task_id: delete_operation
        self.manager._downstream_tasks = lambda: type(
            "DownstreamTasksStub",
            (),
            {"create_child_task": AsyncMock(return_value={"task_id": "should-not-happen"})},
        )()

        async def _run():
            with self.assertRaisesRegex(ValidationError, "禁止创建新的下游子任务"):
                await self.manager._downstream_create_task(
                    db,
                    task,
                    item,
                    service="binary_to_source",
                    token=None,
                    payload={"module_dir": "/tmp/src"},
                )

        __import__("asyncio").run(_run())
        event_types = [event.event_type for event in db.events]
        self.assertIn("downstream_create_skipped_due_to_delete_operation", event_types)
