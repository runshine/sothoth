import asyncio
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.model import (
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    BinarySecurityTaskRuntimeLease,
    TASK_TYPE_SOURCE,
)
from app.service import task_manager as task_manager_module
from app.service.task_manager import TaskManager
from test_task_manager import _ModelAwareDb, _now


class EntryAnalysisRuntimeObserveTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _task(self):
        return BinarySecurityTask(
            id="task-entry-observe",
            project_id="project-1",
            name="entry-observe",
            task_type=TASK_TYPE_SOURCE,
            status="running",
            current_stage="entry_analysis",
            firmware_source="project_filesystem",
            firmware_path="/src",
            output_root="/o",
            workspace_root="/tmp/ws",
        )

    def test_run_entry_item_adopts_bound_terminal_child_instead_of_deferring(self):
        task = self._task()
        stage_run = BinarySecurityStageRun(
            id="sr-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_name="entry_analysis",
            sequence_no=1,
            status="running",
        )
        item = BinarySecurityStageItem(
            id="si-entry",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name=stage_run.stage_name,
            item_key="module-a",
            item_name="module-a",
            parent_key="fw-1",
            status="running",
            downstream_service="entry_analyse",
            downstream_task_id="eat-existing",
        )
        runtime_lease = BinarySecurityTaskRuntimeLease(
            task_id=task.id,
            owner_instance_id=self.manager.instance_id,
            lease_expires_at=_now() + timedelta(minutes=5),
        )
        fake_session = _ModelAwareDb(stage_items=[item], runtime_leases=[runtime_lease], events=[])
        module = {
            "module_key": "module-a",
            "module_name": "module-a",
            "firmware_key": "fw-1",
            "module_dir": "/tmp/module-a",
            "source_root": "/tmp/source",
            "source_root_path": "/tmp/source",
            "entry_files_list": "",
            "entry_descriptor_root": "",
            "files_list_path": "/tmp/module-a/files.list",
        }

        fetch_calls = []

        async def _fake_fetch(_task, _item, _token):
            fetch_calls.append(str(_item.downstream_task_id))
            return {
                "task_id": "eat-existing",
                "status": "passed",
                "parent_stage_item_id": "si-entry",
                "parent_stage_item_key": "module-a",
            }

        async def _fake_poll(fetcher, **kwargs):
            del kwargs
            payload = await fetcher()
            return "success", payload

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_root = Path(tmpdir)
            with (
                patch.object(task_manager_module, "get_session_factory", return_value=lambda: fake_session),
                patch.object(self.manager, "_upsert_stage_item", return_value=item),
                patch.object(self.manager, "_active_downstream_payload", new=AsyncMock(return_value=None)),
                patch.object(self.manager, "_downstream_fetch_item_payload", side_effect=_fake_fetch),
                patch.object(self.manager, "_poll_until_terminal", side_effect=_fake_poll) as poll_mock,
                patch.object(self.manager, "_downstream_create_task", new=AsyncMock(side_effect=AssertionError("should not create replacement child"))),
                patch.object(self.manager, "_queue_archive_and_wait", new=AsyncMock(return_value=(archive_root, None))),
                patch.object(self.manager, "_materialize_stage_artifact", return_value=str(archive_root)),
                patch.object(self.manager, "_parse_entries", return_value=[]),
                patch.object(self.manager, "_write_task_metadata_async", new=AsyncMock(return_value=None)),
            ):
                result = asyncio.run(self.manager._run_entry_item(task, stage_run, module, token="tok", retrying=False))

            self.assertGreaterEqual(len(fetch_calls), 2)
            poll_mock.assert_awaited_once()
            self.assertNotEqual("failed", result["status"])
            self.assertNotEqual("archive_blocked", result["status"])


if __name__ == "__main__":
    unittest.main()
