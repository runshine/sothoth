import asyncio
import unittest

from app.model import (
    PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
    BinarySecurityStageRun,
    BinarySecurityTask,
    TASK_RUNTIME_PHASE_OWNED_EXECUTION,
    TASK_TYPE_SOURCE,
)
from app.service.task_manager import TaskManager, _now


def _kg_task(*, summary=None) -> BinarySecurityTask:
    task = BinarySecurityTask(
        id="task-kg-entry-guard",
        project_id="project-1",
        name="kg-source-vuln",
        status="running",
        task_type=TASK_TYPE_SOURCE,
        current_stage="knowledge_graph_entry_fetch",
        firmware_source="project_filesystem",
        firmware_path="/tmp/source-project",
        output_root="/tmp/bs-kg-out",
        workspace_root="/tmp/bs-kg-ws",
        runtime_phase=TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        started_at=_now(),
    )
    task.summary = {
        "input_dir": "/workspace/input",
        "pipeline_profile": PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN,
        **dict(summary or {}),
    }
    task.policy = {"pipeline_profile": PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN}
    return task


class _MemoryDb:
    def __init__(self):
        self.events = []

    def add(self, obj):
        if obj.__class__.__name__ == "BinarySecurityEvent":
            self.events.append(obj)

    def flush(self):
        return None

    def commit(self):
        return None

    def refresh(self, _obj):
        return None

    def close(self):
        return None


class KgSourceVulnEntryFetchGuardTests(unittest.TestCase):
    def setUp(self):
        self.manager = TaskManager()

    def _stage_run(self) -> BinarySecurityStageRun:
        return BinarySecurityStageRun(
            id="sr-kg-entry",
            task_id="task-kg-entry-guard",
            project_id="project-1",
            stage_name="knowledge_graph_entry_fetch",
            status="running",
            counts={},
        )

    def test_entry_fetch_keeps_running_until_upstream_terminal_even_with_entries(self):
        task = _kg_task()
        db = _MemoryDb()
        stage_run = self._stage_run()

        async def _fake_fetch(_task):
            return (
                [
                    {
                        "entry_key": "entry-a",
                        "source_id": "src-a",
                        "function_id": "fn-a",
                        "function_name": "sink_a",
                        "source_file": "src/a.c",
                        "definition_file": "src/a.c",
                        "definition_line": 12,
                        "line_no": 12,
                        "source_root_path": "/workspace/input",
                        "module_input_path": "/workspace/input",
                        "source_file_exists": True,
                    }
                ],
                {
                    "graph_status": "building",
                    "identification_state": "running",
                    "attack_status": "running",
                    "analysis": {"total": 1, "identified": 1, "pending": 1, "confirmed": 0, "rejected": 0},
                    "raw_entry_count": 1,
                    "selected_entry_count": 1,
                    "filtered_out_count": 0,
                },
            )

        self.manager._fetch_knowledge_graph_entry_results = _fake_fetch
        status, summary = asyncio.run(
            self.manager._stage_knowledge_graph_entry_fetch(db, task, stage_run, token=None, retry_existing=False)
        )

        self.assertEqual("running", status)
        self.assertEqual("waiting_for_upstream_terminal", summary["status"])
        self.assertEqual(1, summary["entry_count"])
        self.assertEqual("success", task.summary["entry_results"][0]["completion_state"])
        self.assertFalse(task.summary["entry_results"][0]["completion_ready"])
        effective_entries = self.manager._effective_entry_inputs(task)
        self.assertEqual(1, len(effective_entries))
        self.assertEqual("entry-a", effective_entries[0]["entry_key"])

    def test_entry_fetch_succeeds_when_upstream_done_and_entries_present(self):
        task = _kg_task()
        db = _MemoryDb()
        stage_run = self._stage_run()

        async def _fake_fetch(_task):
            return (
                [
                    {
                        "entry_key": "entry-a",
                        "source_id": "src-a",
                        "function_id": "fn-a",
                        "function_name": "sink_a",
                        "source_file": "src/a.c",
                        "definition_file": "src/a.c",
                        "definition_line": 12,
                        "line_no": 12,
                        "source_root_path": "/workspace/input",
                        "module_input_path": "/workspace/input",
                        "source_file_exists": True,
                    }
                ],
                {
                    "graph_status": "success",
                    "identification_state": "done",
                    "attack_status": "done",
                    "analysis": {"total": 1, "identified": 1, "pending": 0, "confirmed": 0, "rejected": 0},
                    "raw_entry_count": 1,
                    "selected_entry_count": 1,
                    "filtered_out_count": 0,
                },
            )

        self.manager._fetch_knowledge_graph_entry_results = _fake_fetch
        status, summary = asyncio.run(
            self.manager._stage_knowledge_graph_entry_fetch(db, task, stage_run, token=None, retry_existing=False)
        )

        self.assertEqual("success", status)
        self.assertEqual(1, summary["entry_count"])
        self.assertTrue(task.summary["entry_results"][0]["completion_ready"])

    def test_entry_fetch_succeeds_when_upstream_failed_but_entries_present(self):
        task = _kg_task()
        db = _MemoryDb()
        stage_run = self._stage_run()

        async def _fake_fetch(_task):
            return (
                [
                    {
                        "entry_key": "entry-a",
                        "source_id": "src-a",
                        "function_id": "fn-a",
                        "function_name": "sink_a",
                        "source_file": "src/a.c",
                        "definition_file": "src/a.c",
                        "definition_line": 12,
                        "line_no": 12,
                        "source_root_path": "/workspace/input",
                        "module_input_path": "/workspace/input",
                        "source_file_exists": True,
                    }
                ],
                {
                    "graph_status": "failed",
                    "identification_state": "failed",
                    "attack_status": "failed",
                    "analysis": {"total": 1, "identified": 1, "pending": 0, "confirmed": 0, "rejected": 0},
                    "raw_entry_count": 1,
                    "selected_entry_count": 1,
                    "filtered_out_count": 0,
                },
            )

        self.manager._fetch_knowledge_graph_entry_results = _fake_fetch
        status, summary = asyncio.run(
            self.manager._stage_knowledge_graph_entry_fetch(db, task, stage_run, token=None, retry_existing=False)
        )

        self.assertEqual("success", status)
        self.assertEqual(1, summary["entry_count"])
        self.assertTrue(task.summary["entry_results"][0]["completion_ready"])
