from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from app.api import tasks as task_api
from app.model import B2STask, B2STaskItem
from app.schemas import AdvancedFile, AdvancedRun, TaskItemAdvancedResponse, TokenUser
from app.service import task_service


def _token() -> TokenUser:
    return TokenUser(user_id="1", username="tester", role=["admin"], platform_role="super_admin")


def _task(task_id: str = "task-1") -> B2STask:
    return B2STask(id=task_id, project_id="project-1", name="demo", status="running")


def _item(sequence_no: int, status: str = "running", phase: str = "body") -> B2STaskItem:
    return B2STaskItem(
        id=f"item-{sequence_no}",
        task_id="task-1",
        project_id="project-1",
        sequence_no=sequence_no,
        elf_path=f"/tmp/demo-{sequence_no}.elf",
        output_dir=f"/tmp/out-{sequence_no}",
        status=status,
        phase=phase,
    )


def _advanced(item: B2STaskItem, sessions: list[AdvancedFile]) -> TaskItemAdvancedResponse:
    return TaskItemAdvancedResponse(
        task_id=item.task_id,
        item_id=item.id,
        sequence_no=item.sequence_no,
        output_dir=item.output_dir,
        runs=[AdvancedRun(name="run-1", path=f"{item.output_dir}/run-1", agent_sessions=sessions)],
        ida_files=[],
    )


class AgentSessionRuntimeTests(unittest.TestCase):
    def test_dispatched_virtual_session_when_job_exists_but_no_file(self) -> None:
        item = _item(1, status="queued", phase="body")
        item.pi_job_id = "job-1"
        item.progress = {"current_batch": 1, "current_attempt": 1}
        item.extra_metadata = {"pi_worker_url": "http://pi-1"}

        with mock.patch.object(task_service, "build_task_item_advanced", return_value=_advanced(item, [])):
            payload = task_service.build_task_agent_session_runtime([item])

        self.assertEqual(1, payload.summary.total_sessions)
        self.assertEqual("dispatched", payload.sessions[0].status)
        self.assertFalse(payload.sessions[0].file_ref.can_open)

    def test_streaming_session_matches_current_batch_and_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            item = _item(1, status="running", phase="body")
            item.output_dir = tmpdir
            item.pi_job_id = "job-1"
            item.progress = {"current_batch": 2, "current_attempt": 1, "current_function": "sub_401000"}
            item.extra_metadata = {"pi_worker_url": "http://pi-1"}
            item.updated_at = datetime.now().astimezone()
            session_path = Path(tmpdir) / "run" / "sessions" / "executor_batch_2_attempt_1.jsonl"
            session_path.parent.mkdir(parents=True)
            session_path.write_text("{}\n", encoding="utf-8")
            advanced = _advanced(item, [
                AdvancedFile(
                    name=session_path.name,
                    path=str(session_path),
                    kind="agent_session",
                    size=session_path.stat().st_size,
                    stage="函数体恢复",
                    agent="executor agent",
                    role="executor",
                    batch_no=2,
                    attempt_no=1,
                )
            ])

            with mock.patch.object(task_service, "build_task_item_advanced", return_value=advanced):
                payload = task_service.build_task_agent_session_runtime([item])

        self.assertEqual("streaming", payload.sessions[0].status)
        self.assertTrue(payload.sessions[0].is_current)
        self.assertTrue(payload.sessions[0].file_ref.can_open)
        self.assertIn("/sessions/file?", payload.sessions[0].file_ref.read_api or "")

    def test_validator_current_session_is_waiting_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            item = _item(1, status="running", phase="merge")
            item.output_dir = tmpdir
            item.pi_job_id = "job-2"
            item.progress = {"current_batch": 3, "current_attempt": 2}
            item.updated_at = datetime.now().astimezone()
            session_path = Path(tmpdir) / "validator_batch_3_attempt_2.jsonl"
            session_path.write_text("{}\n", encoding="utf-8")
            advanced = _advanced(item, [
                AdvancedFile(
                    name=session_path.name,
                    path=str(session_path),
                    kind="agent_session",
                    size=session_path.stat().st_size,
                    stage="结果评审",
                    agent="validator agent",
                    role="validator",
                    batch_no=3,
                    attempt_no=2,
                )
            ])

            with mock.patch.object(task_service, "build_task_item_advanced", return_value=advanced):
                payload = task_service.build_task_agent_session_runtime([item])

        self.assertEqual("waiting_review", payload.sessions[0].status)

    def test_executor_previous_attempt_waits_for_next_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            item = _item(1, status="running", phase="body")
            item.output_dir = tmpdir
            item.pi_job_id = "job-3"
            item.progress = {"current_batch": 1, "current_attempt": 3}
            item.updated_at = datetime.now().astimezone()
            session_path = Path(tmpdir) / "executor_batch_1_attempt_2.jsonl"
            session_path.write_text("{}\n", encoding="utf-8")
            advanced = _advanced(item, [
                AdvancedFile(
                    name=session_path.name,
                    path=str(session_path),
                    kind="agent_session",
                    size=session_path.stat().st_size,
                    stage="函数体恢复",
                    agent="executor agent",
                    role="executor",
                    batch_no=1,
                    attempt_no=2,
                )
            ])

            with mock.patch.object(task_service, "build_task_item_advanced", return_value=advanced):
                payload = task_service.build_task_agent_session_runtime([item])

        self.assertEqual("waiting_execution", payload.sessions[0].status)

    def test_stale_and_orphan_sessions_are_classified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            item = _item(1, status="running", phase="body")
            item.output_dir = tmpdir
            item.pi_job_id = "job-4"
            item.progress = {"current_batch": 5, "current_attempt": 2}
            item.updated_at = datetime.now().astimezone() - timedelta(minutes=30)
            session_path = Path(tmpdir) / "executor_batch_1_attempt_1.jsonl"
            session_path.write_text("{}\n", encoding="utf-8")
            stale_ts = (datetime.now() - timedelta(minutes=30)).timestamp()
            os.utime(session_path, (stale_ts, stale_ts))
            advanced = _advanced(item, [
                AdvancedFile(
                    name=session_path.name,
                    path=str(session_path),
                    kind="agent_session",
                    size=session_path.stat().st_size,
                    stage="函数体恢复",
                    agent="executor agent",
                    role="executor",
                    batch_no=1,
                    attempt_no=1,
                )
            ])

            with mock.patch.object(task_service, "build_task_item_advanced", return_value=advanced):
                payload = task_service.build_task_agent_session_runtime([item])

        self.assertEqual("stale", payload.sessions[0].status)
        self.assertTrue(payload.sessions[0].is_stale)

    def test_terminal_item_marks_session_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            item = _item(1, status="failed", phase="body")
            item.output_dir = tmpdir
            item.pi_job_id = "job-5"
            item.progress = {"current_batch": 1, "current_attempt": 1}
            session_path = Path(tmpdir) / "executor.jsonl"
            session_path.write_text("{}\n", encoding="utf-8")
            advanced = _advanced(item, [
                AdvancedFile(
                    name=session_path.name,
                    path=str(session_path),
                    kind="agent_session",
                    size=session_path.stat().st_size,
                    stage="函数体恢复",
                    agent="executor agent",
                    role="executor",
                    batch_no=1,
                    attempt_no=1,
                )
            ])

            with mock.patch.object(task_service, "build_task_item_advanced", return_value=advanced):
                payload = task_service.build_task_agent_session_runtime([item])

        self.assertEqual("failed", payload.sessions[0].status)


class AgentSessionRuntimeApiTests(unittest.TestCase):
    def test_runtime_api_uses_sync_and_returns_payload(self) -> None:
        task = _task()
        item = _item(1, status="queued")
        response = task_service.build_task_agent_session_runtime([item])

        async def _run():
            with (
                mock.patch.object(task_api, "get_task_or_404", return_value=task),
                mock.patch.object(task_api, "query_items", return_value=[item]),
                mock.patch.object(task_api, "build_task_agent_session_runtime", return_value=response),
            ):
                return await task_api.get_b2s_task_agent_sessions_runtime("project-1", "task-1", _token(), mock.Mock())

        payload = asyncio.run(_run())
        self.assertEqual("task-1", payload.task_id)
        self.assertEqual(response.summary.total_sessions, payload.summary.total_sessions)


if __name__ == "__main__":
    unittest.main()
