from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.result_review import (
    ResultReviewExecutor,
    ResultReviewFrameworkError,
)
from app.pi_vuln_core.review.state import ReviewState, calculate_file_sha256
from run_vuln_scan import generate_config


class DelayedPassRuntime(BaseAgentRuntime):
    def __init__(self, agent_config: dict):
        super().__init__(agent_config)
        self.active_calls = 0
        self.max_active_calls = 0
        self.call_session_ids: list[str] = []
        self.session_counter = 0

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        self.session_counter += 1
        session_id = f"delay_{self.session_counter}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()
        session = self._sessions.setdefault(session_id, {"turns": 0})
        session["turns"] += 1
        self.call_session_ids.append(session_id)
        self.active_calls += 1
        self.max_active_calls = max(self.max_active_calls, self.active_calls)
        try:
            await asyncio.sleep(0.2)
        finally:
            self.active_calls -= 1
        return AgentResponse(
            content='{"passed": true, "verdict": "CONFIRMED", "feedback": "验证通过", "scores": {"issue_truth": 0.9}, "confidence": 0.9}',
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )

    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        return await self.send_message(
            message=user_prompt,
            system_prompt=system_prompt,
            session_id=session_id,
            working_dir=working_dir,
        )

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def shutdown(self) -> None:
        self._sessions.clear()
        self._initialized = False


class CountingFailRuntime(BaseAgentRuntime):
    def __init__(self, agent_config: dict):
        super().__init__(agent_config)
        self.call_count = 0

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"fail_{len(self._sessions) + 1}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()
        session = self._sessions.setdefault(session_id, {"turns": 0})
        session["turns"] += 1
        self.call_count += 1
        return AgentResponse(
            content='{"passed": false, "verdict": "FALSE_POSITIVE", "feedback": "仍为失败报告", "scores": {"issue_truth": 0.1}, "confidence": 0.9}',
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )

    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
    ) -> AgentResponse:
        return await self.send_message(
            message=user_prompt,
            system_prompt=system_prompt,
            session_id=session_id,
            working_dir=working_dir,
        )

    async def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def shutdown(self) -> None:
        self._sessions.clear()
        self._initialized = False


class MutatingPassRuntime(DelayedPassRuntime):
    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if working_dir:
            target = Path(working_dir) / "results" / "result_001.md"
            target.write_text("# mutated by advisor\n", encoding="utf-8")
        if session_id is None:
            session_id = await self.create_session()
        session = self._sessions.setdefault(session_id, {"turns": 0})
        session["turns"] += 1
        self.call_session_ids.append(session_id)
        return AgentResponse(
            content='{"passed": true, "verdict": "CONFIRMED", "feedback": "验证通过", "scores": {"issue_truth": 0.9}, "confidence": 0.9}',
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


class RuntimeErrorRuntime(DelayedPassRuntime):
    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()
        session = self._sessions.setdefault(session_id, {"turns": 0})
        session["turns"] += 1
        self.call_session_ids.append(session_id)
        return AgentResponse(
            content="",
            error="runtime no-progress timeout after 1.0s",
            error_code="runtime_timeout",
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=False,
        )


class FlakyTimeoutThenPassResultRuntime(DelayedPassRuntime):
    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()
        session = self._sessions.setdefault(session_id, {"turns": 0})
        session["turns"] += 1
        self.call_session_ids.append(session_id)
        if len(self.call_session_ids) <= 2:
            return AgentResponse(
                content="",
                error="runtime no-progress timeout after 1.0s",
                error_code="runtime_timeout",
                conversation_id=session_id,
                turn_count=session["turns"],
                finished=False,
            )
        return AgentResponse(
            content='{"passed": true, "verdict": "CONFIRMED", "feedback": "retry recovered", "scores": {"issue_truth": 0.95}, "confidence": 0.9}',
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


@pytest.mark.asyncio
async def test_result_review_runs_reports_in_parallel_with_configured_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", DelayedPassRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    for idx in range(1, 6):
        (results_dir / f"result_{idx:03d}.md").write_text(
            f"# result {idx}\n\ncontent\n", encoding="utf-8"
        )

    advisor = AdvisorInstanceDef(
        instance_id="result_fp_check",
        agent_id="advisor-agent",
        role_name="误报检测",
        re_review_on_cycle=False,
        system_prompt_file=str(task_file),
        user_prompt_template=str(task_file),
    )

    executor = ResultReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()

    started = time.monotonic()
    all_passed, failed_items = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        parallel=True,
        concurrency_limit=2,
        advisor_sessions={},
    )
    elapsed = time.monotonic() - started

    runtime = registry.get("advisor-agent")
    assert all_passed is True
    assert failed_items == []
    assert runtime.max_active_calls == 2
    assert 0.4 <= elapsed < 0.8
    assert runtime._sessions == {}

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_isolates_sessions_per_result_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", DelayedPassRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": False,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    for idx in range(1, 3):
        (results_dir / f"result_{idx:03d}.md").write_text(
            f"# result {idx}\n\ncontent\n", encoding="utf-8"
        )

    advisor = AdvisorInstanceDef(
        instance_id="result_fp_check",
        agent_id="advisor-agent",
        role_name="误报检测",
        re_review_on_cycle=False,
        system_prompt_file=str(task_file),
        user_prompt_template=str(task_file),
    )

    executor = ResultReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()
    await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        parallel=False,
        concurrency_limit=3,
        advisor_sessions={},
    )

    runtime = registry.get("advisor-agent")
    assert len(runtime.call_session_ids) == 2
    assert len(set(runtime.call_session_ids)) == 2

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_treats_advisor_workspace_mutation_as_framework_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", MutatingPassRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# original\n", encoding="utf-8")

    advisor = AdvisorInstanceDef(
        instance_id="result_fp_check",
        agent_id="advisor-agent",
        role_name="误报检测",
        re_review_on_cycle=False,
        system_prompt_file=str(task_file),
        user_prompt_template=str(task_file),
    )

    executor = ResultReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()
    with pytest.raises(ResultReviewFrameworkError) as exc_info:
        await executor.execute(
            advisors_cfg=[advisor],
            task_file=str(task_file),
            results_dir=str(results_dir),
            work_dir=str(tmp_path),
            cycle=1,
            review_state=review_state,
            parallel=False,
            concurrency_limit=1,
            advisor_sessions={},
        )

    assert exc_info.value.result_file == "result_001.md"
    assert exc_info.value.error_code == "advisor_read_only_violation"
    assert "result_001.md" not in review_state.result_states
    review_record = (
        tmp_path
        / "reviews"
        / "results"
        / "result_001"
        / "cycle_001"
        / "result_fp_check.json"
    )
    payload = json.loads(review_record.read_text(encoding="utf-8"))
    assert payload["parser_mode"] == "read_only_violation"
    assert "modified: results/result_001.md" in payload["feedback_detail"]

    runtime = registry.get("advisor-agent")
    assert runtime._sessions == {}

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_runtime_error_does_not_mark_report_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", RuntimeErrorRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    advisor = AdvisorInstanceDef(
        instance_id="result_fp_check",
        agent_id="advisor-agent",
        role_name="误报检测",
        re_review_on_cycle=False,
        system_prompt_file=str(task_file),
        user_prompt_template=str(task_file),
    )

    executor = ResultReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()
    with pytest.raises(ResultReviewFrameworkError) as exc_info:
        await executor.execute(
            advisors_cfg=[advisor],
            task_file=str(task_file),
            results_dir=str(results_dir),
            work_dir=str(tmp_path),
            cycle=1,
            review_state=review_state,
            parallel=False,
            concurrency_limit=1,
            advisor_sessions={},
        )

    assert exc_info.value.result_file == "result_001.md"
    assert exc_info.value.advisor_id == "result_fp_check"
    assert exc_info.value.error_code == "runtime_timeout"
    assert review_state.result_states == {}

    review_record = (
        tmp_path
        / "reviews"
        / "results"
        / "result_001"
        / "cycle_001"
        / "result_fp_check.json"
    )
    payload = json.loads(review_record.read_text(encoding="utf-8"))
    assert payload["parser_mode"] == "agent_error"
    assert payload["verdict"] == "ERROR"
    assert "review_runtime_retries" not in payload["feedback_detail"]

    runtime = registry.get("advisor-agent")
    assert len(runtime.call_session_ids) == 1

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_runtime_timeout_does_not_retry_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", FlakyTimeoutThenPassResultRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    advisor = AdvisorInstanceDef(
        instance_id="result_fp_check",
        agent_id="advisor-agent",
        role_name="误报检测",
        re_review_on_cycle=False,
        system_prompt_file=str(task_file),
        user_prompt_template=str(task_file),
    )

    executor = ResultReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    review_state = ReviewState()
    with pytest.raises(ResultReviewFrameworkError):
        await executor.execute(
            advisors_cfg=[advisor],
            task_file=str(task_file),
            results_dir=str(results_dir),
            work_dir=str(tmp_path),
            cycle=1,
            review_state=review_state,
            parallel=False,
            concurrency_limit=1,
            advisor_sessions={},
        )

    runtime = registry.get("advisor-agent")
    assert runtime.call_session_ids == ["delay_1"]

    review_record = (
        tmp_path
        / "reviews"
        / "results"
        / "result_001"
        / "cycle_001"
        / "result_fp_check.json"
    )
    payload = json.loads(review_record.read_text(encoding="utf-8"))
    assert payload["passed"] is False
    assert payload["parser_mode"] == "agent_error"

    await registry.shutdown_all()


def test_run_vuln_scan_generate_config_enables_parallel_result_review(tmp_path: Path) -> None:
    config = generate_config(
        run_dir=str(tmp_path),
        task_file=str(tmp_path / "task.md"),
        run_name="demo",
    )
    assert config["global"]["parallel_result_review"] is True
    assert config["global"]["parallel_result_review_limit"] == 3
    advisor_runtime = config["agents"][1]["runtime_config"]
    assert advisor_runtime["advisor_runtime_retries"] == 0


def test_run_vuln_scan_generate_config_accepts_custom_result_review_concurrency(tmp_path: Path) -> None:
    config = generate_config(
        run_dir=str(tmp_path),
        task_file=str(tmp_path / "task.md"),
        run_name="demo",
        result_review_concurrency=5,
    )
    assert config["global"]["parallel_result_review_limit"] == 5


@pytest.mark.asyncio
async def test_result_review_skips_unchanged_failed_report_without_resubmitting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", CountingFailRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    result_path = results_dir / "result_001.md"
    result_path.write_text("# unchanged failed result\n", encoding="utf-8")

    advisor = AdvisorInstanceDef(
        instance_id="result_fp_check",
        agent_id="advisor-agent",
        role_name="误报检测",
        re_review_on_cycle=False,
        system_prompt_file=str(task_file),
        user_prompt_template=str(task_file),
    )

    review_state = ReviewState()
    fingerprint = calculate_file_sha256(str(result_path))
    review_state.mark_result_failed(
        "result_001.md",
        cycle=1,
        reason="上一轮已判定失败",
        file_fingerprint=fingerprint,
    )

    executor = ResultReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    all_passed, failed_items = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=2,
        review_state=review_state,
        parallel=False,
        concurrency_limit=1,
        advisor_sessions={},
    )

    runtime = registry.get("advisor-agent")
    assert all_passed is True
    assert failed_items == []
    assert runtime.call_count == 0

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_result_review_rechecks_failed_report_after_file_changes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", CountingFailRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    task_file.write_text("# task\n", encoding="utf-8")
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    result_path = results_dir / "result_001.md"
    result_path.write_text("# failed result v1\n", encoding="utf-8")

    advisor = AdvisorInstanceDef(
        instance_id="result_fp_check",
        agent_id="advisor-agent",
        role_name="误报检测",
        re_review_on_cycle=False,
        system_prompt_file=str(task_file),
        user_prompt_template=str(task_file),
    )

    review_state = ReviewState()
    old_fingerprint = calculate_file_sha256(str(result_path))
    review_state.mark_result_failed(
        "result_001.md",
        cycle=1,
        reason="上一轮已判定失败",
        file_fingerprint=old_fingerprint,
    )

    result_path.write_text("# failed result v2\n\nchanged\n", encoding="utf-8")

    executor = ResultReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))
    all_passed, failed_items = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=2,
        review_state=review_state,
        parallel=False,
        concurrency_limit=1,
        advisor_sessions={},
    )

    runtime = registry.get("advisor-agent")
    assert all_passed is True
    assert failed_items == []
    assert review_state.result_states["result_001.md"].vuln_status == "false_positive"
    assert runtime.call_count == 1

    await registry.shutdown_all()
