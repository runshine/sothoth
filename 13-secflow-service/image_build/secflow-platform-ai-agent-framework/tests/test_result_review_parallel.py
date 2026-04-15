from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.result_review import ResultReviewExecutor
from app.pi_vuln_core.review.state import ReviewState
from run_vuln_scan import generate_config


class DelayedPassRuntime(BaseAgentRuntime):
    def __init__(self, agent_config: dict):
        super().__init__(agent_config)
        self.active_calls = 0
        self.max_active_calls = 0
        self.call_session_ids: list[str] = []

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"delay_{len(self._sessions) + 1}"
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
            content='{"passed": true, "feedback": "验证通过"}',
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


def test_run_vuln_scan_generate_config_enables_parallel_result_review(tmp_path: Path) -> None:
    config = generate_config(
        run_dir=str(tmp_path),
        task_file=str(tmp_path / "task.md"),
        run_name="demo",
    )
    assert config["global"]["parallel_result_review"] is True
    assert config["global"]["parallel_result_review_limit"] == 3


def test_run_vuln_scan_generate_config_accepts_custom_result_review_concurrency(tmp_path: Path) -> None:
    config = generate_config(
        run_dir=str(tmp_path),
        task_file=str(tmp_path / "task.md"),
        run_name="demo",
        result_review_concurrency=5,
    )
    assert config["global"]["parallel_result_review_limit"] == 5
