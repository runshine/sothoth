from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AdvisorInstanceDef
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor
from app.pi_vuln_core.review.state import ReviewState

COMPLETENESS_SCORE_FIELDS = [
    "input_coverage",
    "export_followthrough",
    "used_coverage",
    "limitations_honesty",
    "report_completeness",
]
COMPLETENESS_SCORE_THRESHOLDS_START = {
    "input_coverage": 0.8,
    "export_followthrough": 0.7,
    "used_coverage": 0.7,
    "limitations_honesty": 0.75,
    "report_completeness": 0.7,
}
COMPLETENESS_SCORE_THRESHOLDS = {
    "input_coverage": 1.0,
    "export_followthrough": 0.95,
    "used_coverage": 0.95,
    "limitations_honesty": 0.95,
    "report_completeness": 0.9,
}


class MutatingGlobalAdvisorRuntime(BaseAgentRuntime):
    def __init__(self, agent_config: dict):
        super().__init__(agent_config)
        self.session_counter = 0
        self.call_session_ids: list[str] = []

    async def initialize(self) -> None:
        self._initialized = True

    async def create_session(self) -> str:
        self.session_counter += 1
        session_id = f"global_{self.session_counter}"
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
        if working_dir:
            (Path(working_dir) / "summary.md").write_text(
                "# mutated by advisor\n",
                encoding="utf-8",
            )
        return AgentResponse(
            content=json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "looks good",
                    "scores": {
                        "input_coverage": 1.0,
                        "export_followthrough": 1.0,
                        "used_coverage": 1.0,
                        "limitations_honesty": 1.0,
                        "report_completeness": 1.0,
                    },
                    "confidence": 0.9,
                    "issues": [],
                    "resolved_issues": [],
                },
                ensure_ascii=False,
            ),
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


class ErrorGlobalAdvisorRuntime(MutatingGlobalAdvisorRuntime):
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


class FlakyTimeoutThenPassGlobalRuntime(MutatingGlobalAdvisorRuntime):
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
            content=json.dumps(
                {
                    "passed": True,
                    "verdict": "PASS",
                    "feedback": "retry recovered",
                    "scores": {
                        "input_coverage": 1.0,
                        "export_followthrough": 1.0,
                        "used_coverage": 1.0,
                        "limitations_honesty": 1.0,
                        "report_completeness": 1.0,
                    },
                    "confidence": 0.9,
                    "issues": [],
                    "resolved_issues": [],
                },
                ensure_ascii=False,
            ),
            conversation_id=session_id,
            turn_count=session["turns"],
            finished=True,
        )


@pytest.mark.asyncio
async def test_global_review_read_only_violation_fails_and_closes_reset_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", MutatingGlobalAdvisorRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {"advisor_runtime_retries": 3},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    summary_file = tmp_path / "summary.md"
    results_dir = tmp_path / "results"
    task_file.write_text("# task\n", encoding="utf-8")
    summary_file.write_text("# original summary\n", encoding="utf-8")
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    system_prompt = tmp_path / "global_sys.md"
    user_prompt = tmp_path / "global_user.md"
    system_prompt.write_text("global system\n", encoding="utf-8")
    user_prompt.write_text(
        "cycle={cycle}\n"
        "advisor_instance_id={advisor_instance_id}\n"
        "{review_context}\n"
        "{required_score_fields}\n",
        encoding="utf-8",
    )

    advisor = AdvisorInstanceDef(
        instance_id="global_completeness",
        agent_id="advisor-agent",
        role_name="全面性审计",
        re_review_on_cycle=True,
        system_prompt_file=str(system_prompt),
        user_prompt_template=str(user_prompt),
        score_fields=COMPLETENESS_SCORE_FIELDS,
        score_thresholds_start=COMPLETENESS_SCORE_THRESHOLDS_START,
        score_thresholds=COMPLETENESS_SCORE_THRESHOLDS,
    )
    advisor_sessions: dict[str, str] = {}
    executor = GlobalReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))

    passed, feedback = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        summary_file=str(summary_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=ReviewState(),
        advisor_sessions=advisor_sessions,
    )

    assert passed is False
    assert "只读" in feedback or "read-only" in feedback
    record_path = tmp_path / "reviews" / "global" / "cycle_001" / "global_completeness.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["issues"][0]["category"] == "advisor_contract"
    assert "modified:summary.md" in record["issues"][0]["detail"]
    assert advisor_sessions == {}

    runtime = registry.get("advisor-agent")
    assert runtime._sessions == {}

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_global_review_runtime_error_is_framework_actionable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", ErrorGlobalAdvisorRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {"advisor_runtime_retries": 3},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    summary_file = tmp_path / "summary.md"
    results_dir = tmp_path / "results"
    task_file.write_text("# task\n", encoding="utf-8")
    summary_file.write_text("# summary\n", encoding="utf-8")
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    system_prompt = tmp_path / "global_sys.md"
    user_prompt = tmp_path / "global_user.md"
    system_prompt.write_text("global system\n", encoding="utf-8")
    user_prompt.write_text(
        "{review_context}\n{required_score_fields}\n",
        encoding="utf-8",
    )

    advisor = AdvisorInstanceDef(
        instance_id="global_completeness",
        agent_id="advisor-agent",
        role_name="全面性审计",
        re_review_on_cycle=True,
        system_prompt_file=str(system_prompt),
        user_prompt_template=str(user_prompt),
        score_fields=COMPLETENESS_SCORE_FIELDS,
        score_thresholds_start=COMPLETENESS_SCORE_THRESHOLDS_START,
        score_thresholds=COMPLETENESS_SCORE_THRESHOLDS,
    )
    review_state = ReviewState()
    executor = GlobalReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))

    passed, feedback = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        summary_file=str(summary_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        advisor_sessions={},
    )

    assert passed is False
    assert "评审智能体错误" in feedback
    assert review_state.has_failures(actionable_by="worker") is False
    assert review_state.has_failures(actionable_by="framework") is True

    record_path = tmp_path / "reviews" / "global" / "cycle_001" / "global_completeness.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    issue = record["issues"][0]
    assert issue["category"] == "advisor_runtime"
    assert issue["actionable_by"] == "framework"
    assert "重试 3/3 次" in record["feedback_detail"]

    runtime = registry.get("advisor-agent")
    assert len(runtime.call_session_ids) == 4
    assert len(set(runtime.call_session_ids)) == 4
    assert runtime._sessions == {}

    await registry.shutdown_all()


@pytest.mark.asyncio
async def test_global_review_runtime_timeout_retries_with_fresh_sessions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setitem(AgentRuntimeRegistry.RUNTIME_MAP, "claude_code", FlakyTimeoutThenPassGlobalRuntime)

    registry = AgentRuntimeRegistry()
    registry.register_from_config(
        [
            {
                "id": "advisor-agent",
                "name": "Advisor Agent",
                "type": "claude_code",
                "reset_context": True,
                "runtime_config": {"advisor_runtime_retries": 3},
            }
        ]
    )
    await registry.initialize_all()

    task_file = tmp_path / "task.md"
    summary_file = tmp_path / "summary.md"
    results_dir = tmp_path / "results"
    task_file.write_text("# task\n", encoding="utf-8")
    summary_file.write_text("# summary\n", encoding="utf-8")
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    system_prompt = tmp_path / "global_sys.md"
    user_prompt = tmp_path / "global_user.md"
    system_prompt.write_text("global system\n", encoding="utf-8")
    user_prompt.write_text(
        "{review_context}\n{required_score_fields}\n",
        encoding="utf-8",
    )

    advisor = AdvisorInstanceDef(
        instance_id="global_completeness",
        agent_id="advisor-agent",
        role_name="全面性审计",
        re_review_on_cycle=True,
        system_prompt_file=str(system_prompt),
        user_prompt_template=str(user_prompt),
        score_fields=COMPLETENESS_SCORE_FIELDS,
        score_thresholds_start=COMPLETENESS_SCORE_THRESHOLDS_START,
        score_thresholds=COMPLETENESS_SCORE_THRESHOLDS,
    )
    review_state = ReviewState()
    executor = GlobalReviewExecutor(registry, ExecutionRecorder(str(tmp_path)))

    passed, feedback = await executor.execute(
        advisors_cfg=[advisor],
        task_file=str(task_file),
        summary_file=str(summary_file),
        results_dir=str(results_dir),
        work_dir=str(tmp_path),
        cycle=1,
        review_state=review_state,
        advisor_sessions={},
    )

    assert passed is True
    assert feedback == ""

    runtime = registry.get("advisor-agent")
    assert runtime.call_session_ids == ["global_1", "global_2", "global_3"]
    assert runtime._sessions == {}

    record_path = tmp_path / "reviews" / "global" / "cycle_001" / "global_completeness.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["passed"] is True
    assert record["parser_mode"] == "canonical_json"

    await registry.shutdown_all()
